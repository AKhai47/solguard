"""Tool functions and Anthropic tool schemas for the SolGuard auditor agent.

Each tool is implemented as a plain Python function AND described by an
Anthropic-compatible tool schema dict.  The agent calls tools by name;
TOOL_MAP dispatches the name to the correct function.
"""

import re
from engine.parser import _strip_comments, _extract_functions, _extract_state_variables

# ---------------------------------------------------------------------------
# SWC Registry (local, hardcoded)
# ---------------------------------------------------------------------------

_SWC_REGISTRY: dict[str, dict] = {
    "reentrancy": {
        "swc_id": "SWC-107",
        "title": "Re-entrancy",
        "url": "https://swcregistry.io/docs/SWC-107",
        "description": (
            "One of the most dangerous bugs in smart contracts. A malicious contract "
            "can call back into the vulnerable contract before the first execution "
            "completes, draining funds or corrupting state."
        ),
        "remediation": (
            "Follow the checks-effects-interactions pattern: update all state before "
            "making external calls. Use a reentrancy guard (mutex) for extra protection."
        ),
    },
    "tx.origin": {
        "swc_id": "SWC-115",
        "title": "Authorization through tx.origin",
        "url": "https://swcregistry.io/docs/SWC-115",
        "description": (
            "tx.origin refers to the original external account that initiated the "
            "transaction, not the immediate caller. Using it for authorization allows "
            "phishing attacks where a malicious contract tricks the owner into calling "
            "it, passing the tx.origin check."
        ),
        "remediation": (
            "Replace tx.origin with msg.sender for all authorization checks."
        ),
    },
    "integer overflow": {
        "swc_id": "SWC-101",
        "title": "Integer Overflow and Underflow",
        "url": "https://swcregistry.io/docs/SWC-101",
        "description": (
            "In Solidity <0.8.0, arithmetic operations silently wrap on overflow or "
            "underflow. An attacker can craft inputs that cause balances or counters "
            "to wrap to unintended values."
        ),
        "remediation": (
            "Upgrade to Solidity >=0.8.0 (built-in checked arithmetic) or use "
            "OpenZeppelin SafeMath for all arithmetic in older compilers."
        ),
    },
    "unchecked return": {
        "swc_id": "SWC-104",
        "title": "Unchecked Call Return Value",
        "url": "https://swcregistry.io/docs/SWC-104",
        "description": (
            ".send() and .call() return a boolean indicating success. Ignoring this "
            "value means failed transfers are silently swallowed, potentially locking "
            "ETH in the contract."
        ),
        "remediation": (
            "Always capture and require() the return value of .send() and .call(). "
            "Consider using .transfer() which reverts on failure, or the pull-payment pattern."
        ),
    },
    "unprotected function": {
        "swc_id": "SWC-105",
        "title": "Unprotected Ether Withdrawal",
        "url": "https://swcregistry.io/docs/SWC-105",
        "description": (
            "Critical functions lack access control, allowing any account to invoke "
            "privileged operations such as withdrawing funds, changing ownership, or "
            "pausing the protocol."
        ),
        "remediation": (
            "Add an onlyOwner modifier or equivalent require(msg.sender == owner) guard "
            "to every privileged function. Consider OpenZeppelin Ownable or AccessControl."
        ),
    },
    "timestamp": {
        "swc_id": "SWC-116",
        "title": "Block values as a proxy for time",
        "url": "https://swcregistry.io/docs/SWC-116",
        "description": (
            "block.timestamp can be manipulated by miners within a ~15-second window. "
            "Using it for time-sensitive conditions (lotteries, auctions, locks) "
            "introduces a manipulation surface."
        ),
        "remediation": (
            "Use block numbers for relative time measurements, or design logic to "
            "tolerate a 15-second timestamp variance."
        ),
    },
    "hardcoded address": {
        "swc_id": "SWC-134",
        "title": "Message call with hardcoded gas or value",
        "url": "https://swcregistry.io/docs/SWC-134",
        "description": (
            "Hardcoded addresses cannot be changed after deployment. If the target "
            "contract is upgraded, compromised, or decommissioned, every contract "
            "that references it must also be redeployed."
        ),
        "remediation": (
            "Pass critical addresses as constructor arguments or expose an owner-only "
            "setter so they can be rotated without a full redeployment."
        ),
    },
}

# ---------------------------------------------------------------------------
# Internal helpers shared across tools
# ---------------------------------------------------------------------------

_EXTERNAL_CALL_RE = re.compile(
    r"\.(?P<call_type>send|transfer|call|delegatecall|staticcall)\b"
)
_ASSIGN_RE = re.compile(r"[+\-*]?=(?!=)")   # =, +=, -=, *=, /= but not ==


def _build_parsed(source: str) -> dict:
    """Strip comments and extract functions + state variables from raw source."""
    stripped = _strip_comments(source)
    raw_lines = source.splitlines()
    return {
        "stripped": stripped,
        "raw_lines": raw_lines,
        "functions": _extract_functions(stripped, raw_lines),
        "state_variables": _extract_state_variables(stripped),
    }


# ---------------------------------------------------------------------------
# Tool 1 — get_functions
# ---------------------------------------------------------------------------

def get_functions(contract_source: str) -> list[dict]:
    """Return every function declared in the contract source.

    Parameters
    ----------
    contract_source:
        Raw Solidity source code as a string.

    Returns
    -------
    List of dicts with keys: name, visibility, modifiers, has_eth_transfer,
    line_start.  The full body is intentionally excluded to keep responses
    concise when the agent inspects the function list.
    """
    parsed = _build_parsed(contract_source)
    return [
        {
            "name": f["name"],
            "visibility": f["visibility"],
            "modifiers": f["modifiers"],
            "has_eth_transfer": f["has_eth_transfer"],
            "line_start": f["line_start"],
        }
        for f in parsed["functions"]
    ]


# ---------------------------------------------------------------------------
# Tool 2 — get_state_variables
# ---------------------------------------------------------------------------

def get_state_variables(contract_source: str) -> list[dict]:
    """Return every state variable declared at contract scope.

    Parameters
    ----------
    contract_source:
        Raw Solidity source code as a string.

    Returns
    -------
    List of dicts with keys: name, type, visibility, line.
    """
    parsed = _build_parsed(contract_source)
    return parsed["state_variables"]


# ---------------------------------------------------------------------------
# Tool 3 — check_access_control
# ---------------------------------------------------------------------------

def check_access_control(function_name: str, contract_source: str) -> dict:
    """Analyze the access-control posture of a named function.

    Parameters
    ----------
    function_name:
        The exact name of the function to inspect.
    contract_source:
        Raw Solidity source code as a string.

    Returns
    -------
    Dict with keys:
        has_modifier       — True if the function has any named modifier
        uses_msg_sender    — True if msg.sender appears in the body
        uses_tx_origin     — True if tx.origin appears in the body
        has_inline_require — True if require(msg.sender == ... is in the body
        is_publicly_callable — True if visibility is public or external
        verdict            — "protected", "unprotected", or "not_found"
    """
    parsed = _build_parsed(contract_source)

    target = next(
        (f for f in parsed["functions"] if f["name"] == function_name),
        None,
    )

    if target is None:
        return {
            "has_modifier": False,
            "uses_msg_sender": False,
            "uses_tx_origin": False,
            "has_inline_require": False,
            "is_publicly_callable": False,
            "verdict": "not_found",
        }

    # Strip inline comments before inspecting the body so commented-out checks
    # don't produce false positives (e.g. "// missing: require(msg.sender == owner)").
    body = re.sub(r"//[^\n]*", "", target["body"])

    has_modifier = bool(target["modifiers"])
    uses_msg_sender = bool(re.search(r"\bmsg\.sender\b", body))
    uses_tx_origin = bool(re.search(r"\btx\.origin\b", body))
    has_inline_require = bool(re.search(r"require\s*\(\s*msg\.sender\s*==", body))
    is_publicly_callable = target["visibility"] in ("public", "external")

    # A function is "protected" if it has at least one named modifier OR an
    # inline require that gates on msg.sender. tx.origin is NOT considered
    # sufficient protection (it is itself a vulnerability).
    protected = has_modifier or has_inline_require

    return {
        "has_modifier": has_modifier,
        "uses_msg_sender": uses_msg_sender,
        "uses_tx_origin": uses_tx_origin,
        "has_inline_require": has_inline_require,
        "is_publicly_callable": is_publicly_callable,
        "verdict": "protected" if protected else "unprotected",
    }


# ---------------------------------------------------------------------------
# Tool 4 — trace_external_calls
# ---------------------------------------------------------------------------

def trace_external_calls(contract_source: str) -> list[dict]:
    """Find every external call in the contract and assess its safety.

    Parameters
    ----------
    contract_source:
        Raw Solidity source code as a string.

    Returns
    -------
    List of dicts with keys:
        line              — 1-indexed line number
        snippet           — stripped source line
        call_type         — send / transfer / call / delegatecall / staticcall
        return_checked    — True if a bool capture appears on the same line
        state_change_after — True if an assignment appears within 5 lines after
                             the call (potential CEI violation)
    """
    stripped = _strip_comments(contract_source)
    all_lines = stripped.splitlines()
    results = []

    for lineno, line in enumerate(all_lines, start=1):
        for m in _EXTERNAL_CALL_RE.finditer(line):
            # Determine whether the return value is captured on this line.
            return_checked = bool(
                re.search(r"\bbool\b", line) and "=" in line
            )

            # Scan the next 5 lines for any assignment (state-change after call).
            lookahead_lines = all_lines[lineno : lineno + 5]  # lineno is 0-based here
            state_change_after = any(
                _ASSIGN_RE.search(re.sub(r"//[^\n]*", "", la))
                and not re.match(
                    r"^\s*(?:bool|uint\d*|int\d*|address|bytes\d*|\(bool)",
                    la.strip(),
                )
                for la in lookahead_lines
            )

            results.append(
                {
                    "line": lineno,
                    "snippet": line.strip(),
                    "call_type": m.group("call_type"),
                    "return_checked": return_checked,
                    "state_change_after": state_change_after,
                }
            )

    return results


# ---------------------------------------------------------------------------
# Tool 5 — lookup_swc
# ---------------------------------------------------------------------------

def lookup_swc(vulnerability_name: str) -> dict:
    """Look up a Smart Contract Weakness Classification (SWC) entry by name.

    Parameters
    ----------
    vulnerability_name:
        A vulnerability label such as "Reentrancy", "tx.origin", or
        "Integer Overflow/Underflow". Matching is substring-based and
        case-insensitive.

    Returns
    -------
    Dict with keys: swc_id, title, url, description, remediation.
    If no match is found, swc_id is "N/A" and the other fields are empty strings.
    """
    needle = vulnerability_name.lower()
    for key, entry in _SWC_REGISTRY.items():
        # Match if every word in the registry key appears somewhere in the input.
        # This handles cases like "Unprotected Critical Function" matching key
        # "unprotected function" even when extra words are interspersed.
        key_words = key.split()
        if all(word in needle for word in key_words):
            return entry

    return {
        "swc_id": "N/A",
        "title": "",
        "url": "",
        "description": "",
        "remediation": "",
    }


# ---------------------------------------------------------------------------
# Anthropic tool schemas
# ---------------------------------------------------------------------------

TOOL_SCHEMAS: list[dict] = [
    {
        "name": "get_functions",
        "description": (
            "Parse a Solidity contract source string and return a list of all "
            "declared functions with their name, visibility, modifiers, whether "
            "they perform ETH transfers, and their starting line number."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "contract_source": {
                    "type": "string",
                    "description": "The full raw Solidity source code of the contract.",
                }
            },
            "required": ["contract_source"],
        },
    },
    {
        "name": "get_state_variables",
        "description": (
            "Parse a Solidity contract source string and return all contract-level "
            "state variable declarations with name, type, visibility, and line number."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "contract_source": {
                    "type": "string",
                    "description": "The full raw Solidity source code of the contract.",
                }
            },
            "required": ["contract_source"],
        },
    },
    {
        "name": "check_access_control",
        "description": (
            "Inspect a named function for access-control mechanisms. Returns whether "
            "it has a modifier, uses msg.sender or tx.origin, has an inline require "
            "guard, and an overall verdict of 'protected', 'unprotected', or 'not_found'."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "function_name": {
                    "type": "string",
                    "description": "The exact name of the function to inspect.",
                },
                "contract_source": {
                    "type": "string",
                    "description": "The full raw Solidity source code of the contract.",
                },
            },
            "required": ["function_name", "contract_source"],
        },
    },
    {
        "name": "trace_external_calls",
        "description": (
            "Find every external call (.send, .transfer, .call, .delegatecall, "
            ".staticcall) in the contract. For each call, reports the line, snippet, "
            "call type, whether the return value is checked, and whether a state "
            "change occurs within 5 lines after the call (a reentrancy signal)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "contract_source": {
                    "type": "string",
                    "description": "The full raw Solidity source code of the contract.",
                }
            },
            "required": ["contract_source"],
        },
    },
    {
        "name": "lookup_swc",
        "description": (
            "Look up a Smart Contract Weakness Classification (SWC) entry for a given "
            "vulnerability name. Returns the SWC ID, title, reference URL, description, "
            "and recommended remediation. Returns swc_id='N/A' if no match is found."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "vulnerability_name": {
                    "type": "string",
                    "description": (
                        "The vulnerability label to look up, e.g. 'Reentrancy', "
                        "'tx.origin', 'Integer Overflow', 'Unchecked Return Value'."
                    ),
                }
            },
            "required": ["vulnerability_name"],
        },
    },
]

# ---------------------------------------------------------------------------
# Dispatch map
# ---------------------------------------------------------------------------

TOOL_MAP: dict = {
    "get_functions": get_functions,
    "get_state_variables": get_state_variables,
    "check_access_control": check_access_control,
    "trace_external_calls": trace_external_calls,
    "lookup_swc": lookup_swc,
}
