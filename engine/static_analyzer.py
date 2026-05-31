"""Static analysis pass — detects common smart contract vulnerability patterns without executing code."""

import re
from typing import Optional

# ---------------------------------------------------------------------------
# Severity ordering for sorting findings
# ---------------------------------------------------------------------------

SEVERITY_ORDER: dict[str, int] = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Informational": 4,
}

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _make_finding(
    vulnerability: str,
    severity: str,
    confidence: str,
    line: Optional[int],
    snippet: str,
    description: str,
    recommendation: str,
) -> dict:
    """Build a normalized finding dict with all required keys."""
    return {
        "vulnerability": vulnerability,
        "severity": severity,
        "confidence": confidence,
        "line": line,
        "snippet": snippet.strip()[:200],
        "description": description,
        "recommendation": recommendation,
        "source": "static",
    }


def _lines_of(text: str) -> list[tuple[int, str]]:
    """Return (1-indexed line number, line content) pairs for a source string."""
    return list(enumerate(text.splitlines(), start=1))


def _strip_inline_comments(line: str) -> str:
    """Remove // comments from a single line so they don't produce false positives."""
    return re.sub(r"//.*", "", line)


# ---------------------------------------------------------------------------
# Check 1 — Reentrancy  (Critical)
# ---------------------------------------------------------------------------

_ETH_CALL_RE = re.compile(r"\.send\s*\(|\.transfer\s*\(|\.call\s*\{[^}]*value")

# Matches assignment operators: =, +=, -=, *=, /=
# Negative lookbehind avoids matching ==, !=, <=, >=
_ASSIGN_RE = re.compile(r"(?<![=!<>])=(?!=)")

# Type keywords that begin local variable declarations — these are NOT state writes.
_LOCAL_DECL_RE = re.compile(
    r"^\s*(?:bool|uint\d*|int\d*|address\s+payable|address|bytes\d*|string|"
    r"mapping|var\b|\(bool|\(uint|\(int|\(address)"
)


def _is_state_write(raw_line: str) -> bool:
    """Heuristic: return True if the line looks like a state-variable assignment.

    Excludes:
    - Local variable declarations (start with a Solidity type keyword)
    - require / emit / revert / return / for-loop lines
    - Lines with no assignment operator at all
    """
    line = _strip_inline_comments(raw_line)
    stripped = line.strip()

    if not stripped:
        return False
    if _LOCAL_DECL_RE.match(stripped):
        return False
    if stripped.startswith(("require(", "emit ", "revert", "return", "for (")):
        return False

    return bool(_ASSIGN_RE.search(stripped))


def check_reentrancy(parsed: dict) -> list[dict]:
    """Flag functions that perform an ETH transfer before updating state variables.

    The checks-effects-interactions (CEI) pattern mandates that all state
    updates happen *before* any external call.  Violating CEI allows a
    malicious contract's fallback to re-enter the function while the contract's
    state is still stale, enabling repeated withdrawals (the DAO attack).
    """
    findings = []

    for func in parsed.get("functions", []):
        if not func["has_eth_transfer"]:
            continue

        body_lines = func["body"].splitlines()
        eth_call_idx: Optional[int] = None

        # Locate the first line that contains an ETH-transferring call.
        for idx, line in enumerate(body_lines):
            if _ETH_CALL_RE.search(line):
                eth_call_idx = idx
                break

        if eth_call_idx is None:
            continue

        # Scan lines AFTER the ETH call for any state-variable write.
        for post_line in body_lines[eth_call_idx + 1:]:
            if _is_state_write(post_line):
                abs_line = func["line_start"] + eth_call_idx
                findings.append(
                    _make_finding(
                        vulnerability="Reentrancy",
                        severity="Critical",
                        confidence="High",
                        line=abs_line,
                        snippet=body_lines[eth_call_idx].strip(),
                        description=(
                            f"Function '{func['name']}' performs an ETH transfer before updating "
                            "state variables, violating the checks-effects-interactions pattern. "
                            "A malicious fallback can re-enter and drain funds before balances are zeroed."
                        ),
                        recommendation=(
                            "Move all state updates above the external call, or add a reentrancy "
                            "guard (e.g., OpenZeppelin ReentrancyGuard)."
                        ),
                    )
                )
                break  # one finding per function is sufficient

    return findings


# ---------------------------------------------------------------------------
# Check 2 — tx.origin Authentication  (High)
# ---------------------------------------------------------------------------

_TX_ORIGIN_RE = re.compile(r"\btx\.origin\b")


def check_tx_origin(parsed: dict) -> list[dict]:
    """Flag any use of tx.origin for authorization.

    tx.origin is the original EOA signer of the transaction, not the immediate
    caller.  A malicious intermediary contract can lure the real owner into
    signing a transaction that passes a tx.origin == owner check, enabling
    phishing-style ownership takeovers.
    """
    findings = []
    stripped = parsed.get("comments_stripped_source", "")

    for lineno, line in _lines_of(stripped):
        if _TX_ORIGIN_RE.search(line):
            findings.append(
                _make_finding(
                    vulnerability="tx.origin Authentication",
                    severity="High",
                    confidence="High",
                    line=lineno,
                    snippet=line.strip(),
                    description=(
                        "Authorization check uses tx.origin instead of msg.sender. "
                        "A malicious contract can impersonate the original signer, "
                        "bypassing this check via a phishing transaction."
                    ),
                    recommendation=(
                        "Replace tx.origin with msg.sender for all access control checks."
                    ),
                )
            )

    return findings


# ---------------------------------------------------------------------------
# Check 3 — Integer Overflow / Underflow  (High)
# ---------------------------------------------------------------------------

_VERSION_NUM_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")

# Arithmetic on uint/int types: catches `x += y`, `x - y`, etc.
# Intentionally broad — filtered to lines that also contain `=` to reduce noise.
_ARITH_OP_RE = re.compile(r"\b(?:uint\d*|int\d*)\b[^;]*[+\-*]")


def _is_pre_08(pragma: str) -> bool:
    """Return True if the pragma version string resolves to < 0.8.0."""
    m = _VERSION_NUM_RE.search(pragma)
    if not m:
        return False
    major, minor = int(m.group(1)), int(m.group(2))
    return major == 0 and minor < 8


def check_integer_overflow(parsed: dict) -> list[dict]:
    """Flag contracts compiled under pre-0.8 Solidity lacking built-in overflow protection.

    Solidity >=0.8.0 reverts automatically on integer overflow and underflow.
    Older versions silently wrap (e.g., uint8(255)+1 == 0), enabling attackers
    to manipulate balances or bypass require() guards via crafted amounts.
    """
    findings = []
    pragma = parsed.get("pragma", "")

    if not _is_pre_08(pragma):
        return findings  # 0.8+ has built-in checked arithmetic

    # One pragma-level finding to clearly identify the compiler risk.
    findings.append(
        _make_finding(
            vulnerability="Integer Overflow/Underflow",
            severity="High",
            confidence="High",
            line=None,
            snippet=f"pragma solidity {pragma}",
            description=(
                f"Contract compiles under Solidity {pragma}, which lacks built-in checked "
                "arithmetic. Integer overflow and underflow silently wrap around, "
                "enabling balance inflation or logic bypasses with crafted inputs."
            ),
            recommendation=(
                "Upgrade to Solidity >=0.8.0 for automatic overflow/underflow protection, "
                "or apply OpenZeppelin SafeMath to every arithmetic operation."
            ),
        )
    )

    # Also surface individual arithmetic lines so the analyzer report is actionable.
    stripped = parsed.get("comments_stripped_source", "")
    for lineno, line in _lines_of(stripped):
        if _ARITH_OP_RE.search(line) and "=" in line:
            findings.append(
                _make_finding(
                    vulnerability="Integer Overflow/Underflow",
                    severity="High",
                    confidence="Medium",
                    line=lineno,
                    snippet=line.strip(),
                    description=(
                        "Arithmetic on an integer type in a pre-0.8 contract without overflow "
                        "protection. This operation can silently wrap if inputs are not validated."
                    ),
                    recommendation=(
                        "Wrap this arithmetic in SafeMath (e.g., .add(), .sub()) "
                        "or upgrade the compiler to >=0.8.0."
                    ),
                )
            )

    return findings


# ---------------------------------------------------------------------------
# Check 4 — Unchecked Return Value  (Medium)
# ---------------------------------------------------------------------------

_SEND_RE = re.compile(r"\.send\s*\(")
_CALL_RE = re.compile(r"\.call\s*(?:\{[^}]*\})?\s*\(")


def _return_captured(line: str) -> bool:
    """Return True if the line stores the bool result of send/call."""
    # Captured forms: `bool ok = ...`, `(bool ok, ) = ...`, `bool success = ...`
    return bool(re.search(r"\bbool\b", line) and "=" in line)


def check_unchecked_return(parsed: dict) -> list[dict]:
    """Flag .send() and low-level .call() whose boolean return value is not checked.

    .send() and .call() return a bool indicating success rather than reverting
    on failure.  Ignoring that bool means silent transfer failures: the contract
    continues executing, state changes are committed, and the ETH stays locked.
    """
    findings = []
    stripped = parsed.get("comments_stripped_source", "")

    for lineno, line in _lines_of(stripped):
        has_send = _SEND_RE.search(line)
        has_call = _CALL_RE.search(line)

        if has_send and not _return_captured(line):
            findings.append(
                _make_finding(
                    vulnerability="Unchecked Return Value",
                    severity="Medium",
                    confidence="High",
                    line=lineno,
                    snippet=line.strip(),
                    description=(
                        ".send() was called but its boolean return value is not captured or "
                        "checked. A failed transfer will be silently ignored, potentially "
                        "locking the recipient's ETH permanently."
                    ),
                    recommendation=(
                        "Capture and require the return value: "
                        "`bool ok = payable(x).send(amt); require(ok, 'send failed');`"
                    ),
                )
            )

        elif has_call and not _return_captured(line):
            # Only flag .call lines that clearly omit the return — exclude lines
            # where `bool` appears in any form (partial capture on adjacent line, etc.)
            if "bool" not in line:
                findings.append(
                    _make_finding(
                        vulnerability="Unchecked Return Value",
                        severity="Medium",
                        confidence="Medium",
                        line=lineno,
                        snippet=line.strip(),
                        description=(
                            "Low-level .call() return value is not captured. "
                            "If the call fails, execution continues silently and "
                            "the failure goes undetected."
                        ),
                        recommendation=(
                            "Always capture and check both return values: "
                            "`(bool ok, ) = addr.call{value: x}(''); require(ok, 'call failed');`"
                        ),
                    )
                )

    return findings


# ---------------------------------------------------------------------------
# Check 5 — Unprotected Critical Functions  (High)
# ---------------------------------------------------------------------------

_SENSITIVE_NAMES: set[str] = {
    "transfer", "withdraw", "mint", "burn", "destroy",
    "selfdestruct", "setOwner", "transferOwnership",
    "pause", "unpause", "initialize", "upgradeTo",
}

# Inline ownership guard pattern — presence of this means the function is
# protected even without a named modifier.
_INLINE_GUARD_RE = re.compile(r"require\s*\(\s*msg\.sender\s*==")


def check_unprotected_functions(parsed: dict) -> list[dict]:
    """Flag sensitive public/external functions that carry no access-control modifier.

    Critical functions without access control can be called by any account,
    enabling ownership takeovers, fund drains, or protocol manipulation — as
    seen in the Parity Multisig hack (2017, $30M stolen).
    """
    findings = []

    for func in parsed.get("functions", []):
        if func["visibility"] not in ("public", "external"):
            continue
        if func["name"] not in _SENSITIVE_NAMES:
            continue
        if func["modifiers"]:
            continue  # at least one named modifier applied — assume it gates access

        # Allow through if the body contains an explicit inline ownership check.
        # Strip comments first so a comment like "// missing: require(msg.sender == owner)"
        # doesn't produce a false negative.
        body_no_comments = re.sub(r"//[^\n]*", "", func["body"])
        if _INLINE_GUARD_RE.search(body_no_comments):
            continue

        findings.append(
            _make_finding(
                vulnerability="Unprotected Critical Function",
                severity="High",
                confidence="High",
                line=func["line_start"],
                snippet=f"function {func['name']}(...) {func['visibility']}",
                description=(
                    f"'{func['name']}' is {func['visibility']} and has no access-control "
                    "modifier or inline ownership check. Any address can call it, "
                    "potentially draining funds or hijacking ownership."
                ),
                recommendation=(
                    "Add an onlyOwner modifier or a require(msg.sender == owner) guard "
                    "at the top of this function."
                ),
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Check 6 — Timestamp Dependence  (Low)
# ---------------------------------------------------------------------------

_TIMESTAMP_RE = re.compile(r"\bblock\.timestamp\b|\bnow\b")

# Matches require(...block.timestamp...) or if (...block.timestamp...)
_TIMESTAMP_COND_RE = re.compile(
    r"(?:require|if)\s*\([^)]*(?:block\.timestamp|now)"
)


def check_timestamp_dependence(parsed: dict) -> list[dict]:
    """Flag block.timestamp (or now) used inside conditional logic.

    Miners can adjust block.timestamp by up to ~15 seconds.  Using it to gate
    lotteries, auctions, or token locks introduces a manipulation window that
    can be exploited for profit.
    """
    findings = []
    stripped = parsed.get("comments_stripped_source", "")

    for lineno, line in _lines_of(stripped):
        # Remove string literals first so "right now" or "block.timestamp" inside
        # a string argument does not produce a false positive.
        line_no_strings = re.sub(r'"[^"]*"', '""', line)

        if not _TIMESTAMP_RE.search(line_no_strings):
            continue

        if _TIMESTAMP_COND_RE.search(line_no_strings):
            findings.append(
                _make_finding(
                    vulnerability="Timestamp Dependence",
                    severity="Low",
                    confidence="Medium",
                    line=lineno,
                    snippet=line.strip(),
                    description=(
                        "block.timestamp is used inside a conditional (require or if). "
                        "Miners can shift the timestamp by ~15 seconds, which may be "
                        "enough to influence time-sensitive logic."
                    ),
                    recommendation=(
                        "Use block numbers for relative time measurements, or widen the "
                        "tolerance window so a 15-second shift cannot change the outcome."
                    ),
                )
            )
        else:
            findings.append(
                _make_finding(
                    vulnerability="Timestamp Dependence",
                    severity="Low",
                    confidence="Low",
                    line=lineno,
                    snippet=line_no_strings.strip(),
                    description=(
                        "block.timestamp is referenced in this line. If used for randomness "
                        "or precise time-gating it is miner-manipulable."
                    ),
                    recommendation=(
                        "Review whether this timestamp usage is security-sensitive; "
                        "prefer block numbers for relative time measurements."
                    ),
                )
            )

    return findings


# ---------------------------------------------------------------------------
# Check 7 — Hardcoded Addresses  (Informational)
# ---------------------------------------------------------------------------

_ADDR_LITERAL_RE = re.compile(r"\b0x[0-9a-fA-F]{40}\b")


def check_hardcoded_address(parsed: dict) -> list[dict]:
    """Flag Ethereum address literals hardcoded in the source.

    Hardcoded addresses cannot be updated after deployment.  If the target
    contract is upgraded, compromised, or needs to be rotated, a redeployment
    of every contract that references it is required.
    """
    findings = []
    source = parsed.get("comments_stripped_source", "")

    for lineno, line in _lines_of(source):
        for m in _ADDR_LITERAL_RE.finditer(line):
            findings.append(
                _make_finding(
                    vulnerability="Hardcoded Address",
                    severity="Informational",
                    confidence="High",
                    line=lineno,
                    snippet=line.strip(),
                    description=(
                        f"Address literal {m.group(0)} is hardcoded in the contract. "
                        "Hardcoded addresses cannot be changed after deployment and create "
                        "maintenance and upgrade risk."
                    ),
                    recommendation=(
                        "Pass critical addresses as constructor arguments or store them in "
                        "owner-updatable state variables."
                    ),
                )
            )

    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_static_analysis(parsed: dict) -> list[dict]:
    """Run all seven static checks against a parsed contract dict.

    Parameters
    ----------
    parsed:
        The dict returned by engine.parser.parse_contract().  If None or
        empty, an empty list is returned.

    Returns
    -------
    List of finding dicts sorted by severity (Critical → Informational),
    with line number as the secondary sort key.
    """
    if not parsed:
        return []

    all_findings: list[dict] = []

    for check_fn in [
        check_reentrancy,
        check_tx_origin,
        check_integer_overflow,
        check_unchecked_return,
        check_unprotected_functions,
        check_timestamp_dependence,
        check_hardcoded_address,
    ]:
        all_findings.extend(check_fn(parsed))

    all_findings.sort(
        key=lambda f: (
            SEVERITY_ORDER.get(f["severity"], 99),
            f["line"] if f["line"] is not None else 0,
        )
    )

    return all_findings
