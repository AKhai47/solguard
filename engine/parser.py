"""Solidity source parser — reads a .sol file and extracts structured data
for use by the static analyzer and auditor agent."""

import re
import os
from pathlib import Path


# ---------------------------------------------------------------------------
# Comment stripping
# ---------------------------------------------------------------------------

def _strip_comments(source: str) -> str:
    """Remove // line comments and /* ... */ block comments from Solidity source.

    Preserves line count by replacing block-comment lines with blank lines so
    that line numbers reported elsewhere remain accurate.
    """
    # Remove /* ... */ block comments (non-greedy, dotall so newlines match).
    # Replace with whitespace that preserves newline count.
    def _replace_block(m: re.Match) -> str:
        newlines = m.group(0).count("\n")
        return "\n" * newlines

    source = re.sub(r"/\*.*?\*/", _replace_block, source, flags=re.DOTALL)

    # Remove // line comments (keep the newline so line numbers stay intact).
    source = re.sub(r"//[^\n]*", "", source)

    return source


# ---------------------------------------------------------------------------
# Top-level field extractors
# ---------------------------------------------------------------------------

def _extract_pragma(source: str) -> str:
    """Return the solidity version string, e.g. '^0.8.20', or '' if absent."""
    m = re.search(r"pragma\s+solidity\s+([^;]+);", source)
    return m.group(1).strip() if m else ""


def _extract_contract_name(source: str) -> str:
    """Return the first contract name declared in the file, or '' if absent."""
    m = re.search(r"\bcontract\s+(\w+)", source)
    return m.group(1) if m else ""


# ---------------------------------------------------------------------------
# State variable extraction
# ---------------------------------------------------------------------------

# Matches lines like:
#   uint256 public totalSupply;
#   mapping(address => uint256) public balances;
#   address private owner;
#   bool _locked;
_STATE_VAR_RE = re.compile(
    r"^\s*"
    r"(uint\d*|int\d*|address|bool|bytes\d*|string|mapping\s*\([^)]+\))"
    r"\s+"
    r"(?:(public|private|internal|external)\s+)?"
    r"(\w+)"
    r"\s*[;=]",
)


def _extract_state_variables(stripped: str) -> list[dict]:
    """Extract top-level state variable declarations.

    Only scans lines that are *not* inside a function body (heuristic: zero
    brace depth means we are at contract scope).
    """
    variables = []
    depth = 0  # curly-brace nesting depth

    for lineno, line in enumerate(stripped.splitlines(), start=1):
        depth += line.count("{") - line.count("}")

        # State variables live at depth == 1 (inside the contract, outside functions).
        if depth != 1:
            continue

        m = _STATE_VAR_RE.match(line)
        if not m:
            continue

        var_type, visibility, name = m.group(1), m.group(2), m.group(3)

        # Normalize mapping type by collapsing internal whitespace.
        var_type = re.sub(r"\s+", " ", var_type.strip())

        variables.append(
            {
                "name": name,
                "type": var_type,
                "visibility": visibility if visibility else "internal",
                "line": lineno,
            }
        )

    return variables


# ---------------------------------------------------------------------------
# Function extraction
# ---------------------------------------------------------------------------

# Matches function / constructor / receive / fallback declarations.
# Captures: (func_keyword, name_or_empty, param_list, modifiers_and_returns)
_FUNC_DECL_RE = re.compile(
    r"\b(function|constructor|receive|fallback)\s*"
    r"(\w*)?\s*"           # optional name (empty for receive/fallback)
    r"\([^)]*\)\s*"        # parameter list
    r"([^{]*)"             # everything up to the opening brace (modifiers, returns)
)

_VISIBILITY_RE = re.compile(r"\b(public|private|internal|external)\b")
_MODIFIER_RE = re.compile(
    r"\b(?!public|private|internal|external|returns|virtual|override|pure|view|payable)([a-zA-Z_]\w+)\b"
)

_ETH_TRANSFER_RE = re.compile(
    r"\.send\(|\.transfer\(|\.call\s*\{[^}]*value"
)


def _extract_functions(stripped: str, raw_lines: list[str]) -> list[dict]:
    """Extract every function/constructor/receive/fallback from the contract.

    Uses a brace-counting approach to capture the full body of each function,
    then runs targeted regexes over that body slice.
    """
    functions = []
    lines = stripped.splitlines()

    i = 0
    while i < len(lines):
        line = lines[i]
        m = _FUNC_DECL_RE.search(line)

        if not m:
            i += 1
            continue

        # Collect the declaration head — may span multiple lines before '{'.
        decl_start = i
        decl_text = line
        j = i
        while "{" not in decl_text and j < len(lines) - 1:
            j += 1
            decl_text += "\n" + lines[j]

        # Determine function name.
        keyword = m.group(1)  # function / constructor / receive / fallback
        raw_name = m.group(2).strip() if m.group(2) else ""
        func_name = raw_name if raw_name else keyword

        # Determine visibility from the declaration head.
        vis_match = _VISIBILITY_RE.search(decl_text)
        visibility = vis_match.group(1) if vis_match else "public"

        # Modifiers are identifier tokens in the tail (after param list) that
        # are NOT Solidity keywords. Strip `returns (...)` first so return-type
        # identifiers like `uint256` or `bool` are not mistaken for modifiers.
        tail = m.group(3) if m.group(3) else ""
        tail = re.sub(r"\breturns\s*\([^)]*\)", "", tail)
        keywords_to_skip = {
            "public", "private", "internal", "external",
            "returns", "virtual", "override", "pure", "view", "payable",
        }
        modifiers = [
            tok
            for tok in _MODIFIER_RE.findall(tail)
            if tok not in keywords_to_skip
        ]

        # Find the opening '{' and collect the body via brace counting.
        body_lines = []
        depth = 0
        found_open = False
        k = j  # start scanning from where the decl head ended

        while k < len(lines):
            segment = lines[k]
            for ch in segment:
                if ch == "{":
                    depth += 1
                    found_open = True
                elif ch == "}":
                    depth -= 1

            if found_open:
                body_lines.append(segment)

            if found_open and depth == 0:
                break
            k += 1

        body = "\n".join(body_lines)

        # Check for ETH transfer patterns inside the body.
        has_eth_transfer = bool(_ETH_TRANSFER_RE.search(body))

        # Use original (non-stripped) lines for the body so comments are visible.
        raw_body_lines = raw_lines[decl_start : k + 1]
        raw_body = "\n".join(raw_body_lines)

        functions.append(
            {
                "name": func_name,
                "visibility": visibility,
                "modifiers": modifiers,
                "has_eth_transfer": has_eth_transfer,
                "line_start": decl_start + 1,  # 1-indexed
                "body": raw_body,
            }
        )

        i = k + 1  # advance past the function we just consumed

    return functions


# ---------------------------------------------------------------------------
# External call extraction
# ---------------------------------------------------------------------------

_EXTERNAL_CALL_RE = re.compile(
    r"\.(?P<call_type>send|transfer|call|delegatecall|staticcall)\b"
)


def _extract_external_calls(stripped: str) -> list[dict]:
    """Find every line containing a low-level external call."""
    calls = []
    for lineno, line in enumerate(stripped.splitlines(), start=1):
        for m in _EXTERNAL_CALL_RE.finditer(line):
            calls.append(
                {
                    "line": lineno,
                    "snippet": line.strip(),
                    "call_type": m.group("call_type"),
                }
            )
    return calls


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_contract(file_path: str | os.PathLike) -> dict | None:
    """Parse a Solidity source file and return a structured representation.

    Parameters
    ----------
    file_path:
        Path to a .sol file.

    Returns
    -------
    dict with keys:
        source                  — raw source string
        contract_name           — first contract name in the file
        pragma                  — solidity version string (e.g. "^0.8.20")
        functions               — list of function descriptor dicts
        state_variables         — list of state variable descriptor dicts
        external_calls          — list of external-call descriptor dicts
        comments_stripped_source — source with all comments removed

    Returns None if the file cannot be read.
    """
    try:
        source = Path(file_path).read_text(encoding="utf-8")
    except (FileNotFoundError, OSError):
        return None

    stripped = _strip_comments(source)
    raw_lines = source.splitlines()

    return {
        "source": source,
        "contract_name": _extract_contract_name(stripped),
        "pragma": _extract_pragma(stripped),
        "functions": _extract_functions(stripped, raw_lines),
        "state_variables": _extract_state_variables(stripped),
        "external_calls": _extract_external_calls(stripped),
        "comments_stripped_source": stripped,
    }
