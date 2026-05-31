"""Severity classification utilities shared by the static analyzer and auditor agent."""

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEVERITY_ORDER: dict[str, int] = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Informational": 4,
}

SEVERITY_COLORS: dict[str, str] = {
    "Critical": "#FF4444",
    "High": "#FF8800",
    "Medium": "#FFCC00",
    "Low": "#4499FF",
    "Informational": "#888888",
}

# Canonical capitalization mapping — used by normalize_severity.
_SEVERITY_CANONICAL: dict[str, str] = {
    label.lower(): label for label in SEVERITY_ORDER
}

# ---------------------------------------------------------------------------
# Functions
# ---------------------------------------------------------------------------

def normalize_severity(value: str) -> str:
    """Return the canonical severity label for any casing of a severity string.

    Parameters
    ----------
    value:
        A severity string in any case, e.g. "critical", "HIGH", "Medium".

    Returns
    -------
    The properly capitalized label ("Critical", "High", "Medium", "Low",
    or "Informational").  Unrecognized values default to "Informational".
    """
    return _SEVERITY_CANONICAL.get(value.strip().lower(), "Informational")


def sort_findings(findings: list[dict]) -> list[dict]:
    """Sort findings by severity, Critical first and Informational last.

    Uses a stable sort so findings of equal severity preserve their original
    relative order.

    Parameters
    ----------
    findings:
        List of finding dicts, each expected to have a "severity" key.

    Returns
    -------
    A new sorted list (the original list is not mutated).
    """
    return sorted(
        findings,
        key=lambda f: SEVERITY_ORDER.get(f.get("severity", "Informational"), 99),
    )


def score_contract(findings: list[dict]) -> dict:
    """Compute a risk summary for a contract from its findings list.

    The overall_risk is the highest severity present across all findings.
    If there are no findings the contract is rated "Clean".

    Parameters
    ----------
    findings:
        List of finding dicts produced by the static analyzer or agent.

    Returns
    -------
    Dict with keys: overall_risk, total_findings, critical_count,
    high_count, medium_count, low_count, informational_count.
    """
    counts: dict[str, int] = {
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "informational_count": 0,
    }

    _key_map = {
        "Critical": "critical_count",
        "High": "high_count",
        "Medium": "medium_count",
        "Low": "low_count",
        "Informational": "informational_count",
    }

    for finding in findings:
        severity = normalize_severity(finding.get("severity", ""))
        counts[_key_map[severity]] += 1

    # Overall risk = highest severity with at least one finding.
    overall_risk = "Clean"
    for label in ("Critical", "High", "Medium", "Low", "Informational"):
        if counts[_key_map[label]] > 0:
            overall_risk = label
            break

    return {
        "overall_risk": overall_risk,
        "total_findings": len(findings),
        **counts,
    }
