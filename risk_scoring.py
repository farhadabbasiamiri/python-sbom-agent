


# risk_scoring.py

SEVERITY_SCORES = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MODERATE": 4,
    "MEDIUM": 4,
    "LOW": 1
}

def calculate_risk_score(unique_vulnerabilities):
    """
    Custom risk score out of 10.

    Severity: 65%
    Vulnerability count: 25%
    Missing reported fixes: 10%
    """

    records = list(unique_vulnerabilities.values())
    count = len(records)

    if count == 0:
        return {
            "risk_score": 0.0,
            "severity_component": 0.0,
            "count_component": 0.0,
            "fix_component": 0.0,
            "unique_vulnerabilities": 0,
            "without_reported_fixes": 0
        }

    # Factor 1: Highest severity (65%)
    severity_values = [
        SEVERITY_SCORES.get(
            str(record.get("severity", "")).upper(), 0
        )
        for record in records
    ]

    highest_severity = max(severity_values)
    severity_component = highest_severity * 0.65

    # Factor 2: Number of vulnerabilities (25%)
    count_component = min(count, 10) / 10 * 2.5

    # Factor 3: Missing reported fixes (10%)
    without_fixes = sum(
        1 for record in records
        if not record.get("fixed_versions")
    )

    fix_component = (without_fixes / count) * 1.0

    final_score = min(
        10,
        severity_component + count_component + fix_component
    )

    return {
        "risk_score": round(final_score, 2),
        "severity_component": round(severity_component, 2),
        "count_component": round(count_component, 2),
        "fix_component": round(fix_component, 2),
        "unique_vulnerabilities": count,
        "without_reported_fixes": without_fixes
    }
