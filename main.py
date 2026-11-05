
import json
import requests

from backend.ai_agent import analyze_scan_results
from packaging.version import Version
from remediation import extract_fixed_versions, recommend_upgrade
from risk_scoring import calculate_risk_score

# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

DEPENDENCY_FILE = "requirments.txt"
OUTPUT_FILE = "scan_results.json"

# Set this to the Python version your application targets.
TARGET_PYTHON_VERSION = "3.13"

scan_results = []

severity_scores = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MODERATE": 4,
    "MEDIUM": 4,
    "LOW": 1
}

severity_rank = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MODERATE": 2,
    "MEDIUM": 2,
    "LOW": 1
}


# --------------------------------------------------
# READ DEPENDENCIES
# --------------------------------------------------

with open(DEPENDENCY_FILE, "r") as file:
    dependencies = file.readlines()


# --------------------------------------------------
# SCAN EACH DEPENDENCY
# --------------------------------------------------

for dependency in dependencies:

    dependency = dependency.strip()

    if not dependency or dependency.startswith("#"):
        continue

    if "==" not in dependency:
        continue

    package_name, version = [
        part.strip()
        for part in dependency.split("==", 1)
    ]

    print(f"\nScanning {package_name} version {version}")

    payload = {
        "package": {
            "name": package_name,
            "ecosystem": "PyPI"
        },
        "version": version
    }

    try:
        response = requests.post(
            "https://api.osv.dev/v1/query",
            json=payload,
            timeout=15
        )

        response.raise_for_status()

        vulnerabilities = response.json().get("vulns", [])

        unique_vulnerabilities = {}

        # Group records with matching CVE identifiers.
        for vulnerability in vulnerabilities:

            aliases = vulnerability.get("aliases", [])

            cve_ids = sorted(
                alias
                for alias in [vulnerability.get("id", "")] + aliases
                if alias.startswith("CVE-")
            )

            key = tuple(cve_ids) if cve_ids else vulnerability["id"]

            if key not in unique_vulnerabilities:
                unique_vulnerabilities[key] = {
                    "id": vulnerability["id"],
                    "cve": ", ".join(cve_ids) or "Not available",
                    "description": "Not available",
                    "severity": "Not available",
                    "fixed_versions": set()
                }

            record = unique_vulnerabilities[key]

            # Keep an available description.
            summary = vulnerability.get("summary")

            if summary and record["description"] == "Not available":
                record["description"] = summary

            # Keep the highest available severity label.
            severity = vulnerability.get(
                "database_specific", {}
            ).get("severity", "")

            severity = str(severity).upper()

            current = record["severity"].upper()

            if severity_rank.get(severity, 0) > severity_rank.get(current, 0):
                record["severity"] = severity

            # Rehnuma's existing fixed-version extraction.
            fixes = extract_fixed_versions(
                vulnerability,
                package_name
            )

            record["fixed_versions"].update(fixes)

        # --------------------------------------------------
        # PRELIMINARY RISK SCORING
        # --------------------------------------------------

            # Improved risk scoring
        risk_details = calculate_risk_score(unique_vulnerabilities)
        package_score = risk_details["risk_score"]
        


        print(f"OSV records: {len(vulnerabilities)}")
        print(
            f"Unique vulnerability groups: "
            f"{len(unique_vulnerabilities)}"
        )

        print("\n========== PACKAGE RISK SUMMARY ==========")
        print(f"Package: {package_name}")
        print(f"Version: {version}")

        if package_score is None:
            print("Preliminary risk score: Not rated")
        else:
            print(f"Preliminary risk score: {package_score}/10")

        print("==========================================")

        # --------------------------------------------------
        # PREPARE JSON OUTPUT
        # --------------------------------------------------

        package_result = {
        "package": package_name,
        "version": version,
        "osv_records": len(vulnerabilities),
        "unique_vulnerability_count": len(unique_vulnerabilities),
        "risk_score": package_score,
        "risk_details": risk_details,
        "vulnerabilities": []
        }   

        for record in unique_vulnerabilities.values():

            # Correct numerical version sorting.
            fixed_versions = sorted(
                record["fixed_versions"],
                key=Version
            )

            package_result["vulnerabilities"].append({
                "id": record["id"],
                "cve": record["cve"],
                "description": record["description"],
                "severity": record["severity"],
                "reported_fixed_versions": fixed_versions
            })

            print(f"\nCVE: {record['cve']}")
            print(f"Description: {record['description']}")
            print(f"Severity: {record['severity']}")
            print(f"Reported fixed versions: {fixed_versions}")
            print("-" * 45)

        # ==================================================
        # NEW: PHASE 3 AUTOMATIC UPGRADE RECOMMENDATIONS
        # ==================================================

        print("\n========== UPGRADE RECOMMENDATION ==========")

        upgrade_result = recommend_upgrade(
            package_name,
            version,
            python_version=TARGET_PYTHON_VERSION,
            max_candidates=5
        )

        # Include Phase 3 results in JSON.
        package_result["upgrade_recommendation"] = upgrade_result

        print(
            "Upgrade status:",
            upgrade_result.get("status")
        )

        print(
            "Recommended candidate:",
            upgrade_result.get("recommended_candidate")
        )

        print(
            "Target Python:",
            upgrade_result.get("target_python")
        )

        if upgrade_result.get("warning"):
            print("Warning:", upgrade_result["warning"])

        print("============================================")

        # Add complete result for this package.
        scan_results.append(package_result)

    except (requests.RequestException, ValueError) as error:
        print(f"API request failed: {error}")


# --------------------------------------------------
# EXPORT SCAN RESULTS
# --------------------------------------------------

scan_results = analyze_scan_results(scan_results)

for package_result in scan_results:
    analysis = package_result["agent_analysis"]
    print(f"\nAI agent analysis: {analysis['summary']}")
    for action in analysis["recommended_actions"]:
        print(f"- {action}")

with open(OUTPUT_FILE, "w") as file:
    json.dump(scan_results, file, indent=4)

print(f"\nScan results saved to {OUTPUT_FILE}")
