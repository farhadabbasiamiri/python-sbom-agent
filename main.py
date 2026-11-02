
import json
import requests

from remediation import extract_fixed_versions


# Read the dependency file
DEPENDENCY_FILE = "requirments.txt"

with open(DEPENDENCY_FILE, "r") as file:
    dependencies = file.readlines()

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


# Scan every dependency
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

        # Group records with matching CVE identifiers
        for vulnerability in vulnerabilities:
            aliases = vulnerability.get("aliases", [])

            cve_ids = sorted(
                alias for alias in [vulnerability.get("id", "")] + aliases
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

            # Keep an available description
            summary = vulnerability.get("summary")

            if summary and record["description"] == "Not available":
                record["description"] = summary

            # Keep the highest available severity label
            severity = vulnerability.get(
                "database_specific", {}
            ).get("severity", "")

            severity = str(severity).upper()

            current = record["severity"].upper()

            if severity_rank.get(severity, 0) > severity_rank.get(current, 0):
                record["severity"] = severity

            # Use Rehnuma's remediation module
            fixes = extract_fixed_versions(
                vulnerability,
                package_name
            )

            record["fixed_versions"].update(fixes)

        # Preliminary risk scoring
        scores = []

        for record in unique_vulnerabilities.values():
            severity = record["severity"].upper()
            score = severity_scores.get(severity)

            if score is not None:
                scores.append(score)

        package_score = max(scores) if scores else None

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

        # Prepare JSON output
        package_result = {
            "package": package_name,
            "version": version,
            "osv_records": len(vulnerabilities),
            "unique_vulnerability_count": len(unique_vulnerabilities),
            "risk_score": package_score,
            "vulnerabilities": []
        }

        for record in unique_vulnerabilities.values():
            fixed_versions = sorted(record["fixed_versions"])

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

        scan_results.append(package_result)

    except (requests.RequestException, ValueError) as error:
        print(f"API request failed: {error}")


# Export scan results
with open("scan_results.json", "w") as file:
    json.dump(scan_results, file, indent=4)

print("\nScan results saved to scan_results.json")
