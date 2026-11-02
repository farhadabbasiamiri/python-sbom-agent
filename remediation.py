
import requests
from packaging.version import Version, InvalidVersion


def extract_fixed_versions(vulnerability, package_name):
    """
    Extract valid Python package fixed versions from OSV.
    Ignore Git commit hashes and invalid version strings.
    """

    fixed_versions = set()

    for affected in vulnerability.get("affected", []):
        package = affected.get("package", {})

        if package.get("ecosystem") != "PyPI":
            continue

        if package.get("name", "").lower() != package_name.lower():
            continue

        for version_range in affected.get("ranges", []):

            # Git ranges contain commit identifiers, not PyPI versions.
            if version_range.get("type") != "ECOSYSTEM":
                continue

            for event in version_range.get("events", []):
                fixed = event.get("fixed")

                if not fixed:
                    continue

                try:
                    valid_version = Version(fixed)

                    # Keep valid Python package version strings
                    fixed_versions.add(str(valid_version))

                except InvalidVersion:
                    # Ignore invalid release identifiers
                    continue

    # Sort versions numerically, not alphabetically
    return sorted(fixed_versions, key=Version)


def get_fixed_versions(vulnerability_id, package_name):
    """
    Fetch an OSV advisory and return its fixed versions.
    """

    url = f"https://api.osv.dev/v1/vulns/{vulnerability_id}"

    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()

        vulnerability = response.json()

        return {
            "vulnerability_id": vulnerability_id,
            "package": package_name,
            "reported_fixed_versions": extract_fixed_versions(
                vulnerability, package_name
            )
        }

    except (requests.RequestException, ValueError) as error:
        return {
            "vulnerability_id": vulnerability_id,
            "package": package_name,
            "error": str(error)
        }


if __name__ == "__main__":
    test_cases = [
        ("GHSA-2gwj-7jmv-h26r", "django"),
        ("GHSA-j8r2-6x86-q33q", "requests")
    ]

    for vulnerability_id, package_name in test_cases:
        result = get_fixed_versions(
            vulnerability_id,
            package_name
        )

        print("\nRemediation Results")
        print("-" * 40)
        print(result)
