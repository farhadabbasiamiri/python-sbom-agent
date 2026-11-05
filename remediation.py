
import requests
from packaging.version import Version, InvalidVersion

# >>> NEW IMPORTS FOR AUTOMATIC UPGRADE RECOMMENDATIONS
from packaging.specifiers import SpecifierSet, InvalidSpecifier
from packaging.utils import canonicalize_name
import sys
# <<< END NEW IMPORTS


# ==================================================
# PHASE 2: FIXED VERSION EXTRACTION
# EXISTING CODE - UNCHANGED
# ==================================================

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


# ==================================================
# PHASE 3: UPGRADE VALIDATION
# EXISTING CODE - UNCHANGED
# ==================================================

def validate_upgrade(package_name, installed_version, candidate_version):
    """
    Check whether a proposed upgrade still has known
    vulnerabilities reported by OSV.

    This function does not install or modify packages.
    """

    try:
        installed = Version(installed_version)
        candidate = Version(candidate_version)

        if candidate <= installed:
            return {
                "status": "INVALID_UPGRADE",
                "message": "Candidate must be newer than installed version."
            }

    except InvalidVersion:
        return {
            "status": "INVALID_VERSION",
            "message": "Invalid package version."
        }

    payload = {
        "package": {
            "name": package_name,
            "ecosystem": "PyPI"
        },
        "version": str(candidate)
    }

    try:
        vulnerability_ids = set()
        page_token = None

        while True:
            query = payload.copy()

            if page_token:
                query["page_token"] = page_token

            response = requests.post(
                "https://api.osv.dev/v1/query",
                json=query,
                timeout=30
            )

            response.raise_for_status()
            data = response.json()

            for vulnerability in data.get("vulns", []):
                vulnerability_ids.add(vulnerability["id"])

            page_token = data.get("next_page_token")

            if not page_token:
                break

        return {
            "package": package_name,
            "installed_version": installed_version,
            "candidate_version": str(candidate),
            "remaining_osv_records": len(vulnerability_ids),
            "status": (
                "NO_KNOWN_OSV_FINDINGS"
                if len(vulnerability_ids) == 0
                else "VULNERABILITIES_REMAIN"
            ),
            "vulnerability_ids": sorted(vulnerability_ids)
        }

    except (requests.RequestException, ValueError, KeyError) as error:
        return {
            "status": "CHECK_FAILED",
            "message": str(error)
        }


# ==================================================
# PHASE 3: PYPI RELEASE VERIFICATION
# EXISTING CODE - UNCHANGED
# ==================================================

def verify_pypi_release(package_name, candidate_version):
    """
    Verify that a candidate version exists on PyPI
    and check whether its distribution files are yanked.

    This does not guarantee compatibility or security.
    """

    try:
        version = Version(candidate_version)

    except InvalidVersion:
        return {
            "status": "INVALID_VERSION",
            "message": "Invalid package version."
        }

    url = f"https://pypi.org/pypi/{package_name}/{version}/json"

    try:
        response = requests.get(url, timeout=15)

        if response.status_code == 404:
            return {
                "status": "RELEASE_NOT_FOUND",
                "message": "This release was not found on PyPI."
            }

        response.raise_for_status()
        data = response.json()

        files = data.get("urls", [])

        if not files:
            return {
                "status": "NO_DISTRIBUTION_FILES",
                "message": "No downloadable distribution files found."
            }

        if all(file.get("yanked", False) for file in files):
            return {
                "status": "YANKED_RELEASE",
                "message": "All distribution files are yanked."
            }

        return {
            "package": package_name,
            "candidate_version": str(version),
            "status": "RELEASE_AVAILABLE",
            "requires_python": data.get(
                "info", {}
            ).get("requires_python")
        }

    except (requests.RequestException, ValueError) as error:
        return {
            "status": "CHECK_FAILED",
            "message": str(error)
        }


# ==================================================
# >>> NEW PHASE 3 FEATURE STARTS HERE <<<
# AUTOMATIC UPGRADE RECOMMENDATIONS
# ==================================================

def recommend_upgrade(
    package_name,
    installed_version,
    python_version=None,
    max_candidates=10
):
    """
    Find a newer PyPI release with no known OSV findings.

    Checks at most max_candidates recent stable releases.
    Does not install packages or guarantee compatibility.
    """

    if python_version is None:
        python_version = (
            f"{sys.version_info.major}.{sys.version_info.minor}"
        )

    try:
        installed = Version(installed_version)
        target_python = Version(python_version)

        if not isinstance(max_candidates, int) or max_candidates < 1:
            return {
                "status": "INVALID_LIMIT",
                "message": "max_candidates must be a positive integer."
            }

    except InvalidVersion:
        return {
            "status": "INVALID_VERSION",
            "message": "Invalid installed or Python version."
        }

    package_name = canonicalize_name(package_name)

    # STEP A: Retrieve available package releases from PyPI.
    try:
        response = requests.get(
            f"https://pypi.org/pypi/{package_name}/json",
            timeout=20
        )

        if response.status_code == 404:
            return {
                "status": "PACKAGE_NOT_FOUND",
                "package": package_name
            }

        response.raise_for_status()
        releases = response.json().get("releases", {})

    except (requests.RequestException, ValueError) as error:
        return {
            "status": "PYPI_CHECK_FAILED",
            "message": str(error)
        }

    # STEP B: Find newer, stable, non-yanked releases
    # with at least one compatible distribution.
    candidates = []

    for version_string, files in releases.items():
        try:
            version = Version(version_string)
        except InvalidVersion:
            continue

        if (
            version <= installed
            or version.is_prerelease
            or version.is_devrelease
        ):
            continue

        if not isinstance(files, list) or not files:
            continue

        compatible_files = []

        for file in files:
            if file.get("yanked", False):
                continue

            requirement = file.get("requires_python")

            if requirement:
                try:
                    supported = (
                        target_python in SpecifierSet(requirement)
                    )
                except InvalidSpecifier:
                    continue

                if not supported:
                    continue

            compatible_files.append(file)

        if compatible_files:
            candidates.append((version, version_string))

    # STEP C: Check the newest candidate versions first.
    candidates.sort(
        key=lambda item: item[0],
        reverse=True
    )

    checked = []
    selected = None

    for version, version_string in candidates[:max_candidates]:
        result = validate_upgrade(
            package_name,
            installed_version,
            version_string
        )

        checked.append({
            "version": version_string,
            "status": result["status"],
            "remaining_osv_records": result.get(
                "remaining_osv_records"
            )
        })

        if result["status"] == "NO_KNOWN_OSV_FINDINGS":
            selected = version_string
            break

    # STEP D: Return the potential upgrade.
    if selected:
        return {
            "package": package_name,
            "installed_version": installed_version,
            "target_python": str(target_python),
            "recommended_candidate": selected,
            "status": "POTENTIAL_UPGRADE",
            "checked_candidates": checked,
            "warning": (
                "No known OSV findings for this candidate. "
                "Application dependency compatibility and "
                "runtime behavior still require testing."
            )
        }

    return {
        "package": package_name,
        "installed_version": installed_version,
        "target_python": str(target_python),
        "recommended_candidate": None,
        "status": "NO_VALIDATED_CANDIDATE",
        "checked_candidates": checked,
        "warning": (
            "No candidate without known OSV findings was "
            "identified among the checked releases. "
            "Additional releases or investigation may be needed."
        )
    }


# ==================================================
# >>> END OF NEW PHASE 3 FEATURE <<<
# ==================================================


# ==================================================
# ORIGINAL TEST CASES - UNCHANGED
# ==================================================

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
