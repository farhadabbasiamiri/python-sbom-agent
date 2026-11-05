"""Explainable, local security analysis for Python SBOM scan results."""

from collections.abc import Mapping, Sequence
from math import isfinite
from typing import Any


_SEVERITY_LEVELS = ("CRITICAL", "HIGH", "MODERATE", "LOW", "UNKNOWN")


class SBOMSecurityAgent:
    """Turn scanner output into prioritized, evidence-based actions."""

    def analyze_package(self, package: Mapping[str, Any]) -> dict[str, Any]:
        name = self._text(package.get("package")) or "Unknown package"
        version = self._text(package.get("version")) or "unknown"
        vulnerabilities = self._vulnerability_records(
            package.get("vulnerabilities")
        )

        severity_counts = dict.fromkeys(_SEVERITY_LEVELS, 0)
        severity_rank = {
            "CRITICAL": 4,
            "HIGH": 3,
            "MODERATE": 2,
            "MEDIUM": 2,
            "LOW": 1,
        }
        for vulnerability in vulnerabilities:
            severity = self._text(vulnerability.get("severity")).upper()
            normalized = "MODERATE" if severity == "MEDIUM" else severity
            if normalized in severity_rank:
                severity_counts[normalized] += 1
            else:
                severity_counts["UNKNOWN"] += 1

        count = self._nonnegative_int(
            package.get("unique_vulnerability_count"), len(vulnerabilities)
        )
        score = self._risk_score(package.get("risk_score"))
        risk_level = self._risk_level(score, severity_counts, count)
        actions = self._recommended_actions(
            vulnerabilities, severity_counts, package.get("upgrade_recommendation")
        )

        if count == 0:
            summary = (
                f"{name} {version} has no known vulnerabilities in this scan."
            )
        else:
            summary = (
                f"{name} {version} has {count} known vulnerability group(s); "
                f"the assessed risk is {risk_level}."
            )

        if score is not None:
            summary += f" Risk score: {score:g}/10."

        return {
            "risk_level": risk_level,
            "risk_score": score,
            "vulnerability_count": count,
            "severity_counts": severity_counts,
            "summary": summary,
            "recommended_actions": actions,
        }

    def analyze_scan_results(
        self, packages: Sequence[Mapping[str, Any]]
    ) -> list[dict[str, Any]]:
        """Return scan records enriched with per-package agent analysis."""
        if isinstance(packages, (str, bytes)) or not isinstance(packages, Sequence):
            raise TypeError("packages must be a sequence of package scan records")

        analyzed: list[dict[str, Any]] = []
        for index, package in enumerate(packages):
            if not isinstance(package, Mapping):
                raise TypeError(
                    f"package scan record at index {index} must be a mapping"
                )

            result = dict(package)
            result["agent_analysis"] = self.analyze_package(package)
            analyzed.append(result)
        return analyzed

    @staticmethod
    def _vulnerability_records(value: object) -> list[Mapping[str, Any]]:
        if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
            return []
        return [record for record in value if isinstance(record, Mapping)]

    @staticmethod
    def _text(value: object) -> str:
        return value.strip() if isinstance(value, str) else ""

    @staticmethod
    def _nonnegative_int(value: object, default: int) -> int:
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            return value
        return default

    @staticmethod
    def _risk_score(value: object) -> float | None:
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            return float(value) if 0 <= value <= 10 else None
        if not isinstance(value, float) or not isfinite(value) or not 0 <= value <= 10:
            return None
        return value

    @staticmethod
    def _risk_level(
        score: float | None,
        severity_counts: Mapping[str, int],
        vulnerability_count: int,
    ) -> str:
        score_level = "UNKNOWN"
        if score is not None:
            if score >= 8:
                score_level = "CRITICAL"
            elif score >= 6:
                score_level = "HIGH"
            elif score >= 3:
                score_level = "MODERATE"
            else:
                score_level = "LOW"

        if severity_counts["CRITICAL"]:
            severity_level = "CRITICAL"
        elif severity_counts["HIGH"]:
            severity_level = "HIGH"
        elif severity_counts["MODERATE"]:
            severity_level = "MODERATE"
        elif severity_counts["LOW"] or vulnerability_count == 0:
            severity_level = "LOW"
        else:
            severity_level = "UNKNOWN"

        levels = {
            "UNKNOWN": 0,
            "LOW": 1,
            "MODERATE": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }
        return max((score_level, severity_level), key=levels.__getitem__)

    @staticmethod
    def _recommended_actions(
        vulnerabilities: list[Mapping[str, Any]],
        severity_counts: Mapping[str, int],
        upgrade_recommendation: object,
    ) -> list[str]:
        actions: list[str] = []
        critical_or_high = severity_counts["CRITICAL"] + severity_counts["HIGH"]

        if critical_or_high:
            actions.append(
                f"Prioritize review and remediation of the {critical_or_high} "
                "critical/high-severity finding(s)."
            )

        fixed_versions = sorted(
            {
                version
                for vulnerability in vulnerabilities
                for version in SBOMSecurityAgent._text_list(
                    vulnerability.get("reported_fixed_versions")
                )
            }
        )
        if fixed_versions:
            actions.append(
                "Review the reported fixed versions, select a version compatible "
                "with the application, then test and rescan."
            )
        elif vulnerabilities:
            actions.append(
                "No reported fixed version is available in these scan records; "
                "check the advisory details and monitor for an upstream fix."
            )

        if isinstance(upgrade_recommendation, Mapping):
            candidate = SBOMSecurityAgent._text(
                upgrade_recommendation.get("recommended_candidate")
            )
            status = SBOMSecurityAgent._text(
                upgrade_recommendation.get("status")
            )
            package_name = SBOMSecurityAgent._text(
                upgrade_recommendation.get("package")
            )
            if status == "POTENTIAL_UPGRADE" and candidate:
                actions.append(
                    f"Evaluate {package_name or 'the package'} {candidate}; the "
                    "scanner reported no known OSV findings for it. Test "
                    "application compatibility and rescan before adopting it."
                )
            elif vulnerabilities and status == "NO_VALIDATED_CANDIDATE":
                actions.append(
                    "No candidate without known OSV findings was validated; "
                    "review the checked releases and rerun the upgrade check later."
                )

        if not actions:
            actions.append(
                "Keep the dependency inventory current and rescan when packages "
                "or advisory data change."
            )
        return actions

    @staticmethod
    def _text_list(value: object) -> list[str]:
        if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
            return []
        return [
            item.strip()
            for item in value
            if isinstance(item, str) and item.strip()
        ]


def analyze_package(package: Mapping[str, Any]) -> dict[str, Any]:
    """Convenience function to analyze one package scan record."""
    return SBOMSecurityAgent().analyze_package(package)


def analyze_scan_results(
    packages: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Convenience function to enrich a complete scan result."""
    return SBOMSecurityAgent().analyze_scan_results(packages)