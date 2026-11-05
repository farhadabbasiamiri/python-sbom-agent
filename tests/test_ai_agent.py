import unittest

from backend.ai_agent import SBOMSecurityAgent


class SBOMSecurityAgentTests(unittest.TestCase):
    def setUp(self):
        self.agent = SBOMSecurityAgent()

    def test_prioritizes_high_risk_findings_and_upgrade(self):
        package = {
            "package": "example",
            "version": "1.0",
            "risk_score": 8.5,
            "unique_vulnerability_count": 2,
            "vulnerabilities": [
                {"severity": "CRITICAL", "reported_fixed_versions": ["2.0"]},
                {"severity": "HIGH", "reported_fixed_versions": []},
            ],
            "upgrade_recommendation": {
                "status": "POTENTIAL_UPGRADE",
                "package": "example",
                "recommended_candidate": "2.0",
            },
        }

        result = self.agent.analyze_package(package)

        self.assertEqual(result["risk_level"], "CRITICAL")
        self.assertEqual(result["severity_counts"]["CRITICAL"], 1)
        self.assertEqual(result["severity_counts"]["HIGH"], 1)
        self.assertEqual(len(result["recommended_actions"]), 3)
        self.assertIn("2.0", result["recommended_actions"][2])

    def test_clean_package_gets_monitoring_action(self):
        result = self.agent.analyze_package(
            {"package": "clean-package", "version": "1.0", "risk_score": 0}
        )

        self.assertEqual(result["risk_level"], "LOW")
        self.assertEqual(result["vulnerability_count"], 0)
        self.assertIn("no known vulnerabilities", result["summary"])
        self.assertEqual(len(result["recommended_actions"]), 1)

    def test_invalid_score_uses_vulnerability_severity(self):
        result = self.agent.analyze_package(
            {
                "risk_score": float("nan"),
                "vulnerabilities": [{"severity": "MEDIUM"}],
            }
        )

        self.assertIsNone(result["risk_score"])
        self.assertEqual(result["risk_level"], "MODERATE")
        self.assertEqual(result["severity_counts"]["MODERATE"], 1)

    def test_critical_finding_is_not_downgraded_by_composite_score(self):
        result = self.agent.analyze_package(
            {
                "risk_score": 6.6,
                "vulnerabilities": [{"severity": "CRITICAL"}],
            }
        )

        self.assertEqual(result["risk_level"], "CRITICAL")

    def test_scan_analysis_enriches_without_mutating_input(self):
        package = {"package": "example", "vulnerabilities": []}

        results = self.agent.analyze_scan_results([package])

        self.assertIn("agent_analysis", results[0])
        self.assertNotIn("agent_analysis", package)

    def test_scan_analysis_rejects_non_mapping_records(self):
        with self.assertRaisesRegex(TypeError, "index 0"):
            self.agent.analyze_scan_results([None])


if __name__ == "__main__":
    unittest.main()
