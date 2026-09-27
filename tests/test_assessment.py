"""
Tests for the NETWATCH Phase 12 Security Assessment Engine.
"""

import unittest

from assessment.assessment_engine import (
    AssessmentEngine,
    AssessmentResult,
    FindingSummary,
    format_assessment_result,
)


class AssessmentEngineTests(unittest.TestCase):

    def setUp(self):
        self.engine = AssessmentEngine()

    def test_finding_summary(self):
        summary = FindingSummary()

        summary.add("INFO")
        summary.add("LOW")
        summary.add("MEDIUM")
        summary.add("HIGH")
        summary.add("CRITICAL")

        self.assertEqual(summary.info, 1)
        self.assertEqual(summary.low, 1)
        self.assertEqual(summary.medium, 1)
        self.assertEqual(summary.high, 1)
        self.assertEqual(summary.critical, 1)
        self.assertEqual(summary.total, 5)

    def test_empty_assessment(self):
        result = self.engine.build_assessment(
            scope="192.168.0.0/24"
        )

        self.assertIsInstance(
            result,
            AssessmentResult,
        )

        self.assertEqual(
            result.scope,
            "192.168.0.0/24",
        )

        self.assertEqual(
            result.device_count,
            0,
        )

        self.assertEqual(
            result.total_findings,
            0,
        )

    def test_invalid_scope(self):
        with self.assertRaises(ValueError):
            self.engine.build_assessment(
                scope="not-a-network"
            )

    def test_empty_scope(self):
        with self.assertRaises(ValueError):
            self.engine.build_assessment(
                scope=""
            )

    def test_sample_assessment(self):
        result = self.engine.build_sample_assessment()

        self.assertEqual(
            result.device_count,
            3,
        )

        self.assertEqual(
            result.open_port_count,
            2,
        )

        self.assertEqual(
            len(result.detected_services),
            2,
        )

        self.assertEqual(
            len(result.dns_findings),
            1,
        )

        self.assertEqual(
            len(result.http_findings),
            1,
        )

        self.assertEqual(
            len(result.traffic_findings),
            1,
        )

        self.assertEqual(
            result.alert_count,
            2,
        )

        self.assertEqual(
            result.firewall_finding_count,
            1,
        )

        self.assertEqual(
            result.finding_summary.info,
            2,
        )

        self.assertEqual(
            result.finding_summary.low,
            1,
        )

        self.assertEqual(
            result.finding_summary.medium,
            1,
        )

        self.assertEqual(
            result.finding_summary.high,
            2,
        )

        self.assertEqual(
            result.finding_summary.critical,
            0,
        )

        self.assertEqual(
            result.total_findings,
            6,
        )

    def test_severity_normalization(self):
        result = self.engine.build_assessment(
            scope="10.0.0.0/24",
            ids_alerts=[
                {
                    "severity": "high",
                    "description": "Test",
                },
                {
                    "severity": "MEDIUM",
                    "description": "Test",
                },
            ],
        )

        self.assertEqual(
            result.finding_summary.high,
            1,
        )

        self.assertEqual(
            result.finding_summary.medium,
            1,
        )

    def test_unknown_severity_is_ignored(self):
        result = self.engine.build_assessment(
            scope="10.0.0.0/24",
            ids_alerts=[
                {
                    "severity": "UNKNOWN",
                    "description": "Test",
                },
            ],
        )

        self.assertEqual(
            result.total_findings,
            0,
        )

    def test_recommendations(self):
        result = self.engine.build_assessment(
            scope="192.168.1.0/24",
            open_ports=[
                {
                    "port": 22,
                    "state": "OPEN",
                }
            ],
            ids_alerts=[
                {
                    "severity": "HIGH",
                    "description": "Test alert",
                }
            ],
            firewall_findings=[
                {
                    "severity": "MEDIUM",
                    "title": "Broad rule",
                }
            ],
        )

        self.assertGreaterEqual(
            len(result.recommendations),
            3,
        )

    def test_topology_information(self):
        result = self.engine.build_assessment(
            scope="192.168.0.0/24",
            topology_information={
                "available": True,
                "nodes": 6,
                "connections": 5,
            },
        )

        self.assertTrue(
            result.topology_information["available"]
        )

        self.assertEqual(
            result.topology_information["nodes"],
            6,
        )

    def test_dataclass_input(self):
        finding = FindingSummary(
            medium=1,
            high=2,
        )

        result = self.engine.build_assessment(
            scope="192.168.0.0/24",
            traffic_findings=[
                {
                    "severity": "LOW",
                }
            ],
            notes=[
                "Dataclass compatibility test."
            ],
        )

        self.assertIsInstance(
            finding,
            FindingSummary,
        )

        self.assertEqual(
            result.finding_summary.low,
            1,
        )

        self.assertIn(
            "Dataclass compatibility test.",
            result.notes,
        )

    def test_serialization(self):
        result = self.engine.build_sample_assessment()

        data = result.to_dict()

        self.assertIn(
            "assessment_id",
            data,
        )

        self.assertIn(
            "finding_summary",
            data,
        )

        self.assertIn(
            "metrics",
            data,
        )

        self.assertEqual(
            data["metrics"]["devices"],
            3,
        )

        self.assertEqual(
            data["finding_summary"]["TOTAL"],
            6,
        )

    def test_unique_assessment_ids(self):
        first = self.engine.build_assessment(
            scope="192.168.0.0/24"
        )

        second = self.engine.build_assessment(
            scope="192.168.0.0/24"
        )

        self.assertNotEqual(
            first.assessment_id,
            second.assessment_id,
        )

    def test_last_result(self):
        result = self.engine.build_sample_assessment()

        self.assertIs(
            self.engine.last_result,
            result,
        )

    def test_formatting(self):
        result = self.engine.build_sample_assessment()

        output = format_assessment_result(
            result
        )

        self.assertIn(
            "NETWATCH SECURITY ASSESSMENT",
            output,
        )

        self.assertIn(
            "SEVERITY SUMMARY",
            output,
        )

        self.assertIn(
            "RECOMMENDATIONS",
            output,
        )

        self.assertIn(
            result.assessment_id,
            output,
        )

    def test_invalid_formatter_type(self):
        with self.assertRaises(TypeError):
            format_assessment_result(
                "invalid"
            )


if __name__ == "__main__":
    unittest.main()