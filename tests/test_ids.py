"""
NETWATCH Phase 7 IDS Engine Tests.

Tests the integration between:
    DetectionRules
    AlertManager
    IDSEngine

All tests use deterministic synthetic traffic.
No real network traffic is generated.
"""

import unittest

from detection.alert_manager import (
    AlertManager,
    SecurityAlert,
)
from detection.detection_rules import (
    DetectionRuleConfig,
    DetectionRules,
)
from detection.ids_engine import (
    IDSAnalysisResult,
    IDSEngine,
    IDSInputError,
    format_ids_results,
)


class TestIDSAnalysisResult(unittest.TestCase):
    """Test IDSAnalysisResult behavior."""

    def test_alert_count(self):
        engine = IDSEngine()

        result = engine.analyze_sample()

        self.assertEqual(
            result.alert_count,
            len(result.alerts),
        )

    def test_high_severity_count(self):
        engine = IDSEngine()

        result = engine.analyze_sample()

        expected = sum(
            1
            for alert in result.alerts
            if alert.severity in {"HIGH", "CRITICAL"}
        )

        self.assertEqual(
            result.high_severity_count,
            expected,
        )

    def test_medium_severity_count(self):
        engine = IDSEngine()

        result = engine.analyze_sample()

        expected = sum(
            1
            for alert in result.alerts
            if alert.severity == "MEDIUM"
        )

        self.assertEqual(
            result.medium_severity_count,
            expected,
        )

    def test_low_severity_count(self):
        engine = IDSEngine()

        result = engine.analyze_sample()

        expected = sum(
            1
            for alert in result.alerts
            if alert.severity == "LOW"
        )

        self.assertEqual(
            result.low_severity_count,
            expected,
        )

    def test_info_count(self):
        engine = IDSEngine()

        result = engine.analyze_sample()

        expected = sum(
            1
            for alert in result.alerts
            if alert.severity == "INFO"
        )

        self.assertEqual(
            result.info_count,
            expected,
        )


class TestIDSEngine(unittest.TestCase):
    """Test the main IDS engine."""

    def test_engine_initialization(self):
        engine = IDSEngine()

        self.assertIsNotNone(engine.rules)
        self.assertIsNotNone(engine.alert_manager)

    def test_sample_analysis(self):
        engine = IDSEngine()

        result = engine.analyze_sample()

        self.assertIsInstance(
            result,
            IDSAnalysisResult,
        )

        self.assertEqual(
            result.packets_analyzed,
            6,
        )

        self.assertEqual(
            result.total_bytes,
            540,
        )

        self.assertGreater(
            result.alert_count,
            0,
        )

    def test_sample_generates_high_severity_alert(self):
        engine = IDSEngine()

        result = engine.analyze_sample()

        high_or_critical = [
            alert
            for alert in result.alerts
            if alert.severity in {"HIGH", "CRITICAL"}
        ]

        self.assertGreater(
            len(high_or_critical),
            0,
        )

    def test_empty_traffic(self):
        engine = IDSEngine()

        result = engine.analyze([])

        self.assertEqual(
            result.packets_analyzed,
            0,
        )

        self.assertEqual(
            result.total_bytes,
            0,
        )

        self.assertEqual(
            result.alert_count,
            0,
        )

    def test_custom_packet_analysis(self):
        engine = IDSEngine()

        packets = [
            {
                "source_ip": "192.168.1.50",
                "destination_ip": "192.168.1.1",
                "source_port": 50000,
                "destination_port": 443,
                "protocol": "TCP",
                "length": 100,
            }
        ]

        result = engine.analyze(
            packets,
            total_bytes=100,
        )

        self.assertEqual(
            result.packets_analyzed,
            1,
        )

        self.assertEqual(
            result.total_bytes,
            100,
        )

    def test_total_bytes_calculated_from_packets(self):
        engine = IDSEngine()

        packets = [
            {
                "source_ip": "192.168.1.10",
                "destination_ip": "192.168.1.1",
                "destination_port": 80,
                "protocol": "TCP",
                "length": 100,
            },
            {
                "source_ip": "192.168.1.10",
                "destination_ip": "192.168.1.1",
                "destination_port": 443,
                "protocol": "TCP",
                "length": 200,
            },
        ]

        result = engine.analyze(packets)

        self.assertEqual(
            result.total_bytes,
            300,
        )

    def test_previous_alerts_are_cleared(self):
        engine = IDSEngine()

        first = engine.analyze_sample()

        self.assertGreater(
            first.alert_count,
            0,
        )

        second = engine.analyze([])

        self.assertEqual(
            second.alert_count,
            0,
        )

        self.assertEqual(
            engine.alert_manager.count,
            0,
        )

    def test_previous_alerts_can_be_retained(self):
        engine = IDSEngine()

        first = engine.analyze_sample()

        first_count = first.alert_count

        second = engine.analyze(
            [],
            clear_previous_alerts=False,
        )

        self.assertEqual(
            second.alert_count,
            0,
        )

        self.assertEqual(
            engine.alert_manager.count,
            first_count,
        )

    def test_invalid_total_bytes(self):
        engine = IDSEngine()

        with self.assertRaises(IDSInputError):
            engine.analyze(
                [],
                total_bytes="invalid",
            )

    def test_non_iterable_packets(self):
        engine = IDSEngine()

        with self.assertRaises(IDSInputError):
            engine.analyze(12345)

    def test_alert_manager_receives_generated_alerts(self):
        manager = AlertManager()

        engine = IDSEngine(
            alert_manager=manager,
        )

        result = engine.analyze_sample()

        self.assertEqual(
            manager.count,
            result.alert_count,
        )

    def test_custom_rule_configuration(self):
        config = DetectionRuleConfig(
            port_scan_unique_ports=2,
            excessive_connections=3,
            suspicious_port_repetitions=2,
            repeated_requests=3,
            abnormal_traffic_packets=4,
            abnormal_traffic_bytes=500,
        )

        engine = IDSEngine(
            rule_config=config,
        )

        self.assertEqual(
            engine.rules.config.port_scan_unique_ports,
            2,
        )

        packets = [
            {
                "source_ip": "10.0.0.5",
                "destination_ip": "10.0.0.1",
                "destination_port": 80,
                "protocol": "TCP",
                "length": 100,
            },
            {
                "source_ip": "10.0.0.5",
                "destination_ip": "10.0.0.1",
                "destination_port": 443,
                "protocol": "TCP",
                "length": 100,
            },
        ]

        result = engine.analyze(
            packets,
            total_bytes=200,
        )

        self.assertGreaterEqual(
            result.alert_count,
            1,
        )

    def test_alert_fields(self):
        engine = IDSEngine()

        result = engine.analyze_sample()

        self.assertGreater(
            len(result.alerts),
            0,
        )

        for alert in result.alerts:
            self.assertIsInstance(
                alert,
                SecurityAlert,
            )

            self.assertTrue(
                alert.alert_id,
            )

            self.assertTrue(
                alert.timestamp,
            )

            self.assertTrue(
                alert.source,
            )

            self.assertTrue(
                alert.detection_type,
            )

            self.assertTrue(
                alert.description,
            )

            self.assertIn(
                alert.severity,
                {
                    "INFO",
                    "LOW",
                    "MEDIUM",
                    "HIGH",
                    "CRITICAL",
                },
            )

            self.assertTrue(
                alert.evidence,
            )

            self.assertTrue(
                alert.recommended_action,
            )

    def test_alerts_are_rule_based(self):
        engine = IDSEngine()

        result = engine.analyze_sample()

        for alert in result.alerts:
            self.assertNotIn(
                "proof of malicious intent",
                alert.description.lower(),
            )

            self.assertNotIn(
                "confirmed attacker",
                alert.description.lower(),
            )


class TestIDSResultFormatting(unittest.TestCase):
    """Test terminal formatting."""

    def test_format_empty_result(self):
        result = IDSAnalysisResult(
            packets_analyzed=0,
            total_bytes=0,
            alerts=[],
            rules_evaluated=7,
        )

        output = format_ids_results(result)

        self.assertIn(
            "IDS / SECURITY DETECTION",
            output,
        )

        self.assertIn(
            "Packets Analyzed     : 0",
            output,
        )

        self.assertIn(
            "No configured detection rule produced an alert.",
            output,
        )

    def test_format_result_with_alerts(self):
        engine = IDSEngine()

        result = engine.analyze_sample()

        output = format_ids_results(result)

        self.assertIn(
            "IDS / SECURITY DETECTION",
            output,
        )

        self.assertIn(
            "DETECTED SECURITY EVENTS",
            output,
        )

        self.assertIn(
            "ASSESSMENT NOTE",
            output,
        )

        self.assertIn(
            "not proof of malicious intent",
            output,
        )


class TestIDSIntegration(unittest.TestCase):
    """Test integration with Phase 6-style traffic results."""

    def test_dictionary_traffic_result(self):
        engine = IDSEngine()

        traffic_result = {
            "packets": [
                {
                    "source_ip": "192.168.0.25",
                    "destination_ip": "192.168.0.1",
                    "destination_port": 23,
                    "protocol": "TCP",
                    "length": 60,
                }
            ],
            "total_bytes": 60,
        }

        result = engine.analyze_traffic_result(
            traffic_result,
        )

        self.assertEqual(
            result.packets_analyzed,
            1,
        )

        self.assertEqual(
            result.total_bytes,
            60,
        )

    def test_object_traffic_result(self):
        class MockTrafficResult:
            def __init__(self):
                self.packets = [
                    {
                        "source_ip": "192.168.0.30",
                        "destination_ip": "192.168.0.1",
                        "destination_port": 21,
                        "protocol": "TCP",
                        "length": 60,
                    }
                ]
                self.total_bytes = 60

        engine = IDSEngine()

        result = engine.analyze_traffic_result(
            MockTrafficResult(),
        )

        self.assertEqual(
            result.packets_analyzed,
            1,
        )

        self.assertEqual(
            result.total_bytes,
            60,
        )

    def test_empty_traffic_result(self):
        class MockTrafficResult:
            packets = []
            total_bytes = 0

        engine = IDSEngine()

        result = engine.analyze_traffic_result(
            MockTrafficResult(),
        )

        self.assertEqual(
            result.packets_analyzed,
            0,
        )

        self.assertEqual(
            result.total_bytes,
            0,
        )

        self.assertEqual(
            result.alert_count,
            0,
        )


if __name__ == "__main__":
    unittest.main()