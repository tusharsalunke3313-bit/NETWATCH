"""
Tests for the NETWATCH Phase 8 Firewall Analyzer.
"""

import json
import tempfile
import unittest
from pathlib import Path

from firewall.firewall_analyzer import (
    FirewallAnalysisResult,
    FirewallAnalyzer,
    FirewallAnalyzerError,
    FirewallFinding,
    FirewallRule,
    format_firewall_results,
)


class TestFirewallRule(unittest.TestCase):

    def test_valid_rule(self):
        rule = FirewallRule(
            rule_id="1",
            source="192.168.1.0/24",
            destination="ANY",
            port="443",
            protocol="TCP",
            action="ALLOW",
        )

        self.assertEqual(rule.rule_id, "1")
        self.assertEqual(rule.protocol, "TCP")
        self.assertEqual(rule.action, "ALLOW")

    def test_rule_from_dict(self):
        rule = FirewallRule.from_dict(
            {
                "rule_id": "1",
                "source": "ANY",
                "destination": "ANY",
                "port": "80",
                "protocol": "TCP",
                "action": "ALLOW",
            }
        )

        self.assertEqual(rule.port, "80")

    def test_missing_rule_field(self):
        with self.assertRaises(FirewallAnalyzerError):
            FirewallRule.from_dict(
                {
                    "rule_id": "1",
                    "source": "ANY",
                }
            )

    def test_invalid_protocol(self):
        with self.assertRaises(FirewallAnalyzerError):
            FirewallRule(
                rule_id="1",
                source="ANY",
                destination="ANY",
                port="80",
                protocol="INVALID",
                action="ALLOW",
            )

    def test_invalid_action(self):
        with self.assertRaises(FirewallAnalyzerError):
            FirewallRule(
                rule_id="1",
                source="ANY",
                destination="ANY",
                port="80",
                protocol="TCP",
                action="INVALID",
            )


class TestFirewallAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = FirewallAnalyzer()

    def test_empty_rules(self):
        result = self.analyzer.analyze([])

        self.assertEqual(result.rules_analyzed, 0)
        self.assertEqual(result.finding_count, 0)

    def test_none_rules_rejected(self):
        with self.assertRaises(FirewallAnalyzerError):
            self.analyzer.analyze(None)

    def test_dictionary_rules_supported(self):
        result = self.analyzer.analyze(
            [
                {
                    "rule_id": "1",
                    "source": "ANY",
                    "destination": "ANY",
                    "port": "443",
                    "protocol": "TCP",
                    "action": "ALLOW",
                }
            ]
        )

        self.assertEqual(result.rules_analyzed, 1)

    def test_unrestricted_source(self):
        result = self.analyzer.analyze(
            [
                FirewallRule(
                    rule_id="1",
                    source="ANY",
                    destination="192.168.1.10",
                    port="22",
                    protocol="TCP",
                    action="ALLOW",
                )
            ]
        )

        finding_types = {
            finding.finding_type
            for finding in result.findings
        }

        self.assertIn(
            "UNRESTRICTED_SOURCE_ACCESS",
            finding_types,
        )

    def test_unrestricted_destination(self):
        result = self.analyzer.analyze(
            [
                FirewallRule(
                    rule_id="1",
                    source="192.168.1.10",
                    destination="ANY",
                    port="80",
                    protocol="TCP",
                    action="ALLOW",
                )
            ]
        )

        finding_types = {
            finding.finding_type
            for finding in result.findings
        }

        self.assertIn(
            "UNRESTRICTED_DESTINATION_ACCESS",
            finding_types,
        )

    def test_broad_port_range(self):
        result = self.analyzer.analyze(
            [
                FirewallRule(
                    rule_id="1",
                    source="ANY",
                    destination="ANY",
                    port="1-2000",
                    protocol="TCP",
                    action="ALLOW",
                )
            ]
        )

        finding_types = {
            finding.finding_type
            for finding in result.findings
        }

        self.assertIn(
            "BROAD_PORT_RANGE",
            finding_types,
        )

    def test_duplicate_rule(self):
        rules = [
            FirewallRule(
                rule_id="1",
                source="ANY",
                destination="ANY",
                port="443",
                protocol="TCP",
                action="ALLOW",
            ),
            FirewallRule(
                rule_id="2",
                source="ANY",
                destination="ANY",
                port="443",
                protocol="TCP",
                action="ALLOW",
            ),
        ]

        result = self.analyzer.analyze(rules)

        self.assertTrue(
            any(
                finding.finding_type == "DUPLICATE_RULE"
                for finding in result.findings
            )
        )

    def test_conflicting_rules(self):
        rules = [
            FirewallRule(
                rule_id="1",
                source="ANY",
                destination="ANY",
                port="443",
                protocol="TCP",
                action="ALLOW",
            ),
            FirewallRule(
                rule_id="2",
                source="ANY",
                destination="ANY",
                port="443",
                protocol="TCP",
                action="DENY",
            ),
        ]

        result = self.analyzer.analyze(rules)

        self.assertTrue(
            any(
                finding.finding_type == "CONFLICTING_RULE"
                for finding in result.findings
            )
        )

    def test_shadowed_rule(self):
        rules = [
            FirewallRule(
                rule_id="1",
                source="ANY",
                destination="ANY",
                port="1-65535",
                protocol="TCP",
                action="ALLOW",
            ),
            FirewallRule(
                rule_id="2",
                source="192.168.1.0/24",
                destination="192.168.1.10",
                port="443",
                protocol="TCP",
                action="ALLOW",
            ),
        ]

        result = self.analyzer.analyze(rules)

        self.assertTrue(
            any(
                finding.finding_type == "SHADOWED_RULE"
                for finding in result.findings
            )
        )

    def test_telnet_allowed(self):
        result = self.analyzer.analyze(
            [
                FirewallRule(
                    rule_id="1",
                    source="ANY",
                    destination="ANY",
                    port="23",
                    protocol="TCP",
                    action="ALLOW",
                )
            ]
        )

        self.assertTrue(
            any(
                finding.finding_type
                == "INSECURE_SERVICE_ALLOWED"
                for finding in result.findings
            )
        )

    def test_telnet_blocked(self):
        result = self.analyzer.analyze(
            [
                FirewallRule(
                    rule_id="1",
                    source="ANY",
                    destination="ANY",
                    port="23",
                    protocol="TCP",
                    action="DENY",
                )
            ]
        )

        self.assertTrue(
            any(
                finding.finding_type
                == "INSECURE_SERVICE_BLOCKED"
                for finding in result.findings
            )
        )

    def test_overly_permissive_rule(self):
        result = self.analyzer.analyze(
            [
                FirewallRule(
                    rule_id="1",
                    source="ANY",
                    destination="ANY",
                    port="ANY",
                    protocol="ANY",
                    action="ALLOW",
                )
            ]
        )

        findings = [
            finding
            for finding in result.findings
            if finding.finding_type
            == "OVERLY_PERMISSIVE_RULE"
        ]

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_deny_rule_not_flagged_as_overly_permissive(self):
        result = self.analyzer.analyze(
            [
                FirewallRule(
                    rule_id="1",
                    source="ANY",
                    destination="ANY",
                    port="ANY",
                    protocol="ANY",
                    action="DENY",
                )
            ]
        )

        self.assertFalse(
            any(
                finding.finding_type
                == "OVERLY_PERMISSIVE_RULE"
                for finding in result.findings
            )
        )

    def test_result_severity_counts(self):
        result = self.analyzer.analyze(
            [
                FirewallRule(
                    rule_id="1",
                    source="ANY",
                    destination="ANY",
                    port="ANY",
                    protocol="ANY",
                    action="ALLOW",
                )
            ]
        )

        self.assertGreaterEqual(result.critical_count, 1)

    def test_highest_severity(self):
        result = self.analyzer.analyze(
            [
                FirewallRule(
                    rule_id="1",
                    source="ANY",
                    destination="ANY",
                    port="ANY",
                    protocol="ANY",
                    action="ALLOW",
                )
            ]
        )

        self.assertEqual(
            result.highest_severity(),
            "CRITICAL",
        )

    def test_sample_rules(self):
        rules = self.analyzer.sample_rules()

        self.assertGreaterEqual(len(rules), 1)

        result = self.analyzer.analyze(rules)

        self.assertGreater(result.rules_analyzed, 0)
        self.assertGreater(result.finding_count, 0)

    def test_json_file_analysis(self):
        data = {
            "rules": [
                {
                    "rule_id": "JSON-1",
                    "source": "ANY",
                    "destination": "ANY",
                    "port": "23",
                    "protocol": "TCP",
                    "action": "DENY",
                }
            ]
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "firewall.json"

            with path.open("w", encoding="utf-8") as file:
                json.dump(data, file)

            result = self.analyzer.analyze_json_file(path)

        self.assertEqual(result.rules_analyzed, 1)

    def test_missing_json_file(self):
        with self.assertRaises(FirewallAnalyzerError):
            self.analyzer.analyze_json_file(
                "this-file-does-not-exist.json"
            )

    def test_invalid_json_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "invalid.json"
            path.write_text(
                "{ invalid json",
                encoding="utf-8",
            )

            with self.assertRaises(FirewallAnalyzerError):
                self.analyzer.analyze_json_file(path)


class TestFirewallFormatting(unittest.TestCase):

    def test_format_empty_result(self):
        result = FirewallAnalysisResult()

        output = format_firewall_results(result)

        self.assertIn("FIREWALL ANALYSIS", output)
        self.assertIn(
            "No configured firewall rule produced a finding.",
            output,
        )

    def test_format_result_with_findings(self):
        finding = FirewallFinding(
            finding_id="FWF-0000001",
            rule_id="1",
            finding_type="TEST_FINDING",
            severity="MEDIUM",
            observation="Test observation.",
            potential_risk="Test risk.",
            recommendation="Test recommendation.",
            evidence={"test": True},
        )

        result = FirewallAnalysisResult(
            rules_analyzed=1,
            findings=[finding],
        )

        output = format_firewall_results(result)

        self.assertIn("TEST_FINDING", output)
        self.assertIn("Test observation.", output)
        self.assertIn("Test recommendation.", output)


if __name__ == "__main__":
    unittest.main()