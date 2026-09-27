import unittest
from unittest.mock import MagicMock, patch

import dns.exception
import dns.resolver

from dns_analysis.dns_analyzer import (
    DNSAnalysisResult,
    DNSAnalyzer,
    DNSQueryResult,
    format_dns_results,
)


class TestDNSAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = DNSAnalyzer(
            timeout=3.0,
            lifetime=5.0,
        )

    def test_valid_domain(self):
        result = self.analyzer.validate_domain(
            "example.com"
        )

        self.assertEqual(result, "example.com")

    def test_valid_subdomain(self):
        result = self.analyzer.validate_domain(
            "www.example.com"
        )

        self.assertEqual(
            result,
            "www.example.com",
        )

    def test_domain_with_trailing_dot(self):
        result = self.analyzer.validate_domain(
            "example.com."
        )

        self.assertEqual(
            result,
            "example.com",
        )

    def test_invalid_domain_empty(self):
        with self.assertRaises(ValueError):
            self.analyzer.validate_domain("")

    def test_invalid_domain_whitespace(self):
        with self.assertRaises(ValueError):
            self.analyzer.validate_domain("   ")

    def test_invalid_domain_with_scheme(self):
        with self.assertRaises(ValueError):
            self.analyzer.validate_domain(
                "https://example.com"
            )

    def test_resolver_configuration(self):
        analyzer = DNSAnalyzer(
            timeout=2.0,
            lifetime=4.0,
            nameservers=["8.8.8.8"],
        )

        self.assertEqual(
            analyzer.timeout,
            2.0,
        )

        self.assertEqual(
            analyzer.lifetime,
            4.0,
        )

        self.assertEqual(
            analyzer.nameservers,
            ["8.8.8.8"],
        )

        self.assertEqual(
            analyzer.resolver.nameservers,
            ["8.8.8.8"],
        )

    @patch(
        "dns_analysis.dns_analyzer.dns.resolver.Resolver.resolve"
    )
    def test_mock_a_record(self, mock_resolve):
        answer_1 = MagicMock()
        answer_1.__str__.return_value = "93.184.216.34"

        mock_resolve.return_value = [answer_1]

        result = self.analyzer.query_record(
            "example.com",
            "A",
        )

        self.assertEqual(
            result.answers,
            ["93.184.216.34"],
        )

        self.assertEqual(
            result.record_type,
            "A",
        )

        self.assertIsNone(result.error)

        mock_resolve.assert_called_once()

    @patch(
        "dns_analysis.dns_analyzer.dns.resolver.Resolver.resolve"
    )
    def test_no_answer(self, mock_resolve):
        mock_resolve.side_effect = dns.resolver.NoAnswer()

        result = self.analyzer.query_record(
            "example.com",
            "MX",
        )

        self.assertEqual(
            result.answers,
            [],
        )

        self.assertEqual(
            result.error,
            "NO_ANSWER",
        )

    @patch(
        "dns_analysis.dns_analyzer.dns.resolver.Resolver.resolve"
    )
    def test_nxdomain(self, mock_resolve):
        mock_resolve.side_effect = dns.resolver.NXDOMAIN()

        result = self.analyzer.query_record(
            "does-not-exist.example",
            "A",
        )

        self.assertEqual(
            result.answers,
            [],
        )

        self.assertEqual(
            result.error,
            "NXDOMAIN",
        )

    def test_unsupported_record_type(self):
        with self.assertRaises(ValueError):
            self.analyzer.query_record(
                "example.com",
                "INVALID",
            )

    @patch(
        "dns_analysis.dns_analyzer.dns.resolver.resolve"
    )
    @patch(
        "dns_analysis.dns_analyzer.dns.reversename.from_address"
    )
    def test_reverse_dns(
        self,
        mock_from_address,
        mock_resolve,
    ):
        mock_from_address.return_value = (
            "34.216.184.93.in-addr.arpa."
        )

        answer = MagicMock()
        answer.__str__.return_value = "example.com."

        mock_resolve.return_value = [answer]

        result = self.analyzer.reverse_dns(
            "93.184.216.34"
        )

        self.assertEqual(
            result,
            ["example.com."],
        )

    def test_dns_query_result_dataclass(self):
        result = DNSQueryResult(
            record_type="A",
            domain="example.com",
            answers=["93.184.216.34"],
            response_time_ms=12.5,
            error=None,
        )

        self.assertEqual(
            result.record_type,
            "A",
        )

        self.assertEqual(
            result.domain,
            "example.com",
        )

        self.assertEqual(
            result.answers,
            ["93.184.216.34"],
        )

        self.assertEqual(
            result.response_time_ms,
            12.5,
        )

        self.assertIsNone(result.error)

    def test_dns_analysis_result_dataclass(self):
        result = DNSAnalysisResult(
            domain="example.com",
            a_records=["93.184.216.34"],
            aaaa_records=["2606:2800:220:1:248:1893:25c8:1946"],
            mx_records=["10 mail.example.com."],
            ns_records=["ns1.example.com."],
            cname_records=[],
            txt_records=["example-text"],
            reverse_dns=["example.com."],
            response_time_ms=25.5,
            resolver_nameservers=["8.8.8.8"],
        )

        self.assertEqual(
            result.domain,
            "example.com",
        )

        self.assertEqual(
            result.a_records,
            ["93.184.216.34"],
        )

        self.assertEqual(
            result.aaaa_records,
            ["2606:2800:220:1:248:1893:25c8:1946"],
        )

        self.assertEqual(
            result.mx_records,
            ["10 mail.example.com."],
        )

        self.assertEqual(
            result.ns_records,
            ["ns1.example.com."],
        )

        self.assertEqual(
            result.txt_records,
            ["example-text"],
        )

        self.assertEqual(
            result.reverse_dns,
            ["example.com."],
        )

        self.assertEqual(
            result.resolver_nameservers,
            ["8.8.8.8"],
        )

    def test_format_dns_results(self):
        result = DNSAnalysisResult(
            domain="example.com",
            a_records=["93.184.216.34"],
            aaaa_records=[],
            mx_records=["10 mail.example.com."],
            ns_records=["ns1.example.com."],
            cname_records=[],
            txt_records=["sample"],
            reverse_dns=["example.com."],
            response_time_ms=15.25,
            resolver_nameservers=["8.8.8.8"],
            query_results=[
                DNSQueryResult(
                    record_type="A",
                    domain="example.com",
                    answers=["93.184.216.34"],
                    response_time_ms=5.25,
                    error=None,
                )
            ],
        )

        formatted = format_dns_results(result)

        self.assertIn(
            "DNS ANALYSIS RESULTS",
            formatted,
        )

        self.assertIn(
            "example.com",
            formatted,
        )

        self.assertIn(
            "93.184.216.34",
            formatted,
        )

        self.assertIn(
            "8.8.8.8",
            formatted,
        )

    @patch(
        "dns_analysis.dns_analyzer.dns.resolver.Resolver.resolve"
    )
    def test_query_response_time(self, mock_resolve):
        answer = MagicMock()
        answer.__str__.return_value = "93.184.216.34"

        mock_resolve.return_value = [answer]

        result = self.analyzer.query_record(
            "example.com",
            "A",
        )

        self.assertIsNotNone(
            result.response_time_ms
        )

        self.assertGreaterEqual(
            result.response_time_ms,
            0,
        )

    def test_invalid_nameserver(self):
        with self.assertRaises(ValueError):
            DNSAnalyzer(
                nameservers=["not-an-ip-address"]
            )

    def test_empty_nameservers(self):
        with self.assertRaises(ValueError):
            DNSAnalyzer(
                nameservers=[]
            )

    def test_invalid_timeout(self):
        with self.assertRaises(ValueError):
            DNSAnalyzer(timeout=0)

    def test_invalid_lifetime(self):
        with self.assertRaises(ValueError):
            DNSAnalyzer(lifetime=0)

    def test_lifetime_less_than_timeout(self):
        with self.assertRaises(ValueError):
            DNSAnalyzer(
                timeout=5.0,
                lifetime=2.0,
            )


if __name__ == "__main__":
    unittest.main()