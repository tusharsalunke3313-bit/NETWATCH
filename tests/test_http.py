"""
Tests for NETWATCH Phase 5 HTTP/HTTPS analysis.
"""

import unittest
from unittest.mock import MagicMock, patch

from web_analysis.http_analyzer import (
    CertificateInfo,
    HTTPAnalyzer,
    HTTPAnalysisResult,
    HeaderAnalysis,
    SECURITY_HEADERS,
    format_http_result,
)


class TestHTTPAnalyzerValidation(unittest.TestCase):

    def test_normalize_https_url(self):
        analyzer = HTTPAnalyzer()

        result = analyzer.normalize_url(
            "https://example.com"
        )

        self.assertEqual(
            result,
            "https://example.com",
        )

    def test_normalize_url_without_scheme(self):
        analyzer = HTTPAnalyzer()

        result = analyzer.normalize_url(
            "example.com"
        )

        self.assertEqual(
            result,
            "https://example.com",
        )

    def test_http_url_is_allowed(self):
        analyzer = HTTPAnalyzer()

        result = analyzer.normalize_url(
            "http://example.com"
        )

        self.assertEqual(
            result,
            "http://example.com",
        )

    def test_empty_target(self):
        analyzer = HTTPAnalyzer()

        with self.assertRaises(ValueError):
            analyzer.normalize_url("")

    def test_non_string_target(self):
        analyzer = HTTPAnalyzer()

        with self.assertRaises(ValueError):
            analyzer.normalize_url(None)

    def test_invalid_scheme(self):
        analyzer = HTTPAnalyzer()

        with self.assertRaises(ValueError):
            analyzer.normalize_url(
                "ftp://example.com"
            )

    def test_missing_hostname(self):
        analyzer = HTTPAnalyzer()

        with self.assertRaises(ValueError):
            analyzer.normalize_url(
                "https://"
            )

    def test_embedded_credentials_rejected(self):
        analyzer = HTTPAnalyzer()

        with self.assertRaises(ValueError):
            analyzer.normalize_url(
                "https://user:password@example.com"
            )

    def test_invalid_timeout(self):
        with self.assertRaises(ValueError):
            HTTPAnalyzer(timeout=0)

    def test_invalid_redirect_limit(self):
        with self.assertRaises(ValueError):
            HTTPAnalyzer(max_redirects=11)


class TestHeaderAnalysis(unittest.TestCase):

    def test_all_security_headers_present(self):
        headers = {
            header.lower(): f"value-{index}"
            for index, header in enumerate(
                SECURITY_HEADERS
            )
        }

        result = HTTPAnalyzer._analyze_security_headers(
            headers
        )

        self.assertEqual(
            len(result.present),
            len(SECURITY_HEADERS),
        )

        self.assertEqual(
            result.missing,
            [],
        )

    def test_missing_security_headers(self):
        result = HTTPAnalyzer._analyze_security_headers(
            {}
        )

        self.assertEqual(
            result.present,
            {},
        )

        self.assertEqual(
            result.missing,
            list(SECURITY_HEADERS),
        )

    def test_partial_security_headers(self):
        result = HTTPAnalyzer._analyze_security_headers(
            {
                "strict-transport-security":
                    "max-age=31536000",
                "content-security-policy":
                    "default-src 'self'",
            }
        )

        self.assertIn(
            "Strict-Transport-Security",
            result.present,
        )

        self.assertIn(
            "Content-Security-Policy",
            result.present,
        )

        self.assertEqual(
            len(result.missing),
            3,
        )


class TestHTTPAnalysisResult(unittest.TestCase):

    def test_default_result(self):
        result = HTTPAnalysisResult(
            target="https://example.com"
        )

        self.assertEqual(
            result.target,
            "https://example.com",
        )

        self.assertIsNone(
            result.status_code
        )

        self.assertFalse(
            result.redirect_detected
        )

    def test_certificate_dataclass(self):
        certificate = CertificateInfo(
            subject="CN=example.com",
            issuer="CN=Example CA",
            version=3,
            serial_number="ABC123",
            san_count=2,
            valid=True,
        )

        self.assertEqual(
            certificate.subject,
            "CN=example.com",
        )

        self.assertEqual(
            certificate.san_count,
            2,
        )

        self.assertTrue(
            certificate.valid
        )

    def test_header_dataclass(self):
        headers = HeaderAnalysis(
            present={
                "X-Frame-Options": "DENY"
            },
            missing=[
                "Referrer-Policy"
            ],
        )

        self.assertEqual(
            headers.present[
                "X-Frame-Options"
            ],
            "DENY",
        )

        self.assertEqual(
            headers.missing,
            ["Referrer-Policy"],
        )


class TestHTTPAnalysisFormatting(unittest.TestCase):

    def test_format_basic_result(self):
        result = HTTPAnalysisResult(
            target="https://example.com",
            final_url="https://example.com",
            initial_protocol="https",
            final_protocol="https",
            status_code=200,
            response_time_ms=42.50,
            tls_available=True,
            security_headers=HeaderAnalysis(
                present={
                    "Strict-Transport-Security":
                        "max-age=31536000",
                    "Content-Security-Policy":
                        "default-src 'self'",
                },
                missing=[
                    "X-Frame-Options",
                    "X-Content-Type-Options",
                    "Referrer-Policy",
                ],
            ),
            server_header="ExampleServer",
            content_type="text/html",
        )

        formatted = format_http_result(
            result
        )

        self.assertIn(
            "WEB SECURITY ANALYSIS",
            formatted,
        )

        self.assertIn(
            "https://example.com",
            formatted,
        )

        self.assertIn(
            "200",
            formatted,
        )

        self.assertIn(
            "42.50 ms",
            formatted,
        )

        self.assertIn(
            "PRESENT",
            formatted,
        )

        self.assertIn(
            "MISSING",
            formatted,
        )


class FakeHeaders(dict):

    def items(self):
        return super().items()


class FakeResponse:

    def __init__(
        self,
        status=200,
        headers=None,
    ):
        self.status = status
        self.headers = FakeHeaders(
            headers or {}
        )

    def getcode(self):
        return self.status


class TestHTTPAnalysis(unittest.TestCase):

    @patch(
        "web_analysis.http_analyzer.build_opener"
    )
    def test_successful_https_analysis(
        self,
        mock_build_opener,
    ):
        response = FakeResponse(
            status=200,
            headers={
                "Server": "TestServer",
                "Content-Type":
                    "text/html; charset=utf-8",
                "Content-Length": "1024",
                "Strict-Transport-Security":
                    "max-age=31536000",
                "Content-Security-Policy":
                    "default-src 'self'",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options":
                    "nosniff",
                "Referrer-Policy":
                    "strict-origin",
            },
        )

        opener = MagicMock()
        opener.open.return_value = response

        mock_build_opener.return_value = opener

        certificate = CertificateInfo(
            subject="CN=example.com",
            issuer="CN=Example CA",
            version=3,
            serial_number="123",
            san_count=2,
            valid=True,
        )

        analyzer = HTTPAnalyzer()

        with patch.object(
            analyzer,
            "get_certificate_info",
            return_value=certificate,
        ):
            result = analyzer.analyze(
                "https://example.com"
            )

        self.assertEqual(
            result.status_code,
            200,
        )

        self.assertEqual(
            result.server_header,
            "TestServer",
        )

        self.assertEqual(
            result.content_type,
            "text/html; charset=utf-8",
        )

        self.assertTrue(
            result.tls_available
        )

        self.assertIsNotNone(
            result.certificate
        )

        self.assertEqual(
            len(
                result.security_headers.present
            ),
            5,
        )

        opener.open.assert_called_once()

    @patch(
        "web_analysis.http_analyzer.build_opener"
    )
    def test_redirect_detection(
        self,
        mock_build_opener,
    ):
        first_response = FakeResponse(
            status=301,
            headers={
                "Location":
                    "https://example.com/final"
            },
        )

        second_response = FakeResponse(
            status=200,
            headers={
                "Content-Type":
                    "text/html"
            },
        )

        opener = MagicMock()

        opener.open.side_effect = [
            first_response,
            second_response,
        ]

        mock_build_opener.return_value = opener

        analyzer = HTTPAnalyzer()

        with patch.object(
            analyzer,
            "get_certificate_info",
            return_value=CertificateInfo(
                subject="CN=example.com"
            ),
        ):
            result = analyzer.analyze(
                "http://example.com"
            )

        self.assertTrue(
            result.redirect_detected
        )

        self.assertEqual(
            result.redirect_count,
            1,
        )

        self.assertEqual(
            result.status_code,
            200,
        )

        self.assertEqual(
            result.final_url,
            "https://example.com/final",
        )

        self.assertEqual(
            len(result.redirect_chain),
            2,
        )

    @patch(
        "web_analysis.http_analyzer.build_opener"
    )
    def test_http_error(
        self,
        mock_build_opener,
    ):
        opener = MagicMock()

        error = OSError(
            "Connection failed"
        )

        opener.open.side_effect = error

        mock_build_opener.return_value = opener

        analyzer = HTTPAnalyzer()

        result = analyzer.analyze(
            "https://example.com"
        )

        self.assertIsNotNone(
            result.error
        )

        self.assertIn(
            "Network error",
            result.error,
        )


class TestTLS(unittest.TestCase):

    def test_check_tls_rejects_http(self):
        analyzer = HTTPAnalyzer()

        self.assertFalse(
            analyzer.check_tls(
                "http://example.com"
            )
        )

    def test_certificate_rejects_http(self):
        analyzer = HTTPAnalyzer()

        result = analyzer.get_certificate_info(
            "http://example.com"
        )

        self.assertIsNotNone(
            result.error
        )

    @patch(
        "web_analysis.http_analyzer.socket.create_connection"
    )
    def test_tls_connection(
        self,
        mock_create_connection,
    ):
        raw_socket = MagicMock()
        tls_socket = MagicMock()

        raw_socket.__enter__.return_value = (
            raw_socket
        )

        tls_socket.__enter__.return_value = (
            tls_socket
        )

        mock_create_connection.return_value = (
            raw_socket
        )

        with patch(
            "web_analysis.http_analyzer.ssl.create_default_context"
        ) as mock_context_factory:

            context = MagicMock()

            mock_context_factory.return_value = (
                context
            )

            context.wrap_socket.return_value = (
                tls_socket
            )

            analyzer = HTTPAnalyzer()

            result = analyzer.check_tls(
                "https://example.com"
            )

        self.assertTrue(result)

    @patch(
        "web_analysis.http_analyzer.socket.create_connection"
    )
    def test_tls_failure(
        self,
        mock_create_connection,
    ):
        mock_create_connection.side_effect = (
            OSError("Connection refused")
        )

        analyzer = HTTPAnalyzer()

        result = analyzer.check_tls(
            "https://example.com"
        )

        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()