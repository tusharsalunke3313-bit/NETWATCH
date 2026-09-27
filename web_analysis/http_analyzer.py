"""
NETWATCH
HTTP/HTTPS Analyzer

Phase 5 - HTTP/HTTPS Analysis

This module performs safe, read-only analysis of web endpoints.

It does not perform:
- exploitation
- vulnerability exploitation
- credential attacks
- brute forcing
- destructive testing
- intrusive web scanning
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import socket
import ssl
import time
from typing import Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import (
    HTTPRedirectHandler,
    Request,
    build_opener,
)


DEFAULT_TIMEOUT = 5.0
DEFAULT_MAX_REDIRECTS = 5

SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
)


@dataclass
class CertificateInfo:
    """Basic TLS certificate information."""

    subject: str = ""
    issuer: str = ""
    version: Optional[int] = None
    serial_number: str = ""
    not_before: str = ""
    not_after: str = ""
    san_count: int = 0
    valid: Optional[bool] = None
    error: Optional[str] = None


@dataclass
class HeaderAnalysis:
    """Security-related HTTP response headers."""

    present: Dict[str, str] = field(default_factory=dict)
    missing: List[str] = field(default_factory=list)


@dataclass
class HTTPAnalysisResult:
    """Complete HTTP/HTTPS analysis result."""

    target: str
    final_url: str = ""
    initial_protocol: str = ""
    final_protocol: str = ""
    status_code: Optional[int] = None
    response_time_ms: Optional[float] = None
    redirect_detected: bool = False
    redirect_count: int = 0
    redirect_chain: List[str] = field(default_factory=list)
    tls_available: bool = False
    certificate: Optional[CertificateInfo] = None
    security_headers: HeaderAnalysis = field(
        default_factory=HeaderAnalysis
    )
    server_header: str = ""
    content_type: str = ""
    content_length: str = ""
    timestamp: str = ""
    error: Optional[str] = None


class _NoRedirectHandler(HTTPRedirectHandler):
    """Prevent urllib from automatically following redirects."""

    def redirect_request(
        self,
        req,
        fp,
        code,
        msg,
        headers,
        newurl,
    ):
        return None


class HTTPAnalyzer:
    """
    Safe HTTP/HTTPS endpoint analyzer.

    The analyzer performs normal HTTP requests and TLS handshakes only.
    """

    def __init__(
        self,
        timeout: float = DEFAULT_TIMEOUT,
        max_redirects: int = DEFAULT_MAX_REDIRECTS,
    ) -> None:
        if timeout <= 0:
            raise ValueError("Timeout must be greater than zero.")

        if max_redirects < 0 or max_redirects > 10:
            raise ValueError(
                "Maximum redirects must be between 0 and 10."
            )

        self.timeout = float(timeout)
        self.max_redirects = int(max_redirects)

    def normalize_url(self, target: str) -> str:
        """
        Validate and normalize a web target.

        If no scheme is supplied, HTTPS is used.
        """

        if not isinstance(target, str):
            raise ValueError("Target must be a string.")

        target = target.strip()

        if not target:
            raise ValueError("Target cannot be empty.")

        if "://" not in target:
            target = f"https://{target}"

        parsed = urlparse(target)

        if parsed.scheme.lower() not in ("http", "https"):
            raise ValueError(
                "Only HTTP and HTTPS URLs are supported."
            )

        if not parsed.hostname:
            raise ValueError(
                "The target must contain a valid hostname."
            )

        if parsed.username or parsed.password:
            raise ValueError(
                "URLs containing embedded credentials are not allowed."
            )

        return target

    def analyze(self, target: str) -> HTTPAnalysisResult:
        """
        Analyze an HTTP/HTTPS endpoint.

        Redirects are followed manually up to the configured limit.
        """

        normalized_url = self.normalize_url(target)
        initial_protocol = urlparse(normalized_url).scheme.lower()

        result = HTTPAnalysisResult(
            target=normalized_url,
            final_url=normalized_url,
            initial_protocol=initial_protocol,
            final_protocol=initial_protocol,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        current_url = normalized_url
        redirect_chain = [normalized_url]

        for redirect_number in range(
            self.max_redirects + 1
        ):
            try:
                request = Request(
                    current_url,
                    method="HEAD",
                    headers={
                        "User-Agent": "NETWATCH/0.5.0",
                        "Accept": "*/*",
                        "Connection": "close",
                    },
                )

                opener = build_opener(_NoRedirectHandler())

                start = time.perf_counter()

                try:
                    response = opener.open(
                        request,
                        timeout=self.timeout,
                    )
                except HTTPError as exc:
                    response = exc

                elapsed_ms = (
                    time.perf_counter() - start
                ) * 1000.0

                result.response_time_ms = round(
                    elapsed_ms,
                    2,
                )

                status_code = response.getcode()

                result.status_code = status_code
                result.final_url = current_url
                result.final_protocol = (
                    urlparse(current_url)
                    .scheme
                    .lower()
                )

                headers = self._headers_to_dict(
                    response.headers
                )

                result.server_header = headers.get(
                    "server",
                    "",
                )

                result.content_type = headers.get(
                    "content-type",
                    "",
                )

                result.content_length = headers.get(
                    "content-length",
                    "",
                )

                result.security_headers = (
                    self._analyze_security_headers(headers)
                )

                if status_code in (
                    301,
                    302,
                    303,
                    307,
                    308,
                ):
                    location = headers.get(
                        "location",
                        "",
                    )

                    if not location:
                        break

                    if (
                        redirect_number
                        >= self.max_redirects
                    ):
                        result.error = (
                            "Maximum redirect limit reached."
                        )
                        break

                    next_url = urljoin(
                        current_url,
                        location,
                    )

                    self._validate_redirect_url(
                        next_url
                    )

                    redirect_chain.append(next_url)
                    current_url = next_url

                    continue

                break

            except HTTPError as exc:
                result.status_code = exc.code
                result.error = (
                    f"HTTP error: {exc.code} {exc.reason}"
                )
                break

            except URLError as exc:
                result.error = (
                    f"Connection error: {exc.reason}"
                )
                break

            except TimeoutError:
                result.error = "Connection timed out."
                break

            except OSError as exc:
                result.error = (
                    f"Network error: {exc}"
                )
                break

        result.redirect_chain = redirect_chain
        result.redirect_count = max(
            0,
            len(redirect_chain) - 1,
        )
        result.redirect_detected = (
            result.redirect_count > 0
        )

        if (
            result.final_protocol == "https"
            and result.status_code is not None
        ):
            certificate = self.get_certificate_info(
                result.final_url
            )

            result.certificate = certificate
            result.tls_available = (
                certificate.error is None
            )

        return result

    def check_tls(self, target: str) -> bool:
        """
        Check whether a TLS connection can be established.

        This performs only a TLS handshake.
        """

        normalized_url = self.normalize_url(target)
        parsed = urlparse(normalized_url)

        if parsed.scheme.lower() != "https":
            return False

        hostname = parsed.hostname

        if hostname is None:
            return False

        port = parsed.port or 443

        context = ssl.create_default_context()

        try:
            with socket.create_connection(
                (hostname, port),
                timeout=self.timeout,
            ) as raw_socket:
                with context.wrap_socket(
                    raw_socket,
                    server_hostname=hostname,
                ):
                    return True

        except (
            OSError,
            ssl.SSLError,
        ):
            return False

    def get_certificate_info(
        self,
        target: str,
    ) -> CertificateInfo:
        """
        Retrieve basic peer certificate information.

        Only certificate metadata is collected.
        """

        normalized_url = self.normalize_url(target)
        parsed = urlparse(normalized_url)

        if parsed.scheme.lower() != "https":
            return CertificateInfo(
                error="Certificate analysis requires HTTPS."
            )

        hostname = parsed.hostname

        if hostname is None:
            return CertificateInfo(
                error="Unable to determine hostname."
            )

        port = parsed.port or 443

        context = ssl.create_default_context()

        try:
            with socket.create_connection(
                (hostname, port),
                timeout=self.timeout,
            ) as raw_socket:
                with context.wrap_socket(
                    raw_socket,
                    server_hostname=hostname,
                ) as tls_socket:

                    certificate = (
                        tls_socket.getpeercert()
                    )

                    if not certificate:
                        return CertificateInfo(
                            error=(
                                "No peer certificate "
                                "was returned."
                            )
                        )

                    subject = self._certificate_name(
                        certificate.get(
                            "subject",
                            (),
                        )
                    )

                    issuer = self._certificate_name(
                        certificate.get(
                            "issuer",
                            (),
                        )
                    )

                    san_entries = certificate.get(
                        "subjectAltName",
                        (),
                    )

                    not_before = certificate.get(
                        "notBefore",
                        "",
                    )

                    not_after = certificate.get(
                        "notAfter",
                        "",
                    )

                    valid = self._certificate_is_current(
                        not_before,
                        not_after,
                    )

                    return CertificateInfo(
                        subject=subject,
                        issuer=issuer,
                        version=certificate.get(
                            "version"
                        ),
                        serial_number=certificate.get(
                            "serialNumber",
                            "",
                        ),
                        not_before=not_before,
                        not_after=not_after,
                        san_count=len(san_entries),
                        valid=valid,
                    )

        except (
            OSError,
            ssl.SSLError,
        ) as exc:
            return CertificateInfo(
                error=str(exc)
            )

    @staticmethod
    def _certificate_name(
        value,
    ) -> str:
        """Convert a certificate name tuple to text."""

        parts = []

        for group in value or ():
            for key, item in group:
                parts.append(
                    f"{key}={item}"
                )

        return ", ".join(parts)

    @staticmethod
    def _certificate_is_current(
        not_before: str,
        not_after: str,
    ) -> Optional[bool]:
        """Determine whether certificate dates surround now."""

        if not_before == "" or not_after == "":
            return None

        try:
            before = datetime.strptime(
                not_before,
                "%b %d %H:%M:%S %Y %Z",
            ).replace(tzinfo=timezone.utc)

            after = datetime.strptime(
                not_after,
                "%b %d %H:%M:%S %Y %Z",
            ).replace(tzinfo=timezone.utc)

            now = datetime.now(timezone.utc)

            return before <= now <= after

        except ValueError:
            return None

    @staticmethod
    def _headers_to_dict(headers) -> Dict[str, str]:
        """Normalize response headers."""

        normalized = {}

        for key, value in headers.items():
            normalized[key.lower()] = value.strip()

        return normalized

    @staticmethod
    def _analyze_security_headers(
        headers: Dict[str, str],
    ) -> HeaderAnalysis:
        """Analyze recommended security headers."""

        present = {}
        missing = []

        for header in SECURITY_HEADERS:
            value = headers.get(
                header.lower(),
                "",
            )

            if value:
                present[header] = value
            else:
                missing.append(header)

        return HeaderAnalysis(
            present=present,
            missing=missing,
        )

    @staticmethod
    def _validate_redirect_url(
        target: str,
    ) -> None:
        """Allow redirects only to HTTP/HTTPS URLs."""

        parsed = urlparse(target)

        if parsed.scheme.lower() not in (
            "http",
            "https",
        ):
            raise ValueError(
                "Redirect target uses an unsupported protocol."
            )

        if not parsed.hostname:
            raise ValueError(
                "Redirect target has no hostname."
            )


def format_http_result(
    result: HTTPAnalysisResult,
) -> str:
    """Format HTTP analysis results for terminal output."""

    lines = []

    lines.append("WEB SECURITY ANALYSIS")
    lines.append("=" * 70)
    lines.append(
        f"Target             : {result.target}"
    )
    lines.append(
        f"Final URL          : {result.final_url}"
    )
    lines.append(
        f"Initial Protocol   : "
        f"{result.initial_protocol.upper()}"
    )
    lines.append(
        f"Final Protocol     : "
        f"{result.final_protocol.upper()}"
    )

    status = (
        str(result.status_code)
        if result.status_code is not None
        else "N/A"
    )

    lines.append(
        f"Status Code        : {status}"
    )

    response_time = (
        f"{result.response_time_ms:.2f} ms"
        if result.response_time_ms is not None
        else "N/A"
    )

    lines.append(
        f"Response Time      : {response_time}"
    )

    lines.append(
        f"Redirect Detected  : "
        f"{'YES' if result.redirect_detected else 'NO'}"
    )

    lines.append(
        f"Redirect Count     : "
        f"{result.redirect_count}"
    )

    lines.append(
        f"TLS Available      : "
        f"{'YES' if result.tls_available else 'NO'}"
    )

    lines.append("")
    lines.append("RESPONSE INFORMATION")
    lines.append("-" * 70)
    lines.append(
        f"Server             : "
        f"{result.server_header or 'Not disclosed'}"
    )
    lines.append(
        f"Content-Type       : "
        f"{result.content_type or 'Not provided'}"
    )
    lines.append(
        f"Content-Length     : "
        f"{result.content_length or 'Not provided'}"
    )

    lines.append("")
    lines.append("SECURITY HEADERS")
    lines.append("-" * 70)

    for header in SECURITY_HEADERS:
        if header in result.security_headers.present:
            lines.append(
                f"{header:<30} PRESENT"
            )
        else:
            lines.append(
                f"{header:<30} MISSING"
            )

    if result.redirect_chain:
        lines.append("")
        lines.append("REDIRECT CHAIN")
        lines.append("-" * 70)

        for index, url in enumerate(
            result.redirect_chain,
            start=1,
        ):
            lines.append(
                f"{index}. {url}"
            )

    if result.certificate is not None:
        lines.append("")
        lines.append("TLS CERTIFICATE")
        lines.append("-" * 70)

        certificate = result.certificate

        if certificate.error:
            lines.append(
                f"Certificate Error : "
                f"{certificate.error}"
            )
        else:
            lines.append(
                f"Subject            : "
                f"{certificate.subject or 'N/A'}"
            )
            lines.append(
                f"Issuer             : "
                f"{certificate.issuer or 'N/A'}"
            )
            lines.append(
                f"Version            : "
                f"{certificate.version or 'N/A'}"
            )
            lines.append(
                f"Serial Number      : "
                f"{certificate.serial_number or 'N/A'}"
            )
            lines.append(
                f"Valid From         : "
                f"{certificate.not_before or 'N/A'}"
            )
            lines.append(
                f"Valid Until        : "
                f"{certificate.not_after or 'N/A'}"
            )
            lines.append(
                f"Subject Alt Names   : "
                f"{certificate.san_count}"
            )

            certificate_status = (
                "VALID"
                if certificate.valid is True
                else (
                    "INVALID/EXPIRED"
                    if certificate.valid is False
                    else "UNKNOWN"
                )
            )

            lines.append(
                f"Certificate Status  : "
                f"{certificate_status}"
            )

    if result.error:
        lines.append("")
        lines.append("ERROR")
        lines.append("-" * 70)
        lines.append(result.error)

    lines.append("")
    return "\n".join(lines)