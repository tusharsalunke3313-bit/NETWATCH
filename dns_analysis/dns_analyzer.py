"""
NETWATCH DNS Analysis

Phase 4 - DNS Analysis

Provides safe DNS query and analysis functionality for
authorized and appropriate network assessments.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import re
import time
from typing import List, Optional

import dns.exception
import dns.resolver
import dns.reversename


@dataclass
class DNSQueryResult:
    """Result of a single DNS record query."""

    record_type: str
    domain: str
    answers: List[str] = field(default_factory=list)
    response_time_ms: Optional[float] = None
    error: Optional[str] = None


@dataclass
class DNSAnalysisResult:
    """Complete DNS analysis result for a domain."""

    domain: str
    a_records: List[str] = field(default_factory=list)
    aaaa_records: List[str] = field(default_factory=list)
    mx_records: List[str] = field(default_factory=list)
    ns_records: List[str] = field(default_factory=list)
    cname_records: List[str] = field(default_factory=list)
    txt_records: List[str] = field(default_factory=list)
    reverse_dns: List[str] = field(default_factory=list)
    response_time_ms: Optional[float] = None
    resolver_nameservers: List[str] = field(default_factory=list)
    query_results: List[DNSQueryResult] = field(default_factory=list)


class DNSAnalyzer:
    """
    Safe DNS analyzer using dnspython.

    The analyzer performs DNS lookups only. It does not perform
    exploitation, credential collection, brute force, or other
    intrusive activity.
    """

    RECORD_TYPES = (
        "A",
        "AAAA",
        "MX",
        "NS",
        "CNAME",
        "TXT",
    )

    def __init__(
        self,
        timeout: float = 3.0,
        lifetime: float = 5.0,
        nameservers: Optional[List[str]] = None,
    ) -> None:
        if timeout <= 0:
            raise ValueError("DNS timeout must be greater than zero.")

        if lifetime <= 0:
            raise ValueError("DNS lifetime must be greater than zero.")

        if lifetime < timeout:
            raise ValueError(
                "DNS lifetime must be greater than or equal to timeout."
            )

        self.timeout = float(timeout)
        self.lifetime = float(lifetime)

        self.resolver = dns.resolver.Resolver(configure=True)
        self.resolver.timeout = self.timeout
        self.resolver.lifetime = self.lifetime

        if nameservers is not None:
            self._validate_nameservers(nameservers)
            self.resolver.nameservers = list(nameservers)

        self.nameservers = list(self.resolver.nameservers)

    def analyze(self, domain: str) -> DNSAnalysisResult:
        """
        Perform standard DNS analysis for a domain.

        Queries:
        - A
        - AAAA
        - MX
        - NS
        - CNAME
        - TXT
        """
        normalized_domain = self.validate_domain(domain)

        result = DNSAnalysisResult(
            domain=normalized_domain,
            resolver_nameservers=list(self.nameservers),
        )

        overall_start = time.perf_counter()

        for record_type in self.RECORD_TYPES:
            query_result = self.query_record(
                normalized_domain,
                record_type,
            )

            result.query_results.append(query_result)

            if record_type == "A":
                result.a_records = query_result.answers

            elif record_type == "AAAA":
                result.aaaa_records = query_result.answers

            elif record_type == "MX":
                result.mx_records = query_result.answers

            elif record_type == "NS":
                result.ns_records = query_result.answers

            elif record_type == "CNAME":
                result.cname_records = query_result.answers

            elif record_type == "TXT":
                result.txt_records = query_result.answers

        result.response_time_ms = round(
            (time.perf_counter() - overall_start) * 1000,
            2,
        )

        # Perform reverse DNS for A records where appropriate.
        for address in result.a_records:
            reverse_result = self.reverse_dns(address)

            for hostname in reverse_result:
                if hostname not in result.reverse_dns:
                    result.reverse_dns.append(hostname)

        return result

    def query_record(
        self,
        domain: str,
        record_type: str,
    ) -> DNSQueryResult:
        """Query one DNS record type."""
        normalized_domain = self.validate_domain(domain)
        normalized_type = record_type.upper().strip()

        if normalized_type not in self.RECORD_TYPES:
            raise ValueError(
                f"Unsupported DNS record type: {record_type}"
            )

        start = time.perf_counter()

        try:
            answers = self.resolver.resolve(
                normalized_domain,
                normalized_type,
            )

            formatted_answers = self._format_answers(
                answers,
                normalized_type,
            )

            response_time_ms = round(
                (time.perf_counter() - start) * 1000,
                2,
            )

            return DNSQueryResult(
                record_type=normalized_type,
                domain=normalized_domain,
                answers=formatted_answers,
                response_time_ms=response_time_ms,
                error=None,
            )

        except dns.resolver.NXDOMAIN:
            response_time_ms = round(
                (time.perf_counter() - start) * 1000,
                2,
            )

            return DNSQueryResult(
                record_type=normalized_type,
                domain=normalized_domain,
                answers=[],
                response_time_ms=response_time_ms,
                error="NXDOMAIN",
            )

        except dns.resolver.NoAnswer:
            response_time_ms = round(
                (time.perf_counter() - start) * 1000,
                2,
            )

            return DNSQueryResult(
                record_type=normalized_type,
                domain=normalized_domain,
                answers=[],
                response_time_ms=response_time_ms,
                error="NO_ANSWER",
            )

        except (
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ) as exc:
            response_time_ms = round(
                (time.perf_counter() - start) * 1000,
                2,
            )

            return DNSQueryResult(
                record_type=normalized_type,
                domain=normalized_domain,
                answers=[],
                response_time_ms=response_time_ms,
                error=str(exc) or exc.__class__.__name__,
            )

        except Exception as exc:
            response_time_ms = round(
                (time.perf_counter() - start) * 1000,
                2,
            )

            return DNSQueryResult(
                record_type=normalized_type,
                domain=normalized_domain,
                answers=[],
                response_time_ms=response_time_ms,
                error=str(exc) or exc.__class__.__name__,
            )

    def reverse_dns(self, value: str) -> List[str]:
        """
        Perform reverse DNS lookup.

        Returns a list because a reverse lookup can theoretically
        return multiple PTR names.
        """
        try:
            ipaddress.ip_address(value)

        except ValueError as exc:
            raise ValueError(
                f"Invalid IP address for reverse DNS: {value}"
            ) from exc

        try:
            reverse_name = dns.reversename.from_address(value)

            answers = dns.resolver.resolve(
                reverse_name,
                "PTR",
                lifetime=self.lifetime,
            )

            return [
                str(answer).rstrip(".") + "."
                for answer in answers
            ]

        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ):
            return []

        except Exception:
            return []

    @staticmethod
    def validate_domain(domain: str) -> str:
        """
        Validate and normalize a DNS domain name.

        Raises ValueError for invalid input.
        """
        if domain is None:
            raise ValueError("Domain cannot be empty.")

        normalized = domain.strip()

        if not normalized:
            raise ValueError("Domain cannot be empty.")

        # Remove one trailing DNS root dot.
        if normalized.endswith("."):
            normalized = normalized[:-1]

        if not normalized:
            raise ValueError("Domain cannot be empty.")

        if "://" in normalized:
            raise ValueError(
                "Domain must not include a URL scheme."
            )

        if "/" in normalized:
            raise ValueError(
                "Domain must not contain a URL path."
            )

        if ":" in normalized:
            raise ValueError(
                "Domain must not contain a port or protocol separator."
            )

        if len(normalized) > 253:
            raise ValueError(
                "Domain name must not exceed 253 characters."
            )

        labels = normalized.split(".")

        label_pattern = re.compile(
            r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
        )

        for label in labels:
            if not label:
                raise ValueError(
                    "Domain contains an empty DNS label."
                )

            if len(label) > 63:
                raise ValueError(
                    "DNS labels must not exceed 63 characters."
                )

            if not label_pattern.match(label):
                raise ValueError(
                    f"Invalid character in DNS label: {label}"
                )

        return normalized.lower()

    @staticmethod
    def _format_answers(
        answers,
        record_type: str,
    ) -> List[str]:
        """Convert dnspython answer objects into strings."""
        formatted: List[str] = []

        for answer in answers:
            if record_type == "MX":
                exchange = getattr(answer, "exchange", None)

                if exchange is not None:
                    formatted.append(str(exchange))
                else:
                    formatted.append(str(answer))

            elif record_type == "TXT":
                strings = getattr(answer, "strings", None)

                if strings:
                    parts = []

                    for item in strings:
                        if isinstance(item, bytes):
                            parts.append(
                                item.decode(
                                    "utf-8",
                                    errors="replace",
                                )
                            )
                        else:
                            parts.append(str(item))

                    formatted.append("".join(parts))

                else:
                    formatted.append(str(answer))

            else:
                formatted.append(str(answer))

        return formatted

    @staticmethod
    def _validate_nameservers(
        nameservers: List[str],
    ) -> None:
        """Validate configured DNS nameservers."""
        if not nameservers:
            raise ValueError(
                "At least one DNS nameserver must be specified."
            )

        for nameserver in nameservers:
            try:
                ipaddress.ip_address(nameserver)
            except ValueError as exc:
                raise ValueError(
                    f"Invalid DNS nameserver: {nameserver}"
                ) from exc


def format_dns_results(result: DNSAnalysisResult) -> str:
    """Format DNS analysis results for terminal output."""
    lines = []

    lines.append("DNS ANALYSIS RESULTS")
    lines.append("=" * 70)
    lines.append(f"Domain              : {result.domain}")

    if result.resolver_nameservers:
        lines.append(
            "Resolvers            : "
            + ", ".join(result.resolver_nameservers)
        )
    else:
        lines.append("Resolvers            : System default")

    if result.response_time_ms is not None:
        lines.append(
            f"Analysis time       : {result.response_time_ms:.2f} ms"
        )
    else:
        lines.append("Analysis time       : N/A")

    lines.append("")
    lines.append("DNS RECORDS")
    lines.append("-" * 70)

    record_groups = [
        ("A", result.a_records),
        ("AAAA", result.aaaa_records),
        ("MX", result.mx_records),
        ("NS", result.ns_records),
        ("CNAME", result.cname_records),
        ("TXT", result.txt_records),
    ]

    for record_type, records in record_groups:
        lines.append(f"{record_type:<8}:")
        if records:
            for record in records:
                lines.append(f"  - {record}")
        else:
            lines.append("  - None found")

    lines.append("")
    lines.append("REVERSE DNS")
    lines.append("-" * 70)

    if result.reverse_dns:
        for hostname in result.reverse_dns:
            lines.append(f"  - {hostname}")
    else:
        lines.append("  - None found")

    lines.append("")
    lines.append("QUERY STATUS")
    lines.append("-" * 70)

    for query in result.query_results:
        if query.error:
            status = f"ERROR: {query.error}"
        else:
            status = f"{len(query.answers)} answer(s)"

        timing = (
            f"{query.response_time_ms:.2f} ms"
            if query.response_time_ms is not None
            else "N/A"
        )

        lines.append(
            f"{query.record_type:<8} "
            f"{status:<30} "
            f"{timing}"
        )

    return "\n".join(lines)