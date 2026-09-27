"""
NETWATCH Firewall Configuration Analyzer.

Phase 8 - Firewall Analyzer

This module performs read-only analysis of structured firewall rules.

The analyzer does NOT modify firewall configuration, create firewall
rules, disable security controls, or interact with a live firewall.

All findings are observational and represent potential configuration
risks that should be reviewed by an authorized administrator.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional


SEVERITY_LEVELS = (
    "INFO",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
)

SEVERITY_PRIORITY = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


class FirewallAnalyzerError(ValueError):
    """Raised when firewall input or configuration is invalid."""


@dataclass(frozen=True)
class FirewallRule:
    """Normalized firewall rule."""

    rule_id: str
    source: str
    destination: str
    port: str
    protocol: str
    action: str
    description: str = ""

    def __post_init__(self) -> None:
        if not str(self.rule_id).strip():
            raise FirewallAnalyzerError("Rule ID cannot be empty.")

        if not str(self.source).strip():
            raise FirewallAnalyzerError("Rule source cannot be empty.")

        if not str(self.destination).strip():
            raise FirewallAnalyzerError("Rule destination cannot be empty.")

        if not str(self.port).strip():
            raise FirewallAnalyzerError("Rule port cannot be empty.")

        protocol = str(self.protocol).strip().upper()

        if protocol not in {"TCP", "UDP", "ICMP", "ANY"}:
            raise FirewallAnalyzerError(
                f"Unsupported protocol: {self.protocol}"
            )

        action = str(self.action).strip().upper()

        if action not in {"ALLOW", "DENY"}:
            raise FirewallAnalyzerError(
                f"Unsupported firewall action: {self.action}"
            )

        object.__setattr__(self, "protocol", protocol)
        object.__setattr__(self, "action", action)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FirewallRule":
        """Create a firewall rule from a dictionary."""

        if not isinstance(data, dict):
            raise FirewallAnalyzerError(
                "Each firewall rule must be a dictionary."
            )

        required = (
            "rule_id",
            "source",
            "destination",
            "port",
            "protocol",
            "action",
        )

        missing = [
            field_name
            for field_name in required
            if field_name not in data
        ]

        if missing:
            raise FirewallAnalyzerError(
                f"Missing firewall rule fields: {', '.join(missing)}"
            )

        return cls(
            rule_id=str(data["rule_id"]),
            source=str(data["source"]),
            destination=str(data["destination"]),
            port=str(data["port"]),
            protocol=str(data["protocol"]),
            action=str(data["action"]),
            description=str(data.get("description", "")),
        )

    def to_dict(self) -> dict[str, str]:
        """Return the rule as a serializable dictionary."""

        return {
            "rule_id": self.rule_id,
            "source": self.source,
            "destination": self.destination,
            "port": self.port,
            "protocol": self.protocol,
            "action": self.action,
            "description": self.description,
        }


@dataclass(frozen=True)
class FirewallFinding:
    """A rule-based firewall configuration finding."""

    finding_id: str
    rule_id: str
    finding_type: str
    severity: str
    observation: str
    potential_risk: str
    recommendation: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        severity = str(self.severity).upper()

        if severity not in SEVERITY_LEVELS:
            raise FirewallAnalyzerError(
                f"Invalid severity: {self.severity}"
            )

        object.__setattr__(self, "severity", severity)

    @property
    def severity_priority(self) -> int:
        """Return numeric severity priority."""

        return SEVERITY_PRIORITY[self.severity]

    def to_dict(self) -> dict[str, Any]:
        """Return the finding as a serializable dictionary."""

        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "finding_type": self.finding_type,
            "severity": self.severity,
            "observation": self.observation,
            "potential_risk": self.potential_risk,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
        }


@dataclass
class FirewallAnalysisResult:
    """Complete firewall analysis result."""

    rules_analyzed: int = 0
    findings: list[FirewallFinding] = field(default_factory=list)

    @property
    def finding_count(self) -> int:
        """Return total number of findings."""

        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return self._count_severity("CRITICAL")

    @property
    def high_count(self) -> int:
        return self._count_severity("HIGH")

    @property
    def medium_count(self) -> int:
        return self._count_severity("MEDIUM")

    @property
    def low_count(self) -> int:
        return self._count_severity("LOW")

    @property
    def info_count(self) -> int:
        return self._count_severity("INFO")

    def _count_severity(self, severity: str) -> int:
        return sum(
            1
            for finding in self.findings
            if finding.severity == severity
        )

    def severity_distribution(self) -> dict[str, int]:
        """Return findings grouped by severity."""

        return {
            severity: self._count_severity(severity)
            for severity in SEVERITY_LEVELS
        }

    def highest_severity(self) -> str:
        """Return the highest severity present."""

        if not self.findings:
            return "INFO"

        return max(
            self.findings,
            key=lambda finding: finding.severity_priority,
        ).severity


class FirewallAnalyzer:
    """
    Read-only firewall configuration analyzer.

    The analyzer works with structured rule dictionaries or FirewallRule
    objects. It does not interact with operating-system firewall APIs.
    """

    INSECURE_SERVICES = {
        21: "FTP",
        23: "Telnet",
        139: "NetBIOS",
        445: "SMB",
        3389: "RDP",
        5900: "VNC",
    }

    SENSITIVE_SERVICES = {
        22: "SSH",
        23: "Telnet",
        3389: "RDP",
        5900: "VNC",
        445: "SMB",
    }

    def __init__(
        self,
        broad_port_threshold: int = 1000,
    ) -> None:
        if not isinstance(broad_port_threshold, int):
            raise FirewallAnalyzerError(
                "broad_port_threshold must be an integer."
            )

        if broad_port_threshold <= 0:
            raise FirewallAnalyzerError(
                "broad_port_threshold must be greater than zero."
            )

        self.broad_port_threshold = broad_port_threshold

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(
        self,
        rules: Iterable[FirewallRule | dict[str, Any]],
    ) -> FirewallAnalysisResult:
        """Analyze a collection of structured firewall rules."""

        normalized_rules = self._normalize_rules(rules)

        result = FirewallAnalysisResult(
            rules_analyzed=len(normalized_rules)
        )

        result.findings.extend(
            self._detect_unrestricted_access(normalized_rules)
        )

        result.findings.extend(
            self._detect_broad_ports(normalized_rules)
        )

        result.findings.extend(
            self._detect_duplicate_rules(normalized_rules)
        )

        result.findings.extend(
            self._detect_conflicting_rules(normalized_rules)
        )

        result.findings.extend(
            self._detect_shadowed_rules(normalized_rules)
        )

        result.findings.extend(
            self._detect_insecure_services(normalized_rules)
        )

        result.findings.extend(
            self._detect_overly_permissive_rules(normalized_rules)
        )

        result.findings.extend(
            self._detect_blocked_insecure_services(normalized_rules)
        )

        return result

    def analyze_json_file(
        self,
        path: str | Path,
    ) -> FirewallAnalysisResult:
        """Load structured firewall rules from a JSON file."""

        file_path = Path(path)

        if not file_path.exists():
            raise FirewallAnalyzerError(
                f"Firewall configuration file does not exist: {file_path}"
            )

        if not file_path.is_file():
            raise FirewallAnalyzerError(
                f"Firewall configuration path is not a file: {file_path}"
            )

        try:
            with file_path.open("r", encoding="utf-8") as file:
                data = json.load(file)
        except json.JSONDecodeError as exc:
            raise FirewallAnalyzerError(
                f"Invalid JSON firewall configuration: {exc}"
            ) from exc
        except OSError as exc:
            raise FirewallAnalyzerError(
                f"Unable to read firewall configuration: {exc}"
            ) from exc

        if isinstance(data, dict):
            rules = data.get("rules")

            if rules is None:
                raise FirewallAnalyzerError(
                    "Firewall JSON must contain a 'rules' list."
                )
        elif isinstance(data, list):
            rules = data
        else:
            raise FirewallAnalyzerError(
                "Firewall JSON must contain either a rule list or "
                "an object containing a 'rules' list."
            )

        return self.analyze(rules)

    def sample_rules(self) -> list[FirewallRule]:
        """Return deterministic sample rules for demonstration."""

        return [
            FirewallRule(
                rule_id="FW-001",
                source="ANY",
                destination="ANY",
                port="22",
                protocol="TCP",
                action="ALLOW",
                description="SSH administration",
            ),
            FirewallRule(
                rule_id="FW-002",
                source="192.168.0.0/24",
                destination="ANY",
                port="80",
                protocol="TCP",
                action="ALLOW",
                description="Internal web access",
            ),
            FirewallRule(
                rule_id="FW-003",
                source="ANY",
                destination="ANY",
                port="23",
                protocol="TCP",
                action="DENY",
                description="Block Telnet",
            ),
            FirewallRule(
                rule_id="FW-004",
                source="ANY",
                destination="ANY",
                port="443",
                protocol="TCP",
                action="ALLOW",
                description="HTTPS access",
            ),
            FirewallRule(
                rule_id="FW-005",
                source="ANY",
                destination="ANY",
                port="1000-65535",
                protocol="TCP",
                action="ALLOW",
                description="Broad TCP access",
            ),
            FirewallRule(
                rule_id="FW-006",
                source="ANY",
                destination="ANY",
                port="443",
                protocol="TCP",
                action="ALLOW",
                description="Duplicate HTTPS rule",
            ),
        ]

    # ------------------------------------------------------------------
    # Rule normalization
    # ------------------------------------------------------------------

    def _normalize_rules(
        self,
        rules: Iterable[FirewallRule | dict[str, Any]],
    ) -> list[FirewallRule]:
        if rules is None:
            raise FirewallAnalyzerError("Firewall rules cannot be None.")

        if isinstance(rules, (str, bytes, dict)):
            raise FirewallAnalyzerError(
                "Firewall rules must be an iterable collection of rules."
            )

        try:
            rule_list = list(rules)
        except TypeError as exc:
            raise FirewallAnalyzerError(
                "Firewall rules must be iterable."
            ) from exc

        normalized: list[FirewallRule] = []

        for rule in rule_list:
            if isinstance(rule, FirewallRule):
                normalized.append(rule)
            elif isinstance(rule, dict):
                normalized.append(FirewallRule.from_dict(rule))
            else:
                raise FirewallAnalyzerError(
                    "Each firewall rule must be a FirewallRule or dictionary."
                )

        return normalized

    # ------------------------------------------------------------------
    # Access analysis
    # ------------------------------------------------------------------

    def _detect_unrestricted_access(
        self,
        rules: list[FirewallRule],
    ) -> list[FirewallFinding]:
        findings: list[FirewallFinding] = []

        for rule in rules:
            if rule.action != "ALLOW":
                continue

            source_any = self._is_any_network(rule.source)
            destination_any = self._is_any_network(rule.destination)

            if source_any and not destination_any:
                findings.append(
                    self._finding(
                        rule,
                        finding_type="UNRESTRICTED_SOURCE_ACCESS",
                        severity="HIGH"
                        if self._contains_sensitive_port(rule.port)
                        else "MEDIUM",
                        observation=(
                            "The rule permits traffic from an unrestricted "
                            "source."
                        ),
                        risk=(
                            "A broader set of source systems can access the "
                            "destination than may be necessary."
                        ),
                        recommendation=(
                            "Restrict the source to the networks or hosts "
                            "that require access."
                        ),
                        evidence={
                            "source": rule.source,
                            "destination": rule.destination,
                            "port": rule.port,
                            "action": rule.action,
                        },
                    )
                )

            if destination_any and not source_any:
                findings.append(
                    self._finding(
                        rule,
                        finding_type="UNRESTRICTED_DESTINATION_ACCESS",
                        severity="MEDIUM",
                        observation=(
                            "The rule permits traffic to an unrestricted "
                            "destination."
                        ),
                        risk=(
                            "The rule can allow access to destinations "
                            "outside the intended security boundary."
                        ),
                        recommendation=(
                            "Restrict the destination to required hosts or "
                            "network segments."
                        ),
                        evidence={
                            "source": rule.source,
                            "destination": rule.destination,
                            "port": rule.port,
                            "action": rule.action,
                        },
                    )
                )

        return findings

    def _detect_broad_ports(
        self,
        rules: list[FirewallRule],
    ) -> list[FirewallFinding]:
        findings: list[FirewallFinding] = []

        for rule in rules:
            port_count = self._port_count(rule.port)

            if port_count <= self.broad_port_threshold:
                continue

            severity = "HIGH" if rule.action == "ALLOW" else "MEDIUM"

            findings.append(
                self._finding(
                    rule,
                    finding_type="BROAD_PORT_RANGE",
                    severity=severity,
                    observation=(
                        f"The rule covers approximately {port_count} "
                        "ports."
                    ),
                    risk=(
                        "A broad port range can expose more services than "
                        "are required by the stated rule."
                    ),
                    recommendation=(
                        "Restrict the rule to the smallest required set "
                        "of ports."
                    ),
                    evidence={
                        "port": rule.port,
                        "estimated_port_count": port_count,
                        "threshold": self.broad_port_threshold,
                    },
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Duplicate/conflict/shadow analysis
    # ------------------------------------------------------------------

    def _detect_duplicate_rules(
        self,
        rules: list[FirewallRule],
    ) -> list[FirewallFinding]:
        findings: list[FirewallFinding] = []
        seen: dict[tuple[str, ...], FirewallRule] = {}

        for rule in rules:
            key = (
                self._normalize_network(rule.source),
                self._normalize_network(rule.destination),
                self._normalize_port(rule.port),
                rule.protocol,
                rule.action,
            )

            if key in seen:
                original = seen[key]

                findings.append(
                    self._finding(
                        rule,
                        finding_type="DUPLICATE_RULE",
                        severity="LOW",
                        observation=(
                            f"This rule duplicates rule "
                            f"{original.rule_id}."
                        ),
                        risk=(
                            "Duplicate rules can increase configuration "
                            "complexity and make policy review harder."
                        ),
                        recommendation=(
                            "Review the duplicate and retain only the "
                            "required policy entry."
                        ),
                        evidence={
                            "duplicate_of": original.rule_id,
                            "rule": rule.to_dict(),
                        },
                    )
                )
            else:
                seen[key] = rule

        return findings

    def _detect_conflicting_rules(
        self,
        rules: list[FirewallRule],
    ) -> list[FirewallFinding]:
        findings: list[FirewallFinding] = []

        for index, rule in enumerate(rules):
            for previous in rules[:index]:
                if rule.action == previous.action:
                    continue

                if not self._rules_overlap(previous, rule):
                    continue

                findings.append(
                    self._finding(
                        rule,
                        finding_type="CONFLICTING_RULE",
                        severity="HIGH",
                        observation=(
                            f"This rule overlaps with rule "
                            f"{previous.rule_id} but specifies a different "
                            "action."
                        ),
                        risk=(
                            "Overlapping rules with different actions can "
                            "make the effective policy dependent on rule "
                            "ordering or firewall implementation."
                        ),
                        recommendation=(
                            "Review rule ordering and remove ambiguity by "
                            "making the intended policy explicit."
                        ),
                        evidence={
                            "conflicting_rule": previous.rule_id,
                            "current_action": rule.action,
                            "previous_action": previous.action,
                        },
                    )
                )

        return findings

    def _detect_shadowed_rules(
        self,
        rules: list[FirewallRule],
    ) -> list[FirewallFinding]:
        findings: list[FirewallFinding] = []

        for index, rule in enumerate(rules):
            for previous in rules[:index]:
                if previous.action != rule.action:
                    continue

                if not self._rule_contains(previous, rule):
                    continue

                if self._rules_equal(previous, rule):
                    continue

                findings.append(
                    self._finding(
                        rule,
                        finding_type="SHADOWED_RULE",
                        severity="LOW",
                        observation=(
                            f"This rule is covered by earlier rule "
                            f"{previous.rule_id}."
                        ),
                        risk=(
                            "The later rule may be redundant depending on "
                            "the firewall's rule-processing model."
                        ),
                        recommendation=(
                            "Review the rule order and remove redundant "
                            "rules where appropriate."
                        ),
                        evidence={
                            "shadowing_rule": previous.rule_id,
                            "current_rule": rule.rule_id,
                        },
                    )
                )
                break

        return findings

    # ------------------------------------------------------------------
    # Service analysis
    # ------------------------------------------------------------------

    def _detect_insecure_services(
        self,
        rules: list[FirewallRule],
    ) -> list[FirewallFinding]:
        findings: list[FirewallFinding] = []

        for rule in rules:
            if rule.action != "ALLOW":
                continue

            ports = self._extract_explicit_ports(rule.port)

            for port in ports:
                service = self.INSECURE_SERVICES.get(port)

                if service is None:
                    continue

                severity = "HIGH" if port in {23, 3389} else "MEDIUM"

                findings.append(
                    self._finding(
                        rule,
                        finding_type="INSECURE_SERVICE_ALLOWED",
                        severity=severity,
                        observation=(
                            f"The rule allows {service} traffic on "
                            f"port {port}."
                        ),
                        risk=(
                            f"{service} may expose a service that requires "
                            "careful restriction and secure configuration."
                        ),
                        recommendation=(
                            "Confirm the service is required, restrict "
                            "access to authorized sources, and prefer "
                            "secure alternatives where appropriate."
                        ),
                        evidence={
                            "service": service,
                            "port": port,
                            "protocol": rule.protocol,
                            "source": rule.source,
                            "destination": rule.destination,
                        },
                    )
                )

        return findings

    def _detect_overly_permissive_rules(
        self,
        rules: list[FirewallRule],
    ) -> list[FirewallFinding]:
        findings: list[FirewallFinding] = []

        for rule in rules:
            if rule.action != "ALLOW":
                continue

            source_any = self._is_any_network(rule.source)
            destination_any = self._is_any_network(rule.destination)
            port_any = self._is_any_port(rule.port)
            protocol_any = rule.protocol == "ANY"

            if (
                source_any
                and destination_any
                and port_any
                and protocol_any
            ):
                severity = "CRITICAL"

                findings.append(
                    self._finding(
                        rule,
                        finding_type="OVERLY_PERMISSIVE_RULE",
                        severity=severity,
                        observation=(
                            "The rule allows traffic from any source to "
                            "any destination across any port and protocol."
                        ),
                        risk=(
                            "This configuration represents an extremely "
                            "broad allow policy."
                        ),
                        recommendation=(
                            "Replace broad access with narrowly scoped "
                            "source, destination, protocol, and port "
                            "requirements."
                        ),
                        evidence={
                            "source": rule.source,
                            "destination": rule.destination,
                            "port": rule.port,
                            "protocol": rule.protocol,
                            "action": rule.action,
                        },
                    )
                )

        return findings

    def _detect_blocked_insecure_services(
        self,
        rules: list[FirewallRule],
    ) -> list[FirewallFinding]:
        findings: list[FirewallFinding] = []

        for rule in rules:
            if rule.action != "DENY":
                continue

            ports = self._extract_explicit_ports(rule.port)

            for port in ports:
                service = self.INSECURE_SERVICES.get(port)

                if service is None:
                    continue

                findings.append(
                    self._finding(
                        rule,
                        finding_type="INSECURE_SERVICE_BLOCKED",
                        severity="INFO",
                        observation=(
                            f"The rule explicitly denies {service} "
                            f"traffic on port {port}."
                        ),
                        risk=(
                            "No direct configuration risk is identified "
                            "from this observation."
                        ),
                        recommendation=(
                            "Keep the rule if blocking this service is "
                            "consistent with the organization's policy."
                        ),
                        evidence={
                            "service": service,
                            "port": port,
                            "action": rule.action,
                        },
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # Matching helpers
    # ------------------------------------------------------------------

    def _is_any_network(self, value: str) -> bool:
        normalized = str(value).strip().upper()

        if normalized in {"ANY", "*", "0.0.0.0/0", "::/0"}:
            return True

        return False

    def _is_any_port(self, value: str) -> bool:
        normalized = str(value).strip().upper()

        return normalized in {
            "ANY",
            "*",
            "ALL",
            "1-65535",
            "0-65535",
        }

    def _normalize_network(self, value: str) -> str:
        if self._is_any_network(value):
            return "ANY"

        try:
            network = ipaddress.ip_network(
                value,
                strict=False,
            )
            return str(network)
        except ValueError:
            return str(value).strip().upper()

    def _normalize_port(self, value: str) -> str:
        return str(value).strip().upper()

    def _parse_port_ranges(
        self,
        value: str,
    ) -> list[tuple[int, int]]:
        normalized = str(value).strip().upper()

        if normalized in {"ANY", "*", "ALL"}:
            return [(1, 65535)]

        ranges: list[tuple[int, int]] = []

        for part in normalized.split(","):
            part = part.strip()

            if not part:
                continue

            if "-" in part:
                start_text, end_text = part.split("-", 1)

                try:
                    start = int(start_text)
                    end = int(end_text)
                except ValueError:
                    continue
            else:
                try:
                    start = int(part)
                    end = start
                except ValueError:
                    continue

            if not (1 <= start <= 65535):
                continue

            if not (1 <= end <= 65535):
                continue

            if start > end:
                start, end = end, start

            ranges.append((start, end))

        return ranges

    def _port_count(self, value: str) -> int:
        ranges = self._parse_port_ranges(value)

        return sum(
            (end - start) + 1
            for start, end in ranges
        )

    def _extract_explicit_ports(self, value: str) -> list[int]:
        ports: list[int] = []

        for start, end in self._parse_port_ranges(value):
            if start == end:
                ports.append(start)

        return ports

    def _contains_sensitive_port(self, value: str) -> bool:
        return any(
            port in self.SENSITIVE_SERVICES
            for port in self._extract_explicit_ports(value)
        )

    def _network_contains(
        self,
        outer: str,
        inner: str,
    ) -> bool:
        if self._is_any_network(outer):
            return True

        if self._is_any_network(inner):
            return False

        try:
            outer_network = ipaddress.ip_network(
                outer,
                strict=False,
            )
            inner_network = ipaddress.ip_network(
                inner,
                strict=False,
            )

            return inner_network.subnet_of(outer_network)
        except ValueError:
            return outer.strip().upper() == inner.strip().upper()

    def _ports_contain(
        self,
        outer: str,
        inner: str,
    ) -> bool:
        outer_ranges = self._parse_port_ranges(outer)
        inner_ranges = self._parse_port_ranges(inner)

        if not outer_ranges or not inner_ranges:
            return self._normalize_port(outer) == self._normalize_port(inner)

        return all(
            any(
                outer_start <= inner_start
                and outer_end >= inner_end
                for outer_start, outer_end in outer_ranges
            )
            for inner_start, inner_end in inner_ranges
        )

    def _protocol_contains(
        self,
        outer: str,
        inner: str,
    ) -> bool:
        if outer == "ANY":
            return True

        return outer == inner

    def _rule_contains(
        self,
        outer: FirewallRule,
        inner: FirewallRule,
    ) -> bool:
        return (
            self._network_contains(outer.source, inner.source)
            and self._network_contains(
                outer.destination,
                inner.destination,
            )
            and self._ports_contain(outer.port, inner.port)
            and self._protocol_contains(
                outer.protocol,
                inner.protocol,
            )
        )

    def _rules_equal(
        self,
        first: FirewallRule,
        second: FirewallRule,
    ) -> bool:
        return (
            self._normalize_network(first.source)
            == self._normalize_network(second.source)
            and self._normalize_network(first.destination)
            == self._normalize_network(second.destination)
            and self._normalize_port(first.port)
            == self._normalize_port(second.port)
            and first.protocol == second.protocol
            and first.action == second.action
        )

    def _rules_overlap(
        self,
        first: FirewallRule,
        second: FirewallRule,
    ) -> bool:
        source_overlap = (
            self._network_contains(first.source, second.source)
            or self._network_contains(second.source, first.source)
        )

        destination_overlap = (
            self._network_contains(
                first.destination,
                second.destination,
            )
            or self._network_contains(
                second.destination,
                first.destination,
            )
        )

        port_overlap = self._ports_overlap(
            first.port,
            second.port,
        )

        protocol_overlap = (
            first.protocol == second.protocol
            or first.protocol == "ANY"
            or second.protocol == "ANY"
        )

        return (
            source_overlap
            and destination_overlap
            and port_overlap
            and protocol_overlap
        )

    def _ports_overlap(
        self,
        first: str,
        second: str,
    ) -> bool:
        first_ranges = self._parse_port_ranges(first)
        second_ranges = self._parse_port_ranges(second)

        if not first_ranges or not second_ranges:
            return (
                self._normalize_port(first)
                == self._normalize_port(second)
            )

        for first_start, first_end in first_ranges:
            for second_start, second_end in second_ranges:
                if (
                    first_start <= second_end
                    and second_start <= first_end
                ):
                    return True

        return False

    # ------------------------------------------------------------------
    # Finding creation / formatting
    # ------------------------------------------------------------------

    def _finding(
        self,
        rule: FirewallRule,
        finding_type: str,
        severity: str,
        observation: str,
        risk: str,
        recommendation: str,
        evidence: dict[str, Any],
    ) -> FirewallFinding:
        finding_number = abs(
            hash(
                (
                    rule.rule_id,
                    finding_type,
                    observation,
                )
            )
        ) % 10_000_000

        finding_id = (
            f"FWF-{finding_number:07d}"
        )

        return FirewallFinding(
            finding_id=finding_id,
            rule_id=rule.rule_id,
            finding_type=finding_type,
            severity=severity,
            observation=observation,
            potential_risk=risk,
            recommendation=recommendation,
            evidence=evidence,
        )


def format_firewall_results(
    result: FirewallAnalysisResult,
) -> str:
    """Format firewall analysis for terminal presentation."""

    if not isinstance(result, FirewallAnalysisResult):
        raise FirewallAnalyzerError(
            "result must be a FirewallAnalysisResult."
        )

    lines: list[str] = []

    lines.append("FIREWALL ANALYSIS")
    lines.append("=" * 90)
    lines.append(
        f"Rules Analyzed       : {result.rules_analyzed}"
    )
    lines.append(
        f"Findings Generated   : {result.finding_count}"
    )
    lines.append(
        f"Highest Severity     : {result.highest_severity()}"
    )
    lines.append("")

    lines.append("SEVERITY DISTRIBUTION")
    lines.append("-" * 90)

    for severity in SEVERITY_LEVELS:
        lines.append(
            f"{severity:<10}: "
            f"{result.severity_distribution()[severity]}"
        )

    lines.append("")

    if not result.findings:
        lines.append("SECURITY STATUS")
        lines.append("-" * 90)
        lines.append(
            "No configured firewall rule produced a finding."
        )
        lines.append("")
        lines.append(
            "Note: absence of findings does not prove that the "
            "firewall configuration is secure."
        )
        return "\n".join(lines)

    lines.append("FIREWALL FINDINGS")
    lines.append("=" * 90)

    for index, finding in enumerate(result.findings, start=1):
        lines.append("")
        lines.append(f"[{index}] FIREWALL FINDING")
        lines.append("-" * 40)
        lines.append(
            f"Finding ID         : {finding.finding_id}"
        )
        lines.append(
            f"Rule ID            : {finding.rule_id}"
        )
        lines.append(
            f"Finding Type       : {finding.finding_type}"
        )
        lines.append(
            f"Severity           : {finding.severity}"
        )
        lines.append(
            f"Observation        : {finding.observation}"
        )
        lines.append(
            f"Potential Risk     : {finding.potential_risk}"
        )
        lines.append(
            f"Recommendation     : {finding.recommendation}"
        )
        lines.append(
            f"Evidence           : {finding.evidence}"
        )

    lines.append("")
    lines.append("ASSESSMENT NOTE")
    lines.append("-" * 90)
    lines.append(
        "Firewall findings represent rule-based configuration "
        "observations that may require review."
    )
    lines.append(
        "A finding is not proof that a security incident has occurred."
    )

    return "\n".join(lines)