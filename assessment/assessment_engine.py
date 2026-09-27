"""
NETWATCH Phase 12 - Security Assessment Engine.

Centralizes results from the NETWATCH analysis modules and produces
a structured security assessment.

Important:
    Findings are observational indicators. They are not proof of
    malicious intent or compromise.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from ipaddress import ip_address, ip_network
from typing import Any, Iterable, Mapping
from uuid import uuid4


SEVERITIES = (
    "INFO",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
)


def _now() -> str:
    """Return a UTC timestamp suitable for assessment records."""
    return datetime.now(UTC).replace(
        microsecond=0
    ).isoformat().replace(
        "+00:00",
        "Z",
    )


def _new_assessment_id() -> str:
    """Generate a unique assessment identifier."""
    return f"ASM-{uuid4().hex[:10].upper()}"


def _to_mapping(value: Any) -> dict[str, Any]:
    """
    Convert supported objects into a dictionary.

    Supports:
        - mappings
        - dataclasses
        - objects exposing to_dict()
        - regular objects with __dict__
    """
    if value is None:
        return {}

    if isinstance(value, Mapping):
        return dict(value)

    to_dict = getattr(value, "to_dict", None)

    if callable(to_dict):
        try:
            result = to_dict()

            if isinstance(result, Mapping):
                return dict(result)

        except Exception:
            pass

    try:
        result = asdict(value)

        if isinstance(result, Mapping):
            return dict(result)

    except TypeError:
        pass

    if hasattr(value, "__dict__"):
        try:
            return dict(value.__dict__)
        except Exception:
            pass

    return {}


def _as_list(value: Any) -> list[Any]:
    """Normalize a collection-like value into a list."""
    if value is None:
        return []

    if isinstance(value, Mapping):
        return list(value.values())

    if isinstance(value, (str, bytes)):
        return [value]

    if isinstance(value, Iterable):
        return list(value)

    return [value]


def _extract_collection(
    value: Any,
    keys: tuple[str, ...],
) -> list[Any]:
    """Extract a collection from a mapping/object using candidate keys."""
    if value is None:
        return []

    if isinstance(value, Mapping):
        for key in keys:
            if key in value:
                return _as_list(value[key])

    converted = _to_mapping(value)

    for key in keys:
        if key in converted:
            return _as_list(converted[key])

    return []


def _extract_severity(value: Any) -> str | None:
    """Extract and normalize a supported severity."""
    data = _to_mapping(value)

    severity = data.get("severity")

    if severity is None:
        return None

    severity = str(severity).strip().upper()

    if severity in SEVERITIES:
        return severity

    return None


def _extract_ip(value: Any) -> str | None:
    """Extract an IPv4/IPv6 address from a supported record."""
    data = _to_mapping(value)

    candidates = (
        data.get("ip_address"),
        data.get("ip"),
        data.get("address"),
        data.get("host"),
        data.get("target"),
    )

    for candidate in candidates:
        if not candidate:
            continue

        candidate_text = str(candidate).strip()

        try:
            ip_address(candidate_text)
            return candidate_text
        except ValueError:
            continue

    return None


def _infer_scope(
    context: Mapping[str, Any],
) -> str:
    """
    Infer a useful network scope when the session context does not
    explicitly provide one.

    Priority:
        1. Explicit scope/network/target_network.
        2. Network information exposed by the discovery result.
        3. A /24 derived from the first discovered IPv4 address.
        4. 0.0.0.0/0 as a final valid fallback.

    The fallback exists so that a partially populated session can still
    be assessed without crashing.
    """

    explicit_keys = (
        "scope",
        "network",
        "network_scope",
        "target_network",
    )

    for key in explicit_keys:
        value = context.get(key)

        if value:
            try:
                return str(
                    ip_network(
                        str(value),
                        strict=False,
                    )
                )
            except ValueError:
                continue

    discovery = context.get("discovery")

    discovery_mapping = _to_mapping(
        discovery
    )

    for key in explicit_keys:
        value = discovery_mapping.get(key)

        if value:
            try:
                return str(
                    ip_network(
                        str(value),
                        strict=False,
                    )
                )
            except ValueError:
                continue

    discovery_items = _as_list(
        discovery
    )

    for item in discovery_items:
        address = _extract_ip(item)

        if not address:
            continue

        try:
            parsed = ip_address(address)

            if parsed.version == 4:
                return str(
                    ip_network(
                        f"{address}/24",
                        strict=False,
                    )
                )

        except ValueError:
            continue

    return "0.0.0.0/0"


@dataclass
class FindingSummary:
    """Severity distribution for an assessment."""

    info: int = 0
    low: int = 0
    medium: int = 0
    high: int = 0
    critical: int = 0

    @property
    def total(self) -> int:
        """Return total number of findings."""
        return (
            self.info
            + self.low
            + self.medium
            + self.high
            + self.critical
        )

    def add(self, severity: str) -> None:
        """Add one finding to the appropriate severity bucket."""
        normalized = str(
            severity
        ).strip().upper()

        if normalized == "INFO":
            self.info += 1

        elif normalized == "LOW":
            self.low += 1

        elif normalized == "MEDIUM":
            self.medium += 1

        elif normalized == "HIGH":
            self.high += 1

        elif normalized == "CRITICAL":
            self.critical += 1

    def to_dict(self) -> dict[str, int]:
        """Serialize the summary."""
        return {
            "INFO": self.info,
            "LOW": self.low,
            "MEDIUM": self.medium,
            "HIGH": self.high,
            "CRITICAL": self.critical,
            "TOTAL": self.total,
        }


@dataclass
class AssessmentResult:
    """Complete NETWATCH security assessment result."""

    assessment_id: str
    timestamp: str
    scope: str

    discovered_devices: list[dict[str, Any]] = field(
        default_factory=list
    )

    open_ports: list[dict[str, Any]] = field(
        default_factory=list
    )

    detected_services: list[dict[str, Any]] = field(
        default_factory=list
    )

    dns_findings: list[dict[str, Any]] = field(
        default_factory=list
    )

    http_findings: list[dict[str, Any]] = field(
        default_factory=list
    )

    traffic_findings: list[dict[str, Any]] = field(
        default_factory=list
    )

    ids_alerts: list[dict[str, Any]] = field(
        default_factory=list
    )

    firewall_findings: list[dict[str, Any]] = field(
        default_factory=list
    )

    topology_information: dict[str, Any] = field(
        default_factory=dict
    )

    finding_summary: FindingSummary = field(
        default_factory=FindingSummary
    )

    recommendations: list[str] = field(
        default_factory=list
    )

    notes: list[str] = field(
        default_factory=list
    )

    @property
    def device_count(self) -> int:
        return len(
            self.discovered_devices
        )

    @property
    def open_port_count(self) -> int:
        return len(
            self.open_ports
        )

    @property
    def alert_count(self) -> int:
        return len(
            self.ids_alerts
        )

    @property
    def firewall_finding_count(self) -> int:
        return len(
            self.firewall_findings
        )

    @property
    def total_findings(self) -> int:
        return self.finding_summary.total

    def to_dict(self) -> dict[str, Any]:
        """Serialize the complete assessment."""
        return {
            "assessment_id": self.assessment_id,
            "timestamp": self.timestamp,
            "scope": self.scope,
            "discovered_devices": self.discovered_devices,
            "open_ports": self.open_ports,
            "detected_services": self.detected_services,
            "dns_findings": self.dns_findings,
            "http_findings": self.http_findings,
            "traffic_findings": self.traffic_findings,
            "ids_alerts": self.ids_alerts,
            "firewall_findings": self.firewall_findings,
            "topology_information": self.topology_information,
            "finding_summary": self.finding_summary.to_dict(),
            "recommendations": self.recommendations,
            "notes": self.notes,
            "metrics": {
                "devices": self.device_count,
                "open_ports": self.open_port_count,
                "alerts": self.alert_count,
                "firewall_findings": self.firewall_finding_count,
                "total_findings": self.total_findings,
            },
        }


class AssessmentEngine:
    """
    Central assessment engine.

    The engine aggregates outputs from existing NETWATCH modules.
    It does not perform intrusive testing.
    """

    def __init__(self) -> None:
        self.last_result: AssessmentResult | None = None

    @staticmethod
    def _normalize_items(
        items: Iterable[Any] | Any,
    ) -> list[dict[str, Any]]:
        """Normalize arbitrary supported records into dictionaries."""
        normalized: list[dict[str, Any]] = []

        for item in _as_list(items):
            data = _to_mapping(item)

            if data:
                normalized.append(data)

        return normalized

    @staticmethod
    def _add_severities(
        summary: FindingSummary,
        items: Iterable[Any],
    ) -> None:
        """Add severities from a collection to a summary."""
        for item in items:
            severity = _extract_severity(item)

            if severity:
                summary.add(severity)

    @staticmethod
    def _build_recommendations(
        *,
        open_ports: list[dict[str, Any]],
        dns_findings: list[dict[str, Any]],
        http_findings: list[dict[str, Any]],
        traffic_findings: list[dict[str, Any]],
        ids_alerts: list[dict[str, Any]],
        firewall_findings: list[dict[str, Any]],
    ) -> list[str]:
        """Generate defensive recommendations from observed findings."""

        recommendations: list[str] = []

        if open_ports:
            recommendations.append(
                "Review exposed TCP services and disable unnecessary "
                "listening ports."
            )

        if dns_findings:
            recommendations.append(
                "Review DNS observations for unexpected records, "
                "configurations, or exposed information."
            )

        if http_findings:
            recommendations.append(
                "Review HTTP/HTTPS security configuration and missing "
                "security controls."
            )

        if traffic_findings:
            recommendations.append(
                "Review traffic observations for unusual volumes, "
                "protocol distributions, or connection patterns."
            )

        if ids_alerts:
            recommendations.append(
                "Review IDS alerts and validate the associated traffic "
                "against expected network activity."
            )

        if firewall_findings:
            recommendations.append(
                "Review firewall findings and restrict broad or "
                "unnecessary access rules."
            )

        if not recommendations:
            recommendations.append(
                "Continue periodic authorized network assessments and "
                "monitor for changes."
            )

        return recommendations

    @staticmethod
    def _validate_scope(
        scope: str,
    ) -> str:
        """Validate an IPv4 or IPv6 network scope."""

        if not isinstance(scope, str):
            raise ValueError(
                "Assessment scope must be a string."
            )

        scope = scope.strip()

        if not scope:
            raise ValueError(
                "Assessment scope cannot be empty."
            )

        try:
            ip_network(
                scope,
                strict=False,
            )

        except ValueError as exc:
            raise ValueError(
                "Assessment scope must be a valid IPv4 or IPv6 network."
            ) from exc

        return scope

    def assess(
        self,
        context: Mapping[str, Any] | None = None,
    ) -> AssessmentResult:
        """
        Build an assessment from the current NETWATCH session.

        This is the integration entry point used by main.py.

        Expected context keys:

            discovery
            ports
            dns
            http
            traffic
            ids
            firewall
            topology
            routing

        Optional:

            scope
            notes

        The method translates the different module result formats into
        the normalized arguments accepted by build_assessment().
        """

        if context is None:
            context = {}

        if not isinstance(
            context,
            Mapping,
        ):
            raise TypeError(
                "Assessment context must be a mapping."
            )

        scope = _infer_scope(
            context
        )

        discovery_result = context.get(
            "discovery"
        )

        port_result = context.get(
            "ports"
        )

        dns_result = context.get(
            "dns"
        )

        http_result = context.get(
            "http"
        )

        traffic_result = context.get(
            "traffic"
        )

        ids_result = context.get(
            "ids"
        )

        firewall_result = context.get(
            "firewall"
        )

        topology_result = context.get(
            "topology"
        )

        discovered_devices = _extract_collection(
            discovery_result,
            (
                "devices",
                "discovered_devices",
                "hosts",
                "discovered_hosts",
                "results",
            ),
        )

        if not discovered_devices:
            discovered_devices = _as_list(
                discovery_result
            )

        normalized_ports = _extract_collection(
            port_result,
            (
                "results",
                "port_results",
                "open_ports",
                "ports",
            ),
        )

        if not normalized_ports:
            normalized_ports = _as_list(
                port_result
            )

        open_ports: list[Any] = []

        for item in normalized_ports:
            data = _to_mapping(item)

            if not data:
                continue

            state = str(
                data.get(
                    "state",
                    data.get(
                        "status",
                        "",
                    ),
                )
            ).strip().upper()

            if (
                state.startswith("OPEN")
                or state == "LISTENING"
            ):
                open_ports.append(
                    item
                )

        detected_services: list[dict[str, Any]] = []

        for item in open_ports:
            data = _to_mapping(item)

            service = data.get(
                "service"
            )

            if service:
                detected_services.append(
                    {
                        "port": data.get(
                            "port"
                        ),
                        "protocol": data.get(
                            "protocol"
                        ),
                        "service": service,
                    }
                )

        dns_findings = _extract_collection(
            dns_result,
            (
                "findings",
                "dns_findings",
                "records",
                "results",
            ),
        )

        if not dns_findings and dns_result is not None:
            dns_mapping = _to_mapping(
                dns_result
            )

            if dns_mapping:
                dns_findings = [
                    {
                        "type": "DNS",
                        "severity": "INFO",
                        "description": (
                            "DNS analysis result available "
                            "for review."
                        ),
                        "details": dns_mapping,
                    }
                ]

        http_findings = _extract_collection(
            http_result,
            (
                "findings",
                "http_findings",
                "security_findings",
                "results",
            ),
        )

        if not http_findings and http_result is not None:
            http_mapping = _to_mapping(
                http_result
            )

            if http_mapping:
                http_findings = [
                    {
                        "type": "HTTP_SECURITY",
                        "severity": "LOW",
                        "description": (
                            "HTTP/HTTPS analysis result available "
                            "for security review."
                        ),
                        "details": http_mapping,
                    }
                ]

        traffic_findings = _extract_collection(
            traffic_result,
            (
                "findings",
                "traffic_findings",
                "alerts",
                "results",
            ),
        )

        if not traffic_findings and traffic_result is not None:
            traffic_mapping = _to_mapping(
                traffic_result
            )

            if traffic_mapping:
                packet_count = traffic_mapping.get(
                    "packet_count",
                    traffic_mapping.get(
                        "total_packets"
                    ),
                )

                total_bytes = traffic_mapping.get(
                    "total_bytes"
                )

                if (
                    packet_count is not None
                    or total_bytes is not None
                ):
                    traffic_findings = [
                        {
                            "type": "TRAFFIC_OBSERVATION",
                            "severity": "INFO",
                            "description": (
                                "Traffic analysis result available "
                                "for security review."
                            ),
                            "packet_count": packet_count,
                            "total_bytes": total_bytes,
                        }
                    ]

        ids_alerts = _extract_collection(
            ids_result,
            (
                "alerts",
                "ids_alerts",
                "detections",
                "findings",
                "results",
            ),
        )

        if not ids_alerts and ids_result is not None:
            ids_mapping = _to_mapping(
                ids_result
            )

            if ids_mapping:
                ids_alerts = [
                    {
                        "alert_id": "SESSION-IDS",
                        "type": "IDS_RESULT",
                        "severity": "INFO",
                        "description": (
                            "IDS analysis result available "
                            "for validation."
                        ),
                        "details": ids_mapping,
                    }
                ]

        firewall_findings = _extract_collection(
            firewall_result,
            (
                "findings",
                "firewall_findings",
                "alerts",
                "results",
            ),
        )

        if not firewall_findings and firewall_result is not None:
            firewall_mapping = _to_mapping(
                firewall_result
            )

            if firewall_mapping:
                firewall_findings = [
                    {
                        "finding_id": "SESSION-FIREWALL",
                        "severity": "INFO",
                        "title": (
                            "Firewall analysis result available "
                            "for review."
                        ),
                        "details": firewall_mapping,
                    }
                ]

        topology_information = _to_mapping(
            topology_result
        )

        if topology_information:
            nodes = topology_information.get(
                "nodes"
            )

            connections = topology_information.get(
                "connections",
                topology_information.get(
                    "edges"
                ),
            )

            if isinstance(
                nodes,
                (list, tuple, set),
            ):
                topology_information["nodes"] = len(
                    nodes
                )

            if isinstance(
                connections,
                (list, tuple, set),
            ):
                topology_information["connections"] = len(
                    connections
                )

            topology_information.setdefault(
                "available",
                True,
            )

        elif topology_result is not None:
            topology_information = {
                "available": True,
                "details": str(
                    topology_result
                ),
            }

        notes = list(
            context.get(
                "notes",
                [],
            )
            or []
        )

        if scope == "0.0.0.0/0":
            notes.append(
                "Assessment scope was not explicitly supplied by the "
                "session; no network CIDR was available for the stored "
                "discovery result."
            )

        return self.build_assessment(
            scope=scope,
            discovered_devices=discovered_devices,
            open_ports=open_ports,
            detected_services=detected_services,
            dns_findings=dns_findings,
            http_findings=http_findings,
            traffic_findings=traffic_findings,
            ids_alerts=ids_alerts,
            firewall_findings=firewall_findings,
            topology_information=topology_information,
            notes=notes,
        )

    def build_assessment(
        self,
        *,
        scope: str,
        discovered_devices: Iterable[Any] | Any = None,
        open_ports: Iterable[Any] | Any = None,
        detected_services: Iterable[Any] | Any = None,
        dns_findings: Iterable[Any] | Any = None,
        http_findings: Iterable[Any] | Any = None,
        traffic_findings: Iterable[Any] | Any = None,
        ids_alerts: Iterable[Any] | Any = None,
        firewall_findings: Iterable[Any] | Any = None,
        topology_information: Any = None,
        notes: Iterable[str] | None = None,
    ) -> AssessmentResult:
        """
        Build a complete assessment from module results.

        This remains the primary low-level API and intentionally keeps
        all parameters keyword-only for compatibility with Phase 12 tests
        and direct callers.
        """

        normalized_scope = self._validate_scope(
            scope
        )

        devices = self._normalize_items(
            discovered_devices
        )

        ports = self._normalize_items(
            open_ports
        )

        services = self._normalize_items(
            detected_services
        )

        dns = self._normalize_items(
            dns_findings
        )

        http = self._normalize_items(
            http_findings
        )

        traffic = self._normalize_items(
            traffic_findings
        )

        alerts = self._normalize_items(
            ids_alerts
        )

        firewall = self._normalize_items(
            firewall_findings
        )

        topology = _to_mapping(
            topology_information
        )

        summary = FindingSummary()

        self._add_severities(
            summary,
            dns,
        )

        self._add_severities(
            summary,
            http,
        )

        self._add_severities(
            summary,
            traffic,
        )

        self._add_severities(
            summary,
            alerts,
        )

        self._add_severities(
            summary,
            firewall,
        )

        assessment_notes = [
            (
                "Assessment is observational and intended for "
                "authorized network-security analysis."
            ),
            (
                "Findings are indicators requiring validation and are "
                "not proof of malicious intent or compromise."
            ),
        ]

        if notes:
            assessment_notes.extend(
                str(note)
                for note in notes
                if str(note).strip()
            )

        recommendations = self._build_recommendations(
            open_ports=ports,
            dns_findings=dns,
            http_findings=http,
            traffic_findings=traffic,
            ids_alerts=alerts,
            firewall_findings=firewall,
        )

        result = AssessmentResult(
            assessment_id=_new_assessment_id(),
            timestamp=_now(),
            scope=normalized_scope,
            discovered_devices=devices,
            open_ports=ports,
            detected_services=services,
            dns_findings=dns,
            http_findings=http,
            traffic_findings=traffic,
            ids_alerts=alerts,
            firewall_findings=firewall,
            topology_information=topology,
            finding_summary=summary,
            recommendations=recommendations,
            notes=assessment_notes,
        )

        self.last_result = result

        return result

    def build_sample_assessment(
        self,
    ) -> AssessmentResult:
        """
        Build a deterministic sample assessment for testing/demo use.
        """

        return self.build_assessment(
            scope="192.168.0.0/24",
            discovered_devices=[
                {
                    "ip": "192.168.0.1",
                    "hostname": "Router",
                    "status": "UP",
                },
                {
                    "ip": "192.168.0.101",
                    "hostname": "Desktop-PC",
                    "status": "UP",
                },
                {
                    "ip": "192.168.0.107",
                    "hostname": "Laptop",
                    "status": "UP",
                },
            ],
            open_ports=[
                {
                    "port": 22,
                    "state": "OPEN",
                    "service": "SSH",
                },
                {
                    "port": 80,
                    "state": "OPEN",
                    "service": "HTTP",
                },
            ],
            detected_services=[
                {
                    "port": 22,
                    "service": "SSH",
                },
                {
                    "port": 80,
                    "service": "HTTP",
                },
            ],
            dns_findings=[
                {
                    "type": "DNS",
                    "severity": "INFO",
                    "description": "DNS observation recorded.",
                },
            ],
            http_findings=[
                {
                    "type": "HTTP_SECURITY",
                    "severity": "LOW",
                    "description": "Security header review required.",
                },
            ],
            traffic_findings=[
                {
                    "type": "TRAFFIC_VOLUME",
                    "severity": "MEDIUM",
                    "description": "Traffic volume requires review.",
                },
            ],
            ids_alerts=[
                {
                    "alert_id": "ALT-001",
                    "type": "PORT_SCAN",
                    "severity": "HIGH",
                    "description": (
                        "Repeated connection pattern observed."
                    ),
                },
                {
                    "alert_id": "ALT-002",
                    "type": "PROTOCOL",
                    "severity": "HIGH",
                    "description": (
                        "Unusual protocol observation."
                    ),
                },
            ],
            firewall_findings=[
                {
                    "finding_id": "FW-001",
                    "severity": "INFO",
                    "title": "Firewall rule observation",
                },
            ],
            topology_information={
                "available": True,
                "nodes": 6,
                "connections": 5,
                "router_candidate": "192.168.0.1",
            },
        )


def format_assessment_result(
    result: AssessmentResult,
) -> str:
    """Format an assessment result for terminal display."""

    if not isinstance(
        result,
        AssessmentResult,
    ):
        raise TypeError(
            "result must be an AssessmentResult instance."
        )

    summary = result.finding_summary

    lines = [
        "",
        "=" * 72,
        "NETWATCH SECURITY ASSESSMENT",
        "=" * 72,
        f"Assessment ID       : {result.assessment_id}",
        f"Timestamp           : {result.timestamp}",
        f"Scope               : {result.scope}",
        "",
        "ASSESSMENT METRICS",
        "-" * 72,
        f"Devices discovered  : {result.device_count}",
        f"Open ports          : {result.open_port_count}",
        f"Detected services   : {len(result.detected_services)}",
        f"DNS findings        : {len(result.dns_findings)}",
        f"HTTP findings       : {len(result.http_findings)}",
        f"Traffic findings    : {len(result.traffic_findings)}",
        f"IDS alerts          : {result.alert_count}",
        f"Firewall findings   : {result.firewall_finding_count}",
        "",
        "SEVERITY SUMMARY",
        "-" * 72,
        f"INFO                : {summary.info}",
        f"LOW                 : {summary.low}",
        f"MEDIUM              : {summary.medium}",
        f"HIGH                : {summary.high}",
        f"CRITICAL            : {summary.critical}",
        f"TOTAL FINDINGS      : {summary.total}",
        "",
        "RECOMMENDATIONS",
        "-" * 72,
    ]

    for index, recommendation in enumerate(
        result.recommendations,
        start=1,
    ):
        lines.append(
            f"{index}. {recommendation}"
        )

    lines.extend(
        [
            "",
            "NOTES",
            "-" * 72,
        ]
    )

    for note in result.notes:
        lines.append(
            f"- {note}"
        )

    lines.extend(
        [
            "=" * 72,
        ]
    )

    return "\n".join(
        lines
    )