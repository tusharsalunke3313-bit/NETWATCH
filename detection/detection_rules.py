"""
NETWATCH IDS Detection Rules.

Phase 7 - IDS / Security Detection Engine

This module contains rule-based, read-only detection logic for observed
network traffic.

The rules identify patterns that may deserve investigation. An alert is
an observation and is NOT proof of malicious intent.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any, Iterable, Optional


@dataclass(frozen=True)
class DetectionRuleConfig:
    """
    Configuration thresholds used by the IDS detection rules.
    """

    port_scan_unique_ports: int = 5
    excessive_connections: int = 20
    suspicious_port_repetitions: int = 5
    repeated_requests: int = 15
    abnormal_traffic_packets: int = 500
    abnormal_traffic_bytes: int = 1_000_000


class DetectionRules:
    """
    Collection of rule-based IDS detections.

    The class accepts packet-like objects from the Phase 6 traffic
    analyzer. It is deliberately tolerant of different packet summary
    representations so that it can work with both live Scapy traffic
    and deterministic test/sample data.
    """

    SUSPICIOUS_PORTS = {
        21: "FTP",
        23: "Telnet",
        25: "SMTP",
        110: "POP3",
        139: "NetBIOS",
        445: "SMB",
        1433: "MSSQL",
        1521: "Oracle",
        3306: "MySQL",
        3389: "RDP",
        5900: "VNC",
        6379: "Redis",
        9200: "Elasticsearch",
        27017: "MongoDB",
    }

    SUSPICIOUS_PROTOCOLS = {
        "TELNET",
        "FTP",
        "SMB",
        "NETBIOS",
    }

    def __init__(
        self,
        config: Optional[DetectionRuleConfig] = None,
    ) -> None:
        self.config = config or DetectionRuleConfig()
        self._validate_config()

    def _validate_config(self) -> None:
        """Validate IDS threshold configuration."""

        values = {
            "port_scan_unique_ports": self.config.port_scan_unique_ports,
            "excessive_connections": self.config.excessive_connections,
            "suspicious_port_repetitions": (
                self.config.suspicious_port_repetitions
            ),
            "repeated_requests": self.config.repeated_requests,
            "abnormal_traffic_packets": (
                self.config.abnormal_traffic_packets
            ),
            "abnormal_traffic_bytes": self.config.abnormal_traffic_bytes,
        }

        for name, value in values.items():
            if not isinstance(value, int):
                raise TypeError(f"{name} must be an integer.")

            if value <= 0:
                raise ValueError(
                    f"{name} must be greater than zero."
                )

    @staticmethod
    def _get_value(
        packet: Any,
        *names: str,
        default: Any = None,
    ) -> Any:
        """
        Read a value from either an object or dictionary.

        This allows the IDS engine to work with different packet-summary
        representations.
        """

        if isinstance(packet, dict):
            for name in names:
                if name in packet:
                    return packet[name]

            return default

        for name in names:
            if hasattr(packet, name):
                return getattr(packet, name)

        return default

    @classmethod
    def _source_ip(cls, packet: Any) -> str:
        """Extract the source IP address."""

        value = cls._get_value(
            packet,
            "source_ip",
            "src_ip",
            "source",
            "src",
            default="UNKNOWN",
        )

        return str(value)

    @classmethod
    def _destination_ip(cls, packet: Any) -> str:
        """Extract the destination IP address."""

        value = cls._get_value(
            packet,
            "destination_ip",
            "dest_ip",
            "destination",
            "dst_ip",
            "dst",
            default="UNKNOWN",
        )

        return str(value)

    @classmethod
    def _source_port(cls, packet: Any) -> Optional[int]:
        """Extract the source port when available."""

        value = cls._get_value(
            packet,
            "source_port",
            "src_port",
            "sport",
            default=None,
        )

        return cls._safe_int(value)

    @classmethod
    def _destination_port(cls, packet: Any) -> Optional[int]:
        """Extract the destination port when available."""

        value = cls._get_value(
            packet,
            "destination_port",
            "dest_port",
            "dport",
            default=None,
        )

        return cls._safe_int(value)

    @classmethod
    def _protocol(cls, packet: Any) -> str:
        """Extract the network protocol."""

        value = cls._get_value(
            packet,
            "protocol",
            "transport_protocol",
            default="UNKNOWN",
        )

        return str(value).upper()

    @classmethod
    def _application(cls, packet: Any) -> str:
        """Extract the application protocol when available."""

        value = cls._get_value(
            packet,
            "application",
            "application_protocol",
            "app_protocol",
            default="",
        )

        return str(value).upper()

    @classmethod
    def _packet_length(cls, packet: Any) -> int:
        """Extract packet length when available."""

        value = cls._get_value(
            packet,
            "length",
            "packet_length",
            "size",
            "bytes",
            default=0,
        )

        result = cls._safe_int(value)

        return result if result is not None else 0

    @staticmethod
    def _safe_int(value: Any) -> Optional[int]:
        """Convert a value to int without raising conversion errors."""

        if value is None:
            return None

        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @classmethod
    def _normalize_packets(
        cls,
        packets: Iterable[Any],
    ) -> list[Any]:
        """Convert packet input into a reusable list."""

        if packets is None:
            return []

        return list(packets)

    def detect_port_scanning(
        self,
        packets: Iterable[Any],
    ) -> list[dict[str, Any]]:
        """
        Detect possible port-scanning behavior.

        A source is flagged when it contacts at least the configured
        number of unique destination ports.
        """

        packet_list = self._normalize_packets(packets)

        source_ports: dict[str, set[int]] = defaultdict(set)

        for packet in packet_list:
            source = self._source_ip(packet)
            destination_port = self._destination_port(packet)

            if destination_port is not None:
                source_ports[source].add(destination_port)

        detections: list[dict[str, Any]] = []

        for source, ports in source_ports.items():
            if len(ports) >= self.config.port_scan_unique_ports:
                sorted_ports = sorted(ports)

                detections.append(
                    {
                        "source": source,
                        "destination": None,
                        "detection_type": "PORT_SCAN_DETECTED",
                        "severity": "HIGH",
                        "description": (
                            "The same source contacted multiple unique "
                            "destination ports within the observed traffic."
                        ),
                        "evidence": {
                            "unique_ports": len(sorted_ports),
                            "ports": sorted_ports,
                        },
                        "recommended_action": (
                            "Review the source activity and verify whether "
                            "the connection pattern is expected."
                        ),
                    }
                )

        return detections

    def detect_excessive_connections(
        self,
        packets: Iterable[Any],
    ) -> list[dict[str, Any]]:
        """Detect unusually large numbers of connections from one source."""

        packet_list = self._normalize_packets(packets)

        source_counts = Counter(
            self._source_ip(packet)
            for packet in packet_list
        )

        detections: list[dict[str, Any]] = []

        for source, count in source_counts.items():
            if count >= self.config.excessive_connections:
                detections.append(
                    {
                        "source": source,
                        "destination": None,
                        "detection_type": "EXCESSIVE_CONNECTIONS",
                        "severity": "MEDIUM",
                        "description": (
                            "A source generated a high number of observed "
                            "traffic records during the analysis window."
                        ),
                        "evidence": {
                            "observed_packets": count,
                        },
                        "recommended_action": (
                            "Review the source's connection volume and "
                            "confirm that the activity is expected."
                        ),
                    }
                )

        return detections

    def detect_suspicious_ports(
        self,
        packets: Iterable[Any],
    ) -> list[dict[str, Any]]:
        """
        Detect repeated access to commonly sensitive or legacy service
        ports.
        """

        packet_list = self._normalize_packets(packets)

        port_sources: dict[int, Counter[str]] = defaultdict(Counter)

        for packet in packet_list:
            destination_port = self._destination_port(packet)

            if destination_port in self.SUSPICIOUS_PORTS:
                source = self._source_ip(packet)
                port_sources[destination_port][source] += 1

        detections: list[dict[str, Any]] = []

        for port, source_counts in port_sources.items():
            service_name = self.SUSPICIOUS_PORTS[port]

            for source, count in source_counts.items():
                if count >= self.config.suspicious_port_repetitions:
                    detections.append(
                        {
                            "source": source,
                            "destination": None,
                            "detection_type": "SUSPICIOUS_PORT_ACTIVITY",
                            "severity": "MEDIUM",
                            "description": (
                                f"Repeated traffic was observed toward "
                                f"port {port}, commonly associated with "
                                f"{service_name}."
                            ),
                            "evidence": {
                                "destination_port": port,
                                "service": service_name,
                                "observed_connections": count,
                            },
                            "recommended_action": (
                                "Verify whether the service is authorized "
                                "and required on the destination system."
                            ),
                        }
                    )

        return detections

    def detect_unusual_connection_patterns(
        self,
        packets: Iterable[Any],
    ) -> list[dict[str, Any]]:
        """Detect sources communicating with multiple destinations."""

        packet_list = self._normalize_packets(packets)

        destinations_by_source: dict[str, set[str]] = defaultdict(set)

        for packet in packet_list:
            source = self._source_ip(packet)
            destination = self._destination_ip(packet)

            if destination != "UNKNOWN":
                destinations_by_source[source].add(destination)

        detections: list[dict[str, Any]] = []

        for source, destinations in destinations_by_source.items():
            if len(destinations) >= self.config.port_scan_unique_ports:
                detections.append(
                    {
                        "source": source,
                        "destination": None,
                        "detection_type": "UNUSUAL_CONNECTION_PATTERN",
                        "severity": "LOW",
                        "description": (
                            "A source communicated with multiple distinct "
                            "destinations during the observed window."
                        ),
                        "evidence": {
                            "unique_destinations": len(destinations),
                            "destinations": sorted(destinations),
                        },
                        "recommended_action": (
                            "Review the source's normal communication "
                            "pattern and investigate unexpected peers."
                        ),
                    }
                )

        return detections

    def detect_suspicious_protocols(
        self,
        packets: Iterable[Any],
    ) -> list[dict[str, Any]]:
        """Detect traffic using protocols requiring additional review."""

        packet_list = self._normalize_packets(packets)

        protocol_sources: dict[str, Counter[str]] = defaultdict(Counter)

        for packet in packet_list:
            protocol = self._protocol(packet)
            application = self._application(packet)

            detected_protocol = application or protocol

            if detected_protocol in self.SUSPICIOUS_PROTOCOLS:
                source = self._source_ip(packet)
                protocol_sources[detected_protocol][source] += 1

        detections: list[dict[str, Any]] = []

        for protocol, source_counts in protocol_sources.items():
            for source, count in source_counts.items():
                detections.append(
                    {
                        "source": source,
                        "destination": None,
                        "detection_type": "SUSPICIOUS_PROTOCOL_USAGE",
                        "severity": "LOW",
                        "description": (
                            f"Traffic using {protocol} was observed from "
                            f"the source."
                        ),
                        "evidence": {
                            "protocol": protocol,
                            "observed_packets": count,
                        },
                        "recommended_action": (
                            "Confirm that the protocol is authorized and "
                            "appropriately secured."
                        ),
                    }
                )

        return detections

    def detect_abnormal_traffic_volume(
        self,
        packets: Iterable[Any],
        total_bytes: Optional[int] = None,
    ) -> list[dict[str, Any]]:
        """Detect unusually large traffic volume."""

        packet_list = self._normalize_packets(packets)

        packet_count = len(packet_list)

        if total_bytes is None:
            total_bytes = sum(
                self._packet_length(packet)
                for packet in packet_list
            )

        if (
            packet_count < self.config.abnormal_traffic_packets
            and total_bytes < self.config.abnormal_traffic_bytes
        ):
            return []

        source_counts = Counter(
            self._source_ip(packet)
            for packet in packet_list
        )

        source = (
            source_counts.most_common(1)[0][0]
            if source_counts
            else "UNKNOWN"
        )

        return [
            {
                "source": source,
                "destination": None,
                "detection_type": "ABNORMAL_TRAFFIC_VOLUME",
                "severity": "MEDIUM",
                "description": (
                    "The observed traffic volume exceeded one or more "
                    "configured analysis thresholds."
                ),
                "evidence": {
                    "packet_count": packet_count,
                    "total_bytes": total_bytes,
                    "packet_threshold": (
                        self.config.abnormal_traffic_packets
                    ),
                    "byte_threshold": (
                        self.config.abnormal_traffic_bytes
                    ),
                },
                "recommended_action": (
                    "Review traffic volume against expected baseline "
                    "activity and investigate unexplained spikes."
                ),
            }
        ]

    def detect_repeated_requests(
        self,
        packets: Iterable[Any],
    ) -> list[dict[str, Any]]:
        """Detect repeated requests from the same source."""

        packet_list = self._normalize_packets(packets)

        source_counts = Counter(
            self._source_ip(packet)
            for packet in packet_list
        )

        detections: list[dict[str, Any]] = []

        for source, count in source_counts.items():
            if count >= self.config.repeated_requests:
                detections.append(
                    {
                        "source": source,
                        "destination": None,
                        "detection_type": "REPEATED_REQUESTS",
                        "severity": "LOW",
                        "description": (
                            "Repeated requests or traffic records were "
                            "observed from the same source."
                        ),
                        "evidence": {
                            "observed_requests": count,
                        },
                        "recommended_action": (
                            "Compare the request frequency with the "
                            "expected behavior for the source."
                        ),
                    }
                )

        return detections

    def run_all(
        self,
        packets: Iterable[Any],
        total_bytes: Optional[int] = None,
    ) -> list[dict[str, Any]]:
        """
        Run all configured detection rules.

        Returns a list of normalized detection dictionaries.
        """

        packet_list = self._normalize_packets(packets)

        detections: list[dict[str, Any]] = []

        detections.extend(
            self.detect_port_scanning(packet_list)
        )

        detections.extend(
            self.detect_excessive_connections(packet_list)
        )

        detections.extend(
            self.detect_suspicious_ports(packet_list)
        )

        detections.extend(
            self.detect_unusual_connection_patterns(packet_list)
        )

        detections.extend(
            self.detect_suspicious_protocols(packet_list)
        )

        detections.extend(
            self.detect_abnormal_traffic_volume(
                packet_list,
                total_bytes=total_bytes,
            )
        )

        detections.extend(
            self.detect_repeated_requests(packet_list)
        )

        return detections


# ============================================================================
# DEFAULT IDS RULE CONFIGURATION
# ============================================================================

def get_default_detection_rules() -> DetectionRuleConfig:
    """
    Return the default IDS detection-rule configuration.

    This function is used by the NETWATCH main menu to display the
    currently configured default IDS thresholds.
    """

    return DetectionRuleConfig()


def get_detection_rules(
    config: Optional[DetectionRuleConfig] = None,
) -> DetectionRules:
    """
    Create a DetectionRules instance.

    This helper provides a simple public API for callers that want
    an initialized rule engine without constructing the class directly.
    """

    return DetectionRules(config=config)


__all__ = [
    "DetectionRuleConfig",
    "DetectionRules",
    "get_default_detection_rules",
    "get_detection_rules",
]