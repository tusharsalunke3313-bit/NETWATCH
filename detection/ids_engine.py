"""
NETWATCH IDS Engine.

Phase 7 - IDS / Security Detection Engine

Connects the Phase 6 traffic analysis data with the Phase 7 detection
rules and alert manager.

This engine is read-only. It analyzes observed traffic and generates
security alerts. It does not block traffic, modify firewall rules,
terminate connections, or perform intrusive actions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Optional

from .alert_manager import (
    AlertManager,
    SecurityAlert,
    format_alert_summary,
)
from .detection_rules import (
    DetectionRuleConfig,
    DetectionRules,
)


class IDSEngineError(Exception):
    """Base exception for IDS engine errors."""


class IDSInputError(IDSEngineError):
    """Raised when IDS input is invalid."""


@dataclass
class IDSAnalysisResult:
    """
    Result returned by the IDS engine.

    Contains both the generated alerts and useful analysis statistics.
    """

    packets_analyzed: int
    total_bytes: int
    alerts: list[SecurityAlert]
    rules_evaluated: int

    @property
    def alert_count(self) -> int:
        """Return the number of generated alerts."""

        return len(self.alerts)

    @property
    def high_severity_count(self) -> int:
        """Return HIGH and CRITICAL alert count."""

        return sum(
            1
            for alert in self.alerts
            if alert.severity in {"HIGH", "CRITICAL"}
        )

    @property
    def medium_severity_count(self) -> int:
        """Return MEDIUM alert count."""

        return sum(
            1
            for alert in self.alerts
            if alert.severity == "MEDIUM"
        )

    @property
    def low_severity_count(self) -> int:
        """Return LOW alert count."""

        return sum(
            1
            for alert in self.alerts
            if alert.severity == "LOW"
        )

    @property
    def info_count(self) -> int:
        """Return INFO alert count."""

        return sum(
            1
            for alert in self.alerts
            if alert.severity == "INFO"
        )


class IDSEngine:
    """
    Rule-based IDS engine.

    Workflow:

        Traffic data
             ↓
        DetectionRules
             ↓
        Detection observations
             ↓
        AlertManager
             ↓
        SecurityAlert objects

    The engine intentionally does not make claims about attacker intent.
    """

    RULE_COUNT = 7

    def __init__(
        self,
        rule_config: Optional[DetectionRuleConfig] = None,
        alert_manager: Optional[AlertManager] = None,
    ) -> None:
        self.rules = DetectionRules(rule_config)
        self.alert_manager = alert_manager or AlertManager()

    @staticmethod
    def _get_value(
        packet: Any,
        *names: str,
        default: Any = None,
    ) -> Any:
        """Extract a value from dictionaries or packet-summary objects."""

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
    def _packet_length(cls, packet: Any) -> int:
        """Extract packet length from a packet-like object."""

        value = cls._get_value(
            packet,
            "length",
            "packet_length",
            "size",
            "bytes",
            default=0,
        )

        try:
            return max(0, int(value))
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _normalize_packets(
        packets: Iterable[Any],
    ) -> list[Any]:
        """Convert packet input into a reusable list."""

        if packets is None:
            return []

        try:
            return list(packets)
        except TypeError as exc:
            raise IDSInputError(
                "Packets must be an iterable collection."
            ) from exc

    @staticmethod
    def _extract_total_bytes(
        traffic_result: Any,
        packets: list[Any],
    ) -> int:
        """
        Extract total bytes from a Phase 6 result when available.

        If the result does not expose total bytes, calculate it from
        individual packet summaries.
        """

        if traffic_result is not None:
            value = IDSEngine._get_value(
                traffic_result,
                "total_bytes",
                "bytes_analyzed",
                default=None,
            )

            try:
                if value is not None:
                    return max(0, int(value))
            except (TypeError, ValueError):
                pass

        return sum(
            IDSEngine._packet_length(packet)
            for packet in packets
        )

    @staticmethod
    def _extract_packets_from_result(
        traffic_result: Any,
    ) -> list[Any]:
        """
        Extract packet summaries from a Phase 6 analysis result.

        Supports several common attribute names to keep the integration
        tolerant of the traffic analyzer's result representation.
        """

        if traffic_result is None:
            return []

        if isinstance(traffic_result, dict):
            for name in (
                "packets",
                "packet_summaries",
                "packet_details",
                "traffic_details",
            ):
                if name in traffic_result:
                    value = traffic_result[name]

                    if value is None:
                        return []

                    try:
                        return list(value)
                    except TypeError:
                        return []

            return []

        for name in (
            "packets",
            "packet_summaries",
            "packet_details",
            "traffic_details",
        ):
            if hasattr(traffic_result, name):
                value = getattr(traffic_result, name)

                if value is None:
                    return []

                try:
                    return list(value)
                except TypeError:
                    return []

        return []

    @staticmethod
    def _convert_detection_to_alert(
        manager: AlertManager,
        detection: dict[str, Any],
    ) -> SecurityAlert:
        """Convert a detection-rule result into a SecurityAlert."""

        required_fields = (
            "source",
            "detection_type",
            "description",
            "severity",
            "evidence",
            "recommended_action",
        )

        for field_name in required_fields:
            if field_name not in detection:
                raise IDSInputError(
                    f"Detection result is missing '{field_name}'."
                )

        return manager.create_alert(
            source=str(detection["source"]),
            destination=(
                str(detection["destination"])
                if detection.get("destination") is not None
                else None
            ),
            detection_type=str(detection["detection_type"]),
            description=str(detection["description"]),
            severity=str(detection["severity"]),
            evidence=detection["evidence"],
            recommended_action=str(
                detection["recommended_action"]
            ),
        )

    def analyze(
        self,
        packets: Iterable[Any],
        total_bytes: Optional[int] = None,
        clear_previous_alerts: bool = True,
    ) -> IDSAnalysisResult:
        """
        Analyze packet data using every configured detection rule.

        Parameters:
            packets:
                Iterable of Phase 6 packet summaries.

            total_bytes:
                Optional total byte count from the traffic analyzer.

            clear_previous_alerts:
                If True, alerts from an earlier analysis are cleared
                before processing the new traffic set.
        """

        packet_list = self._normalize_packets(packets)

        if clear_previous_alerts:
            self.alert_manager.clear()

        if total_bytes is None:
            total_bytes = sum(
                self._packet_length(packet)
                for packet in packet_list
            )
        else:
            try:
                total_bytes = max(0, int(total_bytes))
            except (TypeError, ValueError) as exc:
                raise IDSInputError(
                    "total_bytes must be an integer."
                ) from exc

        detections = self.rules.run_all(
            packet_list,
            total_bytes=total_bytes,
        )

        alerts: list[SecurityAlert] = []

        for detection in detections:
            alert = self._convert_detection_to_alert(
                self.alert_manager,
                detection,
            )
            alerts.append(alert)

        return IDSAnalysisResult(
            packets_analyzed=len(packet_list),
            total_bytes=total_bytes,
            alerts=alerts,
            rules_evaluated=self.RULE_COUNT,
        )

    def analyze_traffic_result(
        self,
        traffic_result: Any,
        clear_previous_alerts: bool = True,
    ) -> IDSAnalysisResult:
        """
        Analyze a Phase 6 TrafficAnalysisResult directly.

        This is the main integration point between Phase 6 and Phase 7.
        """

        packets = self._extract_packets_from_result(
            traffic_result
        )

        total_bytes = self._extract_total_bytes(
            traffic_result,
            packets,
        )

        return self.analyze(
            packets,
            total_bytes=total_bytes,
            clear_previous_alerts=clear_previous_alerts,
        )

    def analyze_sample(
        self,
    ) -> IDSAnalysisResult:
        """
        Run IDS analysis against a deterministic sample traffic set.

        This sample is safe and contains no real network activity.
        It is intended for testing and demonstrations.
        """

        sample_packets = [
            {
                "source_ip": "192.168.0.50",
                "destination_ip": "192.168.0.1",
                "source_port": 51001,
                "destination_port": 21,
                "protocol": "TCP",
                "application": "",
                "length": 60,
            },
            {
                "source_ip": "192.168.0.50",
                "destination_ip": "192.168.0.1",
                "source_port": 51002,
                "destination_port": 22,
                "protocol": "TCP",
                "application": "",
                "length": 60,
            },
            {
                "source_ip": "192.168.0.50",
                "destination_ip": "192.168.0.1",
                "source_port": 51003,
                "destination_port": 23,
                "protocol": "TCP",
                "application": "TELNET",
                "length": 60,
            },
            {
                "source_ip": "192.168.0.50",
                "destination_ip": "192.168.0.1",
                "source_port": 51004,
                "destination_port": 25,
                "protocol": "TCP",
                "application": "SMTP",
                "length": 60,
            },
            {
                "source_ip": "192.168.0.50",
                "destination_ip": "192.168.0.1",
                "source_port": 51005,
                "destination_port": 80,
                "protocol": "TCP",
                "application": "HTTP",
                "length": 120,
            },
            {
                "source_ip": "192.168.0.50",
                "destination_ip": "192.168.0.1",
                "source_port": 51006,
                "destination_port": 443,
                "protocol": "TCP",
                "application": "HTTPS",
                "length": 180,
            },
        ]

        return self.analyze(
            sample_packets,
            total_bytes=540,
        )


def format_ids_results(
    result: IDSAnalysisResult,
) -> str:
    """
    Format IDS analysis results for terminal display.
    """

    lines = [
        "IDS / SECURITY DETECTION",
        "=" * 90,
        f"Packets Analyzed     : {result.packets_analyzed}",
        f"Total Bytes          : {result.total_bytes}",
        f"Rules Evaluated      : {result.rules_evaluated}",
        f"Alerts Generated     : {result.alert_count}",
        f"High/Critical Alerts : {result.high_severity_count}",
        "",
        format_alert_summary(
            _manager_from_result(result)
        ),
        "",
    ]

    if not result.alerts:
        lines.extend(
            [
                "SECURITY STATUS",
                "-" * 90,
                "No configured detection rule produced an alert.",
                "",
                "Note: absence of alerts does not prove that traffic is safe.",
            ]
        )

        return "\n".join(lines)

    lines.extend(
        [
            "DETECTED SECURITY EVENTS",
            "=" * 90,
        ]
    )

    for index, alert in enumerate(result.alerts, start=1):
        lines.append(
            f"\n[{index}] {alert.format_alert()}"
        )

    lines.extend(
        [
            "",
            "ASSESSMENT NOTE",
            "-" * 90,
            "Alerts represent rule-based observations that may require",
            "investigation. An alert is not proof of malicious intent.",
        ]
    )

    return "\n".join(lines)


def _manager_from_result(
    result: IDSAnalysisResult,
) -> AlertManager:
    """
    Create a temporary AlertManager containing the result alerts.

    This keeps the formatter independent from the engine's live manager.
    """

    manager = AlertManager()
    manager.extend(result.alerts)
    return manager