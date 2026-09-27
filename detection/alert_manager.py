"""
NETWATCH IDS Alert Manager.

Phase 7 - IDS / Security Detection Engine

This module defines the security alert model and provides a centralized
manager for creating, storing, filtering, and formatting IDS alerts.

The alert manager does not determine whether traffic is malicious.
It records observations produced by the configured detection rules.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Optional
from uuid import uuid4


SEVERITY_LEVELS = (
    "INFO",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
)

SEVERITY_PRIORITY = {
    "INFO": 1,
    "LOW": 2,
    "MEDIUM": 3,
    "HIGH": 4,
    "CRITICAL": 5,
}


@dataclass
class SecurityAlert:
    """
    Represents one IDS security alert.

    Every alert contains the fields required by the NETWATCH Phase 7
    specification:
        - alert ID
        - timestamp
        - source
        - destination
        - detection type
        - description
        - severity
        - evidence
        - recommended defensive action
    """

    source: str
    detection_type: str
    description: str
    severity: str
    evidence: Any
    recommended_action: str
    destination: Optional[str] = None
    alert_id: str = field(default_factory=lambda: f"NET-{uuid4().hex[:12].upper()}")
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def __post_init__(self) -> None:
        """Validate alert data after initialization."""

        self.severity = self.severity.upper().strip()

        if self.severity not in SEVERITY_LEVELS:
            raise ValueError(
                f"Invalid severity '{self.severity}'. "
                f"Expected one of: {', '.join(SEVERITY_LEVELS)}."
            )

        if not self.source or not self.source.strip():
            raise ValueError("Alert source cannot be empty.")

        if not self.detection_type or not self.detection_type.strip():
            raise ValueError("Detection type cannot be empty.")

        if not self.description or not self.description.strip():
            raise ValueError("Alert description cannot be empty.")

        if not self.recommended_action or not self.recommended_action.strip():
            raise ValueError("Recommended action cannot be empty.")

        if not isinstance(self.timestamp, datetime):
            raise TypeError("Alert timestamp must be a datetime object.")

    @property
    def severity_priority(self) -> int:
        """Return the numeric priority associated with the alert severity."""

        return SEVERITY_PRIORITY[self.severity]

    def to_dict(self) -> dict[str, Any]:
        """Convert the alert into a serializable dictionary."""

        timestamp = self.timestamp

        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        return {
            "alert_id": self.alert_id,
            "timestamp": timestamp.isoformat(),
            "source": self.source,
            "destination": self.destination,
            "detection_type": self.detection_type,
            "description": self.description,
            "severity": self.severity,
            "evidence": self.evidence,
            "recommended_action": self.recommended_action,
        }

    def formatted_timestamp(self) -> str:
        """Return a human-readable timestamp."""

        timestamp = self.timestamp

        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        return timestamp.astimezone().strftime("%Y-%m-%d %H:%M:%S")

    def format_alert(self) -> str:
        """Return a human-readable security alert."""

        destination = self.destination if self.destination else "N/A"

        return (
            "SECURITY ALERT\n"
            "----------------------------------------\n"
            f"Alert ID           : {self.alert_id}\n"
            f"Timestamp          : {self.formatted_timestamp()}\n"
            f"Source             : {self.source}\n"
            f"Destination        : {destination}\n"
            f"Detection Type     : {self.detection_type}\n"
            f"Severity           : {self.severity}\n"
            f"Description        : {self.description}\n"
            f"Evidence           : {self.evidence}\n"
            f"Recommended Action : {self.recommended_action}\n"
            "----------------------------------------"
        )


class AlertManager:
    """
    Central manager for IDS security alerts.

    The manager stores alerts in memory for the current NETWATCH run.
    It does not perform blocking, firewall modification, or any other
    intrusive action.
    """

    def __init__(self) -> None:
        self._alerts: list[SecurityAlert] = []

    @property
    def alerts(self) -> list[SecurityAlert]:
        """Return a copy of the currently stored alerts."""

        return list(self._alerts)

    @property
    def count(self) -> int:
        """Return the number of stored alerts."""

        return len(self._alerts)

    def add_alert(self, alert: SecurityAlert) -> SecurityAlert:
        """Add an existing SecurityAlert to the manager."""

        if not isinstance(alert, SecurityAlert):
            raise TypeError("Only SecurityAlert objects can be added.")

        self._alerts.append(alert)
        return alert

    def create_alert(
        self,
        source: str,
        detection_type: str,
        description: str,
        severity: str,
        evidence: Any,
        recommended_action: str,
        destination: Optional[str] = None,
    ) -> SecurityAlert:
        """Create and store a new security alert."""

        alert = SecurityAlert(
            source=source,
            destination=destination,
            detection_type=detection_type,
            description=description,
            severity=severity,
            evidence=evidence,
            recommended_action=recommended_action,
        )

        self._alerts.append(alert)
        return alert

    def get_alerts(
        self,
        severity: Optional[str] = None,
        detection_type: Optional[str] = None,
    ) -> list[SecurityAlert]:
        """
        Return alerts matching optional filters.

        Filters are case-insensitive.
        """

        results = self._alerts

        if severity is not None:
            normalized_severity = severity.upper().strip()

            if normalized_severity not in SEVERITY_LEVELS:
                raise ValueError(
                    f"Invalid severity '{severity}'. "
                    f"Expected one of: {', '.join(SEVERITY_LEVELS)}."
                )

            results = [
                alert
                for alert in results
                if alert.severity == normalized_severity
            ]

        if detection_type is not None:
            normalized_type = detection_type.strip().lower()

            results = [
                alert
                for alert in results
                if alert.detection_type.strip().lower() == normalized_type
            ]

        return list(results)

    def get_minimum_severity(self, severity: str) -> list[SecurityAlert]:
        """
        Return alerts at or above the requested severity.

        Example:
            get_minimum_severity("HIGH")
        returns HIGH and CRITICAL alerts.
        """

        normalized_severity = severity.upper().strip()

        if normalized_severity not in SEVERITY_LEVELS:
            raise ValueError(
                f"Invalid severity '{severity}'. "
                f"Expected one of: {', '.join(SEVERITY_LEVELS)}."
            )

        minimum_priority = SEVERITY_PRIORITY[normalized_severity]

        return [
            alert
            for alert in self._alerts
            if alert.severity_priority >= minimum_priority
        ]

    def summary(self) -> dict[str, int]:
        """Return the number of alerts for each severity level."""

        result = {severity: 0 for severity in SEVERITY_LEVELS}

        for alert in self._alerts:
            result[alert.severity] += 1

        return result

    def clear(self) -> None:
        """Remove all stored alerts."""

        self._alerts.clear()

    def extend(self, alerts: Iterable[SecurityAlert]) -> None:
        """Add multiple SecurityAlert objects."""

        for alert in alerts:
            self.add_alert(alert)

    def format_alerts(self) -> str:
        """Format all stored alerts for terminal display."""

        if not self._alerts:
            return "No security alerts detected."

        sections = [
            alert.format_alert()
            for alert in self._alerts
        ]

        return "\n\n".join(sections)


def format_alert_summary(manager: AlertManager) -> str:
    """
    Format a compact IDS alert summary.

    This function is intended for the NETWATCH terminal interface.
    """

    summary = manager.summary()

    lines = [
        "IDS ALERT SUMMARY",
        "=" * 60,
        f"Total Alerts : {manager.count}",
        "",
        "SEVERITY DISTRIBUTION",
        "-" * 60,
    ]

    for severity in SEVERITY_LEVELS:
        lines.append(
            f"{severity:<10} : {summary[severity]}"
        )

    return "\n".join(lines)