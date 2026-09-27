"""
NETWATCH shared data models.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    """Security alert severity levels."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DeviceStatus(str, Enum):
    """Network device status."""

    UP = "UP"
    DOWN = "DOWN"
    UNKNOWN = "UNKNOWN"


class PortState(str, Enum):
    """Network port states."""

    OPEN = "OPEN"
    CLOSED = "CLOSED"
    FILTERED = "FILTERED"
    UNKNOWN = "UNKNOWN"


@dataclass
class NetworkDevice:
    """Represents a discovered network device."""

    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    status: DeviceStatus = DeviceStatus.UNKNOWN
    response_time_ms: Optional[float] = None


@dataclass
class PortResult:
    """Represents the result of a port scan."""

    port: int
    state: PortState
    service: Optional[str] = None
    response_time_ms: Optional[float] = None


@dataclass
class SecurityAlert:
    """Represents an IDS/security detection alert."""

    alert_id: str
    timestamp: datetime
    source: str
    detection_type: str
    description: str
    severity: Severity
    destination: Optional[str] = None
    evidence: list[str] = field(default_factory=list)
    recommended_action: Optional[str] = None


@dataclass
class AssessmentFinding:
    """Represents a security assessment finding."""

    title: str
    description: str
    severity: Severity
    category: str
    evidence: list[str] = field(default_factory=list)
    recommendation: Optional[str] = None


@dataclass
class AssessmentResult:
    """Container for a complete security assessment."""

    assessment_id: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    scope: Optional[str] = None
    devices: list[NetworkDevice] = field(default_factory=list)
    ports: list[PortResult] = field(default_factory=list)
    alerts: list[SecurityAlert] = field(default_factory=list)
    findings: list[AssessmentFinding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)