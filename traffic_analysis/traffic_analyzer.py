"""
NETWATCH - Network Traffic Analyzer

Phase 6:
Network traffic monitoring and analysis.

This module performs read-only packet analysis.

It supports:
- TCP
- UDP
- ICMP
- DNS
- HTTP
- HTTPS
- source/destination IP addresses
- source/destination ports
- packet counts
- protocol distribution
- top talkers

Live packet capture uses Scapy when available and when the operating
system permits packet capture.

No packet injection, modification, blocking, exploitation, or
credential collection is performed.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional
import time


try:
    from scapy.all import (
        DNS,
        ICMP,
        IP,
        TCP,
        UDP,
        sniff,
    )

    SCAPY_AVAILABLE = True
    SCAPY_IMPORT_ERROR = None

except ImportError as exc:
    DNS = None
    ICMP = None
    IP = None
    TCP = None
    UDP = None
    sniff = None

    SCAPY_AVAILABLE = False
    SCAPY_IMPORT_ERROR = str(exc)


class TrafficAnalyzerError(Exception):
    """Base exception for traffic analyzer errors."""


class TrafficCaptureError(TrafficAnalyzerError):
    """Raised when live packet capture cannot be started."""


@dataclass
class PacketSummary:
    """
    Normalized information extracted from one network packet.
    """

    source_ip: str = ""
    destination_ip: str = ""
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    transport_protocol: str = "OTHER"
    application_protocol: Optional[str] = None
    packet_length: int = 0


@dataclass
class TrafficAnalysisResult:
    """
    Aggregated network traffic analysis results.
    """

    packets_analyzed: int = 0
    total_bytes: int = 0

    tcp_packets: int = 0
    udp_packets: int = 0
    icmp_packets: int = 0

    dns_packets: int = 0
    http_packets: int = 0
    https_packets: int = 0

    source_packet_counts: dict[str, int] = field(default_factory=dict)
    destination_packet_counts: dict[str, int] = field(default_factory=dict)

    protocol_distribution: dict[str, int] = field(default_factory=dict)

    packet_summaries: list[PacketSummary] = field(default_factory=list)

    capture_duration_seconds: float = 0.0
    capture_source: str = "analysis"

    @property
    def packet_count(self) -> int:
        """
        Backward-compatible packet count alias.

        The canonical field is packets_analyzed. This property is
        provided because the application menu can refer to the result
        using the shorter packet_count name.
        """

        return self.packets_analyzed


class TrafficAnalyzer:
    """
    Read-only network traffic analyzer.

    The analyzer can:
    1. Analyze already captured packet objects.
    2. Perform a live capture through Scapy.
    3. Validate capture configuration.

    Live capture requires appropriate OS permissions and packet-capture
    support such as Npcap on Windows.
    """

    MAX_CAPTURE_SECONDS = 300
    MAX_PACKET_COUNT = 100_000

    TRANSPORT_PROTOCOLS = (
        "TCP",
        "UDP",
        "ICMP",
        "OTHER",
    )

    APPLICATION_PROTOCOLS = (
        "DNS",
        "HTTP",
        "HTTPS",
    )

    def __init__(
        self,
        interface: Optional[str] = None,
    ) -> None:
        if interface is not None:
            interface = interface.strip()

            if not interface:
                interface = None

        self.interface = interface

    @staticmethod
    def validate_capture_duration(duration: float) -> float:
        """
        Validate live capture duration.
        """

        if isinstance(duration, bool):
            raise ValueError("Capture duration must be numeric.")

        try:
            duration = float(duration)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "Capture duration must be numeric."
            ) from exc

        if duration <= 0:
            raise ValueError(
                "Capture duration must be greater than zero."
            )

        if duration > TrafficAnalyzer.MAX_CAPTURE_SECONDS:
            raise ValueError(
                f"Capture duration cannot exceed "
                f"{TrafficAnalyzer.MAX_CAPTURE_SECONDS} seconds."
            )

        return duration

    @staticmethod
    def validate_packet_count(packet_count: int) -> int:
        """
        Validate the maximum number of packets to capture.
        """

        if isinstance(packet_count, bool):
            raise ValueError("Packet count must be an integer.")

        if not isinstance(packet_count, int):
            raise ValueError("Packet count must be an integer.")

        if packet_count <= 0:
            raise ValueError(
                "Packet count must be greater than zero."
            )

        if packet_count > TrafficAnalyzer.MAX_PACKET_COUNT:
            raise ValueError(
                f"Packet count cannot exceed "
                f"{TrafficAnalyzer.MAX_PACKET_COUNT}."
            )

        return packet_count

    @staticmethod
    def _safe_int(value: Any) -> Optional[int]:
        """
        Convert a value to an integer safely.
        """

        if value is None:
            return None

        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _packet_length(packet: Any) -> int:
        """
        Obtain packet length when available.
        """

        try:
            return max(0, int(len(packet)))
        except (TypeError, ValueError):
            return 0

    def summarize_packet(self, packet: Any) -> PacketSummary:
        """
        Extract a normalized summary from a Scapy packet.
        """

        source_ip = ""
        destination_ip = ""

        source_port: Optional[int] = None
        destination_port: Optional[int] = None

        transport_protocol = "OTHER"
        application_protocol: Optional[str] = None

        if IP is not None and packet.haslayer(IP):
            ip_layer = packet.getlayer(IP)

            source_ip = str(
                getattr(ip_layer, "src", "") or ""
            )

            destination_ip = str(
                getattr(ip_layer, "dst", "") or ""
            )

        if TCP is not None and packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)

            transport_protocol = "TCP"

            source_port = self._safe_int(
                getattr(tcp_layer, "sport", None)
            )

            destination_port = self._safe_int(
                getattr(tcp_layer, "dport", None)
            )

        elif UDP is not None and packet.haslayer(UDP):
            udp_layer = packet.getlayer(UDP)

            transport_protocol = "UDP"

            source_port = self._safe_int(
                getattr(udp_layer, "sport", None)
            )

            destination_port = self._safe_int(
                getattr(udp_layer, "dport", None)
            )

        elif ICMP is not None and packet.haslayer(ICMP):
            transport_protocol = "ICMP"

        if DNS is not None and packet.haslayer(DNS):
            application_protocol = "DNS"

        elif transport_protocol == "TCP":
            ports = {
                source_port,
                destination_port,
            }

            if 80 in ports:
                application_protocol = "HTTP"

            elif 443 in ports:
                application_protocol = "HTTPS"

        return PacketSummary(
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=source_port,
            destination_port=destination_port,
            transport_protocol=transport_protocol,
            application_protocol=application_protocol,
            packet_length=self._packet_length(packet),
        )

    def analyze_packets(
        self,
        packets: Iterable[Any],
        capture_source: str = "analysis",
        capture_duration_seconds: float = 0.0,
    ) -> TrafficAnalysisResult:
        """
        Analyze an iterable of Scapy packets.
        """

        if packets is None:
            raise ValueError("Packets cannot be None.")

        result = TrafficAnalysisResult(
            capture_source=capture_source,
            capture_duration_seconds=max(
                0.0,
                float(capture_duration_seconds),
            ),
        )

        source_counter: Counter[str] = Counter()
        destination_counter: Counter[str] = Counter()

        for packet in packets:
            summary = self.summarize_packet(packet)

            result.packet_summaries.append(summary)

            result.packets_analyzed += 1
            result.total_bytes += summary.packet_length

            if summary.source_ip:
                source_counter[summary.source_ip] += 1

            if summary.destination_ip:
                destination_counter[summary.destination_ip] += 1

            if summary.transport_protocol == "TCP":
                result.tcp_packets += 1

            elif summary.transport_protocol == "UDP":
                result.udp_packets += 1

            elif summary.transport_protocol == "ICMP":
                result.icmp_packets += 1

            if summary.application_protocol:
                if summary.application_protocol == "DNS":
                    result.dns_packets += 1

                elif summary.application_protocol == "HTTP":
                    result.http_packets += 1

                elif summary.application_protocol == "HTTPS":
                    result.https_packets += 1

        result.source_packet_counts = dict(
            source_counter.most_common()
        )

        result.destination_packet_counts = dict(
            destination_counter.most_common()
        )

        result.protocol_distribution = {
            "TCP": result.tcp_packets,
            "UDP": result.udp_packets,
            "ICMP": result.icmp_packets,
            "DNS": result.dns_packets,
            "HTTP": result.http_packets,
            "HTTPS": result.https_packets,
        }

        return result

    def capture_live(
        self,
        duration: float = 10.0,
        packet_count: int = 1000,
    ) -> TrafficAnalysisResult:
        """
        Capture traffic passively for a limited period.

        This function only observes packets. It does not transmit or
        modify network traffic.

        Windows generally requires Npcap for packet capture.
        Appropriate operating-system permissions may also be required.
        """

        duration = self.validate_capture_duration(duration)
        packet_count = self.validate_packet_count(packet_count)

        if not SCAPY_AVAILABLE:
            raise TrafficCaptureError(
                "Scapy is not available. Install the project "
                "requirements before starting live capture."
            )

        if sniff is None:
            raise TrafficCaptureError(
                "Packet capture support is unavailable."
            )

        start_time = time.perf_counter()

        try:
            captured_packets = sniff(
                iface=self.interface,
                timeout=duration,
                count=packet_count,
                store=True,
            )

        except PermissionError as exc:
            raise TrafficCaptureError(
                "Packet capture permission was denied. "
                "Run the authorized assessment with the required "
                "operating-system permissions."
            ) from exc

        except Exception as exc:
            message = str(exc).strip()

            if not message:
                message = (
                    "The operating system or packet-capture driver "
                    "could not start live capture."
                )

            raise TrafficCaptureError(
                f"Live packet capture failed: {message}"
            ) from exc

        elapsed = time.perf_counter() - start_time

        return self.analyze_packets(
            captured_packets,
            capture_source="live",
            capture_duration_seconds=elapsed,
        )

    @staticmethod
    def create_sample_result() -> TrafficAnalysisResult:
        """
        Create deterministic demonstration traffic.

        This is useful for presentations, automated tests, and systems
        where live packet capture is unavailable.

        The data is synthetic and does not represent real network
        activity.
        """

        sample_packets = [
            PacketSummary(
                source_ip="192.168.0.103",
                destination_ip="192.168.0.1",
                source_port=52100,
                destination_port=443,
                transport_protocol="TCP",
                application_protocol="HTTPS",
                packet_length=1500,
            ),
            PacketSummary(
                source_ip="192.168.0.103",
                destination_ip="8.8.8.8",
                source_port=53000,
                destination_port=53,
                transport_protocol="UDP",
                application_protocol="DNS",
                packet_length=86,
            ),
            PacketSummary(
                source_ip="192.168.0.107",
                destination_ip="192.168.0.1",
                source_port=53001,
                destination_port=53,
                transport_protocol="UDP",
                application_protocol="DNS",
                packet_length=92,
            ),
            PacketSummary(
                source_ip="192.168.0.103",
                destination_ip="93.184.216.34",
                source_port=52001,
                destination_port=80,
                transport_protocol="TCP",
                application_protocol="HTTP",
                packet_length=1200,
            ),
            PacketSummary(
                source_ip="192.168.0.1",
                destination_ip="192.168.0.103",
                source_port=443,
                destination_port=52100,
                transport_protocol="TCP",
                application_protocol="HTTPS",
                packet_length=1500,
            ),
            PacketSummary(
                source_ip="192.168.0.107",
                destination_ip="192.168.0.1",
                source_port=None,
                destination_port=None,
                transport_protocol="ICMP",
                application_protocol=None,
                packet_length=98,
            ),
            PacketSummary(
                source_ip="192.168.0.103",
                destination_ip="192.168.0.15",
                source_port=51000,
                destination_port=8080,
                transport_protocol="TCP",
                application_protocol=None,
                packet_length=600,
            ),
            PacketSummary(
                source_ip="192.168.0.15",
                destination_ip="192.168.0.103",
                source_port=8080,
                destination_port=51000,
                transport_protocol="TCP",
                application_protocol=None,
                packet_length=650,
            ),
        ]

        source_counter = Counter(
            packet.source_ip
            for packet in sample_packets
            if packet.source_ip
        )

        destination_counter = Counter(
            packet.destination_ip
            for packet in sample_packets
            if packet.destination_ip
        )

        tcp_count = sum(
            packet.transport_protocol == "TCP"
            for packet in sample_packets
        )

        udp_count = sum(
            packet.transport_protocol == "UDP"
            for packet in sample_packets
        )

        icmp_count = sum(
            packet.transport_protocol == "ICMP"
            for packet in sample_packets
        )

        dns_count = sum(
            packet.application_protocol == "DNS"
            for packet in sample_packets
        )

        http_count = sum(
            packet.application_protocol == "HTTP"
            for packet in sample_packets
        )

        https_count = sum(
            packet.application_protocol == "HTTPS"
            for packet in sample_packets
        )

        total_bytes = sum(
            packet.packet_length
            for packet in sample_packets
        )

        return TrafficAnalysisResult(
            packets_analyzed=len(sample_packets),
            total_bytes=total_bytes,
            tcp_packets=tcp_count,
            udp_packets=udp_count,
            icmp_packets=icmp_count,
            dns_packets=dns_count,
            http_packets=http_count,
            https_packets=https_count,
            source_packet_counts=dict(
                source_counter.most_common()
            ),
            destination_packet_counts=dict(
                destination_counter.most_common()
            ),
            protocol_distribution={
                "TCP": tcp_count,
                "UDP": udp_count,
                "ICMP": icmp_count,
                "DNS": dns_count,
                "HTTP": http_count,
                "HTTPS": https_count,
            },
            packet_summaries=sample_packets,
            capture_duration_seconds=5.0,
            capture_source="sample",
        )


def format_traffic_results(
    result: TrafficAnalysisResult,
    top_talkers: int = 10,
) -> str:
    """
    Format traffic analysis results for terminal display.

    The traffic detail columns are sized dynamically so IPv4
    addresses combined with port numbers do not overlap.
    """

    if not isinstance(result, TrafficAnalysisResult):
        raise TypeError(
            "result must be a TrafficAnalysisResult."
        )

    if not isinstance(top_talkers, int) or top_talkers <= 0:
        raise ValueError(
            "top_talkers must be a positive integer."
        )

    lines: list[str] = []

    lines.append("")
    lines.append("NETWORK TRAFFIC")
    lines.append("=" * 90)

    lines.append(
        f"Capture Source       : {result.capture_source.upper()}"
    )

    lines.append(
        f"Packets Analyzed     : {result.packets_analyzed}"
    )

    lines.append(
        f"Total Bytes          : {result.total_bytes}"
    )

    lines.append(
        f"Capture Duration     : "
        f"{result.capture_duration_seconds:.2f} seconds"
    )

    lines.append("")
    lines.append("PROTOCOL DISTRIBUTION")
    lines.append("-" * 90)

    lines.append(
        f"{'Protocol':<20}{'Packets':>10}"
    )

    lines.append("-" * 30)

    protocol_order = (
        "TCP",
        "UDP",
        "ICMP",
        "DNS",
        "HTTP",
        "HTTPS",
    )

    for protocol in protocol_order:
        lines.append(
            f"{protocol:<20}"
            f"{result.protocol_distribution.get(protocol, 0):>10}"
        )

    lines.append("")
    lines.append("TOP TALKERS")
    lines.append("-" * 90)

    lines.append(
        f"{'Source IP':<25}{'Packets':>10}"
    )

    lines.append("-" * 35)

    if result.source_packet_counts:
        for ip_address, count in list(
            result.source_packet_counts.items()
        )[:top_talkers]:
            lines.append(
                f"{ip_address:<25}{count:>10}"
            )
    else:
        lines.append("No source IP traffic observed.")

    lines.append("")
    lines.append("TOP DESTINATIONS")
    lines.append("-" * 90)

    lines.append(
        f"{'Destination IP':<25}{'Packets':>10}"
    )

    lines.append("-" * 35)

    if result.destination_packet_counts:
        for ip_address, count in list(
            result.destination_packet_counts.items()
        )[:top_talkers]:
            lines.append(
                f"{ip_address:<25}{count:>10}"
            )
    else:
        lines.append("No destination IP traffic observed.")

    lines.append("")
    lines.append("TRAFFIC DETAILS")
    lines.append("-" * 90)

    # Build the display values first so column widths can accommodate
    # IPv4 addresses combined with ports.
    traffic_rows: list[tuple[str, str, str, str]] = []

    for packet in result.packet_summaries[:20]:
        source = packet.source_ip or "-"
        destination = packet.destination_ip or "-"

        if packet.source_port is not None:
            source = f"{source}:{packet.source_port}"

        if packet.destination_port is not None:
            destination = (
                f"{destination}:{packet.destination_port}"
            )

        protocol = packet.transport_protocol or "-"
        application = packet.application_protocol or "-"

        traffic_rows.append(
            (
                source,
                destination,
                protocol,
                application,
            )
        )

    source_width = max(
        12,
        len("Source"),
        *(len(row[0]) for row in traffic_rows),
    )

    destination_width = max(
        15,
        len("Destination"),
        *(len(row[1]) for row in traffic_rows),
    )

    protocol_width = max(
        10,
        len("Protocol"),
        *(len(row[2]) for row in traffic_rows),
    )

    application_width = max(
        12,
        len("Application"),
        *(len(row[3]) for row in traffic_rows),
    )

    table_width = (
        source_width
        + destination_width
        + protocol_width
        + application_width
        + 3
    )

    lines.append(
        f"{'Source':<{source_width}} "
        f"{'Destination':<{destination_width}} "
        f"{'Protocol':<{protocol_width}} "
        f"{'Application':<{application_width}}"
    )

    lines.append("-" * table_width)

    for (
        source,
        destination,
        protocol,
        application,
    ) in traffic_rows:
        lines.append(
            f"{source:<{source_width}} "
            f"{destination:<{destination_width}} "
            f"{protocol:<{protocol_width}} "
            f"{application:<{application_width}}"
        )

    if len(result.packet_summaries) > 20:
        lines.append("")
        lines.append(
            f"... {len(result.packet_summaries) - 20} "
            f"additional packets not displayed."
        )

    lines.append("")
    lines.append(
        "NOTE: Traffic analysis is read-only and depends on "
        "operating-system packet-capture permissions."
    )

    return "\n".join(lines)