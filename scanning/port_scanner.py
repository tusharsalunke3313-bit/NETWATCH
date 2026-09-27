"""
NETWATCH - TCP and UDP Port Scanner

Authorized defensive network assessment only.

Supported:
- TCP connect scanning
- UDP probe scanning
- Ports 1-65535
- Single ports
- Comma-separated ports
- Port ranges
- Full-range scanning
- Common ports
- Service identification
- Response-time measurement

No exploitation, authentication attempts, payload attacks,
credential attacks, or destructive operations are performed.
"""

from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Iterable


MIN_PORT = 1
MAX_PORT = 65535

DEFAULT_TIMEOUT = 1.0
DEFAULT_MAX_WORKERS = 50
DEFAULT_SUBMISSION_DELAY = 0.0

OPEN = "OPEN"
CLOSED = "CLOSED"
FILTERED = "FILTERED/UNREACHABLE"
OPEN_FILTERED = "OPEN|FILTERED"

TCP = "TCP"
UDP = "UDP"

COMMON_PORTS = [
    20,
    21,
    22,
    23,
    25,
    53,
    67,
    68,
    69,
    80,
    110,
    111,
    119,
    123,
    135,
    137,
    138,
    139,
    143,
    161,
    162,
    389,
    443,
    445,
    465,
    514,
    587,
    636,
    993,
    995,
    1433,
    1521,
    1723,
    3306,
    3389,
    5432,
    5900,
    6379,
    8080,
    8443,
]


@dataclass
class PortScanResult:
    """
    Result for one TCP or UDP port probe.

    target and protocol have defaults so older NETWATCH
    tests and callers remain compatible.
    """

    port: int
    state: str
    service: str = "UNKNOWN"
    response_time_ms: float = 0.0
    target: str = ""
    protocol: str = TCP
    error: str | None = None

    @property
    def is_open(self) -> bool:
        return self.state == OPEN

    @property
    def is_closed(self) -> bool:
        return self.state == CLOSED

    @property
    def is_filtered(self) -> bool:
        return self.state in {
            FILTERED,
            OPEN_FILTERED,
        }


def _validate_port(port: int) -> int:
    """
    Validate and return a TCP/UDP port number.
    """

    try:
        value = int(port)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"Invalid port: {port}"
        ) from exc

    if value < MIN_PORT or value > MAX_PORT:
        raise ValueError(
            f"Port must be between {MIN_PORT} and {MAX_PORT}."
        )

    return value


def validate_ports(
    ports: Iterable[int],
) -> list[int]:
    """
    Validate, normalize, deduplicate and sort port numbers.
    """

    if ports is None:
        raise ValueError(
            "At least one port must be specified."
        )

    normalized = []

    for port in ports:
        normalized.append(
            _validate_port(port)
        )

    normalized = sorted(
        set(normalized)
    )

    if not normalized:
        raise ValueError(
            "At least one port must be specified."
        )

    return normalized


def _validate_max_ports(
    max_ports: int | None,
) -> int | None:
    """
    Validate maximum number of ports.

    None means no artificial limit.
    """

    if max_ports is None:
        return None

    try:
        value = int(max_ports)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "max_ports must be an integer."
        ) from exc

    if value < 1:
        raise ValueError(
            "max_ports must be at least 1."
        )

    if value > MAX_PORT:
        return MAX_PORT

    return value


def _apply_max_ports(
    ports: list[int],
    max_ports: int | None,
) -> list[int]:
    """
    Apply configured maximum port count.
    """

    limit = _validate_max_ports(
        max_ports
    )

    if limit is None:
        return ports

    if len(ports) > limit:
        raise ValueError(
            f"Port selection contains {len(ports)} ports, "
            f"which exceeds the configured maximum of {limit}."
        )

    return ports


def parse_port_range(
    start_port: int | str,
    end_port: int | None = None,
    max_ports: int | None = None,
) -> list[int]:
    """
    Parse port input.

    Supported:

        parse_port_range(80)
        parse_port_range(80, 100)

        parse_port_range("80")
        parse_port_range("80,443,8080")
        parse_port_range("1-100")
        parse_port_range("1-65535")
        parse_port_range("common")

    Valid ports are 1-65535.
    """

    if isinstance(start_port, int):

        if end_port is None:
            ports = [
                _validate_port(start_port)
            ]

        else:
            start = _validate_port(
                start_port
            )

            end = _validate_port(
                end_port
            )

            if start > end:
                raise ValueError(
                    "Starting port cannot be greater than ending port."
                )

            ports = list(
                range(
                    start,
                    end + 1,
                )
            )

        return _apply_max_ports(
            ports,
            max_ports,
        )

    if not isinstance(start_port, str):
        raise ValueError(
            "Port input must be a number or string."
        )

    value = start_port.strip()

    if not value:
        raise ValueError(
            "Port input cannot be empty."
        )

    if value.lower() in {
        "common",
        "common ports",
        "default",
    }:
        return _apply_max_ports(
            validate_ports(
                COMMON_PORTS
            ),
            max_ports,
        )

    ports: list[int] = []

    for part in value.split(","):

        item = part.strip()

        if not item:
            continue

        if "-" in item:

            pieces = item.split("-")

            if len(pieces) != 2:
                raise ValueError(
                    f"Invalid port range: {item}"
                )

            try:
                start = int(
                    pieces[0].strip()
                )

                end = int(
                    pieces[1].strip()
                )

            except ValueError as exc:
                raise ValueError(
                    f"Invalid port range: {item}"
                ) from exc

            start = _validate_port(
                start
            )

            end = _validate_port(
                end
            )

            if start > end:
                raise ValueError(
                    f"Invalid port range: {item}. "
                    "Start must be <= end."
                )

            ports.extend(
                range(
                    start,
                    end + 1,
                )
            )

        else:

            try:
                port = int(item)

            except ValueError as exc:
                raise ValueError(
                    f"Invalid port: {item}"
                ) from exc

            ports.append(
                _validate_port(port)
            )

    ports = validate_ports(
        ports
    )

    return _apply_max_ports(
        ports,
        max_ports,
    )


def resolve_target(
    target: str,
) -> str:
    """
    Resolve hostname/IP to IPv4.
    """

    if (
        not isinstance(target, str)
        or not target.strip()
    ):
        raise ValueError(
            "Target cannot be empty."
        )

    target = target.strip()

    try:
        return socket.gethostbyname(
            target
        )

    except socket.gaierror as exc:
        raise ValueError(
            f"Unable to resolve target: {target}"
        ) from exc


def get_service_name(
    port: int,
    protocol: str = TCP,
) -> str:
    """
    Identify service using the local service database.
    """

    protocol = protocol.upper()

    try:
        return socket.getservbyport(
            port,
            protocol.lower(),
        )

    except (
        OSError,
        socket.error,
    ):
        return "UNKNOWN"


class PortScanner:
    """
    Safe TCP/UDP network port scanner.
    """

    def __init__(
        self,
        timeout: float = DEFAULT_TIMEOUT,
        max_workers: int = DEFAULT_MAX_WORKERS,
        submission_delay: float = DEFAULT_SUBMISSION_DELAY,
    ):
        if timeout <= 0:
            raise ValueError(
                "Timeout must be greater than zero."
            )

        if max_workers < 1:
            raise ValueError(
                "max_workers must be at least 1."
            )

        self.timeout = float(
            timeout
        )

        self.max_workers = min(
            int(max_workers),
            DEFAULT_MAX_WORKERS,
        )

        if submission_delay < 0:
            raise ValueError(
                "submission_delay cannot be negative."
            )

        self.submission_delay = float(
            submission_delay
        )

    @staticmethod
    def validate_ports(
        ports: Iterable[int],
    ) -> list[int]:
        """
        Backward-compatible class method.
        """
        return validate_ports(
            ports
        )

    @staticmethod
    def resolve_target(
        target: str,
    ) -> str:
        """
        Backward-compatible instance/class method.
        """
        return resolve_target(
            target
        )

    @staticmethod
    def parse_port_range(
        start_port: int | str,
        end_port: int | None = None,
        max_ports: int | None = None,
    ) -> list[int]:
        """
        Backward-compatible parser access.
        """
        return parse_port_range(
            start_port,
            end_port,
            max_ports,
        )

    def scan_port(
        self,
        target: str,
        port: int,
        protocol: str = TCP,
    ) -> PortScanResult:
        """
        Scan one TCP or UDP port.
        """

        resolved_target = resolve_target(
            target
        )

        port = _validate_port(
            port
        )

        protocol = protocol.upper().strip()

        if protocol not in {
            TCP,
            UDP,
        }:
            raise ValueError(
                "Protocol must be TCP or UDP."
            )

        if protocol == TCP:
            return self._scan_tcp(
                resolved_target,
                port,
            )

        return self._scan_udp(
            resolved_target,
            port,
        )

    def _scan_tcp(
        self,
        target: str,
        port: int,
    ) -> PortScanResult:

        start = time.perf_counter()

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM,
        )

        sock.settimeout(
            self.timeout
        )

        try:

            result = sock.connect_ex(
                (
                    target,
                    port,
                )
            )

            elapsed = (
                time.perf_counter()
                - start
            ) * 1000

            if result == 0:

                state = OPEN
                error = None

            elif result in {
                10060,
                10061,
                10013,
                111,
                113,
            }:

                state = CLOSED
                error = None

            else:

                state = FILTERED
                error = None

            return PortScanResult(
                port=port,
                state=state,
                service=get_service_name(
                    port,
                    TCP,
                ),
                response_time_ms=round(
                    elapsed,
                    2,
                ),
                target=target,
                protocol=TCP,
                error=error,
            )

        except socket.timeout:

            elapsed = (
                time.perf_counter()
                - start
            ) * 1000

            return PortScanResult(
                port=port,
                state=FILTERED,
                service=get_service_name(
                    port,
                    TCP,
                ),
                response_time_ms=round(
                    elapsed,
                    2,
                ),
                target=target,
                protocol=TCP,
            )

        except OSError as exc:

            elapsed = (
                time.perf_counter()
                - start
            ) * 1000

            return PortScanResult(
                port=port,
                state=FILTERED,
                service=get_service_name(
                    port,
                    TCP,
                ),
                response_time_ms=round(
                    elapsed,
                    2,
                ),
                target=target,
                protocol=TCP,
                error=str(exc),
            )

        finally:
            sock.close()

    def _scan_udp(
        self,
        target: str,
        port: int,
    ) -> PortScanResult:

        start = time.perf_counter()

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM,
        )

        sock.settimeout(
            self.timeout
        )

        try:

            sock.connect(
                (
                    target,
                    port,
                )
            )

            # Empty UDP datagram.
            # No service-specific payload.
            sock.send(b"")

            try:

                sock.recv(
                    4096
                )

                elapsed = (
                    time.perf_counter()
                    - start
                ) * 1000

                return PortScanResult(
                    port=port,
                    state=OPEN,
                    service=get_service_name(
                        port,
                        UDP,
                    ),
                    response_time_ms=round(
                        elapsed,
                        2,
                    ),
                    target=target,
                    protocol=UDP,
                )

            except socket.timeout:

                elapsed = (
                    time.perf_counter()
                    - start
                ) * 1000

                return PortScanResult(
                    port=port,
                    state=OPEN_FILTERED,
                    service=get_service_name(
                        port,
                        UDP,
                    ),
                    response_time_ms=round(
                        elapsed,
                        2,
                    ),
                    target=target,
                    protocol=UDP,
                )

        except ConnectionRefusedError:

            elapsed = (
                time.perf_counter()
                - start
            ) * 1000

            return PortScanResult(
                port=port,
                state=CLOSED,
                service=get_service_name(
                    port,
                    UDP,
                ),
                response_time_ms=round(
                    elapsed,
                    2,
                ),
                target=target,
                protocol=UDP,
            )

        except socket.timeout:

            elapsed = (
                time.perf_counter()
                - start
            ) * 1000

            return PortScanResult(
                port=port,
                state=OPEN_FILTERED,
                service=get_service_name(
                    port,
                    UDP,
                ),
                response_time_ms=round(
                    elapsed,
                    2,
                ),
                target=target,
                protocol=UDP,
            )

        except OSError as exc:

            elapsed = (
                time.perf_counter()
                - start
            ) * 1000

            error_code = getattr(
                exc,
                "winerror",
                None,
            )

            if error_code in {
                10061,
                10054,
            }:
                state = CLOSED
            else:
                state = OPEN_FILTERED

            return PortScanResult(
                port=port,
                state=state,
                service=get_service_name(
                    port,
                    UDP,
                ),
                response_time_ms=round(
                    elapsed,
                    2,
                ),
                target=target,
                protocol=UDP,
                error=str(exc),
            )

        finally:
            sock.close()

    def scan(
        self,
        target: str,
        ports: Iterable[int],
        protocol: str = TCP,
    ) -> list[PortScanResult]:
        """
        Scan a collection of ports.

        Returns:
            list[PortScanResult]
        """

        protocol = protocol.upper().strip()

        if protocol not in {
            TCP,
            UDP,
        }:
            raise ValueError(
                "Protocol must be TCP or UDP."
            )

        validated_ports = validate_ports(
            ports
        )

        resolved_target = resolve_target(
            target
        )

        results: list[
            PortScanResult
        ] = []

        with ThreadPoolExecutor(
            max_workers=self.max_workers
        ) as executor:

            futures = {}

            for port in validated_ports:

                future = executor.submit(
                    self.scan_port,
                    resolved_target,
                    port,
                    protocol,
                )

                futures[future] = port

                if self.submission_delay > 0:
                    time.sleep(
                        self.submission_delay
                    )

            for future in as_completed(
                futures
            ):

                result = future.result()

                results.append(
                    result
                )

        results.sort(
            key=lambda item: (
                item.port,
                item.protocol,
            )
        )

        return results

    def scan_common_ports(
        self,
        target: str,
        protocol: str = TCP,
    ) -> list[PortScanResult]:
        """
        Scan predefined common ports.
        """

        return self.scan(
            target,
            COMMON_PORTS,
            protocol,
        )


def count_open_ports(
    results: Iterable[PortScanResult],
) -> int:
    """
    Count strictly OPEN results.

    UDP OPEN|FILTERED is not counted as
    confirmed OPEN.
    """

    if results is None:
        return 0

    return sum(
        1
        for result in results
        if getattr(
            result,
            "state",
            None,
        ) == OPEN
    )


def count_state(
    results: Iterable[PortScanResult],
    state: str,
) -> int:
    """
    Count results matching a state.
    """

    if results is None:
        return 0

    return sum(
        1
        for result in results
        if getattr(
            result,
            "state",
            None,
        ) == state
    )


def _result_items(
    value,
) -> list:
    """
    Normalize result containers.

    Supports:
    - list
    - tuple
    - objects with .results
    - dictionaries containing results
    """

    if value is None:
        return []

    if isinstance(
        value,
        (list, tuple),
    ):
        return list(value)

    if isinstance(
        value,
        dict,
    ):

        candidate = value.get(
            "results"
        )

        if candidate is None:
            candidate = value.get(
                "port_results"
            )

        if candidate is None:
            candidate = value.get(
                "ports"
            )

        if isinstance(
            candidate,
            dict,
        ):
            return list(
                candidate.values()
            )

        if isinstance(
            candidate,
            (list, tuple),
        ):
            return list(candidate)

        return []

    candidate = getattr(
        value,
        "results",
        None,
    )

    if candidate is None:
        candidate = getattr(
            value,
            "port_results",
            None,
        )

    if candidate is None:
        candidate = getattr(
            value,
            "ports",
            None,
        )

    if isinstance(
        candidate,
        dict,
    ):
        return list(
            candidate.values()
        )

    if isinstance(
        candidate,
        (list, tuple),
    ):
        return list(candidate)

    return []


def format_port_results(
    results,
) -> str:
    """
    Format port results as a terminal table.
    """

    items = _result_items(
        results
    )

    if not items:
        return "No port scan results."

    lines = [
        "",
        "PORT SCAN",
        "-" * 90,
        (
            f"{'PORT':<8}"
            f"{'PROTOCOL':<10}"
            f"{'STATE':<24}"
            f"{'SERVICE':<24}"
            f"{'RESPONSE':>15}"
        ),
        "-" * 90,
    ]

    for result in sorted(
        items,
        key=lambda item: (
            getattr(
                item,
                "port",
                0,
            ),
            getattr(
                item,
                "protocol",
                "",
            ),
        ),
    ):

        port = getattr(
            result,
            "port",
            "?",
        )

        protocol = getattr(
            result,
            "protocol",
            TCP,
        )

        state = getattr(
            result,
            "state",
            "UNKNOWN",
        )

        service = getattr(
            result,
            "service",
            "UNKNOWN",
        )

        response = getattr(
            result,
            "response_time_ms",
            0.0,
        )

        lines.append(
            f"{str(port):<8}"
            f"{str(protocol):<10}"
            f"{str(state):<24}"
            f"{str(service):<24}"
            f"{float(response):>12.2f} ms"
        )

    lines.append(
        "-" * 90
    )

    return "\n".join(
        lines
    )


def get_port_statistics(
    results,
) -> dict[str, int]:
    """
    Return statistics for a TCP/UDP scan.
    """

    items = _result_items(
        results
    )

    return {
        "total": len(items),
        "open": count_state(
            items,
            OPEN,
        ),
        "closed": count_state(
            items,
            CLOSED,
        ),
        "filtered": count_state(
            items,
            FILTERED,
        ),
        "open_filtered": count_state(
            items,
            OPEN_FILTERED,
        ),
    }


__all__ = [
    "MIN_PORT",
    "MAX_PORT",
    "DEFAULT_TIMEOUT",
    "DEFAULT_MAX_WORKERS",
    "DEFAULT_SUBMISSION_DELAY",
    "COMMON_PORTS",
    "OPEN",
    "CLOSED",
    "FILTERED",
    "OPEN_FILTERED",
    "TCP",
    "UDP",
    "PortScanResult",
    "PortScanner",
    "parse_port_range",
    "validate_ports",
    "resolve_target",
    "get_service_name",
    "count_open_ports",
    "count_state",
    "get_port_statistics",
    "format_port_results",
]