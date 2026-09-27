"""
NETWATCH
Network Monitoring, Security Assessment & Intrusion Detection Platform

Main application entry point.

Authorized-use project for:
- Network discovery
- TCP/UDP port scanning
- DNS analysis
- HTTP/HTTPS analysis
- Traffic analysis
- IDS detection
- Firewall rule analysis
- Network topology
- Routing simulation
- Security assessment
- PDF reporting
- Web dashboard

All assessment features are observational/educational.
Only scan and analyze networks you are authorized to assess.
"""

from __future__ import annotations

import json
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any

from core.config_manager import ConfigManager
from core.logger import setup_logger

from scanning.port_scanner import (
    PortScanner,
    format_port_results,
    get_port_statistics,
    parse_port_range,
    TCP,
    UDP,
)


# ============================================================================
# PATHS / CORE CONFIGURATION
# ============================================================================

PROJECT_ROOT = Path(__file__).resolve().parent
DATA_DIR = PROJECT_ROOT / "data"
REPORTS_DIR = PROJECT_ROOT / "reports_output"
CONFIG_PATH = DATA_DIR / "configuration.json"

REPORTS_DIR.mkdir(parents=True, exist_ok=True)

logger = setup_logger("netwatch")


# ============================================================================
# GLOBAL SESSION STATE
# ============================================================================

last_discovery_result: Any = None

last_port_scan_result: list[Any] = []
last_port_scan_target: str = ""
last_port_scan_protocol: str = ""

last_dns_result: Any = None
last_http_result: Any = None
last_traffic_result: Any = None
last_ids_result: Any = None
last_firewall_result: Any = None
last_topology_result: Any = None
last_routing_result: Any = None
last_assessment_result: Any = None

last_report_path: Path | None = None


# ============================================================================
# CONFIGURATION
# ============================================================================

def get_configuration() -> dict[str, Any]:
    """Load the NETWATCH configuration."""

    manager = ConfigManager(CONFIG_PATH)
    configuration = manager.load()

    if not isinstance(configuration, dict):
        raise ValueError(
            "NETWATCH configuration must be a JSON object."
        )

    return configuration


def get_config_section(
    configuration: dict[str, Any],
    section: str,
) -> dict[str, Any]:
    """Return a configuration section safely."""

    value = configuration.get(section, {})

    if isinstance(value, dict):
        return value

    return {}


def get_project_version(
    configuration: dict[str, Any],
) -> str:
    """Get the configured project version from common config layouts."""

    version = configuration.get("version")

    if version:
        return str(version)

    project = configuration.get("project")

    if isinstance(project, dict):
        version = project.get("version")

        if version:
            return str(version)

    metadata = configuration.get("metadata")

    if isinstance(metadata, dict):
        version = metadata.get("version")

        if version:
            return str(version)

    return "Configured"


# ============================================================================
# DISPLAY HELPERS
# ============================================================================

def clear_screen() -> None:
    """Clear the terminal screen."""

    print("\033[2J\033[H", end="")


def pause() -> None:
    """Pause until the user presses Enter."""

    input("\nPress Enter to continue...")


def print_header(title: str) -> None:
    """Print a consistent NETWATCH section header."""

    print("\n" + "=" * 78)
    print(f"{title:^78}")
    print("=" * 78)


def print_subheader(title: str) -> None:
    """Print a smaller section header."""

    print("\n" + "-" * 78)
    print(title)
    print("-" * 78)


def print_error(message: str) -> None:
    """Display an error message."""

    print(f"\n[ERROR] {message}")


def print_success(message: str) -> None:
    """Display a success message."""

    print(f"\n[SUCCESS] {message}")


def print_info(message: str) -> None:
    """Display an informational message."""

    print(f"\n[INFO] {message}")


def safe_input(prompt: str) -> str:
    """Read input without crashing on EOF."""

    try:
        return input(prompt).strip()
    except EOFError:
        return ""


def print_object(value: Any) -> None:
    """Print dictionaries, dataclasses and normal objects."""

    if value is None:
        print("No data available.")
        return

    if isinstance(value, str):
        print(value)
        return

    if isinstance(value, dict):
        print(
            json.dumps(
                value,
                indent=2,
                default=str,
            )
        )
        return

    if isinstance(value, (list, tuple)):
        if not value:
            print("No results.")
            return

        for item in value:
            if isinstance(item, dict):
                print(
                    json.dumps(
                        item,
                        indent=2,
                        default=str,
                    )
                )
            else:
                print(item)

        return

    if hasattr(value, "to_dict"):
        try:
            print(
                json.dumps(
                    value.to_dict(),
                    indent=2,
                    default=str,
                )
            )
            return
        except Exception:
            pass

    print(value)


# ============================================================================
# GENERIC OBJECT HELPERS
# ============================================================================

def object_to_dict(value: Any) -> dict[str, Any]:
    """Normalize a result object into a dictionary where possible."""

    if value is None:
        return {}

    if isinstance(value, dict):
        return value

    if hasattr(value, "to_dict"):
        try:
            result = value.to_dict()

            if isinstance(result, dict):
                return result
        except Exception:
            pass

    if hasattr(value, "__dict__"):
        try:
            return dict(value.__dict__)
        except Exception:
            pass

    return {"value": value}


def call_first_available(
    obj: Any,
    method_names: list[str],
    *args: Any,
    **kwargs: Any,
) -> Any:
    """
    Call the first available method from a list.

    This keeps the main application compatible with the independently
    implemented phase modules.
    """

    for method_name in method_names:
        method = getattr(obj, method_name, None)

        if callable(method):
            return method(*args, **kwargs)

    raise AttributeError(
        f"{type(obj).__name__} does not provide any of: "
        + ", ".join(method_names)
    )


# ============================================================================
# WINDOWS NETWORK HELPERS
# ============================================================================

def detect_default_gateway() -> str | None:
    """
    Detect the Windows IPv4 default gateway.

    Uses the local routing table in read-only mode.

    The Windows `route print -4` output normally contains:

        Network Destination
        Netmask
        Gateway
        Interface
        Metric

    Example:

        0.0.0.0
        0.0.0.0
        192.168.0.1
        192.168.0.107
        25

    The default route is identified by:

        Network Destination = 0.0.0.0
        Netmask            = 0.0.0.0

    If multiple default routes exist, the route with the lowest
    numeric metric is preferred.
    """

    try:
        completed = subprocess.run(
            ["route", "print", "-4"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )

        if completed.returncode != 0:
            return None

        candidates: list[tuple[int, str]] = []

        for line in completed.stdout.splitlines():
            parts = line.split()

            if len(parts) < 4:
                continue

            destination = parts[0]
            netmask = parts[1]
            gateway = parts[2]

            if (
                destination != "0.0.0.0"
                or netmask != "0.0.0.0"
                or gateway == "0.0.0.0"
            ):
                continue

            try:
                socket.inet_aton(gateway)
            except OSError:
                continue

            metric = 999999

            if len(parts) >= 5:
                try:
                    metric = int(parts[4])
                except ValueError:
                    metric = 999999

            candidates.append(
                (
                    metric,
                    gateway,
                )
            )

        if not candidates:
            return None

        candidates.sort(
            key=lambda item: item[0]
        )

        return candidates[0][1]

    except (
        FileNotFoundError,
        subprocess.SubprocessError,
        OSError,
    ):
        return None


# ============================================================================
# PHASE 1 - FOUNDATION
# ============================================================================

def foundation_status() -> None:
    """Display project foundation information."""

    print_header("NETWATCH FOUNDATION STATUS")

    try:
        configuration = get_configuration()

        print("Project              : NETWATCH")
        print(
            "Version              :",
            get_project_version(configuration),
        )
        print("Configuration        : OK")
        print("Configuration file   :", CONFIG_PATH)
        print("Reports directory    :", REPORTS_DIR)
        print("Python version       :", sys.version.split()[0])
        print("Platform             :", sys.platform)

        print("\nSecurity model       : Authorized assessment only")
        print("Operating mode       : Observational / defensive")
        print("Project status       : Foundation operational")

    except Exception as exc:
        print_error(str(exc))

    pause()


# ============================================================================
# PHASE 2 - NETWORK DISCOVERY
# ============================================================================

def network_discovery_menu() -> None:
    """Network discovery menu."""

    global last_discovery_result

    while True:
        print_header("NETWORK DISCOVERY")

        print("1. Discover Local Network")
        print("2. Discover Custom Network")
        print("3. View Last Discovery")
        print("4. Back")

        choice = safe_input("\nSelect option: ")

        if choice == "1":
            try:
                from discovery.network_discovery import NetworkDiscovery

                discovery = NetworkDiscovery()

                network = discovery.detect_local_network()

                print_info(
                    f"Detected network: {network}"
                )

                last_discovery_result = discovery.discover(
                    network
                )

                print_object(last_discovery_result)

            except Exception as exc:
                logger.exception(
                    "Network discovery failed."
                )
                print_error(str(exc))

            pause()

        elif choice == "2":
            network = safe_input(
                "\nEnter IPv4 network "
                "(example: 192.168.0.0/24): "
            )

            if not network:
                print_error(
                    "Network cannot be empty."
                )
                pause()
                continue

            try:
                from discovery.network_discovery import NetworkDiscovery

                discovery = NetworkDiscovery()

                last_discovery_result = discovery.discover(
                    network
                )

                print_object(
                    last_discovery_result
                )

            except Exception as exc:
                logger.exception(
                    "Custom network discovery failed."
                )
                print_error(str(exc))

            pause()

        elif choice == "3":
            print_header("LAST NETWORK DISCOVERY")

            if last_discovery_result is None:
                print(
                    "No discovery has been performed yet."
                )
            else:
                print_object(
                    last_discovery_result
                )

            pause()

        elif choice == "4":
            return

        else:
            print_error("Invalid option.")


# ============================================================================
# PHASE 3 - PORT & SERVICE SCANNING
# ============================================================================

def choose_protocol() -> str:
    """
    Choose TCP, UDP or BOTH.

    Numeric and text input are accepted.
    """

    while True:
        print("\nProtocol:")
        print("1. TCP")
        print("2. UDP")
        print("3. TCP + UDP")

        choice = safe_input(
            "Select protocol: "
        ).strip().lower()

        if choice in {"1", "tcp"}:
            return TCP

        if choice in {"2", "udp"}:
            return UDP

        if choice in {
            "3",
            "both",
            "tcp+udp",
            "tcp/udp",
            "tcp udp",
        }:
            return "BOTH"

        print_error(
            "Invalid protocol. Use TCP, UDP or BOTH."
        )


def _parse_ports_expression(
    expression: str,
) -> list[int]:
    """
    Parse a port expression using the scanner's parser.

    Supported examples:
    - 88
    - 22,80,443
    - 1-1024
    - 22,80,443,8000-8100
    - common
    - full
    """

    expression = expression.strip()

    if not expression:
        raise ValueError(
            "Port expression cannot be empty."
        )

    normalized = expression.lower()

    if normalized in {
        "full",
        "all",
        "all-ports",
        "1-65535",
    }:
        return list(range(1, 65536))

    return parse_port_range(expression)


def get_ports_for_scan() -> list[int]:
    """
    Get the requested port set.

    The menu accepts either menu numbers or direct port expressions.
    """

    print("\nPort selection:")
    print("1. Common ports")
    print("2. Single port")
    print("3. Custom ports")
    print("4. Full range (1-65535)")

    print(
        "\nYou can also enter a port directly, "
        "for example: 88"
    )
    print(
        "You can enter an expression directly, "
        "for example: 22,80,443 or 1-1024"
    )

    choice = safe_input(
        "\nSelect port range: "
    ).strip()

    normalized = choice.lower()

    if normalized in {
        "full",
        "all",
        "all-ports",
        "1-65535",
    }:
        return list(range(1, 65536))

    if choice == "1" or normalized == "common":
        return parse_port_range("common")

    if choice == "2":
        port_text = safe_input(
            "Enter port: "
        )

        return _parse_ports_expression(
            port_text
        )

    if choice == "3":
        print(
            "\nExamples:"
            "\n  22"
            "\n  22,80,443"
            "\n  20-25"
            "\n  22,80,443,8000-8100"
        )

        expression = safe_input(
            "Enter ports: "
        )

        return _parse_ports_expression(
            expression
        )

    if choice == "4":
        return list(range(1, 65536))

    return _parse_ports_expression(
        choice
    )


def create_port_scanner(
    configuration: dict[str, Any],
) -> PortScanner:
    """
    Create the scanner using the actual PortScanner constructor.

    PortScanner supports:
        timeout
        max_workers
        submission_delay
    """

    scanning_config = get_config_section(
        configuration,
        "scanning",
    )

    timeout = float(
        scanning_config.get(
            "timeout",
            scanning_config.get(
                "connection_timeout",
                1.0,
            ),
        )
    )

    max_workers = int(
        scanning_config.get(
            "max_workers",
            50,
        )
    )

    submission_delay = float(
        scanning_config.get(
            "submission_delay",
            0.0,
        )
    )

    timeout = max(0.1, timeout)

    max_workers = max(
        1,
        min(max_workers, 50),
    )

    submission_delay = max(
        0.0,
        submission_delay,
    )

    return PortScanner(
        timeout=timeout,
        max_workers=max_workers,
        submission_delay=submission_delay,
    )


def display_port_scan_results(
    results: list[Any],
    target: str,
) -> None:
    """Display port scan results."""

    print_header("PORT SCAN RESULTS")

    if not results:
        print("No results.")
        return

    try:
        formatted = format_port_results(
            results
        )

        if formatted:
            print(formatted)
        else:
            print_object(results)

    except Exception:
        print_object(results)

    print_subheader("SCAN STATISTICS")

    try:
        statistics = get_port_statistics(
            results
        )

        if isinstance(statistics, dict):
            for key, value in statistics.items():
                print(f"{key}: {value}")
        else:
            print(statistics)

    except Exception as exc:
        print_error(
            f"Could not calculate statistics: {exc}"
        )

    print(f"\nTarget: {target}")
    print(
        f"Results returned: {len(results)}"
    )


def run_port_scan(
    scanner: PortScanner,
    target: str,
    ports: list[int],
    protocol: str,
) -> list[Any]:
    """Execute TCP, UDP or combined scanning."""

    if not ports:
        raise ValueError(
            "At least one port must be specified."
        )

    if len(ports) > 65535:
        raise ValueError(
            "A scan cannot contain more than 65535 ports."
        )

    if protocol == "BOTH":
        tcp_results = scanner.scan(
            target,
            ports,
            protocol=TCP,
        )

        udp_results = scanner.scan(
            target,
            ports,
            protocol=UDP,
        )

        return (
            list(tcp_results)
            + list(udp_results)
        )

    return list(
        scanner.scan(
            target,
            ports,
            protocol=protocol,
        )
    )


def run_single_port_scan(
    scanner: PortScanner,
    target: str,
    port: int,
    protocol: str,
) -> list[Any]:
    """Scan one port using the scanner's dedicated API."""

    if protocol == "BOTH":
        tcp_result = scanner.scan_port(
            target,
            port,
            protocol=TCP,
        )

        udp_result = scanner.scan_port(
            target,
            port,
            protocol=UDP,
        )

        return [
            tcp_result,
            udp_result,
        ]

    return [
        scanner.scan_port(
            target,
            port,
            protocol=protocol,
        )
    ]


def run_common_port_scan(
    scanner: PortScanner,
    target: str,
    protocol: str,
) -> list[Any]:
    """Scan common ports using the scanner's dedicated API."""

    if protocol == "BOTH":
        tcp_results = scanner.scan_common_ports(
            target,
            protocol=TCP,
        )

        udp_results = scanner.scan_common_ports(
            target,
            protocol=UDP,
        )

        return (
            list(tcp_results)
            + list(udp_results)
        )

    return list(
        scanner.scan_common_ports(
            target,
            protocol=protocol,
        )
    )


def port_scanning_menu() -> None:
    """Port and service scanning menu."""

    global last_port_scan_result
    global last_port_scan_target
    global last_port_scan_protocol

    try:
        configuration = get_configuration()

    except Exception as exc:
        print_error(
            f"Configuration error: {exc}"
        )
        pause()
        return

    while True:
        print_header(
            "PORT & SERVICE SCANNING"
        )

        print("1. Run Port Scan")
        print("2. Scan Common Ports")
        print("3. Full TCP Scan (1-65535)")
        print("4. Full UDP Scan (1-65535)")
        print("5. View Last Scan")
        print("6. Scan Statistics")
        print("7. Back")

        choice = safe_input(
            "\nSelect option: "
        )

        if choice == "1":
            target = safe_input(
                "\nEnter target IP or hostname: "
            )

            if not target:
                print_error(
                    "Target cannot be empty."
                )
                pause()
                continue

            try:
                protocol = choose_protocol()

                ports = get_ports_for_scan()

                scanner = create_port_scanner(
                    configuration
                )

                print(
                    f"\nScanning {target} "
                    f"using {protocol}..."
                )

                print(
                    f"Ports selected: {len(ports)}"
                )

                if len(ports) == 1:
                    results = run_single_port_scan(
                        scanner,
                        target,
                        ports[0],
                        protocol,
                    )
                else:
                    results = run_port_scan(
                        scanner,
                        target,
                        ports,
                        protocol,
                    )

                last_port_scan_result = results
                last_port_scan_target = target
                last_port_scan_protocol = protocol

                display_port_scan_results(
                    results,
                    target,
                )

            except Exception as exc:
                logger.exception(
                    "Port scan failed."
                )
                print_error(str(exc))

            pause()

        elif choice == "2":
            target = safe_input(
                "\nEnter target IP or hostname: "
            )

            if not target:
                print_error(
                    "Target cannot be empty."
                )
                pause()
                continue

            try:
                protocol = choose_protocol()

                scanner = create_port_scanner(
                    configuration
                )

                print(
                    f"\nScanning common ports on "
                    f"{target} using {protocol}..."
                )

                results = run_common_port_scan(
                    scanner,
                    target,
                    protocol,
                )

                last_port_scan_result = results
                last_port_scan_target = target
                last_port_scan_protocol = protocol

                display_port_scan_results(
                    results,
                    target,
                )

            except Exception as exc:
                logger.exception(
                    "Common port scan failed."
                )
                print_error(str(exc))

            pause()

        elif choice in {"3", "4"}:
            target = safe_input(
                "\nEnter target IP or hostname: "
            )

            if not target:
                print_error(
                    "Target cannot be empty."
                )
                pause()
                continue

            protocol = (
                TCP
                if choice == "3"
                else UDP
            )

            try:
                scanner = create_port_scanner(
                    configuration
                )

                ports = list(
                    range(1, 65536)
                )

                print(
                    f"\nWARNING: This scans all "
                    f"{len(ports)} ports using "
                    f"{protocol}."
                )

                print(
                    "This can take considerably longer "
                    "than a common-port scan."
                )

                confirmation = safe_input(
                    "\nType YES to continue: "
                )

                if confirmation != "YES":
                    print(
                        "Full scan cancelled."
                    )
                    pause()
                    continue

                results = run_port_scan(
                    scanner,
                    target,
                    ports,
                    protocol,
                )

                last_port_scan_result = results
                last_port_scan_target = target
                last_port_scan_protocol = protocol

                display_port_scan_results(
                    results,
                    target,
                )

            except Exception as exc:
                logger.exception(
                    "Full port scan failed."
                )
                print_error(str(exc))

            pause()

        elif choice == "5":
            print_header(
                "LAST PORT SCAN"
            )

            if not last_port_scan_result:
                print(
                    "No port scan has been "
                    "performed yet."
                )
            else:
                display_port_scan_results(
                    last_port_scan_result,
                    last_port_scan_target,
                )

                print(
                    f"\nProtocol: "
                    f"{last_port_scan_protocol}"
                )

            pause()

        elif choice == "6":
            print_header(
                "PORT SCAN STATISTICS"
            )

            if not last_port_scan_result:
                print(
                    "No scan results available."
                )
            else:
                try:
                    statistics = get_port_statistics(
                        last_port_scan_result
                    )

                    print_object(
                        statistics
                    )

                except Exception as exc:
                    print_error(
                        str(exc)
                    )

            pause()

        elif choice == "7":
            return

        else:
            print_error(
                "Invalid option."
            )


# ============================================================================
# PHASE 4 - DNS ANALYSIS
# ============================================================================

def dns_analysis_menu() -> None:
    """DNS analysis menu."""

    global last_dns_result

    while True:
        print_header("DNS ANALYSIS")

        print("1. Analyze Domain")
        print("2. Reverse DNS Lookup")
        print("3. View Last DNS Result")
        print("4. Back")

        choice = safe_input(
            "\nSelect option: "
        )

        if choice == "1":
            domain = safe_input(
                "\nEnter domain: "
            )

            if not domain:
                print_error(
                    "Domain cannot be empty."
                )
                pause()
                continue

            try:
                from dns_analysis.dns_analyzer import (
                    DNSAnalyzer,
                    format_dns_results,
                )

                analyzer = DNSAnalyzer()

                last_dns_result = call_first_available(
                    analyzer,
                    [
                        "analyze_domain",
                        "analyze",
                        "query_domain",
                        "lookup",
                    ],
                    domain,
                )

                try:
                    print(
                        format_dns_results(
                            last_dns_result
                        )
                    )
                except Exception:
                    print_object(
                        last_dns_result
                    )

            except Exception as exc:
                logger.exception(
                    "DNS analysis failed."
                )
                print_error(str(exc))

            pause()

        elif choice == "2":
            address = safe_input(
                "\nEnter IPv4/IPv6 address: "
            )

            if not address:
                print_error(
                    "Address cannot be empty."
                )
                pause()
                continue

            try:
                from dns_analysis.dns_analyzer import (
                    DNSAnalyzer
                )

                analyzer = DNSAnalyzer()

                last_dns_result = call_first_available(
                    analyzer,
                    [
                        "reverse_dns",
                        "reverse_lookup",
                        "lookup_reverse",
                    ],
                    address,
                )

                print_object(
                    last_dns_result
                )

            except Exception as exc:
                logger.exception(
                    "Reverse DNS failed."
                )
                print_error(str(exc))

            pause()

        elif choice == "3":
            print_header(
                "LAST DNS RESULT"
            )

            if last_dns_result is None:
                print(
                    "No DNS analysis has "
                    "been performed."
                )
            else:
                print_object(
                    last_dns_result
                )

            pause()

        elif choice == "4":
            return

        else:
            print_error(
                "Invalid option."
            )


# ============================================================================
# PHASE 5 - HTTP / HTTPS ANALYSIS
# ============================================================================

def http_analysis_menu() -> None:
    """HTTP/HTTPS analysis menu."""

    global last_http_result

    while True:
        print_header(
            "HTTP / HTTPS ANALYSIS"
        )

        print("1. Analyze URL")
        print("2. View Last HTTP Result")
        print("3. Back")

        choice = safe_input(
            "\nSelect option: "
        )

        if choice == "1":
            url = safe_input(
                "\nEnter URL "
                "(example: https://example.com): "
            )

            if not url:
                print_error(
                    "URL cannot be empty."
                )
                pause()
                continue

            try:
                from web_analysis.http_analyzer import (
                    HTTPAnalyzer
                )

                analyzer = HTTPAnalyzer()

                last_http_result = call_first_available(
                    analyzer,
                    [
                        "analyze",
                        "analyze_url",
                        "inspect",
                        "check",
                    ],
                    url,
                )

                print_object(
                    last_http_result
                )

            except Exception as exc:
                logger.exception(
                    "HTTP analysis failed."
                )
                print_error(str(exc))

            pause()

        elif choice == "2":
            print_header(
                "LAST HTTP / HTTPS RESULT"
            )

            if last_http_result is None:
                print(
                    "No HTTP analysis has "
                    "been performed."
                )
            else:
                print_object(
                    last_http_result
                )

            pause()

        elif choice == "3":
            return

        else:
            print_error(
                "Invalid option."
            )


# ============================================================================
# PHASE 6 - TRAFFIC ANALYSIS
# ============================================================================

def traffic_analysis_menu() -> None:
    """Network traffic analysis menu."""

    global last_traffic_result

    while True:
        print_header(
            "NETWORK TRAFFIC ANALYSIS"
        )

        print("1. Analyze Sample Traffic")
        print("2. Live Capture")
        print("3. Analyze Last Capture")
        print("4. View Last Traffic Result")
        print("5. Back")

        choice = safe_input(
            "\nSelect option: "
        )

        # ------------------------------------------------------------------
        # SAMPLE TRAFFIC
        # ------------------------------------------------------------------
        if choice == "1":
            try:
                from traffic_analysis.traffic_analyzer import (
                    TrafficAnalyzer
                )

                analyzer = TrafficAnalyzer()

                # TrafficAnalyzer exposes create_sample_result().
                # This returns the deterministic sample analysis directly.
                last_traffic_result = (
                    analyzer.create_sample_result()
                )

                print_header(
                    "SAMPLE TRAFFIC ANALYSIS"
                )

                print_object(
                    last_traffic_result
                )

            except Exception as exc:
                logger.exception(
                    "Sample traffic analysis failed."
                )
                print_error(str(exc))

            pause()

        # ------------------------------------------------------------------
        # LIVE CAPTURE
        # ------------------------------------------------------------------
        elif choice == "2":
            try:
                duration_text = safe_input(
                    "\nCapture duration in seconds "
                    "(default 10): "
                )

                duration = (
                    float(duration_text)
                    if duration_text
                    else 10.0
                )

                packet_count_text = safe_input(
                    "Maximum packet count "
                    "(default 1000): "
                )

                packet_count = (
                    int(packet_count_text)
                    if packet_count_text
                    else 1000
                )

                from traffic_analysis.traffic_analyzer import (
                    TrafficAnalyzer
                )

                analyzer = TrafficAnalyzer()

                print_info(
                    f"Starting live capture for "
                    f"{duration:g} seconds "
                    f"(maximum {packet_count} packets)..."
                )

                # TrafficAnalyzer.capture_live() is the actual API
                # implemented by Phase 6.
                last_traffic_result = (
                    analyzer.capture_live(
                        duration=duration,
                        packet_count=packet_count,
                    )
                )

                print_header(
                    "LIVE TRAFFIC ANALYSIS"
                )

                print_object(
                    last_traffic_result
                )

            except KeyboardInterrupt:
                print(
                    "\nTraffic capture cancelled by user."
                )

            except Exception as exc:
                logger.exception(
                    "Traffic capture failed."
                )
                print_error(str(exc))

            pause()

        # ------------------------------------------------------------------
        # LAST CAPTURE
        # ------------------------------------------------------------------
        elif choice == "3":
            print_header(
                "LAST TRAFFIC CAPTURE"
            )

            if last_traffic_result is None:
                print(
                    "No traffic capture is available."
                )
                print(
                    "Run Live Capture first."
                )
            else:
                print(
                    "The last capture has already "
                    "been analyzed by TrafficAnalyzer."
                )
                print(
                    "The current Phase 6 analyzer does "
                    "not retain raw packets for a second "
                    "analysis pass."
                )
                print()

                print_object(
                    last_traffic_result
                )

        # ------------------------------------------------------------------
        # VIEW LAST TRAFFIC RESULT
        # ------------------------------------------------------------------
        elif choice == "4":
            print_header(
                "LAST TRAFFIC ANALYSIS"
            )

            if last_traffic_result is None:
                print(
                    "No traffic analysis available."
                )
            else:
                print_object(
                    last_traffic_result
                )

            pause()

        elif choice == "5":
            return

        else:
            print_error(
                "Invalid option."
            )


# ============================================================================
# PHASE 7 - IDS
# ============================================================================

def ids_menu() -> None:
    """IDS/security detection menu."""

    global last_ids_result

    while True:
        print_header(
            "IDS / SECURITY DETECTION"
        )

        print("1. Analyze Sample Traffic")
        print("2. Analyze Last Traffic Capture")
        print("3. Detection Rule Settings")
        print("4. View Last Alert Summary")
        print("5. Back")

        choice = safe_input(
            "\nSelect option: "
        )

        if choice == "1":
            try:
                from detection.ids_engine import (
                    IDSEngine
                )

                engine = IDSEngine()

                last_ids_result = (
                    engine.analyze_sample()
                )

                print_header(
                    "IDS SAMPLE ANALYSIS"
                )

                print_object(
                    last_ids_result
                )

            except Exception as exc:
                logger.exception(
                    "IDS sample analysis failed."
                )
                print_error(
                    str(exc)
                )

            pause()

        elif choice == "2":
            print_header(
                "IDS ANALYSIS OF LAST TRAFFIC CAPTURE"
            )

            if last_traffic_result is None:
                print_error(
                    "No traffic analysis is stored "
                    "in the current session."
                )

                print()
                print(
                    "Run the following in this same "
                    "NETWATCH session:"
                )
                print(
                    "5. Network Traffic Analysis"
                )
                print(
                    "1. Analyze Sample Traffic"
                )
                print(
                    "or"
                )
                print(
                    "2. Live Capture"
                )
                print()
                print(
                    "Then return to:"
                )
                print(
                    "6. IDS / Security Detection"
                )
                print(
                    "2. Analyze Last Traffic Capture"
                )

                pause()
                continue

            try:
                from detection.ids_engine import (
                    IDSEngine
                )

                engine = IDSEngine()

                # Phase 6 returns a TrafficAnalysisResult.
                # IDSEngine provides a dedicated integration
                # method for this exact result type.
                last_ids_result = (
                    engine.analyze_traffic_result(
                        last_traffic_result
                    )
                )

                print_success(
                    "Last traffic capture was "
                    "successfully analyzed by the IDS."
                )

                print_object(
                    last_ids_result
                )

            except Exception as exc:
                logger.exception(
                    "IDS traffic analysis failed."
                )
                print_error(
                    str(exc)
                )

            pause()

        elif choice == "3":
            try:
                from detection.detection_rules import (
                    get_default_detection_rules
                )

                rules = (
                    get_default_detection_rules()
                )

                print_header(
                    "IDS DETECTION RULE SETTINGS"
                )

                print_object(
                    rules
                )

            except Exception as exc:
                logger.exception(
                    "Could not load IDS detection "
                    "rule settings."
                )
                print_error(
                    str(exc)
                )

            pause()

        elif choice == "4":
            print_header(
                "LAST IDS ALERT SUMMARY"
            )

            if last_ids_result is None:
                print(
                    "No IDS analysis has "
                    "been performed."
                )
            else:
                print_object(
                    last_ids_result
                )

            pause()

        elif choice == "5":
            return

        else:
            print_error(
                "Invalid option."
            )


# ============================================================================
# PHASE 8 - FIREWALL ANALYZER
# ============================================================================

def firewall_menu() -> None:
    global last_firewall_result

    while True:
        print_header("FIREWALL ANALYZER")

        print("1. Analyze Sample Firewall Rules")
        print("2. Analyze Firewall Rules JSON")
        print("3. Firewall Analyzer Settings")
        print("4. View Last Firewall Analysis")
        print("5. Back")

        choice = safe_input("\nSelect option: ")

        if choice == "1":
            try:
                from firewall.firewall_analyzer import (
                    FirewallAnalyzer,
                    format_firewall_results,
                )

                analyzer = FirewallAnalyzer()

                sample_rules = analyzer.sample_rules()

                last_firewall_result = analyzer.analyze(
                    sample_rules
                )

                print(
                    format_firewall_results(
                        last_firewall_result
                    )
                )

            except Exception as exc:
                logger.exception(
                    "Firewall sample analysis failed."
                )
                print_error(str(exc))

            pause()

        elif choice == "2":
            path_text = safe_input(
                "\nEnter firewall JSON path "
                "(press Enter for data/firewall_rules.json): "
            )

            path = (
                Path(path_text)
                if path_text
                else DATA_DIR / "firewall_rules.json"
            )

            try:
                from firewall.firewall_analyzer import (
                    FirewallAnalyzer,
                    format_firewall_results,
                )

                analyzer = FirewallAnalyzer()

                last_firewall_result = (
                    analyzer.analyze_json_file(path)
                )

                print(
                    format_firewall_results(
                        last_firewall_result
                    )
                )

            except Exception as exc:
                logger.exception(
                    "Firewall file analysis failed."
                )
                print_error(str(exc))

            pause()

        elif choice == "3":
            try:
                from firewall.firewall_analyzer import (
                    FirewallAnalyzer
                )

                analyzer = FirewallAnalyzer()

                print_header("FIREWALL ANALYZER SETTINGS")

                print(
                    f"Broad Port Threshold : "
                    f"{analyzer.broad_port_threshold}"
                )

                print(
                    "Analysis Mode        : "
                    "Read-only"
                )

                print(
                    "Purpose              : "
                    "Authorized defensive assessment"
                )

            except Exception as exc:
                logger.exception(
                    "Firewall settings display failed."
                )
                print_error(str(exc))

            pause()

        elif choice == "4":
            print_header("LAST FIREWALL ANALYSIS")

            if last_firewall_result is None:
                print("No firewall analysis available.")
            else:
                try:
                    from firewall.firewall_analyzer import (
                        format_firewall_results,
                    )

                    print(
                        format_firewall_results(
                            last_firewall_result
                        )
                    )

                except Exception as exc:
                    logger.exception(
                        "Failed to display firewall analysis."
                    )
                    print_error(str(exc))

            pause()

        elif choice == "5":
            return

        else:
            print_error(
                "Invalid option. Please select 1-5."
            )
            pause()


# ============================================================================
# PHASE 9 - TOPOLOGY
# ============================================================================

def topology_menu():
    """Network topology menu and discovery integration."""

    global last_topology_result

    from topology.topology_mapper import (
        TopologyMapper,
        format_topology_results,
    )

    while True:
        print_header("NETWORK TOPOLOGY")

        print("1. Build Sample Topology")
        print("2. Build Topology from Discovery")
        print("3. Export Topology Image")
        print("4. View Last Topology")
        print("5. Back")

        choice = safe_input("\nSelect option: ")

        # ==================================================================
        # 1. BUILD SAMPLE TOPOLOGY
        # ==================================================================
        if choice == "1":
            try:
                mapper = TopologyMapper()

                last_topology_result = (
                    mapper.build_sample_topology()
                )

                print()
                print(
                    format_topology_results(
                        last_topology_result
                    )
                )

            except Exception as exc:
                logger.exception(
                    "Sample topology generation failed."
                )

                print_error(
                    f"Could not build sample topology: {exc}"
                )

            pause()

        # ==================================================================
        # 2. BUILD TOPOLOGY FROM DISCOVERY
        # ==================================================================
        elif choice == "2":

            if last_discovery_result is None:
                print_error(
                    "Run Network Discovery first."
                )
                print()
                print(
                    "Required sequence:"
                )
                print(
                    "1. Network Discovery"
                )
                print(
                    "2. Discover Local Network"
                )
                print(
                    "3. Return to the main menu"
                )
                print(
                    "4. Network Topology"
                )
                print(
                    "5. Build Topology from Discovery"
                )

                pause()
                continue

            try:
                mapper = TopologyMapper()

                # ----------------------------------------------------------
                # NetworkDiscovery.discover() returns:
                #
                # list[DiscoveryResult]
                #
                # Therefore the normal case is simply:
                #
                # devices = list(last_discovery_result)
                # ----------------------------------------------------------

                discovery_data = last_discovery_result

                devices = []

                if isinstance(
                    discovery_data,
                    list,
                ):
                    devices = list(
                        discovery_data
                    )

                elif isinstance(
                    discovery_data,
                    tuple,
                ):
                    devices = list(
                        discovery_data
                    )

                elif isinstance(
                    discovery_data,
                    dict,
                ):
                    possible_keys = (
                        "devices",
                        "discovered_devices",
                        "hosts",
                        "discovered_hosts",
                        "results",
                    )

                    for key in possible_keys:
                        value = discovery_data.get(
                            key
                        )

                        if isinstance(
                            value,
                            (list, tuple),
                        ):
                            devices = list(value)
                            break

                else:
                    possible_attributes = (
                        "devices",
                        "discovered_devices",
                        "hosts",
                        "discovered_hosts",
                        "results",
                    )

                    for attribute in possible_attributes:
                        if hasattr(
                            discovery_data,
                            attribute,
                        ):
                            value = getattr(
                                discovery_data,
                                attribute,
                            )

                            if isinstance(
                                value,
                                (list, tuple),
                            ):
                                devices = list(value)
                                break

                # ----------------------------------------------------------
                # Handle the case where a single DiscoveryResult object
                # was stored instead of a list.
                # ----------------------------------------------------------

                if (
                    not devices
                    and hasattr(
                        discovery_data,
                        "ip_address",
                    )
                ):
                    devices = [
                        discovery_data
                    ]

                # ----------------------------------------------------------
                # Make sure discovery actually returned devices.
                # ----------------------------------------------------------

                if not devices:
                    print_error(
                        "Discovery completed, but no device records "
                        "were found for topology mapping."
                    )

                    print()
                    print(
                        f"Discovery result type: "
                        f"{type(discovery_data).__name__}"
                    )

                    pause()
                    continue

                # ----------------------------------------------------------
                # Detect the Windows default IPv4 gateway.
                #
                # The gateway is obtained from the local routing table,
                # rather than guessing from the first discovered device.
                # ----------------------------------------------------------

                default_gateway = detect_default_gateway()

                router_ip = (
                    str(default_gateway)
                    if default_gateway
                    else None
                )

                router_hostname = None

                topology_devices = []

                # ----------------------------------------------------------
                # Match the detected gateway against discovery records.
                #
                # If the gateway itself was discovered, use its hostname
                # and exclude it from the normal DEVICE nodes.
                #
                # If the gateway was not discovered, keep every discovered
                # host as a DEVICE while still representing the gateway
                # as the ROUTER node.
                # ----------------------------------------------------------

                gateway_found_in_discovery = False

                for device in devices:

                    if isinstance(
                        device,
                        dict,
                    ):
                        ip_address = device.get(
                            "ip_address",
                            device.get(
                                "ip",
                                device.get(
                                    "address"
                                ),
                            ),
                        )

                        hostname = device.get(
                            "hostname",
                            device.get(
                                "host",
                                device.get(
                                    "name"
                                ),
                            ),
                        )

                    else:
                        ip_address = getattr(
                            device,
                            "ip_address",
                            getattr(
                                device,
                                "ip",
                                getattr(
                                    device,
                                    "address",
                                    None,
                                ),
                            ),
                        )

                        hostname = getattr(
                            device,
                            "hostname",
                            getattr(
                                device,
                                "host",
                                getattr(
                                    device,
                                    "name",
                                    None,
                                ),
                            ),
                        )

                    normalized_ip = (
                        str(ip_address).strip()
                        if ip_address
                        else None
                    )

                    if (
                        router_ip
                        and normalized_ip == router_ip
                    ):
                        gateway_found_in_discovery = True

                        if hostname:
                            router_hostname = str(
                                hostname
                            )

                        continue

                    topology_devices.append(
                        device
                    )

                # ----------------------------------------------------------
                # If Windows could not provide a default gateway, retain a
                # compatibility fallback.
                #
                # IMPORTANT:
                # We do not automatically call the first discovered host
                # the router. The fallback only applies when gateway
                # detection itself is unavailable.
                # ----------------------------------------------------------

                gateway_detection_fallback = False

                if router_ip is None:
                    gateway_detection_fallback = True

                    if devices:
                        first_device = devices[0]

                        if isinstance(
                            first_device,
                            dict,
                        ):
                            candidate_ip = first_device.get(
                                "ip_address",
                                first_device.get(
                                    "ip",
                                    first_device.get(
                                        "address"
                                    ),
                                ),
                            )

                            candidate_hostname = first_device.get(
                                "hostname",
                                first_device.get(
                                    "host",
                                    first_device.get(
                                        "name"
                                    ),
                                ),
                            )

                        else:
                            candidate_ip = getattr(
                                first_device,
                                "ip_address",
                                getattr(
                                    first_device,
                                    "ip",
                                    getattr(
                                        first_device,
                                        "address",
                                        None,
                                    ),
                                ),
                            )

                            candidate_hostname = getattr(
                                first_device,
                                "hostname",
                                getattr(
                                    first_device,
                                    "host",
                                    getattr(
                                        first_device,
                                        "name",
                                        None,
                                    ),
                                ),
                            )

                        if candidate_ip:
                            router_ip = str(
                                candidate_ip
                            )

                        if candidate_hostname:
                            router_hostname = str(
                                candidate_hostname
                            )

                        # Remove the fallback candidate from the normal
                        # device list.
                        topology_devices = [
                            device
                            for device in topology_devices
                            if (
                                (
                                    getattr(
                                        device,
                                        "ip_address",
                                        getattr(
                                            device,
                                            "ip",
                                            getattr(
                                                device,
                                                "address",
                                                None,
                                            ),
                                        ),
                                    )
                                    if not isinstance(
                                        device,
                                        dict,
                                    )
                                    else device.get(
                                        "ip_address",
                                        device.get(
                                            "ip",
                                            device.get(
                                                "address"
                                            ),
                                        ),
                                    )
                                )
                                != router_ip
                            )
                        ]

                # ----------------------------------------------------------
                # Build the topology.
                # ----------------------------------------------------------

                last_topology_result = (
                    mapper.build_topology(
                        devices=topology_devices,
                        router_ip=router_ip,
                        router_hostname=router_hostname,
                    )
                )

                print()
                print_success(
                    "Topology successfully built from "
                    "network discovery."
                )

                print(
                    f"Discovered records : {len(devices)}"
                )

                print(
                    f"Default gateway    : "
                    f"{default_gateway or 'Not detected'}"
                )

                print(
                    f"Router candidate   : "
                    f"{router_ip or 'Not identified'}"
                )

                print(
                    f"Gateway discovered : "
                    f"{'YES' if gateway_found_in_discovery else 'NO'}"
                )

                if gateway_detection_fallback:
                    print(
                        "Router selection   : "
                        "Fallback candidate because the "
                        "Windows default gateway could not be detected."
                    )
                else:
                    print(
                        "Router selection   : "
                        "Windows default IPv4 gateway"
                    )

                print(
                    f"Devices mapped     : "
                    f"{len(topology_devices)}"
                )

                print()
                print(
                    format_topology_results(
                        last_topology_result
                    )
                )

            except Exception as exc:
                logger.exception(
                    "Topology generation from discovery failed."
                )

                print_error(
                    f"Could not build topology from discovery: "
                    f"{exc}"
                )

            pause()

        # ==================================================================
        # 3. EXPORT TOPOLOGY IMAGE
        # ==================================================================
        elif choice == "3":

            if last_topology_result is None:
                print_error(
                    "Build a topology first."
                )
                pause()
                continue

            try:
                mapper = TopologyMapper()

                output_path = (
                    REPORTS_DIR
                    / "network_topology.png"
                )

                exported_path = (
                    mapper.export_image(
                        last_topology_result,
                        output_path,
                    )
                )

                print()
                print_success(
                    "Topology image exported successfully."
                )

                print(
                    f"Path: {exported_path}"
                )

            except Exception as exc:
                logger.exception(
                    "Topology image export failed."
                )

                print_error(
                    f"Could not export topology image: "
                    f"{exc}"
                )

            pause()

        # ==================================================================
        # 4. VIEW LAST TOPOLOGY
        # ==================================================================
        elif choice == "4":

            if last_topology_result is None:
                print_error(
                    "No topology has been generated yet."
                )
                pause()
                continue

            try:
                print()
                print(
                    format_topology_results(
                        last_topology_result
                    )
                )

            except Exception as exc:
                logger.exception(
                    "Topology display failed."
                )

                print_error(
                    f"Could not display topology: {exc}"
                )

            pause()

        # ==================================================================
        # 5. BACK
        # ==================================================================
        elif choice == "5":
            return

        else:
            print_error(
                "Invalid option. Please select 1-5."
            )

            pause()


# ============================================================================
# PHASE 12 - SECURITY ASSESSMENT
# ============================================================================

def security_assessment_menu() -> None:
    """Security assessment engine menu."""

    global last_assessment_result

    while True:
        print_header(
            "SECURITY ASSESSMENT"
        )

        print("1. Assess Current Session")
        print("2. Generate Sample Assessment")
        print("3. View Last Assessment")
        print("4. View Assessment Metrics")
        print("5. Back")

        choice = safe_input(
            "\nSelect option: "
        )

        if choice == "1":
            try:
                from assessment.assessment_engine import (
                    AssessmentEngine
                )

                engine = AssessmentEngine()

                context = {
                    "discovery": last_discovery_result,
                    "ports": last_port_scan_result,
                    "dns": last_dns_result,
                    "http": last_http_result,
                    "traffic": last_traffic_result,
                    "ids": last_ids_result,
                    "firewall": last_firewall_result,
                    "topology": last_topology_result,
                    "routing": last_routing_result,
                }

                last_assessment_result = (
                    call_first_available(
                        engine,
                        [
                            "assess",
                            "build_assessment",
                            "create_assessment",
                        ],
                        context,
                    )
                )

                print_object(
                    last_assessment_result
                )

            except Exception as exc:
                logger.exception(
                    "Security assessment failed."
                )
                print_error(
                    str(exc)
                )

            pause()

        elif choice == "2":
            try:
                from assessment.assessment_engine import (
                    AssessmentEngine
                )

                engine = AssessmentEngine()

                last_assessment_result = (
                    call_first_available(
                        engine,
                        [
                            "build_sample_assessment",
                            "sample_assessment",
                            "create_sample_assessment",
                        ],
                    )
                )

                print_object(
                    last_assessment_result
                )

            except Exception as exc:
                logger.exception(
                    "Sample assessment failed."
                )
                print_error(
                    str(exc)
                )

            pause()

        elif choice == "3":
            print_header(
                "LAST SECURITY ASSESSMENT"
            )

            if last_assessment_result is None:
                print(
                    "No assessment available."
                )
            else:
                print_object(
                    last_assessment_result
                )

            pause()

        elif choice == "4":
            print_header(
                "ASSESSMENT METRICS"
            )

            if last_assessment_result is None:
                print(
                    "No assessment available."
                )

            else:
                data = object_to_dict(
                    last_assessment_result
                )

                for key in (
                    "device_count",
                    "open_port_count",
                    "alert_count",
                    "firewall_finding_count",
                    "total_findings",
                ):
                    value = getattr(
                        last_assessment_result,
                        key,
                        data.get(
                            key,
                            "N/A",
                        ),
                    )

                    print(
                        f"{key}: {value}"
                    )

                summary = data.get(
                    "finding_summary",
                    {},
                )

                if summary:
                    print(
                        "\nFinding Summary:"
                    )
                    print_object(
                        summary
                    )

            pause()

        elif choice == "5":
            return

        else:
            print_error(
                "Invalid option."
            )


# ============================================================================
# PHASE 13 - PDF REPORT
# ============================================================================

def pdf_report_menu() -> None:
    global last_assessment_result
    """Automated PDF report menu."""

    global last_report_path

    while True:
        print_header(
            "AUTOMATED PDF REPORT"
        )

        print("1. Generate Current Assessment PDF")
        print("2. Generate Sample Assessment PDF")
        print("3. View Last Report")
        print("4. Report Information")
        print("5. Back")

        choice = safe_input(
            "\nSelect option: "
        )

        if choice == "1":
            if last_assessment_result is None:
                print(
                    "\nNo security assessment is "
                    "available for reporting."
                )
                print(
                    "Run Security Assessment -> "
                    "Assess Current Session first."
                )
                pause()
                continue

            try:
                from reporting.pdf_report import (
                    PDFReportGenerator
                )

                generator = PDFReportGenerator(
                    output_directory=REPORTS_DIR
                )

                result = generator.generate(
                    last_assessment_result
                )

                last_report_path = Path(
                    result
                )

                print_success(
                    f"PDF report generated:\n"
                    f"{last_report_path}"
                )

            except Exception as exc:
                logger.exception(
                    "Current PDF report generation failed."
                )
                print_error(
                    str(exc)
                )

            pause()

        elif choice == "2":
            try:
                from assessment.assessment_engine import (
                    AssessmentEngine
                )
                from reporting.pdf_report import (
                    PDFReportGenerator
                )

                assessment_engine = (
                    AssessmentEngine()
                )

                sample_assessment = (
                    call_first_available(
                        assessment_engine,
                        [
                            "build_sample_assessment",
                            "sample_assessment",
                            "create_sample_assessment",
                        ],
                    )
                )

                last_assessment_result = (
                    sample_assessment
                )

                generator = PDFReportGenerator(
                    output_directory=REPORTS_DIR
                )

                result = generator.generate(
                    sample_assessment
                )

                last_report_path = Path(
                    result
                )

                print_success(
                    f"Sample PDF report generated:\n"
                    f"{last_report_path}"
                )

            except Exception as exc:
                logger.exception(
                    "Sample PDF report generation failed."
                )
                print_error(
                    str(exc)
                )

            pause()

        elif choice == "3":
            print_header(
                "LAST REPORT"
            )

            if last_report_path is None:
                print(
                    "No report has been generated."
                )

            elif last_report_path.exists():
                print(
                    f"Path    : "
                    f"{last_report_path}"
                )
                print(
                    "Exists  : YES"
                )
                print(
                    f"Size    : "
                    f"{last_report_path.stat().st_size} bytes"
                )

            else:
                print(
                    "Report path no longer exists:\n"
                    f"{last_report_path}"
                )

            pause()

        elif choice == "4":
            print_header(
                "REPORT INFORMATION"
            )

            if last_report_path is None:
                print(
                    "No report generated yet."
                )

            else:
                print(
                    f"Path   : "
                    f"{last_report_path}"
                )

                print(
                    f"Exists : "
                    f"{last_report_path.exists()}"
                )

                if last_report_path.exists():
                    print(
                        f"Size   : "
                        f"{last_report_path.stat().st_size} bytes"
                    )

            pause()

        elif choice == "5":
            return

        else:
            print_error(
                "Invalid option."
            )


# ============================================================================
# PHASE 11 - DASHBOARD
# ============================================================================

def dashboard_menu() -> None:
    """Start the Flask dashboard."""

    print_header(
        "NETWATCH DASHBOARD"
    )

    print(
        "The dashboard is available at:"
    )
    print()
    print(
        "http://127.0.0.1:5000"
    )
    print()
    print(
        "The dashboard will run until you stop it "
        "with CTRL+C."
    )

    try:
        from dashboard.app import app

        app.run(
            host="127.0.0.1",
            port=5000,
            debug=False,
        )

    except KeyboardInterrupt:
        print(
            "\nDashboard stopped."
        )

    except Exception as exc:
        logger.exception(
            "Dashboard failed."
        )
        print_error(
            str(exc)
        )

    pause()


# ============================================================================
# PHASE 10 - ROUTING SIMULATOR
# ============================================================================

def routing_menu() -> None:
    """Provide the routing simulator menu."""

    global last_routing_result

    try:
        from routing.routing_simulator import RoutingSimulator
    except Exception as exc:
        logger.exception("Routing simulator could not be loaded.")
        print_error(str(exc))
        pause()
        return

    simulator = RoutingSimulator()

    while True:
        print_header("ROUTING SIMULATOR")
        print("1. Generate Sample Routing Table")
        print("2. View Last Routing Result")
        print("3. Back")

        choice = safe_input("\nSelect option: ")

        if choice == "1":
            try:
                last_routing_result = call_first_available(
                    simulator,
                    [
                        "build_sample_routing_table",
                        "sample_routing_table",
                        "simulate_sample",
                        "run_sample",
                    ],
                )
                print_object(last_routing_result)
            except Exception as exc:
                logger.exception("Sample routing simulation failed.")
                print_error(str(exc))
            pause()

        elif choice == "2":
            print_header("LAST ROUTING RESULT")
            print_object(last_routing_result)
            pause()

        elif choice == "3":
            return

        else:
            print_error("Invalid option. Please select 1-3.")


# ============================================================================
# MAIN MENU
# ============================================================================

def main_menu() -> None:
    """Run the main NETWATCH application menu."""

    while True:
        print_header(
            "NETWATCH - NETWORK MONITORING, "
            "SECURITY ASSESSMENT & IDS PLATFORM"
        )

        print("1.  Network Discovery")
        print("2.  Port & Service Scanning")
        print("3.  DNS Analysis")
        print("4.  HTTP/HTTPS Analysis")
        print("5.  Network Traffic Analysis")
        print("6.  IDS / Security Detection")
        print("7.  Firewall Analyzer")
        print("8.  Network Topology")
        print("9.  Routing Simulator")
        print("10. Security Assessment")
        print("11. Automated PDF Report")
        print("12. Dashboard")
        print("13. Foundation Status")
        print("14. Exit")

        choice = safe_input(
            "\nSelect option: "
        )

        try:
            if choice == "1":
                network_discovery_menu()

            elif choice == "2":
                port_scanning_menu()

            elif choice == "3":
                dns_analysis_menu()

            elif choice == "4":
                http_analysis_menu()

            elif choice == "5":
                traffic_analysis_menu()

            elif choice == "6":
                ids_menu()

            elif choice == "7":
                firewall_menu()

            elif choice == "8":
                topology_menu()

            elif choice == "9":
                routing_menu()

            elif choice == "10":
                security_assessment_menu()

            elif choice == "11":
                pdf_report_menu()

            elif choice == "12":
                dashboard_menu()

            elif choice == "13":
                foundation_status()

            elif choice == "14":
                print(
                    "\nNETWATCH shutting down."
                )
                print(
                    "Thank you for using NETWATCH."
                )
                return

            else:
                print_error(
                    "Invalid option. "
                    "Please select 1-14."
                )

        except KeyboardInterrupt:
            print(
                "\n\nOperation cancelled by user."
            )

        except Exception as exc:
            logger.exception(
                "Unexpected application error."
            )

            print_error(
                f"Unexpected error: {exc}"
            )


# ============================================================================
# APPLICATION ENTRY POINT
# ============================================================================

def main() -> None:
    """NETWATCH application entry point."""

    print(
        "\nStarting NETWATCH..."
    )

    try:
        configuration = get_configuration()

        version = get_project_version(
            configuration
        )

        print(
            f"NETWATCH version {version}"
        )

    except Exception as exc:
        print_error(
            f"Could not load configuration: {exc}"
        )
        return

    main_menu()


if __name__ == "__main__":
    main()