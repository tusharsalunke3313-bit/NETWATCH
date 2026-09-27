"""
NETWATCH Network Discovery Engine.

Discovers active devices on an authorized local IPv4 network.
"""

import ipaddress
import platform
import socket
import subprocess
import time
from dataclasses import dataclass
from typing import Optional

from discovery.arp_scanner import ARPScanner


@dataclass
class DiscoveryResult:
    """Represents a discovered network device."""

    ip_address: str
    mac_address: Optional[str]
    hostname: Optional[str]
    status: str
    response_time_ms: Optional[float]


class NetworkDiscovery:
    """
    Perform local network discovery.

    Discovery uses:
    - IPv4 subnet calculations
    - ICMP echo through the operating system ping command
    - Local ARP table collection
    - Reverse DNS hostname resolution
    """

    def __init__(
        self,
        timeout: float = 1.0,
        max_hosts: int = 254,
    ):
        self.timeout = timeout
        self.max_hosts = max_hosts
        self.arp_scanner = ARPScanner()

    def discover(
        self,
        network: str,
    ) -> list[DiscoveryResult]:
        """
        Discover active devices in an IPv4 network.

        Args:
            network: IPv4 network in CIDR notation.

        Returns:
            List of discovered devices.

        Raises:
            ValueError: If the network is invalid or too large.
        """

        target_network = self._validate_network(network)

        hosts = list(target_network.hosts())

        if len(hosts) > self.max_hosts:
            raise ValueError(
                f"Network contains {len(hosts)} usable hosts. "
                f"Maximum supported by this discovery phase is "
                f"{self.max_hosts}."
            )

        print()
        print("NETWORK DISCOVERY")
        print("=" * 60)
        print(f"Target network : {target_network}")
        print(f"Usable hosts   : {len(hosts)}")
        print()

        print("Scanning hosts...")
        print()

        discovered: list[DiscoveryResult] = []

        for index, host in enumerate(hosts, start=1):
            ip_address = str(host)

            print(
                f"\rChecking {ip_address:<15} "
                f"[{index}/{len(hosts)}]",
                end="",
                flush=True,
            )

            response_time = self._ping_host(
                ip_address
            )

            if response_time is None:
                continue

            hostname = self._resolve_hostname(
                ip_address
            )

            discovered.append(
                DiscoveryResult(
                    ip_address=ip_address,
                    mac_address=None,
                    hostname=hostname,
                    status="UP",
                    response_time_ms=response_time,
                )
            )

        print()
        print()
        print("Refreshing ARP information...")

        arp_entries = self.arp_scanner.get_arp_table()

        arp_map = {
            entry.ip_address: entry.mac_address
            for entry in arp_entries
        }

        for device in discovered:
            device.mac_address = arp_map.get(
                device.ip_address
            )

        discovered.sort(
            key=lambda device: ipaddress.ip_address(
                device.ip_address
            )
        )

        return discovered

    @staticmethod
    def _validate_network(
        network: str,
    ) -> ipaddress.IPv4Network:
        """Validate an IPv4 CIDR network."""

        try:
            target = ipaddress.ip_network(
                network.strip(),
                strict=False,
            )
        except ValueError as exc:
            raise ValueError(
                f"Invalid network: {network}"
            ) from exc

        if target.version != 4:
            raise ValueError(
                "This discovery phase currently supports IPv4 networks only."
            )

        return target

    def _ping_host(
        self,
        ip_address: str,
    ) -> Optional[float]:
        """
        Ping a host using the operating system.

        Returns:
            Response time in milliseconds, or None if unreachable.
        """

        if platform.system().lower() == "windows":
            command = [
                "ping",
                "-n",
                "1",
                "-w",
                str(int(self.timeout * 1000)),
                ip_address,
            ]
        else:
            command = [
                "ping",
                "-c",
                "1",
                "-W",
                str(max(1, int(self.timeout))),
                ip_address,
            ]

        start = time.perf_counter()

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout + 2,
                check=False,
            )
        except (
            FileNotFoundError,
            subprocess.SubprocessError,
        ):
            return None

        elapsed_ms = (
            time.perf_counter() - start
        ) * 1000

        if result.returncode != 0:
            return None

        return round(elapsed_ms, 2)

    @staticmethod
    def _resolve_hostname(
        ip_address: str,
    ) -> Optional[str]:
        """Resolve an IP address to a hostname."""

        try:
            hostname, _, _ = socket.gethostbyaddr(
                ip_address
            )

            return hostname

        except (
            socket.herror,
            socket.gaierror,
            OSError,
        ):
            return None

    @staticmethod
    def detect_local_network() -> Optional[str]:
        """
        Attempt to determine the local IPv4 network.

        Windows is queried through ipconfig.
        """

        local_ip = NetworkDiscovery._detect_local_ip()

        if local_ip is None:
            return None

        netmask = NetworkDiscovery._detect_subnet_mask(
            local_ip
        )

        if netmask is None:
            return None

        try:
            network = ipaddress.ip_network(
                f"{local_ip}/{netmask}",
                strict=False,
            )

            return str(network)

        except ValueError:
            return None

    @staticmethod
    def _detect_local_ip() -> Optional[str]:
        """Determine the local IPv4 address."""

        try:
            with socket.socket(
                socket.AF_INET,
                socket.SOCK_DGRAM,
            ) as sock:
                sock.connect(
                    ("8.8.8.8", 80)
                )

                return sock.getsockname()[0]

        except OSError:
            return None

    @staticmethod
    def _detect_subnet_mask(
        local_ip: str,
    ) -> Optional[str]:
        """
        Find the subnet mask associated with the local IP.

        Uses Windows ipconfig output.
        """

        if platform.system().lower() != "windows":
            return None

        try:
            result = subprocess.run(
                ["ipconfig"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
                check=False,
            )
        except (
            FileNotFoundError,
            subprocess.SubprocessError,
        ):
            return None

        lines = result.stdout.splitlines()

        found_local_ip = False

        for line in lines:
            stripped = line.strip()

            if stripped.lower().startswith(
                "ipv4 address"
            ):
                if local_ip in stripped:
                    found_local_ip = True
                    continue

            if found_local_ip and (
                "subnet mask" in stripped.lower()
            ):
                if ":" not in stripped:
                    continue

                return stripped.split(
                    ":",
                    1,
                )[1].strip()

        return None


def format_discovery_results(
    results: list[DiscoveryResult],
) -> str:
    """
    Format discovery results as a terminal table.
    """

    lines: list[str] = []

    lines.append(
        "IP Address       MAC Address          "
        "Hostname                 Status     Response"
    )
    lines.append(
        "-" * 95
    )

    for device in results:
        mac = device.mac_address or "N/A"
        hostname = device.hostname or "N/A"

        response = (
            f"{device.response_time_ms:.2f} ms"
            if device.response_time_ms is not None
            else "N/A"
        )

        lines.append(
            f"{device.ip_address:<16}"
            f"{mac:<21}"
            f"{hostname:<25}"
            f"{device.status:<11}"
            f"{response}"
        )

    return "\n".join(lines)