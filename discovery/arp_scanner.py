"""
NETWATCH ARP Scanner.

Provides Windows-based ARP table collection and parsing.
"""

import re
import subprocess
from dataclasses import dataclass
from typing import Optional


@dataclass
class ARPEntry:
    """Represents an entry discovered from the ARP table."""

    ip_address: str
    mac_address: str
    interface: Optional[str] = None


class ARPScanner:
    """
    Collect and parse ARP table information.

    This module reads the local operating system ARP table.
    It does not generate arbitrary ARP packets.
    """

    MAC_PATTERN = re.compile(
        r"(?P<mac>[0-9a-fA-F]{2}"
        r"[-:][0-9a-fA-F]{2}"
        r"[-:][0-9a-fA-F]{2}"
        r"[-:][0-9a-fA-F]{2}"
        r"[-:][0-9a-fA-F]{2}"
        r"[-:][0-9a-fA-F]{2})"
    )

    IP_PATTERN = re.compile(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    )

    def get_arp_table(self) -> list[ARPEntry]:
        """
        Retrieve and parse the Windows ARP table.

        Returns:
            List of ARP entries.
        """

        try:
            result = subprocess.run(
                ["arp", "-a"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
                check=False,
            )
        except (FileNotFoundError, subprocess.SubprocessError):
            return []

        if result.returncode != 0:
            return []

        return self.parse_arp_output(result.stdout)

    def parse_arp_output(
        self,
        output: str,
    ) -> list[ARPEntry]:
        """
        Parse output from Windows 'arp -a'.

        Args:
            output: Raw command output.

        Returns:
            Parsed ARP entries.
        """

        entries: list[ARPEntry] = []
        current_interface: Optional[str] = None

        for line in output.splitlines():
            stripped = line.strip()

            interface_match = self.IP_PATTERN.search(
                stripped
            )

            if (
                stripped.lower().startswith("interface:")
                and interface_match
            ):
                current_interface = interface_match.group()
                continue

            parts = stripped.split()

            if len(parts) < 2:
                continue

            ip_address = parts[0]
            mac_address = parts[1]

            if not self._is_valid_ipv4(ip_address):
                continue

            if not self._is_valid_mac(mac_address):
                continue

            normalized_mac = mac_address.replace(
                "-",
                ":",
            ).upper()

            entries.append(
                ARPEntry(
                    ip_address=ip_address,
                    mac_address=normalized_mac,
                    interface=current_interface,
                )
            )

        return entries

    @staticmethod
    def _is_valid_ipv4(value: str) -> bool:
        """Validate a basic IPv4 address."""

        parts = value.split(".")

        if len(parts) != 4:
            return False

        try:
            return all(
                0 <= int(part) <= 255
                for part in parts
            )
        except ValueError:
            return False

    @classmethod
    def _is_valid_mac(cls, value: str) -> bool:
        """Validate a MAC address."""

        return bool(cls.MAC_PATTERN.fullmatch(value))