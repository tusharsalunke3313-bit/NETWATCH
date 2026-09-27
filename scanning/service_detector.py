"""
NETWATCH Service Detector.

Provides lightweight service identification based on
standard TCP service mappings and common port conventions.

This module does not perform exploitation or authentication.
"""

import socket
from typing import Optional


class ServiceDetector:
    """
    Identify common TCP services.

    Identification is intentionally lightweight and safe.
    """

    COMMON_SERVICES = {
        20: "FTP-DATA",
        21: "FTP",
        22: "SSH",
        23: "TELNET",
        25: "SMTP",
        53: "DNS",
        67: "DHCP",
        80: "HTTP",
        110: "POP3",
        111: "RPCBIND",
        119: "NNTP",
        123: "NTP",
        135: "MSRPC",
        137: "NETBIOS-NS",
        138: "NETBIOS-DGM",
        139: "NETBIOS-SSN",
        143: "IMAP",
        161: "SNMP",
        389: "LDAP",
        443: "HTTPS",
        445: "SMB",
        465: "SMTPS",
        587: "SMTP-SUBMISSION",
        636: "LDAPS",
        993: "IMAPS",
        995: "POP3S",
        1433: "MSSQL",
        1521: "ORACLE",
        2049: "NFS",
        2375: "DOCKER",
        2376: "DOCKER-TLS",
        3000: "HTTP-ALT",
        3306: "MYSQL",
        3389: "RDP",
        5000: "HTTP-ALT",
        5432: "POSTGRESQL",
        5900: "VNC",
        6379: "REDIS",
        6443: "KUBERNETES-API",
        8080: "HTTP-PROXY",
        8443: "HTTPS-ALT",
        9200: "ELASTICSEARCH",
        27017: "MONGODB",
    }

    @classmethod
    def identify(
        cls,
        port: int,
        protocol: str = "tcp",
    ) -> str:
        """
        Identify a service for a port.

        Args:
            port: TCP port number.
            protocol: Network protocol.

        Returns:
            Service name or UNKNOWN.
        """

        if protocol.lower() != "tcp":
            return "UNKNOWN"

        known_service = cls.COMMON_SERVICES.get(port)

        if known_service:
            return known_service

        try:
            service = socket.getservbyport(
                port,
                protocol.lower(),
            )

            return service.upper()

        except OSError:
            return "UNKNOWN"

    @classmethod
    def is_common_service(
        cls,
        port: int,
    ) -> bool:
        """Return whether a port is in the common-service database."""

        return port in cls.COMMON_SERVICES

    @classmethod
    def get_description(
        cls,
        port: int,
    ) -> Optional[str]:
        """Return a short description for a known service."""

        descriptions = {
            21: "File Transfer Protocol",
            22: "Secure Shell",
            23: "Telnet",
            25: "Simple Mail Transfer Protocol",
            53: "Domain Name System",
            80: "Hypertext Transfer Protocol",
            110: "Post Office Protocol",
            143: "Internet Message Access Protocol",
            443: "HTTP over TLS",
            445: "Server Message Block",
            3306: "MySQL Database",
            3389: "Remote Desktop Protocol",
            5432: "PostgreSQL Database",
            5900: "Virtual Network Computing",
            6379: "Redis",
            8080: "Alternative HTTP",
            8443: "Alternative HTTPS",
            27017: "MongoDB Database",
        }

        return descriptions.get(port)