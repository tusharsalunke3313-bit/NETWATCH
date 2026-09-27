"""
NETWATCH shared utility functions.
"""

import ipaddress
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def validate_ip_address(value: str) -> bool:
    """
    Validate an IPv4 or IPv6 address.
    """

    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def validate_network(value: str) -> bool:
    """
    Validate an IPv4 or IPv6 network in CIDR notation.
    """

    try:
        ipaddress.ip_network(value.strip(), strict=False)
        return True
    except ValueError:
        return False


def generate_id(prefix: str = "NET") -> str:
    """
    Generate a unique identifier.
    """

    unique_part = uuid.uuid4().hex[:12].upper()

    return f"{prefix}-{unique_part}"


def utc_timestamp() -> datetime:
    """
    Return the current UTC timestamp.
    """

    return datetime.now(timezone.utc)


def ensure_directory(path: str | Path) -> Path:
    """
    Create a directory if it does not already exist.
    """

    directory = Path(path)

    directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    return directory


def format_timestamp(
    timestamp: Optional[datetime] = None,
) -> str:
    """
    Format a datetime for human-readable output.
    """

    if timestamp is None:
        timestamp = utc_timestamp()

    return timestamp.strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )