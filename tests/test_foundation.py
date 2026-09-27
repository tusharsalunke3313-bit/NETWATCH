"""
Tests for NETWATCH Phase 1 foundation.
"""

import unittest
from datetime import datetime

from core.models import (
    DeviceStatus,
    NetworkDevice,
    PortResult,
    PortState,
    SecurityAlert,
    Severity,
)

from core.utils import (
    generate_id,
    validate_ip_address,
    validate_network,
)


class TestUtilities(unittest.TestCase):
    """Test shared utility functions."""

    def test_valid_ipv4(self):
        self.assertTrue(
            validate_ip_address("192.168.1.1")
        )

    def test_valid_ipv6(self):
        self.assertTrue(
            validate_ip_address("2001:db8::1")
        )

    def test_invalid_ip(self):
        self.assertFalse(
            validate_ip_address(
                "999.999.999.999"
            )
        )

    def test_valid_network(self):
        self.assertTrue(
            validate_network(
                "192.168.1.0/24"
            )
        )

    def test_invalid_network(self):
        self.assertFalse(
            validate_network(
                "192.168.1.0/999"
            )
        )

    def test_generate_id(self):
        generated_id = generate_id("TEST")

        self.assertTrue(
            generated_id.startswith("TEST-")
        )


class TestModels(unittest.TestCase):
    """Test NETWATCH data models."""

    def test_network_device(self):
        device = NetworkDevice(
            ip_address="192.168.1.10",
            hostname="test-device",
            status=DeviceStatus.UP,
        )

        self.assertEqual(
            device.ip_address,
            "192.168.1.10",
        )

        self.assertEqual(
            device.status,
            DeviceStatus.UP,
        )

    def test_port_result(self):
        port = PortResult(
            port=443,
            state=PortState.OPEN,
            service="HTTPS",
        )

        self.assertEqual(
            port.port,
            443,
        )

        self.assertEqual(
            port.state,
            PortState.OPEN,
        )

        self.assertEqual(
            port.service,
            "HTTPS",
        )

    def test_security_alert(self):
        alert = SecurityAlert(
            alert_id="ALERT-001",
            timestamp=datetime.now(),
            source="192.168.1.10",
            detection_type="TEST",
            description="Test alert",
            severity=Severity.LOW,
        )

        self.assertEqual(
            alert.severity,
            Severity.LOW,
        )


if __name__ == "__main__":
    unittest.main()