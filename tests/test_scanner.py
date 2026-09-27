"""
Tests for NETWATCH Phase 3 port and service scanning.
"""

import unittest
from unittest.mock import patch

from scanning.port_scanner import (
    PortScanner,
    count_open_ports,
    format_port_results,
    parse_port_range,
)
from scanning.service_detector import (
    ServiceDetector,
)


class TestServiceDetector(unittest.TestCase):
    """Test service identification."""

    def test_known_service(self):
        service = ServiceDetector.identify(
            22
        )

        self.assertEqual(
            service,
            "SSH",
        )

    def test_https_service(self):
        service = ServiceDetector.identify(
            443
        )

        self.assertEqual(
            service,
            "HTTPS",
        )

    def test_unknown_service(self):
        with patch(
            "socket.getservbyport",
            side_effect=OSError,
        ):
            service = ServiceDetector.identify(
                55555
            )

        self.assertEqual(
            service,
            "UNKNOWN",
        )


class TestPortRange(unittest.TestCase):
    """Test port range validation."""

    def test_valid_range(self):
        ports = parse_port_range(
            80,
            83,
        )

        self.assertEqual(
            ports,
            [80, 81, 82, 83],
        )

    def test_single_port(self):
        ports = parse_port_range(
            443,
            443,
        )

        self.assertEqual(
            ports,
            [443],
        )

    def test_invalid_start_port(self):
        with self.assertRaises(ValueError):
            parse_port_range(
                0,
                80,
            )

    def test_invalid_end_port(self):
        with self.assertRaises(ValueError):
            parse_port_range(
                80,
                70000,
            )

    def test_reversed_range(self):
        with self.assertRaises(ValueError):
            parse_port_range(
                100,
                80,
            )


class TestPortScanner(unittest.TestCase):
    """Test TCP port scanner validation and results."""

    def test_valid_ipv4_target(self):
        scanner = PortScanner()

        result = scanner.resolve_target(
            "127.0.0.1"
        )

        self.assertEqual(
            result,
            "127.0.0.1",
        )

    def test_invalid_target(self):
        scanner = PortScanner()

        with self.assertRaises(ValueError):
            scanner.resolve_target(
                "not-a-real-target.invalid"
            )

    def test_ipv6_target_rejected(self):
        scanner = PortScanner()

        with self.assertRaises(ValueError):
            scanner.resolve_target(
                "::1"
            )

    def test_validate_ports(self):
        ports = PortScanner.validate_ports(
            [80, 22, 80, 443]
        )

        self.assertEqual(
            ports,
            [22, 80, 443],
        )

    def test_invalid_port(self):
        with self.assertRaises(ValueError):
            PortScanner.validate_ports(
                [80, 70000]
            )

    def test_empty_ports(self):
        with self.assertRaises(ValueError):
            PortScanner.validate_ports(
                []
            )

    def test_scanner_configuration(self):
        scanner = PortScanner(
            timeout=0.5,
            max_workers=10,
            submission_delay=0,
        )

        self.assertEqual(
            scanner.timeout,
            0.5,
        )

        self.assertEqual(
            scanner.max_workers,
            10,
        )

    def test_open_port_result(self):
        scanner = PortScanner(
            timeout=0.5,
            max_workers=1,
            submission_delay=0,
        )

        result = scanner.scan_port(
            "127.0.0.1",
            1,
        )

        self.assertIn(
            result.state,
            {
                "OPEN",
                "CLOSED",
                "FILTERED/UNREACHABLE",
            },
        )

        self.assertEqual(
            result.port,
            1,
        )

    def test_count_open_ports(self):
        results = [
            scanner_result(22, "OPEN", "SSH"),
            scanner_result(80, "OPEN", "HTTP"),
            scanner_result(443, "CLOSED", "HTTPS"),
        ]

        self.assertEqual(
            count_open_ports(results),
            2,
        )

    def test_format_results(self):
        results = [
            scanner_result(
                22,
                "OPEN",
                "SSH",
            ),
        ]

        output = format_port_results(
            results
        )

        self.assertIn(
            "22",
            output,
        )

        self.assertIn(
            "OPEN",
            output,
        )

        self.assertIn(
            "SSH",
            output,
        )


def scanner_result(
    port: int,
    state: str,
    service: str,
):
    """Create a deterministic test result."""

    from scanning.port_scanner import PortScanResult

    return PortScanResult(
        port=port,
        state=state,
        service=service,
        response_time_ms=1.0,
    )


if __name__ == "__main__":
    unittest.main()