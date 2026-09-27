"""
Tests for NETWATCH Phase 2 network discovery.
"""

import unittest

from discovery.arp_scanner import ARPScanner
from discovery.network_discovery import (
    NetworkDiscovery,
)


class TestARPScanner(unittest.TestCase):
    """Test ARP output parsing."""

    def setUp(self):
        self.scanner = ARPScanner()

    def test_parse_arp_output(self):
        sample_output = """
Interface: 192.168.1.10 --- 0x5
  Internet Address      Physical Address      Type
  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic
  192.168.1.20          11-22-33-44-55-66     dynamic
"""

        entries = self.scanner.parse_arp_output(
            sample_output
        )

        self.assertEqual(
            len(entries),
            2,
        )

        self.assertEqual(
            entries[0].ip_address,
            "192.168.1.1",
        )

        self.assertEqual(
            entries[0].mac_address,
            "AA:BB:CC:DD:EE:FF",
        )

        self.assertEqual(
            entries[1].ip_address,
            "192.168.1.20",
        )

    def test_invalid_arp_output(self):
        entries = self.scanner.parse_arp_output(
            "invalid arp data"
        )

        self.assertEqual(
            entries,
            [],
        )


class TestNetworkDiscovery(unittest.TestCase):
    """Test network discovery validation."""

    def test_valid_network(self):
        discovery = NetworkDiscovery()

        network = discovery._validate_network(
            "192.168.1.0/24"
        )

        self.assertEqual(
            str(network),
            "192.168.1.0/24",
        )

    def test_host_address_becomes_network(self):
        discovery = NetworkDiscovery()

        network = discovery._validate_network(
            "192.168.1.25/24"
        )

        self.assertEqual(
            str(network),
            "192.168.1.0/24",
        )

    def test_invalid_network(self):
        discovery = NetworkDiscovery()

        with self.assertRaises(ValueError):
            discovery._validate_network(
                "invalid-network"
            )

    def test_ipv6_rejected(self):
        discovery = NetworkDiscovery()

        with self.assertRaises(ValueError):
            discovery._validate_network(
                "2001:db8::/64"
            )


if __name__ == "__main__":
    unittest.main()