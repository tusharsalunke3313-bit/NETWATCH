"""
Tests for the NETWATCH Phase 11 dashboard.
"""

import unittest
from pathlib import Path

from dashboard.app import create_app


class DashboardTests(unittest.TestCase):

    def setUp(self):
        self.sample_state = {
            "application": {
                "name": "NETWATCH",
                "version": "0.7.0",
            },
            "assessment": {
                "authorized_assessment_only": True,
                "network": "192.168.0.0/24",
            },
            "summary": {
                "devices_discovered": 2,
                "open_ports": 3,
                "network_alerts": 2,
                "high_severity_alerts": 1,
                "traffic_packets": 100,
                "traffic_bytes": 5000,
                "firewall_findings": 1,
            },
            "devices": [
                {
                    "ip": "192.168.0.1",
                    "hostname": "Router",
                    "mac": "AA:BB:CC:DD:EE:FF",
                    "status": "UP",
                    "response_time": 1.5,
                },
                {
                    "ip": "192.168.0.10",
                    "hostname": "Desktop",
                    "mac": "11:22:33:44:55:66",
                    "status": "UP",
                    "response_time": 2.1,
                },
            ],
            "ports": [
                {
                    "port": 22,
                    "state": "OPEN",
                    "service": "SSH",
                },
                {
                    "port": 80,
                    "state": "OPEN",
                    "service": "HTTP",
                },
            ],
            "alerts": [
                {
                    "alert_id": "ALT-001",
                    "timestamp": "2026-09-27 11:00:00",
                    "source": "192.168.0.10",
                    "destination": "192.168.0.1",
                    "type": "PORT_SCAN",
                    "severity": "HIGH",
                    "description": "Sample alert",
                    "evidence": "Sample evidence",
                    "recommended_action": "Review source",
                },
            ],
            "severity_counts": {
                "INFO": 0,
                "LOW": 0,
                "MEDIUM": 1,
                "HIGH": 1,
                "CRITICAL": 0,
            },
            "traffic": {
                "packet_count": 100,
                "total_bytes": 5000,
                "protocols": {
                    "TCP": 60,
                    "UDP": 25,
                    "DNS": 10,
                    "ICMP": 5,
                },
                "top_talkers": [],
            },
            "firewall_findings": [
                {
                    "finding_id": "FW-001",
                    "severity": "MEDIUM",
                    "title": "Broad access",
                    "recommendation": "Review rule",
                },
            ],
            "topology": {
                "available": True,
                "image_available": False,
                "nodes": 5,
                "connections": 4,
            },
        }

        self.app = create_app(
            state_provider=lambda: self.sample_state
        )

        self.app.config["TESTING"] = True

        self.client = self.app.test_client()

    def test_dashboard_page(self):
        response = self.client.get("/")

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertIn(
            b"NETWATCH",
            response.data,
        )

        self.assertIn(
            b"Network Devices",
            response.data,
        )

    def test_api_state(self):
        response = self.client.get(
            "/api/state"
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        data = response.get_json()

        self.assertEqual(
            data["summary"]["devices_discovered"],
            2,
        )

        self.assertEqual(
            data["summary"]["open_ports"],
            3,
        )

        self.assertEqual(
            len(data["alerts"]),
            1,
        )

    def test_api_contains_traffic(self):
        response = self.client.get(
            "/api/state"
        )

        data = response.get_json()

        self.assertEqual(
            data["traffic"]["packet_count"],
            100,
        )

        self.assertEqual(
            data["traffic"]["protocols"]["TCP"],
            60,
        )

    def test_api_contains_topology(self):
        response = self.client.get(
            "/api/state"
        )

        data = response.get_json()

        self.assertTrue(
            data["topology"]["available"]
        )

        self.assertEqual(
            data["topology"]["nodes"],
            5,
        )

    def test_api_contains_firewall_findings(self):
        response = self.client.get(
            "/api/state"
        )

        data = response.get_json()

        self.assertEqual(
            len(data["firewall_findings"]),
            1,
        )

    def test_missing_topology_image(self):
        topology_image = (
            Path("reports_output") /
            "network_topology.png"
        )

        backup_image = (
            Path("reports_output") /
            "network_topology_test_backup.png"
        )

        image_existed = topology_image.exists()

        try:
            if image_existed:
                topology_image.rename(backup_image)

            response = self.client.get(
                "/topology-image"
            )

            self.assertEqual(
                response.status_code,
                404,
            )

        finally:
            if image_existed and backup_image.exists():
                backup_image.rename(topology_image)


if __name__ == "__main__":
    unittest.main()