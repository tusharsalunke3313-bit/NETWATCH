"""
Unit tests for NETWATCH Phase 9 - Network Topology.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from topology.topology_mapper import (
    TOPOLOGY_NODE_TYPES,
    TopologyEdge,
    TopologyMapper,
    TopologyNode,
    TopologyResult,
    format_topology_results,
)


class TestTopologyNode(unittest.TestCase):
    """Test topology node validation and serialization."""

    def test_valid_node(self) -> None:
        node = TopologyNode(
            node_id="router",
            label="Router",
            node_type="ROUTER",
            ip_address="192.168.0.1",
            status="UP",
        )

        self.assertEqual(node.node_id, "router")
        self.assertEqual(node.node_type, "ROUTER")
        self.assertEqual(node.ip_address, "192.168.0.1")

    def test_invalid_node_type(self) -> None:
        with self.assertRaises(ValueError):
            TopologyNode(
                node_id="test",
                label="Test",
                node_type="UNKNOWN",
            )

    def test_empty_node_id(self) -> None:
        with self.assertRaises(ValueError):
            TopologyNode(
                node_id="",
                label="Test",
                node_type="DEVICE",
            )

    def test_empty_label(self) -> None:
        with self.assertRaises(ValueError):
            TopologyNode(
                node_id="test",
                label="",
                node_type="DEVICE",
            )

    def test_node_to_dict(self) -> None:
        node = TopologyNode(
            node_id="device-1",
            label="Laptop",
            node_type="DEVICE",
            ip_address="192.168.0.103",
        )

        data = node.to_dict()

        self.assertEqual(data["node_id"], "device-1")
        self.assertEqual(data["label"], "Laptop")
        self.assertEqual(data["node_type"], "DEVICE")
        self.assertEqual(data["ip_address"], "192.168.0.103")


class TestTopologyEdge(unittest.TestCase):
    """Test topology edge validation."""

    def test_valid_edge(self) -> None:
        edge = TopologyEdge(
            source="router",
            destination="device-1",
            relationship="CONNECTED",
        )

        self.assertEqual(edge.source, "router")
        self.assertEqual(edge.destination, "device-1")

    def test_empty_source(self) -> None:
        with self.assertRaises(ValueError):
            TopologyEdge(
                source="",
                destination="device-1",
            )

    def test_empty_destination(self) -> None:
        with self.assertRaises(ValueError):
            TopologyEdge(
                source="router",
                destination="",
            )

    def test_edge_to_dict(self) -> None:
        edge = TopologyEdge(
            source="router",
            destination="device-1",
            relationship="CONNECTED",
        )

        data = edge.to_dict()

        self.assertEqual(data["source"], "router")
        self.assertEqual(data["destination"], "device-1")
        self.assertEqual(data["relationship"], "CONNECTED")


class TestTopologyMapper(unittest.TestCase):
    """Test topology creation and export."""

    def setUp(self) -> None:
        self.mapper = TopologyMapper()

    def test_supported_node_types(self) -> None:
        self.assertIn("INTERNET", TOPOLOGY_NODE_TYPES)
        self.assertIn("FIREWALL", TOPOLOGY_NODE_TYPES)
        self.assertIn("ROUTER", TOPOLOGY_NODE_TYPES)
        self.assertIn("DEVICE", TOPOLOGY_NODE_TYPES)

    def test_base_topology(self) -> None:
        result = self.mapper.build_topology(
            devices=[],
            router_ip="192.168.0.1",
            router_hostname="Router",
        )

        self.assertIsInstance(result, TopologyResult)
        self.assertEqual(result.node_count, 3)
        self.assertEqual(result.edge_count, 2)
        self.assertEqual(result.device_count, 0)

        self.assertTrue(result.graph.has_node("internet"))
        self.assertTrue(result.graph.has_node("firewall"))
        self.assertTrue(result.graph.has_node("router"))

        self.assertTrue(
            result.graph.has_edge(
                "internet",
                "firewall",
            )
        )

        self.assertTrue(
            result.graph.has_edge(
                "firewall",
                "router",
            )
        )

    def test_sample_topology(self) -> None:
        result = self.mapper.build_sample_topology()

        self.assertEqual(result.node_count, 7)
        self.assertEqual(result.edge_count, 6)
        self.assertEqual(result.device_count, 4)

    def test_dictionary_devices(self) -> None:
        devices = [
            {
                "ip_address": "192.168.1.10",
                "hostname": "Desktop",
                "mac_address": "AA:BB:CC:DD:EE:01",
                "status": "UP",
            },
            {
                "ip_address": "192.168.1.20",
                "hostname": "Server",
                "mac_address": "AA:BB:CC:DD:EE:02",
                "status": "UP",
            },
        ]

        result = self.mapper.build_topology(
            devices=devices,
            router_ip="192.168.1.1",
        )

        self.assertEqual(result.device_count, 2)
        self.assertTrue(result.graph.has_node("device-1"))
        self.assertTrue(result.graph.has_node("device-2"))

        self.assertTrue(
            result.graph.has_edge(
                "router",
                "device-1",
            )
        )

        self.assertTrue(
            result.graph.has_edge(
                "router",
                "device-2",
            )
        )

    def test_object_devices(self) -> None:
        class Device:
            ip_address = "192.168.1.50"
            hostname = "Test-PC"
            mac_address = "AA:AA:AA:AA:AA:50"
            status = "UP"

        result = self.mapper.build_topology(
            devices=[Device()],
            router_ip="192.168.1.1",
        )

        self.assertEqual(result.device_count, 1)

        device = result.nodes[-1]

        self.assertEqual(
            device.ip_address,
            "192.168.1.50",
        )

        self.assertEqual(
            device.hostname,
            "Test-PC",
        )

    def test_missing_device_values(self) -> None:
        devices = [
            {},
            {"ip": "192.168.1.30"},
        ]

        result = self.mapper.build_topology(
            devices=devices,
        )

        self.assertEqual(result.device_count, 2)

    def test_empty_devices(self) -> None:
        result = self.mapper.build_topology()

        self.assertEqual(result.device_count, 0)
        self.assertEqual(result.node_count, 3)

    def test_graph_node_metadata(self) -> None:
        result = self.mapper.build_sample_topology()

        router_data = result.graph.nodes["router"]

        self.assertEqual(
            router_data["node_type"],
            "ROUTER",
        )

        self.assertEqual(
            router_data["ip_address"],
            "192.168.0.1",
        )

    def test_graph_edge_metadata(self) -> None:
        result = self.mapper.build_sample_topology()

        edge_data = result.graph.edges[
            "router",
            "device-1",
        ]

        self.assertEqual(
            edge_data["relationship"],
            "CONNECTED",
        )

    def test_export_png(self) -> None:
        result = self.mapper.build_sample_topology()

        with tempfile.TemporaryDirectory() as temp_dir:
            output = (
                Path(temp_dir)
                / "network_topology.png"
            )

            exported = self.mapper.export_image(
                result,
                output,
            )

            self.assertTrue(exported.exists())
            self.assertEqual(
                exported.suffix.lower(),
                ".png",
            )
            self.assertGreater(
                exported.stat().st_size,
                0,
            )
            self.assertEqual(
                result.image_path,
                str(exported.resolve()),
            )

    def test_export_adds_png_extension(self) -> None:
        result = self.mapper.build_sample_topology()

        with tempfile.TemporaryDirectory() as temp_dir:
            output = (
                Path(temp_dir)
                / "network_topology"
            )

            exported = self.mapper.export_image(
                result,
                output,
            )

            self.assertTrue(exported.exists())
            self.assertEqual(
                exported.suffix.lower(),
                ".png",
            )

    def test_export_invalid_result(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "invalid.png"

            with self.assertRaises(TypeError):
                self.mapper.export_image(
                    "invalid",
                    output,
                )

    def test_export_empty_topology(self) -> None:
        empty_graph = __import__(
            "networkx"
        ).Graph()

        result = TopologyResult(
            graph=empty_graph,
            nodes=[],
            edges=[],
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "empty.png"

            with self.assertRaises(ValueError):
                self.mapper.export_image(
                    result,
                    output,
                )

    def test_export_sample(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = (
                Path(temp_dir)
                / "sample_topology.png"
            )

            result, exported = (
                self.mapper.export_sample(output)
            )

            self.assertEqual(
                result.device_count,
                4,
            )

            self.assertTrue(exported.exists())

    def test_format_topology(self) -> None:
        result = self.mapper.build_sample_topology()

        formatted = format_topology_results(
            result
        )

        self.assertIn(
            "NETWORK TOPOLOGY",
            formatted,
        )

        self.assertIn(
            "Internet",
            formatted,
        )

        self.assertIn(
            "Firewall",
            formatted,
        )

        self.assertIn(
            "Router",
            formatted,
        )

        self.assertIn(
            "Desktop-PC",
            formatted,
        )

        self.assertIn(
            "LAPTOP-MHTTMG21",
            formatted,
        )

    def test_invalid_formatter_input(self) -> None:
        with self.assertRaises(TypeError):
            format_topology_results("invalid")


if __name__ == "__main__":
    unittest.main()