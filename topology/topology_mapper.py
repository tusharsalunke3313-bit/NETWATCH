"""
NETWATCH Network Topology Mapper.

Phase 9 - Network Topology Visualization

This module builds a safe, read-only network topology from discovered
network information and exports the topology as an image.

The topology model represents:

Internet
    |
Firewall
    |
Router
    |
    +--- discovered devices

No network modification or active network manipulation is performed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional

import matplotlib

# Use a non-interactive backend so image generation also works in
# automated tests and headless environments.
matplotlib.use("Agg")

import matplotlib.pyplot as plt
import networkx as nx


TOPOLOGY_NODE_TYPES = (
    "INTERNET",
    "FIREWALL",
    "ROUTER",
    "DEVICE",
)


@dataclass(frozen=True)
class TopologyNode:
    """Represents one node in the network topology."""

    node_id: str
    label: str
    node_type: str
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    status: Optional[str] = None

    def __post_init__(self) -> None:
        """Validate topology node fields."""
        if not self.node_id.strip():
            raise ValueError("node_id cannot be empty.")

        if not self.label.strip():
            raise ValueError("label cannot be empty.")

        if self.node_type not in TOPOLOGY_NODE_TYPES:
            raise ValueError(
                f"Unsupported node type: {self.node_type}. "
                f"Supported types: {', '.join(TOPOLOGY_NODE_TYPES)}"
            )

    def to_dict(self) -> dict[str, Optional[str]]:
        """Return a serializable representation of the node."""
        return {
            "node_id": self.node_id,
            "label": self.label,
            "node_type": self.node_type,
            "ip_address": self.ip_address,
            "hostname": self.hostname,
            "mac_address": self.mac_address,
            "status": self.status,
        }


@dataclass(frozen=True)
class TopologyEdge:
    """Represents a connection between two topology nodes."""

    source: str
    destination: str
    relationship: str = "CONNECTED"

    def __post_init__(self) -> None:
        """Validate topology edge fields."""
        if not self.source.strip():
            raise ValueError("Edge source cannot be empty.")

        if not self.destination.strip():
            raise ValueError("Edge destination cannot be empty.")

        if not self.relationship.strip():
            raise ValueError("Edge relationship cannot be empty.")

    def to_dict(self) -> dict[str, str]:
        """Return a serializable representation of the edge."""
        return {
            "source": self.source,
            "destination": self.destination,
            "relationship": self.relationship,
        }


@dataclass
class TopologyResult:
    """Contains the complete network topology."""

    graph: nx.Graph
    nodes: list[TopologyNode] = field(default_factory=list)
    edges: list[TopologyEdge] = field(default_factory=list)
    image_path: Optional[str] = None

    @property
    def node_count(self) -> int:
        """Return the number of topology nodes."""
        return len(self.nodes)

    @property
    def edge_count(self) -> int:
        """Return the number of topology edges."""
        return len(self.edges)

    @property
    def device_count(self) -> int:
        """Return the number of discovered device nodes."""
        return sum(
            1 for node in self.nodes if node.node_type == "DEVICE"
        )

    def to_dict(self) -> dict[str, Any]:
        """Return the topology as serializable dictionaries."""
        return {
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": [edge.to_dict() for edge in self.edges],
            "image_path": self.image_path,
        }


class TopologyMapper:
    """
    Build and export a network topology.

    The mapper does not perform network discovery itself. It consumes
    already discovered information supplied by another NETWATCH module.
    """

    INTERNET_ID = "internet"
    FIREWALL_ID = "firewall"
    ROUTER_ID = "router"

    def __init__(
        self,
        title: str = "NETWATCH Network Topology",
    ) -> None:
        self.title = title

    @staticmethod
    def _value(
        item: Any,
        *names: str,
        default: Any = None,
    ) -> Any:
        """
        Read a value from either a dictionary-like object or an object
        containing attributes.
        """
        if isinstance(item, Mapping):
            for name in names:
                if name in item:
                    return item[name]
            return default

        for name in names:
            if hasattr(item, name):
                return getattr(item, name)

        return default

    @staticmethod
    def _safe_text(value: Any, default: str = "") -> str:
        """Convert a value into safe display text."""
        if value is None:
            return default

        text = str(value).strip()
        return text if text else default

    def create_base_nodes(
        self,
        router_ip: Optional[str] = None,
        router_hostname: Optional[str] = None,
    ) -> list[TopologyNode]:
        """
        Create the standard Internet → Firewall → Router structure.
        """
        router_label = "Router"

        if router_hostname:
            router_label = f"Router\n{router_hostname}"

        if router_ip:
            router_label += f"\n{router_ip}"

        return [
            TopologyNode(
                node_id=self.INTERNET_ID,
                label="Internet",
                node_type="INTERNET",
            ),
            TopologyNode(
                node_id=self.FIREWALL_ID,
                label="Firewall",
                node_type="FIREWALL",
            ),
            TopologyNode(
                node_id=self.ROUTER_ID,
                label=router_label,
                node_type="ROUTER",
                ip_address=router_ip,
                hostname=router_hostname,
                status="UP",
            ),
        ]

    def _device_node(
        self,
        device: Any,
        index: int,
    ) -> TopologyNode:
        """Convert discovered device information into a topology node."""
        ip_address = self._safe_text(
            self._value(
                device,
                "ip_address",
                "ip",
                "address",
            )
        )

        hostname = self._safe_text(
            self._value(
                device,
                "hostname",
                "host",
                "name",
            )
        )

        mac_address = self._safe_text(
            self._value(
                device,
                "mac_address",
                "mac",
            )
        )

        status = self._safe_text(
            self._value(
                device,
                "status",
                "state",
            ),
            default="UNKNOWN",
        )

        if hostname:
            label = hostname
        elif ip_address:
            label = ip_address
        else:
            label = f"Device {index}"

        if ip_address and hostname:
            label = f"{hostname}\n{ip_address}"
        elif ip_address:
            label = ip_address

        return TopologyNode(
            node_id=f"device-{index}",
            label=label,
            node_type="DEVICE",
            ip_address=ip_address or None,
            hostname=hostname or None,
            mac_address=mac_address or None,
            status=status,
        )

    def build_topology(
        self,
        devices: Optional[Iterable[Any]] = None,
        router_ip: Optional[str] = None,
        router_hostname: Optional[str] = None,
    ) -> TopologyResult:
        """
        Build a topology from discovered devices.

        Parameters
        ----------
        devices:
            Iterable containing dictionaries or objects representing
            discovered devices.
        router_ip:
            Optional router IP address.
        router_hostname:
            Optional router hostname.
        """
        if devices is None:
            devices = []

        nodes = self.create_base_nodes(
            router_ip=router_ip,
            router_hostname=router_hostname,
        )

        edges = [
            TopologyEdge(
                source=self.INTERNET_ID,
                destination=self.FIREWALL_ID,
                relationship="PROTECTED_BY",
            ),
            TopologyEdge(
                source=self.FIREWALL_ID,
                destination=self.ROUTER_ID,
                relationship="ROUTES_TO",
            ),
        ]

        device_list = list(devices)

        for index, device in enumerate(device_list, start=1):
            node = self._device_node(device, index)
            nodes.append(node)

            edges.append(
                TopologyEdge(
                    source=self.ROUTER_ID,
                    destination=node.node_id,
                    relationship="CONNECTED",
                )
            )

        graph = nx.Graph()

        for node in nodes:
            graph.add_node(
                node.node_id,
                label=node.label,
                node_type=node.node_type,
                ip_address=node.ip_address,
                hostname=node.hostname,
                mac_address=node.mac_address,
                status=node.status,
            )

        for edge in edges:
            graph.add_edge(
                edge.source,
                edge.destination,
                relationship=edge.relationship,
            )

        return TopologyResult(
            graph=graph,
            nodes=nodes,
            edges=edges,
        )

    def build_sample_topology(self) -> TopologyResult:
        """
        Build deterministic sample topology data.

        This is used for demonstrations and automated tests when
        live discovery data is unavailable.
        """
        sample_devices = [
            {
                "ip_address": "192.168.0.101",
                "hostname": "Desktop-PC",
                "mac_address": "AA:BB:CC:DD:EE:01",
                "status": "UP",
            },
            {
                "ip_address": "192.168.0.103",
                "hostname": "Laptop",
                "mac_address": "AA:BB:CC:DD:EE:02",
                "status": "UP",
            },
            {
                "ip_address": "192.168.0.107",
                "hostname": "LAPTOP-MHTTMG21",
                "mac_address": "AA:BB:CC:DD:EE:03",
                "status": "UP",
            },
            {
                "ip_address": "192.168.0.120",
                "hostname": "Network-Server",
                "mac_address": "AA:BB:CC:DD:EE:04",
                "status": "UP",
            },
        ]

        return self.build_topology(
            devices=sample_devices,
            router_ip="192.168.0.1",
            router_hostname="Router",
        )

    def export_image(
        self,
        result: TopologyResult,
        output_path: str | Path,
        show: bool = False,
    ) -> Path:
        """
        Export the topology graph as a PNG image.

        Parameters
        ----------
        result:
            TopologyResult produced by build_topology().
        output_path:
            Destination PNG path.
        show:
            If True, display the generated figure. Defaults to False.
        """
        if not isinstance(result, TopologyResult):
            raise TypeError("result must be a TopologyResult instance.")

        if result.node_count == 0:
            raise ValueError("Cannot export an empty topology.")

        output = Path(output_path)

        if output.suffix.lower() != ".png":
            output = output.with_suffix(".png")

        output.parent.mkdir(parents=True, exist_ok=True)

        graph = result.graph

        positions = self._calculate_positions(result)

        node_colors = []
        node_sizes = []

        for node_id in graph.nodes:
            node_type = graph.nodes[node_id].get("node_type")

            if node_type == "INTERNET":
                node_colors.append("skyblue")
                node_sizes.append(2600)
            elif node_type == "FIREWALL":
                node_colors.append("lightcoral")
                node_sizes.append(2800)
            elif node_type == "ROUTER":
                node_colors.append("lightgreen")
                node_sizes.append(2800)
            else:
                node_colors.append("lightgray")
                node_sizes.append(2200)

        labels = {
            node_id: graph.nodes[node_id].get("label", node_id)
            for node_id in graph.nodes
        }

        figure = plt.figure(figsize=(13, 8))

        nx.draw_networkx_edges(
            graph,
            positions,
            width=2.0,
            alpha=0.75,
            arrows=False,
        )

        nx.draw_networkx_nodes(
            graph,
            positions,
            node_color=node_colors,
            node_size=node_sizes,
            node_shape="o",
            edgecolors="black",
            linewidths=1.5,
        )

        nx.draw_networkx_labels(
            graph,
            positions,
            labels=labels,
            font_size=9,
            font_weight="bold",
        )

        plt.title(self.title, fontsize=16, fontweight="bold")
        plt.axis("off")
        plt.tight_layout()

        figure.savefig(
            output,
            dpi=180,
            bbox_inches="tight",
        )

        if show:
            plt.show()

        plt.close(figure)

        result.image_path = str(output.resolve())

        return output

    @staticmethod
    def _calculate_positions(
        result: TopologyResult,
    ) -> dict[str, tuple[float, float]]:
        """Create a predictable hierarchical topology layout."""
        positions: dict[str, tuple[float, float]] = {}

        positions[TopologyMapper.INTERNET_ID] = (0.0, 3.0)
        positions[TopologyMapper.FIREWALL_ID] = (0.0, 2.0)
        positions[TopologyMapper.ROUTER_ID] = (0.0, 1.0)

        devices = [
            node
            for node in result.nodes
            if node.node_type == "DEVICE"
        ]

        if not devices:
            return positions

        spacing = 2.2
        center = (len(devices) - 1) / 2

        for index, device in enumerate(devices):
            x_position = (index - center) * spacing
            positions[device.node_id] = (x_position, 0.0)

        return positions

    def export_sample(
        self,
        output_path: str | Path,
    ) -> tuple[TopologyResult, Path]:
        """Build and export the deterministic sample topology."""
        result = self.build_sample_topology()
        path = self.export_image(
            result,
            output_path,
        )
        return result, path


def format_topology_results(
    result: TopologyResult,
) -> str:
    """Format topology information for terminal display."""
    if not isinstance(result, TopologyResult):
        raise TypeError("result must be a TopologyResult instance.")

    lines = [
        "",
        "NETWORK TOPOLOGY",
        "=" * 90,
        f"Nodes                 : {result.node_count}",
        f"Connections            : {result.edge_count}",
        f"Devices represented    : {result.device_count}",
        "",
        "TOPOLOGY STRUCTURE",
        "-" * 90,
        "Internet",
        "   |",
        "Firewall",
        "   |",
        "Router",
    ]

    device_nodes = [
        node
        for node in result.nodes
        if node.node_type == "DEVICE"
    ]

    for index, device in enumerate(device_nodes):
        prefix = "+---" if index < len(device_nodes) - 1 else "\\---"

        detail = device.label.replace("\n", " | ")

        if device.status:
            detail += f" | Status: {device.status}"

        lines.append(f"   {prefix} {detail}")

    lines.extend(
        [
            "",
            "NODES",
            "-" * 90,
            f"{'Type':<12} {'Label':<30} {'IP Address':<18} {'Status':<10}",
            "-" * 90,
        ]
    )

    for node in result.nodes:
        label = node.label.replace("\n", " | ")
        ip_address = node.ip_address or "-"
        status = node.status or "-"

        lines.append(
            f"{node.node_type:<12} "
            f"{label[:30]:<30} "
            f"{ip_address:<18} "
            f"{status:<10}"
        )

    if result.image_path:
        lines.extend(
            [
                "",
                f"Exported Image        : {result.image_path}",
            ]
        )

    return "\n".join(lines)


__all__ = [
    "TOPOLOGY_NODE_TYPES",
    "TopologyNode",
    "TopologyEdge",
    "TopologyResult",
    "TopologyMapper",
    "format_topology_results",
]