"""
NETWATCH Routing Simulator.

Phase 10 - Routing Simulator / Educational Module

This module provides simplified educational simulations of:
- RIP
- OSPF
- BGP

The simulator demonstrates routing tables, network prefixes,
next hops, route selection, hop count, administrative concepts,
and best-path selection.

IMPORTANT:
This is an educational simulation. It is not a production
routing implementation and does not configure real routers.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Optional


ROUTING_PROTOCOLS = ("RIP", "OSPF", "BGP")


@dataclass(frozen=True)
class Route:
    """Represent a simulated network route."""

    prefix: str
    next_hop: str
    metric: float
    protocol: str
    administrative_distance: int
    interface: str = "N/A"
    description: str = ""

    def __post_init__(self) -> None:
        """Validate route information."""

        try:
            ipaddress.ip_network(
                self.prefix,
                strict=False,
            )
        except ValueError as exc:
            raise ValueError(
                f"Invalid network prefix: {self.prefix}"
            ) from exc

        if not self.next_hop:
            raise ValueError(
                "Next hop cannot be empty."
            )

        if self.metric < 0:
            raise ValueError(
                "Route metric cannot be negative."
            )

        protocol = self.protocol.upper()

        if protocol not in ROUTING_PROTOCOLS:
            raise ValueError(
                f"Unsupported routing protocol: {self.protocol}"
            )

        if self.administrative_distance < 0:
            raise ValueError(
                "Administrative distance cannot be negative."
            )

    @property
    def network(self) -> ipaddress.IPv4Network:
        """Return the route prefix as an IPv4 network."""

        network = ipaddress.ip_network(
            self.prefix,
            strict=False,
        )

        if network.version != 4:
            raise ValueError(
                "The routing simulator currently supports IPv4 only."
            )

        return network

    def to_dict(self) -> dict[str, object]:
        """Convert the route to a dictionary."""

        return {
            "prefix": self.prefix,
            "next_hop": self.next_hop,
            "metric": self.metric,
            "protocol": self.protocol.upper(),
            "administrative_distance": (
                self.administrative_distance
            ),
            "interface": self.interface,
            "description": self.description,
        }


@dataclass
class RoutingTable:
    """Represent a simulated routing table."""

    router_name: str
    routes: list[Route] = field(default_factory=list)

    def add_route(self, route: Route) -> None:
        """Add a route to the routing table."""

        if not isinstance(route, Route):
            raise TypeError(
                "route must be a Route instance."
            )

        self.routes.append(route)

    def get_routes(
        self,
        protocol: Optional[str] = None,
    ) -> list[Route]:
        """Return routes, optionally filtered by protocol."""

        if protocol is None:
            return list(self.routes)

        normalized = protocol.upper()

        if normalized not in ROUTING_PROTOCOLS:
            raise ValueError(
                f"Unsupported routing protocol: {protocol}"
            )

        return [
            route
            for route in self.routes
            if route.protocol.upper() == normalized
        ]

    def lookup(
        self,
        destination_ip: str,
    ) -> Optional[Route]:
        """
        Find the best matching route for a destination IP.

        Longest-prefix matching is used first. If multiple routes
        match the same prefix length, administrative distance and
        metric are used as tie-breakers.
        """

        try:
            destination = ipaddress.ip_address(
                destination_ip
            )
        except ValueError as exc:
            raise ValueError(
                f"Invalid destination IP: {destination_ip}"
            ) from exc

        if destination.version != 4:
            raise ValueError(
                "The routing simulator currently supports IPv4 only."
            )

        matching_routes = [
            route
            for route in self.routes
            if destination in route.network
        ]

        if not matching_routes:
            return None

        return min(
            matching_routes,
            key=lambda route: (
                -route.network.prefixlen,
                route.administrative_distance,
                route.metric,
            ),
        )

    def to_dict(self) -> dict[str, object]:
        """Convert the routing table to a dictionary."""

        return {
            "router_name": self.router_name,
            "routes": [
                route.to_dict()
                for route in self.routes
            ],
        }


@dataclass
class RoutingSimulationResult:
    """Store the result of a routing protocol simulation."""

    protocol: str
    description: str
    routing_table: RoutingTable
    selected_routes: list[Route]
    educational_notes: list[str]
    path: list[str] = field(default_factory=list)

    @property
    def route_count(self) -> int:
        """Return the number of routes in the table."""

        return len(self.routing_table.routes)

    def to_dict(self) -> dict[str, object]:
        """Convert the result to a dictionary."""

        return {
            "protocol": self.protocol,
            "description": self.description,
            "routing_table": self.routing_table.to_dict(),
            "selected_routes": [
                route.to_dict()
                for route in self.selected_routes
            ],
            "educational_notes": list(
                self.educational_notes
            ),
            "path": list(self.path),
        }


class RoutingSimulator:
    """
    Educational routing simulator.

    The simulator models simplified routing concepts without
    modifying real operating-system routing tables.
    """

    RIP_ADMINISTRATIVE_DISTANCE = 120
    OSPF_ADMINISTRATIVE_DISTANCE = 110
    BGP_ADMINISTRATIVE_DISTANCE = 20

    def __init__(self) -> None:
        self._sample_routes = self._create_sample_routes()

    @staticmethod
    def _create_sample_routes() -> dict[str, list[Route]]:
        """Create deterministic sample routes."""

        return {
            "RIP": [
                Route(
                    prefix="192.168.10.0/24",
                    next_hop="10.0.0.2",
                    metric=1,
                    protocol="RIP",
                    administrative_distance=120,
                    interface="G0/0",
                    description="One-hop RIP route.",
                ),
                Route(
                    prefix="192.168.20.0/24",
                    next_hop="10.0.0.3",
                    metric=2,
                    protocol="RIP",
                    administrative_distance=120,
                    interface="G0/1",
                    description="Two-hop RIP route.",
                ),
                Route(
                    prefix="192.168.30.0/24",
                    next_hop="10.0.0.4",
                    metric=3,
                    protocol="RIP",
                    administrative_distance=120,
                    interface="G0/2",
                    description="Three-hop RIP route.",
                ),
            ],
            "OSPF": [
                Route(
                    prefix="192.168.10.0/24",
                    next_hop="10.0.0.2",
                    metric=10,
                    protocol="OSPF",
                    administrative_distance=110,
                    interface="G0/0",
                    description="Lowest-cost OSPF path.",
                ),
                Route(
                    prefix="192.168.20.0/24",
                    next_hop="10.0.0.3",
                    metric=20,
                    protocol="OSPF",
                    administrative_distance=110,
                    interface="G0/1",
                    description="Higher-cost OSPF path.",
                ),
                Route(
                    prefix="192.168.30.0/24",
                    next_hop="10.0.0.4",
                    metric=30,
                    protocol="OSPF",
                    administrative_distance=110,
                    interface="G0/2",
                    description="Higher-cost OSPF path.",
                ),
            ],
            "BGP": [
                Route(
                    prefix="10.10.0.0/16",
                    next_hop="203.0.113.1",
                    metric=100,
                    protocol="BGP",
                    administrative_distance=20,
                    interface="WAN0",
                    description="Simulated external BGP route.",
                ),
                Route(
                    prefix="10.20.0.0/16",
                    next_hop="203.0.113.2",
                    metric=200,
                    protocol="BGP",
                    administrative_distance=20,
                    interface="WAN1",
                    description="Alternative BGP route.",
                ),
                Route(
                    prefix="172.16.0.0/16",
                    next_hop="203.0.113.3",
                    metric=150,
                    protocol="BGP",
                    administrative_distance=20,
                    interface="WAN2",
                    description="Simulated BGP network.",
                ),
            ],
        }

    @staticmethod
    def _validate_protocol(protocol: str) -> str:
        """Validate and normalize a routing protocol."""

        if not isinstance(protocol, str):
            raise TypeError(
                "protocol must be a string."
            )

        normalized = protocol.strip().upper()

        if normalized not in ROUTING_PROTOCOLS:
            raise ValueError(
                f"Unsupported routing protocol: {protocol}. "
                f"Supported protocols: {', '.join(ROUTING_PROTOCOLS)}"
            )

        return normalized

    @staticmethod
    def _validate_destination(
        destination_ip: str,
    ) -> str:
        """Validate an IPv4 destination address."""

        try:
            address = ipaddress.ip_address(
                destination_ip.strip()
            )
        except (AttributeError, ValueError) as exc:
            raise ValueError(
                f"Invalid destination IP: {destination_ip}"
            ) from exc

        if address.version != 4:
            raise ValueError(
                "The routing simulator currently supports IPv4 only."
            )

        return str(address)

    def create_routing_table(
        self,
        protocol: str,
    ) -> RoutingTable:
        """
        Create a sample routing table for a protocol.

        This method does not modify the operating-system routing table.
        """

        normalized = self._validate_protocol(protocol)

        table = RoutingTable(
            router_name=f"NETWATCH-{normalized}-ROUTER"
        )

        for route in self._sample_routes[normalized]:
            table.add_route(route)

        return table

    def select_best_route(
        self,
        routing_table: RoutingTable,
        destination_ip: str,
    ) -> Optional[Route]:
        """
        Select the best route for a destination.

        The simplified selection process uses:
        1. Longest prefix match
        2. Administrative distance
        3. Protocol metric
        """

        if not isinstance(
            routing_table,
            RoutingTable,
        ):
            raise TypeError(
                "routing_table must be a RoutingTable."
            )

        destination = self._validate_destination(
            destination_ip
        )

        return routing_table.lookup(destination)

    def simulate_rip(
        self,
        destination_ip: str = "192.168.20.10",
    ) -> RoutingSimulationResult:
        """
        Run a simplified RIP simulation.

        RIP uses hop count as its primary routing metric.
        """

        table = self.create_routing_table("RIP")

        selected = self.select_best_route(
            table,
            destination_ip,
        )

        selected_routes = (
            [selected]
            if selected is not None
            else []
        )

        path = self._build_path(
            selected,
            destination_ip,
        )

        notes = [
            "RIP is a distance-vector routing protocol.",
            "The simplified simulation uses hop count as "
            "the routing metric.",
            "Lower hop count represents a preferred path "
            "when comparing RIP routes.",
            "The simulation does not exchange real RIP "
            "routing updates.",
        ]

        return RoutingSimulationResult(
            protocol="RIP",
            description=(
                "Simplified RIP distance-vector routing "
                "simulation."
            ),
            routing_table=table,
            selected_routes=selected_routes,
            educational_notes=notes,
            path=path,
        )

    def simulate_ospf(
        self,
        destination_ip: str = "192.168.20.10",
    ) -> RoutingSimulationResult:
        """
        Run a simplified OSPF simulation.

        OSPF uses a cost-based shortest-path concept.
        """

        table = self.create_routing_table("OSPF")

        selected = self.select_best_route(
            table,
            destination_ip,
        )

        selected_routes = (
            [selected]
            if selected is not None
            else []
        )

        path = self._build_path(
            selected,
            destination_ip,
        )

        notes = [
            "OSPF is a link-state routing protocol.",
            "The simplified simulation uses route cost "
            "to represent path preference.",
            "Lower cost represents a preferred path "
            "among comparable OSPF routes.",
            "OSPF normally uses a shortest-path calculation "
            "based on its link-state database.",
            "The simulation does not form real OSPF adjacencies.",
        ]

        return RoutingSimulationResult(
            protocol="OSPF",
            description=(
                "Simplified OSPF link-state shortest-path "
                "simulation."
            ),
            routing_table=table,
            selected_routes=selected_routes,
            educational_notes=notes,
            path=path,
        )

    def simulate_bgp(
        self,
        destination_ip: str = "10.10.20.10",
    ) -> RoutingSimulationResult:
        """
        Run a simplified BGP simulation.

        BGP is represented using simplified administrative
        and path-selection concepts.
        """

        table = self.create_routing_table("BGP")

        selected = self.select_best_route(
            table,
            destination_ip,
        )

        selected_routes = (
            [selected]
            if selected is not None
            else []
        )

        path = self._build_path(
            selected,
            destination_ip,
        )

        notes = [
            "BGP is a path-vector routing protocol.",
            "The simplified simulation represents external "
            "network route selection.",
            "Administrative distance is included as an "
            "educational routing concept.",
            "The route metric is simplified and does not "
            "represent the complete BGP decision process.",
            "The simulation does not establish real BGP sessions.",
        ]

        return RoutingSimulationResult(
            protocol="BGP",
            description=(
                "Simplified BGP path-vector routing "
                "simulation."
            ),
            routing_table=table,
            selected_routes=selected_routes,
            educational_notes=notes,
            path=path,
        )

    def simulate_all(
        self,
    ) -> dict[str, RoutingSimulationResult]:
        """Run all three educational simulations."""

        return {
            "RIP": self.simulate_rip(),
            "OSPF": self.simulate_ospf(),
            "BGP": self.simulate_bgp(),
        }

    def build_sample_routing_table(
        self,
    ) -> dict[str, RoutingSimulationResult]:
        """
        Build the complete sample routing simulation.

        This method is the main-menu integration entry point for
        the NETWATCH Routing Simulator.

        It intentionally delegates to simulate_all() so there is
        only one implementation of the routing simulation logic.

        No real operating-system routing table is changed.
        """

        return self.simulate_all()

    @staticmethod
    def _build_path(
        route: Optional[Route],
        destination_ip: str,
    ) -> list[str]:
        """Build a simple educational path representation."""

        if route is None:
            return []

        return [
            "LOCAL ROUTER",
            route.next_hop,
            destination_ip,
        ]


def format_routing_table(
    routing_table: RoutingTable,
) -> str:
    """Format a routing table for terminal display."""

    if not isinstance(
        routing_table,
        RoutingTable,
    ):
        raise TypeError(
            "routing_table must be a RoutingTable."
        )

    lines = [
        "ROUTING TABLE",
        "=" * 105,
        (
            f"Router: {routing_table.router_name}"
        ),
        "",
        (
            f"{'Protocol':<10}"
            f"{'Network Prefix':<20}"
            f"{'Next Hop':<18}"
            f"{'Metric':<10}"
            f"{'AD':<8}"
            f"{'Interface':<12}"
        ),
        "-" * 105,
    ]

    for route in routing_table.routes:
        lines.append(
            f"{route.protocol:<10}"
            f"{route.prefix:<20}"
            f"{route.next_hop:<18}"
            f"{route.metric:<10g}"
            f"{route.administrative_distance:<8}"
            f"{route.interface:<12}"
        )

    return "\n".join(lines)


def format_simulation_result(
    result: RoutingSimulationResult,
) -> str:
    """Format a complete routing simulation result."""

    if not isinstance(
        result,
        RoutingSimulationResult,
    ):
        raise TypeError(
            "result must be a RoutingSimulationResult."
        )

    lines = [
        "",
        "ROUTING SIMULATION",
        "=" * 90,
        f"Protocol              : {result.protocol}",
        f"Description           : {result.description}",
        f"Routes in table       : {result.route_count}",
        "",
        format_routing_table(
            result.routing_table
        ),
        "",
        "BEST ROUTE",
        "-" * 90,
    ]

    if result.selected_routes:
        route = result.selected_routes[0]

        lines.extend(
            [
                f"Network Prefix        : {route.prefix}",
                f"Next Hop              : {route.next_hop}",
                f"Metric                : {route.metric:g}",
                (
                    "Administrative Distance: "
                    f"{route.administrative_distance}"
                ),
                f"Interface             : {route.interface}",
                f"Path                  : {' -> '.join(result.path)}",
            ]
        )
    else:
        lines.append(
            "No matching route was found."
        )

    lines.extend(
        [
            "",
            "EDUCATIONAL NOTES",
            "-" * 90,
        ]
    )

    for index, note in enumerate(
        result.educational_notes,
        start=1,
    ):
        lines.append(
            f"{index}. {note}"
        )

    lines.extend(
        [
            "",
            "IMPORTANT",
            "-" * 90,
            (
                "This is an educational routing simulation. "
                "It does not configure or modify real routers."
            ),
        ]
    )

    return "\n".join(lines)


def format_all_simulations(
    results: dict[str, RoutingSimulationResult],
) -> str:
    """Format all routing protocol simulations."""

    if not isinstance(results, dict):
        raise TypeError(
            "results must be a dictionary."
        )

    sections = [
        "NETWATCH ROUTING SIMULATOR",
        "=" * 90,
        "Educational simulation of RIP, OSPF and BGP.",
        "No real routing tables or network devices are modified.",
    ]

    for protocol in ROUTING_PROTOCOLS:
        result = results.get(protocol)

        if result is None:
            continue

        sections.append(
            format_simulation_result(result)
        )

    return "\n".join(sections)


__all__ = [
    "ROUTING_PROTOCOLS",
    "Route",
    "RoutingTable",
    "RoutingSimulationResult",
    "RoutingSimulator",
    "format_routing_table",
    "format_simulation_result",
    "format_all_simulations",
]