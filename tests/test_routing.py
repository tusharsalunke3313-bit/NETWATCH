"""
Tests for the NETWATCH routing simulator.

Phase 10 - Routing Simulator / Educational Module
"""

import unittest

from routing.routing_simulator import (
    ROUTING_PROTOCOLS,
    Route,
    RoutingSimulationResult,
    RoutingSimulator,
    RoutingTable,
    format_all_simulations,
    format_routing_table,
    format_simulation_result,
)


class TestRoute(unittest.TestCase):
    """Test Route validation and serialization."""

    def test_valid_route(self) -> None:
        route = Route(
            prefix="192.168.1.0/24",
            next_hop="10.0.0.1",
            metric=2,
            protocol="RIP",
            administrative_distance=120,
        )

        self.assertEqual(
            route.network.prefixlen,
            24,
        )

        data = route.to_dict()

        self.assertEqual(
            data["prefix"],
            "192.168.1.0/24",
        )

    def test_invalid_prefix(self) -> None:
        with self.assertRaises(ValueError):
            Route(
                prefix="invalid",
                next_hop="10.0.0.1",
                metric=1,
                protocol="RIP",
                administrative_distance=120,
            )

    def test_empty_next_hop(self) -> None:
        with self.assertRaises(ValueError):
            Route(
                prefix="192.168.1.0/24",
                next_hop="",
                metric=1,
                protocol="RIP",
                administrative_distance=120,
            )

    def test_negative_metric(self) -> None:
        with self.assertRaises(ValueError):
            Route(
                prefix="192.168.1.0/24",
                next_hop="10.0.0.1",
                metric=-1,
                protocol="RIP",
                administrative_distance=120,
            )

    def test_invalid_protocol(self) -> None:
        with self.assertRaises(ValueError):
            Route(
                prefix="192.168.1.0/24",
                next_hop="10.0.0.1",
                metric=1,
                protocol="INVALID",
                administrative_distance=120,
            )


class TestRoutingTable(unittest.TestCase):
    """Test routing table behavior."""

    def setUp(self) -> None:
        self.table = RoutingTable(
            router_name="TEST-ROUTER"
        )

    def test_add_route(self) -> None:
        route = Route(
            prefix="192.168.1.0/24",
            next_hop="10.0.0.1",
            metric=1,
            protocol="RIP",
            administrative_distance=120,
        )

        self.table.add_route(route)

        self.assertEqual(
            len(self.table.routes),
            1,
        )

    def test_reject_invalid_route(self) -> None:
        with self.assertRaises(TypeError):
            self.table.add_route("invalid")  # type: ignore[arg-type]

    def test_protocol_filter(self) -> None:
        self.table.add_route(
            Route(
                prefix="192.168.1.0/24",
                next_hop="10.0.0.1",
                metric=1,
                protocol="RIP",
                administrative_distance=120,
            )
        )

        self.table.add_route(
            Route(
                prefix="192.168.2.0/24",
                next_hop="10.0.0.2",
                metric=10,
                protocol="OSPF",
                administrative_distance=110,
            )
        )

        rip_routes = self.table.get_routes("RIP")

        self.assertEqual(
            len(rip_routes),
            1,
        )

        self.assertEqual(
            rip_routes[0].protocol,
            "RIP",
        )

    def test_invalid_protocol_filter(self) -> None:
        with self.assertRaises(ValueError):
            self.table.get_routes("INVALID")

    def test_lookup_longest_prefix(self) -> None:
        self.table.add_route(
            Route(
                prefix="10.0.0.0/8",
                next_hop="10.1.1.1",
                metric=10,
                protocol="RIP",
                administrative_distance=120,
            )
        )

        self.table.add_route(
            Route(
                prefix="10.10.0.0/16",
                next_hop="10.2.2.2",
                metric=20,
                protocol="RIP",
                administrative_distance=120,
            )
        )

        selected = self.table.lookup(
            "10.10.5.10"
        )

        self.assertIsNotNone(selected)

        self.assertEqual(
            selected.prefix,
            "10.10.0.0/16",
        )

    def test_lookup_returns_none_when_no_match(self) -> None:
        self.table.add_route(
            Route(
                prefix="192.168.1.0/24",
                next_hop="10.0.0.1",
                metric=1,
                protocol="RIP",
                administrative_distance=120,
            )
        )

        selected = self.table.lookup(
            "172.16.1.10"
        )

        self.assertIsNone(selected)

    def test_lookup_uses_administrative_distance(self) -> None:
        self.table.add_route(
            Route(
                prefix="192.168.1.0/24",
                next_hop="10.0.0.1",
                metric=5,
                protocol="RIP",
                administrative_distance=120,
            )
        )

        self.table.add_route(
            Route(
                prefix="192.168.1.0/24",
                next_hop="10.0.0.2",
                metric=50,
                protocol="OSPF",
                administrative_distance=110,
            )
        )

        selected = self.table.lookup(
            "192.168.1.50"
        )

        self.assertIsNotNone(selected)

        self.assertEqual(
            selected.next_hop,
            "10.0.0.2",
        )

    def test_lookup_uses_metric_after_administrative_distance(
        self,
    ) -> None:
        self.table.add_route(
            Route(
                prefix="192.168.1.0/24",
                next_hop="10.0.0.1",
                metric=20,
                protocol="OSPF",
                administrative_distance=110,
            )
        )

        self.table.add_route(
            Route(
                prefix="192.168.1.0/24",
                next_hop="10.0.0.2",
                metric=10,
                protocol="OSPF",
                administrative_distance=110,
            )
        )

        selected = self.table.lookup(
            "192.168.1.50"
        )

        self.assertIsNotNone(selected)

        self.assertEqual(
            selected.next_hop,
            "10.0.0.2",
        )


class TestRoutingSimulator(unittest.TestCase):
    """Test the educational routing simulations."""

    def setUp(self) -> None:
        self.simulator = RoutingSimulator()

    def test_supported_protocols(self) -> None:
        self.assertEqual(
            ROUTING_PROTOCOLS,
            ("RIP", "OSPF", "BGP"),
        )

    def test_create_rip_table(self) -> None:
        table = self.simulator.create_routing_table(
            "RIP"
        )

        self.assertEqual(
            len(table.routes),
            3,
        )

        self.assertTrue(
            all(
                route.protocol == "RIP"
                for route in table.routes
            )
        )

    def test_create_ospf_table(self) -> None:
        table = self.simulator.create_routing_table(
            "OSPF"
        )

        self.assertEqual(
            len(table.routes),
            3,
        )

        self.assertTrue(
            all(
                route.protocol == "OSPF"
                for route in table.routes
            )
        )

    def test_create_bgp_table(self) -> None:
        table = self.simulator.create_routing_table(
            "BGP"
        )

        self.assertEqual(
            len(table.routes),
            3,
        )

        self.assertTrue(
            all(
                route.protocol == "BGP"
                for route in table.routes
            )
        )

    def test_invalid_protocol(self) -> None:
        with self.assertRaises(ValueError):
            self.simulator.create_routing_table(
                "INVALID"
            )

    def test_rip_simulation(self) -> None:
        result = self.simulator.simulate_rip(
            "192.168.20.10"
        )

        self.assertIsInstance(
            result,
            RoutingSimulationResult,
        )

        self.assertEqual(
            result.protocol,
            "RIP",
        )

        self.assertEqual(
            result.route_count,
            3,
        )

        self.assertEqual(
            result.selected_routes[0].prefix,
            "192.168.20.0/24",
        )

        self.assertEqual(
            result.selected_routes[0].metric,
            2,
        )

    def test_ospf_simulation(self) -> None:
        result = self.simulator.simulate_ospf(
            "192.168.20.10"
        )

        self.assertEqual(
            result.protocol,
            "OSPF",
        )

        self.assertEqual(
            result.route_count,
            3,
        )

        self.assertEqual(
            result.selected_routes[0].prefix,
            "192.168.20.0/24",
        )

        self.assertEqual(
            result.selected_routes[0].metric,
            20,
        )

    def test_bgp_simulation(self) -> None:
        result = self.simulator.simulate_bgp(
            "10.10.20.10"
        )

        self.assertEqual(
            result.protocol,
            "BGP",
        )

        self.assertEqual(
            result.route_count,
            3,
        )

        self.assertEqual(
            result.selected_routes[0].prefix,
            "10.10.0.0/16",
        )

    def test_no_matching_rip_route(self) -> None:
        result = self.simulator.simulate_rip(
            "172.16.10.10"
        )

        self.assertEqual(
            result.selected_routes,
            [],
        )

        self.assertEqual(
            result.path,
            [],
        )

    def test_no_matching_ospf_route(self) -> None:
        result = self.simulator.simulate_ospf(
            "172.16.10.10"
        )

        self.assertEqual(
            result.selected_routes,
            [],
        )

    def test_no_matching_bgp_route(self) -> None:
        result = self.simulator.simulate_bgp(
            "192.168.1.10"
        )

        self.assertEqual(
            result.selected_routes,
            [],
        )

    def test_invalid_destination(self) -> None:
        with self.assertRaises(ValueError):
            self.simulator.select_best_route(
                self.simulator.create_routing_table("RIP"),
                "invalid",
            )

    def test_all_simulations(self) -> None:
        results = self.simulator.simulate_all()

        self.assertEqual(
            set(results.keys()),
            {"RIP", "OSPF", "BGP"},
        )

        self.assertEqual(
            results["RIP"].protocol,
            "RIP",
        )

        self.assertEqual(
            results["OSPF"].protocol,
            "OSPF",
        )

        self.assertEqual(
            results["BGP"].protocol,
            "BGP",
        )

    def test_result_serialization(self) -> None:
        result = self.simulator.simulate_rip()

        data = result.to_dict()

        self.assertEqual(
            data["protocol"],
            "RIP",
        )

        self.assertIn(
            "routing_table",
            data,
        )

        self.assertIn(
            "educational_notes",
            data,
        )

    def test_routing_table_serialization(self) -> None:
        table = self.simulator.create_routing_table(
            "OSPF"
        )

        data = table.to_dict()

        self.assertEqual(
            data["router_name"],
            "NETWATCH-OSPF-ROUTER",
        )

        self.assertEqual(
            len(data["routes"]),
            3,
        )


class TestRoutingFormatting(unittest.TestCase):
    """Test terminal formatting."""

    def setUp(self) -> None:
        self.simulator = RoutingSimulator()

    def test_format_routing_table(self) -> None:
        table = self.simulator.create_routing_table(
            "RIP"
        )

        output = format_routing_table(table)

        self.assertIn(
            "ROUTING TABLE",
            output,
        )

        self.assertIn(
            "192.168.10.0/24",
            output,
        )

        self.assertIn(
            "10.0.0.2",
            output,
        )

    def test_format_simulation_result(self) -> None:
        result = self.simulator.simulate_ospf()

        output = format_simulation_result(
            result
        )

        self.assertIn(
            "ROUTING SIMULATION",
            output,
        )

        self.assertIn(
            "OSPF",
            output,
        )

        self.assertIn(
            "EDUCATIONAL NOTES",
            output,
        )

        self.assertIn(
            "educational routing simulation",
            output.lower(),
        )

    def test_format_all_simulations(self) -> None:
        results = self.simulator.simulate_all()

        output = format_all_simulations(
            results
        )

        self.assertIn(
            "NETWATCH ROUTING SIMULATOR",
            output,
        )

        self.assertIn(
            "RIP",
            output,
        )

        self.assertIn(
            "OSPF",
            output,
        )

        self.assertIn(
            "BGP",
            output,
        )

        self.assertIn(
            "No real routing tables",
            output,
        )


if __name__ == "__main__":
    unittest.main()