import unittest

from traffic_analysis.traffic_analyzer import (
    SCAPY_AVAILABLE,
    TrafficAnalyzer,
    TrafficAnalysisResult,
    TrafficCaptureError,
    PacketSummary,
    format_traffic_results,
)


class TestTrafficValidation(unittest.TestCase):

    def test_valid_capture_duration(self):
        self.assertEqual(
            TrafficAnalyzer.validate_capture_duration(10),
            10.0,
        )

    def test_zero_duration_rejected(self):
        with self.assertRaises(ValueError):
            TrafficAnalyzer.validate_capture_duration(0)

    def test_negative_duration_rejected(self):
        with self.assertRaises(ValueError):
            TrafficAnalyzer.validate_capture_duration(-1)

    def test_excessive_duration_rejected(self):
        with self.assertRaises(ValueError):
            TrafficAnalyzer.validate_capture_duration(301)

    def test_invalid_duration_rejected(self):
        with self.assertRaises(ValueError):
            TrafficAnalyzer.validate_capture_duration("abc")

    def test_valid_packet_count(self):
        self.assertEqual(
            TrafficAnalyzer.validate_packet_count(100),
            100,
        )

    def test_zero_packet_count_rejected(self):
        with self.assertRaises(ValueError):
            TrafficAnalyzer.validate_packet_count(0)

    def test_negative_packet_count_rejected(self):
        with self.assertRaises(ValueError):
            TrafficAnalyzer.validate_packet_count(-10)

    def test_excessive_packet_count_rejected(self):
        with self.assertRaises(ValueError):
            TrafficAnalyzer.validate_packet_count(100001)


class TestTrafficResult(unittest.TestCase):

    def test_default_result(self):
        result = TrafficAnalysisResult()

        self.assertEqual(result.packets_analyzed, 0)
        self.assertEqual(result.total_bytes, 0)
        self.assertEqual(result.tcp_packets, 0)
        self.assertEqual(result.udp_packets, 0)
        self.assertEqual(result.icmp_packets, 0)

    def test_packet_summary(self):
        packet = PacketSummary(
            source_ip="192.168.1.10",
            destination_ip="192.168.1.1",
            source_port=50000,
            destination_port=443,
            transport_protocol="TCP",
            application_protocol="HTTPS",
            packet_length=1500,
        )

        self.assertEqual(
            packet.source_ip,
            "192.168.1.10",
        )

        self.assertEqual(
            packet.destination_port,
            443,
        )

        self.assertEqual(
            packet.application_protocol,
            "HTTPS",
        )


class TestSampleTraffic(unittest.TestCase):

    def test_sample_result(self):
        result = TrafficAnalyzer.create_sample_result()

        self.assertEqual(
            result.capture_source,
            "sample",
        )

        self.assertGreater(
            result.packets_analyzed,
            0,
        )

    def test_sample_protocols(self):
        result = TrafficAnalyzer.create_sample_result()

        self.assertGreater(result.tcp_packets, 0)
        self.assertGreater(result.udp_packets, 0)
        self.assertGreater(result.icmp_packets, 0)

        self.assertGreater(result.dns_packets, 0)
        self.assertGreater(result.http_packets, 0)
        self.assertGreater(result.https_packets, 0)

    def test_sample_top_talkers(self):
        result = TrafficAnalyzer.create_sample_result()

        self.assertIn(
            "192.168.0.103",
            result.source_packet_counts,
        )

    def test_sample_bytes(self):
        result = TrafficAnalyzer.create_sample_result()

        self.assertGreater(
            result.total_bytes,
            0,
        )


class TestTrafficFormatting(unittest.TestCase):

    def test_format_sample_result(self):
        result = TrafficAnalyzer.create_sample_result()

        output = format_traffic_results(result)

        self.assertIn(
            "NETWORK TRAFFIC",
            output,
        )

        self.assertIn(
            "PROTOCOL DISTRIBUTION",
            output,
        )

        self.assertIn(
            "TOP TALKERS",
            output,
        )

        self.assertIn(
            "192.168.0.103",
            output,
        )

        self.assertIn(
            "HTTPS",
            output,
        )

    def test_format_empty_result(self):
        result = TrafficAnalysisResult()

        output = format_traffic_results(result)

        self.assertIn(
            "No source IP traffic observed.",
            output,
        )

        self.assertIn(
            "No destination IP traffic observed.",
            output,
        )

    def test_invalid_result_type(self):
        with self.assertRaises(TypeError):
            format_traffic_results(None)

    def test_invalid_top_talkers(self):
        result = TrafficAnalysisResult()

        with self.assertRaises(ValueError):
            format_traffic_results(
                result,
                top_talkers=0,
            )


class TestTrafficAnalyzerConfiguration(unittest.TestCase):

    def test_empty_interface_becomes_none(self):
        analyzer = TrafficAnalyzer("   ")

        self.assertIsNone(
            analyzer.interface
        )

    def test_interface_is_preserved(self):
        analyzer = TrafficAnalyzer(
            "Ethernet"
        )

        self.assertEqual(
            analyzer.interface,
            "Ethernet",
        )


class TestTrafficCaptureAvailability(unittest.TestCase):

    def test_capture_requires_scapy_when_unavailable(self):
        analyzer = TrafficAnalyzer()

        if not SCAPY_AVAILABLE:
            with self.assertRaises(TrafficCaptureError):
                analyzer.capture_live(
                    duration=1,
                    packet_count=1,
                )


if __name__ == "__main__":
    unittest.main()