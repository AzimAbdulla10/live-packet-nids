import unittest
import time
from flow_tracker import FlowTracker

class TestFlowTracker(unittest.TestCase):
    def setUp(self):
        self.tracker = FlowTracker(idle_timeout=5.0, active_timeout=30.0, max_flows=100)

    def test_forward_packets_forming_flow(self):
        """1. Forward packets forming a flow."""
        pkt = {
            "src_ip": "192.168.1.10",
            "dst_ip": "10.0.0.1",
            "src_port": 50000,
            "dst_port": 80,
            "protocol": "TCP",
            "length": 64,
            "flags": "SYN",
            "timestamp": 1000.0
        }
        flow, expired = self.tracker.process_packet(pkt)
        self.assertIsNotNone(flow)
        self.assertEqual(len(expired), 0)
        self.assertEqual(flow.total_packets, 1)
        self.assertEqual(flow.fwd_packets, 1)
        self.assertEqual(flow.bwd_packets, 0)
        self.assertEqual(flow.initiator_ip, "192.168.1.10")
        self.assertEqual(flow.responder_ip, "10.0.0.1")
        self.assertEqual(flow.initiator_port, 50000)
        self.assertEqual(flow.responder_port, 80)

    def test_reverse_direction_packets_mapping_same_flow(self):
        """2. Reverse-direction packets mapping to the same flow."""
        p_fwd = {
            "src_ip": "192.168.1.10",
            "dst_ip": "10.0.0.1",
            "src_port": 50000,
            "dst_port": 80,
            "protocol": "TCP",
            "length": 60,
            "flags": "SYN",
            "timestamp": 1000.0
        }
        p_bwd = {
            "src_ip": "10.0.0.1",
            "dst_ip": "192.168.1.10",
            "src_port": 80,
            "dst_port": 50000,
            "protocol": "TCP",
            "length": 60,
            "flags": "SYN-ACK",
            "timestamp": 1000.05
        }
        flow1, _ = self.tracker.process_packet(p_fwd)
        flow2, _ = self.tracker.process_packet(p_bwd)

        self.assertIs(flow1, flow2, "Forward and backward packets must map to identical Flow instance")
        self.assertEqual(flow1.total_packets, 2)

    def test_forward_and_backward_packet_counts(self):
        """3. Correct forward and backward packet counts."""
        # 3 fwd packets, 2 bwd packets
        base_time = 2000.0
        for i in range(3):
            self.tracker.process_packet({
                "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2",
                "src_port": 1234, "dst_port": 80, "protocol": "TCP",
                "length": 100, "flags": "ACK", "timestamp": base_time + i
            })
        for i in range(2):
            self.tracker.process_packet({
                "src_ip": "2.2.2.2", "dst_ip": "1.1.1.1",
                "src_port": 80, "dst_port": 1234, "protocol": "TCP",
                "length": 200, "flags": "ACK", "timestamp": base_time + 3 + i
            })

        flow = self.tracker.get_flow({
            "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2",
            "src_port": 1234, "dst_port": 80, "protocol": "TCP"
        })
        self.assertIsNotNone(flow)
        self.assertEqual(flow.fwd_packets, 3)
        self.assertEqual(flow.bwd_packets, 2)
        self.assertEqual(flow.total_packets, 5)

    def test_directional_byte_counts(self):
        """4. Correct directional byte counts."""
        self.tracker.process_packet({
            "src_ip": "10.0.0.5", "dst_ip": "10.0.0.6",
            "src_port": 4000, "dst_port": 443, "protocol": "TCP",
            "length": 150, "timestamp": 3000.0
        })
        self.tracker.process_packet({
            "src_ip": "10.0.0.6", "dst_ip": "10.0.0.5",
            "src_port": 443, "dst_port": 4000, "protocol": "TCP",
            "length": 500, "timestamp": 3000.1
        })
        self.tracker.process_packet({
            "src_ip": "10.0.0.5", "dst_ip": "10.0.0.6",
            "src_port": 4000, "dst_port": 443, "protocol": "TCP",
            "length": 250, "timestamp": 3000.2
        })

        flow = self.tracker.get_flow({
            "src_ip": "10.0.0.5", "dst_ip": "10.0.0.6",
            "src_port": 4000, "dst_port": 443, "protocol": "TCP"
        })
        self.assertEqual(flow.fwd_bytes, 400) # 150 + 250
        self.assertEqual(flow.bwd_bytes, 500) # 500
        self.assertEqual(flow.total_bytes, 900)
        self.assertAlmostEqual(flow.fwd_len_stats.mean, 200.0) # (150+250)/2
        self.assertAlmostEqual(flow.bwd_len_stats.mean, 500.0)
        self.assertAlmostEqual(flow.len_stats.mean, 300.0)     # 900/3

    def test_flow_duration_and_inter_arrival_times(self):
        """5. Flow duration and inter-arrival calculations."""
        # Packet at t=10.0, 10.2, 10.5 -> duration = 0.5s, IATs = [0.2, 0.3]
        timestamps = [10.0, 10.2, 10.5]
        for t in timestamps:
            self.tracker.process_packet({
                "src_ip": "192.168.1.50", "dst_ip": "8.8.8.8",
                "src_port": 33333, "dst_port": 53, "protocol": "UDP",
                "length": 80, "timestamp": t
            })
        flow = self.tracker.get_flow({
            "src_ip": "192.168.1.50", "dst_ip": "8.8.8.8",
            "src_port": 33333, "dst_port": 53, "protocol": "UDP"
        })
        self.assertAlmostEqual(flow.duration, 0.5, places=5)
        self.assertAlmostEqual(flow.duration_us, 500000.0, places=1)
        self.assertEqual(flow.flow_iat_stats.count, 2)
        self.assertAlmostEqual(flow.flow_iat_stats.mean, 0.25, places=5)
        self.assertAlmostEqual(flow.flow_iat_stats.min_val, 0.2, places=5)
        self.assertAlmostEqual(flow.flow_iat_stats.max_val, 0.3, places=5)

    def test_tcp_flags_syn_vs_syn_ack(self):
        """6. TCP flag counts, including SYN versus SYN-ACK."""
        # 1 SYN, 1 SYN-ACK, 1 ACK, 1 FIN-ACK
        pkts = [
            {"flags": "SYN", "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "src_port": 10, "dst_port": 20, "protocol": "TCP", "length": 60, "timestamp": 1.0},
            {"flags": "SYN-ACK", "src_ip": "2.2.2.2", "dst_ip": "1.1.1.1", "src_port": 20, "dst_port": 10, "protocol": "TCP", "length": 60, "timestamp": 1.1},
            {"flags": "ACK", "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "src_port": 10, "dst_port": 20, "protocol": "TCP", "length": 54, "timestamp": 1.2},
            {"flags": "FIN-ACK", "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "src_port": 10, "dst_port": 20, "protocol": "TCP", "length": 54, "timestamp": 1.3},
        ]
        for p in pkts:
            self.tracker.process_packet(p)

        flow = self.tracker.get_flow(pkts[0])
        self.assertEqual(flow.syn_count, 2)       # SYN + SYN-ACK
        self.assertEqual(flow.pure_syn_count, 1)  # Only first packet had SYN without ACK
        self.assertEqual(flow.fwd_syn_count, 1)   # Initiator SYN
        self.assertEqual(flow.bwd_syn_count, 1)   # Responder SYN-ACK
        self.assertEqual(flow.ack_count, 3)       # SYN-ACK, ACK, FIN-ACK
        self.assertEqual(flow.fin_count, 1)       # FIN-ACK

    def test_separate_flows_for_different_protocols_or_ports(self):
        """7. Separate flows for different protocols or ports."""
        p_tcp_80 = {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 5000, "dst_port": 80, "protocol": "TCP", "length": 60, "timestamp": 1.0}
        p_tcp_443 = {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 5000, "dst_port": 443, "protocol": "TCP", "length": 60, "timestamp": 1.0}
        p_udp_80 = {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 5000, "dst_port": 80, "protocol": "UDP", "length": 60, "timestamp": 1.0}

        flow1, _ = self.tracker.process_packet(p_tcp_80)
        flow2, _ = self.tracker.process_packet(p_tcp_443)
        flow3, _ = self.tracker.process_packet(p_udp_80)

        self.assertIsNot(flow1, flow2)
        self.assertIsNot(flow1, flow3)
        self.assertIsNot(flow2, flow3)
        self.assertEqual(len(self.tracker.active_flows), 3)

    def test_ipv4_and_ipv6_flow_keys(self):
        """8. IPv4 and IPv6 flow keys."""
        p_v4 = {"src_ip": "192.168.1.1", "dst_ip": "192.168.1.2", "src_port": 1234, "dst_port": 80, "protocol": "TCP", "length": 60, "timestamp": 1.0}
        p_v6_fwd = {"src_ip": "fe80::1", "dst_ip": "fe80::2", "src_port": 8080, "dst_port": 9000, "protocol": "TCP", "length": 80, "timestamp": 2.0}
        p_v6_bwd = {"src_ip": "fe80::2", "dst_ip": "fe80::1", "src_port": 9000, "dst_port": 8080, "protocol": "TCP", "length": 90, "timestamp": 2.1}

        f_v4, _ = self.tracker.process_packet(p_v4)
        f_v6_1, _ = self.tracker.process_packet(p_v6_fwd)
        f_v6_2, _ = self.tracker.process_packet(p_v6_bwd)

        self.assertEqual(f_v4.protocol, "TCP")
        self.assertIs(f_v6_1, f_v6_2)
        self.assertEqual(f_v6_1.total_packets, 2)
        self.assertEqual(f_v6_1.initiator_ip, "fe80::1")
        self.assertEqual(f_v6_1.responder_ip, "fe80::2")

    def test_icmp_flow_handling(self):
        """9. ICMP flow handling without inventing port values."""
        p_echo_req = {"src_ip": "192.168.1.1", "dst_ip": "8.8.8.8", "src_port": None, "dst_port": None, "protocol": "ICMP", "length": 84, "timestamp": 10.0}
        p_echo_rep = {"src_ip": "8.8.8.8", "dst_ip": "192.168.1.1", "src_port": None, "dst_port": None, "protocol": "ICMP", "length": 84, "timestamp": 10.02}

        f1, _ = self.tracker.process_packet(p_echo_req)
        f2, _ = self.tracker.process_packet(p_echo_rep)

        self.assertIs(f1, f2)
        self.assertEqual(f1.protocol, "ICMP")
        self.assertIsNone(f1.initiator_port)
        self.assertIsNone(f1.responder_port)
        self.assertEqual(f1.fwd_packets, 1)
        self.assertEqual(f1.bwd_packets, 1)

    def test_idle_timeout_and_flow_expiration(self):
        """10. Idle timeout and flow expiration."""
        tracker = FlowTracker(idle_timeout=2.0, active_timeout=10.0)
        p1 = {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 100, "dst_port": 200, "protocol": "TCP", "length": 60, "timestamp": 100.0}
        flow1, expired = tracker.process_packet(p1)
        self.assertEqual(len(expired), 0)

        # Send packet after 3.0s (exceeding idle_timeout of 2.0s)
        p2 = {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 100, "dst_port": 200, "protocol": "TCP", "length": 70, "timestamp": 103.0}
        flow2, expired2 = tracker.process_packet(p2)

        self.assertEqual(len(expired2), 1)
        self.assertIs(expired2[0], flow1)
        self.assertIsNot(flow1, flow2)
        self.assertEqual(flow2.total_packets, 1)

    def test_empty_malformed_incomplete_packet_handling(self):
        """11. Empty, malformed, or incomplete packet handling."""
        # Non-dict
        f, exp = self.tracker.process_packet(None)
        self.assertIsNone(f)
        self.assertEqual(len(exp), 0)

        f, exp = self.tracker.process_packet("bad_data")
        self.assertIsNone(f)

        # Missing src_ip or dst_ip
        f, exp = self.tracker.process_packet({"src_ip": None, "dst_ip": "1.1.1.1"})
        self.assertIsNone(f)

        f, exp = self.tracker.process_packet({"src_ip": "1.1.1.1", "dst_ip": ""})
        self.assertIsNone(f)

    def test_memory_cleanup_and_repeated_flow_creation(self):
        """12. Bounded memory table cleanup and repeated flow creation."""
        # Set small capacity table: max_flows=3
        small_tracker = FlowTracker(idle_timeout=10.0, active_timeout=60.0, max_flows=3)

        for i in range(5):
            small_tracker.process_packet({
                "src_ip": f"10.0.0.{i}", "dst_ip": "192.168.1.1",
                "src_port": 1000 + i, "dst_port": 80, "protocol": "TCP",
                "length": 64, "timestamp": 10.0 + i
            })

        # Must never exceed max_flows=3
        self.assertLessEqual(len(small_tracker.active_flows), 3)
        self.assertEqual(small_tracker.total_flows_created, 5)
        self.assertEqual(small_tracker.total_flows_expired, 2)

    def test_model_feature_schema_mapping(self):
        """Verify that to_model_features matches exact CIC-IDS2017 keys and types."""
        pkt = {
            "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
            "src_port": 10000, "dst_port": 80, "protocol": "TCP",
            "length": 64, "flags": "SYN", "timestamp": 10.0
        }
        flow, _ = self.tracker.process_packet(pkt)
        features = flow.to_model_features()

        expected_keys = [
            "Destination Port",
            "Flow Duration",
            "Total Fwd Packets",
            "Total Length of Fwd Packets",
            "Fwd Packet Length Mean",
            "Flow Bytes/s",
            "Flow Packets/s",
            "SYN Flag Count",
            "Average Packet Size"
        ]
        for k in expected_keys:
            self.assertIn(k, features)

        self.assertEqual(features["Destination Port"], 80)
        self.assertEqual(features["Total Fwd Packets"], 1)
        self.assertEqual(features["Total Length of Fwd Packets"], 64)
        self.assertEqual(features["SYN Flag Count"], 1)

    def test_detector_flow_tracker_integration(self):
        """Verify Detector process_packet updates flow tracker without regressions."""
        from detector import Detector
        det = Detector()
        self.assertTrue(hasattr(det, "flow_tracker"))

        pkt = {
            "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
            "src_port": 12345, "dst_port": 80, "protocol": "TCP",
            "length": 64, "flags": "SYN", "timestamp": time.time()
        }
        det.process_packet(pkt)
        flow = det.flow_tracker.get_flow(pkt)
        self.assertIsNotNone(flow)
        self.assertEqual(flow.total_packets, 1)

if __name__ == "__main__":
    unittest.main()
