import unittest
import time
from scapy.all import IP, IPv6, TCP, UDP, ICMP, Ether, ARP
from scapy.layers.inet6 import ICMPv6EchoRequest

from feature_extractor import (
    FeatureExtractor,
    TCP_FLAG_SYN,
    TCP_FLAG_ACK,
    TCP_FLAG_FIN,
    TCP_FLAG_RST,
    TCP_FLAG_PSH,
    TCP_FLAG_URG
)
from detector import Detector

class TestFeatureExtractor(unittest.TestCase):
    def test_ipv4_tcp_packet(self):
        pkt = IP(src="192.168.1.10", dst="10.0.0.1") / TCP(sport=54321, dport=80, flags="S")
        features = FeatureExtractor.extract_features(pkt)
        
        self.assertIsNotNone(features)
        self.assertEqual(features["src_ip"], "192.168.1.10")
        self.assertEqual(features["dst_ip"], "10.0.0.1")
        self.assertEqual(features["protocol"], "TCP")
        self.assertEqual(features["src_port"], 54321)
        self.assertEqual(features["dst_port"], 80)
        self.assertEqual(features["flags"], "SYN")
        self.assertIsNone(features["icmp_type"])
        self.assertIsNone(features["icmp_code"])

    def test_ipv6_tcp_packet(self):
        pkt = IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=12345, dport=443, flags="A")
        features = FeatureExtractor.extract_features(pkt)
        
        self.assertIsNotNone(features)
        self.assertEqual(features["src_ip"], "2001:db8::1")
        self.assertEqual(features["dst_ip"], "2001:db8::2")
        self.assertEqual(features["protocol"], "TCP")
        self.assertEqual(features["src_port"], 12345)
        self.assertEqual(features["dst_port"], 443)
        self.assertEqual(features["flags"], "ACK")

    def test_udp_packet(self):
        pkt = IP(src="192.168.1.5", dst="8.8.8.8") / UDP(sport=40000, dport=53)
        features = FeatureExtractor.extract_features(pkt)
        
        self.assertIsNotNone(features)
        self.assertEqual(features["protocol"], "UDP")
        self.assertEqual(features["src_port"], 40000)
        self.assertEqual(features["dst_port"], 53)
        self.assertEqual(features["flags"], "")

    def test_icmp_v4_packet(self):
        pkt = IP(src="192.168.1.1", dst="192.168.1.254") / ICMP(type=8, code=0)
        features = FeatureExtractor.extract_features(pkt)
        
        self.assertIsNotNone(features)
        self.assertEqual(features["protocol"], "ICMP")
        self.assertIsNone(features["src_port"])
        self.assertIsNone(features["dst_port"])
        self.assertEqual(features["icmp_type"], 8)
        self.assertEqual(features["icmp_code"], 0)

    def test_icmp_v6_packet(self):
        pkt = IPv6(src="fe80::1", dst="fe80::2") / ICMPv6EchoRequest(type=128, code=0)
        features = FeatureExtractor.extract_features(pkt)
        
        self.assertIsNotNone(features)
        self.assertEqual(features["protocol"], "ICMP")
        self.assertEqual(features["icmp_type"], 128)
        self.assertEqual(features["icmp_code"], 0)

    def test_tcp_flags_bitmask_parsing(self):
        # Pure SYN
        pkt_syn = IP() / TCP(flags=TCP_FLAG_SYN)
        f_syn = FeatureExtractor.extract_features(pkt_syn)
        self.assertEqual(f_syn["flags"], "SYN")

        # SYN-ACK
        pkt_syn_ack = IP() / TCP(flags=TCP_FLAG_SYN | TCP_FLAG_ACK)
        f_syn_ack = FeatureExtractor.extract_features(pkt_syn_ack)
        self.assertEqual(f_syn_ack["flags"], "SYN-ACK")

        # FIN-ACK
        pkt_fin_ack = IP() / TCP(flags=TCP_FLAG_FIN | TCP_FLAG_ACK)
        f_fin_ack = FeatureExtractor.extract_features(pkt_fin_ack)
        self.assertEqual(f_fin_ack["flags"], "ACK-FIN")

        # RST
        pkt_rst = IP() / TCP(flags=TCP_FLAG_RST)
        f_rst = FeatureExtractor.extract_features(pkt_rst)
        self.assertEqual(f_rst["flags"], "RST")

        # PSH-ACK
        pkt_psh_ack = IP() / TCP(flags=TCP_FLAG_PSH | TCP_FLAG_ACK)
        f_psh_ack = FeatureExtractor.extract_features(pkt_psh_ack)
        self.assertEqual(f_psh_ack["flags"], "ACK-PSH")

        # URG
        pkt_urg = IP() / TCP(flags=TCP_FLAG_URG)
        f_urg = FeatureExtractor.extract_features(pkt_urg)
        self.assertEqual(f_urg["flags"], "URG")

    def test_malformed_and_unsupported_packets(self):
        # None input
        self.assertIsNone(FeatureExtractor.extract_features(None))

        # ARP packet (non-IP)
        arp_pkt = Ether() / ARP()
        self.assertIsNone(FeatureExtractor.extract_features(arp_pkt))


class TestDetectorRules(unittest.TestCase):
    def setUp(self):
        self.detector = Detector()

    def test_syn_flood_ignores_syn_ack(self):
        src_ip = "10.10.10.1"
        now = time.time()
        
        # Send 110 SYN-ACK packets (e.g. server responses)
        for i in range(110):
            pkt = {
                "src_ip": src_ip,
                "dst_ip": "127.0.0.1",
                "protocol": "TCP",
                "src_port": 80,
                "dst_port": 10000 + i,
                "flags": "SYN-ACK",
                "timestamp": now + (i * 0.01)
            }
            self.detector.process_packet(pkt)

        # SYN flood history should be completely empty because SYN-ACK is not pure SYN
        self.assertEqual(len(self.detector.syn_flood_history[src_ip]), 0)

    def test_syn_flood_threshold_and_sliding_window(self):
        src_ip = "10.10.10.2"
        now = time.time()

        # Send exactly 100 SYN packets (threshold is > 100, so exactly 100 should not alert)
        for i in range(100):
            pkt = {
                "src_ip": src_ip,
                "dst_ip": "127.0.0.1",
                "protocol": "TCP",
                "src_port": 20000 + i,
                "dst_port": 80,
                "flags": "SYN",
                "timestamp": now + (i * 0.01)
            }
            self.detector.process_packet(pkt)
        self.assertNotIn(src_ip, self.detector.last_syn_flood_alert)

        # 101st SYN packet within 3s window triggers alert
        pkt_101 = {
            "src_ip": src_ip,
            "dst_ip": "127.0.0.1",
            "protocol": "TCP",
            "src_port": 20101,
            "dst_port": 80,
            "flags": "SYN",
            "timestamp": now + 1.05
        }
        self.detector.process_packet(pkt_101)
        self.assertIn(src_ip, self.detector.last_syn_flood_alert)

        # Window expiration test:
        # Packets arriving after 3.1s window should prune old timestamps
        future_time = now + 10.0
        pkt_future = {
            "src_ip": src_ip,
            "dst_ip": "127.0.0.1",
            "protocol": "TCP",
            "src_port": 20200,
            "dst_port": 80,
            "flags": "SYN",
            "timestamp": future_time
        }
        self.detector.process_packet(pkt_future)
        # All packets older than future_time - 3.0s should be pruned
        self.assertEqual(len(self.detector.syn_flood_history[src_ip]), 1)

    def test_port_scan_threshold_and_cooldown(self):
        src_ip = "10.10.10.3"
        now = time.time()

        # 19 unique ports in 1s (threshold is >= 20, so 19 should not alert)
        for port in range(1, 20):
            pkt = {
                "src_ip": src_ip,
                "dst_ip": "127.0.0.1",
                "protocol": "TCP",
                "src_port": 50000,
                "dst_port": port,
                "flags": "SYN",
                "timestamp": now + (port * 0.05)
            }
            self.detector.process_packet(pkt)
        self.assertNotIn(src_ip, self.detector.last_port_scan_alert)

        # 20th unique port triggers alert
        pkt_20 = {
            "src_ip": src_ip,
            "dst_ip": "127.0.0.1",
            "protocol": "TCP",
            "src_port": 50000,
            "dst_port": 20,
            "flags": "SYN",
            "timestamp": now + 1.0
        }
        self.detector.process_packet(pkt_20)
        self.assertIn(src_ip, self.detector.last_port_scan_alert)
        alert_time_1 = self.detector.last_port_scan_alert[src_ip]

        # 21st unique port within cooldown window (e.g. at 2.0s) should NOT update cooldown / duplicate alert
        pkt_21 = {
            "src_ip": src_ip,
            "dst_ip": "127.0.0.1",
            "protocol": "TCP",
            "src_port": 50000,
            "dst_port": 21,
            "flags": "SYN",
            "timestamp": now + 2.0
        }
        self.detector.process_packet(pkt_21)
        self.assertEqual(self.detector.last_port_scan_alert[src_ip], alert_time_1)

if __name__ == "__main__":
    unittest.main()
