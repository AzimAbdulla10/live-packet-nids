import time
from typing import Optional, Dict, Any
from scapy.all import Packet
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6

# TCP Flag Bitmasks (RFC 793 / RFC 3168)
TCP_FLAG_FIN = 0x01
TCP_FLAG_SYN = 0x02
TCP_FLAG_RST = 0x04
TCP_FLAG_PSH = 0x08
TCP_FLAG_ACK = 0x10
TCP_FLAG_URG = 0x20
TCP_FLAG_ECE = 0x40
TCP_FLAG_CWR = 0x80

class FeatureExtractor:
    @staticmethod
    def extract_features(packet: Packet) -> Optional[Dict[str, Any]]:
        """
        Extracts key features from a Scapy packet into a standard dictionary.
        Returns None for unsupported or non-IP packets (e.g. ARP, STP).
        """
        if packet is None:
            return None

        try:
            # 1. Network Layer (IPv4 or IPv6)
            if IP in packet:
                ip_layer = packet[IP]
                src_ip = str(ip_layer.src)
                dst_ip = str(ip_layer.dst)
            elif IPv6 in packet:
                ipv6_layer = packet[IPv6]
                src_ip = str(ipv6_layer.src)
                dst_ip = str(ipv6_layer.dst)
            else:
                # Non-IP packet (ARP, LLC, STP, etc.)
                return None

            length = len(packet)
            pkt_time = getattr(packet, "time", None)
            timestamp = float(pkt_time) if pkt_time is not None else time.time()

            features = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "length": length,
                "timestamp": timestamp,
                "protocol": "Other",
                "src_port": None,
                "dst_port": None,
                "flags": "",
                "payload_length": 0,
                "icmp_type": None,
                "icmp_code": None
            }

            # 2. Transport Layer (TCP, UDP, ICMP, ICMPv6)
            if TCP in packet:
                tcp_layer = packet[TCP]
                features["protocol"] = "TCP"
                features["src_port"] = int(tcp_layer.sport)
                features["dst_port"] = int(tcp_layer.dport)
                try:
                    features["payload_length"] = len(tcp_layer.payload) if tcp_layer.payload else 0
                except Exception:
                    features["payload_length"] = 0

                # Bitmask TCP flag evaluation
                try:
                    raw_flags = int(tcp_layer.flags)
                except (ValueError, TypeError):
                    raw_flags = 0

                flags_list = []
                if raw_flags & TCP_FLAG_SYN:
                    flags_list.append("SYN")
                if raw_flags & TCP_FLAG_ACK:
                    flags_list.append("ACK")
                if raw_flags & TCP_FLAG_FIN:
                    flags_list.append("FIN")
                if raw_flags & TCP_FLAG_RST:
                    flags_list.append("RST")
                if raw_flags & TCP_FLAG_PSH:
                    flags_list.append("PSH")
                if raw_flags & TCP_FLAG_URG:
                    flags_list.append("URG")
                if raw_flags & TCP_FLAG_ECE:
                    flags_list.append("ECE")
                if raw_flags & TCP_FLAG_CWR:
                    flags_list.append("CWR")

                features["flags"] = "-".join(flags_list)

            elif UDP in packet:
                udp_layer = packet[UDP]
                features["protocol"] = "UDP"
                features["src_port"] = int(udp_layer.sport)
                features["dst_port"] = int(udp_layer.dport)

            elif ICMP in packet:
                icmp_layer = packet[ICMP]
                features["protocol"] = "ICMP"
                features["icmp_type"] = int(getattr(icmp_layer, "type", 0))
                features["icmp_code"] = int(getattr(icmp_layer, "code", 0))

            else:
                # Check for ICMPv6 layers
                for layer_cls in packet.layers():
                    if "ICMPv6" in layer_cls.__name__:
                        icmp6_layer = packet[layer_cls]
                        features["protocol"] = "ICMP"
                        features["icmp_type"] = int(getattr(icmp6_layer, "type", 0))
                        features["icmp_code"] = int(getattr(icmp6_layer, "code", 0))
                        break

            # Exclude monitoring dashboard's own port (8501) to prevent self-monitoring noise
            if features.get("src_port") == 8501 or features.get("dst_port") == 8501:
                return None

            return features

        except Exception:
            # Corrupted or truncated packet headers
            return None
