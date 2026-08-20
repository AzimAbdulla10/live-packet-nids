from scapy.all import Packet
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6

class FeatureExtractor:
    @staticmethod
    def extract_features(packet: Packet) -> dict:
        # Pull out key packet details to feed into NIDS rules / future ML model
        features = {}
        
        if IP in packet:
            ip_layer = packet[IP]
            features["src_ip"] = ip_layer.src
            features["dst_ip"] = ip_layer.dst
            features["length"] = len(packet)
            features["timestamp"] = float(packet.time)
        elif IPv6 in packet:
            ipv6_layer = packet[IPv6]
            features["src_ip"] = ipv6_layer.src
            features["dst_ip"] = ipv6_layer.dst
            features["length"] = len(packet)
            features["timestamp"] = float(packet.time)
        else:
            # Skip ARP, STP, etc.
            return None

        if TCP in packet:
            tcp_layer = packet[TCP]
            features["protocol"] = "TCP"
            features["src_port"] = int(tcp_layer.sport)
            features["dst_port"] = int(tcp_layer.dport)
            
            # Convert Scapy TCP flag characters to readable words
            flags_str = []
            raw_flags = str(tcp_layer.flags)
            if "S" in raw_flags:
                flags_str.append("SYN")
            if "A" in raw_flags:
                flags_str.append("ACK")
            if "F" in raw_flags:
                flags_str.append("FIN")
            if "R" in raw_flags:
                flags_str.append("RST")
            if "P" in raw_flags:
                flags_str.append("PSH")
            if "U" in raw_flags:
                flags_str.append("URG")
            
            features["flags"] = "-".join(flags_str) if flags_str else ""
        elif UDP in packet:
            udp_layer = packet[UDP]
            features["protocol"] = "UDP"
            features["src_port"] = int(udp_layer.sport)
            features["dst_port"] = int(udp_layer.dport)
            features["flags"] = ""
        elif ICMP in packet:
            features["protocol"] = "ICMP"
            features["src_port"] = None
            features["dst_port"] = None
            features["flags"] = ""
        else:
            features["protocol"] = "Other"
            features["src_port"] = None
            features["dst_port"] = None
            features["flags"] = ""

        return features
