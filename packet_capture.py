from scapy.all import sniff
from config import INTERFACE
from feature_extractor import FeatureExtractor
from logger import log_info, log_packet

class PacketCapture:
    def __init__(self, callback):
        self.callback = callback

    def _packet_handler(self, packet):
        try:
            features = FeatureExtractor.extract_features(packet)
            if features:
                log_packet(features)
                self.callback(features)
        except Exception:
            # Skip any malformed packets so the sniffer doesn't crash
            pass

    def start(self):
        import platform
        # macOS has issues binding to lo0; use pcap to fix it
        if platform.system().lower() == "darwin":
            from scapy.all import conf
            conf.use_pcap = True

        log_info(f"Sniffing packets on interface: {INTERFACE}")
        log_info("Please ensure you run this command with 'sudo'. Press Ctrl+C to terminate.")
        
        try:
            # store=0 stops scapy from keeping all sniffed packets in RAM
            sniff(iface=INTERFACE, prn=self._packet_handler, store=0)
        except PermissionError:
            print("\n[ERROR] Permission Denied. Sniffing requires raw socket access.")
            print("Please run the script using sudo: 'sudo python main.py'\n")
        except Exception as e:
            print(f"\n[ERROR] Failed to capture packets: {e}")
            print("Make sure the interface is correct and Scapy is installed with correct permissions.\n")
