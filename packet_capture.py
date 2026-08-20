from scapy.all import sniff
from config import INTERFACE
from feature_extractor import FeatureExtractor
from logger import log_info, log_packet

class PacketCapture:
    def __init__(self, callback):
        """
        Initializes the packet capture module.
        :param callback: Function to call on each extracted packet feature dictionary.
        """
        self.callback = callback

    def _packet_handler(self, packet):
        """
        Callback handler called by Scapy for each captured packet.
        """
        try:
            features = FeatureExtractor.extract_features(packet)
            if features:
                # Print the packet to the terminal in the required readable format
                log_packet(features)
                # Forward to the detector for rule-based analysis
                self.callback(features)
        except Exception:
            # Silently ignore parsing issues to keep packet capture resilient
            pass

    def start(self):
        """
        Starts sniffing packets on the configured interface.
        Requires root privileges for socket access.
        """
        log_info(f"Sniffing packets on interface: {INTERFACE}")
        log_info("Please ensure you run this command with 'sudo'. Press Ctrl+C to terminate.")
        
        try:
            # store=0 prevents memory leaks by not saving packet history in Scapy memory
            sniff(iface=INTERFACE, prn=self._packet_handler, store=0)
        except PermissionError:
            print("\n[ERROR] Permission Denied. Sniffing requires raw socket access.")
            print("Please run the script using sudo: 'sudo python main.py'\n")
        except Exception as e:
            print(f"\n[ERROR] Failed to capture packets: {e}")
            print("Make sure the interface is correct and Scapy is installed with correct permissions.\n")
