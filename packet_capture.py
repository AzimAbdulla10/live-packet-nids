import time
from scapy.all import sniff
from config import INTERFACE
from feature_extractor import FeatureExtractor
from logger import log_info, log_packet
from database import db

class PacketCapture:
    def __init__(self, callback):
        self.callback = callback
        self._buffer = []
        self._last_flush = time.time()
        self._error_count = 0
        self._last_error_log = 0.0

    def _packet_handler(self, packet):
        try:
            features = FeatureExtractor.extract_features(packet)
            if features:
                log_packet(features)
                
                # Batch buffer for database persistence
                self._buffer.append(features)
                now = time.time()
                if len(self._buffer) >= 20 or (now - self._last_flush >= 1.0):
                    try:
                        db.insert_packets_batch(self._buffer)
                    except Exception as db_err:
                        self._log_error(f"Database insertion failed: {db_err}")
                    self._buffer.clear()
                    self._last_flush = now

                # Execute detection callback
                try:
                    self.callback(features)
                except Exception as cb_err:
                    self._log_error(f"Detection callback failed: {cb_err}")

        except Exception as err:
            self._log_error(f"Packet parsing failed: {err}")

    def _log_error(self, message: str):
        self._error_count += 1
        now = time.time()
        # Rate-limit error logging to at most once every 5 seconds to prevent console flooding
        if now - self._last_error_log >= 5.0:
            log_info(f"[WARN] {message} (Total suppressed errors: {self._error_count})")
            self._last_error_log = now

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
        finally:
            if self._buffer:
                try:
                    db.insert_packets_batch(self._buffer)
                except Exception as e:
                    self._log_error(f"Final flush to database failed: {e}")
                self._buffer.clear()
