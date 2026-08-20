from collections import defaultdict
import time
from config import (
    PORT_SCAN_THRESHOLD,
    PORT_SCAN_WINDOW,
    SYN_FLOOD_THRESHOLD,
    SYN_FLOOD_WINDOW
)
from logger import log_alert, log_critical

class Detector:
    def __init__(self):
        # Keep track of recent connections to detect port scans and syn floods
        self.port_scan_history = defaultdict(list)
        self.syn_flood_history = defaultdict(list)
        
        # Avoid spamming multiple alerts in the same window
        self.last_port_scan_alert = {}
        self.last_syn_flood_alert = {}

    def process_packet(self, pkt_data: dict):
        if not pkt_data:
            return
            
        src_ip = pkt_data.get("src_ip")
        if not src_ip:
            return
            
        current_time = pkt_data.get("timestamp", time.time())
        
        self._check_port_scan(src_ip, pkt_data, current_time)
        self._check_syn_flood(src_ip, pkt_data, current_time)

    def _check_port_scan(self, src_ip: str, pkt_data: dict, current_time: float):
        dst_port = pkt_data.get("dst_port")
        protocol = pkt_data.get("protocol")
        
        if dst_port is None or protocol not in ("TCP", "UDP"):
            return
            
        self.port_scan_history[src_ip].append((current_time, dst_port))
        
        # Remove packets older than the sliding window
        cutoff = current_time - PORT_SCAN_WINDOW
        self.port_scan_history[src_ip] = [
            (t, p) for t, p in self.port_scan_history[src_ip] if t >= cutoff
        ]
        
        unique_ports = {p for _, p in self.port_scan_history[src_ip]}
        
        # Trigger alert if threshold reached and we haven't alerted in this window
        if len(unique_ports) >= PORT_SCAN_THRESHOLD:
            last_alert = self.last_port_scan_alert.get(src_ip, 0.0)
            if current_time - last_alert >= PORT_SCAN_WINDOW:
                log_alert(src_ip, list(unique_ports))
                self.last_port_scan_alert[src_ip] = current_time

    def _check_syn_flood(self, src_ip: str, pkt_data: dict, current_time: float):
        if pkt_data.get("protocol") != "TCP":
            return
            
        flags = pkt_data.get("flags", "")
        # SYN set but ACK not set indicates half-open connections
        if "SYN" in flags and "ACK" not in flags:
            self.syn_flood_history[src_ip].append(current_time)
            
            # Remove packets older than the sliding window
            cutoff = current_time - SYN_FLOOD_WINDOW
            self.syn_flood_history[src_ip] = [
                t for t in self.syn_flood_history[src_ip] if t >= cutoff
            ]
            
            syn_count = len(self.syn_flood_history[src_ip])
            if syn_count > SYN_FLOOD_THRESHOLD:
                last_alert = self.last_syn_flood_alert.get(src_ip, 0.0)
                if current_time - last_alert >= SYN_FLOOD_WINDOW:
                    log_critical(src_ip, syn_count)
                    self.last_syn_flood_alert[src_ip] = current_time
