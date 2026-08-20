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
        # Maps src_ip -> list of (timestamp, dst_port)
        self.port_scan_history = defaultdict(list)
        # Maps src_ip -> list of timestamp
        self.syn_flood_history = defaultdict(list)
        
        # Cooldown trackers to prevent log spamming (alert once per window size)
        # Maps src_ip -> last alert timestamp
        self.last_port_scan_alert = {}
        self.last_syn_flood_alert = {}

    def process_packet(self, pkt_data: dict):
        """
        Processes a packet's features through the intrusion detection rules.
        """
        if not pkt_data:
            return
            
        src_ip = pkt_data.get("src_ip")
        if not src_ip:
            return
            
        current_time = pkt_data.get("timestamp", time.time())
        
        # Run rule checks
        self._check_port_scan(src_ip, pkt_data, current_time)
        self._check_syn_flood(src_ip, pkt_data, current_time)

    def _check_port_scan(self, src_ip: str, pkt_data: dict, current_time: float):
        """
        Port Scan Rule:
        If one source IP attempts connections to PORT_SCAN_THRESHOLD (20) or more
        different ports within PORT_SCAN_WINDOW (5) seconds.
        """
        dst_port = pkt_data.get("dst_port")
        protocol = pkt_data.get("protocol")
        
        # We only track port scan attempts on TCP or UDP ports
        if dst_port is None or protocol not in ("TCP", "UDP"):
            return
            
        # Add to history
        self.port_scan_history[src_ip].append((current_time, dst_port))
        
        # Prune packets outside the sliding window
        cutoff = current_time - PORT_SCAN_WINDOW
        self.port_scan_history[src_ip] = [
            (t, p) for t, p in self.port_scan_history[src_ip] if t >= cutoff
        ]
        
        # Count unique ports contacted in the window
        unique_ports = {p for _, p in self.port_scan_history[src_ip]}
        
        # Check threshold and suppression window
        if len(unique_ports) >= PORT_SCAN_THRESHOLD:
            last_alert = self.last_port_scan_alert.get(src_ip, 0.0)
            if current_time - last_alert >= PORT_SCAN_WINDOW:
                log_alert(src_ip, list(unique_ports))
                self.last_port_scan_alert[src_ip] = current_time

    def _check_syn_flood(self, src_ip: str, pkt_data: dict, current_time: float):
        """
        SYN Flood Rule:
        If more than SYN_FLOOD_THRESHOLD (100) SYN packets arrive within
        SYN_FLOOD_WINDOW (3) seconds from one IP.
        """
        if pkt_data.get("protocol") != "TCP":
            return
            
        flags = pkt_data.get("flags", "")
        # Standard SYN flood checks for SYN set and ACK not set (half-open connection attempts)
        if "SYN" in flags and "ACK" not in flags:
            # Add to history
            self.syn_flood_history[src_ip].append(current_time)
            
            # Prune timestamps outside the sliding window
            cutoff = current_time - SYN_FLOOD_WINDOW
            self.syn_flood_history[src_ip] = [
                t for t in self.syn_flood_history[src_ip] if t >= cutoff
            ]
            
            # Check threshold and suppression window
            syn_count = len(self.syn_flood_history[src_ip])
            if syn_count > SYN_FLOOD_THRESHOLD:
                last_alert = self.last_syn_flood_alert.get(src_ip, 0.0)
                if current_time - last_alert >= SYN_FLOOD_WINDOW:
                    log_critical(src_ip, syn_count)
                    self.last_syn_flood_alert[src_ip] = current_time
