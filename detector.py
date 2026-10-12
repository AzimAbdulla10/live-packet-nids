from collections import defaultdict
import time
from config import (
    PORT_SCAN_THRESHOLD,
    PORT_SCAN_WINDOW,
    SYN_FLOOD_THRESHOLD,
    SYN_FLOOD_WINDOW
)
from logger import log_alert, log_critical, log_ml_alert, log_anomaly_alert
from ml_detector import MLDetector
from flow_tracker import FlowTracker
from database import db

class Detector:
    def __init__(self):
        # Sliding-window packet histories for rule-based engine
        self.port_scan_history = defaultdict(list)
        self.syn_flood_history = defaultdict(list)
        
        # Cooldown trackers to avoid alert spamming
        self.last_port_scan_alert = {}
        self.last_syn_flood_alert = {}

        # Bidirectional flow tracker
        self.flow_tracker = FlowTracker()

        # Machine learning inference engine
        self.ml_detector = MLDetector()

    def process_packet(self, pkt_data: dict):
        if not pkt_data:
            return
            
        src_ip = pkt_data.get("src_ip")
        if not src_ip:
            return
            
        current_time = pkt_data.get("timestamp", time.time())
        
        # 1. Bidirectional flow tracking
        self.flow_tracker.process_packet(pkt_data)

        # 2. Rule-based signature analysis
        self._check_port_scan(src_ip, pkt_data, current_time)
        self._check_syn_flood(src_ip, pkt_data, current_time)

        # 2. Machine Learning flow classification & anomaly detection
        ml_result = self.ml_detector.process_packet(pkt_data)
        if ml_result:
            threat_name, score, details = ml_result
            if threat_name == "Anomaly":
                log_anomaly_alert(src_ip, score, details)
                db.insert_alert("Zero-Day Anomaly", "MEDIUM", "ML", src_ip, details)
            else:
                log_ml_alert(threat_name, src_ip, score, details)
                db.insert_alert(f"ML-{threat_name}", "HIGH", "ML", src_ip, details)

    def _check_port_scan(self, src_ip: str, pkt_data: dict, current_time: float):
        dst_port = pkt_data.get("dst_port")
        protocol = pkt_data.get("protocol")
        
        if dst_port is None or protocol not in ("TCP", "UDP"):
            return
            
        self.port_scan_history[src_ip].append((current_time, dst_port))
        
        cutoff = current_time - PORT_SCAN_WINDOW
        self.port_scan_history[src_ip] = [
            (t, p) for t, p in self.port_scan_history[src_ip] if t >= cutoff
        ]
        
        unique_ports = {p for _, p in self.port_scan_history[src_ip]}
        
        if len(unique_ports) >= PORT_SCAN_THRESHOLD:
            last_alert = self.last_port_scan_alert.get(src_ip, 0.0)
            if current_time - last_alert >= PORT_SCAN_WINDOW:
                ports_list = list(unique_ports)
                log_alert(src_ip, ports_list)
                details = f"Scanned {len(ports_list)} unique ports: {','.join(map(str, sorted(ports_list)[:15]))}"
                db.insert_alert("Port Scan", "HIGH", "RULE", src_ip, details)
                self.last_port_scan_alert[src_ip] = current_time

    def _check_syn_flood(self, src_ip: str, pkt_data: dict, current_time: float):
        if pkt_data.get("protocol") != "TCP":
            return
            
        flags = pkt_data.get("flags", "")
        if "SYN" in flags and "ACK" not in flags:
            self.syn_flood_history[src_ip].append(current_time)
            
            cutoff = current_time - SYN_FLOOD_WINDOW
            self.syn_flood_history[src_ip] = [
                t for t in self.syn_flood_history[src_ip] if t >= cutoff
            ]
            
            syn_count = len(self.syn_flood_history[src_ip])
            if syn_count > SYN_FLOOD_THRESHOLD:
                last_alert = self.last_syn_flood_alert.get(src_ip, 0.0)
                if current_time - last_alert >= SYN_FLOOD_WINDOW:
                    log_critical(src_ip, syn_count)
                    details = f"SYN packet count: {syn_count} within 3s window"
                    db.insert_alert("SYN Flood", "CRITICAL", "RULE", src_ip, details)
                    self.last_syn_flood_alert[src_ip] = current_time
