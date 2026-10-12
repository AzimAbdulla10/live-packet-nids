from collections import defaultdict, deque
from typing import Tuple, Optional, List, Dict, Any
import time

from config import (
    PORT_SCAN_THRESHOLD,
    PORT_SCAN_WINDOW,
    SYN_FLOOD_THRESHOLD,
    SYN_FLOOD_WINDOW
)
from logger import log_alert, log_critical, log_ml_alert, log_anomaly_alert, log_info
from ml_detector import MLDetector
from flow_tracker import FlowTracker, Flow
from threat_decision import ThreatDecisionEngine, DetectionEvent, Incident
from database import db

class Detector:
    def __init__(self):
        # Sliding-window packet histories for rule-based engine using deque for O(1) pops
        self.port_scan_history = defaultdict(deque)
        self.port_scan_counts = defaultdict(lambda: defaultdict(int))
        self.syn_flood_history = defaultdict(deque)
        
        # Cooldown trackers to avoid alert spamming
        self.last_port_scan_alert = {}
        self.last_syn_flood_alert = {}

        # Bidirectional flow tracker
        self.flow_tracker = FlowTracker()

        # Machine learning inference engine
        self.ml_detector = MLDetector()

        # Unified threat decision and correlation engine
        self.threat_engine = ThreatDecisionEngine()

    def process_packet(self, pkt_data: dict):
        if not pkt_data:
            return
            
        src_ip = pkt_data.get("src_ip")
        if not src_ip:
            return
            
        current_time = pkt_data.get("timestamp", time.time())
        
        # 1. Bidirectional flow tracking
        flow, expired_flows = self.flow_tracker.process_packet(pkt_data)

        # 2. Rule-based signature analysis
        self._check_port_scan(src_ip, pkt_data, current_time)
        self._check_syn_flood(src_ip, pkt_data, current_time)

        # 3. Handle expired/finalized flows (Persist & Evaluate)
        for exp_flow in expired_flows:
            self._persist_flow(exp_flow)
            ml_result = self.ml_detector.evaluate_flow(exp_flow, is_final=True)
            if ml_result:
                self._handle_ml_flow_detection(exp_flow, ml_result)

        # 4. Machine Learning inference on active ongoing flow
        if flow:
            ml_result = self.ml_detector.evaluate_flow(flow, is_final=False)
            if ml_result:
                self._handle_ml_flow_detection(flow, ml_result)

    def _persist_flow(self, flow: Flow):
        """Persists finalized flow summary to SQLite safely."""
        try:
            db.insert_flow_summary(flow.to_dict(), finalization_reason=flow.finalization_reason)
        except Exception as e:
            log_info(f"[WARN] Failed to persist flow summary: {e}")

    def _handle_ml_flow_detection(self, flow: Flow, ml_result: Tuple[str, float, str]):
        threat_name, score, details = ml_result
        if threat_name == "Anomaly":
            event = DetectionEvent(
                timestamp=flow.last_seen,
                engine="ANOMALY",
                detection_type="Statistical Anomaly",
                severity="MEDIUM",
                src_ip=flow.initiator_ip,
                dst_ip=flow.responder_ip,
                src_port=flow.initiator_port,
                dst_port=flow.responder_port,
                protocol=flow.protocol,
                flow_id=flow.flow_id,
                anomaly_score=score,
                details=details
            )
        else:
            event = DetectionEvent(
                timestamp=flow.last_seen,
                engine="ML",
                detection_type=threat_name,
                severity="HIGH",
                src_ip=flow.initiator_ip,
                dst_ip=flow.responder_ip,
                src_port=flow.initiator_port,
                dst_port=flow.responder_port,
                protocol=flow.protocol,
                flow_id=flow.flow_id,
                confidence=score,
                details=details
            )
        self._dispatch_detection(event)

    def _dispatch_detection(
        self,
        event: DetectionEvent,
        ports_list: Optional[List[int]] = None,
        syn_count: Optional[int] = None
    ) -> Incident:
        """
        Routes all observations through the unified threat decision engine,
        correlates related events, logs to the terminal, and persists alerts.
        """
        incident, is_new = self.threat_engine.process_event(event)

        if is_new or (incident.is_corroborated and event.engine == incident.engines[-1]):
            # 1. Terminal logging
            if event.engine == "RULE":
                if event.detection_type == "Port Scan":
                    log_alert(event.src_ip, ports_list or [])
                elif event.detection_type == "SYN Flood":
                    log_critical(event.src_ip, syn_count or 0)
            elif event.engine == "ANOMALY":
                log_anomaly_alert(event.src_ip, event.anomaly_score or 0.0, event.details)
            elif event.engine == "ML":
                log_ml_alert(event.detection_type, event.src_ip, event.confidence or 0.0, event.details)

            # 2. Database persistence
            engine_label = "HYBRID" if incident.is_corroborated else event.engine
            alert_type = (
                f"ML-{incident.primary_threat}"
                if incident.primary_threat in ("DDoS", "PortScan") and event.engine == "ML"
                else incident.primary_threat
            )
            try:
                db.insert_alert(
                    alert_type=alert_type,
                    severity=incident.severity,
                    engine=engine_label,
                    src_ip=incident.src_ip,
                    details=incident.details
                )
            except Exception as e:
                log_info(f"[WARN] Failed to write alert to database: {e}")

        return incident

    def finalize_flows(self):
        """Finalizes, persists, and evaluates all remaining active flows (e.g. on shutdown)."""
        for flow in list(self.flow_tracker.active_flows.values()):
            flow.finalization_reason = "shutdown"
            self._persist_flow(flow)
            ml_result = self.ml_detector.evaluate_flow(flow, is_final=True)
            if ml_result:
                self._handle_ml_flow_detection(flow, ml_result)

    def _check_port_scan(self, src_ip: str, pkt_data: dict, current_time: float):
        dst_port = pkt_data.get("dst_port")
        protocol = pkt_data.get("protocol")
        
        if dst_port is None or protocol not in ("TCP", "UDP"):
            return
            
        history = self.port_scan_history[src_ip]
        counts = self.port_scan_counts[src_ip]
        history.append((current_time, dst_port))
        counts[dst_port] += 1
        
        cutoff = current_time - PORT_SCAN_WINDOW
        while history and history[0][0] < cutoff:
            _, old_port = history.popleft()
            counts[old_port] -= 1
            if counts[old_port] <= 0:
                del counts[old_port]
        
        if len(counts) >= PORT_SCAN_THRESHOLD:
            last_alert = self.last_port_scan_alert.get(src_ip, 0.0)
            if current_time - last_alert >= PORT_SCAN_WINDOW:
                ports_list = list(counts.keys())
                self.last_port_scan_alert[src_ip] = current_time
                event = DetectionEvent(
                    timestamp=current_time,
                    engine="RULE",
                    detection_type="Port Scan",
                    severity="HIGH",
                    src_ip=src_ip,
                    dst_ip=pkt_data.get("dst_ip"),
                    dst_port=dst_port,
                    protocol=protocol,
                    details=f"Scanned {len(ports_list)} unique ports: {','.join(map(str, sorted(ports_list)[:15]))}"
                )
                self._dispatch_detection(event, ports_list=ports_list)

    def _check_syn_flood(self, src_ip: str, pkt_data: dict, current_time: float):
        if pkt_data.get("protocol") != "TCP":
            return
            
        flags = pkt_data.get("flags", "")
        if "SYN" in flags and "ACK" not in flags:
            history = self.syn_flood_history[src_ip]
            history.append(current_time)
            
            cutoff = current_time - SYN_FLOOD_WINDOW
            while history and history[0] < cutoff:
                history.popleft()
            
            syn_count = len(history)
            if syn_count > SYN_FLOOD_THRESHOLD:
                last_alert = self.last_syn_flood_alert.get(src_ip, 0.0)
                if current_time - last_alert >= SYN_FLOOD_WINDOW:
                    self.last_syn_flood_alert[src_ip] = current_time
                    event = DetectionEvent(
                        timestamp=current_time,
                        engine="RULE",
                        detection_type="SYN Flood",
                        severity="CRITICAL",
                        src_ip=src_ip,
                        dst_ip=pkt_data.get("dst_ip"),
                        dst_port=pkt_data.get("dst_port"),
                        protocol="TCP",
                        details=f"SYN packet count: {syn_count} within 3s window"
                    )
                    self._dispatch_detection(event, syn_count=syn_count)
