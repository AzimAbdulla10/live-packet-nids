import uuid
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List, Tuple

# Severity rank order for severity escalation
SEVERITY_ORDER = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}

def max_severity(sev1: str, sev2: str) -> str:
    r1 = SEVERITY_ORDER.get(sev1.upper(), 1)
    r2 = SEVERITY_ORDER.get(sev2.upper(), 1)
    return sev1 if r1 >= r2 else sev2

def get_threat_category(detection_type: str) -> str:
    """Normalizes detection types into broad attack categories for correlation."""
    dt = detection_type.upper()
    if "PORT" in dt or "SCAN" in dt:
        return "SCAN"
    if "SYN" in dt or "FLOOD" in dt or "DDOS" in dt or "DOS" in dt:
        return "FLOOD_DDOS"
    if "ANOMALY" in dt:
        return "ANOMALY"
    return dt


@dataclass
class DetectionEvent:
    """
    Normalized observation produced by an individual detection engine.
    """
    timestamp: float
    engine: str            # "RULE", "ML", "ANOMALY"
    detection_type: str    # "Port Scan", "SYN Flood", "DDoS", "PortScan", "Statistical Anomaly"
    severity: str          # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    src_ip: str
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    flow_id: Optional[str] = None
    confidence: Optional[float] = None
    anomaly_score: Optional[float] = None
    details: str = ""
    features: Optional[Dict[str, Any]] = None

    @property
    def category(self) -> str:
        return get_threat_category(self.detection_type)


@dataclass
class Incident:
    """
    Correlated security incident combining observations from one or more detection engines.
    """
    incident_id: str
    created_at: float
    updated_at: float
    primary_threat: str
    severity: str
    src_ip: str
    dst_ip: Optional[str]
    flow_id: Optional[str]
    engines: List[str] = field(default_factory=list)
    detection_types: List[str] = field(default_factory=list)
    events: List[DetectionEvent] = field(default_factory=list)
    confidence: Optional[float] = None
    anomaly_score: Optional[float] = None
    details: str = ""
    event_count: int = 1
    has_disagreement: bool = False
    disagreement_details: Optional[str] = None

    @property
    def is_corroborated(self) -> bool:
        """True if more than one distinct detection engine contributed to this incident."""
        return len(set(self.engines)) > 1


class ThreatDecisionEngine:
    """
    Centralized decision component that correlates rule-based detections,
    supervised ML predictions, and unsupervised anomaly scores into unified incidents.
    """
    def __init__(self, correlation_window: float = 10.0, max_active_incidents: int = 5000):
        self.correlation_window = correlation_window
        self.max_active_incidents = max_active_incidents
        # Mapping: correlation_key -> Incident
        self.active_incidents: Dict[str, Incident] = {}
        self.total_events_processed: int = 0
        self.total_incidents_created: int = 0

    def _make_correlation_key(self, event: DetectionEvent) -> str:
        """
        Builds correlation key based on underlying attack evidence.
        - Flow-specific attacks correlate on the canonical flow and threat category.
        - Host-wide attacks (such as multi-port scans) correlate on src_ip, dst_ip, and category.
        """
        if event.flow_id:
            return f"flow:{event.flow_id}:{event.category}"
        dst = event.dst_ip if event.dst_ip else "any"
        return f"host:{event.src_ip}->{dst}:{event.category}"

    def process_event(self, event: DetectionEvent) -> Tuple[Incident, bool]:
        """
        Ingests a detection event, correlating it with existing incidents or creating a new one.
        Returns:
            (incident, is_new_or_significantly_updated)
        """
        self.total_events_processed += 1
        now = event.timestamp
        self.cleanup_stale_incidents(now)

        corr_key = self._make_correlation_key(event)
        existing_incident = self.active_incidents.get(corr_key)

        if existing_incident and (now - existing_incident.updated_at <= self.correlation_window):
            # Correlate with existing incident
            is_new_engine = event.engine not in existing_incident.engines
            existing_incident.updated_at = now
            existing_incident.event_count += 1
            existing_incident.events.append(event)

            if event.engine not in existing_incident.engines:
                existing_incident.engines.append(event.engine)
            if event.detection_type not in existing_incident.detection_types:
                existing_incident.detection_types.append(event.detection_type)

            # Escalate severity if incoming event is higher severity
            existing_incident.severity = max_severity(existing_incident.severity, event.severity)

            # Update highest confidence / anomaly score
            if event.confidence is not None:
                if existing_incident.confidence is None or event.confidence > existing_incident.confidence:
                    existing_incident.confidence = event.confidence
            if event.anomaly_score is not None:
                if existing_incident.anomaly_score is None or event.anomaly_score > existing_incident.anomaly_score:
                    existing_incident.anomaly_score = event.anomaly_score

            # Check for detector disagreement:
            # e.g. one engine says SCAN while another says FLOOD, or conflicting classifications
            if len(set(existing_incident.detection_types)) > 1:
                # Check if categories differ
                cats = {get_threat_category(dt) for dt in existing_incident.detection_types}
                if len(cats) > 1:
                    existing_incident.has_disagreement = True
                    existing_incident.disagreement_details = (
                        f"Detector disagreement: Contributing types {existing_incident.detection_types} "
                        f"across engines {existing_incident.engines}"
                    )

            # Update details with corroboration info
            if is_new_engine:
                existing_incident.details = (
                    f"Corroborated Incident: Engines={existing_incident.engines} | "
                    f"Types={existing_incident.detection_types} | "
                    f"Observations={existing_incident.event_count} | {event.details}"
                )
            return existing_incident, False

        else:
            # Create new Incident
            incident_id = f"inc-{int(now)}-{uuid.uuid4().hex[:6]}"
            new_incident = Incident(
                incident_id=incident_id,
                created_at=now,
                updated_at=now,
                primary_threat=event.detection_type,
                severity=event.severity,
                src_ip=event.src_ip,
                dst_ip=event.dst_ip,
                flow_id=event.flow_id,
                engines=[event.engine],
                detection_types=[event.detection_type],
                events=[event],
                confidence=event.confidence,
                anomaly_score=event.anomaly_score,
                details=event.details,
                event_count=1,
                has_disagreement=False,
                disagreement_details=None
            )

            # Bound memory
            if len(self.active_incidents) >= self.max_active_incidents:
                # Evict oldest incident
                oldest_key = min(self.active_incidents.keys(), key=lambda k: self.active_incidents[k].updated_at)
                self.active_incidents.pop(oldest_key, None)

            self.active_incidents[corr_key] = new_incident
            self.total_incidents_created += 1
            return new_incident, True

    def cleanup_stale_incidents(self, current_time: float):
        """Purges incidents that have exceeded the correlation window."""
        stale_keys = [
            k for k, inc in self.active_incidents.items()
            if (current_time - inc.updated_at) > self.correlation_window
        ]
        for k in stale_keys:
            self.active_incidents.pop(k, None)

    def clear(self):
        """Resets all active incidents."""
        self.active_incidents.clear()
        self.total_events_processed = 0
        self.total_incidents_created = 0
