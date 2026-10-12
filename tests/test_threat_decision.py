import unittest
import time
import sqlite3
from unittest.mock import patch, MagicMock

from threat_decision import ThreatDecisionEngine, DetectionEvent
from database import DatabaseManager, db
from detector import Detector

class TestThreatDecisionAndFlowPersistence(unittest.TestCase):
    def setUp(self):
        self.engine = ThreatDecisionEngine(correlation_window=5.0)
        self.db = DatabaseManager(":memory:")

    def test_rule_ml_anomaly_observations_enter_engine(self):
        """1. Rule, ML, and anomaly observations properly enter decision engine."""
        e_rule = DetectionEvent(
            timestamp=10.0, engine="RULE", detection_type="SYN Flood",
            severity="CRITICAL", src_ip="10.0.0.1", dst_ip="10.0.0.2",
            dst_port=80, protocol="TCP", flow_id="TCP:10.0.0.1:1000<->10.0.0.2:80",
            details="SYN Flood rule triggered"
        )
        e_ml = DetectionEvent(
            timestamp=10.5, engine="ML", detection_type="DDoS",
            severity="HIGH", src_ip="10.0.0.1", dst_ip="10.0.0.2",
            dst_port=80, protocol="TCP", flow_id="TCP:10.0.0.1:1000<->10.0.0.2:80",
            confidence=0.88, details="ML DDoS prediction"
        )
        e_anom = DetectionEvent(
            timestamp=11.0, engine="ANOMALY", detection_type="Statistical Anomaly",
            severity="MEDIUM", src_ip="10.0.0.5", dst_ip="10.0.0.6",
            anomaly_score=-0.22, details="Isolation Forest anomaly score"
        )

        inc1, is_new1 = self.engine.process_event(e_rule)
        self.assertTrue(is_new1)
        self.assertEqual(inc1.severity, "CRITICAL")

        inc2, is_new2 = self.engine.process_event(e_ml)
        # Should correlate into same incident because same flow and category
        self.assertFalse(is_new2)
        self.assertIs(inc1, inc2)
        self.assertIn("RULE", inc2.engines)
        self.assertIn("ML", inc2.engines)

        inc3, is_new3 = self.engine.process_event(e_anom)
        self.assertTrue(is_new3)
        self.assertIsNot(inc1, inc3)

    def test_structured_alert_field_consistency(self):
        """2. Structured alert fields are consistent and accurate without fabrication."""
        e = DetectionEvent(
            timestamp=100.0, engine="RULE", detection_type="Port Scan",
            severity="HIGH", src_ip="192.168.1.50", dst_ip="10.0.0.1",
            dst_port=80, protocol="TCP", details="20 ports scanned"
        )
        inc, _ = self.engine.process_event(e)
        self.assertEqual(inc.src_ip, "192.168.1.50")
        self.assertEqual(inc.dst_ip, "10.0.0.1")
        self.assertEqual(inc.primary_threat, "Port Scan")
        self.assertIsNone(inc.confidence)
        self.assertIsNone(inc.anomaly_score)
        self.assertEqual(inc.event_count, 1)

    def test_correlation_multiple_detectors_same_flow(self):
        """3. Correlation merges multiple detector observations on same flow into one incident."""
        flow_id = "TCP:192.168.1.100:4444<->10.0.0.1:80"
        e1 = DetectionEvent(
            timestamp=100.0, engine="RULE", detection_type="SYN Flood",
            severity="HIGH", src_ip="192.168.1.100", dst_ip="10.0.0.1",
            flow_id=flow_id, details="Rule alert"
        )
        e2 = DetectionEvent(
            timestamp=101.0, engine="ML", detection_type="DDoS",
            severity="CRITICAL", src_ip="192.168.1.100", dst_ip="10.0.0.1",
            flow_id=flow_id, confidence=0.92, details="ML alert"
        )

        inc1, _ = self.engine.process_event(e1)
        inc2, is_new2 = self.engine.process_event(e2)

        self.assertIs(inc1, inc2)
        self.assertFalse(is_new2) # Merged into existing incident
        self.assertTrue(inc2.is_corroborated)
        self.assertEqual(inc2.severity, "CRITICAL") # Escalated to max severity
        self.assertEqual(inc2.confidence, 0.92)
        self.assertEqual(set(inc2.engines), {"RULE", "ML"})

    def test_separate_incidents_unrelated_events_same_src_ip(self):
        """4. Unrelated events from same source IP must NOT be merged."""
        # Host performs a Port Scan against Host A
        e_scan = DetectionEvent(
            timestamp=200.0, engine="RULE", detection_type="Port Scan",
            severity="HIGH", src_ip="10.0.0.99", dst_ip="10.0.0.1",
            details="Port scan on 10.0.0.1"
        )
        # Simultaneously performs a DDoS against Host B
        e_ddos = DetectionEvent(
            timestamp=200.5, engine="ML", detection_type="DDoS",
            severity="CRITICAL", src_ip="10.0.0.99", dst_ip="10.0.0.2",
            flow_id="TCP:10.0.0.99:5000<->10.0.0.2:80", details="DDoS on 10.0.0.2"
        )

        inc1, is_new1 = self.engine.process_event(e_scan)
        inc2, is_new2 = self.engine.process_event(e_ddos)

        self.assertTrue(is_new1)
        self.assertTrue(is_new2)
        self.assertIsNot(inc1, inc2)
        self.assertNotEqual(inc1.incident_id, inc2.incident_id)

    def test_detections_that_disagree_preserved(self):
        """5. Conflicting detector classifications on same stream record disagreement."""
        flow_id = "TCP:1.1.1.1:1000<->2.2.2.2:80"
        e_rule = DetectionEvent(
            timestamp=300.0, engine="RULE", detection_type="Port Scan",
            severity="HIGH", src_ip="1.1.1.1", dst_ip="2.2.2.2",
            flow_id=flow_id, details="Rule said port scan"
        )
        e_ml = DetectionEvent(
            timestamp=301.0, engine="ML", detection_type="DDoS",
            severity="HIGH", src_ip="1.1.1.1", dst_ip="2.2.2.2",
            flow_id=flow_id, confidence=0.85, details="ML said DDoS"
        )

        inc1, _ = self.engine.process_event(e_rule)
        # Note: Port Scan category is SCAN, DDoS category is FLOOD_DDOS -> separate categories
        inc2, _ = self.engine.process_event(e_ml)
        self.assertIsNot(inc1, inc2)

    def test_deduplication_and_correlation_window_expiry(self):
        """6. Observations within window update incident; after window expire, create new."""
        e1 = DetectionEvent(
            timestamp=10.0, engine="RULE", detection_type="SYN Flood",
            severity="CRITICAL", src_ip="10.0.0.1", flow_id="TCP:10.0.0.1:10<->10.0.0.2:80"
        )
        inc1, is_new1 = self.engine.process_event(e1)
        self.assertTrue(is_new1)

        # Event within 5.0s correlation window updates existing
        e2 = DetectionEvent(
            timestamp=12.0, engine="RULE", detection_type="SYN Flood",
            severity="CRITICAL", src_ip="10.0.0.1", flow_id="TCP:10.0.0.1:10<->10.0.0.2:80"
        )
        inc2, is_new2 = self.engine.process_event(e2)
        self.assertFalse(is_new2)
        self.assertIs(inc1, inc2)

        # Event after correlation window expires (10.0 + 6.0s = 16.0s) creates new incident
        e3 = DetectionEvent(
            timestamp=18.0, engine="RULE", detection_type="SYN Flood",
            severity="CRITICAL", src_ip="10.0.0.1", flow_id="TCP:10.0.0.1:10<->10.0.0.2:80"
        )
        inc3, is_new3 = self.engine.process_event(e3)
        self.assertTrue(is_new3)
        self.assertIsNot(inc1, inc3)

    def test_correlation_state_cleanup(self):
        """7. Correlation state cleanup removes expired incidents."""
        e = DetectionEvent(
            timestamp=100.0, engine="RULE", detection_type="Port Scan",
            severity="HIGH", src_ip="10.0.0.1", details="Scan"
        )
        self.engine.process_event(e)
        self.assertEqual(len(self.engine.active_incidents), 1)

        # Fast forward time past correlation_window
        self.engine.cleanup_stale_incidents(110.0)
        self.assertEqual(len(self.engine.active_incidents), 0)

    def test_sqlite_schema_backward_compatibility(self):
        """8. Database initializes flow_summaries alongside existing tables."""
        with self.db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {row[0] for row in cursor.fetchall()}
            self.assertIn("packets", tables)
            self.assertIn("alerts", tables)
            self.assertIn("flow_summaries", tables)

    def test_flow_summary_insertion_and_retrieval(self):
        """9. Flow summaries can be inserted and queried."""
        flow_dict = {
            "flow_id": "TCP:192.168.1.1:1000<->10.0.0.1:80",
            "protocol": "TCP",
            "initiator_ip": "192.168.1.1",
            "responder_ip": "10.0.0.1",
            "initiator_port": 1000,
            "responder_port": 80,
            "start_time": 10.0,
            "last_seen": 15.0,
            "duration": 5.0,
            "total_packets": 20,
            "fwd_packets": 15,
            "bwd_packets": 5,
            "total_bytes": 1200,
            "fwd_bytes": 800,
            "bwd_bytes": 400,
            "flow_bytes_s": 240.0,
            "flow_pkts_s": 4.0,
            "syn_count": 1
        }
        success = self.db.insert_flow_summary(flow_dict, finalization_reason="idle_timeout")
        self.assertTrue(success)

        recent = self.db.get_recent_flows(limit=10)
        self.assertEqual(len(recent), 1)
        self.assertEqual(recent[0]["flow_id"], "TCP:192.168.1.1:1000<->10.0.0.1:80")
        self.assertEqual(recent[0]["finalization_reason"], "idle_timeout")

    def test_duplicate_flow_summary_prevention(self):
        """10. Re-inserting identical flow summary interval is prevented by UNIQUE constraint."""
        flow_dict = {
            "flow_id": "TCP:10.0.0.1:5000<->10.0.0.2:80",
            "protocol": "TCP",
            "initiator_ip": "10.0.0.1",
            "responder_ip": "10.0.0.2",
            "initiator_port": 5000,
            "responder_port": 80,
            "start_time": 100.0,
            "last_seen": 105.0,
            "duration": 5.0,
            "total_packets": 10
        }
        res1 = self.db.insert_flow_summary(flow_dict, finalization_reason="idle_timeout")
        self.assertTrue(res1)

        # Duplicate insertion returns False
        res2 = self.db.insert_flow_summary(flow_dict, finalization_reason="idle_timeout")
        self.assertFalse(res2)

        flows = self.db.get_recent_flows()
        self.assertEqual(len(flows), 1)

    def test_persistence_on_idle_active_timeout_and_shutdown(self):
        """11. Persistence triggers and records reasons on timeout and shutdown."""
        det = Detector()
        det.flow_tracker.idle_timeout = 1.0

        # Feed packet
        now = time.time()
        p1 = {
            "src_ip": "10.1.1.1", "dst_ip": "10.1.1.2",
            "src_port": 8888, "dst_port": 80, "protocol": "TCP",
            "length": 64, "flags": "SYN", "timestamp": now
        }
        det.process_packet(p1)

        # Expire by idle timeout
        p2 = {
            "src_ip": "10.2.2.2", "dst_ip": "10.2.2.3",
            "src_port": 9999, "dst_port": 80, "protocol": "TCP",
            "length": 64, "flags": "SYN", "timestamp": now + 2.5
        }
        det.process_packet(p2)

        # Shutdown flushes remaining active flow p2
        det.finalize_flows()

        flows = db.get_recent_flows(limit=10)
        reasons = {f["finalization_reason"] for f in flows if f["initiator_ip"] in ("10.1.1.1", "10.2.2.2")}
        self.assertIn("idle_timeout", reasons)
        self.assertIn("shutdown", reasons)

    def test_database_failure_handling(self):
        """12. Database failures are logged and do not crash the engine."""
        det = Detector()
        broken_db = MagicMock()
        broken_db.insert_alert.side_effect = sqlite3.OperationalError("DB locked")
        broken_db.insert_flow_summary.side_effect = sqlite3.OperationalError("DB disk full")

        with patch("detector.db", broken_db):
            # Feeding packet and triggering rule must not raise unhandled exception
            event = DetectionEvent(
                timestamp=time.time(), engine="RULE", detection_type="Port Scan",
                severity="HIGH", src_ip="99.99.99.99", details="Test scan"
            )
            # Must handle gracefully
            incident = det._dispatch_detection(event)
            self.assertIsNotNone(incident)

if __name__ == "__main__":
    unittest.main()
