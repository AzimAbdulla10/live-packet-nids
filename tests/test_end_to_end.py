import unittest
import time
import os
import tempfile
from database import DatabaseManager
from detector import Detector
from simulator import generate_mock_packets
from reporter import generate_text_summary, export_alerts_csv, export_flows_csv

class TestEndToEndPipeline(unittest.TestCase):
    def setUp(self):
        # Dedicated in-memory database for clean, isolated pipeline execution
        self.db = DatabaseManager(":memory:")
        self.detector = Detector()
        # Wire detector to use our test db
        import detector
        self.orig_db = detector.db
        detector.db = self.db

    def tearDown(self):
        import detector
        detector.db = self.orig_db

    def test_full_live_pipeline_e2e(self):
        """
        Validates entire pipeline end-to-end:
        Packet Capture / Mock -> Feature Extraction -> Rules -> FlowTracker -> ML & Anomaly ->
        ThreatDecisionEngine -> SQLite (packets, alerts, flows) -> Reporter & Dashboard data.
        """
        base_time = 1000.0

        # 1. Normal Traffic
        normal_pkts = generate_mock_packets("normal", count=15, base_time=base_time)
        for p in normal_pkts:
            self.db.insert_packet(p)
            self.detector.process_packet(p)

        # 2. Port Scan Attack (25 ports from single IP)
        scan_pkts = generate_mock_packets("portscan", count=25, base_time=base_time + 5.0)
        for p in scan_pkts:
            self.db.insert_packet(p)
            self.detector.process_packet(p)

        # 3. SYN Flood Attack (110 SYN packets from single IP)
        flood_pkts = generate_mock_packets("synflood", count=110, base_time=base_time + 10.0)
        for p in flood_pkts:
            self.db.insert_packet(p)
            self.detector.process_packet(p)

        # 4. DDoS Flood Attack (120 high-rate SYN packets evaluated by ML classifier)
        ddos_pkts = generate_mock_packets("ddos", count=120, base_time=base_time + 15.0)
        for p in ddos_pkts:
            self.db.insert_packet(p)
            self.detector.process_packet(p)

        # 5. Zero-Day Anomaly Traffic (Unusual flags and exotic ports evaluated by Isolation Forest)
        anomaly_pkts = generate_mock_packets("anomaly", count=30, base_time=base_time + 20.0)
        for p in anomaly_pkts:
            self.db.insert_packet(p)
            self.detector.process_packet(p)

        # 6. Flush active flows on shutdown
        self.detector.finalize_flows()

        # 7. Verify SQLite Database State
        stats = self.db.get_stats()
        total_injected = len(normal_pkts) + len(scan_pkts) + len(flood_pkts) + len(ddos_pkts) + len(anomaly_pkts)
        self.assertEqual(stats["total_packets"], total_injected)
        self.assertGreater(stats["total_alerts"], 0, "Expected alerts to be generated")
        self.assertGreater(stats["rule_alerts"], 0, "Expected signature rule alerts")
        self.assertGreater(stats["ml_alerts"], 0, "Expected machine learning alerts")
        self.assertGreater(stats["total_flows"], 0, "Expected flow summaries in database")

        # Check alert types present
        alert_types = [b["alert_type"] for b in stats["alert_breakdown"]]
        self.assertTrue(any("Port Scan" in at or "PortScan" in at for at in alert_types))
        self.assertTrue(any("SYN Flood" in at for at in alert_types))

        # Check flow summaries
        recent_flows = self.db.get_recent_flows(limit=50)
        self.assertGreater(len(recent_flows), 0)
        self.assertTrue(all(f["finalization_reason"] in ("shutdown", "idle_timeout", "active_timeout") for f in recent_flows))

        # 8. Verify Reporter Output with real persisted data
        # Temporarily wire reporter.db to self.db
        import reporter
        orig_reporter_db = reporter.db
        reporter.db = self.db
        try:
            summary_text = generate_text_summary()
            self.assertIn("NETWORK INTRUSION DETECTION SYSTEM - AUDIT REPORT", summary_text)
            self.assertIn(f"Total Packets Analyzed:   {total_injected:,}", summary_text)
            self.assertIn("Total Flows Tracked:", summary_text)

            with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f_alerts:
                alerts_csv_path = f_alerts.name
            with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f_flows:
                flows_csv_path = f_flows.name

            export_alerts_csv(alerts_csv_path)
            export_flows_csv(flows_csv_path)

            self.assertTrue(os.path.exists(alerts_csv_path))
            self.assertGreater(os.path.getsize(alerts_csv_path), 50)
            self.assertTrue(os.path.exists(flows_csv_path))
            self.assertGreater(os.path.getsize(flows_csv_path), 50)

            os.remove(alerts_csv_path)
            os.remove(flows_csv_path)
        finally:
            reporter.db = orig_reporter_db

    def test_malformed_packets_do_not_crash_pipeline(self):
        """Malformed or incomplete packets must not terminate the pipeline."""
        malformed = [
            None,
            {},
            {"src_ip": None, "dst_ip": "10.0.0.1"},
            {"src_ip": "1.1.1.1", "dst_ip": "", "protocol": "TCP"},
            {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": "not_an_int"},
            {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "timestamp": -999.0}
        ]
        for bad_pkt in malformed:
            # Must not raise unhandled exception
            self.detector.process_packet(bad_pkt)

        # Subsequent valid packet must still be processed normally
        valid_pkt = {
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_port": 1234,
            "dst_port": 80,
            "protocol": "TCP",
            "length": 64,
            "flags": "S",
            "timestamp": time.time()
        }
        self.detector.process_packet(valid_pkt)
        active = self.detector.flow_tracker.active_flows
        self.assertGreaterEqual(len(active), 1)

    def test_pipeline_throughput_performance(self):
        """Pipeline must sustain > 5,000 pkts/sec on standard single-threaded CPU."""
        pkt = {
            "src_ip": "192.168.1.50",
            "dst_ip": "192.168.1.1",
            "protocol": "TCP",
            "src_port": 45678,
            "dst_port": 80,
            "length": 120,
            "flags": "PA",
            "timestamp": 1000.0
        }
        N = 2000
        start = time.perf_counter()
        for i in range(N):
            p = dict(pkt)
            p["timestamp"] = 1000.0 + (i * 0.001)
            p["src_port"] = 40000 + (i % 20)
            self.detector.process_packet(p)
        duration = time.perf_counter() - start
        pkts_per_sec = N / duration
        print(f"\n[THROUGHPUT TEST] {N} packets processed in {duration:.3f}s: {pkts_per_sec:.1f} pkts/sec")
        self.assertGreater(pkts_per_sec, 5000.0)

if __name__ == "__main__":
    unittest.main()
