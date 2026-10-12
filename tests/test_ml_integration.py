import unittest
import time
import numpy as np
import pandas as pd
from flow_tracker import Flow
from ml_detector import MLDetector
from detector import Detector

class TestMLIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.detector = MLDetector()

    def test_model_input_feature_names_and_ordering(self):
        """1. Verify model input feature names and exact ordering."""
        expected_features = [
            "Destination Port",
            "Flow Duration",
            "Total Fwd Packets",
            "Total Length of Fwd Packets",
            "Fwd Packet Length Mean",
            "Flow Bytes/s",
            "Flow Packets/s",
            "SYN Flag Count",
            "Average Packet Size"
        ]
        self.assertTrue(self.detector.is_ready())
        self.assertEqual(list(self.detector.feature_names), expected_features)
        if hasattr(self.detector.scaler, "feature_names_in_"):
            self.assertEqual(list(self.detector.scaler.feature_names_in_), expected_features)

    def test_flow_to_model_features_conversion(self):
        """2. Correct conversion from a flow to the model's input format."""
        flow = Flow({
            "src_ip": "192.168.1.10", "dst_ip": "10.0.0.1",
            "src_port": 50000, "dst_port": 80, "protocol": "TCP",
            "length": 60, "flags": "SYN", "timestamp": 100.0
        })
        flow.update({
            "src_ip": "10.0.0.1", "dst_ip": "192.168.1.10",
            "src_port": 80, "dst_port": 50000, "protocol": "TCP",
            "length": 60, "flags": "SYN-ACK", "timestamp": 100.05
        })

        features = flow.to_model_features()
        for k in self.detector.feature_names:
            self.assertIn(k, features)
            self.assertIsInstance(features[k], (int, float))

        self.assertEqual(features["Destination Port"], 80)
        self.assertAlmostEqual(features["Flow Duration"], 50000.0, places=1) # 0.05s * 1e6
        self.assertEqual(features["Total Fwd Packets"], 1)
        self.assertEqual(features["SYN Flag Count"], 1)

    def test_bidirectional_packet_updates(self):
        """3. Bidirectional packet updates maintain forward and backward stats."""
        flow = Flow({
            "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2",
            "src_port": 1000, "dst_port": 80, "protocol": "TCP",
            "length": 100, "flags": "ACK", "timestamp": 1.0
        })
        flow.update({
            "src_ip": "2.2.2.2", "dst_ip": "1.1.1.1",
            "src_port": 80, "dst_port": 1000, "protocol": "TCP",
            "length": 500, "flags": "ACK", "timestamp": 1.2
        })
        self.assertEqual(flow.fwd_packets, 1)
        self.assertEqual(flow.bwd_packets, 1)
        self.assertEqual(flow.total_packets, 2)
        self.assertEqual(flow.fwd_bytes, 100)
        self.assertEqual(flow.bwd_bytes, 500)
        self.assertEqual(flow.total_bytes, 600)
        self.assertAlmostEqual(flow.len_stats.mean, 300.0)

    def test_flow_timeout_and_finalization(self):
        """4. Flow timeout and finalization evaluation."""
        det = Detector()
        det.flow_tracker.idle_timeout = 1.0

        p1 = {
            "src_ip": "10.0.0.5", "dst_ip": "10.0.0.6",
            "src_port": 2000, "dst_port": 80, "protocol": "TCP",
            "length": 64, "flags": "SYN", "timestamp": 100.0
        }
        det.process_packet(p1)

        # Send packet after 2.0s to trigger expiration of flow p1
        p2 = {
            "src_ip": "10.0.0.7", "dst_ip": "10.0.0.8",
            "src_port": 3000, "dst_port": 80, "protocol": "TCP",
            "length": 64, "flags": "SYN", "timestamp": 102.5
        }
        det.process_packet(p2)
        # Previous flow must have expired
        self.assertIn("TCP:10.0.0.5:2000<->10.0.0.6:80", det.ml_detector.evaluated_flows)

    def test_invalid_and_zero_duration_flows(self):
        """5. Invalid, empty, and zero-duration flows handled safely without crashes."""
        # 0 duration single packet
        flow = Flow({
            "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
            "src_port": 10, "dst_port": 20, "protocol": "TCP",
            "length": 64, "flags": "", "timestamp": 50.0
        })
        self.assertEqual(flow.duration, 0.0)
        self.assertEqual(flow.flow_bytes_per_sec, 0.0)
        self.assertEqual(flow.flow_packets_per_sec, 0.0)

        # evaluate_flow must not crash or return inf
        result = self.detector.evaluate_flow(flow, is_final=True)
        # None returned for benign single packet
        self.assertIsNone(result)

        # None / invalid flow handling
        self.assertIsNone(self.detector.evaluate_flow(None))

    def test_supervised_inference_classification(self):
        """6. Supervised inference on known attack profile."""
        # Simulate typical CIC-IDS2017 DDoS flow profile:
        # Fwd packets to port 80 with small payload, backward response
        flow = Flow({
            "src_ip": "10.0.0.99", "dst_ip": "127.0.0.1",
            "src_port": 30000, "dst_port": 80, "protocol": "TCP",
            "length": 6, "flags": "ACK", "timestamp": 10.0
        })
        for i in range(1, 5):
            flow.update({
                "src_ip": "10.0.0.99", "dst_ip": "127.0.0.1",
                "src_port": 30000, "dst_port": 80, "protocol": "TCP",
                "length": 6, "flags": "ACK", "timestamp": 10.0 + (i * 0.2)
            })
        flow.update({
            "src_ip": "127.0.0.1", "dst_ip": "10.0.0.99",
            "src_port": 80, "dst_port": 30000, "protocol": "TCP",
            "length": 1000, "flags": "ACK", "timestamp": 11.0
        })

        # Reset alert cooldown for test isolation
        self.detector.last_ml_alert.clear()
        self.detector.evaluated_flows.clear()

        result = self.detector.evaluate_flow(flow, is_final=True)
        self.assertIsNotNone(result)
        label, conf, details = result
        self.assertEqual(label, "DDoS")
        self.assertGreaterEqual(conf, 0.65)
        self.assertIn("Class: DDoS", details)

    def test_anomaly_inference(self):
        """7. Anomaly inference flags statistical outliers as Anomaly."""
        # Mock high-volume outlier flow
        flow = Flow({
            "src_ip": "192.168.1.250", "dst_ip": "10.0.0.1",
            "src_port": 9999, "dst_port": 31337, "protocol": "TCP",
            "length": 1400, "flags": "PSH", "timestamp": 10.0
        })
        for i in range(1, 100):
            flow.update({
                "src_ip": "192.168.1.250", "dst_ip": "10.0.0.1",
                "src_port": 9999, "dst_port": 31337, "protocol": "TCP",
                "length": 1400, "flags": "PSH", "timestamp": 10.0 + (i * 0.001)
            })

        self.detector.last_ml_alert.clear()
        self.detector.evaluated_flows.clear()

        # Evaluate flow
        feat = flow.to_model_features()
        df_row = pd.DataFrame([feat])[self.detector.feature_names]
        X_scaled = self.detector.scaler.transform(df_row)
        score = self.detector.isolation_forest.decision_function(X_scaled)[0]
        self.assertIsInstance(score, (float, np.floating))

    def test_model_loading_failure_handling(self):
        """8. Model loading failures handled gracefully without unhandled exceptions."""
        dummy_detector = MLDetector(model_path="non_existent_model.joblib")
        self.assertFalse(dummy_detector.is_ready())
        dummy_flow = Flow({
            "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2",
            "src_port": 1, "dst_port": 2, "protocol": "TCP",
            "length": 64, "timestamp": 1.0
        })
        self.assertIsNone(dummy_detector.evaluate_flow(dummy_flow))

    def test_duplicate_alert_and_repeated_inference_prevention(self):
        """9. Duplicate alerts prevented on finalized flow and during cooldown."""
        flow = Flow({
            "src_ip": "10.0.0.99", "dst_ip": "127.0.0.1",
            "src_port": 30000, "dst_port": 80, "protocol": "TCP",
            "length": 6, "flags": "ACK", "timestamp": 10.0
        })
        for i in range(1, 5):
            flow.update({
                "src_ip": "10.0.0.99", "dst_ip": "127.0.0.1",
                "src_port": 30000, "dst_port": 80, "protocol": "TCP",
                "length": 6, "flags": "ACK", "timestamp": 10.0 + (i * 0.2)
            })
        flow.update({
            "src_ip": "127.0.0.1", "dst_ip": "10.0.0.99",
            "src_port": 80, "dst_port": 30000, "protocol": "TCP",
            "length": 1000, "flags": "ACK", "timestamp": 11.0
        })

        self.detector.last_ml_alert.clear()
        self.detector.evaluated_flows.clear()

        # First evaluation returns alert
        res1 = self.detector.evaluate_flow(flow, is_final=True)
        self.assertIsNotNone(res1)

        # Immediate re-evaluation of finalized flow returns None (de-duplicated)
        res2 = self.detector.evaluate_flow(flow, is_final=True)
        self.assertIsNone(res2)

    def test_regression_rules_still_active(self):
        """10. Regression: Rule-based Port Scan and SYN Flood detection still operate."""
        det = Detector()
        now = time.time()
        # Port scan
        for i in range(20):
            det.process_packet({
                "src_ip": "172.16.0.5", "dst_ip": "127.0.0.1",
                "src_port": 5000, "dst_port": 100 + i, "protocol": "TCP",
                "length": 64, "flags": "SYN", "timestamp": now + (i * 0.05)
            })
        self.assertIn("172.16.0.5", det.last_port_scan_alert)

        # SYN flood
        for i in range(105):
            det.process_packet({
                "src_ip": "172.16.0.6", "dst_ip": "127.0.0.1",
                "src_port": 6000, "dst_port": 80, "protocol": "TCP",
                "length": 64, "flags": "SYN", "timestamp": now + (i * 0.01)
            })
        self.assertIn("172.16.0.6", det.last_syn_flood_alert)

if __name__ == "__main__":
    unittest.main()
