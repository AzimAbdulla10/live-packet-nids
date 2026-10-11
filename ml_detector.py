import os
import time
import joblib
import numpy as np
import pandas as pd
from collections import defaultdict
from typing import Dict, Any, Optional, Tuple

from config import MODEL_PATH, FLOW_WINDOW, ANOMALY_THRESHOLD

class MLDetector:
    def __init__(self, model_path: str = MODEL_PATH):
        self.model_path = model_path
        self.rf_model = None
        self.isolation_forest = None
        self.scaler = None
        self.feature_names = None
        self.classes = None

        self.active_flows = defaultdict(self._new_flow)
        self.last_ml_alert = {}

        self.load_model()

    def _new_flow(self) -> Dict[str, Any]:
        return {
            "start_time": time.time(),
            "last_time": time.time(),
            "packet_count": 0,
            "byte_count": 0,
            "dst_ports": [],
            "syn_count": 0,
            "lengths": []
        }

    def load_model(self) -> bool:
        if os.path.exists(self.model_path):
            try:
                bundle = joblib.load(self.model_path)
                self.rf_model = bundle.get("rf_model")
                self.isolation_forest = bundle.get("isolation_forest")
                self.scaler = bundle.get("scaler")
                self.feature_names = bundle.get("features")
                self.classes = bundle.get("classes")
                return True
            except Exception as e:
                print(f"[WARN] Failed to load ML model: {e}")
                return False
        return False

    def is_ready(self) -> bool:
        return self.rf_model is not None and self.scaler is not None

    def process_packet(self, pkt_data: Dict[str, Any]) -> Optional[Tuple[str, float, str]]:
        if not pkt_data or not self.is_ready():
            return None

        src_ip = pkt_data.get("src_ip")
        if not src_ip:
            return None

        current_time = pkt_data.get("timestamp", time.time())
        flow = self.active_flows[src_ip]

        flow["packet_count"] += 1
        flow["last_time"] = current_time
        pkt_len = pkt_data.get("length", 64)
        flow["byte_count"] += pkt_len
        flow["lengths"].append(pkt_len)

        dst_port = pkt_data.get("dst_port")
        if dst_port is not None:
            flow["dst_ports"].append(dst_port)

        flags = pkt_data.get("flags", "")
        if "SYN" in flags:
            flow["syn_count"] += 1

        duration = max(0.001, current_time - flow["start_time"])

        if flow["packet_count"] >= 50 or duration >= FLOW_WINDOW:
            result = self._evaluate_flow(src_ip, flow, duration)
            self.active_flows[src_ip] = self._new_flow()
            return result

        return None

    def _evaluate_flow(self, src_ip: str, flow: Dict[str, Any], duration: float) -> Optional[Tuple[str, float, str]]:
        pkts = flow["packet_count"]
        bytes_total = flow["byte_count"]
        duration_us = duration * 1e6

        primary_port = flow["dst_ports"][-1] if flow["dst_ports"] else 80
        avg_pkt_size = bytes_total / max(1, pkts)
        flow_bytes_s = bytes_total / duration
        flow_pkts_s = pkts / duration

        feature_dict = {
            "Destination Port": primary_port,
            "Flow Duration": duration_us,
            "Total Fwd Packets": pkts,
            "Total Length of Fwd Packets": bytes_total,
            "Fwd Packet Length Mean": avg_pkt_size,
            "Flow Bytes/s": flow_bytes_s,
            "Flow Packets/s": flow_pkts_s,
            "SYN Flag Count": flow["syn_count"],
            "Average Packet Size": avg_pkt_size
        }

        # Construct DataFrame to maintain exact feature names expected by StandardScaler
        df_row = pd.DataFrame([feature_dict])[self.feature_names]

        try:
            X_scaled = self.scaler.transform(df_row)

            prediction = self.rf_model.predict(X_scaled)[0]
            probabilities = self.rf_model.predict_proba(X_scaled)[0]
            confidence = float(np.max(probabilities))

            now = time.time()
            last_alert = self.last_ml_alert.get(src_ip, 0.0)

            if prediction.upper() != "BENIGN" and confidence >= 0.65:
                if now - last_alert >= 3.0:
                    self.last_ml_alert[src_ip] = now
                    details = f"Class: {prediction} | Confidence: {confidence*100:.1f}% | Packets: {pkts} | Rate: {flow_pkts_s:.1f} pkts/s"
                    return (prediction, confidence, details)

            if self.isolation_forest:
                anomaly_score = float(self.isolation_forest.decision_function(X_scaled)[0])
                if anomaly_score < ANOMALY_THRESHOLD:
                    if now - last_alert >= 3.0:
                        self.last_ml_alert[src_ip] = now
                        details = f"Statistical Anomaly (Score: {anomaly_score:.3f}) | Profile: {pkts} pkts across {len(set(flow['dst_ports']))} ports"
                        return ("Anomaly", abs(anomaly_score), details)

        except Exception:
            pass

        return None
