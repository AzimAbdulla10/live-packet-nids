import os
import time
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, Optional, Tuple, Set

from config import MODEL_PATH, ANOMALY_THRESHOLD
from flow_tracker import Flow

class MLDetector:
    """
    Supervised classifier (Random Forest) and unsupervised anomaly detector (Isolation Forest)
    operating on bidirectional network flows derived from flow_tracker.py.
    """
    def __init__(self, model_path: str = MODEL_PATH):
        self.model_path = model_path
        self.rf_model = None
        self.isolation_forest = None
        self.scaler = None
        self.feature_names = None
        self.classes = None

        # Alert cooldown to avoid flooding alerts for the same source host (seconds)
        self.last_ml_alert: Dict[str, float] = {}

        # De-duplication trackers to avoid repeated inference on the same flow
        self.evaluated_flows: Set[str] = set()
        self.flow_eval_history: Dict[str, float] = {}

        self.load_model()

    def load_model(self) -> bool:
        """Loads trained models and preprocessing artifacts once at initialization."""
        if os.path.exists(self.model_path):
            try:
                bundle = joblib.load(self.model_path)
                self.rf_model = bundle.get("rf_model")
                self.isolation_forest = bundle.get("isolation_forest")
                self.scaler = bundle.get("scaler")
                self.feature_names = bundle.get("features")
                self.classes = bundle.get("classes")
                if self.rf_model is not None:
                    self.rf_model.n_jobs = 1
                if self.isolation_forest is not None:
                    self.isolation_forest.n_jobs = 1
                return True
            except Exception as e:
                print(f"[WARN] Failed to load ML model from {self.model_path}: {e}")
                self.rf_model = None
                self.scaler = None
                return False
        return False

    def is_ready(self) -> bool:
        """Returns True if the supervised model and scaler are loaded and ready."""
        return self.rf_model is not None and self.scaler is not None and self.feature_names is not None

    def evaluate_flow(self, flow: Flow, is_final: bool = False) -> Optional[Tuple[str, float, str]]:
        """
        Evaluates a bidirectional Flow using the trained Random Forest classifier
        and Isolation Forest anomaly detector.

        Inference Policy:
        - If is_final is True: evaluated upon flow timeout or finalization. De-duplicated
          to ensure completed flows are not re-evaluated.
        - If is_final is False: evaluated periodically during active transmission once
          the flow has accumulated sufficient packets (>= 20) or duration (>= FLOW_WINDOW),
          throttled to at most once per second per flow stream.

        Returns:
            (threat_label, confidence_score, details_string) or None if benign/unalerted.
        """
        if not flow or not self.is_ready():
            return None

        # 1. Inference policy & de-duplication checks
        now = time.time()
        flow_key = flow.flow_id

        if is_final:
            if flow_key in self.evaluated_flows:
                return None
            self.evaluated_flows.add(flow_key)
            if len(self.evaluated_flows) > 50000:
                self.evaluated_flows.clear()
        else:
            # Active flow periodic check
            if flow.total_packets < 5 and flow.duration < 1.0:
                return None
            last_eval = self.flow_eval_history.get(flow_key, 0.0)
            if (now - last_eval) < 0.5:
                return None
            self.flow_eval_history[flow_key] = now
            if len(self.flow_eval_history) > 50000:
                self.flow_eval_history.clear()

        # 2. Extract and validate feature schema
        try:
            feat_dict = flow.to_model_features()
        except Exception:
            return None

        # Ensure all expected columns are present, replace invalid/inf values with 0.0
        row_data = {}
        for col in self.feature_names:
            val = feat_dict.get(col, 0.0)
            if val is None or np.isnan(val) or np.isinf(val):
                row_data[col] = 0.0
            else:
                row_data[col] = float(val)

        # 3. Construct DataFrame and scale features
        try:
            df_row = pd.DataFrame([row_data])[self.feature_names]
            X_scaled = self.scaler.transform(df_row)
        except Exception as e:
            return None

        # 4. Supervised ML classification (single pass for class and confidence)
        try:
            probabilities = self.rf_model.predict_proba(X_scaled)[0]
            pred_idx = int(np.argmax(probabilities))
            classes_list = self.classes if self.classes is not None else list(self.rf_model.classes_)
            prediction = classes_list[pred_idx]
            confidence = float(probabilities[pred_idx])
        except Exception:
            return None

        host = flow.initiator_ip
        last_alert = self.last_ml_alert.get(host, 0.0)

        # Alert on known attack classification with confidence >= 65%
        if str(prediction).upper() != "BENIGN" and confidence >= 0.65:
            if (now - last_alert) >= 3.0:
                self.last_ml_alert[host] = now
                details = (
                    f"Class: {prediction} | Confidence: {confidence*100:.1f}% | "
                    f"Packets: {flow.total_packets} | Duration: {flow.duration:.2f}s | "
                    f"Rate: {flow.flow_packets_per_sec:.1f} pkts/s"
                )
                return (str(prediction), confidence, details)
            return None

        # 5. Unsupervised Anomaly Detection (Isolation Forest)
        # Evaluated on benign flows to identify statistical anomalies (potential threats)
        if self.isolation_forest is not None:
            try:
                anomaly_score = float(self.isolation_forest.decision_function(X_scaled)[0])
                if anomaly_score < ANOMALY_THRESHOLD:
                    if (now - last_alert) >= 3.0:
                        self.last_ml_alert[host] = now
                        details = (
                            f"Statistical Anomaly (Score: {anomaly_score:.3f}) | "
                            f"Flow: {flow.protocol} {flow.initiator_ip}:{flow.initiator_port}->{flow.responder_port} | "
                            f"Packets: {flow.total_packets} | Bytes: {flow.total_bytes}"
                        )
                        return ("Anomaly", abs(anomaly_score), details)
            except Exception:
                pass

        return None

    def process_packet(
        self,
        pkt_data: Dict[str, Any],
        flow: Optional[Flow] = None
    ) -> Optional[Tuple[str, float, str]]:
        """
        Legacy/convenience packet interface.
        If a flow instance is provided, evaluates that flow.
        If no flow is provided, wraps pkt_data into a standalone Flow and evaluates.
        """
        if not pkt_data or not self.is_ready():
            return None

        if flow is not None:
            return self.evaluate_flow(flow, is_final=False)

        # Standalone packet evaluation fallback
        temp_flow = Flow(pkt_data)
        return self.evaluate_flow(temp_flow, is_final=True)
