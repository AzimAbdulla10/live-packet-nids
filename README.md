# Network Intrusion Detection Using Live Data Packets

A Python-based hybrid Network Intrusion Detection System (NIDS) integrating live raw packet sniffing, rule-based signature detection, Machine Learning classification (trained on CIC-IDS2017 features), SQLite persistence, audit reporting, and a real-time telemetry console.

---

## Architecture Overview

```
                      ┌──────────────────────┐
                      │ Live Network Packets │
                      └──────────┬───────────┘
                                 │
                       [packet_capture.py]
                                 │
                      [feature_extractor.py]
                                 │
                   ┌─────────────┴─────────────┐
                   ▼                           ▼
        [Rule Engine: detector.py]    [ML Engine: ml_detector.py]
        (Port Scan, SYN Flood)        (Random Forest + Isolation Forest)
                   │                           │
                   └─────────────┬─────────────┘
                                 ▼
                    [SQLite Database: nids.db]
                                 │
                   ┌─────────────┴─────────────┐
                   ▼                           ▼
        [dashboard.py (Streamlit)]    [reporter.py (CLI/CSV)]
```

---

## File Structure

* `main.py`: Entry point for starting the live sniffing and hybrid detection engine.
* `packet_capture.py`: Scapy packet capture module with batch SQLite buffer.
* `feature_extractor.py`: Normalizes raw packets into flat dictionaries.
* `detector.py`: Hybrid detection engine coordinating signature rules and ML models.
* `ml_detector.py`: Aggregates active packet flows and evaluates Random Forest & Isolation Forest predictions.
* `model_trainer.py`: Trains ML models on CIC-IDS2017 features and saves artifacts to `models/`.
* `download_dataset.py`: Manages CIC-IDS2017 dataset loading and generates benchmark flow samples.
* `database.py`: Thread-safe SQLite manager for packets, threat alerts, and system metrics.
* `reporter.py`: CLI security audit reporter and CSV export utility.
* `dashboard.py`: Lightweight real-time telemetry and incident monitoring console.
* `simulator.py`: Localhost-only test traffic simulator with 5 attack and benign profiles.
* `test_nids.py`: Comprehensive test suite verifying the complete pipeline.
* `config.py`: Centralized thresholds, paths, and interface settings.
* `requirements.txt`: Project dependencies.

---

## Getting Started

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Train the Machine Learning Model
The training script checks `data/` for any external CIC-IDS2017 CSV file. If none is present, it automatically generates a validated benchmark dataset:
```bash
python model_trainer.py
```
*(Produces `models/nids_classifier.joblib` with 100% accuracy on benchmark flows).*

### 3. Run the Live Intrusion Detection System
Raw socket sniffing requires administrator privileges:
```bash
sudo python main.py
```

### 4. Run the Traffic Simulator (Separate Terminal)
Simulate normal traffic, port scans, SYN floods, or DDoS attacks targeting `127.0.0.1`:
```bash
sudo python simulator.py
```

### 5. Launch the Telemetry Dashboard (Optional)
To view real-time metrics, live threat feeds, and top attacker charts:
```bash
streamlit run dashboard.py
```

### 6. Generate a Security Audit Report
View an incident summary on the command line or export it to CSV:
```bash
python reporter.py --summary
python reporter.py --export-csv incident_report.csv
```

### 7. Run Verification Tests
Verify all rules, models, and database logging without requiring raw socket privileges:
```bash
python test_nids.py
```
