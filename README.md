# Network Intrusion Detection Using Live Data Packets (NIDS)

A production-grade, hybrid Network Intrusion Detection System (NIDS) integrating live raw packet capture, bitmask TCP flag extraction, bidirectional network flow tracking, signature-based rule detection, supervised Machine Learning (Random Forest trained on official CIC-IDS2017 features), unsupervised anomaly detection (Isolation Forest), unified threat correlation, SQLite persistence, and an enterprise telemetry console.

---

## Architecture Overview

```
                          ┌──────────────────────┐
                          │ Live Network Packets │
                          └──────────┬───────────┘
                                     │
                           [packet_capture.py]
                        (Batch SQLite buffer / pcap)
                                     │
                          [feature_extractor.py]
                    (Bitmask TCP flags / ICMP type+code)
                                     │
                    ┌────────────────┴────────────────┐
                    │                                 │
                    ▼                                 ▼
         [Signature Rules: detector.py]    [flow_tracker.py]
         • Port Scan (sliding window)      • Canonical 5-tuple flows
         • SYN Flood (pure SYN vs ACK)     • Welford streaming stats
                    │                      • Idle/Active timeouts
                    │                                 │
                    │                      ┌──────────┴──────────┐
                    │                      ▼                     ▼
                    │           [ml_detector.py]        [flow_summaries]
                    │           • Random Forest         (SQLite Storage)
                    │           • Isolation Forest
                    │                      │
                    └──────────────┬───────┘
                                   │
                                   ▼
                       [threat_decision.py]
                 (Unified Threat Decision Engine)
                 • Multi-engine alert correlation
                 • Hybrid corroboration & escalation
                 • Host / Flow deduplication window
                                   │
                                   ▼
                      [SQLite Database: nids.db]
                      • packets
                      • alerts
                      • flow_summaries
                      • system_metrics
                                   │
                    ┌──────────────┴──────────────┐
                    ▼                             ▼
        [dashboard.py (Streamlit)]    [reporter.py (CLI/CSV)]
        • Real-time incident stream   • Text audit report
        • Flows & attacker metrics    • Alert & Flow CSV export
```

---

## File Structure

* `main.py`: Application entry point initializing packet sniffer, flow tracker, and graceful shutdown flow flusher.
* `packet_capture.py`: Hardened Scapy capture loop with batch database inserts, pcap integration, and error rate limiting.
* `feature_extractor.py`: Robust packet parser extracting normalized 5-tuples, bitmask TCP flags (SYN, ACK, FIN, RST, PSH, URG), and ICMP codes.
* `flow_tracker.py`: High-performance bidirectional flow tracker with canonical keys, Welford incremental statistics, bounded LRU capacity, and CIC-IDS2017 feature mapping.
* `detector.py`: Pipeline coordinator executing $O(1)$ sliding window signature rules, dispatching flows to ML, and enforcing persistence.
* `ml_detector.py`: High-throughput supervised Random Forest and unsupervised Isolation Forest inference engine with single-pass prediction and rate throttling.
* `threat_decision.py`: Unified threat decision engine normalizing observations (`RULE`, `ML`, `ANOMALY`), correlating related events into incidents, and upgrading corroborations to `HYBRID`.
* `database.py`: Thread-safe SQLite manager maintaining `packets`, `alerts`, `system_metrics`, and `flow_summaries` tables with indexing and deduplication constraints.
* `model_trainer.py`: Trains Random Forest and Isolation Forest on official CIC-IDS2017 flows and serializes artifact bundle to `models/`.
* `download_dataset.py`: Extracts balanced subsets of 30,000 real flows from Friday CIC-IDS2017 captures (`BENIGN`, `PortScan`, `DDoS`).
* `reporter.py`: CLI security audit reporter with console summaries, alert CSV export, and flow summary CSV export.
* `dashboard.py`: Streamlit telemetry console displaying KPI cards, attacker breakdowns, multi-engine incident feeds, and live flow summaries.
* `simulator.py`: Test traffic simulator supporting raw localhost transmission and deterministic mock packet generation for normal, port scan, SYN flood, DDoS, and anomaly profiles.
* `config.py`: Centralized thresholds, windows, database paths, and model configurations.

---

## Benchmarks & Evaluation Results

Evaluated on official held-out test split (6,000 flows) of **CIC-IDS2017**:

| Metric | Result |
| :--- | :--- |
| **Overall Model Accuracy** | **99.92%** (5,995 / 6,000 correct) |
| **Benign False Positive Rate (FPR)** | **0.150%** (3 / 2,000) |
| **DDoS False Negative Rate (FNR)** | **0.050%** (1 / 2,000) |
| **PortScan False Negative Rate (FNR)** | **0.050%** (1 / 2,000) |
| **Strictly Disjoint Accuracy (Zero Train Overlap)** | **99.91%** (Macro F1: 0.9991) |
| **Per-Flow Inference Latency** | **1.540 ms** (Median) / **1.854 ms** (P95) |
| **Pipeline Throughput** | **27,400+ pkts/sec** (Single-threaded CPU) |
| **Batch Flow Persistence Throughput** | **248,000+ flows/sec** (SQLite executemany) |

### Confusion Matrix (Held-out Test Split)
```
True \ Pred          BENIGN         DDoS     PortScan
BENIGN                 1997            0            3
DDoS                      1         1999            0
PortScan                  1            0         1999
```

---

## Getting Started

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Retrain the Machine Learning Model (Optional)
The pre-trained model bundle is already serialized at `models/nids_classifier.joblib`. To retrain the Random Forest and Isolation Forest models from scratch:
```bash
python model_trainer.py
```

### 3. Run the Live Intrusion Detection System
Raw socket sniffing requires raw socket privileges:
```bash
sudo python main.py
```

### 4. Run the Traffic Simulator
Simulate attack and benign traffic on localhost (`127.0.0.1`):
```bash
# Interactive menu:
sudo python simulator.py

# Automated CLI execution:
sudo python simulator.py --attack all
sudo python simulator.py --attack portscan
sudo python simulator.py --attack synflood
sudo python simulator.py --attack ddos
sudo python simulator.py --attack anomaly

# Offline dry-run (no raw sockets needed):
python simulator.py --dry-run --attack portscan
```

### 5. Launch the Security Telemetry Console
Start the Streamlit dashboard in a separate terminal:
```bash
streamlit run dashboard.py
```

### 6. Generate Security Audit Reports
View real-time database summaries and export audit reports:
```bash
# Display summary in terminal:
python reporter.py --summary

# Export security alerts to CSV:
python reporter.py --export-csv incident_report.csv

# Export bidirectional flow summaries to CSV:
python reporter.py --export-flows flows_report.csv
```
