# Network Intrusion Detection Using Live Data Packets

This project implements a Python-based Network Intrusion Detection System (NIDS) backend. It captures live network packets, extracts key connection features, and runs rule-based checks to flag common network attacks in real-time.

---

## Folder Structure

* `main.py`: Entry point for starting the packet capture and rule detection engine.
* `packet_capture.py`: Scapy packet sniffer module with raw socket capturing.
* `feature_extractor.py`: Converts raw packet structures into standard Python dictionaries for modular processing.
* `detector.py`: Sliding-window rule engine for intrusion signature detection.
* `simulator.py`: Loopback traffic simulator to run harmless test cases locally.
* `logger.py`: ANSI-colored CLI terminal logs.
* `config.py`: Thresholds and interface parameters.
* `requirements.txt`: Project library dependencies.

---

## Getting Started

### 1. Install Dependencies

Install required dependencies (primarily Scapy) using `pip`:

```bash
pip install -r requirements.txt
```

### 2. Start the NIDS

Because live network sniffing accesses raw sockets, the main program must run with root/administrator privileges:

```bash
sudo python main.py
```

### 3. Generate Simulated Traffic

To test the intrusion detection rules without disturbing external network traffic, run the localhost-only traffic simulator in a separate terminal:

```bash
python simulator.py
# (Note: sending custom raw packets may also require 'sudo python simulator.py' depending on your OS)
```

---

## Detection Rules Implemented

1. **Port Scan Detection (`[ALERT]`)**
   * Triggered if a single source IP attempts to contact **20 or more unique ports within 5 seconds**.
   * Output lists the scanner source IP and the set of ports contacted.

2. **SYN Flood Detection (`[CRITICAL]`)**
   * Triggered if a source IP transmits **more than 100 SYN packets within 3 seconds**.
   * Output lists the attacker source IP and the total count of SYN packets detected.
