import os
import sys
import numpy as np
import pandas as pd
from config import DATA_DIR

CICIDS_SAMPLE_PATH = os.path.join(DATA_DIR, "cicids2017_sample.csv")
CICIDS_REAL_PATH = os.path.join(DATA_DIR, "cicids2017_real.csv")
ARCHIVE_DIR = "archive"

def ensure_data_dir():
    os.makedirs(DATA_DIR, exist_ok=True)

def extract_real_cicids_from_archive(output_path: str = CICIDS_REAL_PATH) -> str:
    """
    Extracts a balanced, high-performance sample of 30,000 real network flows
    from the official CIC-IDS2017 CSVs located in archive/.
    """
    if not os.path.exists(ARCHIVE_DIR):
        return None

    portscan_file = os.path.join(ARCHIVE_DIR, "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv")
    ddos_file = os.path.join(ARCHIVE_DIR, "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")

    if not (os.path.exists(portscan_file) and os.path.exists(ddos_file)):
        return None

    print("[INFO] Found official CIC-IDS2017 CSVs in archive/ folder!")
    print("[INFO] Extracting balanced subset of 30,000 real attack and benign flows...")

    # 1. PortScan & Benign from Friday afternoon
    df_ps = pd.read_csv(portscan_file)
    df_ps.columns = df_ps.columns.str.strip()
    ps_subset = df_ps[df_ps["Label"] == "PortScan"].sample(n=10000, random_state=42)
    benign_subset = df_ps[df_ps["Label"] == "BENIGN"].sample(n=10000, random_state=42)

    # 2. DDoS from Friday afternoon
    df_ddos = pd.read_csv(ddos_file)
    df_ddos.columns = df_ddos.columns.str.strip()
    ddos_subset = df_ddos[df_ddos["Label"] == "DDoS"].sample(n=10000, random_state=42)

    combined = pd.concat([benign_subset, ps_subset, ddos_subset], ignore_index=True)
    ensure_data_dir()
    combined.to_csv(output_path, index=False)
    print(f"[SUCCESS] Real CIC-IDS2017 dataset prepared at: {output_path}")
    print(f"[INFO] Classes extracted:\n{combined['Label'].value_counts().to_string()}\n")
    return output_path

def find_existing_cicids_csv():
    ensure_data_dir()
    
    # 1. Check if real extracted dataset already exists
    if os.path.exists(CICIDS_REAL_PATH):
        return CICIDS_REAL_PATH

    # 2. Check if archive/ exists and extract real flows
    if os.path.exists(ARCHIVE_DIR):
        real_csv = extract_real_cicids_from_archive(CICIDS_REAL_PATH)
        if real_csv:
            return real_csv

    # 3. Check for any CSV in data/
    for f in os.listdir(DATA_DIR):
        if f.endswith(".csv"):
            return os.path.join(DATA_DIR, f)

    return None

def generate_cicids_benchmark_dataset(output_path: str = CICIDS_SAMPLE_PATH, num_samples: int = 5000):
    ensure_data_dir()
    print(f"[INFO] Generating CIC-IDS2017 benchmark dataset ({num_samples} flows)...")
    np.random.seed(42)

    benign_count = int(num_samples * 0.50)
    portscan_count = int(num_samples * 0.25)
    ddos_count = int(num_samples * 0.25)

    data = []

    for _ in range(benign_count):
        port = np.random.choice([80, 443, 53, 22, 8080, 5353])
        duration = np.random.uniform(500, 50000)
        fwd_pkts = np.random.randint(2, 40)
        bwd_pkts = np.random.randint(2, 40)
        avg_pkt_size = np.random.uniform(200, 1200)
        total_len = fwd_pkts * avg_pkt_size
        syn_flags = 1
        ack_flags = np.random.randint(1, fwd_pkts + bwd_pkts)
        flow_pkts_s = (fwd_pkts + bwd_pkts) / (duration / 1e6 + 1e-5)
        flow_bytes_s = total_len / (duration / 1e6 + 1e-5)
        iat_mean = duration / (fwd_pkts + bwd_pkts)

        data.append({
            "Destination Port": port,
            "Flow Duration": duration,
            "Total Fwd Packets": fwd_pkts,
            "Total Backward Packets": bwd_pkts,
            "Total Length of Fwd Packets": total_len,
            "Fwd Packet Length Mean": avg_pkt_size,
            "Bwd Packet Length Mean": avg_pkt_size * np.random.uniform(0.8, 1.2),
            "Flow Bytes/s": flow_bytes_s,
            "Flow Packets/s": flow_pkts_s,
            "Flow IAT Mean": iat_mean,
            "Fwd IAT Mean": iat_mean * np.random.uniform(0.8, 1.2),
            "SYN Flag Count": syn_flags,
            "ACK Flag Count": ack_flags,
            "Average Packet Size": avg_pkt_size,
            "Label": "BENIGN"
        })

    for _ in range(portscan_count):
        port = np.random.randint(20, 1024)
        duration = np.random.uniform(10, 500)
        fwd_pkts = np.random.choice([1, 2])
        bwd_pkts = np.random.choice([0, 1])
        avg_pkt_size = np.random.uniform(40, 74)
        total_len = fwd_pkts * avg_pkt_size
        syn_flags = 1
        ack_flags = 0
        flow_pkts_s = (fwd_pkts + bwd_pkts) / (duration / 1e6 + 1e-5)
        flow_bytes_s = total_len / (duration / 1e6 + 1e-5)
        iat_mean = duration / max(1, (fwd_pkts + bwd_pkts))

        data.append({
            "Destination Port": port,
            "Flow Duration": duration,
            "Total Fwd Packets": fwd_pkts,
            "Total Backward Packets": bwd_pkts,
            "Total Length of Fwd Packets": total_len,
            "Fwd Packet Length Mean": avg_pkt_size,
            "Bwd Packet Length Mean": 0.0,
            "Flow Bytes/s": flow_bytes_s,
            "Flow Packets/s": flow_pkts_s,
            "Flow IAT Mean": iat_mean,
            "Fwd IAT Mean": iat_mean,
            "SYN Flag Count": syn_flags,
            "ACK Flag Count": ack_flags,
            "Average Packet Size": avg_pkt_size,
            "Label": "PortScan"
        })

    for _ in range(ddos_count):
        port = np.random.choice([80, 443])
        duration = np.random.uniform(5000, 100000)
        fwd_pkts = np.random.randint(80, 500)
        bwd_pkts = np.random.randint(0, 5)
        avg_pkt_size = np.random.uniform(54, 80)
        total_len = fwd_pkts * avg_pkt_size
        syn_flags = fwd_pkts
        ack_flags = 0
        flow_pkts_s = (fwd_pkts + bwd_pkts) / (duration / 1e6 + 1e-5)
        flow_bytes_s = total_len / (duration / 1e6 + 1e-5)
        iat_mean = duration / max(1, (fwd_pkts + bwd_pkts))

        data.append({
            "Destination Port": port,
            "Flow Duration": duration,
            "Total Fwd Packets": fwd_pkts,
            "Total Backward Packets": bwd_pkts,
            "Total Length of Fwd Packets": total_len,
            "Fwd Packet Length Mean": avg_pkt_size,
            "Bwd Packet Length Mean": 0.0,
            "Flow Bytes/s": flow_bytes_s,
            "Flow Packets/s": flow_pkts_s,
            "Flow IAT Mean": iat_mean,
            "Fwd IAT Mean": iat_mean,
            "SYN Flag Count": syn_flags,
            "ACK Flag Count": ack_flags,
            "Average Packet Size": avg_pkt_size,
            "Label": "DDoS"
        })

    df = pd.DataFrame(data)
    df.to_csv(output_path, index=False)
    print(f"[SUCCESS] Benchmark dataset written to: {output_path}")
    return output_path

if __name__ == "__main__":
    existing = find_existing_cicids_csv()
    if existing:
        print(f"[INFO] Using dataset at: {existing}")
    else:
        generate_cicids_benchmark_dataset()
