import time
from detector import Detector
from logger import log_info
from database import db
from reporter import generate_text_summary

def test_full_pipeline():
    print("==================================================")
    print("   Running End-to-End NIDS Verification Tests     ")
    print("==================================================")

    detector = Detector()

    # 1. Test Port Scan Rule Detection
    log_info("1. Testing Port Scan Signature Rule...")
    scan_ip = "192.168.1.100"
    now = time.time()
    for i in range(20):
        pkt = {
            "src_ip": scan_ip,
            "dst_ip": "127.0.0.1",
            "protocol": "TCP",
            "src_port": 12345,
            "dst_port": 1000 + i,
            "length": 64,
            "flags": "S",
            "timestamp": now + (i * 0.05)
        }
        db.insert_packet(pkt)
        detector.process_packet(pkt)

    # 2. Test SYN Flood Rule Detection
    log_info("2. Testing SYN Flood Rule Detection...")
    flood_ip = "192.168.1.200"
    now = time.time()
    for i in range(105):
        pkt = {
            "src_ip": flood_ip,
            "dst_ip": "127.0.0.1",
            "protocol": "TCP",
            "src_port": 20000 + (i % 50),
            "dst_port": 80,
            "length": 64,
            "flags": "SYN",
            "timestamp": now + (i * 0.01)
        }
        db.insert_packet(pkt)
        detector.process_packet(pkt)

    # 3. Test Machine Learning Flow Classifier (DDoS attack flow)
    log_info("3. Testing Machine Learning Classifier (Random Forest)...")
    ml_attack_ip = "10.0.0.99"
    now = time.time()
    for i in range(100):
        pkt = {
            "src_ip": ml_attack_ip,
            "dst_ip": "127.0.0.1",
            "protocol": "TCP",
            "src_port": 30000 + i,
            "dst_port": 80,
            "length": 64,
            "flags": "SYN",
            "timestamp": now + (i * 0.005)
        }
        db.insert_packet(pkt)
        detector.process_packet(pkt)

    # 4. Verify Database Records & Report Generation
    log_info("4. Verifying Database Storage & Audit Report Generation...")
    stats = db.get_stats()
    print(f"\n[DB STATS VERIFIED]")
    print(f"Total Packets in SQLite:  {stats['total_packets']}")
    print(f"Total Alerts in SQLite:   {stats['total_alerts']}")
    print(f"Rule Alerts:              {stats['rule_alerts']}")
    print(f"ML Alerts:                {stats['ml_alerts']}")

    assert stats["total_packets"] > 0, "Error: Packets were not recorded in database"
    assert stats["total_alerts"] > 0, "Error: Alerts were not recorded in database"
    assert stats["ml_alerts"] > 0, "Error: ML alerts were not recorded in database"

    report_text = generate_text_summary()
    assert "NETWORK INTRUSION DETECTION SYSTEM - AUDIT REPORT" in report_text
    print("\n[SUCCESS] All pipeline tests passed! Database, Rules, ML, and Reports verified.\n")

if __name__ == "__main__":
    test_full_pipeline()
