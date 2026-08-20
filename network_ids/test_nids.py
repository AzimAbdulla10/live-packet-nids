import time
from detector import Detector
from logger import log_info

def test_detector_rules():
    detector = Detector()
    
    log_info("Testing Port Scan Detection Rule...")
    # Generate 20 unique ports for IP 192.168.1.100 within 1 second
    src_ip = "192.168.1.100"
    now = time.time()
    
    # We will feed 20 different ports
    for i in range(20):
        pkt = {
            "src_ip": src_ip,
            "dst_ip": "127.0.0.1",
            "protocol": "TCP",
            "src_port": 12345,
            "dst_port": 1000 + i,
            "length": 64,
            "flags": "S",
            "timestamp": now + (i * 0.05)
        }
        detector.process_packet(pkt)
        
    log_info("Testing SYN Flood Detection Rule...")
    # Generate 101 SYN packets from IP 192.168.1.200 within 1 second (flags containing 'SYN')
    src_ip_flood = "192.168.1.200"
    now = time.time()
    for i in range(101):
        pkt = {
            "src_ip": src_ip_flood,
            "dst_ip": "127.0.0.1",
            "protocol": "TCP",
            "src_port": 10000 + i,
            "dst_port": 80,
            "length": 64,
            "flags": "SYN",
            "timestamp": now + (i * 0.01)
        }
        detector.process_packet(pkt)

if __name__ == "__main__":
    test_detector_rules()
