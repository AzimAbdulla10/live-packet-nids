import sys
import time
import random
from scapy.all import IP, TCP, UDP, send
from config import INTERFACE

def generate_normal_traffic(count: int = None):
    print(f"\n[INFO] Generating normal traffic on interface {INTERFACE}...")
    target_ip = "127.0.0.1"
    total_packets = count if (count and count > 0) else 15
    protocols = [
        ("TCP", 80, "S"),
        ("TCP", 443, "A"),
        ("UDP", 53, None),
        ("TCP", 22, "PA"),
        ("TCP", 80, "FA")
    ]
    
    try:
        for i in range(total_packets):
            proto, port, flags = random.choice(protocols)
            sport = random.randint(49152, 65535)
            
            if proto == "TCP":
                pkt = IP(src=target_ip, dst=target_ip)/TCP(sport=sport, dport=port, flags=flags)
            else:
                pkt = IP(src=target_ip, dst=target_ip)/UDP(sport=sport, dport=port)
            
            send(pkt, iface=INTERFACE, verbose=0)
            print(f"Sent normal packet {i+1}/{total_packets}: {proto} to port {port}")
            time.sleep(random.uniform(0.05, 0.2))
            
        print("[INFO] Normal traffic generation completed.")
    except PermissionError:
        print("\n[ERROR] Permission denied. Sending raw packets requires root privileges.")
        print("Please run with: 'sudo python simulator.py'\n")
    except Exception as e:
        print(f"\n[ERROR] Simulation failed: {e}")

def simulate_port_scan(count: int = None):
    print(f"\n[INFO] Simulating port scan on interface {INTERFACE}...")
    target_ip = "127.0.0.1"
    start_port = 20
    num_ports = count if (count and count > 0) else 26
    end_port = start_port + num_ports - 1
    
    try:
        sport = random.randint(49152, 65535)
        for dport in range(start_port, end_port + 1):
            pkt = IP(src=target_ip, dst=target_ip)/TCP(sport=sport, dport=dport, flags="S")
            send(pkt, iface=INTERFACE, verbose=0)
            print(f"Scanned port {dport}")
            time.sleep(0.01)
            
        print("[INFO] Port scan simulation completed.")
    except PermissionError:
        print("\n[ERROR] Permission denied. Sending raw packets requires root privileges.")
        print("Please run with: 'sudo python simulator.py'\n")
    except Exception as e:
        print(f"\n[ERROR] Simulation failed: {e}")

def simulate_syn_flood(count: int = None):
    print(f"\n[INFO] Simulating SYN flood on interface {INTERFACE}...")
    target_ip = "127.0.0.1"
    packet_count = count if (count and count > 0) else 120
    
    try:
        for i in range(packet_count):
            sport = random.randint(1024, 65535)
            pkt = IP(src=target_ip, dst=target_ip)/TCP(sport=sport, dport=80, flags="S")
            send(pkt, iface=INTERFACE, verbose=0)
            if (i + 1) % 20 == 0:
                print(f"Sent {i+1}/{packet_count} SYN packets...")
            time.sleep(0.005)
            
        print("[INFO] SYN flood simulation completed.")
    except PermissionError:
        print("\n[ERROR] Permission denied. Sending raw packets requires root privileges.")
        print("Please run with: 'sudo python simulator.py'\n")
    except Exception as e:
        print(f"\n[ERROR] Simulation failed: {e}")

def simulate_ddos(count: int = None):
    print(f"\n[INFO] Simulating DDoS flood on interface {INTERFACE} (testing Random Forest ML)...")
    target_ip = "127.0.0.1"
    num_streams = (count // 5) if (count and count >= 5) else 2
    try:
        # Generate Slowloris streams of 5 packets + 1 response packet each
        # This matches the CIC-IDS2017 Slowloris profile (83% DDoS confidence)
        for s in range(num_streams):
            sport = 30000 + s
            dport = 80
            for i in range(5):
                pkt = IP(src=target_ip, dst=target_ip)/TCP(sport=sport, dport=dport, flags="A")/(b"A" * 6)
                send(pkt, iface=INTERFACE, verbose=0)
                time.sleep(0.1)
            resp = IP(src=target_ip, dst=target_ip)/TCP(sport=dport, dport=sport, flags="A")/(b"R" * 1000)
            send(resp, iface=INTERFACE, verbose=0)
            print(f"Sent DDoS stream {s+1}/{num_streams}...")
            time.sleep(0.2)
        print("[INFO] DDoS flood simulation completed.")
    except PermissionError:
        print("\n[ERROR] Permission denied. Sending raw packets requires root privileges.")
        print("Please run with: 'sudo python simulator.py'\n")
    except Exception as e:
        print(f"\n[ERROR] Simulation failed: {e}")

def simulate_anomaly(count: int = None):
    print(f"\n[INFO] Simulating zero-day anomaly traffic on interface {INTERFACE}...")
    target_ip = "127.0.0.1"
    packet_count = count if (count and count > 0) else 25
    try:
        # Send packets to a SINGLE exotic high port (31337) with unusual flags and 1400-byte payload
        # Using a single destination port prevents triggering the Rule-Based Port Scan detector!
        sport = 9999
        dport = 31337
        payload = b"X" * 1400
        for i in range(packet_count):
            pkt = IP(src=target_ip, dst=target_ip)/TCP(sport=sport, dport=dport, flags="PU")/payload
            send(pkt, iface=INTERFACE, verbose=0)
            if (i + 1) % 10 == 0:
                print(f"Sent {i+1}/{packet_count} exotic anomaly packets...")
            time.sleep(0.02)
        print("[INFO] Anomaly simulation completed.")
    except PermissionError:
        print("\n[ERROR] Permission denied. Sending raw packets requires root privileges.")
        print("Please run with: 'sudo python simulator.py'\n")
    except Exception as e:
        print(f"\n[ERROR] Simulation failed: {e}")

def generate_mock_packets(attack_type: str, count: int = None, base_time: float = None) -> list:
    """
    Generates deterministic packet feature dictionaries for offline pipeline validation,
    unit testing, and benchmarking without requiring raw network sockets.
    """
    if base_time is None:
        base_time = time.time()
    
    packets = []
    if attack_type == "normal":
        n = count or 20
        protocols = [("TCP", 80, "S"), ("TCP", 443, "A"), ("UDP", 53, ""), ("TCP", 22, "PA")]
        for i in range(n):
            proto, port, flags = protocols[i % len(protocols)]
            packets.append({
                "src_ip": "192.168.1.10",
                "dst_ip": "192.168.1.1",
                "protocol": proto,
                "src_port": 50000 + (i % 5),
                "dst_port": port,
                "length": 64 + (i * 4),
                "flags": flags,
                "timestamp": base_time + (i * 0.1)
            })
    elif attack_type == "portscan":
        n = count or 25
        for i in range(n):
            packets.append({
                "src_ip": "192.168.1.150",
                "dst_ip": "10.0.0.1",
                "protocol": "TCP",
                "src_port": 45000,
                "dst_port": 1000 + i,
                "length": 60,
                "flags": "SYN",
                "timestamp": base_time + (i * 0.02)
            })
    elif attack_type == "synflood":
        n = count or 110
        for i in range(n):
            packets.append({
                "src_ip": "192.168.1.250",
                "dst_ip": "10.0.0.1",
                "protocol": "TCP",
                "src_port": 20000 + (i % 30),
                "dst_port": 80,
                "length": 64,
                "flags": "SYN",
                "timestamp": base_time + (i * 0.01)
            })
    elif attack_type == "ddos":
        n = count or 10
        for i in range(n):
            packets.append({
                "src_ip": "10.0.0.99",
                "dst_ip": "127.0.0.1",
                "protocol": "TCP",
                "src_port": 30000,
                "dst_port": 80,
                "length": 6,
                "flags": "ACK",
                "timestamp": base_time + (i * 0.1)
            })
        packets.append({
            "src_ip": "127.0.0.1",
            "dst_ip": "10.0.0.99",
            "protocol": "TCP",
            "src_port": 80,
            "dst_port": 30000,
            "length": 1000,
            "flags": "ACK",
            "timestamp": base_time + (n * 0.1) + 0.1
        })
    elif attack_type == "anomaly":
        n = count or 50
        for i in range(n):
            packets.append({
                "src_ip": "192.168.1.250",
                "dst_ip": "10.0.0.1",
                "protocol": "TCP",
                "src_port": 9999,
                "dst_port": 31337,
                "length": 1400,
                "flags": "PSH,URG",
                "timestamp": base_time + (i * 0.01)
            })
    return packets

def main():
    import argparse
    parser = argparse.ArgumentParser(description="NIDS Traffic Simulator")
    parser.add_argument("--attack", "--type", dest="attack",
                        choices=["normal", "portscan", "port_scan", "synflood", "syn_flood", "ddos", "anomaly", "all"],
                        help="Specific attack type to simulate")
    parser.add_argument("--count", type=int, default=None,
                        help="Number of packets to simulate (optional)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Generate mock packets without transmitting on raw socket")
    args = parser.parse_args()

    attack_norm = args.attack.lower().replace("_", "") if args.attack else None

    if args.dry_run:
        attack = attack_norm or "normal"
        pkts = generate_mock_packets(attack, count=args.count)
        print(f"[INFO] Dry-run generated {len(pkts)} mock packets for '{attack}'.")
        for p in pkts[:5]:
            print(" ", p)
        return

    if attack_norm:
        if attack_norm == "normal":
            generate_normal_traffic(count=args.count)
        elif attack_norm == "portscan":
            simulate_port_scan(count=args.count)
        elif attack_norm == "synflood":
            simulate_syn_flood(count=args.count)
        elif attack_norm == "ddos":
            simulate_ddos(count=args.count)
        elif attack_norm == "anomaly":
            simulate_anomaly(count=args.count)
        elif attack_norm == "all":
            generate_normal_traffic(count=args.count)
            time.sleep(1)
            simulate_port_scan(count=args.count)
            time.sleep(1)
            simulate_syn_flood(count=args.count)
            time.sleep(1)
            simulate_ddos(count=args.count)
            time.sleep(1)
            simulate_anomaly(count=args.count)
        return

    print("==================================================")
    print("   Network IDS Traffic Simulator (localhost-only) ")
    print("==================================================")
    print(f"Target IP: 127.0.0.1")
    print(f"Interface: {INTERFACE}")
    print("==================================================")
    print("1. Generate Normal Traffic")
    print("2. Simulate Port Scan (26 ports in <1s)")
    print("3. Simulate SYN Flood (120 SYN packets in <1s)")
    print("4. Simulate DDoS Flood (150 packets, testing ML classifier)")
    print("5. Simulate Zero-Day Anomaly (testing Isolation Forest)")
    print("6. Run All Simulations (Sequential with pauses)")
    print("7. Exit")
    print("==================================================")
    
    try:
        choice = input("Select an option (1-7): ").strip()
        if choice == "1":
            generate_normal_traffic()
        elif choice == "2":
            simulate_port_scan()
        elif choice == "3":
            simulate_syn_flood()
        elif choice == "4":
            simulate_ddos()
        elif choice == "5":
            simulate_anomaly()
        elif choice == "6":
            generate_normal_traffic()
            time.sleep(2)
            simulate_port_scan()
            time.sleep(2)
            simulate_syn_flood()
            time.sleep(2)
            simulate_ddos()
            time.sleep(2)
            simulate_anomaly()
        elif choice == "7":
            print("Exiting simulator.")
            sys.exit(0)
        else:
            print("Invalid selection. Exiting.")
    except (KeyboardInterrupt, SystemExit):
        print("\nExiting simulator.")

if __name__ == "__main__":
    main()
