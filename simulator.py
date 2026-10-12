import sys
import time
import random
from scapy.all import IP, TCP, UDP, send
from config import INTERFACE

def generate_normal_traffic():
    print(f"\n[INFO] Generating normal traffic on interface {INTERFACE}...")
    target_ip = "127.0.0.1"
    protocols = [
        ("TCP", 80, "S"),
        ("TCP", 443, "A"),
        ("UDP", 53, None),
        ("TCP", 22, "PA"),
        ("TCP", 80, "FA")
    ]
    
    try:
        for i in range(15):
            proto, port, flags = random.choice(protocols)
            sport = random.randint(49152, 65535)
            
            if proto == "TCP":
                pkt = IP(src=target_ip, dst=target_ip)/TCP(sport=sport, dport=port, flags=flags)
            else:
                pkt = IP(src=target_ip, dst=target_ip)/UDP(sport=sport, dport=port)
            
            send(pkt, iface=INTERFACE, verbose=0)
            print(f"Sent normal packet {i+1}/15: {proto} to port {port}")
            time.sleep(random.uniform(0.1, 0.4))
            
        print("[INFO] Normal traffic generation completed.")
    except PermissionError:
        print("\n[ERROR] Permission denied. Sending raw packets requires root privileges.")
        print("Please run with: 'sudo python simulator.py'\n")
    except Exception as e:
        print(f"\n[ERROR] Simulation failed: {e}")

def simulate_port_scan():
    print(f"\n[INFO] Simulating port scan on interface {INTERFACE}...")
    target_ip = "127.0.0.1"
    start_port = 20
    end_port = 45
    
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

def simulate_syn_flood():
    print(f"\n[INFO] Simulating SYN flood on interface {INTERFACE}...")
    target_ip = "127.0.0.1"
    packet_count = 120
    
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

def simulate_ddos():
    print(f"\n[INFO] Simulating DDoS flood on interface {INTERFACE} (testing ML classifier)...")
    target_ip = "127.0.0.1"
    packet_count = 150
    try:
        for i in range(packet_count):
            sport = random.randint(1024, 65535)
            # Mixed TCP/UDP flood to port 80/443
            if i % 2 == 0:
                pkt = IP(src=target_ip, dst=target_ip)/TCP(sport=sport, dport=80, flags="S")
            else:
                pkt = IP(src=target_ip, dst=target_ip)/UDP(sport=sport, dport=443)
            send(pkt, iface=INTERFACE, verbose=0)
            if (i + 1) % 30 == 0:
                print(f"Sent {i+1}/{packet_count} DDoS flood packets...")
            time.sleep(0.003)
        print("[INFO] DDoS flood simulation completed.")
    except Exception as e:
        print(f"\n[ERROR] Simulation failed: {e}")

def simulate_anomaly():
    print(f"\n[INFO] Simulating zero-day anomaly traffic on interface {INTERFACE}...")
    target_ip = "127.0.0.1"
    try:
        # High entropy packet sizes to exotic unassigned high ports
        for i in range(30):
            exotic_port = random.randint(32000, 48000)
            pkt = IP(src=target_ip, dst=target_ip)/TCP(sport=exotic_port, dport=exotic_port, flags="SEC")
            send(pkt, iface=INTERFACE, verbose=0)
            time.sleep(0.02)
        print("[INFO] Anomaly simulation completed.")
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
    parser.add_argument("--attack", choices=["normal", "portscan", "synflood", "ddos", "anomaly", "all"],
                        help="Specific attack type to simulate")
    parser.add_argument("--dry-run", action="store_true",
                        help="Generate mock packets without transmitting on raw socket")
    args = parser.parse_args()

    if args.dry_run:
        attack = args.attack or "normal"
        pkts = generate_mock_packets(attack)
        print(f"[INFO] Dry-run generated {len(pkts)} mock packets for '{attack}'.")
        for p in pkts[:5]:
            print(" ", p)
        return

    if args.attack:
        if args.attack == "normal":
            generate_normal_traffic()
        elif args.attack == "portscan":
            simulate_port_scan()
        elif args.attack == "synflood":
            simulate_syn_flood()
        elif args.attack == "ddos":
            simulate_ddos()
        elif args.attack == "anomaly":
            simulate_anomaly()
        elif args.attack == "all":
            generate_normal_traffic()
            time.sleep(1)
            simulate_port_scan()
            time.sleep(1)
            simulate_syn_flood()
            time.sleep(1)
            simulate_ddos()
            time.sleep(1)
            simulate_anomaly()
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
