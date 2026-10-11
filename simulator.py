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

def main():
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
        elif choice == "7":
            print("Exiting simulator.")
            sys.exit(0)
        else:
            print("Invalid selection. Exiting.")
    except (KeyboardInterrupt, SystemExit):
        print("\nExiting simulator.")

if __name__ == "__main__":
    main()
