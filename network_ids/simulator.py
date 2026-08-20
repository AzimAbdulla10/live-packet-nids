import sys
import time
import random
from scapy.all import IP, TCP, UDP, send
from config import INTERFACE

def generate_normal_traffic():
    """
    Generates normal traffic (DNS, HTTP, HTTPS, SSH) targeting localhost.
    Sends 15 packets with minor random delays.
    """
    print(f"\n[INFO] Generating normal traffic on interface {INTERFACE}...")
    target_ip = "127.0.0.1"
    protocols = [
        ("TCP", 80, "S"),    # HTTP connection start
        ("TCP", 443, "A"),   # HTTPS ack
        ("UDP", 53, None),   # DNS query
        ("TCP", 22, "PA"),   # SSH push-ack
        ("TCP", 80, "FA")    # HTTP fin-ack
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
    """
    Simulates a port scan by sending SYN packets to 26 sequential ports in under 1 second.
    This should trigger the Port Scan detection rule (>= 20 ports in 5 seconds).
    """
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
            time.sleep(0.01)  # fast scan rate
            
        print("[INFO] Port scan simulation completed.")
    except PermissionError:
        print("\n[ERROR] Permission denied. Sending raw packets requires root privileges.")
        print("Please run with: 'sudo python simulator.py'\n")
    except Exception as e:
        print(f"\n[ERROR] Simulation failed: {e}")

def simulate_syn_flood():
    """
    Simulates a SYN flood by sending 120 SYN packets to port 80 in under 1 second.
    This should trigger the SYN Flood detection rule (> 100 SYN packets in 3 seconds).
    """
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
            time.sleep(0.005)  # rapid rate
            
        print("[INFO] SYN flood simulation completed.")
    except PermissionError:
        print("\n[ERROR] Permission denied. Sending raw packets requires root privileges.")
        print("Please run with: 'sudo python simulator.py'\n")
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
    print("4. Run All Simulations (Sequential with pauses)")
    print("5. Exit")
    print("==================================================")
    
    try:
        choice = input("Select an option (1-5): ").strip()
        if choice == "1":
            generate_normal_traffic()
        elif choice == "2":
            simulate_port_scan()
        elif choice == "3":
            simulate_syn_flood()
        elif choice == "4":
            generate_normal_traffic()
            time.sleep(2)
            simulate_port_scan()
            time.sleep(2)
            simulate_syn_flood()
        elif choice == "5":
            print("Exiting simulator.")
            sys.exit(0)
        else:
            print("Invalid selection. Exiting.")
    except (KeyboardInterrupt, SystemExit):
        print("\nExiting simulator.")

if __name__ == "__main__":
    main()
