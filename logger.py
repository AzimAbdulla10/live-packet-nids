import sys
from datetime import datetime

# Term colors
COLOR_RESET = "\033[0m"
COLOR_BOLD = "\033[1m"
COLOR_INFO = "\033[94m"      # Blue
COLOR_PACKET = "\033[92m"    # Green
COLOR_ALERT = "\033[93m"     # Yellow
COLOR_CRITICAL = "\033[91m"  # Red

def log_info(message: str):
    print(f"{COLOR_BOLD}{COLOR_INFO}[INFO]{COLOR_RESET} {message}")
    sys.stdout.flush()

def log_packet(pkt_data: dict):
    # Print out packet info in the requested terminal style
    time_str = datetime.fromtimestamp(pkt_data.get("timestamp", datetime.now().timestamp())).strftime("%H:%M:%S")
    protocol = pkt_data.get("protocol", "UNKNOWN")
    src = pkt_data.get("src_ip", "UNKNOWN")
    dst = pkt_data.get("dst_ip", "UNKNOWN")
    src_port = pkt_data.get("src_port")
    dst_port = pkt_data.get("dst_port")
    length = pkt_data.get("length", 0)
    flags = pkt_data.get("flags", "")

    src_str = f"{src}:{src_port}" if src_port is not None else src
    dst_str = f"{dst}:{dst_port}" if dst_port is not None else dst

    print(f"\n{COLOR_BOLD}[{time_str}]{COLOR_RESET}")
    print(f"{COLOR_BOLD}{COLOR_PACKET}[PACKET] {protocol}{COLOR_RESET}")
    print(f"{src_str} {COLOR_BOLD}→{COLOR_RESET} {dst_str}")
    print(f"Length: {length}")
    if flags:
        print(f"Flags: {flags}")
    sys.stdout.flush()

def log_alert(src_ip: str, ports: list):
    # Format ports list to comma separated string
    ports_str = ",".join(map(str, sorted(ports)))
    print(f"\n{COLOR_BOLD}{COLOR_ALERT}[ALERT]")
    print("Possible Port Scan")
    print(f"\nSource:\n{src_ip}")
    print(f"\nPorts contacted:\n{ports_str}{COLOR_RESET}\n")
    sys.stdout.flush()

def log_critical(src_ip: str, syn_count: int):
    print(f"\n{COLOR_BOLD}{COLOR_CRITICAL}[CRITICAL]")
    print("Possible SYN Flood")
    print(f"\nSource:\n{src_ip}")
    print(f"\nSYN Count:\n{syn_count}{COLOR_RESET}\n")
    sys.stdout.flush()
