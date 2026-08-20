import os
import platform

# Network Interface Configuration
# Default to macOS loopback interface 'lo0' since local simulations run on 127.0.0.1.
# On Linux this is typically 'lo'. Can also be overridden by setting the NIDS_INTERFACE environment variable.
SYSTEM_OS = platform.system().lower()
DEFAULT_INTERFACE = "lo0" if "darwin" in SYSTEM_OS else "lo"
INTERFACE = os.environ.get("NIDS_INTERFACE", DEFAULT_INTERFACE)

# Port Scan Detection Parameters
# If one source IP attempts connections to 20 or more different ports within 5 seconds
PORT_SCAN_THRESHOLD = 20
PORT_SCAN_WINDOW = 5.0  # seconds

# SYN Flood Detection Parameters
# If more than 100 SYN packets arrive within 3 seconds from one IP
SYN_FLOOD_THRESHOLD = 100
SYN_FLOOD_WINDOW = 3.0  # seconds
