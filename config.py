import os
import platform

# lo0 for macOS, lo for linux. Can override with NIDS_INTERFACE env var.
SYSTEM_OS = platform.system().lower()
DEFAULT_INTERFACE = "lo0" if "darwin" in SYSTEM_OS else "lo"
INTERFACE = os.environ.get("NIDS_INTERFACE", DEFAULT_INTERFACE)

# Rule thresholds
PORT_SCAN_THRESHOLD = 20
PORT_SCAN_WINDOW = 5.0  # seconds

SYN_FLOOD_THRESHOLD = 100
SYN_FLOOD_WINDOW = 3.0  # seconds
