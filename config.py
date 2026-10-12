import os
import platform

# Network Interface Configuration
# lo0 for macOS, lo for linux. Can override with NIDS_INTERFACE env var.
SYSTEM_OS = platform.system().lower()
DEFAULT_INTERFACE = "lo0" if "darwin" in SYSTEM_OS else "lo"
INTERFACE = os.environ.get("NIDS_INTERFACE", DEFAULT_INTERFACE)

# Rule thresholds
PORT_SCAN_THRESHOLD = 20
PORT_SCAN_WINDOW = 5.0  # seconds

SYN_FLOOD_THRESHOLD = 100
SYN_FLOOD_WINDOW = 3.0  # seconds

# Database & Storage
DB_PATH = os.environ.get("NIDS_DB_PATH", "nids.db")

# Machine Learning & Data Paths
DATA_DIR = "data"
MODEL_DIR = "models"
MODEL_PATH = os.path.join(MODEL_DIR, "nids_classifier.joblib")

# ML Flow sliding window parameters
FLOW_WINDOW = 3.0  # Aggregate flow statistics every 3 seconds per IP
ANOMALY_THRESHOLD = -0.15  # Isolation Forest score cutoff for anomaly alert

# Bidirectional Flow Tracking Parameters
FLOW_IDLE_TIMEOUT = 15.0    # seconds before idle flow expires
FLOW_ACTIVE_TIMEOUT = 120.0 # max lifetime in seconds of active continuous flow
FLOW_MAX_TABLE_SIZE = 10000 # bounded memory table size for concurrent flows
