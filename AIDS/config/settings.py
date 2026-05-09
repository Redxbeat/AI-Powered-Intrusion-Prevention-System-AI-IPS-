"""
=============================================================
AI-IPS Configuration Settings
=============================================================
Central configuration for all IPS modules.
Modify thresholds, paths, and whitelists here.
=============================================================
"""

import os
import platform

# ── Platform Detection ──────────────────────────────────────
IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"

# ── Project Paths ───────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
MODELS_DIR = os.path.join(BASE_DIR, "models")
LOGS_DIR = os.path.join(BASE_DIR, "logs")
ASSETS_DIR = os.path.join(BASE_DIR, "assets")

# Ensure directories exist
for d in [DATA_DIR, MODELS_DIR, LOGS_DIR, ASSETS_DIR]:
    os.makedirs(d, exist_ok=True)

# File paths
TRAINING_DATA_PATH = os.path.join(DATA_DIR, "training_data.csv")
MODEL_PATH = os.path.join(MODELS_DIR, "rf_model.joblib")
SCALER_PATH = os.path.join(MODELS_DIR, "scaler.joblib")
DATABASE_PATH = os.path.join(LOGS_DIR, "threats.db")
ALERT_SOUND_PATH = os.path.join(ASSETS_DIR, "alert.wav")

# ── Feature Columns (order matters for model) ──────────────
FEATURE_COLUMNS = [
    "packet_count",
    "unique_dst_ips",
    "unique_dst_ports",
    "avg_packet_length",
    "std_packet_length",
    "tcp_ratio",
    "udp_ratio",
    "icmp_ratio",
    "syn_count",
    "packet_rate",
]

# ── Detection Thresholds ───────────────────────────────────
PORT_SCAN_THRESHOLD = 15       # Unique ports accessed to flag port scan
BRUTE_FORCE_THRESHOLD = 200    # Packet count with low port diversity
SYN_FLOOD_THRESHOLD = 30       # SYN packets to flag SYN flood
PACKET_RATE_THRESHOLD = 500    # Packets per second threshold
HIGH_RATE_WINDOW = 5           # Seconds for rate calculation

# ── Capture Settings ───────────────────────────────────────
FEATURE_WINDOW = 30            # Seconds of traffic to aggregate
CAPTURE_INTERFACE = None       # None = auto-detect default interface
PACKET_BUFFER_SIZE = 10000     # Max packets in rolling buffer
ANALYSIS_INTERVAL = 5          # Seconds between analysis cycles

# ── Firewall Settings ──────────────────────────────────────
FIREWALL_RULE_PREFIX = "IPS_BLOCK"  # Prefix for firewall rule names
MAX_BLOCKED_IPS = 500               # Safety limit on blocked IPs

# ── Whitelisted IPs ────────────────────────────────────────
# These IPs will NEVER be blocked (still monitored/logged)
WHITELISTED_IPS = {
    "127.0.0.1",
    "0.0.0.0",
    "255.255.255.255",
    "::1",
    # This server
    "10.114.159.152",
    # Connected clients (local network)
    "10.114.159.3",
    # Common private network gateways
    "192.168.0.1",
    "192.168.1.1",
    "10.0.0.1",
    "10.114.159.1",
    # Google DNS
    "8.8.8.8",
    "8.8.4.4",
    # Cloudflare DNS
    "1.1.1.1",
    "1.0.0.1",
}

# ── USB Monitor Settings ──────────────────────────────────
USB_MONITOR_ENABLED = True
USB_WHITELIST = set()   # Add allowed USB device IDs here

# ── Dashboard Settings ─────────────────────────────────────
DASHBOARD_REFRESH_INTERVAL = 3  # Seconds between dashboard refreshes
MAX_LOG_DISPLAY = 100           # Max rows in threat log table

# ── ML Model Settings ─────────────────────────────────────
ML_CONFIDENCE_THRESHOLD = 0.85  # Minimum probability to classify as malicious
ML_MIN_PACKETS = 100            # ML-only detections need this many packets
RANDOM_FOREST_ESTIMATORS = 100
RANDOM_FOREST_MAX_DEPTH = 20
TEST_SPLIT_RATIO = 0.2
RANDOM_SEED = 42
