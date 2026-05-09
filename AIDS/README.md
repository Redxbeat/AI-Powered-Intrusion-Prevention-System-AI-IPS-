<<<<<<< HEAD
# AI-Powered-Intrusion-Prevention-System-AI-IPS-
Real-time network intrusion detection and prevention using Machine Learning with a JARVIS-themed monitoring dashboard. 
=======
# 🛡️ AI-Powered Intrusion Prevention System (AI-IPS)

> Real-time network intrusion detection and prevention using Machine Learning with a JARVIS-themed monitoring dashboard.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![ML](https://img.shields.io/badge/ML-Random_Forest-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## 🌟 Features

- **Real-Time Packet Capture** — Live network monitoring using Scapy
- **ML-Powered Detection** — Random Forest classifier trained on 10K+ samples
- **Multi-Attack Detection** — Port scans, brute force, SYN floods, rate anomalies
- **Automated Response** — Instant IP blocking via Windows Firewall / iptables
- **JARVIS Dashboard** — Futuristic real-time monitoring with live charts
- **USB Monitoring** — Detect unauthorized USB device insertions
- **SQLite Logging** — Persistent threat history and analytics
- **Sound Alerts** — Toast notifications for new threats

---

## 📁 Project Structure

```
AIDS/
├── .streamlit/config.toml       # JARVIS dark theme
├── config/settings.py           # Central configuration
├── modules/
│   ├── packet_capture.py        # Module 1: Scapy packet capture
│   ├── feature_engineering.py   # Module 2: Per-IP feature extraction
│   ├── ml_model.py              # Module 3: Random Forest model
│   ├── prediction_engine.py     # Module 4: Real-time predictions
│   ├── threat_detection.py      # Module 5: Attack classification
│   ├── firewall.py              # Module 6: IP blocking/unblocking
│   ├── logger_db.py             # Module 7: SQLite logging
│   └── usb_monitor.py           # Module 9: USB detection
├── data/generate_dataset.py     # Synthetic dataset generator
├── scripts/
│   ├── train_model.py           # Train the ML model
│   ├── run_ids.py               # Main IDS engine
│   └── simulate_attack.py       # Attack simulator
├── dashboard/app.py             # Streamlit dashboard
├── models/                      # Saved ML models (auto-generated)
├── logs/                        # SQLite database (auto-generated)
├── requirements.txt
├── run.bat                      # One-click Windows launcher
└── README.md
```

---

## 🚀 Quick Start

### Prerequisites

1. **Python 3.10+** installed
2. **Npcap** installed (required for Scapy on Windows)
   - Download from: https://npcap.com/
   - Install with "WinPcap API-compatible Mode" checked
3. **Administrator privileges** (required for packet capture and firewall rules)

### Installation

```bash
# 1. Navigate to project directory
cd "b:\Python programming\AIDS"

# 2. Install dependencies
pip install -r requirements.txt

# 3. Generate dataset and train the model
python scripts/train_model.py

# 4. Start the IDS engine (requires admin terminal)
python scripts/run_ids.py

# 5. In another terminal, start the dashboard
streamlit run dashboard/app.py
```

### One-Click Launch (Windows)

Right-click `run.bat` → **Run as administrator**

This will:
1. Train the model (if not already trained)
2. Start the IDS engine
3. Open the Streamlit dashboard at http://localhost:8501

---

## 🧪 Testing with Attack Simulation

### Using the Built-in Simulator

Open a **separate admin terminal** and run:

```bash
# Mixed attacks (port scan + brute force + SYN flood)
python scripts/simulate_attack.py --mode mixed

# Port scan only
python scripts/simulate_attack.py --mode portscan --count 200

# Brute force on SSH port
python scripts/simulate_attack.py --mode bruteforce --count 150

# SYN flood
python scripts/simulate_attack.py --mode synflood --count 500
```

### Using Kali Linux (External Attack)

From a Kali Linux machine on the same network:

```bash
# Find target IP
# On Windows target: ipconfig

# Port scan
nmap -sS -p 1-1000 <TARGET_IP>

# Aggressive scan
nmap -A -T4 <TARGET_IP>

# SYN flood (requires root)
hping3 -S --flood -p 80 <TARGET_IP>

# Brute force SSH
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://<TARGET_IP>
```

---

## 📊 Dashboard Features

| Section | Description |
|---------|-------------|
| KPI Cards | Total packets, normal/malicious traffic, threats, blocked IPs |
| Traffic Graph | Live time-series of normal vs malicious traffic |
| Attack Pie Chart | Distribution of attack types |
| Top Attackers | Bar chart of most active threat sources |
| Threat Log | Scrollable table with timestamp, IP, attack type |
| Blocked IPs | List with UNBLOCK buttons |
| USB Monitor | Device insertion alerts |

---

## ⚙️ Configuration

Edit `config/settings.py` to customize:

| Setting | Default | Description |
|---------|---------|-------------|
| `PORT_SCAN_THRESHOLD` | 15 | Unique ports to flag port scan |
| `BRUTE_FORCE_THRESHOLD` | 50 | Packets to flag brute force |
| `SYN_FLOOD_THRESHOLD` | 30 | SYN packets to flag flood |
| `PACKET_RATE_THRESHOLD` | 100 | Packets/sec threshold |
| `FEATURE_WINDOW` | 30s | Analysis time window |
| `ANALYSIS_INTERVAL` | 5s | Seconds between analysis cycles |
| `ML_CONFIDENCE_THRESHOLD` | 0.6 | Min ML confidence for classification |
| `WHITELISTED_IPS` | (see file) | IPs that will never be blocked |

---

## 🏗️ Architecture

```
┌──────────────┐     ┌──────────────────┐     ┌──────────────┐
│   Network    │────▶│  Packet Capture  │────▶│   Feature    │
│   Traffic    │     │    (Scapy)       │     │  Engineering │
└──────────────┘     └──────────────────┘     └──────┬───────┘
                                                      │
                     ┌──────────────────┐     ┌──────▼───────┐
                     │  Threat Detect   │◀────│  ML Predict  │
                     │  (Rules + ML)    │     │ (Rnd Forest) │
                     └──────┬───────────┘     └──────────────┘
                            │
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
       ┌────────────┐ ┌──────────┐ ┌────────────┐
       │  Firewall  │ │  SQLite  │ │ Dashboard  │
       │  (Block)   │ │  Logger  │ │ (Streamlit)│
       └────────────┘ └──────────┘ └────────────┘
```

---

## 🔒 Security Notes

- **Whitelist your gateway/DNS** in `settings.py` to avoid blocking critical infrastructure
- **Run as admin** — packet capture and firewall rules require elevated privileges
- **Firewall rules** are named `IPS_BLOCK_<IP>` and can be viewed in Windows Firewall
- **Unblock from dashboard** or manually via: `netsh advfirewall firewall delete rule name=IPS_BLOCK_<IP>`

---

## 📦 Deployment

### Local Deployment
Follow the Quick Start guide above.

### Cloud Deployment (Optional)

1. **Docker**:
   ```dockerfile
   FROM python:3.11-slim
   WORKDIR /app
   COPY . .
   RUN pip install -r requirements.txt
   CMD ["streamlit", "run", "dashboard/app.py", "--server.port", "8501"]
   ```

2. **Cloud VM** (AWS/GCP/Azure):
   - Deploy on a Linux VM
   - Use `iptables` for firewall rules
   - Use `systemd` to run the IDS engine as a service
   - Expose port 8501 for the dashboard

---

## 📄 License

MIT License — free to use, modify, and distribute.
>>>>>>> f642f39 (Initial commit)
