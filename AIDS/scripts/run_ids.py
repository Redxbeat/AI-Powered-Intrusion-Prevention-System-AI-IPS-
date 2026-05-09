"""
=============================================================
Main IDS Engine — Real-Time Detection Loop
=============================================================
Orchestrates all modules:
  1. Captures packets in background
  2. Periodically extracts features
  3. Runs ML predictions
  4. Detects threat types
  5. Blocks malicious IPs
  6. Logs everything to SQLite
  7. Scans for connected clients
  8. Tracks DNS queries for visited sites

Must be run with ADMINISTRATOR privileges.
=============================================================
"""

import time
import signal
import sys
import os
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from config.settings import (
    FEATURE_WINDOW, ANALYSIS_INTERVAL,
    WHITELISTED_IPS, USB_MONITOR_ENABLED
)
from modules.packet_capture import PacketCapture
from modules.feature_engineering import FeatureEngineer
from modules.prediction_engine import PredictionEngine
from modules.threat_detection import ThreatDetector
from modules.firewall import FirewallManager
from modules.logger_db import ThreatLogger
from modules.usb_monitor import USBMonitor
from modules.network_scanner import NetworkScanner


class IDSEngine:
    """Main Intrusion Detection & Prevention Engine."""

    def __init__(self):
        print("=" * 60)
        print("  AI-POWERED INTRUSION PREVENTION SYSTEM")
        print("  Initializing modules...")
        print("=" * 60)

        # Initialize all modules
        self.capture = PacketCapture()
        self.feature_engine = FeatureEngineer(time_window=FEATURE_WINDOW)
        self.predictor = PredictionEngine()
        self.detector = ThreatDetector()
        self.firewall = FirewallManager()
        self.logger = ThreatLogger()
        self.usb_monitor = USBMonitor()
        self.scanner = NetworkScanner()

        # Load ML model
        print("[Engine] Loading ML model...")
        self.predictor.load_model()

        # Register alert callbacks
        self.detector.register_alert_callback(self._on_threat_detected)
        self.usb_monitor.register_alert_callback(self._on_usb_event)

        # Stats
        self._cycle_count = 0
        self._total_threats = 0
        self._running = False

        # Cooldown: track recently flagged IPs to avoid re-flagging
        # every cycle while the same 30s traffic window is still active
        self._recent_flags = {}   # {ip: timestamp_of_last_flag}
        self._cooldown_seconds = 60  # Ignore repeat detections within this window

    def _on_threat_detected(self, src_ip, attack_type, details):
        """Callback fired when a threat is detected."""
        print(f"\n  ⚠️  THREAT DETECTED: {src_ip}")
        print(f"      Type: {attack_type}")
        print(f"      Details: {details}")

    def _on_usb_event(self, usb_event):
        """Callback fired when a USB device is detected."""
        self.logger.log_usb_event(
            device_id=usb_event.device_id,
            description=usb_event.description,
            event_type=usb_event.event_type,
            is_authorized=usb_event.is_authorized,
        )
        print(f"  🔌 USB event logged to database: {usb_event.description}")

    def start(self):
        """Start the IDS engine."""
        self._running = True

        # Clear stale client data from previous session
        self.logger.log_client_snapshot([])   # Wipe connected_clients table
        print("[Engine] Cleared stale client data from database.")

        # Start packet capture
        print("\n[Engine] Starting packet capture...")
        self.capture.start()

        # Start USB monitor (if enabled)
        if USB_MONITOR_ENABLED:
            print("[Engine] Starting USB monitor...")
            self.usb_monitor.start()

        # Initial network scan — populate ARP registry
        print("[Engine] Scanning local network for clients...")
        self.scanner.scan_arp_table()
        confirmed = self.scanner.get_client_count()
        print(f"[Engine] Found {confirmed} confirmed clients (with active traffic)")

        print(f"\n[Engine] System ACTIVE — analyzing every "
              f"{ANALYSIS_INTERVAL}s with {FEATURE_WINDOW}s window")
        print("[Engine] Press Ctrl+C to stop\n")

        # Main analysis loop
        try:
            while self._running:
                time.sleep(ANALYSIS_INTERVAL)
                self._analysis_cycle()
        except KeyboardInterrupt:
            print("\n\n[Engine] Shutting down...")
            self.stop()

    def stop(self):
        """Stop all modules gracefully."""
        self._running = False
        self.capture.stop()
        self.usb_monitor.stop()
        print(f"[Engine] Total analysis cycles: {self._cycle_count}")
        print(f"[Engine] Total threats detected: {self._total_threats}")
        print(f"[Engine] Blocked IPs: {self.firewall.get_blocked_ips()}")
        print("[Engine] Shutdown complete.")

    def _analysis_cycle(self):
        """Run one analysis cycle."""
        self._cycle_count += 1

        # 1. Get recent packets
        packets = self.capture.get_recent_packets(seconds=FEATURE_WINDOW)
        if not packets:
            return

        # 2. Extract features
        features_df = self.feature_engine.extract_features(packets)
        if features_df.empty:
            return

        # 3. Run ML predictions
        prediction_df = self.predictor.predict(features_df)

        # 4. Detect threats
        threats = self.detector.analyze(prediction_df)

        # 5. Count normal vs malicious
        normal_count = int((prediction_df["prediction"] == 0).sum())
        malicious_count = int((prediction_df["prediction"] == 1).sum())
        total_ips = len(prediction_df)

        # 6. Log traffic stats
        self.logger.log_traffic_stats(
            total=len(packets),
            normal=normal_count,
            malicious=malicious_count,
            unique_ips=total_ips
        )

        # 7. Process each threat
        now = time.time()
        for threat in threats:
            src_ip = threat["src_ip"]
            attack_type = threat["attack_type"]
            confidence = threat["confidence"]
            details = threat["details"]
            dst_ip = threat.get("dst_ip", "N/A")

            # Cooldown check — skip if this IP was flagged recently
            last_flagged = self._recent_flags.get(src_ip, 0)
            if (now - last_flagged) < self._cooldown_seconds:
                continue

            self._recent_flags[src_ip] = now
            self._total_threats += 1

            # Block the IP
            if src_ip not in WHITELISTED_IPS:
                blocked = self.firewall.block_ip(src_ip, reason=attack_type)
                action = "blocked" if blocked else "logged"

                if blocked:
                    self.logger.log_block(src_ip, reason=attack_type)
            else:
                action = "whitelisted"

            # Log the threat
            self.logger.log_threat(
                src_ip=src_ip,
                attack_type=attack_type,
                confidence=confidence,
                dst_ip=dst_ip,
                action=action,
                details=details
            )

        # 8. Network scanning — refresh ARP table every cycle
        self.scanner.scan_arp_table()

        # 9. Update per-client traffic stats
        self.scanner.process_packets(packets)

        # 9b. Remove clients with no traffic for 90 seconds
        self.scanner.purge_inactive_clients()

        # 10. Extract DNS queries from captured packets
        dns_entries = []
        for pkt in packets:
            if pkt.dns_query:
                dns_entries.append((pkt.src_ip, pkt.dns_query))
        if dns_entries:
            self.logger.log_dns_queries_bulk(dns_entries)

        # 11. Save client snapshot to DB (clears old data if no clients)
        clients = self.scanner.get_all_clients()
        self.logger.log_client_snapshot(clients)

        # 12. Print cycle summary
        status = "🟢" if not threats else "🔴"
        client_count = self.scanner.get_client_count()   # live in-memory count
        print(f"  [{status}] Cycle {self._cycle_count}: "
              f"{len(packets)} pkts | {total_ips} IPs | "
              f"{normal_count} normal | {malicious_count} malicious | "
              f"{len(threats)} threats | {client_count} clients")


def main():
    # Handle Ctrl+C gracefully
    engine = IDSEngine()

    def signal_handler(sig, frame):
        engine.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    engine.start()


if __name__ == "__main__":
    main()
