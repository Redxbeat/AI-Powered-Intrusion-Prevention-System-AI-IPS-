"""
=============================================================
Module 5: Threat Detection Engine
=============================================================
Combines ML predictions with rule-based heuristics to
classify attack types and generate alerts.
=============================================================
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config.settings import (
    PORT_SCAN_THRESHOLD, BRUTE_FORCE_THRESHOLD,
    SYN_FLOOD_THRESHOLD, PACKET_RATE_THRESHOLD,
    ML_MIN_PACKETS
)


class ThreatDetector:
    """
    Multi-layered threat detection combining ML + rule-based analysis.
    
    Attack types detected:
        - Port Scan:        Many unique ports accessed
        - Brute Force:      High packet count to few ports
        - SYN Flood:        Excessive SYN packets
        - High Rate Anomaly: Packets/sec exceeds threshold
        - ML Detected:      Model flags as malicious, no specific rule match
    """

    def __init__(self):
        self.alert_callbacks = []

    def register_alert_callback(self, callback):
        """Register a function to call when a threat is detected."""
        self.alert_callbacks.append(callback)

    def _fire_alert(self, src_ip, attack_type, details):
        """Trigger all registered alert callbacks."""
        for cb in self.alert_callbacks:
            try:
                cb(src_ip, attack_type, details)
            except Exception:
                pass

    def analyze(self, prediction_df):
        """
        Analyze prediction results and classify attack types.
        
        Args:
            prediction_df: DataFrame from PredictionEngine with columns:
                src_ip, prediction, confidence, + feature columns
                
        Returns:
            List of threat dicts:
                {src_ip, attack_type, confidence, details}
        """
        threats = []

        if prediction_df.empty:
            return threats

        for _, row in prediction_df.iterrows():
            src_ip = row.get("src_ip", "unknown")
            ml_prediction = row.get("prediction", 0)
            confidence = row.get("confidence", 0.0)

            # Run rule-based checks
            attack_type = self._classify_attack(row)

            # If ML says malicious but no rule match — require minimum
            # packet volume to avoid flagging normal CDN/cloud traffic
            if attack_type == "Normal" and ml_prediction == 1:
                packet_count = row.get("packet_count", 0)
                if packet_count >= ML_MIN_PACKETS:
                    attack_type = "ML Detected"

            # If attack detected (either by rules or ML)
            if attack_type != "Normal":
                details = self._build_details(row, attack_type)
                threat = {
                    "src_ip": src_ip,
                    "attack_type": attack_type,
                    "confidence": confidence,
                    "details": details,
                    "dst_ip": row.get("dst_ip", "N/A"),
                }
                threats.append(threat)
                self._fire_alert(src_ip, attack_type, details)

        return threats

    def _classify_attack(self, row):
        """Determine attack type based on rule-based thresholds."""
        unique_ports = row.get("unique_dst_ports", 0)
        packet_count = row.get("packet_count", 0)
        syn_count = row.get("syn_count", 0)
        packet_rate = row.get("packet_rate", 0)

        # Priority order: most specific first
        if syn_count > SYN_FLOOD_THRESHOLD:
            return "SYN Flood"

        if unique_ports > PORT_SCAN_THRESHOLD:
            return "Port Scan"

        if (packet_count > BRUTE_FORCE_THRESHOLD and
                unique_ports <= 3):
            return "Brute Force"

        if packet_rate > PACKET_RATE_THRESHOLD:
            return "High Rate Anomaly"

        return "Normal"

    def _build_details(self, row, attack_type):
        """Build a human-readable detail string."""
        parts = [f"Attack: {attack_type}"]
        parts.append(f"Packets: {int(row.get('packet_count', 0))}")
        parts.append(f"Unique Ports: {int(row.get('unique_dst_ports', 0))}")
        parts.append(f"SYN Count: {int(row.get('syn_count', 0))}")
        parts.append(f"Rate: {row.get('packet_rate', 0):.1f} pkt/s")
        return " | ".join(parts)


# ── Quick Test ──────────────────────────────────────────────
if __name__ == "__main__":
    import pandas as pd

    detector = ThreatDetector()
    detector.register_alert_callback(
        lambda ip, at, d: print(f"  ALERT: {ip} -> {at}: {d}")
    )

    test_data = pd.DataFrame([
        {"src_ip": "10.0.0.5", "prediction": 1, "confidence": 0.92,
         "unique_dst_ports": 50, "packet_count": 200, "syn_count": 45,
         "packet_rate": 80},
        {"src_ip": "10.0.0.6", "prediction": 0, "confidence": 0.85,
         "unique_dst_ports": 2, "packet_count": 10, "syn_count": 0,
         "packet_rate": 5},
    ])

    threats = detector.analyze(test_data)
    print(f"\nTotal threats: {len(threats)}")
    for t in threats:
        print(f"  {t}")
