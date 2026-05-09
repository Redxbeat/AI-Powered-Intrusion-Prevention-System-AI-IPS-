"""
=============================================================
Module 2: Feature Engineering
=============================================================
Aggregates raw packet data into per-source-IP feature vectors
suitable for the machine learning classifier.
=============================================================
"""

import pandas as pd
import numpy as np
from datetime import datetime

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config.settings import FEATURE_COLUMNS, FEATURE_WINDOW


class FeatureEngineer:
    """
    Transforms raw packet lists into structured feature DataFrames.
    
    Features computed per source IP:
        - packet_count:      Total packets sent
        - unique_dst_ips:    Number of distinct destination IPs
        - unique_dst_ports:  Number of distinct destination ports
        - avg_packet_length: Mean packet size in bytes
        - std_packet_length: Std deviation of packet size
        - tcp_ratio:         Fraction of TCP packets
        - udp_ratio:         Fraction of UDP packets
        - icmp_ratio:        Fraction of ICMP packets
        - syn_count:         Number of TCP SYN flags
        - packet_rate:       Packets per second over the window
    """

    def __init__(self, time_window=None):
        """
        Args:
            time_window: Seconds of traffic to consider (default from config)
        """
        self.time_window = time_window or FEATURE_WINDOW

    def extract_features(self, packets):
        """
        Extract features from a list of PacketInfo objects.
        
        Args:
            packets: List of PacketInfo objects from PacketCapture
            
        Returns:
            pd.DataFrame with one row per source IP and feature columns,
            plus a 'src_ip' column for identification.
        """
        if not packets:
            return pd.DataFrame(columns=["src_ip"] + FEATURE_COLUMNS)

        # Filter to time window
        now = datetime.now()
        windowed = [
            p for p in packets
            if (now - p.timestamp).total_seconds() <= self.time_window
        ]

        if not windowed:
            return pd.DataFrame(columns=["src_ip"] + FEATURE_COLUMNS)

        # Convert to DataFrame for vectorized operations
        records = [p.to_dict() for p in windowed]
        df = pd.DataFrame(records)

        # Calculate time span of the window
        time_span = max(
            (df["timestamp"].max() - df["timestamp"].min()).total_seconds(),
            1.0  # Avoid division by zero
        )

        # Group by source IP and compute features
        features = df.groupby("src_ip").apply(
            lambda g: self._compute_group_features(g, time_span),
            include_groups=False
        ).reset_index()

        # Ensure all feature columns exist
        for col in FEATURE_COLUMNS:
            if col not in features.columns:
                features[col] = 0.0

        return features[["src_ip"] + FEATURE_COLUMNS]

    def _compute_group_features(self, group, time_span):
        """Compute feature vector for a single source IP group."""
        n = len(group)
        protocols = group["protocol"].value_counts()
        total = max(n, 1)

        # Count SYN flags (TCP SYN = 'S' in Scapy flags)
        syn_count = group["tcp_flags"].apply(
            lambda f: 1 if "S" in str(f) and "A" not in str(f) else 0
        ).sum()

        # Packet rate
        ip_time_span = max(
            (group["timestamp"].max() - group["timestamp"].min()).total_seconds(),
            1.0
        )

        return pd.Series({
            "packet_count": n,
            "unique_dst_ips": group["dst_ip"].nunique(),
            "unique_dst_ports": group["dst_port"].nunique(),
            "avg_packet_length": group["packet_length"].mean(),
            "std_packet_length": group["packet_length"].std() if n > 1 else 0.0,
            "tcp_ratio": protocols.get("TCP", 0) / total,
            "udp_ratio": protocols.get("UDP", 0) / total,
            "icmp_ratio": protocols.get("ICMP", 0) / total,
            "syn_count": syn_count,
            "packet_rate": n / ip_time_span,
        })

    def extract_features_from_dataframe(self, df):
        """
        Extract features from an already-constructed DataFrame.
        Useful for training data preparation.
        
        Args:
            df: DataFrame with columns matching packet fields
            
        Returns:
            Feature DataFrame
        """
        if df.empty:
            return pd.DataFrame(columns=["src_ip"] + FEATURE_COLUMNS)

        time_span = 30.0  # Default window assumption for static data

        features = df.groupby("src_ip").apply(
            lambda g: self._compute_group_features(g, time_span),
            include_groups=False
        ).reset_index()

        for col in FEATURE_COLUMNS:
            if col not in features.columns:
                features[col] = 0.0

        return features[["src_ip"] + FEATURE_COLUMNS]


# ── Quick Test ──────────────────────────────────────────────
if __name__ == "__main__":
    from modules.packet_capture import PacketInfo

    # Create mock packets
    test_packets = []
    for i in range(20):
        test_packets.append(PacketInfo(
            timestamp=datetime.now(),
            src_ip="192.168.1.100",
            dst_ip=f"10.0.0.{i % 5}",
            protocol="TCP" if i % 3 == 0 else "UDP",
            packet_length=64 + i * 10,
            dst_port=80 + i,
            tcp_flags="S" if i % 4 == 0 else "",
        ))

    engine = FeatureEngineer()
    features = engine.extract_features(test_packets)
    print("Extracted Features:")
    print(features.to_string())
