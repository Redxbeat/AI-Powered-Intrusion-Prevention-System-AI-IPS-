"""
=============================================================
Dataset Generator
=============================================================
Generates a synthetic training dataset simulating both normal
and malicious network traffic patterns.

Classes:
    0 = Normal traffic
    1 = Malicious traffic (port scan, brute force, flood, etc.)
=============================================================
"""

import os
import sys
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config.settings import TRAINING_DATA_PATH, FEATURE_COLUMNS, RANDOM_SEED

np.random.seed(RANDOM_SEED)


def generate_normal_traffic(n=5000):
    """Generate samples representing normal network traffic."""
    data = {
        "packet_count": np.random.randint(1, 30, n),
        "unique_dst_ips": np.random.randint(1, 5, n),
        "unique_dst_ports": np.random.randint(1, 8, n),
        "avg_packet_length": np.random.normal(500, 200, n).clip(40, 1500),
        "std_packet_length": np.random.normal(100, 50, n).clip(0, 500),
        "tcp_ratio": np.random.uniform(0.3, 0.8, n),
        "udp_ratio": np.random.uniform(0.1, 0.5, n),
        "icmp_ratio": np.random.uniform(0.0, 0.1, n),
        "syn_count": np.random.randint(0, 10, n),
        "packet_rate": np.random.uniform(0.5, 20, n),
        "label": 0,
    }
    # Ensure ratios sum ~ 1
    df = pd.DataFrame(data)
    total = df["tcp_ratio"] + df["udp_ratio"] + df["icmp_ratio"]
    df["tcp_ratio"] /= total
    df["udp_ratio"] /= total
    df["icmp_ratio"] /= total
    return df


def generate_port_scan(n=1500):
    """Port scan: many unique ports, moderate packet count, high SYN."""
    data = {
        "packet_count": np.random.randint(20, 200, n),
        "unique_dst_ips": np.random.randint(1, 3, n),
        "unique_dst_ports": np.random.randint(20, 500, n),
        "avg_packet_length": np.random.normal(60, 15, n).clip(40, 120),
        "std_packet_length": np.random.normal(10, 5, n).clip(0, 50),
        "tcp_ratio": np.random.uniform(0.8, 1.0, n),
        "udp_ratio": np.random.uniform(0.0, 0.1, n),
        "icmp_ratio": np.random.uniform(0.0, 0.1, n),
        "syn_count": np.random.randint(15, 200, n),
        "packet_rate": np.random.uniform(10, 100, n),
        "label": 1,
    }
    df = pd.DataFrame(data)
    total = df["tcp_ratio"] + df["udp_ratio"] + df["icmp_ratio"]
    df["tcp_ratio"] /= total
    df["udp_ratio"] /= total
    df["icmp_ratio"] /= total
    return df


def generate_brute_force(n=1500):
    """Brute force: high packet count, very few ports (1-3)."""
    data = {
        "packet_count": np.random.randint(60, 500, n),
        "unique_dst_ips": np.random.randint(1, 2, n),
        "unique_dst_ports": np.random.randint(1, 3, n),
        "avg_packet_length": np.random.normal(200, 80, n).clip(40, 600),
        "std_packet_length": np.random.normal(30, 15, n).clip(0, 100),
        "tcp_ratio": np.random.uniform(0.85, 1.0, n),
        "udp_ratio": np.random.uniform(0.0, 0.1, n),
        "icmp_ratio": np.random.uniform(0.0, 0.05, n),
        "syn_count": np.random.randint(5, 50, n),
        "packet_rate": np.random.uniform(20, 150, n),
        "label": 1,
    }
    df = pd.DataFrame(data)
    total = df["tcp_ratio"] + df["udp_ratio"] + df["icmp_ratio"]
    df["tcp_ratio"] /= total
    df["udp_ratio"] /= total
    df["icmp_ratio"] /= total
    return df


def generate_syn_flood(n=1000):
    """SYN flood: extremely high SYN count, high rate."""
    data = {
        "packet_count": np.random.randint(100, 1000, n),
        "unique_dst_ips": np.random.randint(1, 3, n),
        "unique_dst_ports": np.random.randint(1, 10, n),
        "avg_packet_length": np.random.normal(54, 8, n).clip(40, 80),
        "std_packet_length": np.random.normal(5, 3, n).clip(0, 20),
        "tcp_ratio": np.random.uniform(0.95, 1.0, n),
        "udp_ratio": np.random.uniform(0.0, 0.03, n),
        "icmp_ratio": np.random.uniform(0.0, 0.02, n),
        "syn_count": np.random.randint(50, 900, n),
        "packet_rate": np.random.uniform(100, 500, n),
        "label": 1,
    }
    df = pd.DataFrame(data)
    total = df["tcp_ratio"] + df["udp_ratio"] + df["icmp_ratio"]
    df["tcp_ratio"] /= total
    df["udp_ratio"] /= total
    df["icmp_ratio"] /= total
    return df


def generate_high_rate_anomaly(n=1000):
    """High rate anomaly: extremely high packets per second."""
    data = {
        "packet_count": np.random.randint(150, 800, n),
        "unique_dst_ips": np.random.randint(1, 10, n),
        "unique_dst_ports": np.random.randint(1, 15, n),
        "avg_packet_length": np.random.normal(300, 150, n).clip(40, 1500),
        "std_packet_length": np.random.normal(80, 40, n).clip(0, 400),
        "tcp_ratio": np.random.uniform(0.4, 0.9, n),
        "udp_ratio": np.random.uniform(0.1, 0.5, n),
        "icmp_ratio": np.random.uniform(0.0, 0.1, n),
        "syn_count": np.random.randint(10, 100, n),
        "packet_rate": np.random.uniform(120, 600, n),
        "label": 1,
    }
    df = pd.DataFrame(data)
    total = df["tcp_ratio"] + df["udp_ratio"] + df["icmp_ratio"]
    df["tcp_ratio"] /= total
    df["udp_ratio"] /= total
    df["icmp_ratio"] /= total
    return df


def generate_dataset():
    """Generate the complete training dataset."""
    print("[DataGen] Generating synthetic training dataset...")

    normal = generate_normal_traffic(5000)
    port_scan = generate_port_scan(1500)
    brute_force = generate_brute_force(1500)
    syn_flood = generate_syn_flood(1000)
    high_rate = generate_high_rate_anomaly(1000)

    dataset = pd.concat(
        [normal, port_scan, brute_force, syn_flood, high_rate],
        ignore_index=True
    )

    # Shuffle
    dataset = dataset.sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)

    # Save
    os.makedirs(os.path.dirname(TRAINING_DATA_PATH), exist_ok=True)
    dataset.to_csv(TRAINING_DATA_PATH, index=False)

    print(f"[DataGen] Dataset saved to {TRAINING_DATA_PATH}")
    print(f"[DataGen] Total samples: {len(dataset)}")
    print(f"[DataGen] Class distribution:")
    print(f"  Normal (0):    {(dataset['label'] == 0).sum()}")
    print(f"  Malicious (1): {(dataset['label'] == 1).sum()}")

    return dataset


if __name__ == "__main__":
    generate_dataset()
