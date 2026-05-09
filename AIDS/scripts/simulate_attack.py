"""
=============================================================
Attack Simulator
=============================================================
Generates simulated malicious traffic for testing the IPS.
Uses Scapy to craft and send attack packets.

Attack modes:
  1. Port Scan   — SYN packets to many ports
  2. Brute Force — Rapid connections to a single port
  3. SYN Flood   — Massive SYN packet burst
  4. Mixed        — All attacks combined

Must be run with ADMINISTRATOR privileges.
Usage:
    python simulate_attack.py --target <IP> --mode <portscan|bruteforce|synflood|mixed>
=============================================================
"""

import argparse
import time
import random
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def get_local_ip():
    """Get the local machine's IP address."""
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def simulate_port_scan(target_ip, src_ip, count=100):
    """Simulate a port scan — SYN to many ports."""
    from scapy.all import IP, TCP, send
    print(f"\n[Attack] PORT SCAN: {src_ip} -> {target_ip}")
    print(f"         Scanning {count} ports...")

    ports = random.sample(range(1, 65535), min(count, 1000))
    packets = []
    for port in ports:
        pkt = IP(src=src_ip, dst=target_ip) / TCP(
            sport=random.randint(1024, 65535),
            dport=port,
            flags="S"
        )
        packets.append(pkt)

    # Send in batches
    batch_size = 20
    for i in range(0, len(packets), batch_size):
        batch = packets[i:i + batch_size]
        send(batch, verbose=False)
        print(f"  Sent {min(i + batch_size, len(packets))}/{len(packets)} SYN packets")
        time.sleep(0.1)

    print(f"[Attack] Port scan complete. {len(packets)} packets sent.")


def simulate_brute_force(target_ip, src_ip, port=22, count=200):
    """Simulate brute force — many connections to same port."""
    from scapy.all import IP, TCP, send
    print(f"\n[Attack] BRUTE FORCE: {src_ip} -> {target_ip}:{port}")
    print(f"         Sending {count} connection attempts...")

    packets = []
    for _ in range(count):
        pkt = IP(src=src_ip, dst=target_ip) / TCP(
            sport=random.randint(1024, 65535),
            dport=port,
            flags="S"
        )
        packets.append(pkt)

    batch_size = 30
    for i in range(0, len(packets), batch_size):
        batch = packets[i:i + batch_size]
        send(batch, verbose=False)
        print(f"  Sent {min(i + batch_size, len(packets))}/{len(packets)} packets")
        time.sleep(0.05)

    print(f"[Attack] Brute force complete. {len(packets)} packets sent.")


def simulate_syn_flood(target_ip, src_ip, port=80, count=500):
    """Simulate SYN flood — massive SYN packet burst."""
    from scapy.all import IP, TCP, send
    print(f"\n[Attack] SYN FLOOD: {src_ip} -> {target_ip}:{port}")
    print(f"         Flooding with {count} SYN packets...")

    packets = []
    for _ in range(count):
        pkt = IP(src=src_ip, dst=target_ip) / TCP(
            sport=random.randint(1024, 65535),
            dport=port,
            flags="S"
        )
        packets.append(pkt)

    batch_size = 50
    for i in range(0, len(packets), batch_size):
        batch = packets[i:i + batch_size]
        send(batch, verbose=False)
        time.sleep(0.01)

    print(f"[Attack] SYN flood complete. {len(packets)} packets sent.")


def simulate_mixed(target_ip, src_ip):
    """Run all attack types."""
    print("\n" + "=" * 50)
    print("  MIXED ATTACK SIMULATION")
    print("=" * 50)

    simulate_port_scan(target_ip, src_ip, count=80)
    time.sleep(2)
    simulate_brute_force(target_ip, src_ip, port=22, count=150)
    time.sleep(2)
    simulate_syn_flood(target_ip, src_ip, port=80, count=300)

    print("\n[Attack] All attack simulations complete!")


def main():
    parser = argparse.ArgumentParser(
        description="AI-IPS Attack Simulator"
    )
    parser.add_argument(
        "--target", "-t",
        default=None,
        help="Target IP address (default: localhost)"
    )
    parser.add_argument(
        "--source", "-s",
        default="10.0.0.66",
        help="Spoofed source IP (default: 10.0.0.66)"
    )
    parser.add_argument(
        "--mode", "-m",
        choices=["portscan", "bruteforce", "synflood", "mixed"],
        default="mixed",
        help="Attack mode (default: mixed)"
    )
    parser.add_argument(
        "--count", "-c",
        type=int, default=100,
        help="Number of packets per attack (default: 100)"
    )

    args = parser.parse_args()
    target = args.target or get_local_ip()
    source = args.source

    print("=" * 50)
    print("  AI-IPS ATTACK SIMULATOR")
    print("=" * 50)
    print(f"  Target: {target}")
    print(f"  Source: {source}")
    print(f"  Mode:   {args.mode}")
    print(f"  Count:  {args.count}")
    print("=" * 50)

    confirm = input("\nProceed with simulation? (y/n): ")
    if confirm.lower() != "y":
        print("Aborted.")
        return

    if args.mode == "portscan":
        simulate_port_scan(target, source, args.count)
    elif args.mode == "bruteforce":
        simulate_brute_force(target, source, count=args.count)
    elif args.mode == "synflood":
        simulate_syn_flood(target, source, count=args.count)
    elif args.mode == "mixed":
        simulate_mixed(target, source)


if __name__ == "__main__":
    main()
