"""
=============================================================
Module 1: Packet Capture
=============================================================
Real-time network packet capture using Scapy.
Runs in a background thread and stores packets in a
thread-safe deque for consumption by the feature engine.
=============================================================
"""

import time
import threading
from collections import deque
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw, conf

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config.settings import CAPTURE_INTERFACE, PACKET_BUFFER_SIZE


def _find_active_interface():
    """
    Find the Scapy interface that matches the machine's outbound IP.
    Scapy's default conf.iface on Windows often picks a virtual/link-local
    adapter with no real traffic. This finds the correct one.
    """
    import socket
    from scapy.all import get_if_addr, get_if_list

    # Get the actual outbound IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        outbound_ip = s.getsockname()[0]
        s.close()
    except Exception:
        return None

    if outbound_ip in ("127.0.0.1", "0.0.0.0"):
        return None

    for iface in get_if_list():
        try:
            if get_if_addr(iface) == outbound_ip:
                print(f"[PacketCapture] Auto-selected interface: {iface} ({outbound_ip})")
                return iface
        except Exception:
            continue

    print(f"[PacketCapture] WARNING: Could not find interface for {outbound_ip}, sniffing all.")
    return None


class PacketInfo:
    """Lightweight container for extracted packet metadata."""
    __slots__ = [
        "timestamp", "src_ip", "dst_ip", "protocol",
        "packet_length", "dst_port", "tcp_flags", "src_port",
        "dns_query", "ttl"
    ]

    def __init__(self, timestamp, src_ip, dst_ip, protocol,
                 packet_length, dst_port=0, tcp_flags="", src_port=0,
                 dns_query="", ttl=0):
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocol = protocol
        self.packet_length = packet_length
        self.dst_port = dst_port
        self.tcp_flags = tcp_flags
        self.src_port = src_port
        self.dns_query = dns_query
        self.ttl = ttl

    def to_dict(self):
        return {
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "protocol": self.protocol,
            "packet_length": self.packet_length,
            "dst_port": self.dst_port,
            "tcp_flags": self.tcp_flags,
            "src_port": self.src_port,
            "dns_query": self.dns_query,
            "ttl": self.ttl,
        }


class PacketCapture:
    """
    Real-time packet capture engine.
    
    Usage:
        capture = PacketCapture()
        capture.start()          # Starts background capture thread
        packets = capture.get_packets()   # Get current buffer
        capture.stop()           # Stop capture
    """

    def __init__(self, interface=None, buffer_size=None):
        # Use explicit setting, else auto-detect the active network interface
        self.interface = interface or CAPTURE_INTERFACE or _find_active_interface()
        self.buffer_size = buffer_size or PACKET_BUFFER_SIZE
        self.packet_buffer = deque(maxlen=self.buffer_size)
        self._lock = threading.Lock()
        self._running = False
        self._thread = None
        self._total_captured = 0

    @staticmethod
    def _extract_tls_sni(raw_data):
        """
        Extract Server Name Indication (SNI) from a TLS ClientHello.

        When browsers use DNS-over-HTTPS (DoH), traditional DNS queries
        on port 53 are invisible. However, the TLS ClientHello message
        always contains the target domain in the SNI extension — in
        plain text. This extracts that domain name.
        """
        try:
            data = bytes(raw_data)
            if len(data) < 10 or data[0] != 0x16:  # Not TLS handshake
                return None
            # Skip TLS record header (5 bytes)
            # Check handshake type is ClientHello (0x01)
            if data[5] != 0x01:
                return None
            # Skip: handshake header(4) + version(2) + random(32)
            pos = 5 + 4 + 2 + 32
            if pos >= len(data):
                return None
            # Session ID
            sid_len = data[pos]
            pos += 1 + sid_len
            # Cipher suites
            if pos + 2 > len(data):
                return None
            cs_len = int.from_bytes(data[pos:pos+2], 'big')
            pos += 2 + cs_len
            # Compression methods
            if pos >= len(data):
                return None
            cm_len = data[pos]
            pos += 1 + cm_len
            # Extensions
            if pos + 2 > len(data):
                return None
            ext_len = int.from_bytes(data[pos:pos+2], 'big')
            pos += 2
            end = min(pos + ext_len, len(data))
            while pos + 4 <= end:
                ext_type = int.from_bytes(data[pos:pos+2], 'big')
                ext_data_len = int.from_bytes(data[pos+2:pos+4], 'big')
                pos += 4
                if ext_type == 0 and pos + 5 <= end:  # SNI extension
                    # skip: list_len(2) + type(1) + name_len(2)
                    sni_len = int.from_bytes(data[pos+3:pos+5], 'big')
                    if pos + 5 + sni_len <= len(data):
                        sni = data[pos+5:pos+5+sni_len].decode(
                            'ascii', errors='ignore'
                        )
                        return sni
                pos += ext_data_len
        except (IndexError, ValueError, TypeError):
            pass
        return None

    def _process_packet(self, packet):
        """Extract metadata from a captured packet."""
        try:
            if not packet.haslayer(IP):
                return

            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            packet_length = len(packet)
            timestamp = datetime.now()
            dst_port = 0
            src_port = 0
            tcp_flags = ""
            dns_query = ""

            # Determine protocol and extract port/flag info
            if packet.haslayer(TCP):
                protocol = "TCP"
                tcp_layer = packet[TCP]
                dst_port = tcp_layer.dport
                src_port = tcp_layer.sport
                tcp_flags = str(tcp_layer.flags)
            elif packet.haslayer(UDP):
                protocol = "UDP"
                udp_layer = packet[UDP]
                dst_port = udp_layer.dport
                src_port = udp_layer.sport
            elif packet.haslayer(ICMP):
                protocol = "ICMP"
            else:
                protocol = "OTHER"

            # --- Method 1: DNS query on port 53 ---
            if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                if packet[DNS].qr == 0:  # Query (not response)
                    try:
                        domain = packet[DNSQR].qname.decode(
                            "utf-8", errors="ignore"
                        ).rstrip(".")
                        if (domain
                                and not domain.endswith(".local")
                                and not domain.endswith(".arpa")
                                and len(domain) > 3):
                            dns_query = domain
                    except Exception:
                        pass

            # --- Method 2: TLS SNI from HTTPS connections ---
            # Most browsers use DNS-over-HTTPS, making port 53 invisible.
            # But TLS ClientHello always contains the domain in SNI.
            if not dns_query and dst_port == 443 and packet.haslayer(Raw):
                sni = self._extract_tls_sni(packet[Raw].load)
                if sni and len(sni) > 3:
                    dns_query = sni

            pkt_info = PacketInfo(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                packet_length=packet_length,
                dst_port=dst_port,
                tcp_flags=tcp_flags,
                src_port=src_port,
                dns_query=dns_query,
                ttl=ip_layer.ttl,
            )

            with self._lock:
                self.packet_buffer.append(pkt_info)
                self._total_captured += 1

        except Exception as e:
            # Silently skip malformed packets
            pass

    def _capture_loop(self):
        """Main capture loop running in background thread."""
        if self.interface:
            print(f"[PacketCapture] Capturing on interface: {self.interface}")
        else:
            print("[PacketCapture] Capturing on ALL interfaces")
        try:
            sniff(
                iface=self.interface if self.interface else None,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda _: not self._running,
            )
        except PermissionError:
            print("[PacketCapture] ERROR: Requires Administrator privileges! Run as Admin.")
        except Exception as e:
            print(f"[PacketCapture] ERROR: {e}")

    def start(self):
        """Start packet capture in a background daemon thread."""
        if self._running:
            print("[PacketCapture] Already running.")
            return

        self._running = True
        self._thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._thread.start()
        print("[PacketCapture] Capture thread started.")

    def stop(self):
        """Stop the packet capture."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        print(f"[PacketCapture] Stopped. Total packets captured: {self._total_captured}")

    def get_packets(self, clear=False):
        """
        Get all packets currently in the buffer.
        
        Args:
            clear: If True, clear the buffer after reading.
        
        Returns:
            List of PacketInfo objects.
        """
        with self._lock:
            packets = list(self.packet_buffer)
            if clear:
                self.packet_buffer.clear()
        return packets

    def get_recent_packets(self, seconds=30):
        """Get packets from the last N seconds."""
        cutoff = datetime.now()
        with self._lock:
            packets = [
                p for p in self.packet_buffer
                if (cutoff - p.timestamp).total_seconds() <= seconds
            ]
        return packets

    @property
    def total_captured(self):
        return self._total_captured

    @property
    def buffer_count(self):
        with self._lock:
            return len(self.packet_buffer)

    @property
    def is_running(self):
        return self._running


# ── Quick Test ──────────────────────────────────────────────
if __name__ == "__main__":
    capture = PacketCapture()
    capture.start()
    try:
        while True:
            time.sleep(5)
            packets = capture.get_recent_packets(seconds=5)
            print(f"  Captured {len(packets)} packets in last 5s "
                  f"(total: {capture.total_captured})")
            for p in packets[:3]:
                print(f"    {p.src_ip} -> {p.dst_ip} [{p.protocol}] "
                      f"{p.packet_length}B port={p.dst_port}")
    except KeyboardInterrupt:
        capture.stop()
