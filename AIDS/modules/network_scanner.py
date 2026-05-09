"""
=============================================================
Module 10: Network Scanner & Client Monitor
=============================================================
Discovers connected clients on the local network via ARP scan.
Tracks per-client traffic stats and DNS queries (visited sites)
from packets flowing through this server.
Includes passive OS fingerprinting and device vendor detection.
=============================================================
"""

import threading
import socket
import time
import subprocess
import re
from datetime import datetime
from collections import defaultdict, Counter

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config.settings import IS_WINDOWS


# ── MAC OUI Vendor Table (common manufacturers) ─────────────
OUI_TABLE = {
    "00:0C:29": "VMware", "00:50:56": "VMware", "00:05:69": "VMware",
    "00:1C:14": "VMware", "00:0F:4B": "Oracle VM",
    "08:00:27": "VirtualBox", "0A:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM", "00:16:3E": "Xen",
    "00:15:5D": "Hyper-V",
    "D4:6A:6A": "Realtek", "00:E0:4C": "Realtek",
    "48:5D:36": "Realtek", "80:32:53": "Realtek",
    "74:D0:2B": "ASUSTek", "04:D4:C4": "ASUSTek",
    "00:1A:2B": "Ayecom", "AC:DE:48": "Private",
    "00:24:D7": "Intel", "3C:97:0E": "Intel", "A4:BB:6D": "Intel",
    "00:1B:21": "Intel", "68:05:CA": "Intel", "48:21:0B": "Intel",
    "F8:75:A4": "Intel", "8C:8D:28": "Intel",
    "F4:8C:50": "Intel", "B4:96:91": "Intel",
    "00:23:24": "Apple", "3C:15:C2": "Apple", "A4:83:E7": "Apple",
    "AC:BC:32": "Apple", "F0:18:98": "Apple", "14:7D:DA": "Apple",
    "DC:A6:32": "Raspberry Pi", "B8:27:EB": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "00:1E:68": "Quanta", "00:26:6C": "Inventec",
    "F8:63:3F": "Huawei", "48:46:FB": "Huawei",
    "00:E0:FC": "Huawei", "70:8B:CD": "Huawei",
    "2C:F0:5D": "Samsung", "00:21:19": "Samsung",
    "A8:F2:74": "Samsung", "F4:42:8F": "Samsung",
    "D0:17:C2": "ASUSTek", "2C:4D:54": "ASUSTek",
    "00:1D:7E": "Cisco", "00:1B:2B": "Cisco",
    "00:1A:A1": "Cisco", "00:22:55": "Cisco",
    "B0:BE:76": "TP-Link", "50:C7:BF": "TP-Link",
    "C0:25:E9": "TP-Link", "14:CC:20": "TP-Link",
    "38:D5:47": "ASUSTek", "1C:B7:2C": "ASUSTek",
    "9C:5C:8E": "Dell", "00:14:22": "Dell",
    "F8:DB:88": "Dell", "B0:83:FE": "Dell",
    "3C:52:82": "HP", "00:1E:0B": "HP",
    "D4:C9:EF": "HP", "10:1F:74": "HP",
    "00:50:B6": "Microsoft", "00:03:FF": "Microsoft",
    "60:45:BD": "Microsoft", "7C:1E:52": "Microsoft",
    "00:1D:D8": "Microsoft", "28:18:78": "Microsoft",
    "54:27:1E": "Motorola", "5C:51:88": "Motorola",
    "30:07:4D": "Xiaomi", "64:CC:2E": "Xiaomi",
    "9C:99:A0": "Xiaomi", "28:6C:07": "Xiaomi",
    "AC:84:C6": "TP-Link", "E8:DE:27": "TP-Link",
    "44:D9:E7": "Ubiquiti", "24:5A:4C": "Ubiquiti",
    "18:E8:29": "Ubiquiti", "FC:EC:DA": "Ubiquiti",
    "00:1B:44": "SanDisk", "00:26:B4": "SanDisk",
    "C8:3A:35": "Tenda", "D8:32:14": "TP-Link",
    "EC:08:6B": "TP-Link", "00:25:86": "TP-Link",
}


def lookup_vendor(mac):
    """Look up device vendor from MAC OUI (first 3 octets)."""
    if not mac or mac == "Unknown":
        return "Unknown"
    prefix = mac[:8].upper()
    return OUI_TABLE.get(prefix, "Unknown")


def guess_os_from_ttl(ttl):
    """Guess OS from IP TTL value."""
    if ttl == 0:
        return "Unknown"
    elif ttl <= 64:
        return "Linux / macOS"
    elif ttl <= 128:
        return "Windows"
    else:
        return "Network Device"


# Well-known port labels for display
PORT_LABELS = {
    80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP", 25: "SMTP",
    53: "DNS", 110: "POP3", 143: "IMAP", 993: "IMAPS",
    3389: "RDP", 8080: "HTTP-Alt", 3306: "MySQL", 5432: "PostgreSQL",
    6379: "Redis", 27017: "MongoDB", 8443: "HTTPS-Alt",
    445: "SMB", 139: "NetBIOS", 123: "NTP", 67: "DHCP",
    68: "DHCP", 161: "SNMP", 5060: "SIP", 1194: "OpenVPN",
    1723: "PPTP", 5900: "VNC", 9090: "Prometheus",
}


class ClientInfo:
    """Stores information about a connected client."""

    def __init__(self, ip, mac="Unknown"):
        self.ip = ip
        self.mac = mac
        self.hostname = ""
        self.packets_sent = 0
        self.packets_received = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        self.last_seen = datetime.now()
        self.dns_queries = []  # Recent domains visited
        self.first_seen = datetime.now()
        # New fingerprinting fields
        self.device_vendor = lookup_vendor(mac)
        self.os_guess = "Unknown"
        self._ttl_samples = []       # Collect TTL values
        self._protocol_counts = Counter()  # TCP, UDP, ICMP
        self._port_counts = Counter()      # dst_port usage

    def update_from_packet(self, pkt):
        """Update fingerprint data from a captured packet."""
        if pkt.ttl > 0:
            self._ttl_samples.append(pkt.ttl)
            # Keep only last 50 samples
            if len(self._ttl_samples) > 50:
                self._ttl_samples = self._ttl_samples[-50:]
            # Use the most common TTL for OS guess
            most_common_ttl = Counter(self._ttl_samples).most_common(1)[0][0]
            self.os_guess = guess_os_from_ttl(most_common_ttl)

        self._protocol_counts[pkt.protocol] += 1
        if pkt.dst_port > 0:
            self._port_counts[pkt.dst_port] += 1

    def to_dict(self):
        # Top 5 ports with labels
        top_ports = []
        for port, count in self._port_counts.most_common(5):
            label = PORT_LABELS.get(port, str(port))
            top_ports.append({"port": port, "label": label, "count": count})

        # Protocol breakdown
        proto_total = sum(self._protocol_counts.values()) or 1
        protocol_stats = {
            proto: round(cnt / proto_total * 100, 1)
            for proto, cnt in self._protocol_counts.most_common()
        }

        return {
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname or self._resolve_hostname(),
            "packets_sent": self.packets_sent,
            "packets_received": self.packets_received,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "last_seen": self.last_seen.isoformat(),
            "first_seen": self.first_seen.isoformat(),
            "dns_queries": list(set(self.dns_queries[-50:])),
            "device_vendor": self.device_vendor,
            "os_guess": self.os_guess,
            "top_ports": top_ports,
            "protocol_stats": protocol_stats,
        }

    def _resolve_hostname(self):
        """Try to resolve hostname via reverse DNS."""
        try:
            hostname = socket.gethostbyaddr(self.ip)[0]
            self.hostname = hostname
            return hostname
        except (socket.herror, socket.gaierror, OSError):
            return ""


class NetworkScanner:
    """
    Discovers and monitors client systems connected to this server's network.

    Features:
        - ARP table scanning to find connected clients
        - Per-client traffic statistics from packet capture
        - DNS query extraction for visited domain tracking
    """

    def __init__(self):
        self._clients = {}  # ip -> ClientInfo
        self._lock = threading.Lock()
        self._local_ips = set()
        self._arp_confirmed = {}    # ip -> last ARP+ping confirmed datetime
        self._CLIENT_TIMEOUT = 15   # seconds without ARP confirmation = removed
        self._TRAFFIC_TIMEOUT = 90  # seconds without any captured packet = removed
        self._discover_local_ips()

    def _discover_local_ips(self):
        """Find this machine's own IP addresses."""
        try:
            hostname = socket.gethostname()
            ips = socket.getaddrinfo(hostname, None, socket.AF_INET)
            self._local_ips = {addr[4][0] for addr in ips}
            self._local_ips.add("127.0.0.1")
        except Exception:
            self._local_ips = {"127.0.0.1"}

    def _flush_arp_entry(self, ip):
        """Delete Windows ARP cache entry so next ping forces a real ARP request."""
        try:
            if IS_WINDOWS:
                subprocess.run(
                    ["arp", "-d", ip],
                    capture_output=True, timeout=3,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
        except Exception:
            pass

    def _is_reachable(self, ip, timeout=1):
        """Quick ping check to verify a host is actually online."""
        try:
            if IS_WINDOWS:
                result = subprocess.run(
                    ["ping", "-n", "1", "-w", str(timeout * 1000), ip],
                    capture_output=True, text=True, timeout=timeout + 2,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
            else:
                result = subprocess.run(
                    ["ping", "-c", "1", "-W", str(timeout), ip],
                    capture_output=True, text=True, timeout=timeout + 2,
                )
            return result.returncode == 0
        except Exception:
            return False

    def scan_arp_table(self):
        """
        Read the system ARP table to discover connected devices,
        then verify each one is reachable via ping.
        """
        arp_candidates = []
        try:
            if IS_WINDOWS:
                result = subprocess.run(
                    ["arp", "-a"],
                    capture_output=True, text=True, timeout=10
                )
                # Parse Windows ARP output:
                # 192.168.1.5   00-1a-2b-3c-4d-5e   dynamic
                pattern = re.compile(
                    r"(\d+\.\d+\.\d+\.\d+)\s+"
                    r"([\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2}[:-]"
                    r"[\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2})\s+"
                    r"(\w+)"
                )
                for match in pattern.finditer(result.stdout):
                    ip = match.group(1)
                    mac = match.group(2).replace("-", ":").upper()
                    entry_type = match.group(3).lower()

                    # Skip broadcast and own IPs
                    if (ip not in self._local_ips
                            and not ip.endswith(".255")
                            and mac != "FF:FF:FF:FF:FF:FF"
                            and entry_type == "dynamic"):
                        arp_candidates.append({"ip": ip, "mac": mac})
            else:
                result = subprocess.run(
                    ["arp", "-n"],
                    capture_output=True, text=True, timeout=10
                )
                pattern = re.compile(
                    r"(\d+\.\d+\.\d+\.\d+)\s+\w+\s+"
                    r"([\da-fA-F]{2}:[\da-fA-F]{2}:[\da-fA-F]{2}:"
                    r"[\da-fA-F]{2}:[\da-fA-F]{2}:[\da-fA-F]{2})"
                )
                for match in pattern.finditer(result.stdout):
                    ip = match.group(1)
                    mac = match.group(2).upper()
                    if ip not in self._local_ips and not ip.endswith(".255"):
                        arp_candidates.append({"ip": ip, "mac": mac})

        except Exception as e:
            print(f"[NetworkScanner] ARP scan error: {e}")

        # Verify each candidate is actually reachable
        # First flush the ARP cache entry to force a real hardware check
        clients_found = []
        for candidate in arp_candidates:
            self._flush_arp_entry(candidate["ip"])  # clear stale cache
            if self._is_reachable(candidate["ip"]):
                clients_found.append(candidate)

        now = datetime.now()

        # Update client registry — sync with verified clients
        with self._lock:
            current_ips = {c["ip"] for c in clients_found}

            # Add new clients / update existing
            for client in clients_found:
                ip = client["ip"]
                if ip not in self._clients:
                    self._clients[ip] = ClientInfo(ip, client["mac"])
                    print(f"[NetworkScanner] + Client connected: {ip} ({client['mac']})")
                else:
                    self._clients[ip].mac = client["mac"]
                    self._clients[ip].last_seen = now
                self._arp_confirmed[ip] = now   # record confirmation time

            # Remove clients no longer in ARP+ping results
            stale_ips = [ip for ip in self._clients if ip not in current_ips]
            for ip in stale_ips:
                print(f"[NetworkScanner] - Client disconnected: {ip}")
                del self._clients[ip]
                self._arp_confirmed.pop(ip, None)

            # Safety net: hard-remove any client not confirmed in CLIENT_TIMEOUT seconds
            timeout_ips = [
                ip for ip, confirmed_at in self._arp_confirmed.items()
                if (now - confirmed_at).total_seconds() > self._CLIENT_TIMEOUT
                and ip in self._clients
            ]
            for ip in timeout_ips:
                print(f"[NetworkScanner] - Client timed out (no ARP): {ip}")
                del self._clients[ip]
                self._arp_confirmed.pop(ip, None)

        return clients_found

    def process_packets(self, packets):
        """
        Analyze captured packets to update per-client traffic stats
        and extract DNS queries.

        Args:
            packets: List of PacketInfo objects from PacketCapture
        """
        with self._lock:
            for pkt in packets:
                src = pkt.src_ip
                dst = pkt.dst_ip
                size = pkt.packet_length

                # Track traffic for known clients
                if src in self._clients:
                    self._clients[src].packets_sent += 1
                    self._clients[src].bytes_sent += size
                    self._clients[src].last_seen = pkt.timestamp
                    self._clients[src].update_from_packet(pkt)

                if dst in self._clients:
                    self._clients[dst].packets_received += 1
                    self._clients[dst].bytes_received += size
                    self._clients[dst].last_seen = pkt.timestamp

    def extract_dns_from_packets(self, raw_packets):
        """
        Extract DNS query domains from raw Scapy packets.
        This processes the actual Scapy packet objects (not PacketInfo).

        Args:
            raw_packets: Raw Scapy packet list
        """
        try:
            from scapy.all import DNS, DNSQR, IP
        except ImportError:
            return

        with self._lock:
            for pkt in raw_packets:
                try:
                    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                        if pkt[DNS].qr == 0:  # Query (not response)
                            domain = pkt[DNSQR].qname.decode(
                                "utf-8", errors="ignore"
                            ).rstrip(".")
                            src_ip = pkt[IP].src if pkt.haslayer(IP) else None

                            # Skip noise domains
                            if (domain and src_ip
                                    and not domain.endswith(".local")
                                    and not domain.endswith(".arpa")
                                    and len(domain) > 3):
                                if src_ip in self._clients:
                                    self._clients[src_ip].dns_queries.append(
                                        domain
                                    )
                                    # Keep only last 100 queries per client
                                    if len(self._clients[src_ip].dns_queries) > 100:
                                        self._clients[src_ip].dns_queries = \
                                            self._clients[src_ip].dns_queries[-100:]
                except Exception:
                    continue

    def get_all_clients(self):
        """
        Return clients that have ACTUAL captured packet traffic through
        this machine (packets_sent + packets_received > 0).

        Devices that are simply visible on the LAN (via ARP/ping) but
        not routing traffic through us are excluded. This prevents
        false positives when a device is on WiFi but not connected via
        the monitored interface (e.g. ICS ethernet cable removed).
        """
        with self._lock:
            return [
                c.to_dict() for c in self._clients.values()
                if c.packets_sent + c.packets_received > 0
            ]

    def purge_inactive_clients(self):
        """
        Remove clients that have sent/received NO packets through this
        machine in the last _TRAFFIC_TIMEOUT seconds.

        This handles devices that disconnect from a direct link (e.g. ICS
        ethernet cable) but remain reachable on the broader LAN via WiFi.
        Without this check they would stay forever because ARP+ping still
        works via the alternate path.
        """
        now = datetime.now()
        with self._lock:
            inactive = [
                ip for ip, client in self._clients.items()
                if (now - client.last_seen).total_seconds() > self._TRAFFIC_TIMEOUT
            ]
            for ip in inactive:
                print(f"[NetworkScanner] - Client removed (no traffic for "
                      f"{self._TRAFFIC_TIMEOUT}s): {ip}")
                del self._clients[ip]
                self._arp_confirmed.pop(ip, None)
        return inactive

    def get_client_count(self):
        """Get number of clients with actual captured packet traffic."""
        with self._lock:
            return sum(
                1 for c in self._clients.values()
                if c.packets_sent + c.packets_received > 0
            )

    def get_client_dns(self, ip, limit=20):
        """Get recent DNS queries for a specific client."""
        with self._lock:
            if ip in self._clients:
                queries = self._clients[ip].dns_queries[-limit:]
                return list(set(queries))  # Unique domains
            return []


# ── Quick Test ──────────────────────────────────────────────
if __name__ == "__main__":
    scanner = NetworkScanner()
    print(f"Local IPs: {scanner._local_ips}")
    print("\nScanning ARP table...")
    found = scanner.scan_arp_table()
    print(f"Found {len(found)} clients:")
    for c in found:
        print(f"  {c['ip']} ({c['mac']})")

    clients = scanner.get_all_clients()
    for c in clients:
        print(f"\n  Client: {c['ip']}")
        print(f"    MAC: {c['mac']}")
        print(f"    Hostname: {c['hostname'] or 'N/A'}")
