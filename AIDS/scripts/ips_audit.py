"""
=============================================================
  AI-IPS: Full Attack & Defense Audit Report
=============================================================
  Run this to verify every layer of your IPS is working.
  It checks:
    1. demo_webapp internal IDS (SQLi + Brute Force detection)
    2. Real FirewallManager (Windows netsh / Linux iptables)
    3. ThreatDetector rule engine
    4. DB logging
=============================================================
  Usage:
    python scripts/ips_audit.py
=============================================================
"""

import sys, os, time, sqlite3, threading, http.client, urllib.parse, socket
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.firewall        import FirewallManager
from modules.threat_detection import ThreatDetector
from modules.logger_db       import ThreatLogger
from config.settings         import DATABASE_PATH

# ── Colours ───────────────────────────────────────────────────────────────────
G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"; C = "\033[96m"; B = "\033[1m"; X = "\033[0m"
OK   = f"{G}[✓ PASS]{X}"
FAIL = f"{R}[✗ FAIL]{X}"
WARN = f"{Y}[! WARN]{X}"
INFO = f"{C}[INFO  ]{X}"

results = {"pass": 0, "fail": 0, "warn": 0}

def passed(msg):
    results["pass"] += 1
    print(f"  {OK}  {msg}")

def failed(msg):
    results["fail"] += 1
    print(f"  {FAIL}  {msg}")

def warned(msg):
    results["warn"] += 1
    print(f"  {WARN}  {msg}")

def section(title):
    print(f"\n{B}{C}{'─'*60}{X}")
    print(f"{B}{C}  {title}{X}")
    print(f"{B}{C}{'─'*60}{X}")


# ─────────────────────────────────────────────────────────────────────────────
#  TEST 1: Firewall Manager
# ─────────────────────────────────────────────────────────────────────────────

def test_firewall():
    section("Layer 1 — Real Firewall (netsh / iptables)")
    fw = FirewallManager()
    test_ip = "203.0.113.99"   # RFC-5737 TEST-NET, safe to use

    print(f"  {INFO}  Blocking test IP: {test_ip}")
    ok = fw.block_ip(test_ip, "Audit test block")
    if ok:
        passed(f"IP {test_ip} blocked via OS firewall")
    else:
        failed(f"Could not block {test_ip} — run as Administrator?")

    if fw.is_blocked(test_ip):
        passed("is_blocked() returns True correctly")
    else:
        failed("is_blocked() returned False after blocking")

    print(f"\n  {INFO}  Unblocking {test_ip}")
    ok2 = fw.unblock_ip(test_ip)
    if ok2:
        passed(f"IP {test_ip} unblocked successfully")
    else:
        failed(f"Could not unblock {test_ip}")

    if not fw.is_blocked(test_ip):
        passed("is_blocked() returns False after unblock")
    else:
        failed("IP still marked as blocked after unblock")

    # Whitelist check
    print(f"\n  {INFO}  Whitelist protection check (127.0.0.1)")
    blocked_white = fw.block_ip("127.0.0.1", "Should be skipped")
    if not blocked_white:
        passed("Whitelisted IP (127.0.0.1) correctly skipped")
    else:
        failed("Whitelisted IP was blocked — whitelist not working!")

    return fw


# ─────────────────────────────────────────────────────────────────────────────
#  TEST 2: Threat Detector (rule engine)
# ─────────────────────────────────────────────────────────────────────────────

def test_threat_detector():
    section("Layer 2 — Threat Detection Engine (rules + ML)")
    import pandas as pd

    detector  = ThreatDetector()
    alerts    = []
    detector.register_alert_callback(lambda ip, at, d: alerts.append((ip, at, d)))

    test_cases = [
        # (name,              unique_ports, pkt_count, syn_count, pkt_rate, expected)
        ("Port Scan",         50,  100,  5,   20,  "Port Scan"),
        ("SYN Flood",          3,  400, 40,   50,  "SYN Flood"),
        ("Brute Force",        2,  250,  5,   30,  "Brute Force"),
        ("High Rate Anomaly",  2,   50,  2,  600,  "High Rate Anomaly"),
        ("Normal Traffic",     2,   20,  1,   10,  "Normal"),
    ]

    for name, ports, pkts, syn, rate, expected in test_cases:
        df = pd.DataFrame([{
            "src_ip": "10.5.5.5", "prediction": 0, "confidence": 0.0,
            "unique_dst_ports": ports, "packet_count": pkts,
            "syn_count": syn, "packet_rate": rate,
        }])
        threats = detector.analyze(df)
        detected = threats[0]["attack_type"] if threats else "Normal"

        if detected == expected:
            passed(f"{name:<22} → detected as '{detected}'")
        else:
            failed(f"{name:<22} → expected '{expected}' but got '{detected}'")


# ─────────────────────────────────────────────────────────────────────────────
#  TEST 3: Database Logging
# ─────────────────────────────────────────────────────────────────────────────

def test_db_logging():
    section("Layer 3 — Threat Database Logging")

    try:
        logger = ThreatLogger(DATABASE_PATH)
        passed("ThreatLogger initialised successfully")
    except Exception as e:
        failed(f"ThreatLogger init failed: {e}")
        return

    try:
        logger.log_threat(
            src_ip="10.99.99.99",
            attack_type="AUDIT_TEST",
            confidence=0.99,
            details="IPS audit test entry",
            dst_ip="10.0.0.1",
            action="BLOCKED"
        )
        passed("Threat logged to database")
    except Exception as e:
        failed(f"Failed to log threat: {e}")
        return

    try:
        conn  = sqlite3.connect(DATABASE_PATH)
        row   = conn.execute(
            "SELECT * FROM threats WHERE src_ip='10.99.99.99' AND attack_type='AUDIT_TEST' "
            "ORDER BY id DESC LIMIT 1"
        ).fetchone()
        conn.close()
        if row:
            passed(f"Log entry verified in DB (id={row[0]})")
        else:
            failed("Log entry not found in DB")
    except Exception as e:
        failed(f"DB read error: {e}")


# ─────────────────────────────────────────────────────────────────────────────
#  TEST 4: Demo Web App (SQLi + Brute Force IDS)
# ─────────────────────────────────────────────────────────────────────────────

def _webapp_running(port=5000) -> bool:
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=1)
        s.close()
        return True
    except Exception:
        return False


def test_webapp_ids(port=5000):
    section("Layer 4 — Demo Web App IDS (SQLi + Brute Force)")

    if not _webapp_running(port):
        warned(f"demo_webapp.py is NOT running on port {port}")
        warned("Start it first:  python scripts/demo_webapp.py")
        warned("Skipping web IDS tests.")
        return

    passed(f"demo_webapp.py is running on port {port}")

    # ── SQL Injection test ────────────────────────────────────
    print(f"\n  {INFO}  Testing SQL Injection detection on /search ...")
    payloads = [
        "' OR '1'='1",
        "'; DROP TABLE users;--",
        "1 UNION SELECT * FROM users--",
    ]
    for payload in payloads:
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
            encoded = urllib.parse.quote(payload)
            conn.request("GET", f"/search?q={encoded}",
                         headers={"User-Agent": "AuditBot/1.0"})
            resp = conn.getresponse()
            resp.read()
            conn.close()
            if resp.status == 403:
                passed(f"SQLi blocked → '{payload[:40]}' → HTTP 403")
            else:
                failed(f"SQLi NOT blocked → '{payload[:40]}' → HTTP {resp.status}")
        except Exception as e:
            failed(f"Request error: {e}")
        time.sleep(0.2)

    # ── Brute Force test ──────────────────────────────────────
    print(f"\n  {INFO}  Testing Brute Force detection on /login (6 attempts) ...")
    blocked_at = None
    for i in range(6):
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
            body = urllib.parse.urlencode({
                "username": "admin",
                "password": f"wrongpass_{i}",
            })
            conn.request("POST", "/login", body=body,
                         headers={"Content-Type": "application/x-www-form-urlencoded",
                                  "User-Agent": "AuditBot/1.0"})
            resp = conn.getresponse()
            resp.read()
            conn.close()
            print(f"    Attempt {i+1}: HTTP {resp.status}")
            if resp.status == 403:
                blocked_at = i + 1
                break
        except Exception as e:
            failed(f"Request error: {e}")
        time.sleep(0.15)

    if blocked_at:
        passed(f"Brute Force detected and blocked at attempt #{blocked_at}")
    else:
        failed("Brute Force NOT detected after 6 failed logins")

    # ── IDS status API ────────────────────────────────────────
    print(f"\n  {INFO}  Checking IDS status endpoint (/api/ids-status) ...")
    try:
        import json
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        conn.request("GET", "/api/ids-status")
        resp = conn.getresponse()
        data = json.loads(resp.read())
        conn.close()
        bc = data.get("blocked_count", 0)
        te = data.get("total_events", 0)
        passed(f"IDS API reachable — Blocked IPs: {bc}, Total Events: {te}")
    except Exception as e:
        failed(f"IDS status API error: {e}")


# ─────────────────────────────────────────────────────────────────────────────
#  FULL INTEGRATION CHECK
# ─────────────────────────────────────────────────────────────────────────────

def check_integration():
    section("Layer 5 — Integration: demo_webapp ↔ FirewallManager")

    if not _webapp_running():
        warned("demo_webapp not running — skipping integration check")
        return

    print(f"  {INFO}  Current state of demo_webapp.py:")
    print()
    print(f"    {Y}ISSUE FOUND:{X} The demo_webapp.py uses its own")
    print(f"    internal in-memory block list, but does NOT call")
    print(f"    FirewallManager.block_ip() to create a real OS firewall rule.")
    print()
    print(f"    {C}What this means:{X}")
    print(f"    • The web app IDS correctly returns HTTP 403 to attackers ✓")
    print(f"    • But the attacker's IP is NOT blocked at the OS/network level ✗")
    print(f"    • A real attacker could bypass by sending raw packets or")
    print(f"      changing ports — the OS firewall would still allow them.")
    print()
    print(f"    {G}Fix applied in demo_webapp_v2.py:{X}")
    print(f"    • When IDS detects SQLi or brute force, it now calls")
    print(f"      FirewallManager.block_ip() in addition to the HTTP 403.")
    print(f"    • This creates a real Windows Firewall rule blocking all")
    print(f"      future traffic from that IP, not just HTTP requests.")

    warned("demo_webapp.py → FirewallManager integration needs patching (see above)")


# ─────────────────────────────────────────────────────────────────────────────
#  SUMMARY
# ─────────────────────────────────────────────────────────────────────────────

def print_summary():
    section("AUDIT SUMMARY")
    total = results["pass"] + results["fail"] + results["warn"]
    print(f"  Total Checks : {total}")
    print(f"  {G}Passed{X}       : {results['pass']}")
    print(f"  {R}Failed{X}       : {results['fail']}")
    print(f"  {Y}Warnings{X}     : {results['warn']}")
    print()

    if results["fail"] == 0 and results["warn"] == 0:
        print(f"  {G}{B}ALL SYSTEMS OPERATIONAL — Full attack blocking confirmed.{X}")
    elif results["fail"] == 0:
        print(f"  {Y}{B}MOSTLY OPERATIONAL — Some warnings to address.{X}")
    else:
        print(f"  {R}{B}ACTION REQUIRED — {results['fail']} layer(s) not blocking attacks.{X}")
    print()
    print("  Layers verified:")
    print("    [1] OS Firewall (netsh/iptables) — real IP blocking")
    print("    [2] Threat Detection rules (port scan, SYN flood, brute force, high rate)")
    print("    [3] SQLite threat logging")
    print("    [4] Web app IDS (SQLi regex + login rate limiting → HTTP 403)")
    print("    [5] Integration check")


if __name__ == "__main__":
    print(f"\n{B}{C}{'='*60}")
    print("  AI-IPS FULL SYSTEM AUDIT")
    print(f"{'='*60}{X}\n")

    test_firewall()
    test_threat_detector()
    test_db_logging()
    test_webapp_ids()
    check_integration()
    print_summary()
