"""
=============================================================
  AI-IPS Demo Web Application
=============================================================
  A small Flask web server that simulates a real website
  with intentionally VULNERABLE endpoints (for demo only).

  Built-in IDS middleware detects:
    • SQL Injection  — payload patterns in URL/POST body
    • Brute Force    — too many failed logins from one IP

  Defense:
    • Attacker IP is blocked automatically
    • All events are logged to AIDS threat DB
    • Live dashboard at http://localhost:5000/dashboard

  HOW TO RUN:
    1. pip install flask
    2. python scripts/demo_webapp.py
    3. Open http://localhost:5000/dashboard
    4. In another terminal, run the attack:
         python scripts/simulate_attacks_full.py --target 127.0.0.1 --port 5000 --mode sqli --count 30
         python scripts/simulate_attacks_full.py --target 127.0.0.1 --port 5000 --mode bruteforce --count 50 --yes
=============================================================
"""

import os
import re
import sys
import time
import sqlite3
import threading
import datetime
import collections
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:
    from flask import Flask, request, jsonify, render_template_string, g
except ImportError:
    print("[ERROR] Flask is not installed. Run:  pip install flask")
    sys.exit(1)

from config.settings import LOGS_DIR, DATABASE_PATH
from modules.firewall import FirewallManager

# Real OS-level firewall (blocks IP at network layer via netsh/iptables)
_firewall = FirewallManager()

# ── Constants ─────────────────────────────────────────────────────────────────
WEB_DB_PATH     = os.path.join(LOGS_DIR, "web_demo.db")
BRUTE_THRESHOLD = 5      # failed logins before block
BRUTE_WINDOW    = 30     # seconds to count failures in
PORT            = 5000

# ── In-memory IDS state ───────────────────────────────────────────────────────
_blocked_ips   = set()          # IPs blocked by IDS
_failed_logins = collections.defaultdict(list)   # ip → [timestamps]
_attack_log    = []             # list of dicts (for dashboard)
_lock          = threading.Lock()

# ── SQL Injection detection patterns ─────────────────────────────────────────
SQLI_PATTERNS = [
    r"('|(\%27))",
    r"(--|#|;)",
    r"\b(or|and)\b\s+\d+=\d+",
    r"\b(union|select|insert|update|delete|drop|truncate|exec|execute)\b",
    r"sleep\s*\(",
    r"benchmark\s*\(",
    r"information_schema",
    r"xp_cmdshell",
    r"\bor\b\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?",
    r"convert\s*\(int",
]
SQLI_REGEX = re.compile("|".join(SQLI_PATTERNS), re.IGNORECASE)


# ─────────────────────────────────────────────────────────────────────────────
#  Database setup
# ─────────────────────────────────────────────────────────────────────────────

def init_web_db():
    """Create the demo SQLite database with a users table."""
    conn = sqlite3.connect(WEB_DB_PATH)
    c = conn.cursor()

    # ── Users table (intentionally insecure passwords for demo) ──
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role     TEXT DEFAULT 'user'
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id    INTEGER PRIMARY KEY AUTOINCREMENT,
            name  TEXT,
            price REAL,
            stock INTEGER
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS attack_events (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp  TEXT,
            src_ip     TEXT,
            attack_type TEXT,
            endpoint   TEXT,
            payload    TEXT,
            action     TEXT
        )
    """)

    # Seed demo data
    try:
        c.executemany("INSERT INTO users (username, password, role) VALUES (?,?,?)", [
            ("admin",  "supersecret123", "admin"),
            ("alice",  "password123",    "user"),
            ("bob",    "qwerty",         "user"),
        ])
    except sqlite3.IntegrityError:
        pass

    try:
        c.executemany("INSERT INTO products (name, price, stock) VALUES (?,?,?)", [
            ("Laptop",    999.99, 10),
            ("Mouse",     29.99,  50),
            ("Keyboard",  79.99,  30),
            ("Monitor",   399.99,  8),
        ])
    except sqlite3.IntegrityError:
        pass

    conn.commit()
    conn.close()


def get_web_db():
    db = getattr(g, "_web_db", None)
    if db is None:
        db = g._web_db = sqlite3.connect(WEB_DB_PATH)
        db.row_factory = sqlite3.Row
    return db


def log_attack_event(src_ip, attack_type, endpoint, payload, action):
    """Log attack to DB and in-memory list."""
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    event = {
        "timestamp":   ts,
        "src_ip":      src_ip,
        "attack_type": attack_type,
        "endpoint":    endpoint,
        "payload":     payload[:120],
        "action":      action,
    }
    with _lock:
        _attack_log.append(event)
        if len(_attack_log) > 200:
            _attack_log.pop(0)

    try:
        conn = sqlite3.connect(WEB_DB_PATH)
        conn.execute(
            "INSERT INTO attack_events (timestamp,src_ip,attack_type,endpoint,payload,action) "
            "VALUES (?,?,?,?,?,?)",
            (ts, src_ip, attack_type, endpoint, payload[:120], action)
        )
        conn.commit()
        conn.close()
    except Exception:
        pass

    print(f"  [{ts}] \033[91m{attack_type}\033[0m  {src_ip}  {endpoint}  → {action}")


# ─────────────────────────────────────────────────────────────────────────────
#  IDS Middleware
# ─────────────────────────────────────────────────────────────────────────────

def get_client_ip():
    """Extract real client IP (respect X-Forwarded-For for demo)."""
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"


def check_blocked(ip):
    with _lock:
        return ip in _blocked_ips


def block_ip(ip, reason, endpoint, payload):
    with _lock:
        _blocked_ips.add(ip)
    log_attack_event(ip, reason, endpoint, payload, "BLOCKED")

    # ── Real OS firewall block (Windows netsh / Linux iptables) ──
    fw_result = _firewall.block_ip(ip, reason)
    if fw_result:
        print(f"  [Firewall] OS-level rule created → {ip} blocked at network layer")
    else:
        print(f"  [Firewall] WARNING: OS rule failed for {ip} (run as Administrator?)")


def detect_sqli(value: str) -> bool:
    return bool(SQLI_REGEX.search(value))


def ids_middleware_check(endpoint: str):
    """
    Call this at the start of every vulnerable endpoint.
    Returns (is_attack, attack_type, payload) or (False, None, None).
    """
    ip = get_client_ip()

    # 1. Already blocked?
    if check_blocked(ip):
        return True, "REPEAT_BLOCKED", ""

    # 2. Collect all input values
    all_inputs = []
    all_inputs.extend(request.args.values())
    all_inputs.extend(request.form.values())
    try:
        body = request.get_data(as_text=True)
        if body:
            all_inputs.append(body)
    except Exception:
        pass

    combined = " ".join(str(v) for v in all_inputs)

    # 3. SQL Injection check
    if detect_sqli(combined):
        block_ip(ip, "SQL_INJECTION", endpoint, combined[:120])
        return True, "SQL_INJECTION", combined[:120]

    return False, None, None


def record_failed_login(ip, endpoint, payload):
    """Track failed logins for brute force detection."""
    now = time.time()
    with _lock:
        # Purge old entries
        _failed_logins[ip] = [t for t in _failed_logins[ip] if now - t < BRUTE_WINDOW]
        _failed_logins[ip].append(now)
        count = len(_failed_logins[ip])

    log_attack_event(ip, "FAILED_LOGIN", endpoint, payload, f"attempt #{count}")

    if count >= BRUTE_THRESHOLD:
        block_ip(ip, "BRUTE_FORCE", endpoint, f"{count} failed logins in {BRUTE_WINDOW}s")
        return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
#  Flask App
# ─────────────────────────────────────────────────────────────────────────────

app = Flask(__name__)


@app.teardown_appcontext
def close_web_db(error):
    db = getattr(g, "_web_db", None)
    if db:
        db.close()


# ── HOME ──────────────────────────────────────────────────────────────────────

@app.route("/")
def home():
    ip = get_client_ip()
    blocked = check_blocked(ip)
    status_html = (
        '<div class="blocked">⛔ Your IP is BLOCKED by the IDS</div>'
        if blocked else
        '<div class="safe">✅ Connection Allowed</div>'
    )
    return render_template_string(HOME_TEMPLATE, status=status_html)


# ── LOGIN (vulnerable to SQLi + brute force) ─────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    ip = get_client_ip()

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # IDS Check — SQLi
        is_attack, atype, payload = ids_middleware_check("/login")
        if is_attack:
            return jsonify({
                "status":  "BLOCKED",
                "message": f"🛡️ IDS blocked your request — {atype} detected",
                "ip":      ip,
            }), 403

        # ── VULNERABLE query (intentional for demo) ──────────────────
        # In a real app you would NEVER do this — always use parameterised queries
        db = get_web_db()
        try:
            query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
            row   = db.execute(query).fetchone()
        except Exception as e:
            return jsonify({"status": "ERROR", "message": str(e)}), 500

        if row:
            return jsonify({
                "status":   "SUCCESS",
                "message":  f"Welcome, {row['username']}! (role: {row['role']})",
                "user_id":  row["id"],
            })
        else:
            # Brute force tracking
            brute = record_failed_login(ip, "/login", f"{username}:{password}")
            if brute:
                return jsonify({
                    "status":  "BLOCKED",
                    "message": "🛡️ IDS blocked your IP — Brute Force detected",
                    "ip":      ip,
                }), 403
            return jsonify({"status": "FAIL", "message": "Invalid credentials"}), 401

    return render_template_string(LOGIN_TEMPLATE)


# ── SEARCH (vulnerable to SQLi) ───────────────────────────────────────────────

@app.route("/search")
def search():
    ip    = get_client_ip()
    query = request.args.get("q", "")

    # IDS Check
    is_attack, atype, payload = ids_middleware_check("/search")
    if is_attack:
        return jsonify({
            "status":  "BLOCKED",
            "message": f"🛡️ IDS blocked your request — {atype} detected",
            "ip":      ip,
        }), 403

    # ── VULNERABLE query ──────────────────────────────────────────────
    db = get_web_db()
    try:
        sql    = f"SELECT * FROM products WHERE name LIKE '%{query}%'"
        rows   = db.execute(sql).fetchall()
        result = [dict(r) for r in rows]
    except Exception as e:
        result = []

    return jsonify({"status": "OK", "query": query, "results": result})


# ── API: IDS status ───────────────────────────────────────────────────────────

@app.route("/api/ids-status")
def ids_status():
    with _lock:
        blocked = list(_blocked_ips)
        log     = list(reversed(_attack_log))[:50]
    fw_blocked = list(_firewall.get_blocked_ips())
    return jsonify({
        "blocked_ips":      blocked,
        "blocked_count":    len(blocked),
        "attack_log":       log,
        "total_events":     len(_attack_log),
        "firewall_blocked": fw_blocked,       # OS-level blocks
        "firewall_count":   len(fw_blocked),
    })


@app.route("/api/unblock/<ip>")
def unblock(ip):
    with _lock:
        _blocked_ips.discard(ip)
    _firewall.unblock_ip(ip)   # Remove OS firewall rule too
    return jsonify({"status": "OK", "message": f"{ip} unblocked (web + firewall)"})


# ── DASHBOARD ─────────────────────────────────────────────────────────────────

@app.route("/dashboard")
def dashboard():
    return render_template_string(DASHBOARD_TEMPLATE)


# ─────────────────────────────────────────────────────────────────────────────
#  HTML Templates
# ─────────────────────────────────────────────────────────────────────────────

_CSS = """
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #e6edf3; }
  .container { max-width: 1100px; margin: 0 auto; padding: 20px; }
  h1 { color: #58a6ff; margin-bottom: 10px; }
  h2 { color: #79c0ff; margin: 20px 0 10px; border-bottom: 1px solid #30363d; padding-bottom: 6px; }
  .badge { display:inline-block; padding:3px 10px; border-radius:12px; font-size:12px; font-weight:bold; }
  .badge-red    { background:#3d1a1a; color:#ff6b6b; border:1px solid #ff4444; }
  .badge-green  { background:#1a3d1a; color:#69db7c; border:1px solid #44cc44; }
  .badge-yellow { background:#3d3a1a; color:#ffd43b; border:1px solid #ccaa00; }
  .badge-blue   { background:#1a2a3d; color:#74c0fc; border:1px solid #4499cc; }
  .blocked { background:#3d1a1a; border:1px solid #ff4444; color:#ff6b6b; padding:12px 20px; border-radius:8px; margin:10px 0; }
  .safe    { background:#1a3d1a; border:1px solid #44cc44; color:#69db7c; padding:12px 20px; border-radius:8px; margin:10px 0; }
  table { width:100%; border-collapse:collapse; margin-top:10px; font-size:13px; }
  th { background:#161b22; color:#8b949e; padding:10px; text-align:left; border-bottom:2px solid #30363d; }
  td { padding:9px 10px; border-bottom:1px solid #21262d; word-break:break-all; }
  tr:hover td { background:#161b22; }
  .stat-grid { display:grid; grid-template-columns:repeat(4,1fr); gap:15px; margin:15px 0; }
  .stat-card { background:#161b22; border:1px solid #30363d; border-radius:10px; padding:18px; text-align:center; }
  .stat-num  { font-size:36px; font-weight:bold; color:#58a6ff; }
  .stat-lbl  { font-size:12px; color:#8b949e; margin-top:4px; }
  .nav { display:flex; gap:15px; margin-bottom:25px; }
  .nav a { color:#58a6ff; text-decoration:none; padding:8px 16px; border:1px solid #30363d; border-radius:6px; }
  .nav a:hover { background:#161b22; }
  .pulse { animation: pulse 1s ease-in-out infinite alternate; }
  @keyframes pulse { from{opacity:1} to{opacity:0.5} }
  input,button { padding:10px 14px; border-radius:6px; border:1px solid #30363d; background:#161b22; color:#e6edf3; font-size:14px; }
  button { background:#1f6feb; border-color:#1f6feb; cursor:pointer; }
  button:hover { background:#388bfd; }
  .form-row { display:flex; gap:10px; margin:10px 0; }
</style>
"""

HOME_TEMPLATE = f"""<!DOCTYPE html>
<html>
<head><title>Demo Website — AI-IPS</title>{_CSS}</head>
<body><div class="container">
  <h1>🌐 Demo Web Application</h1>
  <p style="color:#8b949e;margin-bottom:15px">This is the vulnerable demo website used to demonstrate AI-IPS attack detection.</p>
  {{{{ status }}}}
  <nav class="nav">
    <a href="/login">🔐 Login Page</a>
    <a href="/search?q=Laptop">🔍 Search Products</a>
    <a href="/dashboard">🛡️ IDS Dashboard</a>
  </nav>
  <h2>Available Endpoints (Attack Targets)</h2>
  <table>
    <tr><th>Endpoint</th><th>Method</th><th>Vulnerability</th><th>IDS Protection</th></tr>
    <tr><td>/login</td><td>POST</td><td><span class="badge badge-red">SQL Injection</span> <span class="badge badge-red">Brute Force</span></td><td><span class="badge badge-green">Active</span></td></tr>
    <tr><td>/search?q=</td><td>GET</td><td><span class="badge badge-red">SQL Injection</span></td><td><span class="badge badge-green">Active</span></td></tr>
  </table>
</div></body></html>"""

LOGIN_TEMPLATE = f"""<!DOCTYPE html>
<html>
<head><title>Login — Demo Site</title>{_CSS}</head>
<body><div class="container">
  <h1>🔐 Login</h1>
  <nav class="nav"><a href="/">← Home</a><a href="/dashboard">🛡️ IDS Dashboard</a></nav>
  <form method="POST" style="max-width:400px">
    <div class="form-row"><input name="username" placeholder="Username" style="flex:1"></div>
    <div class="form-row"><input name="password" type="password" placeholder="Password" style="flex:1"></div>
    <div class="form-row"><button type="submit">Login</button></div>
  </form>
  <p style="color:#8b949e;margin-top:20px;font-size:13px">
    Demo credentials: admin / supersecret123 &nbsp;|&nbsp; alice / password123
  </p>
</div></body></html>"""

DASHBOARD_TEMPLATE = f"""<!DOCTYPE html>
<html>
<head>
  <title>IDS Dashboard — AI-IPS</title>
  {_CSS}
  <script>
    async function refresh() {{
      const r   = await fetch('/api/ids-status');
      const d   = await r.json();
      const log = d.attack_log;

      // Stats
      const sqli   = log.filter(e => e.attack_type === 'SQL_INJECTION').length;
      const brute  = log.filter(e => e.attack_type === 'BRUTE_FORCE').length;
      const failed = log.filter(e => e.attack_type === 'FAILED_LOGIN').length;
      document.getElementById('stat-total').textContent   = d.total_events;
      document.getElementById('stat-blocked').textContent = d.blocked_count;
      document.getElementById('stat-sqli').textContent    = sqli;
      document.getElementById('stat-brute').textContent   = brute + failed;

      // Blocked IPs
      const bDiv = document.getElementById('blocked-ips');
      if (d.blocked_ips.length === 0) {{
        bDiv.innerHTML = '<p style="color:#8b949e">No IPs blocked yet — run an attack to see defense in action.</p>';
      }} else {{
        bDiv.innerHTML = d.blocked_ips.map(ip =>
          `<span class="badge badge-red" style="margin:4px;font-size:14px">⛔ ${{ip}}</span>
           <a href="/api/unblock/${{ip}}" style="color:#69db7c;font-size:11px;margin-right:10px">[unblock]</a>`
        ).join('');
      }}

      // Attack log table
      const tbody = document.getElementById('log-body');
      tbody.innerHTML = log.map(e => {{
        const color = e.attack_type === 'SQL_INJECTION' ? 'badge-red' :
                      e.attack_type === 'BRUTE_FORCE'   ? 'badge-yellow' :
                      e.action === 'BLOCKED'             ? 'badge-red' : 'badge-blue';
        const actionColor = e.action === 'BLOCKED' ? 'badge-red' : 'badge-yellow';
        return `<tr>
          <td>${{e.timestamp}}</td>
          <td>${{e.src_ip}}</td>
          <td><span class="badge ${{color}}">${{e.attack_type}}</span></td>
          <td>${{e.endpoint}}</td>
          <td style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${{e.payload}}">${{e.payload}}</td>
          <td><span class="badge ${{actionColor}}">${{e.action}}</span></td>
        </tr>`;
      }}).join('');
    }}

    refresh();
    setInterval(refresh, 2000);
  </script>
</head>
<body><div class="container">
  <h1>🛡️ AI-IPS — Web Attack Dashboard</h1>
  <p style="color:#8b949e;margin-bottom:10px">Auto-refreshes every 2 seconds &nbsp;
    <span class="pulse" style="color:#ff4444">●</span> LIVE
  </p>
  <nav class="nav">
    <a href="/">🌐 Demo Site</a>
    <a href="/login">🔐 Login</a>
    <a href="/search?q=test">🔍 Search</a>
  </nav>

  <div class="stat-grid">
    <div class="stat-card">
      <div class="stat-num" id="stat-total">0</div>
      <div class="stat-lbl">Total Events</div>
    </div>
    <div class="stat-card">
      <div class="stat-num" id="stat-blocked" style="color:#ff6b6b">0</div>
      <div class="stat-lbl">Blocked IPs</div>
    </div>
    <div class="stat-card">
      <div class="stat-num" id="stat-sqli" style="color:#ffd43b">0</div>
      <div class="stat-lbl">SQLi Attacks</div>
    </div>
    <div class="stat-card">
      <div class="stat-num" id="stat-brute" style="color:#ff9900">0</div>
      <div class="stat-lbl">Brute Force</div>
    </div>
  </div>

  <h2>⛔ Blocked IPs</h2>
  <div id="blocked-ips"><p style="color:#8b949e">Loading...</p></div>

  <h2>📋 Attack Event Log</h2>
  <table>
    <thead>
      <tr>
        <th>Timestamp</th><th>Source IP</th><th>Attack Type</th>
        <th>Endpoint</th><th>Payload</th><th>Action</th>
      </tr>
    </thead>
    <tbody id="log-body">
      <tr><td colspan="6" style="color:#8b949e;text-align:center">Waiting for events...</td></tr>
    </tbody>
  </table>
</div></body></html>"""


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  AI-IPS Demo Web Application")
    print("=" * 60)
    print(f"  Initialising demo database at: {WEB_DB_PATH}")
    init_web_db()
    print(f"\n  🌐  Demo site   →  http://localhost:{PORT}/")
    print(f"  🔐  Login page  →  http://localhost:{PORT}/login")
    print(f"  🛡️  Dashboard   →  http://localhost:{PORT}/dashboard")
    print()
    print("  Attack commands (run in a second terminal):")
    print(f"    SQL Injection:  python scripts/simulate_attacks_full.py --target 127.0.0.1 --port {PORT} --mode sqli --count 30 --yes")
    print(f"    Brute Force:    python scripts/simulate_attacks_full.py --target 127.0.0.1 --port {PORT} --mode bruteforce --port {PORT} --count 50 --yes")
    print()
    print("  Press Ctrl+C to stop.")
    print("=" * 60)

    app.run(host="0.0.0.0", port=PORT, debug=False, threaded=True)
