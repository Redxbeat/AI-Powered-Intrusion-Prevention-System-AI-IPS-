"""
=============================================================
Module 7: SQLite Logging System
=============================================================
Persistent logging of threats, blocked IPs, and traffic
statistics using SQLite for dashboard consumption.
=============================================================
"""

import sqlite3
import threading
from datetime import datetime
import json
import sys, os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config.settings import DATABASE_PATH


class ThreatLogger:
    """
    Thread-safe SQLite logger for the IPS system.
    
    Tables:
        - threat_logs:   Individual threat events
        - blocked_ips:   Currently/historically blocked IPs
        - traffic_stats: Periodic traffic summaries
    """

    def __init__(self, db_path=None):
        self.db_path = db_path or DATABASE_PATH
        self._local = threading.local()
        self._init_db()

    def _get_conn(self):
        """Get a thread-local database connection."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(
                self.db_path, check_same_thread=False
            )
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn

    def _init_db(self):
        """Create tables if they don't exist."""
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS threat_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT DEFAULT 'N/A',
                attack_type TEXT NOT NULL,
                confidence REAL DEFAULT 0.0,
                action_taken TEXT DEFAULT 'logged',
                details TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                blocked_at TEXT NOT NULL,
                reason TEXT DEFAULT '',
                is_active INTEGER DEFAULT 1,
                unblocked_at TEXT DEFAULT NULL
            );

            CREATE TABLE IF NOT EXISTS traffic_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                total_packets INTEGER DEFAULT 0,
                normal_count INTEGER DEFAULT 0,
                malicious_count INTEGER DEFAULT 0,
                unique_ips INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS usb_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                device_id TEXT NOT NULL,
                description TEXT DEFAULT '',
                event_type TEXT DEFAULT 'inserted',
                is_authorized INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS connected_clients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                ip TEXT NOT NULL,
                mac TEXT DEFAULT 'Unknown',
                hostname TEXT DEFAULT '',
                packets_sent INTEGER DEFAULT 0,
                packets_received INTEGER DEFAULT 0,
                bytes_sent INTEGER DEFAULT 0,
                bytes_received INTEGER DEFAULT 0,
                last_seen TEXT DEFAULT '',
                device_vendor TEXT DEFAULT 'Unknown',
                os_guess TEXT DEFAULT 'Unknown',
                top_ports TEXT DEFAULT '[]',
                protocol_stats TEXT DEFAULT '{}'
            );

            CREATE TABLE IF NOT EXISTS dns_queries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                client_ip TEXT NOT NULL,
                domain TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_threat_timestamp
                ON threat_logs(timestamp);
            CREATE INDEX IF NOT EXISTS idx_blocked_active
                ON blocked_ips(is_active);
            CREATE INDEX IF NOT EXISTS idx_stats_timestamp
                ON traffic_stats(timestamp);
            CREATE INDEX IF NOT EXISTS idx_usb_timestamp
                ON usb_events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_clients_ip
                ON connected_clients(ip);
            CREATE INDEX IF NOT EXISTS idx_dns_client
                ON dns_queries(client_ip);
        """)
        conn.commit()

    def log_threat(self, src_ip, attack_type, confidence=0.0,
                   dst_ip="N/A", action="logged", details=""):
        """Log a threat event."""
        conn = self._get_conn()
        conn.execute(
            """INSERT INTO threat_logs
               (timestamp, src_ip, dst_ip, attack_type, confidence,
                action_taken, details)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (datetime.now().isoformat(), src_ip, dst_ip,
             attack_type, confidence, action, details)
        )
        conn.commit()

    def log_block(self, ip, reason=""):
        """Log an IP block event."""
        conn = self._get_conn()
        conn.execute(
            """INSERT INTO blocked_ips (ip, blocked_at, reason, is_active)
               VALUES (?, ?, ?, 1)""",
            (ip, datetime.now().isoformat(), reason)
        )
        conn.commit()

    def log_unblock(self, ip):
        """Mark an IP as unblocked."""
        conn = self._get_conn()
        conn.execute(
            """UPDATE blocked_ips SET is_active = 0,
               unblocked_at = ? WHERE ip = ? AND is_active = 1""",
            (datetime.now().isoformat(), ip)
        )
        conn.commit()

    def log_traffic_stats(self, total, normal, malicious, unique_ips):
        """Log periodic traffic statistics."""
        conn = self._get_conn()
        conn.execute(
            """INSERT INTO traffic_stats
               (timestamp, total_packets, normal_count,
                malicious_count, unique_ips)
               VALUES (?, ?, ?, ?, ?)""",
            (datetime.now().isoformat(), total, normal,
             malicious, unique_ips)
        )
        conn.commit()

    # ── USB Event Methods ───────────────────────────────────

    def log_usb_event(self, device_id, description="",
                      event_type="inserted", is_authorized=False):
        """Log a USB device event."""
        conn = self._get_conn()
        conn.execute(
            """INSERT INTO usb_events
               (timestamp, device_id, description, event_type, is_authorized)
               VALUES (?, ?, ?, ?, ?)""",
            (datetime.now().isoformat(), device_id, description,
             event_type, 1 if is_authorized else 0)
        )
        conn.commit()

    def get_usb_events(self, limit=50):
        """Get recent USB events."""
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT * FROM usb_events
               ORDER BY timestamp DESC LIMIT ?""", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    # ── Connected Client Methods ────────────────────────────

    def log_client_snapshot(self, clients):
        """
        Log a snapshot of all connected clients.
        Replaces old data to keep only latest state.

        Args:
            clients: List of client dicts from NetworkScanner.get_all_clients()
        """
        conn = self._get_conn()
        conn.execute("DELETE FROM connected_clients")
        for c in clients:
            conn.execute(
                """INSERT INTO connected_clients
                   (timestamp, ip, mac, hostname, packets_sent,
                    packets_received, bytes_sent, bytes_received, last_seen,
                    device_vendor, os_guess, top_ports, protocol_stats)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (datetime.now().isoformat(), c["ip"], c["mac"],
                 c.get("hostname", ""), c.get("packets_sent", 0),
                 c.get("packets_received", 0), c.get("bytes_sent", 0),
                 c.get("bytes_received", 0), c.get("last_seen", ""),
                 c.get("device_vendor", "Unknown"), c.get("os_guess", "Unknown"),
                 json.dumps(c.get("top_ports", [])), json.dumps(c.get("protocol_stats", {})))
            )
        conn.commit()

    def remove_client(self, ip: str):
        """Immediately remove a specific client IP from the dashboard DB."""
        conn = self._get_conn()
        conn.execute("DELETE FROM connected_clients WHERE ip = ?", (ip,))
        conn.commit()

    def get_connected_clients(self):
        """Get all currently connected clients."""
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT * FROM connected_clients
               ORDER BY packets_sent + packets_received DESC"""
        ).fetchall()
        
        clients = []
        for r in rows:
            d = dict(r)
            try:
                d["top_ports"] = json.loads(d["top_ports"])
                d["protocol_stats"] = json.loads(d["protocol_stats"])
            except:
                d["top_ports"] = []
                d["protocol_stats"] = {}
            clients.append(d)
        return clients

    def log_dns_query(self, client_ip, domain):
        """Log a DNS query from a client."""
        conn = self._get_conn()
        conn.execute(
            """INSERT INTO dns_queries (timestamp, client_ip, domain)
               VALUES (?, ?, ?)""",
            (datetime.now().isoformat(), client_ip, domain)
        )
        conn.commit()

    def log_dns_queries_bulk(self, queries):
        """
        Log multiple DNS queries efficiently.

        Args:
            queries: List of (client_ip, domain) tuples
        """
        if not queries:
            return
        conn = self._get_conn()
        now = datetime.now().isoformat()
        conn.executemany(
            """INSERT INTO dns_queries (timestamp, client_ip, domain)
               VALUES (?, ?, ?)""",
            [(now, ip, domain) for ip, domain in queries]
        )
        conn.commit()

    def get_client_dns_queries(self, client_ip=None, limit=30):
        """Get recent DNS queries, optionally filtered by client IP."""
        conn = self._get_conn()
        if client_ip:
            rows = conn.execute(
                """SELECT DISTINCT domain, MAX(timestamp) as last_queried
                   FROM dns_queries WHERE client_ip = ?
                   GROUP BY domain
                   ORDER BY last_queried DESC LIMIT ?""",
                (client_ip, limit)
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT client_ip, domain, MAX(timestamp) as last_queried
                   FROM dns_queries
                   GROUP BY client_ip, domain
                   ORDER BY last_queried DESC LIMIT ?""",
                (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    # ── Original Query Methods ──────────────────────────────

    def get_recent_threats(self, limit=100):
        """Get recent threat logs."""
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT * FROM threat_logs
               ORDER BY timestamp DESC LIMIT ?""", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_blocked_ips(self, active_only=True):
        """Get blocked IPs."""
        conn = self._get_conn()
        if active_only:
            rows = conn.execute(
                "SELECT * FROM blocked_ips WHERE is_active = 1"
                " ORDER BY blocked_at DESC"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM blocked_ips ORDER BY blocked_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def get_traffic_stats(self, limit=100):
        """Get recent traffic stats for graphing."""
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT * FROM traffic_stats
               ORDER BY timestamp DESC LIMIT ?""", (limit,)
        ).fetchall()
        return [dict(r) for r in reversed(rows)]

    def get_attack_summary(self):
        """Get attack type distribution for pie chart."""
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT attack_type, COUNT(*) as count
               FROM threat_logs GROUP BY attack_type
               ORDER BY count DESC"""
        ).fetchall()
        return [dict(r) for r in rows]

    def get_top_attackers(self, limit=10):
        """Get top attacker IPs."""
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT src_ip, COUNT(*) as count
               FROM threat_logs GROUP BY src_ip
               ORDER BY count DESC LIMIT ?""", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_stats_count(self):
        """Get summary counts for KPI cards."""
        conn = self._get_conn()
        threats = conn.execute(
            "SELECT COUNT(*) FROM threat_logs"
        ).fetchone()[0]
        blocked = conn.execute(
            "SELECT COUNT(*) FROM blocked_ips WHERE is_active = 1"
        ).fetchone()[0]
        stats = conn.execute(
            """SELECT COALESCE(SUM(total_packets), 0) as total,
                      COALESCE(SUM(normal_count), 0) as normal,
                      COALESCE(SUM(malicious_count), 0) as malicious
               FROM traffic_stats"""
        ).fetchone()
        clients = conn.execute(
            "SELECT COUNT(DISTINCT ip) FROM connected_clients"
        ).fetchone()[0]
        return {
            "total_threats": threats,
            "blocked_ips": blocked,
            "total_packets": stats[0],
            "normal_packets": stats[1],
            "malicious_packets": stats[2],
            "connected_clients": clients,
        }

