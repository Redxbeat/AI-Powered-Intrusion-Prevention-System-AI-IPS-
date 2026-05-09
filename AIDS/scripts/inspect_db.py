import sqlite3
import os

db_path = os.path.join(os.path.dirname(__file__), "..", "logs", "threats.db")
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
cur = conn.cursor()

# Recent threat logs
print("=== RECENT THREAT LOGS ===")
cur.execute("SELECT * FROM threat_logs ORDER BY timestamp DESC LIMIT 20")
for r in cur.fetchall():
    d = dict(r)
    print(f"  {d['timestamp'][:19]}  {d['src_ip']:>18}  {d['attack_type']:<20}  conf={d['confidence']:.2f}  action={d['action_taken']}")
    print(f"    Details: {d['details']}")

# Count by attack type
print("\n=== ATTACK TYPE BREAKDOWN ===")
cur.execute("SELECT attack_type, COUNT(*) as cnt FROM threat_logs GROUP BY attack_type ORDER BY cnt DESC")
for r in cur.fetchall():
    print(f"  {dict(r)['attack_type']:<20} {dict(r)['cnt']}")

# IPs blocked most often
print("\n=== MOST FREQUENTLY BLOCKED IPs ===")
cur.execute("SELECT ip, reason, COUNT(*) as cnt FROM blocked_ips GROUP BY ip ORDER BY cnt DESC LIMIT 15")
for r in cur.fetchall():
    print(f"  {dict(r)['ip']:>18}  reason={dict(r)['reason']:<20}  times={dict(r)['cnt']}")

# Currently active blocked
print("\n=== CURRENTLY ACTIVE BLOCKED ===")
cur.execute("SELECT ip, reason, blocked_at FROM blocked_ips WHERE is_active=1")
for r in cur.fetchall():
    d = dict(r)
    print(f"  {d['ip']:>18}  reason={d['reason']:<20}  at={d['blocked_at'][:19]}")

conn.close()
