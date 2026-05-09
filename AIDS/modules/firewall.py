"""
=============================================================
Module 6: Firewall Automation
=============================================================
Automatically blocks/unblocks malicious IPs using:
  - Windows: netsh advfirewall
  - Linux:   iptables
Prevents duplicate blocking and respects whitelist.
=============================================================
"""

import subprocess
import sys
import os
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config.settings import (
    IS_WINDOWS, IS_LINUX, FIREWALL_RULE_PREFIX,
    WHITELISTED_IPS, MAX_BLOCKED_IPS
)


class FirewallManager:
    """
    Cross-platform firewall manager for IP blocking/unblocking.
    Thread-safe with duplicate prevention.
    """

    def __init__(self):
        self._blocked_ips = set()
        self._lock = threading.Lock()

    def block_ip(self, ip, reason="Malicious traffic detected"):
        """
        Block an IP address via firewall rule.
        
        Returns:
            True if blocked successfully, False otherwise.
        """
        # Safety checks
        if ip in WHITELISTED_IPS:
            print(f"[Firewall] SKIPPED: {ip} is whitelisted")
            return False

        with self._lock:
            if ip in self._blocked_ips:
                return False  # Already blocked

            if len(self._blocked_ips) >= MAX_BLOCKED_IPS:
                print(f"[Firewall] WARNING: Max blocked IPs reached ({MAX_BLOCKED_IPS})")
                return False

        # Execute platform-specific block command
        success = False
        rule_name = f"{FIREWALL_RULE_PREFIX}_{ip.replace('.', '_')}"

        try:
            if IS_WINDOWS:
                success = self._windows_block(ip, rule_name)
            elif IS_LINUX:
                success = self._linux_block(ip)
            else:
                print(f"[Firewall] Unsupported platform")
                return False

            if success:
                with self._lock:
                    self._blocked_ips.add(ip)
                print(f"[Firewall] BLOCKED: {ip} ({reason})")
            return success

        except Exception as e:
            print(f"[Firewall] ERROR blocking {ip}: {e}")
            return False

    def unblock_ip(self, ip):
        """
        Remove firewall block for an IP.
        
        Returns:
            True if unblocked successfully, False otherwise.
        """
        rule_name = f"{FIREWALL_RULE_PREFIX}_{ip.replace('.', '_')}"
        success = False

        try:
            if IS_WINDOWS:
                success = self._windows_unblock(rule_name)
            elif IS_LINUX:
                success = self._linux_unblock(ip)

            if success:
                with self._lock:
                    self._blocked_ips.discard(ip)
                print(f"[Firewall] UNBLOCKED: {ip}")
            return success

        except Exception as e:
            print(f"[Firewall] ERROR unblocking {ip}: {e}")
            return False

    def is_blocked(self, ip):
        """Check if an IP is currently blocked."""
        with self._lock:
            return ip in self._blocked_ips

    def get_blocked_ips(self):
        """Get set of currently blocked IPs."""
        with self._lock:
            return self._blocked_ips.copy()

    # ── Windows Implementation ──────────────────────────────

    def _windows_block(self, ip, rule_name):
        """Block IP using Windows netsh advfirewall."""
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=in",
            "action=block",
            f"remoteip={ip}",
            "protocol=any",
            "enable=yes",
        ]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10
        )
        return result.returncode == 0

    def _windows_unblock(self, rule_name):
        """Remove Windows firewall rule."""
        cmd = [
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={rule_name}",
        ]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10
        )
        return result.returncode == 0

    # ── Linux Implementation ────────────────────────────────

    def _linux_block(self, ip):
        """Block IP using iptables."""
        cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10
        )
        return result.returncode == 0

    def _linux_unblock(self, ip):
        """Remove iptables rule."""
        cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10
        )
        return result.returncode == 0


# ── Quick Test ──────────────────────────────────────────────
if __name__ == "__main__":
    fw = FirewallManager()
    test_ip = "203.0.113.99"
    print(f"Blocking {test_ip}...")
    fw.block_ip(test_ip, "Test block")
    print(f"Is blocked: {fw.is_blocked(test_ip)}")
    print(f"Blocked IPs: {fw.get_blocked_ips()}")
    print(f"Unblocking {test_ip}...")
    fw.unblock_ip(test_ip)
    print(f"Is blocked: {fw.is_blocked(test_ip)}")
