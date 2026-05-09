"""
=============================================================
Module 9: USB Intrusion Detection (Advanced)
=============================================================
Monitors USB device insertion events on Windows using WMI.
Logs unauthorized devices and can trigger alerts.
=============================================================
"""

import threading
import time
from datetime import datetime
import sys, os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config.settings import USB_MONITOR_ENABLED, USB_WHITELIST, IS_WINDOWS


class USBEvent:
    """Container for USB device event data."""
    def __init__(self, device_id, description, event_type, timestamp=None):
        self.device_id = device_id
        self.description = description
        self.event_type = event_type  # "inserted" or "removed"
        self.timestamp = timestamp or datetime.now()
        self.is_authorized = device_id in USB_WHITELIST

    def to_dict(self):
        return {
            "device_id": self.device_id,
            "description": self.description,
            "event_type": self.event_type,
            "timestamp": self.timestamp.isoformat(),
            "is_authorized": self.is_authorized,
        }


class USBMonitor:
    """
    Monitors USB device insertions on Windows.
    Detects unauthorized devices based on whitelist.
    """

    def __init__(self):
        self._running = False
        self._thread = None
        self._events = []
        self._lock = threading.Lock()
        self._alert_callbacks = []

    def register_alert_callback(self, callback):
        """Register callback for unauthorized USB events."""
        self._alert_callbacks.append(callback)

    def start(self):
        """Start USB monitoring in background thread."""
        if not IS_WINDOWS:
            print("[USBMonitor] Only supported on Windows. Skipping.")
            return

        if not USB_MONITOR_ENABLED:
            print("[USBMonitor] Disabled in config. Skipping.")
            return

        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        print("[USBMonitor] Monitoring started.")

    def stop(self):
        """Stop USB monitoring."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        print("[USBMonitor] Stopped.")

    def _monitor_loop(self):
        """Main monitoring loop — spawns two WMI watcher threads."""
        try:
            import wmi
            import pythoncom
        except ImportError as e:
            print(f"[USBMonitor] Missing dependency: {e}. "
                  "Install with: pip install wmi pywin32")
            return

        # ── Initial scan so _known_usb is populated before watching ──
        pythoncom.CoInitialize()
        try:
            c = wmi.WMI()
            with self._lock:
                self._known_usb = {}
                for disk in c.Win32_DiskDrive():
                    if "USB" in (disk.InterfaceType or ""):
                        dev_id = disk.PNPDeviceID or "Unknown"
                        self._known_usb[dev_id] = disk.Caption or "USB Device"
            if self._known_usb:
                print(f"[USBMonitor] Found {len(self._known_usb)} USB device(s) at startup.")
        except Exception as e:
            print(f"[USBMonitor] Initial scan error: {e}")
        finally:
            pythoncom.CoUninitialize()

        # ── Spawn insertion + removal watcher threads ──────────────
        insert_thread = threading.Thread(
            target=self._watch_insertions, daemon=True
        )
        remove_thread = threading.Thread(
            target=self._watch_removals, daemon=True
        )
        insert_thread.start()
        remove_thread.start()

        while self._running:
            time.sleep(1)

    def _watch_insertions(self):
        """Watch for USB insertion events (WMI Creation)."""
        try:
            import pythoncom, wmi
            pythoncom.CoInitialize()          # Required per-thread for WMI
            c = wmi.WMI()
            watcher = c.Win32_DeviceChangeEvent.watch_for(
                notification_type="Creation",
                delay_secs=1
            )
            while self._running:
                try:
                    event = watcher(timeout_ms=2000)
                    if event:
                        self._scan_and_update(c)
                except Exception:
                    time.sleep(0.5)
        except Exception as e:
            print(f"[USBMonitor] Insertion watcher error: {e}")
        finally:
            try:
                import pythoncom
                pythoncom.CoUninitialize()
            except Exception:
                pass

    def _watch_removals(self):
        """Watch for USB removal events (WMI Deletion)."""
        try:
            import pythoncom, wmi
            pythoncom.CoInitialize()          # Required per-thread for WMI
            c = wmi.WMI()
            watcher = c.Win32_DeviceChangeEvent.watch_for(
                notification_type="Deletion",
                delay_secs=1
            )
            while self._running:
                try:
                    event = watcher(timeout_ms=2000)
                    if event:
                        self._scan_and_update(c)
                except Exception:
                    time.sleep(0.5)
        except Exception as e:
            print(f"[USBMonitor] Removal watcher error: {e}")
        finally:
            try:
                import pythoncom
                pythoncom.CoUninitialize()
            except Exception:
                pass

    def _scan_and_update(self, wmi_conn):
        """
        Diff current USB state against known state.
        Fires inserted / removed events for any change.
        """
        try:
            current = {}
            for disk in wmi_conn.Win32_DiskDrive():
                if "USB" in (disk.InterfaceType or ""):
                    dev_id = disk.PNPDeviceID or "Unknown"
                    current[dev_id] = disk.Caption or "USB Device"

            with self._lock:
                prev = dict(self._known_usb)

            for dev_id, desc in current.items():
                if dev_id not in prev:
                    self._fire_event(dev_id, desc, "inserted")

            for dev_id, desc in prev.items():
                if dev_id not in current:
                    self._fire_event(dev_id, desc, "removed")

            with self._lock:
                self._known_usb = current

        except Exception as e:
            print(f"[USBMonitor] Scan error: {e}")

    def _fire_event(self, device_id: str, description: str, event_type: str):
        """Create USBEvent, store it, and notify callbacks."""
        usb_event = USBEvent(
            device_id=device_id,
            description=description,
            event_type=event_type,
        )
        with self._lock:
            self._events.append(usb_event)

        icon   = "🔌" if event_type == "inserted" else "🔴"
        status = "UNAUTHORIZED" if not usb_event.is_authorized else "Authorized"
        print(f"\n[USBMonitor] {icon} USB {event_type.upper()}: "
              f"{description} [{status}]")

        if not usb_event.is_authorized:
            for cb in self._alert_callbacks:
                try:
                    cb(usb_event)
                except Exception:
                    pass

    def _handle_device_change(self, wmi_conn):
        """Legacy compatibility wrapper."""
        self._scan_and_update(wmi_conn)

    def get_events(self, limit=50):
        """Get recent USB events."""
        with self._lock:
            return [e.to_dict() for e in self._events[-limit:]]

    @property
    def is_running(self):
        return self._running


# ── Quick Test ──────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    print("=" * 50)
    print("  USB Monitor — Live Test")
    print("=" * 50)
    print("  Insert or remove a USB drive to test detection.")
    print("  Press Ctrl+C to stop.\n")

    monitor = USBMonitor()
    monitor.register_alert_callback(
        lambda e: print(f"  >>> ALERT callback fired: {e.description} ({e.event_type})")
    )
    monitor.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping...")
        monitor.stop()
        events = monitor.get_events()
        print(f"\nTotal events recorded: {len(events)}")
        for ev in events:
            print(f"  [{ev['event_type'].upper():8s}] {ev['description']} at {ev['timestamp']}")


