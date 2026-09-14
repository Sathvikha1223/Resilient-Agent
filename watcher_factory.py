"""
Auto-selects auditd (deterministic attribution) if root + rule exist,
else falls back to psutil.
"""
import os
import subprocess
import threading
from collections import deque

from live_watcher import LiveWatcher


def auditd_available(audit_key="resilient_agent"):
    if os.geteuid() != 0:
        return False
    if not os.path.exists("/var/log/audit/audit.log"):
        return False
    try:
        result = subprocess.run(["auditctl", "-l"], capture_output=True, text=True, timeout=3)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    return audit_key in result.stdout


class AuditdBackedWatcher:
    def __init__(self, watched_dir):
        self.watched_dir = watched_dir
        self.events = deque()
        self.lock = threading.Lock()
        self._thread = None
        self._stop_flag = threading.Event()

    def _run(self):
        import auditd_watcher
        for evt in auditd_watcher.watch_audit_log():
            if self._stop_flag.is_set():
                break
            with self.lock:
                self.events.append(evt)

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_flag.set()

    def drain_events(self):
        with self.lock:
            drained = list(self.events)
            self.events.clear()
        return drained


def get_watcher(watched_dir, prefer_auditd=True):
    if prefer_auditd and auditd_available():
        print("[watcher_factory] Using auditd -- deterministic attribution.")
        watcher = AuditdBackedWatcher(watched_dir)
    else:
        print("[watcher_factory] auditd not available -- falling back to psutil.")
        print("[watcher_factory] TIP: run with sudo and set an auditctl rule to get real process names.")
        watcher = LiveWatcher(watched_dir)
    watcher.start()
    return watcher
