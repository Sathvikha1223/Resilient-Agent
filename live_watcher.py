"""
Phase 1+2: real-time file-system events via watchdog (inotify).
Best-effort process correlation via psutil (fallback only -- use auditd
for reliable attribution).
"""
import os
import time
import threading
from collections import deque
from typing import Optional

import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from events import RawEvent


def guess_responsible_process(watched_dir: str):
    watched_dir = os.path.abspath(watched_dir)
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            for f in proc.open_files():
                if os.path.abspath(f.path).startswith(watched_dir):
                    return proc
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
            continue
    return None


class LiveEventHandler(FileSystemEventHandler):
    def __init__(self, watched_dir, event_queue, lock):
        super().__init__()
        self.watched_dir = watched_dir
        self.event_queue = event_queue
        self.lock = lock

    def _record(self, event_type, path):
        if os.path.basename(path).startswith("."):
            return
        proc = guess_responsible_process(self.watched_dir)
        raw = RawEvent(
            path=path,
            event_type=event_type,
            timestamp=time.time(),
            process_name=proc.name() if proc else "unknown",
            process_pid=proc.pid if proc else None,
        )
        with self.lock:
            self.event_queue.append(raw)

    def on_created(self, event):
        if not event.is_directory:
            self._record("created", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._record("modified", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._record("moved", event.dest_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self._record("deleted", event.src_path)


class LiveWatcher:
    def __init__(self, watched_dir):
        self.watched_dir = watched_dir
        self.events = deque()
        self.lock = threading.Lock()
        self._handler = LiveEventHandler(watched_dir, self.events, self.lock)
        self._observer = Observer()
        self._observer.schedule(self._handler, watched_dir, recursive=True)

    def start(self):
        self._observer.start()

    def stop(self):
        self._observer.stop()
        self._observer.join(timeout=2)

    def drain_events(self):
        with self.lock:
            drained = list(self.events)
            self.events.clear()
        return drained
