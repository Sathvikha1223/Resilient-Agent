"""
Phase 2: auditd-based watcher. Deterministic process attribution via the
Linux kernel audit subsystem -- gives REAL process names/PIDs, not guesses.

REQUIRES: sudo auditctl -w <sandbox_path> -p wa -k resilient_agent
Run this whole program with sudo.
"""
import os
import re
import subprocess
import time
from typing import Iterator

from events import RawEvent

AUDIT_LOG_PATH = "/var/log/audit/audit.log"
AUDIT_KEY = "resilient_agent"

_SYSCALL_RE = re.compile(
    r'audit\((?P<ts>[\d.]+):(?P<id>\d+)\).*?'
    r'comm="(?P<comm>[^"]+)".*?exe="(?P<exe>[^"]+)"'
)
_PID_RE = re.compile(r'\bpid=(?P<pid>\d+)\b')
_AUID_RE = re.compile(r'\bauid=(?P<auid>\S+)\b')
_KEY_RE = re.compile(r'\bkey=(?:"(?P<key_q>[^"]*)"|(?P<key_bare>\S+))')
_PATH_ID_RE = re.compile(r'audit\([\d.]+:(?P<id>\d+)\)')
_PATH_NAME_RE = re.compile(r'\bname="(?P<name>[^"]+)"')
_NAMETYPE_RE = re.compile(r'\bnametype=(?P<nametype>\w+)')

NAMETYPE_TO_EVENT = {"CREATE": "created", "NORMAL": "modified", "DELETE": "deleted"}
MAX_PENDING = 2000


def check_prerequisites():
    if os.geteuid() != 0:
        raise PermissionError("Run with sudo -- this reads /var/log/audit/audit.log")
    if not os.path.exists(AUDIT_LOG_PATH):
        raise FileNotFoundError(f"{AUDIT_LOG_PATH} not found. Is auditd running?")
    result = subprocess.run(["auditctl", "-l"], capture_output=True, text=True)
    if AUDIT_KEY not in result.stdout:
        raise RuntimeError(
            f"No audit rule tagged '{AUDIT_KEY}'. Set one:\n"
            f"  sudo auditctl -w /path/to/sandbox -p wa -k {AUDIT_KEY}"
        )


def _tail(path):
    with open(path, "r", errors="replace") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue
            yield line


def watch_audit_log() -> Iterator[RawEvent]:
    check_prerequisites()
    pending = {}

    for line in _tail(AUDIT_LOG_PATH):
        if "type=SYSCALL" in line:
            m = _SYSCALL_RE.search(line)
            if not m:
                continue
            event_id = m.group("id")
            pid_m = _PID_RE.search(line)
            auid_m = _AUID_RE.search(line)
            key_m = _KEY_RE.search(line)

            key_val = None
            if key_m:
                key_val = key_m.group("key_q") or key_m.group("key_bare")
                if key_val == "(null)":
                    key_val = None
            if key_val != AUDIT_KEY:
                continue

            if len(pending) > MAX_PENDING:
                pending.clear()

            pending[event_id] = {
                "comm": m.group("comm"),
                "exe": m.group("exe"),
                "pid": int(pid_m.group("pid")) if pid_m else None,
                "auid": auid_m.group("auid") if auid_m else None,
                "ts": float(m.group("ts")),
            }
            continue

        if "type=PATH" in line:
            id_m = _PATH_ID_RE.search(line)
            name_m = _PATH_NAME_RE.search(line)
            nt_m = _NAMETYPE_RE.search(line)
            if not id_m or not name_m or not nt_m:
                continue
            event_id = id_m.group("id")
            info = pending.get(event_id)
            if info is None:
                continue
            nametype = nt_m.group("nametype")
            if nametype not in NAMETYPE_TO_EVENT:
                continue
            yield RawEvent(
                path=name_m.group("name"),
                event_type=NAMETYPE_TO_EVENT[nametype],
                timestamp=info["ts"],
                process_name=info["comm"],
                process_pid=info["pid"],
                exe=info["exe"],
                auid=info["auid"],
            )


if __name__ == "__main__":
    print(f"Tailing {AUDIT_LOG_PATH} for key='{AUDIT_KEY}'...\n")
    for evt in watch_audit_log():
        print(f"[{evt.event_type}] {evt.path}  process={evt.process_name} pid={evt.process_pid}")
