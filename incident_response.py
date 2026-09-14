"""
Phase 6a: incident state machine -- requires CONSECUTIVE alert windows
before declaring CRITICAL.
"""
import json
import os
import time
from dataclasses import dataclass
from typing import Dict

INCIDENT_STATE_FILE = "incident_state.json"
CONSECUTIVE_ALERTS_FOR_CRITICAL = 2


@dataclass
class ProcessIncidentState:
    consecutive_alerts: int = 0
    state: str = "NORMAL"


class IncidentTracker:
    def __init__(self):
        self._states: Dict[str, ProcessIncidentState] = {}

    def observe(self, process_name, risk_score, alert_threshold):
        s = self._states.setdefault(process_name, ProcessIncidentState())
        if risk_score >= alert_threshold:
            s.consecutive_alerts += 1
            s.state = "CRITICAL" if s.consecutive_alerts >= CONSECUTIVE_ALERTS_FOR_CRITICAL else "WATCH"
        else:
            s.consecutive_alerts = 0
            s.state = "NORMAL"
        return s.state


def write_incident_state(process_name, risk_score, snapshot_path, readiness,
                          explanation_summary, process_pid=None, state_file=INCIDENT_STATE_FILE):
    payload = {
        "process_name": process_name, "process_pid": process_pid, "risk_score": risk_score,
        "recommended_snapshot": snapshot_path, "recovery_readiness": readiness,
        "summary": explanation_summary, "declared_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    with open(state_file, "w") as f:
        json.dump(payload, f, indent=2)


def clear_incident_state(state_file=INCIDENT_STATE_FILE):
    if os.path.exists(state_file):
        os.remove(state_file)


def read_incident_state(state_file=INCIDENT_STATE_FILE):
    if not os.path.exists(state_file):
        return None
    with open(state_file) as f:
        return json.load(f)
