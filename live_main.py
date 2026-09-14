"""
Phase 5+6: Live Dashboard Loop.
Run WITH sudo for real process attribution (auditd):
    sudo python3 live_main.py
"""
import os
import json
import time
import signal
import sys

from engine import run_rules, compute_risk_score, explain
from aggregator import aggregate_window
from baseline_store import BaselineStore
from recovery import take_snapshot, latest_snapshot, recovery_readiness
from watcher_factory import get_watcher
from incident_response import IncidentTracker, write_incident_state, clear_incident_state
from snapshot_manager import protect_snapshot, prune_old_snapshots

SANDBOX_DIR = "sandbox"
SNAPSHOTS_DIR = "snapshots"
WINDOW_SECONDS = 5
SNAPSHOT_INTERVAL_SECONDS = 30
RISK_ALERT_THRESHOLD = 40
NUM_SAMPLE_FILES = 20
DASHBOARD_STATE_FILE = "dashboard_state.json"


def setup_sandbox_if_needed():
    if os.path.isdir(SANDBOX_DIR) and os.listdir(SANDBOX_DIR):
        return
    os.makedirs(SANDBOX_DIR, exist_ok=True)
    for i in range(NUM_SAMPLE_FILES):
        with open(os.path.join(SANDBOX_DIR, f"document_{i:02d}.txt"), "w") as f:
            f.write("Quarterly report draft.\n" * 10)


def print_dashboard(proc_name, risk_score, explanation, readiness, files_affected):
    bar_len = 30
    filled = int(bar_len * risk_score / 100)
    bar = "#" * filled + "-" * (bar_len - filled)
    status = "ALERT" if risk_score >= RISK_ALERT_THRESHOLD else "normal"
    print("\n" + "=" * 62)
    print(f" LIVE DASHBOARD  [{status}]   {time.strftime('%H:%M:%S')}")
    print("=" * 62)
    print(f" Process:         {proc_name}")
    print(f" Risk Score:      {risk_score:5.1f}/100  [{bar}]")
    print(f" Files affected:  {files_affected}")
    if readiness is not None:
        print(f" Recovery ready:  {readiness:.1f}%")
    if explanation is not None:
        print("-" * 62)
        print(f" Summary:        {explanation.summary}")
        print(f" Root cause:     {explanation.root_cause}")
        print(f" Recommendation: {explanation.recommendation}")
    print("=" * 62)


def write_dashboard_state(proc_name, risk_score, explanation, readiness, files_affected, pid):
    payload = {
        "timestamp": time.strftime("%H:%M:%S"), "process_name": proc_name, "pid": pid,
        "risk_score": risk_score, "files_affected": files_affected, "recovery_readiness": readiness,
        "alert": risk_score >= RISK_ALERT_THRESHOLD,
        "summary": explanation.summary if explanation else None,
        "root_cause": explanation.root_cause if explanation else None,
        "recommendation": explanation.recommendation if explanation else None,
    }
    with open(DASHBOARD_STATE_FILE, "w") as f:
        json.dump(payload, f)


def main():
    print("Setting up sandbox (first run only)...")
    setup_sandbox_if_needed()

    print("Taking initial snapshot...")
    take_snapshot(SANDBOX_DIR, SNAPSHOTS_DIR)
    last_snapshot_time = time.time()
    last_known_good_snapshot = latest_snapshot(SNAPSHOTS_DIR)

    baseline_store = BaselineStore()
    incident_tracker = IncidentTracker()
    clear_incident_state()
    known_extensions = {}
    known_entropy = {}
    for f in os.listdir(SANDBOX_DIR):
        known_extensions[os.path.join(SANDBOX_DIR, f)] = os.path.splitext(f)[1].lstrip(".")

    print(f"Starting watcher on '{SANDBOX_DIR}/'...")
    watcher = get_watcher(SANDBOX_DIR)

    print(f"\nWatching live. Window = {WINDOW_SECONDS}s. Ctrl+C to stop.")
    print("Modify files in another terminal to see the dashboard react.\n")

    def handle_sigint(sig, frame):
        print("\nStopping watcher...")
        try:
            watcher.stop()
        except Exception:
            pass
        os._exit(0)

    signal.signal(signal.SIGINT, handle_sigint)

    while True:
        time.sleep(WINDOW_SECONDS)
        raw_events = watcher.drain_events()

        if time.time() - last_snapshot_time >= SNAPSHOT_INTERVAL_SECONDS:
            take_snapshot(SANDBOX_DIR, SNAPSHOTS_DIR)
            deleted = prune_old_snapshots(SNAPSHOTS_DIR)
            last_snapshot_time = time.time()
            msg = f"[{time.strftime('%H:%M:%S')}] Routine snapshot taken."
            if deleted:
                msg += f" Pruned {len(deleted)} old snapshot(s)."
            print(msg)

        if not raw_events:
            continue

        windows = aggregate_window(raw_events, WINDOW_SECONDS, known_extensions, known_entropy)

        for proc_name, window in windows.items():
            baseline = baseline_store.get(proc_name)
            rules = run_rules(window, baseline)
            risk_score = compute_risk_score(rules)
            explanation = explain(window, rules, risk_score)

            readiness = None
            affected_count = window.files_modified
            real_affected_paths = list({
                evt.path for evt in raw_events if (evt.process_name or "unknown") == proc_name
            })

            if risk_score >= RISK_ALERT_THRESHOLD:
                readiness = recovery_readiness(
                    [os.path.basename(p) for p in real_affected_paths], last_known_good_snapshot
                )
            else:
                baseline_store.update(proc_name, window.files_per_minute, window.avg_write_kb)
                current_latest = latest_snapshot(SNAPSHOTS_DIR)
                if current_latest:
                    last_known_good_snapshot = current_latest

            print_dashboard(proc_name, risk_score, explanation, readiness, affected_count)
            write_dashboard_state(proc_name, risk_score, explanation, readiness, affected_count, window.pid)

            incident_state = incident_tracker.observe(proc_name, risk_score, RISK_ALERT_THRESHOLD)

            if incident_state == "CRITICAL":
                snap = last_known_good_snapshot
                if snap:
                    protect_snapshot(snap)
                write_incident_state(
                    process_name=proc_name, risk_score=risk_score, snapshot_path=snap,
                    readiness=readiness if readiness is not None else 0.0,
                    explanation_summary=explanation.summary, process_pid=window.pid,
                )
                print(f"\n*** INCIDENT DECLARED for '{proc_name}' (pid={window.pid}). Snapshot "
                      f"{snap} is now protected. Run `python3 confirm_restore.py` or use the "
                      f"web dashboard to review and restore. ***\n")
            elif incident_state == "NORMAL":
                clear_incident_state()


if __name__ == "__main__":
    main()
