"""
Snapshot & recovery.
"""
import os
import shutil
import time


def take_snapshot(sandbox_dir, snapshots_root):
    os.makedirs(snapshots_root, exist_ok=True)
    stamp = time.strftime("%Y-%m-%d_%H-%M-%S")
    snapshot_path = os.path.join(snapshots_root, stamp)
    shutil.copytree(sandbox_dir, snapshot_path)
    return snapshot_path


def latest_snapshot(snapshots_root):
    if not os.path.isdir(snapshots_root):
        return None
    snaps = sorted(os.listdir(snapshots_root))
    if not snaps:
        return None
    return os.path.join(snapshots_root, snaps[-1])


def recovery_readiness(affected_files, snapshot_path):
    if not affected_files:
        return 100.0
    if not snapshot_path:
        return 0.0
    recoverable = sum(1 for fname in affected_files if os.path.isfile(os.path.join(snapshot_path, fname)))
    return round(100 * recoverable / len(affected_files), 1)


def restore_from_snapshot(sandbox_dir, snapshot_path):
    if not snapshot_path or not os.path.isdir(snapshot_path):
        raise FileNotFoundError("No snapshot available to restore from.")
    if os.path.isdir(sandbox_dir):
        shutil.rmtree(sandbox_dir)
    shutil.copytree(snapshot_path, sandbox_dir)
