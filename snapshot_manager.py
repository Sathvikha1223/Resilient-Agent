"""
Phase 6b: snapshot retention -- prunes old snapshots but never deletes
one protecting an active incident.
"""
import os
import shutil

MAX_SNAPSHOTS = 5


def protect_snapshot(snapshot_path):
    with open(os.path.join(snapshot_path, ".protected"), "w") as f:
        f.write("protected during active incident\n")


def is_protected(snapshot_path):
    return os.path.exists(os.path.join(snapshot_path, ".protected"))


def prune_old_snapshots(snapshots_root, max_snapshots=MAX_SNAPSHOTS):
    if not os.path.isdir(snapshots_root):
        return []
    snaps = sorted(os.listdir(snapshots_root))
    deleted = []
    while len(snaps) - len(deleted) > max_snapshots:
        candidates = [s for s in snaps if s not in deleted]
        oldest = candidates[0]
        oldest_path = os.path.join(snapshots_root, oldest)
        if is_protected(oldest_path):
            candidates.remove(oldest)
            if not candidates:
                break
            oldest = candidates[0]
            oldest_path = os.path.join(snapshots_root, oldest)
            if is_protected(oldest_path):
                break
        shutil.rmtree(oldest_path)
        deleted.append(oldest)
    return deleted
