"""
Phase 4: turns raw OS events into ActivityWindow objects, with entropy
HISTORY tracking (not just absolute values) so legitimate high-entropy
files can be told apart from a real plaintext->encrypted jump.
"""
import math
import os
from collections import defaultdict, Counter
from typing import List, Dict

from engine import ActivityWindow
from events import RawEvent


def file_entropy(path, sample_bytes=4096):
    try:
        with open(path, "rb") as f:
            data = f.read(sample_bytes)
    except (FileNotFoundError, IsADirectoryError, PermissionError):
        return 0.0
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = -sum((c / length) * math.log2(c / length) for c in counts.values())
    return round(entropy / 8.0, 3)


def _extension(path):
    ext = os.path.splitext(path)[1].lstrip(".")
    return ext or "noext"


def aggregate_window(events: List[RawEvent], window_seconds: float,
                      known_extensions: Dict[str, str],
                      known_entropy: Dict[str, float] = None) -> Dict[str, ActivityWindow]:
    if known_entropy is None:
        known_entropy = {}

    by_process = defaultdict(list)
    for evt in events:
        by_process[evt.process_name or "unknown"].append(evt)

    windows = {}
    minutes = max(window_seconds / 60.0, 0.001)

    for proc, proc_events in by_process.items():
        exts_before, exts_after = Counter(), Counter()
        total_kb = 0.0
        entropy_samples, delta_samples = [], []
        last_pid = None

        for evt in proc_events:
            if evt.process_pid is not None:
                last_pid = evt.process_pid

            new_ext = _extension(evt.path)
            old_ext = known_extensions.get(evt.path)
            if old_ext is not None:
                exts_before[old_ext] += 1
            exts_after[new_ext] += 1
            known_extensions[evt.path] = new_ext

            if os.path.isfile(evt.path):
                try:
                    total_kb += os.path.getsize(evt.path) / 1024.0
                except OSError:
                    pass
                current_entropy = file_entropy(evt.path)
                entropy_samples.append(current_entropy)
                prior_entropy = known_entropy.get(evt.path)
                if prior_entropy is not None:
                    delta_samples.append(abs(current_entropy - prior_entropy))
                known_entropy[evt.path] = current_entropy

        avg_entropy = sum(entropy_samples) / len(entropy_samples) if entropy_samples else 0.0
        avg_delta = sum(delta_samples) / len(delta_samples) if delta_samples else 0.0

        windows[proc] = ActivityWindow(
            process_name=proc, files_modified=len(proc_events), minutes_elapsed=minutes,
            total_write_kb=total_kb, extensions_before=exts_before, extensions_after=exts_after,
            sample_entropy=round(avg_entropy, 3), entropy_delta=round(avg_delta, 3), pid=last_pid,
        )

    return windows
