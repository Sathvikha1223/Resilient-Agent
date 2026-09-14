"""
Phase 3: per-process rolling baseline (EMA), updated only from
non-anomalous windows.
"""
from typing import Dict
from engine import Baseline, DEFAULT_BASELINE

ALPHA = 0.3


class BaselineStore:
    def __init__(self):
        self._baselines: Dict[str, Baseline] = {}

    def get(self, process_name: str) -> Baseline:
        return self._baselines.get(process_name, DEFAULT_BASELINE)

    def update(self, process_name: str, files_per_minute: float, avg_write_kb: float):
        current = self._baselines.get(process_name, DEFAULT_BASELINE)
        self._baselines[process_name] = Baseline(
            files_per_minute=(ALPHA * files_per_minute) + (1 - ALPHA) * current.files_per_minute,
            avg_write_kb=(ALPHA * avg_write_kb) + (1 - ALPHA) * current.avg_write_kb,
        )

    def snapshot(self) -> Dict[str, Baseline]:
        return dict(self._baselines)
