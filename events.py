"""
Shared event shape used by BOTH watcher backends.
"""
from dataclasses import dataclass
from typing import Optional


@dataclass
class RawEvent:
    path: str
    event_type: str
    timestamp: float
    process_name: Optional[str] = None
    process_pid: Optional[int] = None
    exe: Optional[str] = None
    auid: Optional[str] = None
