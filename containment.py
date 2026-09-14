"""
Process containment -- identifies a candidate PID, but only kills it on
explicit human confirmation (never automatic).
"""
import os
import signal


def process_still_running(pid):
    if pid is None:
        return False
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False


def contain_process(pid):
    if pid is None:
        return "No PID recorded for this incident -- nothing to contain."
    if not process_still_running(pid):
        return f"Process {pid} is no longer running -- nothing to contain."
    try:
        os.kill(pid, signal.SIGKILL)
        return f"Process {pid} was terminated."
    except PermissionError:
        return f"Permission denied terminating process {pid}. Try running with sudo."
    except ProcessLookupError:
        return f"Process {pid} exited before it could be terminated."
