"""
Phase 6c: human-confirmed restore AND containment. The ONLY code paths
that actually restore data or kill a process.
"""
from incident_response import read_incident_state, clear_incident_state
from recovery import restore_from_snapshot
from containment import contain_process, process_still_running

SANDBOX_DIR = "sandbox"


def main():
    state = read_incident_state()
    if state is None:
        print("No active incident found. Nothing to restore.")
        return

    pid = state.get("process_pid")

    print("=" * 60)
    print(" ACTIVE INCIDENT")
    print("=" * 60)
    print(f" Process:            {state['process_name']}")
    print(f" PID:                {pid if pid else 'unknown'}")
    print(f" Risk score:         {state['risk_score']}/100")
    print(f" Recovery readiness: {state['recovery_readiness']}%")
    print(f" Declared at:        {state['declared_at']}")
    print(f" Summary:            {state['summary']}")
    print(f" Snapshot to use:    {state['recommended_snapshot']}")
    print("=" * 60)

    if pid and process_still_running(pid):
        c = input(f"\nProcess {pid} is still running. Type CONTAIN to terminate it, or Enter to skip: ")
        if c.strip() == "CONTAIN":
            print(contain_process(pid))

    confirm = input(f"\nType RESTORE to overwrite '{SANDBOX_DIR}/', or anything else to cancel: ")
    if confirm.strip() != "RESTORE":
        print("Cancelled. No changes made.")
        return

    restore_from_snapshot(SANDBOX_DIR, state["recommended_snapshot"])
    clear_incident_state()
    print(f"\nRestore complete. '{SANDBOX_DIR}/' reverted to {state['recommended_snapshot']}.")


if __name__ == "__main__":
    main()
