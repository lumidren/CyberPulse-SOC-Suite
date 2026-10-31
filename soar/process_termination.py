"""
Graceful-First Process Termination Plans (CyberPulse SOC Lab)

The lab's responders are simulated, but the plan they record is the one a real
responder should follow. Force-killing a whole tree (`taskkill /F /T`) gives
processes no chance to flush buffers, release file locks or commit
transactions, which can corrupt documents, databases and the evidence an
investigator needs. So the plan is:

1. Snapshot the process first (see evidence collection) - never kill blind.
2. Ask the process to exit (`taskkill /PID <pid>` without /F) and wait a grace
   period.
3. Only if it is still running, force-terminate that single PID.
4. Children are handled individually by PID, never with /T on a guess.

Exception: active ransomware gets grace 0, because every second of delay means
more encrypted files. That trade-off is recorded on the action.

Commands are argv lists (never concatenated strings) so a hostile process name
cannot inject extra arguments.
"""

DEFAULT_GRACE_SECONDS = 15
RANSOMWARE_GRACE_SECONDS = 0

DATA_LOSS_NOTE = (
    "Forced termination can lose unsaved data and corrupt files or databases the "
    "process had open; it also destroys in-memory evidence if no snapshot was taken."
)


def termination_plan(pid, process_name=None, grace_seconds=DEFAULT_GRACE_SECONDS, reason="malicious process"):
    """Ordered, argv-based steps for stopping one process gracefully first."""
    from soar.command_builder import CommandValidationError, valid_pid
    try:
        pid = valid_pid(pid)
    except CommandValidationError as exc:
        raise ValueError(f"Refusing to plan termination: {exc}") from exc
    steps = [
        {"step": 1, "action": "snapshot_process", "detail": "Collect process, handle, network and memory metadata first."},
    ]
    if grace_seconds > 0:
        steps += [
            {"step": 2, "action": "request_exit", "argv": ["taskkill.exe", "/PID", str(pid)],
             "detail": f"Ask {process_name or 'the process'} to exit cleanly."},
            {"step": 3, "action": "wait", "seconds": grace_seconds,
             "detail": "Give it time to flush buffers and release locks."},
            {"step": 4, "action": "force_terminate_if_running", "argv": ["taskkill.exe", "/PID", str(pid), "/F"],
             "detail": "Only if still running after the grace period. Single PID, no /T."},
        ]
    else:
        steps.append({
            "step": 2, "action": "force_terminate", "argv": ["taskkill.exe", "/PID", str(pid), "/F"],
            "detail": "Immediate forced kill: delay causes more damage than the data-loss risk.",
        })
    return {
        "pid": pid,
        "process_name": process_name,
        "reason": reason,
        "grace_seconds": grace_seconds,
        "steps": steps,
        "data_loss_risk": DATA_LOSS_NOTE,
    }
