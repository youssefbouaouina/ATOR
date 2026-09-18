import os
import sys
import time
import psutil


def collect():
    """Return a lightweight self-monitoring snapshot of the agent process."""
    return [snapshot()]


def snapshot():
    try:
        proc = psutil.Process()
    except Exception:
        # Fallback if psutil fails
        return _fallback_snapshot()

    now = time.time()

    # CPU percent (non-blocking)
    cpu_pct = proc.cpu_percent(interval=None)

    # Memory info
    mem_info = proc.memory_info()
    mem_rss_mb = mem_info.rss / (1024 * 1024)

    # Threads
    try:
        num_threads = proc.num_threads()
    except Exception:
        num_threads = None

    # File descriptors / handles
    try:
        if sys.platform.startswith("win"):
            # On Windows, use num_handles
            fds = proc.num_handles()
        else:
            fds = proc.num_fds()
    except Exception:
        fds = None

    # CPU times
    try:
        cpu_times = proc.cpu_times()
        cpu_user = cpu_times.user
        cpu_system = cpu_times.system
    except Exception:
        cpu_user = None
        cpu_system = None

    snap = {
        "sampled_at_utc": datetime_iso(),
        "agent_cpu_pct": float(cpu_pct) if cpu_pct is not None else None,
        "agent_mem_mb": float(mem_rss_mb) if mem_rss_mb is not None else None,
        "agent_threads": num_threads,
        "agent_fds": fds,
        "agent_cpu_time_user": cpu_user,
        "agent_cpu_time_system": cpu_system,
    }
    return snap


def _fallback_snapshot():
    """Fallback when psutil fails."""
    return {
        "sampled_at_utc": datetime_iso(),
        "agent_cpu_pct": None,
        "agent_mem_mb": None,
        "agent_threads": None,
        "agent_fds": None,
        "agent_cpu_time_user": None,
        "agent_cpu_time_system": None,
    }


def datetime_iso():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="seconds")