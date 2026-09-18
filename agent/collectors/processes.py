import os
from datetime import datetime, timezone

import psutil

from agent.agent import AGENT_VERSION


def _iso_utc(epoch):
    """psutil create_time() epoch -> ISO-8601 UTC, or None.

    Returns None rather than a fallback for anything unusable. A wrong start time is worse
    than a missing one: the timing features treat NULL as "unknown" and skip the row, but a
    plausible-looking wrong value would be learned from. psutil reports create_time for pid 0
    and some kernel processes as 0.0 or as the boot time, and on Windows it can raise for
    protected processes, so all of those collapse to None here.
    """
    try:
        if epoch is None or float(epoch) <= 0:
            return None
        return datetime.fromtimestamp(float(epoch), timezone.utc).isoformat(timespec="seconds")
    except (OverflowError, OSError, ValueError, TypeError):
        return None


def _sha256_file(path):
    try:
        if not path or not os.path.isfile(path):
            return None
        if os.path.getsize(path) > 64 * 1024 * 1024:
            return None
        import hashlib
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def collect():
    results = []
    for proc in psutil.process_iter(
            attrs=["pid", "ppid", "name", "cmdline", "username", "exe", "create_time"]):
        try:
            info = proc.info
            exe = info.get("exe")
            results.append({
                "pid": info.get("pid"),
                "ppid": info.get("ppid"),
                "name": info.get("name"),
                "cmdline": " ".join(info.get("cmdline") or []) or None,
                "exe_path": exe,
                "sha256": _sha256_file(exe),
                "username": info.get("username"),
                "create_time_utc": _iso_utc(info.get("create_time")),
                "agent_version": AGENT_VERSION,
            })
        except Exception:
            continue
    return results
