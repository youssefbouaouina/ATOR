"""One pipeline run at a time, and no lock that outlives a crash.

A plain "file exists = locked" lock is the classic way an unattended job stops forever: the
process dies (power cut, killed by the scheduler's time limit) and every later run sees the
lock and exits. Here a lock is only honoured while its owner is demonstrably alive: same pid,
same process start time (pid reuse), and younger than `stale_lock_hours`.
"""
from __future__ import annotations

import json
import os
import time


class LockHeld(RuntimeError):
    """Another live pipeline run owns the lock."""


def _owner_alive(info: dict) -> bool:
    try:
        import psutil
    except ImportError:                          # pragma: no cover - psutil is a server dependency
        return True                              # cannot tell: be conservative, honour it
    pid = info.get("pid")
    if not isinstance(pid, int) or not psutil.pid_exists(pid):
        return False
    try:
        created = psutil.Process(pid).create_time()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False
    # A process that started after the lock was written cannot be the lock's owner.
    return abs(created - float(info.get("process_created", created))) < 2.0


class RunLock:
    def __init__(self, path: str, stale_after_hours: float = 6.0):
        self.path = path
        self.stale_after = stale_after_hours * 3600.0
        self.reclaimed: dict | None = None
        self._held = False

    def _read(self) -> dict:
        try:
            with open(self.path, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return {}

    def acquire(self) -> "RunLock":
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        for _ in range(2):
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            except FileExistsError:
                info = self._read()
                age = time.time() - float(info.get("acquired_at", 0) or 0)
                if _owner_alive(info) and age < self.stale_after:
                    raise LockHeld(f"pipeline already running (pid {info.get('pid')}, "
                                   f"started {int(age)}s ago)")
                # Dead or ancient owner: the run crashed. Reclaim, and say so in the report.
                self.reclaimed = info or {"note": "unreadable lock file"}
                try:
                    os.remove(self.path)
                except FileNotFoundError:
                    pass
                continue
            try:
                import psutil
                created = psutil.Process(os.getpid()).create_time()
            except Exception:                    # noqa: BLE001
                created = time.time()
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump({"pid": os.getpid(), "process_created": created,
                           "acquired_at": time.time()}, fh)
            self._held = True
            return self
        raise LockHeld("could not acquire the pipeline lock")

    def release(self) -> None:
        if self._held:
            try:
                os.remove(self.path)
            except FileNotFoundError:
                pass
            self._held = False

    def __enter__(self) -> "RunLock":
        return self.acquire()

    def __exit__(self, *exc) -> None:
        self.release()
