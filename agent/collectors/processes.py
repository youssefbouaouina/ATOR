import os

import psutil

from agent.agent import AGENT_VERSION


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
    for proc in psutil.process_iter(attrs=["pid", "ppid", "name", "cmdline", "username", "exe"]):
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
                "agent_version": AGENT_VERSION,
            })
        except Exception:
            continue
    return results
