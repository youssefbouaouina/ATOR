import os
import time
import psutil

# In-process previous-counter store for delta-rate computation. One snapshot
# per collection cycle keeps this module stateless from the server's view.
_prev = {"ts": None, "disk_r": None, "disk_w": None, "net_s": None, "net_r": None}
_gpu_cache = {"ts": 0.0, "util": None, "mem_mb": None, "present": False}


def collect():
    """Registry-compatible entry point: returns a list with one snapshot."""
    return [snapshot()]


def _hardware_tier(cores, mem_total_mb):
    if cores is None or not mem_total_mb:
        return "unknown"
    if mem_total_mb < 4096 or cores <= 2:
        return "low"
    if mem_total_mb >= 16384 and cores >= 8:
        return "high"
    return "mid"


def _gpu(enabled):
    """Best-effort NVIDIA probe, cached 60s. Returns (present, util_pct, mem_used_mb)."""
    if not enabled:
        return False, None, None
    now = time.time()
    if now - _gpu_cache["ts"] < 60:
        return _gpu_cache["present"], _gpu_cache["util"], _gpu_cache["mem_mb"]
    present, util, mem = False, None, None
    try:
        import shutil
        import subprocess
        exe = shutil.which("nvidia-smi")
        if exe:
            proc = subprocess.run(
                [exe, "--query-gpu=utilization.gpu,memory.used",
                 "--format=csv,noheader,nounits"],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=2,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                parts = [p.strip() for p in proc.stdout.strip().splitlines()[0].split(",")]
                util = float(parts[0])
                if len(parts) > 1:
                    mem = float(parts[1])
                present = True
    except Exception:
        pass
    _gpu_cache.update(ts=now, present=present, util=util, mem_mb=mem)
    return present, util, mem


def _delta_rates():

    def kbps(prev, cur, dt):
        """Bytes/sec -> KB/s; None on first sample or counter reset."""
        if prev is None or cur is None or dt is None or dt <= 0:
            return None
        delta = cur - prev
        if delta < 0:
            return None  # counter reset (reboot/rotation): skip rather than lie
        return delta / dt / 1024.0

    disk = psutil.disk_io_counters()
    net = psutil.net_io_counters()
    now = time.time()
    dt = (now - _prev["ts"]) if _prev["ts"] else None
    out = {
        "disk_read_kbps": kbps(_prev["disk_r"], getattr(disk, "read_bytes", None), dt),
        "disk_write_kbps": kbps(_prev["disk_w"], getattr(disk, "write_bytes", None), dt),
        "net_sent_kbps": kbps(_prev["net_s"], getattr(net, "bytes_sent", None), dt),
        "net_recv_kbps": kbps(_prev["net_r"], getattr(net, "bytes_recv", None), dt),
    }
    _prev.update(ts=now,
                 disk_r=getattr(disk, "read_bytes", None) if disk else None,
                 disk_w=getattr(disk, "write_bytes", None) if disk else None,
                 net_s=getattr(net, "bytes_sent", None) if net else None,
                 net_r=getattr(net, "bytes_recv", None) if net else None)
    return out


def _battery():
    try:
        batt = psutil.sensors_battery()
    except Exception:
        batt = None
    if batt is None:
        return None, None
    plugged = int(batt.power_plugged) if batt.power_plugged is not None else None
    pct = float(batt.percent) if batt.percent is not None else None
    return pct, plugged


def snapshot():
    try:
        from agent.agent import load_config
        gpu_enabled = bool(load_config().get("enable_gpu_probe", True))
    except Exception:
        gpu_enabled = True
    cpu = psutil.cpu_percent(interval=None)          # prime-on-first-call
    vm = psutil.virtual_memory()
    sm = psutil.swap_memory()
    cores = os.cpu_count()
    gpu_present, gpu_util, gpu_mem = _gpu(gpu_enabled)
    batt_pct, batt_plugged = _battery()

    snap = {
        "sampled_at_utc": datetime_iso(),
        "cpu_pct": float(cpu),
        "mem_total_mb": float(vm.total) / (1024 * 1024),
        "mem_used_mb": float(vm.used) / (1024 * 1024),
        "mem_pct": float(vm.percent),
        "swap_pct": float(sm.percent),
        "hw_tier": _hardware_tier(cores, vm.total / (1024 * 1024)),
        "cpu_cores": cores,
        "gpu_present": int(gpu_present),
        "gpu_util_pct": gpu_util,
        "gpu_mem_used_mb": gpu_mem,
        "battery_pct": batt_pct,
        "battery_plugged": batt_plugged,
    }
    snap.update(_delta_rates())
    return snap


def datetime_iso():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
