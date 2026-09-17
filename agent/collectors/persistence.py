import glob
import os
import subprocess
import sys


def collect():
    if sys.platform.startswith("win"):
        return _windows()
    return _linux()


def _windows():
    items = []
    items += _win_registry_persistence()
    items += _win_services()
    items += _win_scheduled_tasks()
    items += _win_startup_folders()
    return items


def _win_registry_persistence():
    try:
        import winreg
    except ImportError:
        return []
    hives = [
        (winreg.HKEY_LOCAL_MACHINE, "HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
        (winreg.HKEY_LOCAL_MACHINE, "HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
        (winreg.HKEY_CURRENT_USER, "HKCU", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
        (winreg.HKEY_CURRENT_USER, "HKCU", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
    ]
    out = []
    for hive, hive_name, path in hives:
        try:
            key = winreg.OpenKey(hive, path)
        except OSError:
            continue
        with key:
            idx = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, idx)
                    out.append({
                        "ptype": "registry_run",
                        "name": name,
                        "command": str(value),
                        "location": f"{hive_name}\\{path}",
                    })
                    idx += 1
                except OSError:
                    break
    return out


def _win_services():
    try:
        import winreg
    except ImportError:
        return []
    out = []
    base = "SYSTEM\\CurrentControlSet\\Services"
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base)
    except OSError:
        return out
    with key:
        idx = 0
        while True:
            try:
                svc_name = winreg.EnumKey(key, idx)
            except OSError:
                break
            idx += 1
            try:
                with winreg.OpenKey(key, svc_name) as sub:
                    image = ""
                    start_type = None
                    try:
                        image, _ = winreg.QueryValueEx(sub, "ImagePath")
                    except OSError:
                        pass
                    try:
                        start_type, _ = winreg.QueryValueEx(sub, "Start")
                    except OSError:
                        pass
                    if image and int(start_type or 99) in (2, 3):
                        out.append({
                            "ptype": "service",
                            "name": svc_name,
                            "command": str(image),
                            "location": f"HKLM\\{base}\\{svc_name}",
                        })
            except OSError:
                continue
    return out


def _win_scheduled_tasks():
    out = []
    try:
        proc = subprocess.run(
            ["schtasks", "/query", "/fo", "csv", "/nh"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60,
        )
    except Exception:
        return out
    for line in proc.stdout.splitlines():
        parts = next(iter(__import__("csv").reader([line])), [])
        if len(parts) >= 9 and parts[1] != "":
            out.append({
                "ptype": "schtask",
                "name": parts[1],
                "command": parts[8] if len(parts) > 8 else "",
                "location": "\\Microsoft\\Windows\\" + parts[0].split(":")[-1].strip() if ":" in parts[0] else parts[0],
            })
    return out


def _win_startup_folders():
    out = []
    candidates = set()
    for env in ("APPDATA", "PROGRAMDATA"):
        base_env = os.environ.get(env)
        if not base_env:
            continue
        if env == "APPDATA":
            candidates.add(os.path.join(base_env, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"))
        else:
            candidates.add(os.path.join(base_env, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"))
    for folder in candidates:
        if os.path.isdir(folder):
            for fname in os.listdir(folder):
                full = os.path.join(folder, fname)
                if os.path.isfile(full):
                    out.append({"ptype": "startup_folder", "name": fname, "command": full, "location": folder})
    return out


def _linux():
    items = []
    items += _cron_entries()
    items += _systemd_timers()
    return items


def _cron_entries():
    out = []
    paths = ["/etc/crontab"] + sorted(glob.glob("/etc/cron.d/*")) + sorted(glob.glob("/var/spool/cron/crontabs/*"))
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    out.append({
                        "ptype": "cron",
                        "name": f"{os.path.basename(path)}:{line[:40]}",
                        "command": line,
                        "location": path,
                    })
        except OSError:
            continue
    return out


def _systemd_timers():
    out = []
    patterns = ["/etc/systemd/system/*.timer", "/usr/lib/systemd/system/*.timer"]
    seen = set()
    for pattern in patterns:
        for path in sorted(glob.glob(pattern)):
            real = os.path.realpath(path)
            if real in seen:
                continue
            seen.add(real)
            try:
                with open(real, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
                name = os.path.basename(path)
                exec_line = ""
                for line in content.splitlines():
                    if line.strip().lower().startswith("execstart"):
                        exec_line = line.split("=", 1)[-1].strip()
                        break
                out.append({
                    "ptype": "systemd_timer",
                    "name": name,
                    "command": exec_line,
                    "location": real,
                })
            except OSError:
                continue
    return out
