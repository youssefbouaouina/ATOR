import glob
import os
import sys

from agent.agent import load_config


def collect():
    cfg = load_config()
    max_files = int(cfg.get("max_files", 200))
    max_bytes = int(cfg.get("max_file_bytes", 5_242_880))
    candidates = _candidate_paths()
    out = []
    scanned = 0
    yara_rules = _load_yara_rules()
    for path in candidates:
        if scanned >= max_files:
            break
        try:
            if not os.path.isfile(path):
                continue
            size = os.path.getsize(path)
            if size > max_bytes:
                continue
            import hashlib
            h = hashlib.sha256()
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    h.update(chunk)
            matches = None
            if yara_rules is not None:
                try:
                    ym = yara_rules.match(path, timeout=10)
                    matches = [r.rule for r in ym] or None
                except Exception:
                    matches = None
            out.append({
                "path": path,
                "sha256": h.hexdigest(),
                "size_bytes": size,
                "yara_matches": matches,
            })
            scanned += 1
        except OSError:
            continue
    return out


def _candidate_paths():
    paths = []
    if sys.platform.startswith("win"):
        appdata = os.environ.get("APPDATA")
        programdata = os.environ.get("PROGRAMDATA")
        startup_dirs = []
        if appdata:
            startup_dirs.append(os.path.join(appdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"))
        if programdata:
            startup_dirs.append(os.path.join(programdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"))
        temp = os.environ.get("TEMP")
        if temp:
            paths += sorted(glob.glob(os.path.join(temp, "*")))
        for d in startup_dirs:
            paths += sorted(glob.glob(os.path.join(d, "**", "*"), recursive=True))
        win_temp = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Temp", "*")
        paths += sorted(glob.glob(win_temp))
    else:
        for d in ("/tmp", "/var/tmp", "/dev/shm"):
            paths += sorted(glob.glob(os.path.join(d, "*")))
        paths += sorted(glob.glob("/etc/cron.d/*"))
    seen = set()
    uniq = []
    for p in paths:
        rp = os.path.realpath(p)
        if rp not in seen:
            seen.add(rp)
            uniq.append(p)
    return uniq


def _load_yara_rules():
    if not load_config().get("enable_local_yara", True):
        return None
    try:
        import yara
    except ImportError:
        return None
    rules_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "rules", "malware")
    if not os.path.isdir(rules_dir):
        return None
    filepaths = {}
    for idx, yar in enumerate(sorted(glob.glob(os.path.join(rules_dir, "*.yar")))):
        filepaths[f"ns{idx}"] = yar
    if not filepaths:
        return None
    try:
        return yara.compile(filepaths=filepaths)
    except Exception:
        return None
