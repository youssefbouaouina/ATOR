import glob
import json
import os
import re
import shutil
import subprocess


def collect():
    if not shutil.which("docker"):
        return []
    out = []
    containers = _docker_ps()
    out += _container_inventory(containers)
    out += _cgroup_process_mapping()
    out += _port_mapping_attribution(containers)
    return [item for item in out if item]


def _run(args):
    try:
        proc = subprocess.run(["docker"] + args, capture_output=True, text=True, timeout=60)
        if proc.returncode != 0:
            return None
        return proc.stdout
    except Exception:
        return None


def _docker_ps():
    raw = _run(["ps", "-a", "--format", "{{json .}}"])
    if not raw:
        return []
    items = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            items.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return items


def _container_inventory(containers):
    inv = []
    for c in containers:
        inspect_raw = _run(["inspect", c.get("ID", "")])
        ip = None
        if inspect_raw:
            try:
                data = json.loads(inspect_raw)
                if isinstance(data, list) and data:
                    nets = (data[0].get("NetworkSettings") or {}).get("Networks") or {}
                    for net in nets.values():
                        ip = net.get("IPAddress")
                        break
            except (json.JSONDecodeError, IndexError, AttributeError):
                pass
        inv.append({
            "record": "inventory",
            "container_id": c.get("ID"),
            "container_name": (c.get("Names") or "").lstrip("/"),
            "image_name": c.get("Image"),
            "status": c.get("State"),
            "ip_address": ip,
        })
    return inv


CGROUP_RE = re.compile(
    r"/(docker[-/])([0-9a-f]{64})", re.IGNORECASE,
)


def _cgroup_process_mapping():
    mapping = []
    if not os.path.isdir("/proc"):
        return mapping
    for stat_path in glob.glob("/proc/[0-9]*/cgroup"):
        try:
            pid = int(stat_path.split("/")[2])
            with open(stat_path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
            match = CGROUP_RE.search(content)
            if match:
                cid = match.group(2)[:12]
                name_path = f"/proc/{pid}/comm"
                pname = None
                try:
                    with open(name_path, "r", encoding="utf-8", errors="replace") as fh:
                        pname = fh.read().strip()
                except OSError:
                    pass
                mapping.append({
                    "record": "process_mapping",
                    "container_id": cid,
                    "pid": pid,
                    "process_name": pname,
                })
        except (OSError, ValueError):
            continue
    return mapping


def _port_mapping_attribution(containers):
    attribution = []
    for c in containers:
        ports = c.get("Ports") or ""
        m = re.search(r"0\.0\.0\.0:(\d+)->(\d+)/tcp", str(ports))
        if m:
            attribution.append({
                "record": "port_mapping",
                "container_id": c.get("ID"),
                "host_port": int(m.group(1)),
                "container_port": int(m.group(2)),
                "container_name": (c.get("Names") or "").lstrip("/"),
            })
    return attribution
