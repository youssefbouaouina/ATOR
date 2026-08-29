import hashlib
import json
import os
import sys
import uuid

AGENT_VERSION = "1.0.0"

DEFAULT_CONFIG = {
    "server_url": "http://127.0.0.1:8000",
    "api_key": "",
    "client_id": "",
    "spool_dir": "spool",
    "max_events_per_source": 300,
    "max_files": 200,
    "max_file_bytes": 5242880,
    "enable_local_yara": True,
    "collection_interval_seconds": 60,
    "resource_interval_seconds": 15,
    "enable_gpu_probe": True,
}


_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.environ.get("ATOR_AGENT_CONFIG", os.path.join(_BASE_DIR, "config.json"))


def load_config(config_path=None):
    path = config_path or CONFIG_PATH
    cfg = dict(DEFAULT_CONFIG)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            cfg.update(json.load(fh))
    env_url = os.environ.get("ATOR_SERVER_URL")
    if env_url:
        cfg["server_url"] = env_url
    return cfg


def get_hostname():
    import socket
    return socket.gethostname()


def get_os_type():
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform.startswith("linux"):
        return "linux"
    return sys.platform


COLLECTOR_ORDER_VOLATILITY_FIRST = [
    "network",
    "processes",
    "persistence",
    "logs",
    "files_triage",
    "containers",
    "resources",
]


try:
    from server.security import sha256_bytes
except ImportError:
    def sha256_bytes(data):
        return hashlib.sha256(data).hexdigest()


def build_manifest(collection_id, started_at, finished_at, artifacts):
    entries = []
    order = []
    for name in COLLECTOR_ORDER_VOLATILITY_FIRST:
        items = artifacts.get(name) or []
        blob = json.dumps(items, sort_keys=True, default=str).encode()
        entries.append({
            "collector": name,
            "count": len(items),
            "sha256": sha256_bytes(blob),
        })
        order.append(name)
    manifest = {
        "collection_id": collection_id,
        "hostname": get_hostname(),
        "os_type": get_os_type(),
        "agent_version": AGENT_VERSION,
        "started_at_utc": started_at,
        "finished_at_utc": finished_at,
        "collector_order": order,
        "artifacts": entries,
    }
    manifest["manifest_sha256"] = sha256_bytes(
        json.dumps({k: v for k, v in manifest.items()}, sort_keys=True, default=str).encode()
    )
    return manifest


def dispatch(name):
    from agent.collectors import registry
    func = registry.get(name)
    if func is None:
        return []
    return func() or []


def run_collection():
    from datetime import datetime, timezone
    import uuid
    started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    collection_id = str(uuid.uuid4())
    artifacts = {}
    for name in COLLECTOR_ORDER_VOLATILITY_FIRST:
        try:
            artifacts[name] = dispatch(name)
        except Exception as exc:
            artifacts[name] = [{"_error": f"{type(exc).__name__}: {exc}"}]
    finished = datetime.now(timezone.utc).isoformat(timespec="seconds")
    manifest = build_manifest(collection_id, started, finished, artifacts)
    return {"manifest": manifest, "artifacts": artifacts}


def send_payload(cfg, payload):
    import requests
    url = cfg["server_url"].rstrip("/") + "/api/v1/ingest"
    headers = {
        "Authorization": "Bearer " + cfg.get("api_key", ""),
        "X-Client-ID": cfg.get("client_id", ""),
        "Content-Type": "application/json",
    }
    resp = requests.post(url, json=payload, headers=headers, timeout=30)
    resp.raise_for_status()
    return resp


def _headers(cfg):
    return {
        "Authorization": "Bearer " + cfg.get("api_key", ""),
        "X-Client-ID": cfg.get("client_id", ""),
        "Content-Type": "application/json",
    }


def send_resources(cfg, samples):
    """Lightweight telemetry POST to the dedicated resources endpoint."""
    import requests
    url = cfg["server_url"].rstrip("/") + "/api/v1/ingest/resources"
    resp = requests.post(
        url, json={"samples": samples}, headers=_headers(cfg), timeout=15,
    )
    resp.raise_for_status()
    return resp


def spool_payload(cfg, payload, target="artifacts"):
    os.makedirs(cfg["spool_dir"], exist_ok=True)
    cid = (payload.get("manifest") or {}).get("collection_id") or str(uuid.uuid4())
    path = os.path.join(cfg["spool_dir"], f"{cid}.json")
    wrapper = {"target": target}
    if target == "resources":
        wrapper["payload"] = payload
    else:
        # legacy shape: bare ingest payload at top level
        wrapper.update(payload)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(wrapper, fh)
    return path


def flush_spool(cfg):
    sent = 0
    if not os.path.isdir(cfg["spool_dir"]):
        return sent
    for fname in sorted(os.listdir(cfg["spool_dir"])):
        if not fname.endswith(".json"):
            continue
        path = os.path.join(cfg["spool_dir"], fname)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            target = data.get("target")
            if target == "resources":
                send_resources(cfg, data["payload"]["samples"])
            else:
                # legacy/unwrapped files go to the artifact ingest endpoint
                send_payload(cfg, {k: v for k, v in data.items() if k != "target"})
            os.remove(path)
            sent += 1
        except Exception:
            continue
    return sent


def enroll(cfg):
    import requests
    url = cfg["server_url"].rstrip("/") + "/api/v1/enroll"
    body = {
        "hostname": get_hostname(),
        "os_type": get_os_type(),
        "docker_engine_flag": 1 if has_docker_engine() else 0,
        "agent_version": AGENT_VERSION,
    }
    resp = requests.post(url, json=body, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    cfg["api_key"] = data["api_key"]
    cfg["client_id"] = data["client_id"]
    with open(CONFIG_PATH, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=2)
    return data


def has_docker_engine():
    import shutil
    import subprocess
    sock_paths = ["/var/run/docker.sock"]
    if any(os.path.exists(p) for p in sock_paths):
        return True
    if shutil.which("docker"):
        try:
            probe = subprocess.run(
                ["docker", "version", "--format", "{{.Server.Version}}"],
                capture_output=True, text=True, timeout=15,
            )
            return probe.returncode == 0
        except Exception:
            return False
    return False


def run_resource_sample(cfg):
    """Collect a single lightweight resource sample and send it."""
    sample = dispatch("resources")
    if not sample:
        return False
    try:
        send_resources(cfg, sample)
        return True
    except Exception:
        spool_payload(cfg, {"samples": sample}, target="resources")
        return False


def main():
    import time
    cfg = load_config()
    if len(sys.argv) > 1 and sys.argv[1] == "enroll":
        print(json.dumps(enroll(cfg), indent=2))
        return 0
    if len(sys.argv) > 1 and sys.argv[1] == "once":
        flush_spool(cfg)
        payload = run_collection()
        try:
            send_payload(cfg, payload)
            print(json.dumps({"status": "sent", "collection_id": payload["manifest"]["collection_id"]}))
        except Exception as exc:
            spool_payload(cfg, payload)
            print(json.dumps({"status": "spooled", "reason": str(exc)}))
        return 0
    if len(sys.argv) > 1 and sys.argv[1] == "loop":
        interval = max(5, int(cfg.get("collection_interval_seconds", 60)))
        r_interval = max(5, int(cfg.get("resource_interval_seconds", 15)))
        full_due = time.time()
        res_due = time.time()
        while True:
            now = time.time()
            # flush any spooled items first
            flush_spool(cfg)
            did_work = False
            if res_due <= now:
                run_resource_sample(cfg)
                res_due = now + r_interval
                did_work = True
            if full_due <= now:
                payload = run_collection()
                try:
                    send_payload(cfg, payload)
                    status = "sent"
                except Exception:
                    spool_payload(cfg, payload)
                    status = "spooled"
                print(f"[{payload['manifest']['finished_at_utc']}] {status}", flush=True)
                full_due = now + interval
                did_work = True
            if not did_work:
                # sleep to the nearest due time, capped at 30s
                wait = min(full_due, res_due) - now
                time.sleep(max(0.5, min(wait, 30)))
        return 0
    print("usage: python -m agent.agent [enroll|once|loop]")
    return 1


if __name__ == "__main__":
    sys.exit(main())
