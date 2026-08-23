import hashlib
import json

from agent.agent import build_manifest, run_collection
from agent.collectors import persistence as persistence_mod


def test_manifest_integrity():
    from datetime import datetime, timezone
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    artifacts = {
        "network": [{"pid": 1}],
        "processes": [{"pid": 2, "name": "x"}],
        "persistence": [],
        "logs": [],
        "files_triage": [],
        "containers": [],
    }
    manifest = build_manifest("col-x", ts, ts, artifacts)
    assert manifest["manifest_sha256"]
    blob = json.dumps({k: v for k, v in manifest.items() if k != "manifest_sha256"},
                      sort_keys=True, default=str).encode()
    recomputed = hashlib.sha256(blob).hexdigest()
    assert manifest["manifest_sha256"] == recomputed
    counts = {e["collector"]: e["count"] for e in manifest["artifacts"]}
    assert counts == {"network": 1, "processes": 1, "persistence": 0,
                      "logs": 0, "files_triage": 0, "containers": 0}
    order = [e["collector"] for e in manifest["artifacts"]]
    assert order.index("network") < order.index("processes") < order.index("persistence")


def test_live_collection_windows(monkeypatch):
    small_cfg = {
        "server_url": "http://127.0.0.1:8000", "api_key": "", "client_id": "",
        "spool_dir": "spool_test", "max_events_per_source": 30,
        "max_files": 10, "max_file_bytes": 100000,
        "enable_local_yara": True,
        "collection_interval_seconds": 60,
    }
    monkeypatch.setattr("agent.collectors.logs.load_config", lambda: dict(small_cfg))
    monkeypatch.setattr("agent.collectors.files_triage.load_config", lambda: dict(small_cfg))
    payload = run_collection()
    manifest = payload["manifest"]
    assert manifest["hostname"]
    by_name = {e["collector"]: e for e in manifest["artifacts"]}
    assert by_name["processes"]["count"] > 10
    assert by_name["network"]["count"] >= 0
    errors = []
    for name in ("processes", "network", "persistence", "logs", "files_triage"):
        for item in payload["artifacts"][name]:
            if isinstance(item, dict) and "_error" in item:
                errors.append((name, item["_error"]))
    fatal = [(n, e) for n, e in errors
             if not (n == "logs" and ("Security" in e or "access_denied" in e))]
    assert not fatal, fatal


def test_persistence_collector_runs():
    items = persistence_mod.collect()
    assert isinstance(items, list)
    assert all({"ptype", "name", "command", "location"} <= set(i.keys()) for i in items)
