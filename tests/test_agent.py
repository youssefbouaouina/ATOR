import hashlib
import json
import os

import agent.agent as ag
from agent.agent import build_manifest, load_config, run_collection
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
        "resources": [],
    }
    manifest = build_manifest("col-x", ts, ts, artifacts)
    assert manifest["manifest_sha256"]
    blob = json.dumps({k: v for k, v in manifest.items() if k != "manifest_sha256"},
                      sort_keys=True, default=str).encode()
    recomputed = hashlib.sha256(blob).hexdigest()
    assert manifest["manifest_sha256"] == recomputed
    counts = {e["collector"]: e["count"] for e in manifest["artifacts"]}
    assert counts == {"network": 1, "processes": 1, "persistence": 0,
                      "logs": 0, "files_triage": 0, "containers": 0, "resources": 0}
    order = [e["collector"] for e in manifest["artifacts"]]
    assert order.index("network") < order.index("processes") < order.index("persistence")
    assert order.index("persistence") < order.index("resources")


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


def test_enroll_os_type_is_real_os_even_with_docker(monkeypatch, tmp_path):
    captured = {}

    class FakeResp:
        def raise_for_status(self):
            return None

        def json(self):
            return {"api_key": "k-test", "client_id": "c-test"}

    def fake_post(url, json=None, timeout=None):
        captured["url"] = url
        captured["body"] = dict(json)
        return FakeResp()

    monkeypatch.setattr("requests.post", fake_post)
    monkeypatch.setattr(ag, "get_os_type", lambda: "windows")
    monkeypatch.setattr(ag, "has_docker_engine", lambda: True)
    monkeypatch.setattr(ag, "CONFIG_PATH", str(tmp_path / "config.json"))

    cfg = {"server_url": "http://srv:8000"}
    result = ag.enroll(cfg)

    assert captured["url"].endswith("/api/v1/enroll")
    # A Windows box with Docker Desktop installed must enroll as windows,
    # never as docker_host (regression: host was misclassified as docker).
    assert captured["body"]["os_type"] == "windows"
    assert captured["body"]["docker_engine_flag"] == 1
    assert result["api_key"] == "k-test"
    saved = json.loads((tmp_path / "config.json").read_text(encoding="utf-8"))
    assert saved["api_key"] == "k-test"


def test_load_config_env_beats_config_file_beats_default(monkeypatch, tmp_path):
    cfg_path = tmp_path / "config.json"
    cfg_path.write_text(json.dumps({"server_url": "http://from-file:8000"}), encoding="utf-8")

    monkeypatch.delenv("ATOR_SERVER_URL", raising=False)
    cfg = load_config(str(cfg_path))
    assert cfg["server_url"] == "http://from-file:8000"

    monkeypatch.setenv("ATOR_SERVER_URL", "http://from-env:8000")
    cfg = load_config(str(cfg_path))
    assert cfg["server_url"] == "http://from-env:8000"

    monkeypatch.delenv("ATOR_SERVER_URL")
    default = load_config(tmp_path / "missing.json")
    assert default["server_url"] == ag.DEFAULT_CONFIG["server_url"]
    assert not os.environ.get("ATOR_SERVER_URL")
