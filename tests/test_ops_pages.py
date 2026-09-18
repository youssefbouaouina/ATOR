"""Threat-intel, containment, report-history and per-endpoint stats - verified
to work identically for Windows and Linux endpoints."""
import hashlib
import json
from datetime import datetime, timezone

import pytest


@pytest.fixture()
def client(tmp_db, monkeypatch):
    """Full app (API + UI routes + static) so page renders can be asserted."""
    monkeypatch.setenv("ATOR_DFIR_DB", tmp_db)
    from fastapi.testclient import TestClient
    from server.ui import register_ui
    from server.api import app
    register_ui(app)
    with TestClient(app) as tc:
        yield tc


def _enroll(client, hostname, os_type):
    r = client.post("/api/v1/enroll", json={"hostname": hostname, "os_type": os_type})
    assert r.status_code == 200, r.text
    return r.json()


def _ingest(client, creds, artifacts, cid, os_type="linux"):
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    man = {"collection_id": cid, "hostname": "h", "os_type": os_type, "agent_version": "1.0.0",
           "started_at_utc": ts, "finished_at_utc": ts, "collector_order": [], "manifest_sha256": "x"}
    headers = {"Authorization": "Bearer " + creds["api_key"], "X-Client-ID": creds["client_id"]}
    r = client.post("/api/v1/ingest", json={"manifest": man, "artifacts": artifacts}, headers=headers)
    assert r.status_code == 202, r.text


def test_threat_intel_ioc_and_pivot_both_os(client):
    win = _enroll(client, "win-01", "windows")
    lnx = _enroll(client, "lnx-01", "linux")
    bad_hash = hashlib.sha256(b"evil.exe").hexdigest()
    # Watchlist accepts hash / ip / domain.
    for ioc in [{"ioc_type": "hash", "value": bad_hash},
                {"ioc_type": "ip", "value": "198.51.100.5"},
                {"ioc_type": "domain", "value": "c2.evil.example"}]:
        assert client.post("/api/v1/iocs", json=ioc).status_code == 200
    # Windows process carries the bad hash; Linux connection hits the bad IP.
    _ingest(client, win, {"processes": [{"pid": 10, "name": "evil.exe", "cmdline": "evil.exe",
            "exe_path": "C:/Temp/evil.exe", "sha256": bad_hash}]}, "win-c", "windows")
    _ingest(client, lnx, {"network": [{"pid": 20, "process_name": "curl",
            "remote": "198.51.100.5:443", "local": "10.0.0.2:5000", "proto": "tcp"}]}, "lnx-c", "linux")

    hit = client.get("/api/v1/iocs/search", params={"q": bad_hash}).json()
    assert hit["known_ioc"] is True
    assert any(p["hostname"] == "win-01" for p in hit["pivot"]["processes"])
    ip_hit = client.get("/api/v1/iocs/search", params={"q": "198.51.100.5"}).json()
    assert any(c["hostname"] == "lnx-01" for c in ip_hit["pivot"]["connections"])
    # The IOC page + engine correlation must flag both hosts.
    client.post("/api/v1/engine/run?scan_history=true")
    dets = client.get("/api/v1/detections").json()
    ioc_hosts = {d["host_id"] for d in dets if d["rule_type"] == "ioc"}
    assert win["host_id"] in ioc_hosts and lnx["host_id"] in ioc_hosts
    assert client.get("/intel").status_code == 200


def test_containment_policy_approvals_both_os(client):
    win = _enroll(client, "win-c", "windows")
    lnx = _enroll(client, "lnx-c", "linux")
    # A broad "approve everything >= high" policy.
    r = client.post("/api/v1/policies", json={"name": "auto-high", "min_severity": "high",
                                              "mode": "approve", "action": "isolate"})
    assert r.status_code == 200, r.text
    # High-severity detections on each OS via marker rules.
    _ingest(client, win, {"processes": [{"pid": 1, "name": "powershell.exe",
            "cmdline": "powershell ATOR_DEMO_BOTNET_BEACON c2=x", "exe_path": "powershell.exe"}]},
            "wc", "windows")
    _ingest(client, lnx, {"processes": [{"pid": 2, "name": "sleep",
            "cmdline": "ATOR_DEMO_RANSOMWARE_ENCRYPT ext=.locked", "exe_path": "/usr/bin/sleep"}]},
            "lc", "linux")
    client.post("/api/v1/engine/run?scan_history=true")

    pending = client.get("/api/v1/approvals?status=pending").json()
    hosts_with_approvals = set()
    for a in pending:
        det = client.get(f"/api/v1/detections?host_id={win['host_id']}").json()
        hosts_with_approvals.add(a.get("detection_id"))
    assert pending, "policy should have queued approvals"
    # Decide one (dry-run) and confirm it leaves the pending queue.
    first = pending[0]
    dec = client.post(f"/api/v1/approvals/{first['id']}/decide",
                      json={"decision": "approved", "analyst": "tester"})
    assert dec.status_code == 200, dec.text
    still = client.get("/api/v1/approvals?status=pending").json()
    assert first["id"] not in {p["id"] for p in still}
    assert client.get("/containment").status_code == 200


def test_report_history_and_filters(client):
    win = _enroll(client, "rep-win", "windows")
    _ingest(client, win, {"processes": [{"pid": 1, "name": "sleep",
            "cmdline": "ATOR_DEMO_SPYWARE_KEYLOGGER x", "exe_path": "/x"}]}, "rc", "windows")
    client.post("/api/v1/engine/run?scan_history=true")

    # Generate one of each kind and confirm history records them.
    for kind in ("pdf", "json", "stix"):
        g = client.post(f"/api/v1/hosts/{win['host_id']}/reports?kind={kind}")
        assert g.status_code == 200, g.text
        assert g.json()["report_id"]
    hist = client.get(f"/api/v1/reports?host_id={win['host_id']}").json()
    assert len(hist) >= 3
    kinds = {h["kind"] for h in hist}
    assert {"pdf", "json", "stix"} <= kinds
    assert all(h["available"] for h in hist)
    assert any(h["kind"] == "pdf" and h["detection_total"] >= 1 for h in hist)

    # Date filters: current year returns rows, a past year returns none.
    year = datetime.now(timezone.utc).year
    assert client.get(f"/api/v1/reports?host_id={win['host_id']}&year={year}").json()
    assert client.get(f"/api/v1/reports?host_id={win['host_id']}&year=2000").json() == []
    facets = client.get(f"/api/v1/reports/facets?host_id={win['host_id']}").json()
    assert str(year) in facets["years"] and facets["total"] >= 3

    # Download a stored report.
    pdf = next(h for h in hist if h["kind"] == "pdf")
    dl = client.get(f"/api/v1/reports/{pdf['id']}/download")
    assert dl.status_code == 200 and dl.content[:4] == b"%PDF"


def _req(client, hostname, os_type="windows"):
    r = client.post("/api/v1/enroll/request", json={"hostname": hostname, "os_type": os_type})
    assert r.status_code == 200, r.text
    return r.json()["request_token"]


def test_enrollment_crud_and_filters(client):
    t_win = _req(client, "crud-win", "windows")
    t_lnx = _req(client, "crud-lnx", "linux")
    _req(client, "crud-win2", "windows")

    # List all, then filter by status / platform / search.
    all_rows = client.get("/api/v1/enrollments?status=all").json()
    assert len(all_rows) == 3
    assert len(client.get("/api/v1/enrollments?platform=windows").json()) == 2
    assert len(client.get("/api/v1/enrollments?status=pending").json()) == 3
    hit = client.get("/api/v1/enrollments?q=crud-lnx").json()
    assert len(hit) == 1 and hit[0]["hostname"] == "crud-lnx"

    # Reject one so a 'rejected' bucket exists.
    client.post(f"/api/v1/enrollments/{t_lnx}/reject",
                json={"action": "reject", "analyst": "a", "rejection_reason": "test"})
    assert len(client.get("/api/v1/enrollments?status=rejected").json()) == 1

    # Delete a single request.
    d = client.delete(f"/api/v1/enrollments/{t_win}")
    assert d.status_code == 200 and d.json()["request_token"] == t_win
    assert client.delete(f"/api/v1/enrollments/{t_win}").status_code == 404
    assert len(client.get("/api/v1/enrollments?status=all").json()) == 2

    # Bulk purge by status.
    p = client.post("/api/v1/enrollments/purge", json={"statuses": ["rejected"]})
    assert p.status_code == 200 and p.json()["deleted"] == 1
    remaining = client.get("/api/v1/enrollments?status=all").json()
    assert len(remaining) == 1 and remaining[0]["hostname"] == "crud-win2"

    # Purge by explicit tokens clears the rest.
    tokens = [r["request_token"] for r in remaining]
    assert client.post("/api/v1/enrollments/purge", json={"tokens": tokens}).json()["deleted"] == 1
    assert client.get("/api/v1/enrollments?status=all").json() == []
    assert client.get("/enrollments").status_code == 200


def test_enrollment_purge_before_date(client):
    _req(client, "old-host")
    # Nothing is older than year 2000; everything is older than a far-future date.
    assert client.post("/api/v1/enrollments/purge", json={"before": "2000-01-01"}).json()["deleted"] == 0
    assert client.post("/api/v1/enrollments/purge", json={"before": "2999-01-01"}).json()["deleted"] == 1


def test_stats_footprint(client):
    win = _enroll(client, "fp-host", "windows")
    headers = {"Authorization": "Bearer " + win["api_key"], "X-Client-ID": win["client_id"]}
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    client.post("/api/v1/ingest/resources", json={"samples": [{
        "sampled_at_utc": ts, "cpu_pct": 30.0, "mem_pct": 40.0, "mem_used_mb": 3276.0,
        "mem_total_mb": 8192.0, "cpu_cores": 4, "hw_tier": "mid"}]}, headers=headers)
    client.post("/api/v1/agent-self/ingest", json={"samples": [{
        "sampled_at_utc": ts, "agent_cpu_pct": 1.5, "agent_mem_mb": 52.0, "agent_threads": 10,
        "collection_duration_ms": 850.0, "payload_size_bytes": 4096, "spool_count": 0,
        "telemetry_mode": "full"}]}, headers=headers)

    f = client.get("/api/v1/stats/footprint").json()
    assert f["reporting"] == 1 and f["endpoints"] == 1
    assert f["avg_agent_cpu_pct"] == 1.5
    assert f["total_agent_mem_mb"] == 52.0
    assert f["avg_collection_ms"] == 850.0
    assert f["avg_sys_cpu_pct"] == 30.0 and f["avg_sys_mem_pct"] == 40.0
    assert f["verdict"] == "Lightweight"          # 1.5% cpu / 52 MB
    assert f["telemetry_bytes_24h"] >= 4096
    assert client.get("/telemetry").status_code == 200


def test_stats_endpoints_per_host(client):
    win = _enroll(client, "s-win", "windows")
    lnx = _enroll(client, "s-lnx", "linux")
    _ingest(client, win, {"processes": [{"pid": 1, "name": "p",
            "cmdline": "ATOR_DEMO_RANSOMWARE_ENCRYPT", "exe_path": "/x"}]}, "sw", "windows")
    client.post("/api/v1/engine/run?scan_history=true")
    rows = client.get("/api/v1/stats/endpoints").json()
    by_name = {r["hostname"]: r for r in rows}
    assert "s-win" in by_name and "s-lnx" in by_name
    assert by_name["s-win"]["detection_total"] >= 1
    assert by_name["s-lnx"]["detection_total"] == 0
    assert by_name["s-win"]["os_type"] == "windows"
    assert "agent_status" in by_name["s-win"]
