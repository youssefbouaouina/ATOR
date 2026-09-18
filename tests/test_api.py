import json
import uuid

import pytest


def _enroll(client, hostname="e2e-win", os_type="windows"):
    resp = client.post("/api/v1/enroll", json={
        "hostname": hostname, "os_type": os_type, "docker_engine_flag": 0,
    })
    assert resp.status_code == 200, resp.text
    return resp.json()


def _ingest(client, enrolled, artifacts, cid):
    from datetime import datetime, timezone
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    manifest = {
        "collection_id": cid,
        "hostname": "e2e-win",
        "os_type": "windows",
        "agent_version": "1.0.0-test",
        "started_at_utc": ts,
        "finished_at_utc": ts,
        "collector_order": ["network", "processes"],
        "artifacts": [],
    }
    import hashlib
    blob = json.dumps({k: v for k, v in manifest.items()}, sort_keys=True, default=str).encode()
    manifest["manifest_sha256"] = hashlib.sha256(blob).hexdigest()
    payload = {"manifest": manifest, "artifacts": artifacts}
    headers = {
        "Authorization": "Bearer " + enrolled["api_key"],
        "X-Client-ID": enrolled["client_id"],
    }
    resp = client.post("/api/v1/ingest", json=payload, headers=headers)
    assert resp.status_code == 202, resp.text
    return ts


def test_full_api_flow(client):
    enrolled = _enroll(client)
    artifacts = {
        "processes": [
            {"pid": 900, "ppid": 4, "name": "powershell.exe",
             "cmdline": r"powershell.exe -nop -w hidden -enc SQBFAFgA",
             "exe_path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
             "sha256": None},
            {"pid": 901, "ppid": 900, "name": "whoami.exe", "cmdline": "whoami.exe /all",
             "exe_path": r"C:\Windows\System32\whoami.exe", "sha256": None},
            {"pid": 902, "ppid": 900, "name": "mimikatz.exe",
             "cmdline": "mimikatz.exe sekurlsa::logonpasswords",
             "exe_path": r"C:\Temp\mimikatz_x64.exe", "sha256": None},
        ],
        "network": [
            {"pid": 900, "process_name": "powershell.exe", "remote": "198.51.100.23:4444"},
        ],
        "persistence": [{"ptype": "registry_run", "name": "updater", "command": "evil.exe"}],
        "files_triage": [],
        "logs": [{"source": "system", "event_id": 7045, "event_time_utc":
                  "2026-08-20T10:00:00+00:00", "payload_json": {"message": "service installed"}}],
        "containers": [],
    }
    _ingest(client, enrolled, artifacts, "col-e2e-1")

    dets = client.get("/api/v1/detections").json()
    names = [d["rule_name"] for d in dets]
    assert any("Encoded Command" in n for n in names), names
    assert any("Reverse Shell" in n for n in names), names
    assert any("Mimikatz" in n for n in names), names

    powershell_det = next(d for d in dets if "Encoded Command" in d["rule_name"])
    assert powershell_det["technique_id"] == "T1059.001"
    assert powershell_det["technique_name"] == "PowerShell"
    tactics = powershell_det["tactics_parsed"]
    assert any(t["short"] == "execution" for t in tactics)

    host_id = enrolled["host_id"]
    tl = client.get("/api/v1/timeline", params={"host_id": host_id}).json()
    dts = [e["_dt"] for e in tl["events"] if e.get("_dt")]
    assert dts == sorted(dts)
    assert tl["total"] >= len(artifacts["logs"]) + len(dets)

    soc = client.get(f"/api/v1/soc/{host_id}").json()
    stages = [s["tactic"] for s in soc["chain"]]
    assert "execution" in stages

    policy = client.post("/api/v1/policies", json={
        "name": "auto-escalate", "min_severity": "high", "mode": "approve", "action": "isolate",
    })
    assert policy.status_code == 200

    client.post("/api/v1/engine/run")

    # First engine run processes the raw artifacts and creates new detections,
    # then evaluates policies against those new detections - this SHOULD create
    # approvals for the newly processed findings.
    approvals = client.get("/api/v1/approvals").json()
    assert len(approvals) >= 1
    # scan_history explicitly applies a newly created policy to recent
    # detections from PREVIOUS runs, capped by ATOR_POLICY_MAX_PER_RUN.
    client.post("/api/v1/engine/run?scan_history=true")
    approvals = client.get("/api/v1/approvals").json()
    assert len(approvals) >= 1
    approval = approvals[0]
    decided = client.post(
        f"/api/v1/approvals/{approval['id']}/decide",
        json={"decision": "approved", "analyst": "tester"},
    )
    assert decided.status_code == 200
    result = decided.json()["result"]
    assert result["mode"].startswith("DRY-RUN")
    assert result["target_host"] == "e2e-win"

    audit_rows = client.get("/api/v1/detections").json()
    assert audit_rows


def test_auth_failures(client):
    enrolled = _enroll(client, hostname="auth-host")
    bad_headers = {"Authorization": "Bearer wrong", "X-Client-ID": enrolled["client_id"]}
    resp = client.post("/api/v1/ingest", json={"manifest": {}, "artifacts": {}}, headers=bad_headers)
    assert resp.status_code == 403
    no_headers = client.post("/api/v1/ingest", json={"manifest": {}, "artifacts": {}})
    assert no_headers.status_code in (401, 403)


def test_revoke_blocks_ingest(client):
    enrolled = _enroll(client, hostname="revoke-me")
    revoke = client.post(f"/api/v1/hosts/{enrolled['host_id']}/revoke")
    assert revoke.status_code == 200
    headers = {"Authorization": "Bearer " + enrolled["api_key"], "X-Client-ID": enrolled["client_id"]}
    payload = {
        "manifest": {"collection_id": "x", "hostname": "revoke-me", "os_type": "windows"},
        "artifacts": {},
    }
    resp = client.post("/api/v1/ingest", json=payload, headers=headers)
    assert resp.status_code == 403


def test_duplicate_collection_ignored(client):
    enrolled = _enroll(client, hostname="dup-host")
    artifacts = {"processes": [], "network": [], "persistence": [], "files_triage": [],
                 "logs": [], "containers": []}
    first = _ingest(client, enrolled, artifacts, "dup-col")
    assert first

    import hashlib
    from datetime import datetime, timezone
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    manifest = {
        "collection_id": "dup-col", "hostname": "dup-host", "os_type": "windows",
        "agent_version": "1.0.0-test", "started_at_utc": ts, "finished_at_utc": ts,
        "collector_order": [],
    }
    manifest["manifest_sha256"] = hashlib.sha256(
        json.dumps(manifest, sort_keys=True, default=str).encode()).hexdigest()
    headers = {
        "Authorization": "Bearer " + enrolled["api_key"],
        "X-Client-ID": enrolled["client_id"],
    }
    second = client.post("/api/v1/ingest", json={"manifest": manifest, "artifacts": artifacts},
                         headers=headers)
    assert second.status_code == 202
    assert second.json().get("status") == "duplicate"


def test_ioc_watchlist_and_pivot(client):
    add = client.post("/api/v1/iocs", json={"ioc_type": "hash", "value": "b" * 64})
    assert add.status_code == 200
    pivot = client.get("/api/v1/iocs/search", params={"q": "b" * 64}).json()
    assert pivot["known_ioc"] is True


@pytest.mark.parametrize("technique_id, path", [
    ("T1059", "T1059/"),
    ("T1059.001", "T1059/001/"),
    ("T1071.001", "T1071/001/"),
])
def test_mitre_link_paths(technique_id, path):
    from server.engine import reporter
    markup = reporter._mitre_link(technique_id, None)
    assert f'href="https://attack.mitre.org/techniques/{path}"' in markup
    assert f"<u>{technique_id}</u>" in markup


@pytest.mark.parametrize("technique_id", [
    None, "", "T1059.01", "T1059.0001", "T1059/001", "T1059.001/",
    "T1059\n", " T1059", "t1059", "T１０５９", 1059,
    'T1059" title="invalid', "<b>invalid & ID</b>",
])
def test_mitre_link_invalid_ids_are_plain_text(technique_id):
    import html
    from server.engine import reporter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph
    markup = reporter._mitre_link(technique_id, None)
    assert markup == (html.escape(str(technique_id)) if technique_id else "-")
    paragraph = Paragraph(markup, getSampleStyleSheet()["BodyText"])
    assert not any(fragment.link for fragment in paragraph.frags)


def test_pdf_mitre_links(seeded_host, tmp_path, monkeypatch):
    import re
    from server import db as database
    from server.engine import reporter

    monkeypatch.setattr(reporter, "REPORTS_DIR", str(tmp_path))
    conn = database.connect()
    try:
        for tid in ("T1059", "T1059.001", '<b>invalid & ID</b>'):
            cur = conn.execute(
                "INSERT INTO detections (host_id, rule_type, rule_name, severity, technique_id, "
                "summary, detected_at_utc) VALUES (?, 'sigma', 'Link regression', 'high', ?, '{}', ?)",
                (seeded_host["host_id"], tid, "2026-09-17T00:00:00+00:00"),
            )
            conn.execute(
                "INSERT INTO enriched_detections (detection_id, technique_name, tactic) VALUES (?, ?, ?)",
                (cur.lastrowid, "Link regression", json.dumps([{"short": "execution", "name": "Execution"}])),
            )
        conn.commit()
        path = tmp_path / "links.pdf"
        reporter.generate_pdf(conn, seeded_host["host_id"], str(path))
        pdf = path.read_bytes()
        uris = re.findall(rb"/URI\s*\(([^)]*)\)", pdf)
        assert sorted(uris) == sorted([
            b"https://attack.mitre.org/techniques/T1059/",
            b"https://attack.mitre.org/techniques/T1059/",
            b"https://attack.mitre.org/techniques/T1059/001/",
            b"https://attack.mitre.org/techniques/T1059/001/",
        ])
        assert b"/S /GoTo" in pdf or b"/Dest" in pdf
    finally:
        conn.close()


def test_exports_generate(client, tmp_path, monkeypatch):
    from server.engine import reporter
    monkeypatch.setattr(reporter, "REPORTS_DIR", str(tmp_path))
    enrolled = _enroll(client, hostname="export-host")
    artifacts = {
        "processes": [{"pid": 7, "ppid": 1, "name": "powershell.exe",
                       "cmdline": "powershell.exe -enc AAAA",
                       "exe_path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                       "sha256": None}],
        "network": [], "persistence": [], "files_triage": [], "logs": [], "containers": [],
    }
    _ingest(client, enrolled, artifacts, "col-export")
    client.post("/api/v1/iocs", json={"ioc_type": "ip", "value": "198.51.100.23"})
    client.post("/api/v1/engine/run")
    hid = enrolled["host_id"]

    pdf = client.get(f"/api/v1/export/report/{hid}.pdf")
    assert pdf.status_code == 200 and b"%PDF" in pdf.content[:8]

    jsn = client.get(f"/api/v1/export/report/{hid}.json").json()
    assert jsn["risk"]["verdict"]
    assert isinstance(jsn["detections"], list)

    stix = client.get(f"/api/v1/export/stix/{hid}.json").json()
    assert stix["type"] == "bundle"
    types = {o["type"] for o in stix["objects"]}
    assert "identity" in types

    nav = client.get("/api/v1/export/navigator.json").json()
    assert nav["domain"] == "enterprise-attack"
    assert isinstance(nav["techniques"], list) and nav["techniques"], nav
    tids = {t["techniqueID"] for t in nav["techniques"]}
    assert "T1059.001" in tids


def test_sample_upload_yara(client, tmp_path):
    from fastapi.testclient import TestClient as _TC
    enrolled = _enroll(client, hostname="sample-host")
    headers = {
        "Authorization": "Bearer " + enrolled["api_key"],
        "X-Client-ID": enrolled["client_id"],
    }
    sample = tmp_path / "marker.bin"
    sample.write_bytes(b"MZ" + b"\x00" * 32 + b"ATOR_DFIR_TEST_FILE_MARKER_X7Q9")
    with open(sample, "rb") as fh:
        resp = client.post("/api/v1/samples", files={"file": ("marker.bin", fh)},
                           data={"note": "validation"}, headers=headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert any("Eicar_Style" in m.get("rule", "") for m in body["yara_matches"]), body

