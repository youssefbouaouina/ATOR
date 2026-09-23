import json
import os
import subprocess

import pytest

from agent import velociraptor_catalog as catalog


# --- catalog / allow-list ---------------------------------------------------

def test_catalog_entries_are_well_formed():
    for name, meta in catalog.CATALOG.items():
        assert meta["platforms"], name
        assert set(meta["platforms"]) <= {"windows", "linux"}, name
        assert meta["description"], name
        assert isinstance(meta["timeout_seconds"], int) and meta["timeout_seconds"] > 0, name
        # the artifact name must match the platform it claims, or the UI offers
        # an artifact the agent will refuse
        prefix = name.split(".", 1)[0].lower()
        assert prefix in meta["platforms"], name


def test_default_triage_is_inside_the_allow_list():
    for platform, names in catalog.DEFAULT_TRIAGE.items():
        for name in names:
            assert catalog.is_allowed(name)
            assert platform in catalog.CATALOG[name]["platforms"]


def test_validate_rejects_unknown_and_cross_platform():
    accepted, rejected = catalog.validate(
        ["Windows.System.Pslist", "Linux.Sys.Pslist", "Evil.Artifact"], os_type="windows")
    assert accepted == ["Windows.System.Pslist"]
    reasons = {r["artifact"]: r["reason"] for r in rejected}
    assert "not in the ATOR artifact allow-list" in reasons["Evil.Artifact"]
    assert "does not run on windows" in reasons["Linux.Sys.Pslist"]


def test_validate_caps_the_request_size():
    names = [n for n, m in catalog.CATALOG.items() if "windows" in m["platforms"]]
    accepted, rejected = catalog.validate(names, os_type="windows")
    assert len(accepted) == catalog.MAX_ARTIFACTS_PER_REQUEST
    assert rejected


def test_validate_deduplicates():
    accepted, _ = catalog.validate(
        ["Windows.System.Pslist", "Windows.System.Pslist"], os_type="windows")
    assert accepted == ["Windows.System.Pslist"]


# --- agent collector --------------------------------------------------------

def test_normalise_row_promotes_correlatable_fields():
    from agent.collectors import velociraptor as velo
    row = velo.normalise_row("Windows.System.Pslist", {
        "Pid": "1234", "Name": "evil.exe", "Exe": r"C:\Temp\evil.exe",
        "Hash": {"SHA256": "AABBCC"},
    })
    assert row["pid"] == 1234
    assert row["process_name"] == "evil.exe"
    assert row["path"] == r"C:\Temp\evil.exe"
    assert row["sha256"] == "aabbcc"
    assert json.loads(row["row_json"])["Name"] == "evil.exe"


def test_normalise_row_survives_rows_with_nothing_to_promote():
    from agent.collectors import velociraptor as velo
    row = velo.normalise_row("Linux.Sys.Crontab", {"Line": "* * * * * /bin/true"})
    assert row["sha256"] is None and row["path"] is None
    assert json.loads(row["row_json"])["Line"] == "* * * * * /bin/true"


def test_normalise_row_splits_host_port_remote():
    from agent.collectors import velociraptor as velo
    row = velo.normalise_row("Windows.Network.Netstat", {"RemoteAddr": "10.0.0.9:4444"})
    assert row["remote_ip"] == "10.0.0.9"


def test_parse_output_handles_both_json_shapes():
    from agent.collectors import velociraptor as velo
    as_array = velo._parse_output("A", '[{"Name": "a"}, {"Name": "b"}]')
    as_lines = velo._parse_output("A", '{"Name": "a"}\n{"Name": "b"}\n')
    assert len(as_array) == len(as_lines) == 2


def test_parse_output_handles_real_pretty_printed_multi_document_output():
    """Regression: real Velociraptor output, not the tidy shape first assumed.

    An artifact with several sources emits several PRETTY-PRINTED arrays
    concatenated on stdout. The original parser failed whole-text, fell back to
    line-by-line, and stored the handful of lines that happened to be lone
    scalars - producing rows like {"value": "RemoteDisconnect"} with nothing
    promoted. Observed live on Windows.System.TaskScheduler / Forensics.Prefetch.
    """
    from agent.collectors import velociraptor as velo
    stdout = """[
 {
  "Name": "RemoteDisconnect",
  "Command": "C:\\\\Windows\\\\System32\\\\rdpsa.exe",
  "Arguments": "-m:aemarebackup.dll -f:BackupMareData"
 },
 {
  "Name": "SessionUnlock",
  "Command": "C:\\\\Windows\\\\System32\\\\unlock.exe",
  "Arguments": "5"
 }
]
[
 {
  "Name": "SecondSource",
  "Command": "C:\\\\Windows\\\\System32\\\\other.exe",
  "Arguments": "1"
 }
]
"""
    rows = velo._parse_output("Windows.System.TaskScheduler", stdout)
    assert len(rows) == 3, "both documents must be read, not just the first"
    names = [r["process_name"] for r in rows]
    assert names == ["RemoteDisconnect", "SessionUnlock", "SecondSource"]
    # the bug's signature: a row whose only key is "value"
    for r in rows:
        assert "value" not in json.loads(r["row_json"])
        assert r["path"], "Command must be promoted to path"


def test_parse_output_discards_scalars_rather_than_storing_them():
    """A stray scalar is a parse failure, not evidence - it must not be stored."""
    from agent.collectors import velociraptor as velo
    assert velo._parse_output("A", '"RemoteDisconnect"\n5\n') == []


def test_parse_output_skips_banner_lines_before_json():
    from agent.collectors import velociraptor as velo
    rows = velo._parse_output("A", 'Velociraptor 0.77.2 starting\n[{"Name": "x"}]\n')
    assert len(rows) == 1 and rows[0]["process_name"] == "x"


def test_parse_output_caps_rows(monkeypatch):
    from agent.collectors import velociraptor as velo
    monkeypatch.setattr(velo, "MAX_ROWS_PER_ARTIFACT", 3)
    rows = velo._parse_output("A", json.dumps([{"i": i} for i in range(50)]))
    assert len(rows) == 4                       # 3 rows + the cap notice
    assert "row cap reached" in rows[-1]["row_json"]


def test_run_artifact_refuses_anything_off_the_allow_list(monkeypatch):
    from agent.collectors import velociraptor as velo

    def explode(*a, **k):                        # pragma: no cover - must not run
        raise AssertionError("subprocess must not be invoked for a rejected artifact")

    monkeypatch.setattr(subprocess, "run", explode)
    out = velo.run_artifact("Evil.Artifact; rm -rf /", cfg={})
    assert out[0]["_error"] == "artifact not in allow-list"


def test_collect_without_a_binary_does_not_raise(monkeypatch):
    from agent.collectors import velociraptor as velo
    monkeypatch.setattr(velo, "find_binary", lambda cfg=None: None)
    monkeypatch.setattr(velo, "os_type", lambda: "windows")
    rows = velo.collect(["Windows.System.Pslist"], cfg={})
    assert rows and "not found" in rows[0]["_error"]


def test_command_artifacts_parses_server_args():
    from agent.agent import _command_artifacts
    assert _command_artifacts({"args": '{"artifacts": ["A", "B"]}'}) == ["A", "B"]
    assert _command_artifacts({"args": {"artifacts": ["A"]}}) == ["A"]
    assert _command_artifacts({"args": "not json"}) == []
    assert _command_artifacts({}) == []


def test_sweep_manifest_hash_covers_the_extra_fields(monkeypatch):
    """The trigger/requested_artifacts keys must be inside manifest_sha256."""
    import hashlib

    from agent import agent as ag
    monkeypatch.setattr("agent.collectors.velociraptor.collect",
                        lambda names: [{"artifact": "X", "row_json": "{}"}])
    payload = ag.run_velociraptor_collection(["Windows.System.Pslist"])
    manifest = payload["manifest"]
    assert manifest["trigger"] == "velociraptor_collect"
    assert manifest["requested_artifacts"] == ["Windows.System.Pslist"]
    recomputed = hashlib.sha256(json.dumps(
        {k: v for k, v in manifest.items() if k != "manifest_sha256"},
        sort_keys=True, default=str).encode()).hexdigest()
    assert manifest["manifest_sha256"] == recomputed
    counts = {e["collector"]: e["count"] for e in manifest["artifacts"]}
    assert counts["velociraptor"] == 1


# --- schema migration -------------------------------------------------------

def test_legacy_command_table_is_widened():
    import os
    import sqlite3
    import tempfile

    from server import db as database
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.remove(path)
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE hosts (id INTEGER PRIMARY KEY, hostname TEXT);
        CREATE TABLE agent_commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL REFERENCES hosts(id),
            command TEXT NOT NULL CHECK (command IN ('collect_now','detect_now')),
            status TEXT NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending','claimed','done','failed','expired')),
            requested_by TEXT, created_at_utc TEXT NOT NULL,
            claimed_at_utc TEXT, finished_at_utc TEXT, result TEXT);
        INSERT INTO hosts VALUES (1, 'legacy');
        INSERT INTO agent_commands (host_id, command, created_at_utc)
            VALUES (1, 'collect_now', '2026-01-01T00:00:00');
    """)
    conn.commit()
    conn.close()

    database.init_db(path)
    conn = database.connect(path)
    # history survived the rebuild
    assert conn.execute("SELECT COUNT(*) FROM agent_commands").fetchone()[0] == 1
    conn.execute("""INSERT INTO agent_commands (host_id, command, args, created_at_utc)
                    VALUES (1,'velociraptor_collect','{}','2026-01-02T00:00:00')""")
    conn.commit()
    assert database.ensure_command_types(conn) is False      # idempotent
    conn.close()
    for suffix in ("", "-wal", "-shm"):
        try:
            os.remove(path + suffix)
        except OSError:
            pass


# --- server: tasking, ingest, correlation -----------------------------------

@pytest.fixture()
def client(tmp_db, monkeypatch):
    """Full app (API + UI routes) so the page render can be asserted too."""
    monkeypatch.setenv("ATOR_DFIR_DB", tmp_db)
    from fastapi.testclient import TestClient

    from server.api import app
    from server.ui import register_ui
    register_ui(app)
    with TestClient(app) as tc:
        yield tc


@pytest.fixture()
def enrolled(client):
    resp = client.post("/api/v1/enroll", json={
        "hostname": "velo-win01", "os_type": "windows", "agent_version": "1.0.0"})
    assert resp.status_code == 200
    body = resp.json()
    return {"headers": {"Authorization": f"Bearer {body['api_key']}",
                        "X-Client-ID": body["client_id"]},
            "host_id": body.get("host_id", 1)}


def test_catalog_endpoint_scopes_by_platform(client):
    everything = client.get("/api/v1/velociraptor/catalog").json()
    assert everything["artifacts"] and everything["default_triage"]["windows"]
    windows = client.get("/api/v1/velociraptor/catalog?os_type=windows").json()
    assert windows["artifacts"]
    assert all("windows" in a["platforms"] for a in windows["artifacts"])


def test_requesting_a_sweep_queues_a_command_the_agent_receives(client, enrolled):
    resp = client.post("/api/v1/hosts/1/velociraptor",
                       json={"artifacts": ["Windows.System.Pslist", "Linux.Sys.Pslist"]})
    assert resp.status_code == 200
    body = resp.json()
    assert body["artifacts"] == ["Windows.System.Pslist"]
    assert body["rejected"][0]["artifact"] == "Linux.Sys.Pslist"

    hb = client.post("/api/v1/agent/heartbeat", json={"state": "running"},
                     headers=enrolled["headers"]).json()
    queued = [c for c in hb["commands"] if c["command"] == "velociraptor_collect"]
    assert len(queued) == 1
    assert json.loads(queued[0]["args"])["artifacts"] == ["Windows.System.Pslist"]


def test_empty_request_expands_to_the_platform_triage_set(client, enrolled):
    body = client.post("/api/v1/hosts/1/velociraptor", json={}).json()
    assert body["artifacts"] == list(catalog.DEFAULT_TRIAGE["windows"])


def test_sweep_request_rejects_an_all_invalid_list(client, enrolled):
    resp = client.post("/api/v1/hosts/1/velociraptor", json={"artifacts": ["Evil.Artifact"]})
    assert resp.status_code == 400


def test_sweep_request_refused_for_a_paused_agent(client, enrolled):
    client.post("/api/v1/hosts/1/agent/state", json={"state": "paused"})
    resp = client.post("/api/v1/hosts/1/velociraptor", json={})
    assert resp.status_code == 409


def test_heartbeat_records_the_agent_probe(client, enrolled):
    client.post("/api/v1/agent/heartbeat", headers=enrolled["headers"], json={
        "state": "running",
        "velociraptor": {"present": True, "version": "velociraptor 0.72.4", "path": "/opt/velo"},
    })
    body = client.get("/api/v1/hosts/1/velociraptor").json()
    assert body["velociraptor"]["state"] == "ready"
    assert body["velociraptor"]["version"] == "velociraptor 0.72.4"


def test_unknown_probe_is_not_reported_as_absent(client, enrolled):
    body = client.get("/api/v1/hosts/1/velociraptor").json()
    assert body["velociraptor"]["state"] == "unknown"


def _sweep_payload(collection_id, rows):
    return {
        "manifest": {"collection_id": collection_id, "hostname": "velo-win01",
                     "started_at_utc": "2026-09-22T10:00:00+00:00",
                     "finished_at_utc": "2026-09-22T10:00:05+00:00",
                     "agent_version": "1.0.0", "trigger": "velociraptor_collect",
                     "manifest_sha256": "deadbeef"},
        "artifacts": {"velociraptor": rows},
    }


def test_ingest_stores_rows_and_dedupes_repeat_sweeps(client, enrolled):
    rows = [{"artifact": "Windows.System.Pslist", "row_json": '{"Name": "evil.exe"}',
             "path": r"C:\Temp\evil.exe", "sha256": "ab" * 32,
             "process_name": "evil.exe", "pid": 1234}]
    first = client.post("/api/v1/ingest", json=_sweep_payload("sweep-1", rows),
                        headers=enrolled["headers"]).json()
    assert first["inserted"] == 1

    second = client.post("/api/v1/ingest", json=_sweep_payload("sweep-2", rows),
                         headers=enrolled["headers"]).json()
    assert second["deduped"] == 1, "an unchanged row must update, not duplicate"

    body = client.get("/api/v1/hosts/1/velociraptor").json()
    assert len(body["rows"]) == 1
    assert body["rows"][0]["observation_count"] == 2
    assert body["rows"][0]["row"]["Name"] == "evil.exe"
    assert body["summary"][0]["artifact"] == "Windows.System.Pslist"


def test_error_rows_are_not_stored_as_evidence(client, enrolled):
    payload = _sweep_payload("sweep-err", [
        {"artifact": "Windows.System.Pslist", "_error": "velociraptor binary not found"}])
    client.post("/api/v1/ingest", json=payload, headers=enrolled["headers"])
    assert client.get("/api/v1/hosts/1/velociraptor").json()["rows"] == []


def test_artifact_rows_raise_ioc_detections_with_provenance(client, enrolled):
    bad_hash = "cd" * 32
    client.post("/api/v1/iocs", json={"ioc_type": "hash", "value": bad_hash,
                                      "threat_source": "unit-test"})
    payload = _sweep_payload("sweep-ioc", [
        {"artifact": "Windows.System.Pslist", "row_json": '{"Name": "mal.exe"}',
         "path": r"C:\Temp\mal.exe", "sha256": bad_hash,
         "process_name": "mal.exe", "pid": 99}])
    client.post("/api/v1/ingest", json=payload, headers=enrolled["headers"])
    client.post("/api/v1/hosts/1/scan")

    hits = [d for d in client.get("/api/v1/detections?host_id=1").json()
            if d["rule_type"] == "ioc"]
    assert hits, "a watchlisted hash seen by an artifact must fire"
    evidence = json.loads(hits[0]["summary"])
    assert evidence["collector"] == "velociraptor"
    assert evidence["velociraptor_artifact"] == "Windows.System.Pslist"


def test_clean_artifact_rows_raise_nothing(client, enrolled):
    payload = _sweep_payload("sweep-clean", [
        {"artifact": "Windows.System.Pslist", "row_json": '{"Name": "svchost.exe"}',
         "path": r"C:\Windows\System32\svchost.exe", "sha256": "ee" * 32,
         "process_name": "svchost.exe", "pid": 4}])
    client.post("/api/v1/ingest", json=payload, headers=enrolled["headers"])
    client.post("/api/v1/hosts/1/scan")
    assert client.get("/api/v1/detections?host_id=1").json() == []


def test_sweep_rows_reach_the_timeline_grouped_by_artifact(client, enrolled):
    rows = [{"artifact": "Windows.System.Pslist", "row_json": '{"i": %d}' % i,
             "process_name": "p%d" % i} for i in range(20)]
    client.post("/api/v1/ingest", json=_sweep_payload("sweep-tl", rows),
                headers=enrolled["headers"])
    body = client.get("/api/v1/timeline?host_id=1").json()
    velo_events = [e for e in body["events"] if e["kind"] == "velociraptor"]
    assert len(velo_events) == 1, "20 rows must collapse to one timeline event"
    assert "20 rows" in velo_events[0]["detail"]
    # the reported total must count the same way the timeline displays, or the
    # investigation page claims events that are never shown
    assert body["total"] == len(body["events"])


def test_report_json_records_which_artifacts_were_collected(client, enrolled):
    client.post("/api/v1/ingest", headers=enrolled["headers"], json=_sweep_payload(
        "sweep-report", [{"artifact": "Windows.System.Services",
                          "row_json": '{"Name": "svc"}', "process_name": "svc"}]))
    report = client.get("/api/v1/export/report/1.json").json()
    collected = {v["artifact"] for v in report["velociraptor"]}
    assert "Windows.System.Services" in collected


def test_velociraptor_page_renders(client, enrolled):
    resp = client.get("/velociraptor")
    assert resp.status_code == 200
    assert "Velociraptor artifacts" in resp.text
    assert "Windows.System.Pslist" in resp.text


def test_probe_reports_the_version_line_not_the_name_line(monkeypatch):
    """`velociraptor version` prints YAML starting with "name: velociraptor"."""
    from agent.collectors import velociraptor as velo

    class Result:
        returncode = 0
        stdout = "name: velociraptor\nversion: 0.77.2\ncommit: abc123\n"
        stderr = ""

    monkeypatch.setattr(velo, "find_binary", lambda cfg=None: "/opt/velociraptor")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: Result())
    assert velo.probe(cfg={})["version"] == "0.77.2"


# --- results are read from a file, not a pipe --------------------------------

def _fake_collect(monkeypatch, stdout_bytes, returncode=0, stderr=b""):
    """Stand in for velociraptor.exe: write to the sink the collector opened."""
    from agent.collectors import velociraptor as velo

    class Result:
        pass

    def fake_run(cmd, stdout=None, stderr=None, timeout=None, **kw):
        stdout.write(stdout_bytes)
        r = Result()
        r.returncode = returncode
        r.stderr = kw.get("_stderr", b"")
        return r

    monkeypatch.setattr(velo, "find_binary", lambda cfg=None: "/usr/bin/velociraptor")
    monkeypatch.setattr(subprocess, "run",
                        lambda *a, **k: fake_run(*a, **dict(k, _stderr=stderr)))
    return velo


def test_results_file_is_removed_after_a_good_parse(monkeypatch, tmp_out):
    velo = _fake_collect(monkeypatch, b'[{"Name": "svchost.exe", "Pid": 4}]')
    rows = velo.run_artifact("Windows.System.Pslist", cfg={"velociraptor_output_dir": tmp_out})
    assert len(rows) == 1 and rows[0]["process_name"] == "svchost.exe"
    assert os.listdir(tmp_out) == [], "a parsed results file must not be left behind"


def test_unparseable_output_keeps_the_file_and_says_where(monkeypatch, tmp_out):
    """The bug that stored 285 unusable rows must now announce itself."""
    velo = _fake_collect(monkeypatch, b"<html>not json at all</html>")
    rows = velo.run_artifact("Windows.System.Pslist", cfg={"velociraptor_output_dir": tmp_out})
    assert len(rows) == 1 and "_error" in rows[0]
    assert "no rows could be parsed" in rows[0]["_error"]
    leftover = os.listdir(tmp_out)
    assert len(leftover) == 1, "the raw output must survive for inspection"
    assert leftover[0] in rows[0]["_error"] or tmp_out in rows[0]["_error"]


def test_empty_output_is_not_an_error(monkeypatch, tmp_out):
    """An artifact that legitimately finds nothing is not a failure."""
    velo = _fake_collect(monkeypatch, b"")
    rows = velo.run_artifact("Windows.System.Pslist", cfg={"velociraptor_output_dir": tmp_out})
    assert rows == []
    assert os.listdir(tmp_out) == []


def test_failing_exit_code_reports_stderr_not_the_data_file(monkeypatch, tmp_out):
    velo = _fake_collect(monkeypatch, b"", returncode=1, stderr=b"unknown artifact\n")
    rows = velo.run_artifact("Windows.System.Pslist", cfg={"velociraptor_output_dir": tmp_out})
    assert "unknown artifact" in rows[0]["_error"]
    assert os.listdir(tmp_out) == [], "nothing to inspect, so nothing kept"


def test_stderr_never_reaches_the_parser(monkeypatch, tmp_out):
    """Velociraptor's logging goes to stderr and must not pollute the rows."""
    velo = _fake_collect(monkeypatch, b'[{"Name": "real.exe"}]',
                         stderr=b"INFO: starting collection\nINFO: done\n")
    rows = velo.run_artifact("Windows.System.Pslist", cfg={"velociraptor_output_dir": tmp_out})
    assert len(rows) == 1 and rows[0]["process_name"] == "real.exe"


def test_normalise_row_promotes_real_world_column_names():
    """Column names taken from a live v0.77.2 sweep, not from guesswork."""
    from agent.collectors import velociraptor as velo
    task = velo.normalise_row("Windows.System.TaskScheduler", {
        "TaskName": r"\Microsoft\Windows\Defrag\ScheduledDefrag",
        "Command": r"%windir%\system32\defrag.exe", "Arguments": "-c -h -o",
        "UserId": "SYSTEM", "RunLevel": "HighestAvailable"})
    assert task["process_name"] == r"\Microsoft\Windows\Defrag\ScheduledDefrag"
    assert task["path"] == r"%windir%\system32\defrag.exe"

    pf = velo.normalise_row("Windows.Forensics.Prefetch", {
        "Executable": "CHROME.EXE", "FileSize": 28114,
        "Hash": "A1B2C3D4", "LastRunTimes": ["2026-09-23T09:23:39Z"]})
    assert pf["process_name"] == "CHROME.EXE"
    # Prefetch's "Hash" is the prefetch hash, NOT a SHA-256 - promoting it
    # would put a fake hash in front of the IOC correlator.
    assert pf["sha256"] is None


def test_timeline_does_not_let_one_source_crowd_out_the_others(client, enrolled):
    """A sweep must stay visible next to hundreds of routine persistence rows.

    Observed live: 499 persistence rows carrying the newest collection timestamp
    filled the entire window, so the investigation timeline showed nothing else.
    """
    ts = "2026-09-22T10:00:00+00:00"
    client.post("/api/v1/ingest", headers=enrolled["headers"], json={
        "manifest": {"collection_id": "flood", "hostname": "velo-win01",
                     "started_at_utc": ts, "finished_at_utc": ts,
                     "agent_version": "1.0.0", "manifest_sha256": "x"},
        "artifacts": {
            "persistence": [{"ptype": "run_key", "name": f"entry{i}",
                             "command": f"c:/tools/x{i}.exe", "location": "HKCU"}
                            for i in range(300)],
            "velociraptor": [{"artifact": "Windows.System.Pslist",
                              "row_json": '{"Name": "needle.exe"}',
                              "process_name": "needle.exe"}],
        }})
    events = client.get("/api/v1/timeline?host_id=1&limit=50").json()["events"]
    kinds = {e["kind"] for e in events}
    assert "velociraptor" in kinds, f"sweep crowded out; only saw {kinds}"
