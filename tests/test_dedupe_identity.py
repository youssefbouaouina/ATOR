"""Identity rules for de-duplicated ingestion, and for ML findings on top of it.

The DFIR ingest folds repeated agent observations into one row (merged from the DFIR-only
branch). That is right in principle; three of its identities were too coarse and merged
records that are genuinely different. Every scenario here was first reproduced through the
real /api/v1/ingest endpoint before it was fixed:

  * raw_logs keyed on (host, source, SECOND, event_id, provider): distinct events sharing a
    second collapsed - `whoami`, `net user` and `ipconfig` launched together were stored as
    one process-creation event.
  * raw_processes keyed without a start time: a new process reusing a PID with the same
    command line inherited the old instance's parent and start time.
  * ML findings keyed on (host, collection, row): the ingest moves a re-observed process
    into the newest collection, so a long-running suspicious process was reported again on
    every sweep - 1, 2, 3 detections over three sweeps.

The suite was green through all three. These tests are the reason it would not be now.
"""
import hashlib
import json
import sqlite3
import uuid

import pytest

from server import db as database


# --------------------------------------------------------------------------- helpers

@pytest.fixture()
def api(tmp_path, monkeypatch):
    """The real application against a fresh store (so the dedupe indexes exist)."""
    path = str(tmp_path / "dedupe.db")
    monkeypatch.setenv("ATOR_DFIR_DB", path)
    monkeypatch.setattr(database, "DB_PATH", path)
    database.init_db(path)
    from fastapi.testclient import TestClient
    from server.app import app
    with TestClient(app) as client:
        yield client, path


def _enroll(client, name="dedupe-host"):
    r = client.post("/api/v1/enroll", json={"hostname": name, "os_type": "windows",
                                            "docker_engine_flag": 0})
    assert r.status_code == 200, r.text
    return r.json()


def _ingest(client, host, artifacts, finished="2026-09-21T10:00:05+00:00"):
    manifest = {"collection_id": str(uuid.uuid4()), "hostname": "h", "os_type": "windows",
                "agent_version": "t", "started_at_utc": finished, "finished_at_utc": finished,
                "collector_order": list(artifacts), "artifacts": []}
    manifest["manifest_sha256"] = hashlib.sha256(
        json.dumps(manifest, sort_keys=True).encode()).hexdigest()
    r = client.post("/api/v1/ingest", json={"manifest": manifest, "artifacts": artifacts},
                    headers={"Authorization": "Bearer " + host["api_key"],
                             "X-Client-ID": host["client_id"]})
    assert r.status_code == 202, r.text


def _event(image, cmdline, pid, t="2026-09-21T10:00:00+00:00"):
    return {"source": "sysmon", "event_id": 1, "event_time_utc": t,
            "provider": "Microsoft-Windows-Sysmon", "computer": "h",
            "event_data": {"Image": image, "CommandLine": cmdline, "ProcessId": str(pid)}}


def _count(path, sql, params=()):
    conn = sqlite3.connect(path)
    try:
        return conn.execute(sql, params).fetchone()[0]
    finally:
        conn.close()


BURST = [_event(r"C:\Windows\System32\whoami.exe", "whoami", 501),
         _event(r"C:\Windows\System32\net.exe", "net user", 502),
         _event(r"C:\Windows\System32\ipconfig.exe", "ipconfig /all", 503)]


# --------------------------------------------------------------------------- raw_logs

class TestLogIdentity:
    def test_distinct_events_in_one_second_are_all_kept(self, api):
        client, path = api
        host = _enroll(client)
        _ingest(client, host, {"logs": BURST})
        assert _count(path, "SELECT COUNT(*) FROM raw_logs WHERE source='sysmon'") == 3

    def test_resent_duplicates_are_still_dropped(self, api):
        """The v1 intent must survive: the agent re-sends its recent window every sweep."""
        client, path = api
        host = _enroll(client)
        _ingest(client, host, {"logs": BURST}, "2026-09-21T10:00:05+00:00")
        _ingest(client, host, {"logs": BURST}, "2026-09-21T10:01:05+00:00")
        _ingest(client, host, {"logs": BURST}, "2026-09-21T10:02:05+00:00")
        assert _count(path, "SELECT COUNT(*) FROM raw_logs WHERE source='sysmon'") == 3

    def test_key_order_does_not_defeat_deduplication(self):
        from server.api import _payload_sha256
        a = json.dumps({"x": 1, "y": {"b": 2, "a": 3}})
        b = json.dumps({"y": {"a": 3, "b": 2}, "x": 1})
        assert _payload_sha256(a) == _payload_sha256(b)
        assert _payload_sha256(a) != _payload_sha256(json.dumps({"x": 2, "y": {"a": 3, "b": 2}}))

    def test_non_json_payload_is_hashed_verbatim(self):
        from server.api import _payload_sha256
        assert _payload_sha256("not json") == hashlib.sha256(b"not json").hexdigest()


# --------------------------------------------------------------------------- raw_processes

def _proc(**overrides):
    base = {"pid": 4242, "ppid": 700, "name": "conhost.exe",
            "cmdline": r"\??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1",
            "exe_path": r"C:\Windows\System32\conhost.exe", "sha256": None,
            "username": "user", "create_time_utc": "2026-09-21T09:00:00+00:00"}
    base.update(overrides)
    return base


class TestProcessIdentity:
    def test_reused_pid_is_a_new_process(self, api):
        client, path = api
        host = _enroll(client)
        _ingest(client, host, {"processes": [_proc()]}, "2026-09-21T09:30:00+00:00")
        _ingest(client, host, {"processes": [_proc(ppid=900,
                                                   create_time_utc="2026-09-21T11:00:00+00:00")]},
                "2026-09-21T11:00:30+00:00")
        conn = sqlite3.connect(path)
        rows = conn.execute("SELECT ppid, create_time_utc FROM raw_processes WHERE pid=4242 "
                            "ORDER BY id").fetchall()
        conn.close()
        assert rows == [(700, "2026-09-21T09:00:00+00:00"), (900, "2026-09-21T11:00:00+00:00")]

    def test_same_instance_is_still_folded_into_one_row(self, api):
        client, path = api
        host = _enroll(client)
        for minute in range(3):
            _ingest(client, host, {"processes": [_proc()]}, f"2026-09-21T09:3{minute}:00+00:00")
        assert _count(path, "SELECT COUNT(*) FROM raw_processes WHERE pid=4242") == 1
        assert _count(path, "SELECT observation_count FROM raw_processes WHERE pid=4242") == 3

    def test_agent_without_start_times_behaves_exactly_as_before(self, api):
        """NULL start time -> the v2 key reduces to v1. Older agents see no change."""
        client, path = api
        host = _enroll(client)
        for minute in range(2):
            _ingest(client, host, {"processes": [_proc(create_time_utc=None)]},
                    f"2026-09-21T09:3{minute}:00+00:00")
        assert _count(path, "SELECT COUNT(*) FROM raw_processes WHERE pid=4242") == 1


# --------------------------------------------------------------------------- index upgrade

V1_LOGS = ("CREATE UNIQUE INDEX ux_raw_logs_dedupe ON raw_logs(host_id, source,"
           " COALESCE(event_time_utc,''), COALESCE(event_id,-1), COALESCE(provider,''))")
V1_PROCS = ("CREATE UNIQUE INDEX ux_raw_processes_dedupe ON raw_processes(host_id,"
            " COALESCE(pid,-1), COALESCE(name,''), COALESCE(cmdline,''), COALESCE(exe_path,''),"
            " COALESCE(sha256,''))")


def _indexes(path):
    conn = sqlite3.connect(path)
    try:
        return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    finally:
        conn.close()


class TestIndexUpgrade:
    def test_fresh_store_gets_v2_only(self, tmp_path):
        path = str(tmp_path / "fresh.db")
        database.init_db(path)
        names = _indexes(path)
        assert {"ux_raw_logs_dedupe_v2", "ux_raw_processes_dedupe_v2"} <= names
        assert not {"ux_raw_logs_dedupe", "ux_raw_processes_dedupe"} & names

    def test_store_built_by_the_v1_release_is_upgraded_in_place(self, tmp_path):
        path = str(tmp_path / "v1.db")
        database.init_db(path)
        conn = sqlite3.connect(path)
        conn.execute("DROP INDEX ux_raw_logs_dedupe_v2")
        conn.execute("DROP INDEX ux_raw_processes_dedupe_v2")
        conn.execute(V1_LOGS)
        conn.execute(V1_PROCS)
        conn.execute("INSERT INTO hosts (client_id, hostname, os_type, api_key_hash, "
                     "enrolled_at_utc) VALUES ('c','h','windows','x','2026-01-01')")
        conn.execute("INSERT INTO raw_logs (host_id, source, event_id, event_time_utc, "
                     "collected_at_utc, payload_json) VALUES (1,'sysmon',1,'t','t','{}')")
        conn.commit()
        conn.close()

        database.init_db(path)                   # a restart on the new release

        names = _indexes(path)
        assert {"ux_raw_logs_dedupe_v2", "ux_raw_processes_dedupe_v2"} <= names
        assert not {"ux_raw_logs_dedupe", "ux_raw_processes_dedupe"} & names
        assert _count(path, "SELECT COUNT(*) FROM raw_logs") == 1      # data untouched

    def test_legacy_store_without_indexes_is_left_alone(self, tmp_path):
        """Building indexes on a large legacy store is purge_host_data.py's job, not startup's."""
        path = str(tmp_path / "legacy.db")
        database.init_db(path)
        conn = sqlite3.connect(path)
        for name in ("ux_raw_logs_dedupe_v2", "ux_raw_processes_dedupe_v2"):
            conn.execute(f"DROP INDEX {name}")
        conn.execute("INSERT INTO hosts (client_id, hostname, os_type, api_key_hash, "
                     "enrolled_at_utc) VALUES ('c','h','windows','x','2026-01-01')")
        conn.execute("INSERT INTO raw_logs (host_id, source, event_id, event_time_utc, "
                     "collected_at_utc, payload_json) VALUES (1,'sysmon',1,'t','t','{}')")
        conn.commit()
        conn.close()
        database.init_db(path)
        assert "ux_raw_logs_dedupe_v2" not in _indexes(path)

    def test_drop_dedupe_indexes_covers_current_and_superseded(self, tmp_path):
        path = str(tmp_path / "drop.db")
        database.init_db(path)
        conn = database.connect(path)
        try:
            conn.execute(V1_LOGS)
            dropped = database.drop_dedupe_indexes(conn)
        finally:
            conn.close()
        assert "ux_raw_logs_dedupe" in dropped and "ux_raw_logs_dedupe_v2" in dropped
        assert not {n for n in _indexes(path) if n.startswith("ux_raw_")}


# --------------------------------------------------------------------------- ML findings

class TestProcessKey:
    def test_pid_as_float_or_int_is_the_same_process(self):
        from server.engine.ml_integration import _process_key
        a = {"host_id": 1, "pid": 4, "name": "x.exe", "create_time_utc": "t"}
        b = {"host_id": 1.0, "pid": 4.0, "name": "x.exe", "create_time_utc": "t"}
        assert _process_key(a) == _process_key(b)

    def test_start_time_distinguishes_instances(self):
        from server.engine.ml_integration import _process_key
        a = {"host_id": 1, "pid": 4, "name": "x.exe", "create_time_utc": "t1"}
        assert _process_key(a) != _process_key(dict(a, create_time_utc="t2"))

    def test_collection_is_not_part_of_the_identity(self):
        from server.engine.ml_integration import _process_key
        a = {"host_id": 1, "pid": 4, "name": "x.exe", "collection_id": "c1"}
        assert _process_key(a) == _process_key(dict(a, collection_id="c2"))


@pytest.mark.skipif(__import__("importlib").util.find_spec("sklearn") is None,
                    reason="ML stack not installed")
class TestMlFindingsAreNotRepeated:
    def _sweep(self, client, host, path, minute):
        benign = [{"pid": 1000 + i, "ppid": 4, "name": "svchost.exe",
                   "cmdline": rf"C:\Windows\system32\svchost.exe -k netsvcs -p -s Svc{i}",
                   "exe_path": r"C:\Windows\System32\svchost.exe", "username": "SYSTEM",
                   "create_time_utc": "2026-09-21T08:00:00+00:00"} for i in range(30)]
        odd = {"pid": 6666, "ppid": 1000, "name": "rundll32.exe",
               "cmdline": r"rundll32.exe C:\Users\Public\x.dll,Start",
               "exe_path": r"C:\Users\Public\rundll32.exe", "username": "user",
               "create_time_utc": "2026-09-21T08:05:00+00:00"}
        _ingest(client, host, {"processes": benign + [odd]}, f"2026-09-21T12:0{minute}:00+00:00")
        from server.engine import ml_integration
        conn = database.connect(path)
        try:
            hits = ml_integration.run_ml_anomaly_detection(
                conn, host_ids=[host["host_id"]], top_k=1, threshold=0.0)
            return ml_integration.insert_ml_detections(conn, hits) if hits else []
        finally:
            conn.close()

    def test_one_finding_across_sweeps_with_a_hit_count(self, api):
        client, path = api
        host = _enroll(client)
        new_ids = [self._sweep(client, host, path, m) for m in range(3)]
        from server.engine import ml_registry
        if ml_registry.load_artefact("anomaly", "t1") is None:
            pytest.skip("no trained anomaly model in this checkout")
        assert [len(ids) for ids in new_ids] == [1, 0, 0], "only the first sweep is new"
        assert _count(path, "SELECT COUNT(*) FROM detections WHERE rule_type='ml_anomaly'") == 1
        assert _count(path, "SELECT hit_count FROM detections WHERE rule_type='ml_anomaly'") == 3

    def test_rescanning_does_not_inflate_the_sighting_count(self, api):
        """Found in the UI: every "Run hunt now" click re-counted old sweeps (x3, x5, ...)."""
        client, path = api
        host = _enroll(client)
        from server.engine import ml_registry
        if ml_registry.load_artefact("anomaly", "t1") is None:
            pytest.skip("no trained anomaly model in this checkout")
        self._sweep(client, host, path, 0)
        self._sweep(client, host, path, 1)       # one genuine later sighting
        from server.engine import ml_integration
        for _ in range(4):                       # four clicks, no new data
            conn = database.connect(path)
            try:
                hits = ml_integration.run_ml_anomaly_detection(
                    conn, host_ids=[host["host_id"]], top_k=1, threshold=0.0)
                ml_integration.insert_ml_detections(conn, hits)
            finally:
                conn.close()
        assert _count(path, "SELECT hit_count FROM detections WHERE rule_type='ml_anomaly'") == 2

    def test_finding_recorded_before_process_keys_is_recognised(self, api):
        """Upgrading must not open one more duplicate per process already flagged."""
        client, path = api
        host = _enroll(client)
        first = self._sweep(client, host, path, 0)
        from server.engine import ml_registry
        if not first:
            pytest.skip("no trained anomaly model in this checkout")
        conn = sqlite3.connect(path)          # strip the key, as an old release wrote it
        explanation = json.loads(conn.execute(
            "SELECT ml_explanation FROM detections WHERE id=?", (first[0],)).fetchone()[0])
        explanation.pop("process_key")
        conn.execute("UPDATE detections SET ml_explanation=? WHERE id=?",
                     (json.dumps(explanation), first[0]))
        conn.commit()
        conn.close()
        assert self._sweep(client, host, path, 1) == []
        assert _count(path, "SELECT COUNT(*) FROM detections WHERE rule_type='ml_anomaly'") == 1
