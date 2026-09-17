"""Phase 1 tests: ML schema migration, OTRF -> ATOR ETL, process-lineage labelling.

These use synthetic in-memory captures rather than the 400 MB real training database, so
they are fast, hermetic and need no network. The real corpus is exercised separately by
`ml/evaluation/audit_baseline.py`.
"""
import io
import json
import os
import sqlite3
import tempfile
import zipfile

import pytest

from ml.datasets import labels as labels_mod
from ml.datasets import otrf, otrf_etl
from server import db as database


# --------------------------------------------------------------------------- fixtures

def _sysmon_event(eid, **fields):
    """A corpus-shaped event: WEF envelope + Sysmon EventData."""
    base = {
        "EventID": eid,
        "Channel": otrf_etl.SYSMON_CHANNEL,
        "Hostname": "WS01.lab.local",
        "@timestamp": "2026-03-01T10:00:00.000Z",
        "UtcTime": "2026-03-01 10:00:00.000",
        "SourceName": "Microsoft-Windows-Sysmon",
    }
    base.update(fields)
    return base


def _make_capture(tmpdir, filename, events):
    path = os.path.join(tmpdir, filename)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(filename.replace(".zip", ".json"),
                   "\n".join(json.dumps(e) for e in events))
    with open(path, "wb") as fh:
        fh.write(buf.getvalue())
    tactic, scope, name = otrf._parse_filename(filename)
    return otrf.Capture(local_path=path, filename=filename,
                        tactic=tactic, scope=scope, name=name)


@pytest.fixture()
def corpus_dir():
    with tempfile.TemporaryDirectory() as d:
        yield d


@pytest.fixture()
def train_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.remove(path)
    yield path
    for suffix in ("", "-wal", "-shm"):
        try:
            os.remove(path + suffix)
        except OSError:
            pass


# --------------------------------------------------------------------------- migration

class TestMlMigration:
    def test_creates_tables_and_columns(self, tmp_db):
        conn = database.connect(tmp_db)
        try:
            tables = {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            assert {"ml_models", "host_risk_scores",
                    "ml_resource_rollup", "ml_drift_log"} <= tables
            cols = {r[1] for r in conn.execute("PRAGMA table_info(detections)")}
            assert {"confidence_score", "anomaly_score", "suggested_tactics",
                    "ml_model_id", "ml_explanation"} <= cols
        finally:
            conn.close()

    def test_idempotent(self, tmp_db):
        conn = database.connect(tmp_db)
        try:
            again = database.migrate(conn)
            assert again == {"tables_created": [], "columns_added": []}
            assert database.migrate(conn)["columns_added"] == []
        finally:
            conn.close()

    def test_preserves_existing_rows(self, tmp_db, seeded_host):
        """Migration must never rewrite or drop DFIR data."""
        conn = database.connect(tmp_db)
        try:
            conn.execute(
                """INSERT INTO detections (host_id, rule_type, rule_name, severity,
                                           technique_id, summary, detected_at_utc)
                   VALUES (?,'sigma','Test Rule','high','T1059','s',?)""",
                (seeded_host["host_id"], database.now_iso()))
            conn.commit()
            database.migrate(conn)
            row = conn.execute(
                "SELECT rule_type, severity, confidence_score FROM detections").fetchone()
            assert row["rule_type"] == "sigma"
            assert row["severity"] == "high"
            assert row["confidence_score"] is None      # new column, not back-filled
            assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        finally:
            conn.close()

    def test_no_source_column_added(self, tmp_db):
        """rule_type is the single column of record - a 'source' column would duplicate it."""
        conn = database.connect(tmp_db)
        try:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(detections)")}
            assert "source" not in cols
            assert "rule_type" in cols
        finally:
            conn.close()


# --------------------------------------------------------------------------- ETL mapping

class TestEtlFieldMapping:
    def test_process_create_maps_to_raw_processes(self, corpus_dir, train_db):
        cap = _make_capture(corpus_dir, "execution__host__demo.zip", [
            _sysmon_event(
                1, ProcessId="4242", ParentProcessId="1000",
                Image=r"C:\Windows\System32\whoami.exe",
                CommandLine=r'"C:\Windows\System32\whoami.exe" /priv',
                ProcessGuid="{aaa}", ParentProcessGuid="{root}",
                ParentImage=r"C:\Windows\System32\cmd.exe",
                ParentCommandLine="cmd.exe /c whoami",
                User=r"LAB\alice",
                Hashes="SHA1=DEAD,MD5=BEEF,SHA256=" + "A" * 64,
            ),
        ])
        otrf_etl.build(train_db, corpus_dir, [cap], rebuild=True, verbose=False)
        conn = database.connect(train_db)
        try:
            row = conn.execute(
                "SELECT * FROM raw_processes WHERE pid=4242").fetchone()
            assert row["ppid"] == 1000
            assert row["name"] == "whoami.exe"                  # basename(Image)
            assert row["exe_path"] == r"C:\Windows\System32\whoami.exe"
            assert row["cmdline"].endswith("/priv")
            assert row["sha256"] == "A" * 64                    # parsed out of Hashes
            assert row["username"] == r"LAB\alice"
            assert row["collection_id"] == "execution__host__demo"
            assert row["collected_at_utc"].startswith("2026-03-01T10:00:00")
        finally:
            conn.close()

    def test_network_connect_maps_to_raw_connections_with_null_status(self, corpus_dir, train_db):
        cap = _make_capture(corpus_dir, "execution__host__net.zip", [
            _sysmon_event(3, ProcessId="77", Image=r"C:\evil\bad.exe",
                          SourceIp="10.0.0.5", SourcePort="50000",
                          DestinationIp="93.184.216.34", DestinationPort="4444",
                          Protocol="tcp", ProcessGuid="{n}"),
        ])
        otrf_etl.build(train_db, corpus_dir, [cap], rebuild=True, verbose=False)
        conn = database.connect(train_db)
        try:
            row = conn.execute("SELECT * FROM raw_connections").fetchone()
            assert (row["process_name"], row["remote_port"], row["proto"]) == ("bad.exe", 4444, "tcp")
            # Sysmon carries no TCP state: must be NULL, never a fabricated category.
            assert row["status"] is None
        finally:
            conn.close()

    def test_run_key_write_becomes_persistence(self, corpus_dir, train_db):
        cap = _make_capture(corpus_dir, "persistence__host__runkey.zip", [
            _sysmon_event(
                13, ProcessId="9", Image=r"C:\Windows\System32\reg.exe",
                EventType="SetValue", ProcessGuid="{r}",
                TargetObject=r"HKU\S-1-5-21\Software\Microsoft\Windows\CurrentVersion\Run\evil",
                Details=r"C:\Temp\evil.exe"),
        ])
        otrf_etl.build(train_db, corpus_dir, [cap], rebuild=True, verbose=False)
        conn = database.connect(train_db)
        try:
            row = conn.execute("SELECT * FROM raw_persistence").fetchone()
            assert row["ptype"] == "registry_run"
            assert row["command"] == r"C:\Temp\evil.exe"
        finally:
            conn.close()

    def test_payload_shape_matches_agent(self, corpus_dir, train_db):
        """raw_logs.payload_json must use the agent's {'fields': {...}} layout."""
        cap = _make_capture(corpus_dir, "execution__host__shape.zip", [
            _sysmon_event(1, ProcessId="1", Image=r"C:\a.exe", CommandLine="a.exe",
                          ProcessGuid="{s}", IntegrityLevel="High"),
        ])
        otrf_etl.build(train_db, corpus_dir, [cap], rebuild=True, verbose=False)
        conn = database.connect(train_db)
        try:
            payload = json.loads(conn.execute(
                "SELECT payload_json FROM raw_logs WHERE event_id=1").fetchone()[0])
            assert "fields" in payload
            assert payload["fields"]["IntegrityLevel"] == "High"
            # envelope keys must not leak into EventData
            assert "Channel" not in payload["fields"]
            assert "Hostname" not in payload["fields"]
        finally:
            conn.close()

    def test_idempotent_reimport(self, corpus_dir, train_db):
        cap = _make_capture(corpus_dir, "execution__host__idem.zip", [
            _sysmon_event(1, ProcessId="5", Image=r"C:\x.exe", CommandLine="x",
                          ProcessGuid="{i}"),
        ])
        otrf_etl.build(train_db, corpus_dir, [cap], rebuild=True, verbose=False)
        otrf_etl.import_capture(
            database.connect(train_db), cap,
            otrf_etl._HostRegistry(database.connect(train_db)))
        conn = database.connect(train_db)
        try:
            # Re-importing replaces rather than duplicates.
            assert conn.execute(
                "SELECT COUNT(*) FROM raw_processes WHERE pid=5").fetchone()[0] == 1
        finally:
            conn.close()


class TestSensorProfileFidelity:
    """The corpus must be filtered through scripts/sysmon-config.xml's policy."""

    def test_conhost_process_create_is_excluded(self, corpus_dir, train_db):
        cap = _make_capture(corpus_dir, "execution__host__conhost.zip", [
            _sysmon_event(1, ProcessId="1", Image=r"C:\Windows\System32\conhost.exe",
                          CommandLine="conhost.exe", ProcessGuid="{c}"),
            _sysmon_event(1, ProcessId="2", Image=r"C:\Windows\System32\cmd.exe",
                          CommandLine="cmd.exe", ProcessGuid="{k}"),
        ])
        otrf_etl.build(train_db, corpus_dir, [cap], rebuild=True, verbose=False)
        conn = database.connect(train_db)
        try:
            names = {r[0] for r in conn.execute("SELECT name FROM raw_processes")}
            assert "conhost.exe" not in names, "sensor config excludes conhost"
            assert "cmd.exe" in names
        finally:
            conn.close()

    def test_system32_image_loads_are_excluded(self, corpus_dir, train_db):
        cap = _make_capture(corpus_dir, "execution__host__imgload.zip", [
            _sysmon_event(7, ProcessId="1", Image=r"C:\app.exe", ProcessGuid="{a}",
                          ImageLoaded=r"C:\Windows\System32\kernel32.dll"),
            _sysmon_event(7, ProcessId="1", Image=r"C:\app.exe", ProcessGuid="{a}",
                          ImageLoaded=r"C:\Temp\evil.dll"),
        ])
        otrf_etl.build(train_db, corpus_dir, [cap], rebuild=True, verbose=False)
        conn = database.connect(train_db)
        try:
            loaded = [json.loads(r[0])["fields"].get("ImageLoaded")
                      for r in conn.execute(
                          "SELECT payload_json FROM raw_logs WHERE event_id=7")]
            assert r"C:\Temp\evil.dll" in loaded
            assert not any(str(p).startswith(r"C:\Windows\System32") for p in loaded)
        finally:
            conn.close()

    def test_events_outside_ator_profile_are_quarantined(self, corpus_dir, train_db):
        """EID 10 is not in scripts/sysmon-config.xml, so it must not be source='sysmon'."""
        cap = _make_capture(corpus_dir, "credential_access__host__pa.zip", [
            _sysmon_event(10, SourceProcessId="1", SourceImage=r"C:\evil.exe",
                          TargetImage=r"C:\Windows\System32\lsass.exe",
                          GrantedAccess="0x1410", SourceProcessGUID="{s}"),
        ])
        otrf_etl.build(train_db, corpus_dir, [cap], rebuild=True, verbose=False)
        conn = database.connect(train_db)
        try:
            src = conn.execute(
                "SELECT source FROM raw_logs WHERE event_id=10").fetchone()[0]
            assert src == otrf_etl.SOURCE_SYSMON_EXTENDED
            assert conn.execute(
                "SELECT COUNT(*) FROM raw_logs WHERE source='sysmon' AND event_id=10"
            ).fetchone()[0] == 0
        finally:
            conn.close()

    def test_process_access_to_non_sensitive_target_is_dropped(self, corpus_dir, train_db):
        cap = _make_capture(corpus_dir, "credential_access__host__pa2.zip", [
            _sysmon_event(10, SourceProcessId="1", SourceImage=r"C:\a.exe",
                          TargetImage=r"C:\Windows\System32\notepad.exe",
                          GrantedAccess="0x1000", SourceProcessGUID="{x}"),
        ])
        otrf_etl.build(train_db, corpus_dir, [cap], rebuild=True, verbose=False)
        conn = database.connect(train_db)
        try:
            assert conn.execute(
                "SELECT COUNT(*) FROM raw_logs WHERE event_id=10").fetchone()[0] == 0
        finally:
            conn.close()


class TestParentReconstruction:
    def test_missing_parent_is_reconstructed(self, corpus_dir, train_db):
        """The Empire case: the attacker is only visible as ParentCommandLine."""
        cap = _make_capture(corpus_dir, "credential_access__host__empire_demo.zip", [
            _sysmon_event(
                1, ProcessId="6504", ParentProcessId="1648",
                Image=r"C:\Windows\System32\whoami.exe",
                CommandLine=r'"C:\Windows\System32\whoami.exe" /user',
                ProcessGuid="{child}", ParentProcessGuid="{agent}",
                ParentImage=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                ParentCommandLine=('"powershell.exe" -noP -sta -w 1 -enc '
                                   + "S" * 60),
            ),
        ])
        otrf_etl.build(train_db, corpus_dir, [cap], rebuild=True, verbose=False)
        conn = database.connect(train_db)
        try:
            agent = conn.execute(
                "SELECT * FROM corpus_lineage WHERE process_guid='{agent}'").fetchone()
            assert agent is not None, "parent must be reconstructed"
            assert agent["is_reconstructed"] == 1
            assert agent["pid"] == 1648, "parent pid comes from the child's ParentProcessId"
            assert "powershell.exe" in agent["image"].lower()
            # It is a real running process, so psutil would see it -> raw_processes too.
            assert conn.execute(
                "SELECT COUNT(*) FROM raw_processes WHERE pid=1648").fetchone()[0] == 1
        finally:
            conn.close()

    def test_present_parent_is_not_duplicated(self, corpus_dir, train_db):
        cap = _make_capture(corpus_dir, "execution__host__pair.zip", [
            _sysmon_event(1, ProcessId="100", Image=r"C:\Windows\System32\cmd.exe",
                          CommandLine="cmd", ProcessGuid="{p}", ParentProcessGuid="{gp}"),
            _sysmon_event(1, ProcessId="101", Image=r"C:\Windows\System32\ping.exe",
                          CommandLine="ping", ProcessGuid="{c}", ParentProcessGuid="{p}",
                          ParentProcessId="100",
                          ParentImage=r"C:\Windows\System32\cmd.exe",
                          ParentCommandLine="cmd"),
        ])
        otrf_etl.build(train_db, corpus_dir, [cap], rebuild=True, verbose=False)
        conn = database.connect(train_db)
        try:
            rows = conn.execute(
                "SELECT process_guid, is_reconstructed FROM corpus_lineage").fetchall()
            flags = {r["process_guid"]: r["is_reconstructed"] for r in rows}
            assert flags["{p}"] == 0, "parent has its own EID 1; must not be reconstructed"
            assert flags["{c}"] == 0
        finally:
            conn.close()


# --------------------------------------------------------------------------- labelling

class TestLineageLabelling:
    def _labelled(self, corpus_dir, train_db, filename, events):
        cap = _make_capture(corpus_dir, filename, events)
        otrf_etl.build(train_db, corpus_dir, [cap], rebuild=True, verbose=False)
        result = labels_mod.label_all(train_db, verbose=False)
        conn = database.connect(train_db)
        try:
            rows = {r["process_guid"]: dict(r)
                    for r in conn.execute("SELECT * FROM corpus_labels")}
        finally:
            conn.close()
        return result, rows

    def test_seed_and_descendants_labelled_malicious(self, corpus_dir, train_db):
        """A 3-level chain, so inheritance is isolated from direct matching.

        `{kid}` matches directly (its ParentCommandLine is the mimikatz line, which is a seed
        signature), so it lands at depth 0. `{grandkid}` matches nothing itself and its own
        parent line is innocuous - it can only be malicious by inheritance.
        """
        events = [
            _sysmon_event(1, ProcessId="10", Image=r"C:\Temp\mimikatz.exe",
                          CommandLine="mimikatz.exe sekurlsa::logonpasswords",
                          ProcessGuid="{seed}", ParentProcessGuid="{none}"),
            _sysmon_event(1, ProcessId="11", Image=r"C:\Windows\System32\cmd.exe",
                          CommandLine="cmd.exe /c whoami",
                          ProcessGuid="{kid}", ParentProcessGuid="{seed}",
                          ParentProcessId="10",
                          ParentImage=r"C:\Temp\mimikatz.exe",
                          ParentCommandLine="mimikatz.exe sekurlsa::logonpasswords"),
            _sysmon_event(1, ProcessId="12", Image=r"C:\Windows\System32\whoami.exe",
                          CommandLine="whoami /priv",
                          ProcessGuid="{grandkid}", ParentProcessGuid="{kid}",
                          ParentProcessId="11",
                          ParentImage=r"C:\Windows\System32\cmd.exe",
                          ParentCommandLine="cmd.exe /c whoami"),
            _sysmon_event(1, ProcessId="13", Image=r"C:\Windows\System32\notepad.exe",
                          CommandLine="notepad.exe",
                          ProcessGuid="{unrelated}", ParentProcessGuid="{other}"),
        ]
        _, rows = self._labelled(
            corpus_dir, train_db, "credential_access__host__mimikatz_demo.zip", events)
        assert rows["{seed}"]["label"] == "malicious"
        assert rows["{seed}"]["depth"] == 0
        assert rows["{kid}"]["label"] == "malicious"
        # Inherited purely through lineage - nothing about it matches a signature.
        assert rows["{grandkid}"]["label"] == "malicious", "descendant inherits the label"
        assert rows["{grandkid}"]["depth"] >= 1
        assert rows["{grandkid}"]["seed_rule"] == rows["{kid}"]["seed_rule"]
        # The crucial half: unrelated background in the SAME capture stays benign.
        assert rows["{unrelated}"]["label"] == "benign"

    def test_benign_background_is_the_majority_control(self, corpus_dir, train_db):
        events = [_sysmon_event(
            1, ProcessId=str(100 + i), Image=rf"C:\Windows\System32\svc{i}.exe",
            CommandLine=f"svc{i}.exe", ProcessGuid=f"{{b{i}}}",
            ParentProcessGuid="{root}") for i in range(8)]
        events.append(_sysmon_event(
            1, ProcessId="200", Image=r"C:\Temp\mimikatz.exe",
            CommandLine="mimikatz.exe lsadump::sam", ProcessGuid="{bad}",
            ParentProcessGuid="{root2}"))
        result, rows = self._labelled(
            corpus_dir, train_db, "credential_access__host__mimikatz_bg.zip", events)
        assert result["totals"]["malicious"] == 1
        assert result["totals"]["benign"] >= 8

    def test_system_processes_never_seed(self, corpus_dir, train_db):
        """A denylisted root must not seed, or propagation swallows the host."""
        for name in ("services.exe", "svchost.exe", "explorer.exe"):
            assert labels_mod._is_seed(
                rf"C:\Windows\System32\{name}",
                "anything -enc " + "A" * 60,
                labels_mod.signatures_for("credential_access__host__empire_x"),
            ) is None, name

    def test_depth_cap_bounds_propagation(self):
        assert labels_mod.MAX_DEPTH <= 8, "an unbounded cap lets one bad seed label a host"

    def test_parent_signature_seeds_child(self, corpus_dir, train_db):
        """Covers the case where the parent cannot be reconstructed but is clearly hostile."""
        sigs = labels_mod.signatures_for("credential_access__host__empire_x")
        rule = labels_mod._is_child_of_seed(
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            '"powershell.exe" -noP -sta -w 1 -enc ' + "Q" * 60, sigs)
        assert rule is not None

    def test_seed_audit_is_reported(self, corpus_dir, train_db):
        events = [_sysmon_event(1, ProcessId="1", Image=r"C:\Temp\mimikatz.exe",
                                CommandLine="mimikatz sekurlsa::logonpasswords",
                                ProcessGuid="{a}", ParentProcessGuid="{z}")]
        result, _ = self._labelled(
            corpus_dir, train_db, "credential_access__host__mimikatz_audit.zip", events)
        # Weak labels are only defensible if they are auditable.
        assert result["malicious_by_seed_rule"]
        assert "positive_rate" in result
        assert "malicious_by_propagation_depth" in result


class TestLabelSideChannelDiscipline:
    """Labels may use ProcessGuid; FEATURES may not. This guards that boundary."""

    def test_production_schema_has_no_process_guid(self, tmp_db):
        """Any feature reading ProcessGuid would be uncomputable on live data."""
        conn = database.connect(tmp_db)
        try:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(raw_processes)")}
            assert "process_guid" not in cols
            assert "parent_process_guid" not in cols
        finally:
            conn.close()

    def test_lineage_tables_are_training_only(self, corpus_dir, train_db, tmp_db):
        """corpus_lineage / corpus_labels must exist only in the training database."""
        prod = {r[0] for r in database.connect(tmp_db).execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        assert "corpus_lineage" not in prod
        assert "corpus_labels" not in prod


class TestCorpusManifest:
    def test_av_blocked_file_does_not_break_hashing(self, corpus_dir):
        """Defender blocks some archives; a manifest must degrade, not crash."""
        path = os.path.join(corpus_dir, "x.zip")
        with open(path, "wb") as fh:
            fh.write(b"PK\x03\x04dummy")
        assert otrf.sha256_file(path) is not None
        assert otrf.is_av_blocked(path) is False
        assert otrf.sha256_file(os.path.join(corpus_dir, "missing.zip")) is None

    def test_filename_round_trip(self):
        repo_path = ("datasets/atomic/windows/credential_access/host/"
                     "empire_mimikatz_logonpasswords.zip")
        flat = otrf._flatten(repo_path)
        assert flat == "credential_access__host__empire_mimikatz_logonpasswords.zip"
        assert otrf._parse_filename(flat) == (
            "credential_access", "host", "empire_mimikatz_logonpasswords")


class TestTimestampNormalisation:
    @pytest.mark.parametrize("raw,expect_prefix", [
        ("2020-08-07 14:32:45.881", "2020-08-07T14:32:45.881"),
        ("2020-08-07T14:32:25.358Z", "2020-08-07T14:32:25.358"),
        ("2020-08-07 14:32:25", "2020-08-07T14:32:25"),
    ])
    def test_shapes(self, raw, expect_prefix):
        out = otrf_etl._norm_ts(raw)
        assert out.startswith(expect_prefix)
        assert out.endswith("+00:00")

    def test_falls_through_to_next_candidate(self):
        assert otrf_etl._norm_ts(None, "", "2026-01-02 03:04:05").startswith("2026-01-02")

    def test_all_unparseable_returns_none(self):
        assert otrf_etl._norm_ts(None, "not a date") is None


class TestHashParsing:
    def test_extracts_sha256(self):
        parsed = otrf_etl._parse_hashes("SHA1=AA,MD5=BB,SHA256=CC,IMPHASH=DD")
        assert parsed["SHA256"] == "CC"

    def test_tolerates_missing_and_garbage(self):
        assert otrf_etl._parse_hashes(None) == {}
        assert otrf_etl._parse_hashes("garbage") == {}
        assert otrf_etl._parse_hashes("sha256=lower")["SHA256"] == "lower"
