"""Phase 10: what data the weekly pipeline admits to training, and what it refuses.

Automated retraining on live telemetry is a poisoning channel (docs/ML_MLOPS_PLAN.md 4.4):
an intrusion folded into next week's "benign" baseline teaches the model it is normal. These
tests pin every exclusion rule, and that the live database is only ever read.
"""
import hashlib
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from ml.mlops import config, data
from server import db as database

NOW = datetime(2026, 9, 27, 3, 0, tzinfo=timezone.utc)


def _iso(days_ago=0.0, hours=0.0):
    return (NOW - timedelta(days=days_ago, hours=hours)).isoformat(timespec="seconds")


@pytest.fixture()
def live(tmp_db, seeded_host):
    """A live DB with one real host and a demo host."""
    conn = database.connect(tmp_db)
    demo = conn.execute(
        """INSERT INTO hosts (client_id, hostname, os_type, api_key_hash, enrolled_at_utc)
           VALUES ('demo-x', 'DEMO', 'windows', 'h', ?)""", (_iso(30),)).lastrowid
    conn.commit()
    conn.close()
    return {"db": tmp_db, "host": seeded_host["host_id"], "demo": demo}


def _proc(conn, host, pid, name, days_ago, ppid=None, create=None):
    return conn.execute(
        """INSERT INTO raw_processes (host_id, collection_id, collected_at_utc, pid, ppid, name,
                                      cmdline, create_time_utc)
           VALUES (?,?,?,?,?,?,?,?)""",
        (host, f"c-{days_ago}", _iso(days_ago), pid, ppid, name, f"{name} /x", create)).lastrowid


def _detection(conn, host, rule_type, pid, name, days_ago, severity="medium", raw_id=None):
    return conn.execute(
        """INSERT INTO detections (host_id, collection_id, rule_type, rule_name, severity,
                                    summary, detected_at_utc, ml_explanation)
           VALUES (?,?,?,?,?,?,?,?)""",
        (host, "c", rule_type, "r", severity, json.dumps({"pid": str(pid), "name": name}),
         _iso(days_ago), json.dumps({"raw_process_id": raw_id}) if raw_id else None)).lastrowid


def _exclusions(db, policy=None):
    result = data.write_training_exclusions(db, policy or config.Policy(), NOW)
    conn = sqlite3.connect(db)
    reasons = dict(conn.execute("SELECT raw_process_id, reason FROM ml_training_exclusions"))
    conn.close()
    return result, reasons


class TestExclusions:
    def test_recent_rows_wait_out_the_cooling_off_window(self, live):
        conn = database.connect(live["db"])
        old = _proc(conn, live["host"], 10, "notepad.exe", days_ago=20)
        new = _proc(conn, live["host"], 11, "notepad.exe", days_ago=2)
        conn.commit()
        conn.close()
        _, reasons = _exclusions(live["db"])
        assert old not in reasons
        assert reasons[new] == "cooling_off"

    def test_detected_process_and_its_children_are_excluded(self, live):
        conn = database.connect(live["db"])
        parent = _proc(conn, live["host"], 100, "powershell.exe", 20, create="2026-09-01T10:00:00")
        child = _proc(conn, live["host"], 101, "whoami.exe", 20, ppid=100,
                      create="2026-09-01T10:00:05")
        grandchild = _proc(conn, live["host"], 102, "cmd.exe", 20, ppid=101)
        unrelated = _proc(conn, live["host"], 200, "notepad.exe", 20)
        _detection(conn, live["host"], "sigma", 100, "powershell.exe", 20)
        conn.commit()
        conn.close()
        _, reasons = _exclusions(live["db"])
        assert reasons[parent] == "detected"
        assert reasons[child] == "descendant"
        assert reasons[grandchild] == "descendant"
        assert unrelated not in reasons

    def test_reused_pid_started_before_the_parent_is_not_a_child(self, live):
        conn = database.connect(live["db"])
        _proc(conn, live["host"], 100, "powershell.exe", 20, create="2026-09-01T10:00:00")
        older = _proc(conn, live["host"], 150, "svc.exe", 20, ppid=100,
                      create="2026-08-01T00:00:00")
        _detection(conn, live["host"], "yara", 100, "powershell.exe", 20)
        conn.commit()
        conn.close()
        _, reasons = _exclusions(live["db"])
        assert older not in reasons

    def test_unreviewed_ml_lead_on_an_os_root_does_not_cascade(self, live):
        """An ML lead on System (pid 4) must not exclude the whole OS tree."""
        conn = database.connect(live["db"])
        system = _proc(conn, live["host"], 4, "System", 20)
        smss = _proc(conn, live["host"], 300, "smss.exe", 20, ppid=4)
        _detection(conn, live["host"], "ml_anomaly", 4, "System", 20)
        conn.commit()
        conn.close()
        _, reasons = _exclusions(live["db"])
        assert reasons[system] == "detected"
        assert smss not in reasons

    def test_unreviewed_ml_leads_follow_the_triage_likelihood(self, live):
        """Excluding every ML lead doubled next week's alerts (measured, Phase 10): the model's
        own false positives vanish from "normal". Only likely-malicious leads stay out."""
        conn = database.connect(live["db"])
        low = _proc(conn, live["host"], 810, "backup.exe", 20)
        high = _proc(conn, live["host"], 811, "rundll32.exe", 20)
        unscored = _proc(conn, live["host"], 812, "odd.exe", 20)
        for pid, name, row, conf in ((810, "backup.exe", low, 0.03),
                                     (811, "rundll32.exe", high, 0.85),
                                     (812, "odd.exe", unscored, None)):
            det = _detection(conn, live["host"], "ml_anomaly", pid, name, 20, raw_id=row)
            conn.execute("UPDATE detections SET confidence_score=? WHERE id=?", (conf, det))
        conn.commit()
        conn.close()
        result, reasons = _exclusions(live["db"])
        assert low not in reasons
        assert reasons[high] == "detected" and reasons[unscored] == "detected"
        assert result["low_likelihood_leads_kept"] == 1

    def test_a_rule_hit_overrides_a_low_likelihood(self, live):
        conn = database.connect(live["db"])
        row = _proc(conn, live["host"], 820, "tool.exe", 20)
        det = _detection(conn, live["host"], "ml_anomaly", 820, "tool.exe", 20, raw_id=row)
        conn.execute("UPDATE detections SET confidence_score=0.01 WHERE id=?", (det,))
        _detection(conn, live["host"], "yara", 820, "tool.exe", 20)
        conn.commit()
        conn.close()
        _, reasons = _exclusions(live["db"])
        assert reasons[row] == "detected"

    def test_rows_near_a_serious_incident_are_excluded(self, live):
        conn = database.connect(live["db"])
        near = _proc(conn, live["host"], 400, "rundll32.exe", 20)
        far = _proc(conn, live["host"], 401, "rundll32.exe", 40)
        _detection(conn, live["host"], "sigma", 999, "evil.exe", 20, severity="critical")
        conn.commit()
        conn.close()
        _, reasons = _exclusions(live["db"], config.Policy(local_window_days=365))
        assert reasons[near] == "incident_window"
        assert far not in reasons

    def test_dismissed_ml_lead_rejoins_the_baseline(self, live):
        conn = database.connect(live["db"])
        row = _proc(conn, live["host"], 500, "backup.exe", 20)
        det = _detection(conn, live["host"], "ml_anomaly", 500, "backup.exe", 20, raw_id=row)
        conn.execute("INSERT INTO ml_feedback (detection_id, verdict, recorded_at_utc) "
                     "VALUES (?, 'benign', ?)", (det, _iso(19)))
        conn.commit()
        conn.close()
        result, reasons = _exclusions(live["db"])
        assert row not in reasons
        assert result["feedback_readmitted"] == [row]

    def test_dismissal_cannot_override_a_rule_hit(self, live):
        """Forged or mistaken feedback must not launder a process a rule caught."""
        conn = database.connect(live["db"])
        row = _proc(conn, live["host"], 600, "implant.exe", 20)
        det = _detection(conn, live["host"], "ml_anomaly", 600, "implant.exe", 20, raw_id=row)
        _detection(conn, live["host"], "ioc", 600, "implant.exe", 20)
        conn.execute("INSERT INTO ml_feedback (detection_id, verdict, recorded_at_utc) "
                     "VALUES (?, 'benign', ?)", (det, _iso(19)))
        conn.commit()
        conn.close()
        _, reasons = _exclusions(live["db"])
        assert reasons[row] == "detected"

    def test_feedback_readmission_is_capped(self, live):
        conn = database.connect(live["db"])
        for i in range(5):
            row = _proc(conn, live["host"], 700 + i, f"tool{i}.exe", 20)
            det = _detection(conn, live["host"], "ml_anomaly", 700 + i, f"tool{i}.exe", 20,
                             raw_id=row)
            conn.execute("INSERT INTO ml_feedback (detection_id, verdict, recorded_at_utc) "
                         "VALUES (?, 'benign', ?)", (det, _iso(19)))
        conn.commit()
        conn.close()
        result, reasons = _exclusions(live["db"], config.Policy(max_feedback_readmissions=2))
        assert len(result["feedback_readmitted"]) == 2
        assert list(reasons.values()).count("feedback_cap") == 3

    def test_window_and_row_cap(self, live):
        conn = database.connect(live["db"])
        ancient = _proc(conn, live["host"], 800, "a.exe", 200)
        rows = [_proc(conn, live["host"], 900 + i, "b.exe", 10 + i) for i in range(5)]
        conn.commit()
        conn.close()
        _, reasons = _exclusions(live["db"], config.Policy(max_local_rows=3))
        assert reasons[ancient] == "outside_window"
        assert [reasons.get(r) for r in rows] == [None, None, None, "row_cap", "row_cap"]

    def test_demo_hosts_are_not_considered(self, live):
        conn = database.connect(live["db"])
        _proc(conn, live["demo"], 1, "mimikatz.exe", 20)
        conn.commit()
        conn.close()
        result, _ = _exclusions(live["db"])
        assert result["local_rows"] == 0

    def test_assemble_drops_excluded_rows(self, live, tmp_path):
        """The exclusions reach training: assemble.load honours the snapshot's table."""
        from ml.datasets import assemble as A
        conn = database.connect(live["db"])
        keep = _proc(conn, live["host"], 10, "notepad.exe", 20)
        drop = _proc(conn, live["host"], 11, "notepad.exe", 2)
        conn.commit()
        conn.close()
        _exclusions(live["db"])
        empty_train = str(tmp_path / "train.db")
        database.init_db(empty_train)
        dataset = A.load(empty_train, live["db"], include_local=True)
        assert set(dataset.frame["id"]) == {keep}
        assert dataset.meta["local_rows_excluded_by_reason"] == {"cooling_off": 1}
        assert drop not in set(dataset.frame["id"])

    def test_local_fingerprint_changes_only_with_admitted_rows(self, live):
        conn = database.connect(live["db"])
        _proc(conn, live["host"], 10, "notepad.exe", 20)
        conn.commit()
        first, _ = _exclusions(live["db"])
        _proc(conn, live["host"], 11, "notepad.exe", 1)      # cooling off: not admitted
        conn.commit()
        second, _ = _exclusions(live["db"])
        _proc(conn, live["host"], 12, "calc.exe", 15)
        conn.commit()
        conn.close()
        third, _ = _exclusions(live["db"])
        assert first["local_fingerprint"] == second["local_fingerprint"]
        assert third["local_fingerprint"] != second["local_fingerprint"]


class TestSnapshot:
    def test_snapshot_is_consistent_and_live_is_untouched(self, live, tmp_path):
        conn = database.connect(live["db"])
        _proc(conn, live["host"], 10, "notepad.exe", 20)
        conn.commit()
        conn.close()
        before = hashlib.sha256(open(live["db"], "rb").read()).hexdigest()
        result = data.snapshot_live_db(live["db"], str(tmp_path / "snap.db"))
        assert result["quick_check"] == "ok" and result["raw_processes"] == 1
        data.write_training_exclusions(str(tmp_path / "snap.db"), config.Policy(), NOW)
        assert hashlib.sha256(open(live["db"], "rb").read()).hexdigest() == before
        tables = {r[0] for r in sqlite3.connect(live["db"]).execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        assert "ml_training_exclusions" not in tables

    def test_missing_live_db_is_an_error(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            data.snapshot_live_db(str(tmp_path / "nope.db"), str(tmp_path / "snap.db"))


class TestAdmission:
    @pytest.fixture()
    def corpus(self, tmp_path, monkeypatch):
        corpus = tmp_path / "otrf"
        corpus.mkdir()
        monkeypatch.setenv("ATOR_OTRF_DIR", str(corpus))
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setattr(data, "APPROVED_BASELINE", str(tmp_path / "baseline.json"))
        return corpus, home, tmp_path / "baseline.json"

    def test_only_approved_unchanged_captures_are_admitted(self, corpus):
        corpus_dir, home, baseline = corpus
        for name, content in (("execution__host__a.zip", b"A"), ("execution__host__b.zip", b"B"),
                              ("execution__host__new.zip", b"N")):
            (corpus_dir / name).write_bytes(content)
        baseline.write_text(json.dumps({"captures": {
            "execution__host__a.zip": hashlib.sha256(b"A").hexdigest(),
            "execution__host__b.zip": hashlib.sha256(b"old content").hexdigest()}}))
        result = data.admit_captures(str(home))
        assert [c.filename for c in result["admitted"]] == ["execution__host__a.zip"]
        assert [p["capture"] for p in result["pending"]] == ["execution__host__new.zip"]
        assert [c["capture"] for c in result["changed"]] == ["execution__host__b.zip"]

    def test_approval_pins_current_content(self, corpus):
        corpus_dir, home, baseline = corpus
        baseline.write_text(json.dumps({"captures": {}}))
        (corpus_dir / "execution__host__new.zip").write_bytes(b"N")
        assert data.approve(str(home), ["execution__host__new.zip"])["approved"]
        assert [c.filename for c in data.admit_captures(str(home))["admitted"]] == \
            ["execution__host__new.zip"]
        (corpus_dir / "execution__host__new.zip").write_bytes(b"tampered")
        assert data.admit_captures(str(home))["changed"]

    def test_shipped_baseline_pins_every_capture(self):
        with open(data.APPROVED_BASELINE, encoding="utf-8") as fh:
            captures = json.load(fh)["captures"]
        assert len(captures) >= 100
        assert all(isinstance(v, str) and len(v) == 64 for v in captures.values())


class TestValidation:
    STATS = {"captures": 100, "processes": 20000, "malicious": 200, "benign": 19800,
             "malicious_by_tactic": {"execution": 50, "persistence": 12, "discovery": 3}}

    def _failed(self, stats, previous=None, expected=100):
        return [c["check"] for c in data.validate_training_db(
            stats, previous, expected, config.Policy()) if not c["ok"]]

    def test_healthy_rebuild_passes(self):
        assert self._failed(self.STATS, self.STATS) == []

    def test_lost_attack_labels_block_training(self):
        broken = dict(self.STATS, malicious=150)
        assert "attacks_not_lost" in self._failed(broken, self.STATS)

    def test_learnable_tactic_class_lost_blocks_training(self):
        broken = dict(self.STATS, malicious_by_tactic={"execution": 50, "persistence": 4})
        assert "tactic_classes_kept" in self._failed(broken, self.STATS)

    def test_empty_database_blocks_training(self):
        assert "has_processes" in self._failed(dict(self.STATS, processes=0, malicious=0))


class TestFingerprints:
    def test_code_hash_ignores_line_endings(self, tmp_path, monkeypatch):
        monkeypatch.setattr(config, "PROJECT_ROOT", str(tmp_path))
        (tmp_path / "a.py").write_bytes(b"x = 1\r\ny = 2\r\n")
        crlf = data.code_hash(["a.py"])
        (tmp_path / "a.py").write_bytes(b"x = 1\ny = 2\n")
        assert data.code_hash(["a.py"]) == crlf
        (tmp_path / "a.py").write_bytes(b"x = 2\ny = 2\n")
        assert data.code_hash(["a.py"]) != crlf

    def test_only_the_anomaly_fingerprint_depends_on_live_rows(self):
        policy = config.Policy()
        for component, depends in (("anomaly", True), ("triage", False), ("tactic", False)):
            a = data.component_fingerprint(component, corpus="c", local="L1", policy=policy)
            b = data.component_fingerprint(component, corpus="c", local="L2", policy=policy)
            assert (a != b) is depends


def test_policy_overrides_reject_unknown_keys(tmp_path):
    (tmp_path / "config.json").write_text(json.dumps({"cooling_off_days": 3}))
    assert config.load_policy(str(tmp_path)).cooling_off_days == 3
    (tmp_path / "config.json").write_text(json.dumps({"cooling_of_days": 3}))
    with pytest.raises(ValueError):
        config.load_policy(str(tmp_path))


class TestDriftReference:
    def _fill(self, db, host, n_old, n_new):
        conn = database.connect(db)
        for i in range(n_old):
            _proc(conn, host, 5000 + i, "svchost.exe", 20)
        for i in range(n_new):
            _proc(conn, host, 9000 + i, "chrome.exe", 1)
        conn.commit()
        conn.close()

    def test_estate_history_is_the_reference_when_there_is_enough(self, live):
        from ml.mlops import monitor
        self._fill(live["db"], live["host"], 30, 20)
        data.write_training_exclusions(live["db"], config.Policy(), NOW)
        conn = database.connect(live["db"])
        result = monitor.drift("unused.db", live["db"], _iso(7), conn, min_local_rows=20)
        conn.close()
        assert result["reference"] == "local"
        assert result["reference_rows"] == 30 and result["live_rows"] == 20
        assert result["counts"]["shifted"] > 0          # svchost history vs chrome this week
