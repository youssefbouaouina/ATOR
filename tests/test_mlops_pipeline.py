"""Phase 10: the weekly orchestration and its invariants (docs/ML_MLOPS_PLAN.md section 6).

The expensive stages (upstream fetch, corpus ETL, the real trainers) are replaced by small
deterministic stand-ins, so these tests exercise what only the orchestrator decides: order,
cadence, isolation of failures, trial lifecycle, promotion, rollback, pause and freeze. The
real stages are covered by their own tests and by the end-to-end run recorded in
docs/ML_PROGRESS.md.
"""
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone

import joblib
import numpy as np
import pytest

from ml.mlops import config, data, evaluate, monitor, pipeline, store, train
from server import db as database
from server.engine import ml_anomaly, ml_features as mlf, ml_registry

T0 = datetime(2026, 9, 27, 3, 0, tzinfo=timezone.utc)
WEEK = timedelta(days=7)


def _models_digest(models_dir) -> dict:
    out = {}
    for name in sorted(os.listdir(models_dir)):
        path = os.path.join(models_dir, name)
        if os.path.isfile(path):
            out[name] = hashlib.sha256(open(path, "rb").read()).hexdigest()
    return out


@pytest.fixture()
def stack(tmp_path, tmp_db, seeded_host, monkeypatch):
    models = tmp_path / "models"
    models.mkdir()
    home = tmp_path / "home"
    monkeypatch.setattr(ml_registry, "MODELS_DIR", str(models))
    monkeypatch.setenv("ATOR_MLOPS_HOME", str(home))
    monkeypatch.setenv("ATOR_DFIR_DB", tmp_db)
    monkeypatch.setenv("ATOR_ML_TRAIN_DB", str(tmp_path / "train.db"))
    monkeypatch.setenv("ATOR_OTRF_DIR", str(tmp_path / "otrf"))
    monkeypatch.setattr(config, "COMPONENTS", ("anomaly",))
    ml_registry.clear_cache()

    conn = database.connect(tmp_db)
    rng = np.random.default_rng(5)
    for i in range(80):
        conn.execute("""INSERT INTO raw_processes (host_id, collection_id, collected_at_utc,
                            pid, ppid, name, cmdline, exe_path) VALUES (?,?,?,?,?,?,?,?)""",
                     (seeded_host["host_id"], "c1", "2026-09-01T10:00:00+00:00", 1000 + i, 4,
                      "svchost.exe", f"svchost.exe -k S{i % 5}",
                      r"C:\Windows\System32\svchost.exe"))
    for i in range(6):
        blob = "".join(rng.choice(list("ABCDEFabcdef0123456789+/"), size=150))
        conn.execute("""INSERT INTO raw_processes (host_id, collection_id, collected_at_utc,
                            pid, ppid, name, cmdline, exe_path) VALUES (?,?,?,?,?,?,?,?)""",
                     (seeded_host["host_id"], "c1", "2026-09-01T10:00:00+00:00", 2000 + i, 4,
                      "evil.exe", f"powershell -enc {blob}", rf"C:\Temp\e{i}.exe"))
    conn.commit()
    frame = mlf.extract_process_frame(conn)
    conn.close()
    benign = frame[frame["name"] == "svchost.exe"].reset_index(drop=True)
    attacks = frame[frame["name"] == "evil.exe"].reset_index(drop=True)

    def artefact(seed, **extra):
        stats = mlf.fit_stats(benign)
        X = mlf.transform(benign, stats=stats, tier=mlf.TIER_T1)
        model = ml_anomaly.AnomalyModel(n_estimators=50, seed=seed).fit(X)
        return {"kind": "anomaly", "payload": model.to_payload(),
                "feature_stats": stats.to_dict(),
                "feature_spec_sha256": mlf.feature_spec_sha256(),
                "metrics": {"pr_auc": 0.55}, "trained_at_utc": f"seed-{seed}", **extra}

    for tier in ("t1", "t2"):
        joblib.dump(artefact(1), str(models / f"anomaly_{tier}.joblib"))    # the legacy champion

    state = {"seed": 10, "report_t1": 0.56, "train_ok": True}

    def fake_trainer(component, *, out_dir, report_path, log_path, **_):
        os.makedirs(out_dir, exist_ok=True)
        for tier in ("t1", "t2"):
            joblib.dump(artefact(state["seed"]), os.path.join(out_dir, f"anomaly_{tier}.joblib"))
        with open(report_path, "w") as fh:
            json.dump({"results": {
                "anomaly_iforest_t1": {"metrics": {"pr_auc": state["report_t1"]}},
                "anomaly_iforest_t2": {"metrics": {"pr_auc": 0.56}},
                "baseline:sigma_rules": {"metrics": {"pr_auc": 0.28}},
                "baseline:best_single_feature": {"metrics": {"pr_auc": 0.32}}}}, fh)
        open(log_path, "w").close()
        return {"component": component, "ok": state["train_ok"], "returncode": 0,
                "seconds": 0.1, "log": log_path, "report": report_path,
                "missing_artefacts": []}

    def fake_canary(train_db, version_dir, components):
        version = os.path.basename(version_dir)
        expected = {n: __import__("ml.mlops.scoring", fromlist=["x"]).score(
            "anomaly", joblib.load(p), benign.head(20), "t1")
            for n, p in store.component_files(version, "anomaly").items()}
        joblib.dump({"frame": benign.head(20), "expected": expected},
                    os.path.join(version_dir, train.CANARY_NAME))
        return {"rows": 20}

    monkeypatch.setattr(train, "run_trainer", fake_trainer)
    monkeypatch.setattr(train, "build_canary", fake_canary)
    monkeypatch.setattr(pipeline, "_retrieve", lambda run: {
        "fetch": {"status": "skipped"}, "admitted": [], "pending": [], "changed": [],
        "av_blocked": []})
    monkeypatch.setattr(pipeline, "_etl", lambda run, admitted: {"mode": "stub", "stats": {}})
    monkeypatch.setattr(data, "corpus_hash", lambda path: "corpus-v1")
    monkeypatch.setattr(evaluate, "build_context",
                        lambda *a: evaluate.EvalContext(corpus_positives=attacks))
    monkeypatch.setattr(monitor, "drift", lambda *a: {"counts": {"stable": 1},
                                                      "retrain_recommended": False, "worst": []})
    real_outcomes = monitor.live_outcomes
    monkeypatch.setattr(monitor, "live_outcomes",
                        lambda *a: {**real_outcomes(*a), "active_hosts": 1})
    yield {"models": models, "home": home, "db": tmp_db, "state": state,
           "host": seeded_host["host_id"]}
    ml_registry.clear_cache()


def _run(when, **kwargs):
    return pipeline.run_pipeline(now=when, trigger="schedule", **kwargs)


def _q(db, sql, *params):
    conn = database.connect(db)
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


def _served_version():
    ml_registry.clear_cache()
    return (ml_registry.load_artefact("anomaly", "t1") or {}).get("version_id")


def _new_live_process(db, host, collected_at):
    """New benign telemetry: changes what Component A would learn next week."""
    conn = database.connect(db)
    conn.execute("""INSERT INTO raw_processes (host_id, collection_id, collected_at_utc, pid,
                        ppid, name, cmdline, exe_path)
                    VALUES (?, 'c2', ?, 3000, 4, 'code.exe', 'code.exe --new-window', 'code.exe')""",
                 (host, collected_at))
    conn.commit()
    conn.close()


def _give_trial_evidence(db, host, hours=30, processes=400):
    conn = database.connect(db)
    tid = conn.execute("SELECT id FROM ml_shadow_trials WHERE status='running'").fetchone()[0]
    for h in range(hours):
        conn.execute("""INSERT INTO ml_shadow_observations (trial_id, hour_utc, passes,
                            processes_scored, errors, champion_ms_total, challenger_ms_total,
                            challenger_ms_max) VALUES (?, ?, 2, ?, 0, 20, 22, 12)""",
                     (tid, f"2026-09-28T{h % 24:02d}:00:00+00:{h // 24:02d}",
                      processes // hours + 1))
    conn.execute("""INSERT INTO ml_shadow_flags (trial_id, process_key, host_id, pid,
                        champion_flag, challenger_flag, first_seen_utc)
                    VALUES (?, 'k', ?, 1, 1, 1, 't')""", (tid, host))
    conn.commit()
    conn.close()
    return tid


class TestLifecycle:
    def test_week_one_starts_a_trial_and_changes_nothing_served(self, stack):
        before = _models_digest(stack["models"])
        assert _run(T0) == pipeline.EXIT_OK
        assert _models_digest(stack["models"]) == before       # invariant 1/3
        trials = _q(stack["db"], "SELECT version_id, status FROM ml_shadow_trials")
        assert [tuple(t) for t in trials] == [("v20260927T030000Z", "running")]
        assert (stack["models"] / "shadow" / "anomaly_t1.joblib").exists()
        assert store.champion_entry("anomaly")["reason"] == "legacy"

    def test_week_two_promotes_after_a_good_trial(self, stack):
        _run(T0)
        _give_trial_evidence(stack["db"], stack["host"])
        _new_live_process(stack["db"], stack["host"], "2026-09-25T09:00:00+00:00")
        stack["state"]["seed"] = 11
        assert _run(T0 + WEEK) == pipeline.EXIT_OK
        assert _served_version() == "v20260927T030000Z"
        statuses = dict(_q(stack["db"], "SELECT version_id, status FROM ml_shadow_trials"))
        assert statuses["v20260927T030000Z"] == "promoted"
        assert statuses["v20261004T030000Z"] == "running"      # the next challenger
        registered = _q(stack["db"], "SELECT training_source FROM ml_models WHERE is_active=1 "
                                     "AND name='anomaly_t1'")
        assert registered[0][0] == "mlops:v20260927T030000Z"

    def test_no_evidence_extends_the_trial_and_keeps_the_champion(self, stack):
        _run(T0)
        assert _run(T0 + WEEK) == pipeline.EXIT_OK      # identical inputs: same fingerprint
        assert _served_version() is None                # legacy champion has no version_id
        rows = _q(stack["db"], "SELECT status, online_json FROM ml_shadow_trials")
        assert rows[0][0] == "running"
        assert json.loads(rows[0][1])["extensions"] == 1
        assert len(rows) == 1                           # not retrained: identical to the trial

    def test_freeze_blocks_promotion(self, stack):
        _run(T0)
        _give_trial_evidence(stack["db"], stack["host"])
        os.makedirs(stack["home"], exist_ok=True)
        (stack["home"] / "FROZEN").write_text("x")
        _run(T0 + WEEK)
        assert _served_version() is None
        assert _q(stack["db"], "SELECT status FROM ml_shadow_trials")[0][0] == "running"

    def test_failed_smoke_test_rolls_back_automatically(self, stack, monkeypatch):
        _run(T0)
        _give_trial_evidence(stack["db"], stack["host"])
        before = _models_digest(stack["models"])
        monkeypatch.setattr(train, "canary_check",
                            lambda *a: {"ok": False, "reason": "simulated corruption"})
        assert _run(T0 + WEEK) == pipeline.EXIT_ATTENTION
        after = _models_digest(stack["models"])
        assert after["anomaly_t1.joblib"] == before["anomaly_t1.joblib"]
        assert _q(stack["db"], "SELECT status FROM ml_shadow_trials WHERE version_id=?",
                  "v20260927T030000Z")[0][0] == "aborted"
        assert store.champion_entry("anomaly")["reason"].startswith("auto-rollback")

    def test_identical_retrain_is_adopted_without_a_trial(self, stack, monkeypatch):
        """The same fitted model as the champion: provenance only, no week-long trial.

        Identity itself is unit-tested in test_mlops_gates.py::TestEquivalence; here it is
        forced, because sklearn trees do not pickle reproducibly (see that test)."""
        monkeypatch.setattr(evaluate, "equivalent", lambda challenger, champion: True)
        before = _models_digest(stack["models"])
        assert _run(T0) == pipeline.EXIT_OK
        assert _q(stack["db"], "SELECT COUNT(*) FROM ml_shadow_trials")[0][0] == 0
        assert _served_version() == "v20260927T030000Z"
        assert store.champion_entry("anomaly")["reason"].startswith("equivalent")
        assert _models_digest(stack["models"]) != before            # provenance stamped
        _run(T0 + WEEK)
        plan = json.loads(_q(stack["db"], "SELECT summary_json FROM ml_pipeline_runs "
                                          "ORDER BY started_at_utc DESC LIMIT 1")[0][0])["plan"]
        assert plan == {"anomaly": "unchanged"}         # and it stops the weekly churn

    def test_unchanged_inputs_are_not_retrained_after_promotion(self, stack):
        _run(T0)
        _give_trial_evidence(stack["db"], stack["host"])
        _run(T0 + WEEK)                                  # promotes; same data, same seed
        plan = json.loads(_q(stack["db"], "SELECT summary_json FROM ml_pipeline_runs "
                                          "ORDER BY started_at_utc DESC LIMIT 1")[0][0])["plan"]
        assert plan == {"anomaly": "unchanged"}


class TestSafety:
    def test_pause_has_no_side_effects(self, stack):
        os.makedirs(stack["home"], exist_ok=True)
        (stack["home"] / "PAUSED").write_text("x")
        before = _models_digest(stack["models"])
        assert _run(T0) == pipeline.EXIT_OK
        assert _q(stack["db"], "SELECT COUNT(*) FROM ml_pipeline_runs")[0][0] == 0
        assert not (stack["home"] / "runs").exists()
        assert _models_digest(stack["models"]) == before

    def test_cadence_guard_allows_one_run_per_week(self, stack):
        assert _run(T0) == pipeline.EXIT_OK
        assert _run(T0 + timedelta(days=2)) == pipeline.EXIT_OK
        assert _q(stack["db"], "SELECT COUNT(*) FROM ml_pipeline_runs")[0][0] == 1
        _run(T0 + timedelta(days=2), force=True)
        assert _q(stack["db"], "SELECT COUNT(*) FROM ml_pipeline_runs")[0][0] == 2

    def test_a_failed_run_does_not_count_toward_the_cadence(self, stack, monkeypatch):
        monkeypatch.setattr(pipeline, "_etl", lambda *a: (_ for _ in ()).throw(OSError("disk")))
        assert _run(T0) == pipeline.EXIT_FAILED
        monkeypatch.setattr(pipeline, "_etl", lambda run, admitted: {"mode": "stub", "stats": {}})
        assert _run(T0 + timedelta(hours=1)) == pipeline.EXIT_OK

    def test_failure_before_promotion_leaves_models_byte_identical(self, stack, monkeypatch):
        _run(T0)
        _give_trial_evidence(stack["db"], stack["host"])
        before = _models_digest(stack["models"])
        monkeypatch.setattr(pipeline, "_snapshot",
                            lambda run: (_ for _ in ()).throw(RuntimeError("snapshot broke")))
        assert _run(T0 + WEEK) == pipeline.EXIT_FAILED
        assert _models_digest(stack["models"]) == before
        row = _q(stack["db"], "SELECT status, summary_json FROM ml_pipeline_runs "
                              "ORDER BY started_at_utc DESC LIMIT 1")[0]
        assert row[0] == "failed"
        assert json.loads(row[1])["failed_stage"] == "snapshot"

    def test_offline_gate_failure_starts_no_trial(self, stack):
        stack["state"]["report_t1"] = 0.20              # below the Sigma baseline
        assert _run(T0) == pipeline.EXIT_OK
        assert _q(stack["db"], "SELECT COUNT(*) FROM ml_shadow_trials")[0][0] == 0
        assert not (stack["models"] / "shadow" / "anomaly_t1.joblib").exists()

    def test_training_failure_needs_attention_and_stages_nothing(self, stack):
        stack["state"]["train_ok"] = False
        assert _run(T0) == pipeline.EXIT_ATTENTION
        assert _q(stack["db"], "SELECT COUNT(*) FROM ml_shadow_trials")[0][0] == 0

    def test_no_valid_champion_bootstraps_directly(self, stack):
        for tier in ("t1", "t2"):
            os.remove(stack["models"] / f"anomaly_{tier}.joblib")
        assert _run(T0) == pipeline.EXIT_OK
        assert _served_version() == "v20260927T030000Z"
        assert _q(stack["db"], "SELECT COUNT(*) FROM ml_shadow_trials")[0][0] == 0

    def test_stale_lock_from_a_crashed_run_is_reclaimed_and_reported(self, stack):
        os.makedirs(stack["home"], exist_ok=True)
        (stack["home"] / "pipeline.lock").write_text(json.dumps(
            {"pid": 999_999_999, "process_created": 1, "acquired_at": 1}))
        assert _run(T0) == pipeline.EXIT_ATTENTION
        summary = json.loads(_q(stack["db"], "SELECT summary_json FROM ml_pipeline_runs")[0][0])
        assert any("did not finish" in a for a in summary["attention"])

    def test_an_interrupted_run_is_closed_by_the_next(self, stack):
        conn = database.connect(stack["db"])
        conn.execute("""INSERT INTO ml_pipeline_runs (run_id, started_at_utc, status, trigger)
                        VALUES ('crashed', '2026-09-20T03:00:00+00:00', 'running', 'schedule')""")
        conn.commit()
        conn.close()
        _run(T0)
        assert _q(stack["db"], "SELECT status FROM ml_pipeline_runs WHERE run_id='crashed'"
                  )[0][0] == "failed"

    def test_a_silent_week_needs_attention(self, stack, monkeypatch):
        """No telemetry at all means nothing was protected: agents or server down."""
        monkeypatch.setattr(monitor, "live_outcomes", lambda *a: {"active_hosts": 0})
        assert _run(T0) == pipeline.EXIT_ATTENTION
        summary = json.loads(_q(stack["db"], "SELECT summary_json FROM ml_pipeline_runs")[0][0])
        assert any("no endpoint telemetry" in a for a in summary["attention"])

    def test_every_run_writes_a_report(self, stack):
        _run(T0)
        report = _q(stack["db"], "SELECT report_path FROM ml_pipeline_runs")[0][0]
        text = open(report, encoding="utf-8").read()
        assert "Offline gates - anomaly: PASSED" in text
        assert "A3_no_lost_detections" in text


def test_cli_status_and_flags(stack, capsys):
    from ml.mlops.__main__ import main
    _run(T0)
    assert main(["freeze"]) == 0 and (stack["home"] / "FROZEN").exists()
    assert main(["unfreeze"]) == 0 and not (stack["home"] / "FROZEN").exists()
    capsys.readouterr()
    assert main(["status", "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["trials"][0]["component"] == "anomaly"
    assert out["champions"]["anomaly"]["serving"] is True
