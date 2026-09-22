"""Phase 10: shadow scoring inside the engine - the "A/B test in deployment".

The contract that matters is isolation: a challenger on trial may be broken, slow or wrong,
and none of that may reach the champion's scores, the detections table, or the engine.
"""
import json
import os

import numpy as np
import pytest

from server import db as database
from server.engine import ml_anomaly, ml_features as mlf
from server.engine import ml_integration, ml_registry, ml_shadow


@pytest.fixture()
def model_dir(tmp_path, monkeypatch):
    path = tmp_path / "models"
    path.mkdir()
    monkeypatch.setattr(ml_registry, "MODELS_DIR", str(path))
    ml_registry.clear_cache()
    yield path
    ml_registry.clear_cache()


def _fit_artefact(frame, n_estimators, seed, version_id=None):
    stats = mlf.fit_stats(frame)
    X = mlf.transform(frame, stats=stats, tier=mlf.TIER_T1)
    model = ml_anomaly.AnomalyModel(n_estimators=n_estimators, seed=seed).fit(X)
    artefact = {"kind": "anomaly", "tier": "t1", "payload": model.to_payload(),
                "feature_stats": stats.to_dict(),
                "feature_spec_sha256": mlf.feature_spec_sha256(),
                "metrics": {"pr_auc": 0.5}, "trained_at_utc": f"2026-09-0{seed}T00:00:00+00:00"}
    if version_id:
        artefact["version_id"] = version_id
    return artefact


@pytest.fixture()
def env(tmp_db, seeded_host, model_dir):
    import joblib
    host = seeded_host["host_id"]
    conn = database.connect(tmp_db)
    ts = database.now_iso()
    rng = np.random.default_rng(1)
    for i in range(80):
        conn.execute(
            """INSERT INTO raw_processes (host_id, collection_id, collected_at_utc, pid, ppid,
                                          name, cmdline, exe_path, username)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (host, "col-1", ts, 1000 + i, 4, "svchost.exe", f"svchost.exe -k netsvcs -s S{i}",
             r"C:\Windows\System32\svchost.exe", r"NT AUTHORITY\SYSTEM"))
    for i in range(4):
        blob = "".join(rng.choice(list("ABCDEFabcdef0123456789+/"), size=120))
        conn.execute(
            """INSERT INTO raw_processes (host_id, collection_id, collected_at_utc, pid, ppid,
                                          name, cmdline, exe_path, username)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (host, "col-1", ts, 2000 + i, 4, "evil.exe", f"powershell -nop -w hidden -enc {blob}",
             rf"C:\Users\x\AppData\Local\Temp\evil{i}.exe", r"LAB\bob"))
    conn.commit()
    frame = mlf.extract_process_frame(conn)
    joblib.dump(_fit_artefact(frame, 60, 1), str(model_dir / "anomaly_t1.joblib"))
    (model_dir / "shadow").mkdir()
    joblib.dump(_fit_artefact(frame, 40, 2, version_id="vTEST"),
                str(model_dir / "shadow" / "anomaly_t1.joblib"))
    yield {"conn": conn, "host": host, "models": model_dir}
    conn.close()


def _start_trial(conn, version="vTEST", component="anomaly"):
    cur = conn.execute(
        """INSERT INTO ml_shadow_trials (version_id, components_json, started_at_utc, status)
           VALUES (?, ?, ?, 'running')""", (version, json.dumps([component]), database.now_iso()))
    conn.commit()
    return cur.lastrowid


def _score(conn, shadow=True):
    return ml_integration.run_ml_anomaly_detection(conn, top_k=3, threshold=0.0, shadow=shadow)


def _count(conn, table, trial_id=None):
    sql = f"SELECT COUNT(*) FROM {table}" + (" WHERE trial_id=?" if trial_id else "")
    return conn.execute(sql, (trial_id,) if trial_id else ()).fetchone()[0]


class TestShadowScoring:
    def test_no_trial_means_no_shadow_work(self, env):
        hits = _score(env["conn"])
        assert hits
        assert _count(env["conn"], "ml_shadow_observations") == 0

    def test_trial_records_both_models_on_the_same_processes(self, env):
        trial_id = _start_trial(env["conn"])
        _score(env["conn"])
        obs = env["conn"].execute(
            "SELECT passes, processes_scored, errors FROM ml_shadow_observations "
            "WHERE trial_id=?", (trial_id,)).fetchone()
        assert tuple(obs) == (1, 84, 0)
        flags = env["conn"].execute(
            "SELECT SUM(champion_flag), SUM(challenger_flag) FROM ml_shadow_flags "
            "WHERE trial_id=?", (trial_id,)).fetchone()
        assert flags[0] == 3 and flags[1] == 3          # same top-K budget for both

    def test_champion_findings_are_identical_with_and_without_a_trial(self, env):
        without = _score(env["conn"], shadow=False)
        _start_trial(env["conn"])
        with_trial = _score(env["conn"], shadow=True)
        strip = lambda hits: [(h["summary"], h["anomaly_score"]) for h in hits]   # noqa: E731
        assert strip(with_trial) == strip(without)

    def test_shadow_never_writes_detections(self, env):
        _start_trial(env["conn"])
        _score(env["conn"])
        assert _count(env["conn"], "detections") == 0

    def test_repeated_passes_count_distinct_processes_once(self, env):
        trial_id = _start_trial(env["conn"])
        for _ in range(3):
            _score(env["conn"])
        assert _count(env["conn"], "ml_shadow_flags", trial_id) <= 6
        passes = env["conn"].execute("SELECT SUM(passes) FROM ml_shadow_observations "
                                     "WHERE trial_id=?", (trial_id,)).fetchone()[0]
        assert passes == 3                               # one hour bucket, three passes

    def test_manual_hunt_does_not_feed_the_trial(self, env):
        """'Run hunt now' rescans all history; counting it would inflate the evidence."""
        _start_trial(env["conn"])
        _score(env["conn"], shadow=False)
        assert _count(env["conn"], "ml_shadow_observations") == 0

    def test_missing_challenger_is_an_error_not_a_crash(self, env):
        trial_id = _start_trial(env["conn"])
        os.remove(env["models"] / "shadow" / "anomaly_t1.joblib")
        ml_registry.clear_cache()
        hits = _score(env["conn"])
        assert hits                                      # champion unaffected
        errors = env["conn"].execute("SELECT errors, last_error FROM ml_shadow_observations "
                                     "WHERE trial_id=?", (trial_id,)).fetchone()
        assert errors[0] == 1 and "missing" in errors[1]

    def test_wrong_version_in_shadow_slot_is_an_error(self, env):
        trial_id = _start_trial(env["conn"], version="vOTHER")
        _score(env["conn"])
        row = env["conn"].execute("SELECT errors, last_error FROM ml_shadow_observations "
                                  "WHERE trial_id=?", (trial_id,)).fetchone()
        assert row[0] == 1 and "does not match" in row[1]

    def test_challenger_exception_is_contained(self, env, monkeypatch):
        trial_id = _start_trial(env["conn"])
        monkeypatch.setattr(ml_shadow, "_score_challenger",
                            lambda *a, **k: (_ for _ in ()).throw(MemoryError("boom")))
        assert _score(env["conn"])
        assert env["conn"].execute("SELECT errors FROM ml_shadow_observations WHERE trial_id=?",
                                   (trial_id,)).fetchone()[0] == 1

    def test_a_non_anomaly_trial_does_not_shadow(self, env):
        _start_trial(env["conn"], component="triage")
        _score(env["conn"])
        assert _count(env["conn"], "ml_shadow_observations") == 0

    def test_engine_passes_shadow_on_its_incremental_run(self, env, monkeypatch):
        seen = {}
        real = ml_integration.run_ml_anomaly_detection

        def spy(conn, **kwargs):
            seen.update(kwargs)
            return real(conn, **kwargs)
        monkeypatch.setattr(ml_integration, "run_ml_anomaly_detection", spy)
        from server.engine import run_engine
        run_engine(conn=env["conn"])
        assert seen.get("shadow") is True
