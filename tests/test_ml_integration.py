"""Phase 4 tests: engine integration, model registry, and the /api/v1/ml/* endpoints.

The property that matters most here is negative: **ML must never be able to break
deterministic detection.** A missing scikit-learn, a corrupt artefact, a model trained
against an older feature spec, an exception mid-scoring - each must cost only the ML
findings, leaving YARA/Sigma/IOC untouched. Several tests below deliberately break ML and
assert the rest of the pipeline is unharmed.
"""
import json
import os

import numpy as np
import pandas as pd
import pytest

from server import db as database
from server.engine import ml_features as mlf
from server.engine import ml_anomaly, ml_integration, ml_registry


# --------------------------------------------------------------------------- fixtures

@pytest.fixture()
def model_dir(tmp_path, monkeypatch):
    path = tmp_path / "models"
    path.mkdir()
    monkeypatch.setattr(ml_registry, "MODELS_DIR", str(path))
    ml_registry.clear_cache()
    yield str(path)
    ml_registry.clear_cache()


@pytest.fixture()
def scored_db(tmp_db, seeded_host, model_dir):
    """A live-shaped DB with processes, plus a small trained anomaly artefact on disk."""
    host_id = seeded_host["host_id"]
    conn = database.connect(tmp_db)
    ts = "2026-03-02T11:00:00+00:00"
    rng = np.random.default_rng(0)

    def add(pid, name, cmdline, exe, user=r"NT AUTHORITY\SYSTEM"):
        conn.execute(
            """INSERT INTO raw_processes (host_id, collection_id, collected_at_utc, pid, ppid,
                                          name, cmdline, exe_path, sha256, username)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (host_id, "col-1", ts, pid, 4, name, cmdline, exe, "a" * 64, user))

    for i in range(60):
        svc = f"svchost.exe"
        add(1000 + i, svc, f"{svc} -k netsvcs -p -s Svc{i}",
            r"C:\Windows\System32\svchost.exe")
    # a handful of clearly unusual ones
    for i in range(4):
        blob = "".join(rng.choice(list("ABCDEFabcdef0123456789+/"), size=120))
        add(2000 + i, "evil.exe", f"powershell.exe -nop -w hidden -enc {blob}",
            rf"C:\Users\x\AppData\Local\Temp\evil{i}.exe", user=r"LAB\bob")
    conn.commit()

    frame = mlf.extract_process_frame(conn)
    stats = mlf.fit_stats(frame)
    X = mlf.transform(frame, stats=stats, tier=mlf.TIER_T1)
    model = ml_anomaly.AnomalyModel(n_estimators=60).fit(X)

    import joblib
    joblib.dump({
        "kind": "anomaly", "tier": "t1", "payload": model.to_payload(),
        "feature_stats": stats.to_dict(),
        "feature_spec_sha256": mlf.feature_spec_sha256(),
        "metrics": {"pr_auc": 0.5}, "trained_at_utc": "2026-03-02T00:00:00+00:00",
    }, os.path.join(model_dir, "anomaly_t1.joblib"))
    conn.close()
    return {"db": tmp_db, "host_id": host_id, "model_dir": model_dir}


# --------------------------------------------------------------------------- registry

class TestRegistry:
    def test_reports_dependencies(self):
        status = ml_registry.dependencies_available()
        assert status.available is True          # the ML venv has them
        assert status.reason == ""

    def test_missing_dependency_is_reported_not_raised(self, monkeypatch):
        monkeypatch.setattr(ml_registry, "dependencies_available",
                            lambda: ml_registry.MlStatus(False, "no sklearn", "sklearn"))
        assert ml_registry.load_artefact("anomaly", "t1") is None

    def test_absent_artefact_returns_none(self, model_dir):
        assert ml_registry.load_artefact("anomaly", "t1") is None

    def test_corrupt_artefact_returns_none(self, model_dir):
        with open(os.path.join(model_dir, "anomaly_t1.joblib"), "wb") as fh:
            fh.write(b"not a joblib file")
        assert ml_registry.load_artefact("anomaly", "t1") is None

    def test_feature_spec_mismatch_is_refused(self, scored_db, monkeypatch):
        """A stale model fed a changed vector produces confident nonsense - refuse it."""
        assert ml_registry.load_artefact("anomaly", "t1") is not None
        ml_registry.clear_cache()
        monkeypatch.setattr(mlf, "feature_spec_sha256", lambda: "deadbeef" * 8)
        assert ml_registry.load_artefact("anomaly", "t1") is None

    def test_cache_invalidated_by_mtime(self, scored_db):
        first = ml_registry.load_artefact("anomaly", "t1")
        assert first is not None
        assert ml_registry.load_artefact("anomaly", "t1") is first      # cached
        path = ml_registry.model_path("anomaly", "t1")
        os.utime(path, (os.path.getatime(path), os.path.getmtime(path) + 10))
        assert ml_registry.load_artefact("anomaly", "t1") is not first  # reloaded

    def _add_sysmon(self, conn, host_id):
        conn.execute(
            """INSERT INTO raw_logs (host_id, collection_id, collected_at_utc, source,
                                      event_id, payload_json)
               VALUES (?,?,?,'sysmon',1,'{}')""",
            (host_id, "col-1", database.now_iso()))
        conn.commit()

    def test_default_tier_is_t1_even_with_sysmon(self, tmp_db, seeded_host, monkeypatch):
        """Changed after the DFIR-only merge: auto-upgrading Sysmon hosts to T2 served the
        T2 model sysmon_available=0 for every long-running process from its second sweep
        on. See ml_registry.choose_tier."""
        monkeypatch.delenv("ATOR_ML_TIER", raising=False)
        conn = database.connect(tmp_db)
        try:
            assert ml_registry.choose_tier(conn) == "t1"
            self._add_sysmon(conn, seeded_host["host_id"])
            assert ml_registry.choose_tier(conn) == "t1"
        finally:
            conn.close()

    def test_t2_opt_in_requires_sysmon(self, tmp_db, seeded_host, monkeypatch):
        monkeypatch.setenv("ATOR_ML_TIER", "t2")
        conn = database.connect(tmp_db)
        try:
            assert ml_registry.choose_tier(conn) == "t1", "T2 without Sysmon is all NaN"
            self._add_sysmon(conn, seeded_host["host_id"])
            assert ml_registry.choose_tier(conn) == "t2"
        finally:
            conn.close()

    def test_tier_can_be_pinned(self, tmp_db, monkeypatch):
        monkeypatch.setenv("ATOR_ML_TIER", "t1")
        conn = database.connect(tmp_db)
        try:
            assert ml_registry.choose_tier(conn) == "t1"
        finally:
            conn.close()

    def test_register_activates_exactly_one_per_type_and_tier(self, tmp_db):
        conn = database.connect(tmp_db)
        try:
            common = dict(model_type="anomaly", tier="t1", feature_spec_sha256="x",
                          training_rows=10, training_source="test", metrics={},
                          path="/tmp/a.joblib")
            first = ml_registry.register(conn, name="anomaly_t1", version="1", **common)
            second = ml_registry.register(conn, name="anomaly_t1", version="2", **common)
            active = conn.execute(
                "SELECT id FROM ml_models WHERE model_type='anomaly' AND feature_tier='t1' "
                "AND is_active=1").fetchall()
            assert len(active) == 1
            assert active[0]["id"] == second != first
        finally:
            conn.close()

    def test_ensure_registered_is_idempotent(self, scored_db):
        conn = database.connect(scored_db["db"])
        try:
            first = ml_registry.ensure_registered(conn, "anomaly", "t1")
            second = ml_registry.ensure_registered(conn, "anomaly", "t1")
            assert first is not None and first == second
            assert conn.execute("SELECT COUNT(*) FROM ml_models").fetchone()[0] == 1
        finally:
            conn.close()

    def test_describe_works_without_any_model(self, tmp_db, model_dir):
        conn = database.connect(tmp_db)
        try:
            out = ml_registry.describe(conn)
            assert out["available"] is True
            assert out["models"] == []
            assert len(out["feature_spec_sha256"]) == 64
        finally:
            conn.close()


# --------------------------------------------------------------------------- scoring

class TestAnomalyScoring:
    def test_produces_detections_with_scores_and_explanations(self, scored_db):
        conn = database.connect(scored_db["db"])
        try:
            hits = ml_integration.run_ml_anomaly_detection(conn)
            assert hits, "expected at least one anomaly among synthetic outliers"
            for hit in hits:
                assert hit["rule_type"] == "ml_anomaly"
                assert 0.0 <= hit["anomaly_score"] <= 1.0
                assert hit["severity"] in ("low", "medium", "high")
                payload = json.loads(hit["ml_explanation"])
                assert payload["top_features"]
                assert all(f["feature"] in mlf.FEATURE_NAMES
                           for f in payload["top_features"])
        finally:
            conn.close()

    def test_alert_budget_is_enforced_per_host(self, scored_db):
        """Top-K, not a bare threshold, is what bounds analyst workload."""
        conn = database.connect(scored_db["db"])
        try:
            hits = ml_integration.run_ml_anomaly_detection(conn, top_k=3, threshold=0.0)
            assert len(hits) <= 3
        finally:
            conn.close()

    def test_threshold_acts_as_a_floor(self, scored_db):
        conn = database.connect(scored_db["db"])
        try:
            assert ml_integration.run_ml_anomaly_detection(
                conn, top_k=50, threshold=1.01) == []
        finally:
            conn.close()

    def test_second_run_does_not_duplicate(self, scored_db):
        """Re-running over the same data opens no new detections and counts no new sightings.

        Since the DFIR-only merge, a process seen again in a LATER sweep is folded into its
        finding as a sighting (hit_count), the convention rule detections use. Re-scanning
        data already counted - which "Run hunt now" does on every click - is neither.
        """
        conn = database.connect(scored_db["db"])
        try:
            hits = ml_integration.run_ml_anomaly_detection(conn, top_k=5)
            first_ids = ml_integration.insert_ml_detections(conn, hits)
            for _ in range(3):                   # three more clicks, no new sweep
                again = ml_integration.run_ml_anomaly_detection(conn, top_k=5)
                assert again == [], "a rescan of counted data is not a new sighting"
                assert ml_integration.insert_ml_detections(conn, again) == []
            assert conn.execute("SELECT COUNT(*) FROM detections WHERE rule_type='ml_anomaly'"
                                ).fetchone()[0] == len(first_ids)
            assert conn.execute("SELECT MAX(hit_count) FROM detections "
                                "WHERE rule_type='ml_anomaly'").fetchone()[0] == 1
        finally:
            conn.close()

    def test_severity_never_claims_critical(self):
        """A statistical outlier must not outrank a rule that knows what it matched."""
        assert ml_integration._severity_for(1.0) == "high"
        assert ml_integration._severity_for(0.9999) == "high"
        assert ml_integration._severity_for(0.996) == "medium"
        assert ml_integration._severity_for(0.5) == "low"
        for score in (0.0, 0.5, 0.99, 0.999, 1.0):
            assert ml_integration._severity_for(score) != "critical"

    def test_summary_flags_that_it_is_not_a_rule_match(self, scored_db):
        conn = database.connect(scored_db["db"])
        try:
            hits = ml_integration.run_ml_anomaly_detection(conn, top_k=2)
            assert hits
            assert "not a rule match" in hits[0]["summary"].lower()
        finally:
            conn.close()

    def test_no_model_yields_no_detections_and_no_error(self, tmp_db, seeded_host, model_dir):
        conn = database.connect(tmp_db)
        try:
            assert ml_integration.run_ml_anomaly_detection(conn) == []
        finally:
            conn.close()

    def test_scoring_never_raises(self, scored_db, monkeypatch):
        """Any internal failure must degrade to 'no ML findings', never propagate."""
        def explode(*a, **kw):
            raise RuntimeError("simulated scoring failure")
        monkeypatch.setattr(ml_integration, "_score", explode)
        conn = database.connect(scored_db["db"])
        try:
            assert ml_integration.run_ml_anomaly_detection(conn) == []
        finally:
            conn.close()

    def test_insert_writes_ml_columns(self, scored_db):
        conn = database.connect(scored_db["db"])
        try:
            hits = ml_integration.run_ml_anomaly_detection(conn, top_k=2)
            ids = ml_integration.insert_ml_detections(conn, hits)
            row = conn.execute(
                "SELECT rule_type, anomaly_score, ml_model_id, ml_explanation "
                "FROM detections WHERE id=?", (ids[0],)).fetchone()
            assert row["rule_type"] == "ml_anomaly"
            assert row["anomaly_score"] is not None
            assert row["ml_model_id"] is not None
            assert json.loads(row["ml_explanation"])["tier"] in ("t1", "t2")
        finally:
            conn.close()


# --------------------------------------------------------------------------- engine

class TestEngineIsolation:
    """ML failures must cost ML findings and nothing else."""

    def test_engine_runs_and_reports_ml_results(self, scored_db):
        from server.engine import run_engine
        conn = database.connect(scored_db["db"])
        try:
            result = run_engine(conn)
            assert "ml_detections" in result
            assert result["ml_error"] is None
            assert result["ml_detections"] >= 1
            assert conn.execute(
                "SELECT COUNT(*) FROM detections WHERE rule_type='ml_anomaly'"
            ).fetchone()[0] == result["ml_detections"]
        finally:
            conn.close()

    def test_sigma_still_runs_when_ml_explodes(self, scored_db, monkeypatch):
        from server.engine import run_engine
        import server.engine.ml_integration as mi

        def explode(*a, **kw):
            raise RuntimeError("simulated ML catastrophe")
        monkeypatch.setattr(mi, "run_ml_anomaly_detection", explode)

        conn = database.connect(scored_db["db"])
        try:
            result = run_engine(conn)
            assert result["ml_detections"] == 0
            assert "simulated ML catastrophe" in (result["ml_error"] or "")
            # The deterministic half must be unaffected.
            assert "sigma_hits" in result
            assert isinstance(result["total_new_detections"], int)
        finally:
            conn.close()

    def test_engine_works_with_no_ml_stack(self, scored_db, monkeypatch):
        monkeypatch.setattr(ml_registry, "dependencies_available",
                            lambda: ml_registry.MlStatus(False, "no numpy", "numpy"))
        from server.engine import run_engine
        conn = database.connect(scored_db["db"])
        try:
            result = run_engine(conn)
            assert result["ml_detections"] == 0
            assert result["ml_error"] is None      # absence is not an error
        finally:
            conn.close()

    def test_total_new_detections_still_counts_only_rules(self, scored_db):
        """Existing dashboards read this field; ML must not silently inflate it."""
        from server.engine import run_engine
        conn = database.connect(scored_db["db"])
        try:
            result = run_engine(conn)
            rule_rows = conn.execute(
                "SELECT COUNT(*) FROM detections WHERE rule_type != 'ml_anomaly'"
            ).fetchone()[0]
            assert result["total_new_detections"] == rule_rows
        finally:
            conn.close()


# --------------------------------------------------------------------------- API

class TestMlEndpoints:
    def test_status_reports_availability(self, client):
        response = client.get("/api/v1/ml/status")
        assert response.status_code == 200
        body = response.json()
        assert "available" in body and "models" in body

    def test_models_endpoint_lists_registered(self, client):
        response = client.get("/api/v1/ml/models")
        assert response.status_code == 200
        assert "models" in response.json()

    def test_anomalies_endpoint_returns_empty_cleanly(self, client):
        response = client.get("/api/v1/ml/anomalies")
        assert response.status_code == 200
        assert response.json() == {"anomalies": [], "count": 0}

    def test_anomalies_endpoint_parses_json_columns(self, client, seeded_host):
        conn = database.connect(os.environ["ATOR_DFIR_DB"])
        try:
            conn.execute(
                """INSERT INTO detections (host_id, collection_id, rule_type, rule_name,
                                           severity, summary, detected_at_utc,
                                           anomaly_score, ml_explanation)
                   VALUES (?,?,'ml_anomaly','ML Anomaly: x','low','s',?,0.995,?)""",
                (seeded_host["host_id"], "col-1", database.now_iso(),
                 json.dumps({"tier": "t1", "top_features": [{"feature": "cmdline_len",
                                                             "deviation": 3.2}]})))
            conn.commit()
        finally:
            conn.close()
        body = client.get("/api/v1/ml/anomalies").json()
        assert body["count"] == 1
        item = body["anomalies"][0]
        assert item["anomaly_score"] == 0.995
        assert item["ml_explanation"]["top_features"][0]["feature"] == "cmdline_len"

    def test_anomalies_endpoint_filters_by_host(self, client, seeded_host):
        assert client.get("/api/v1/ml/anomalies?host_id=99999").json()["count"] == 0

    def test_score_endpoint_reports_unavailable_cleanly(self, client, monkeypatch):
        monkeypatch.setattr(ml_registry, "dependencies_available",
                            lambda: ml_registry.MlStatus(False, "no sklearn", "sklearn"))
        response = client.post("/api/v1/ml/score", json={})
        assert response.status_code == 503
        detail = response.json()["detail"]
        assert detail["error"] == "ml_unavailable"
        assert "requirements-ml.txt" in detail["hint"]

    def test_score_endpoint_with_no_model_returns_zero(self, client, model_dir):
        response = client.post("/api/v1/ml/score", json={"persist": False})
        assert response.status_code == 200
        body = response.json()
        assert body["detections_found"] == 0
        assert body["detections_persisted"] == 0

    def test_score_endpoint_validates_input(self, client):
        assert client.post("/api/v1/ml/score", json={"top_k": 0}).status_code == 422
        assert client.post("/api/v1/ml/score", json={"threshold": 5}).status_code == 422


class TestSummaryContract:
    """`detections.summary` is JSON, and every consumer depends on that.

    Regression: ML detections originally wrote a prose sentence there. `engine/timeline.py`
    calls `json.loads()` on the column, so `/api/v1/timeline` raised JSONDecodeError for
    every host that had an ML detection - a 500 on a core dashboard endpoint, caused purely
    by the new detector not honouring an undocumented contract.
    """

    def test_ml_summary_is_valid_json(self, scored_db):
        conn = database.connect(scored_db["db"])
        try:
            hits = ml_integration.run_ml_anomaly_detection(conn, top_k=3)
            assert hits
            for hit in hits:
                payload = json.loads(hit["summary"])      # must not raise
                assert isinstance(payload, dict)
                assert "ml_anomaly_score" in payload
                assert "ml_note" in payload
        finally:
            conn.close()

    def test_ml_summary_keeps_the_standard_artefact_keys(self, scored_db):
        """So anything rendering a detection shows the process, not just ML metadata."""
        conn = database.connect(scored_db["db"])
        try:
            hits = ml_integration.run_ml_anomaly_detection(conn, top_k=3)
            payload = json.loads(hits[0]["summary"])
            assert "name" in payload and "pid" in payload
        finally:
            conn.close()

    def test_timeline_survives_ml_detections(self, scored_db):
        from server.engine import timeline
        conn = database.connect(scored_db["db"])
        try:
            hits = ml_integration.run_ml_anomaly_detection(conn, top_k=3)
            ml_integration.insert_ml_detections(conn, hits)
            result = timeline.build(conn)                  # used to raise JSONDecodeError
            titles = [e["title"] for e in result["events"]]
            assert any("ML_ANOMALY" in t for t in titles)
        finally:
            conn.close()

    def test_timeline_survives_a_non_json_summary(self, tmp_db, seeded_host):
        """Defence in depth: a future detector making the same mistake must not 500."""
        from server.engine import timeline
        conn = database.connect(tmp_db)
        try:
            conn.execute(
                """INSERT INTO detections (host_id, rule_type, rule_name, severity,
                                           summary, detected_at_utc)
                   VALUES (?,'sigma','Legacy Rule','low',?,?)""",
                (seeded_host["host_id"], "this is not json at all", database.now_iso()))
            conn.commit()
            result = timeline.build(conn)
            assert result["total"] >= 1
            detail = json.loads(result["events"][0]["detail"])
            assert detail["summary"]["text"].startswith("this is not json")
        finally:
            conn.close()

    def test_timeline_handles_empty_summary(self, tmp_db, seeded_host):
        from server.engine import timeline
        conn = database.connect(tmp_db)
        try:
            conn.execute(
                """INSERT INTO detections (host_id, rule_type, rule_name, severity,
                                           summary, detected_at_utc)
                   VALUES (?,'sigma','No Summary','low',NULL,?)""",
                (seeded_host["host_id"], database.now_iso()))
            conn.commit()
            assert timeline.build(conn)["total"] >= 1
        finally:
            conn.close()
