"""Phase 5 tests: Component B (triage), Component C (tactic), host risk, drift.

Where Phase 3/4 guarded the measuring instrument and the isolation boundary, these guard the
*claims*: that calibration is real, that the leak audit is possible, that risk ordering is
defensible, and that drift detection reacts to the thing it is supposed to react to.
"""
import json
import math

import numpy as np
import pandas as pd
import pytest

from ml.evaluation import harness as H
from server import db as database
from server.engine import ml_drift, ml_features as mlf, ml_risk, ml_tactic, ml_triage


# --------------------------------------------------------------------------- fixtures

def _xy(n_benign=300, n_malicious=60, seed=0, separable=True):
    """A feature matrix with a learnable (or unlearnable) signal."""
    rng = np.random.default_rng(seed)
    n = n_benign + n_malicious
    y = np.array([0] * n_benign + [1] * n_malicious)
    shift = 2.5 if separable else 0.0
    data = {
        "cmdline_entropy": np.concatenate([rng.normal(3, 1, n_benign),
                                           rng.normal(3 + shift, 1, n_malicious)]),
        "cmdline_len": np.concatenate([rng.normal(40, 12, n_benign),
                                       rng.normal(40 + shift * 20, 12, n_malicious)]),
        "path_depth": rng.integers(2, 6, n).astype(float),
        "sibling_count": np.concatenate([rng.integers(5, 40, n_benign).astype(float),
                                         rng.integers(0, 3, n_malicious).astype(float)]),
        "all_nan_column": np.full(n, np.nan),          # must be dropped, not crash
        "constant_column": np.ones(n),                 # must be dropped
    }
    return pd.DataFrame(data), y


# --------------------------------------------------------------------------- Component B

class TestTriageModel:
    def test_learns_a_separable_signal(self):
        X, y = _xy()
        model = ml_triage.TriageModel().fit(X, y)
        scores = model.score(X)
        assert scores[y == 1].mean() > scores[y == 0].mean()
        assert scores.min() >= 0.0 and scores.max() <= 1.0

    def test_drops_all_nan_and_constant_columns(self):
        """HistGradientBoosting cannot bin an all-NaN column - it raises."""
        X, y = _xy()
        model = ml_triage.TriageModel().fit(X, y)
        assert "all_nan_column" not in model.used_features
        assert "constant_column" not in model.used_features
        assert "cmdline_entropy" in model.used_features

    def test_all_nan_column_alone_would_break_the_raw_estimator(self):
        """Documents why _usable_columns exists."""
        from sklearn.ensemble import HistGradientBoostingClassifier
        X, y = _xy()
        with pytest.raises(ValueError):
            HistGradientBoostingClassifier(max_iter=5).fit(X, y)
        ml_triage.TriageModel().fit(X, y)         # the wrapper copes

    def test_refuses_single_class_data(self):
        X, y = _xy()
        with pytest.raises(ValueError, match="only one class"):
            ml_triage.TriageModel().fit(X, np.zeros(len(X), dtype=int))

    def test_refuses_empty_data(self):
        with pytest.raises(ValueError, match="zero rows"):
            ml_triage.TriageModel().fit(pd.DataFrame(columns=["a"]), np.array([]))

    def test_refuses_when_everything_is_unusable(self):
        n = 50
        X = pd.DataFrame({"a": np.full(n, np.nan), "b": np.ones(n)})
        y = np.array([0] * 40 + [1] * 10)
        with pytest.raises(ValueError, match="no usable features"):
            ml_triage.TriageModel().fit(X, y)

    def test_scoring_before_fitting_is_an_error(self):
        with pytest.raises(RuntimeError, match="fit must be called"):
            ml_triage.TriageModel().score(pd.DataFrame({"a": [1.0]}))

    def test_feature_mismatch_is_refused(self):
        X, y = _xy()
        model = ml_triage.TriageModel().fit(X, y)
        with pytest.raises(ValueError, match="feature mismatch"):
            model.score(X.drop(columns=["cmdline_entropy"]))

    def test_round_trip_preserves_scores(self):
        X, y = _xy()
        model = ml_triage.TriageModel().fit(X, y)
        before = model.score(X)
        revived = ml_triage.TriageModel.from_payload(model.to_payload())
        assert np.allclose(before, revived.score(X))
        assert revived.used_features == model.used_features

    def test_deterministic_for_a_fixed_seed(self):
        X, y = _xy()
        a = ml_triage.TriageModel(seed=7).fit(X, y).score(X)
        b = ml_triage.TriageModel(seed=7).fit(X, y).score(X)
        assert np.allclose(a, b)

    def test_falls_back_when_too_few_positives_to_calibrate(self):
        X, y = _xy(n_benign=100, n_malicious=4)
        model = ml_triage.TriageModel(calibration_folds=3).fit(X, y)
        # 4 positives cannot support 3-fold calibration; it must degrade, not explode.
        assert model.model.__class__.__name__ == "HistGradientBoostingClassifier"

    def test_explainer_names_used_features(self):
        X, y = _xy()
        model = ml_triage.TriageModel().fit(X, y).fit_explainer(X)
        for row in model.explain(X.head(3), top_k=2):
            for item in row:
                assert item["feature"] in model.used_features


class TestConfidenceBands:
    def test_bands(self):
        assert ml_triage.confidence_band(0.95) == "high"
        assert ml_triage.confidence_band(0.65) == "medium"
        assert ml_triage.confidence_band(0.10) == "low"

    def test_unknown_for_missing(self):
        assert ml_triage.confidence_band(None) == "unknown"
        assert ml_triage.confidence_band(float("nan")) == "unknown"


class TestCalibrationMetrics:
    def test_perfectly_calibrated_scores_well(self):
        rng = np.random.default_rng(0)
        p = rng.random(4000)
        y = (rng.random(4000) < p).astype(int)      # outcome matches its stated probability
        metrics = H.calibration_metrics(y, p)
        assert metrics["expected_calibration_error"] < 0.05
        assert metrics["brier_skill_score"] > 0.3

    def test_overconfident_scores_badly(self):
        rng = np.random.default_rng(1)
        y = (rng.random(2000) < 0.2).astype(int)
        p = np.clip(y * 0.3 + 0.65, 0, 1)           # says ~0.7-0.95 for everything
        metrics = H.calibration_metrics(y, p)
        assert metrics["expected_calibration_error"] > 0.3
        assert metrics["brier_skill_score"] < 0

    def test_base_rate_predictor_has_zero_skill(self):
        rng = np.random.default_rng(2)
        y = (rng.random(2000) < 0.25).astype(int)
        p = np.full(len(y), y.mean())
        assert abs(H.calibration_metrics(y, p)["brier_skill_score"]) < 1e-6

    def test_reliability_bins_are_consistent(self):
        rng = np.random.default_rng(3)
        p = rng.random(1000)
        y = (rng.random(1000) < p).astype(int)
        curve = H.reliability_curve(y, p, n_bins=10)
        assert sum(b["n"] for b in curve["bins"]) == len(y)
        for b in curve["bins"]:
            assert 0.0 <= b["observed_frequency"] <= 1.0


class TestLeakAudit:
    """The seed-echo list is what makes the circularity measurable."""

    def test_seed_echo_features_all_exist(self):
        for name in mlf.SEED_ECHO_FEATURES:
            assert name in mlf.FEATURE_NAMES, name

    def test_seed_echo_covers_the_encoded_command_signature(self):
        """Labels seed on '-enc <base64>'; these features restate exactly that."""
        assert "cmdline_has_encoded_flag" in mlf.SEED_ECHO_FEATURES
        assert "cmdline_longest_b64_run" in mlf.SEED_ECHO_FEATURES
        # Propagation to children is restated by the parent flag.
        assert "parent_cmdline_has_encoded_flag" in mlf.SEED_ECHO_FEATURES

    def test_excluding_seed_echo_leaves_a_usable_feature_set(self):
        remaining = mlf.features_excluding("seed_echo", tier=mlf.TIER_T1)
        assert len(remaining) >= 60
        assert not set(mlf.SEED_ECHO_FEATURES) & set(remaining)


# --------------------------------------------------------------------------- Component C

class TestTacticModel:
    def _tactics(self, counts):
        out = []
        for name, n in counts.items():
            out += [name] * n
        return np.array(out, dtype=object)

    def test_rare_classes_are_collapsed(self):
        tactics = self._tactics({"defense_evasion": 40, "lateral_movement": 20,
                                 "execution": 3, "discovery": 2})
        labels, kept = ml_tactic.collapse_rare_classes(tactics, min_examples=10)
        assert set(kept) == {"defense_evasion", "lateral_movement"}
        assert (labels == ml_tactic.OTHER_CLASS).sum() == 5

    def test_none_tactic_becomes_other(self):
        labels, _ = ml_tactic.collapse_rare_classes(
            np.array(["defense_evasion"] * 12 + [None] * 3, dtype=object))
        assert (labels == ml_tactic.OTHER_CLASS).sum() == 3

    def test_fits_and_suggests(self):
        rng = np.random.default_rng(0)
        n = 90
        tactics = self._tactics({"credential_access": 30, "defense_evasion": 30,
                                 "lateral_movement": 30})
        X = pd.DataFrame({
            "f1": np.concatenate([rng.normal(0, 1, 30), rng.normal(4, 1, 30),
                                  rng.normal(8, 1, 30)]),
            "f2": rng.normal(0, 1, n),
            "dead": np.full(n, np.nan),
        })
        model = ml_tactic.TacticModel(min_examples=10).fit(X, tactics)
        assert "dead" not in model.used_features
        suggestions = model.suggest(X.head(5))
        assert len(suggestions) == 5
        for row in suggestions:
            for item in row:
                assert item["tactic"] in model.classes_
                assert 0.0 <= item["probability"] <= 1.0

    def test_other_is_never_suggested(self):
        """'other' is a bucket for under-supported classes - suggesting it tells nobody
        anything."""
        rng = np.random.default_rng(1)
        tactics = self._tactics({"defense_evasion": 40, "execution": 3, "discovery": 2})
        X = pd.DataFrame({"f1": rng.normal(0, 1, 45), "f2": rng.normal(0, 1, 45)})
        model = ml_tactic.TacticModel(min_examples=10).fit(X, tactics)
        assert ml_tactic.OTHER_CLASS in model.classes_
        for row in model.suggest(X, min_probability=0.0):
            assert all(item["tactic"] != ml_tactic.OTHER_CLASS for item in row)

    def test_low_confidence_yields_no_suggestion(self):
        rng = np.random.default_rng(2)
        tactics = self._tactics({"a_tactic": 30, "b_tactic": 30})
        X = pd.DataFrame({"f1": rng.normal(0, 1, 60), "f2": rng.normal(0, 1, 60)})
        model = ml_tactic.TacticModel(min_examples=10).fit(X, tactics)
        assert all(row == [] for row in model.suggest(X, min_probability=0.99))

    def test_refuses_single_class(self):
        X = pd.DataFrame({"f1": np.arange(20.0), "f2": np.arange(20.0)})
        with pytest.raises(ValueError, match="fewer than two usable classes"):
            ml_tactic.TacticModel().fit(X, np.array(["only_one"] * 20, dtype=object))

    def test_round_trip(self):
        rng = np.random.default_rng(3)
        tactics = self._tactics({"a_tactic": 30, "b_tactic": 30})
        X = pd.DataFrame({"f1": rng.normal(0, 1, 60), "f2": rng.normal(0, 1, 60)})
        model = ml_tactic.TacticModel(min_examples=10).fit(X, tactics)
        revived = ml_tactic.TacticModel.from_payload(model.to_payload())
        assert np.allclose(model.predict_proba(X), revived.predict_proba(X))


# --------------------------------------------------------------------------- host risk

class TestHostRisk:
    def _host(self, conn, hostname="h1"):
        return conn.execute(
            """INSERT INTO hosts (client_id, hostname, os_type, api_key_hash,
                                  enrolled_at_utc, last_seen_utc)
               VALUES (?,?,'windows','x',?,?)""",
            (hostname, hostname, database.now_iso(), database.now_iso())).lastrowid

    def _detect(self, conn, host_id, severity, rule_type="sigma", technique=None,
                tactic=None, ts=None):
        det_id = conn.execute(
            """INSERT INTO detections (host_id, rule_type, rule_name, severity,
                                       technique_id, summary, detected_at_utc)
               VALUES (?,?,?,?,?,'{}',?)""",
            (host_id, rule_type, f"{rule_type} rule", severity, technique,
             ts or database.now_iso())).lastrowid
        if tactic:
            conn.execute(
                "INSERT INTO enriched_detections (detection_id, tactic) VALUES (?,?)",
                (det_id, tactic))
        return det_id

    def test_severity_dominates_the_score(self, tmp_db):
        conn = database.connect(tmp_db)
        try:
            low = self._host(conn, "low-host")
            high = self._host(conn, "high-host")
            self._detect(conn, low, "low")
            self._detect(conn, high, "critical")
            conn.commit()
            assert (ml_risk.compute_host_risk(conn, high)["score"]
                    > ml_risk.compute_host_risk(conn, low)["score"])
        finally:
            conn.close()

    def test_recency_decay_reduces_old_findings(self, tmp_db):
        from datetime import datetime, timedelta, timezone
        conn = database.connect(tmp_db)
        try:
            recent = self._host(conn, "recent")
            old = self._host(conn, "old")
            now = datetime.now(timezone.utc)
            self._detect(conn, recent, "high", ts=now.isoformat())
            self._detect(conn, old, "high",
                         ts=(now - timedelta(days=90)).isoformat())
            conn.commit()
            assert (ml_risk.compute_host_risk(conn, recent, now=now)["score"]
                    > ml_risk.compute_host_risk(conn, old, now=now)["score"])
        finally:
            conn.close()

    def test_tactic_diversity_beats_repetition(self, tmp_db):
        """Three findings across three tactics is a kill chain; three of one is a noisy rule."""
        conn = database.connect(tmp_db)
        try:
            varied = self._host(conn, "varied")
            repeated = self._host(conn, "repeated")
            for tactic in ("execution", "persistence", "credential-access"):
                self._detect(conn, varied, "medium", tactic=tactic)
            for _ in range(3):
                self._detect(conn, repeated, "medium", tactic="execution")
            conn.commit()
            assert (ml_risk.compute_host_risk(conn, varied)["score"]
                    > ml_risk.compute_host_risk(conn, repeated)["score"])
        finally:
            conn.close()

    def test_ml_contribution_is_capped(self, tmp_db):
        """Component A emits a fixed top-K per run; uncapped it would dominate over time."""
        conn = database.connect(tmp_db)
        try:
            host = self._host(conn, "noisy")
            for _ in range(200):
                self._detect(conn, host, "high", rule_type="ml_anomaly")
            conn.commit()
            result = ml_risk.compute_host_risk(conn, host)
            assert result["breakdown"]["ml_anomaly_points"] <= ml_risk.ML_SPIKE_CAP
        finally:
            conn.close()

    def test_ml_findings_do_not_earn_tactic_diversity(self, tmp_db):
        """An ML suggestion inflating a kill-chain signal would be circular."""
        conn = database.connect(tmp_db)
        try:
            host = self._host(conn, "mlhost")
            for tactic in ("execution", "persistence"):
                self._detect(conn, host, "high", rule_type="ml_anomaly", tactic=tactic)
            conn.commit()
            assert ml_risk.compute_host_risk(conn, host)["breakdown"]["distinct_tactics"] == []
        finally:
            conn.close()

    def test_host_with_nothing_scores_zero(self, tmp_db):
        conn = database.connect(tmp_db)
        try:
            host = self._host(conn, "clean")
            conn.commit()
            result = ml_risk.compute_host_risk(conn, host)
            assert result["score"] == 0.0
            assert result["tier"] == "low"
        finally:
            conn.close()

    def test_update_all_persists_and_is_idempotent(self, tmp_db):
        conn = database.connect(tmp_db)
        try:
            host = self._host(conn, "persisted")
            self._detect(conn, host, "critical")
            conn.commit()
            first = ml_risk.update_all(conn)
            second = ml_risk.update_all(conn)
            assert first["hosts_scored"] == second["hosts_scored"] == 1
            assert conn.execute(
                "SELECT COUNT(*) FROM host_risk_scores").fetchone()[0] == 1
            stored = ml_risk.get_host_risk(conn, host)
            assert stored["tier"] in ("low", "medium", "high", "critical")
            assert "detection_points" in stored["breakdown"]
        finally:
            conn.close()

    def test_tiers_are_ordered(self):
        assert ml_risk.tier_for(100) == "critical"
        assert ml_risk.tier_for(25) == "high"
        assert ml_risk.tier_for(10) == "medium"
        assert ml_risk.tier_for(0) == "low"


# --------------------------------------------------------------------------- drift

class TestDrift:
    def test_identical_distributions_are_stable(self):
        rng = np.random.default_rng(0)
        values = rng.normal(0, 1, 2000)
        assert ml_drift.psi_for_feature(values, values.copy()) < ml_drift.PSI_STABLE

    def test_shifted_distribution_is_detected(self):
        rng = np.random.default_rng(1)
        assert ml_drift.psi_for_feature(
            rng.normal(0, 1, 2000), rng.normal(3, 1, 2000)) > ml_drift.PSI_SHIFTED

    def test_missingness_jump_is_detected(self):
        """The signal that matters most operationally: a collector broke."""
        rng = np.random.default_rng(2)
        reference = rng.normal(0, 1, 1000)
        current = reference.copy()
        current[:800] = np.nan                        # 0% -> 80% missing
        assert ml_drift.psi_for_feature(reference, current) > ml_drift.PSI_SHIFTED

    def test_verdict_thresholds(self):
        assert ml_drift.verdict_for(0.05) == "stable"
        assert ml_drift.verdict_for(0.15) == "moderate"
        assert ml_drift.verdict_for(0.50) == "shifted"

    def test_empty_inputs_do_not_crash(self):
        assert ml_drift.psi_for_feature(np.array([]), np.array([1.0])) == 0.0
        assert ml_drift.psi_for_feature(np.array([1.0]), np.array([])) == 0.0

    def test_all_nan_reference_compares_missingness_only(self):
        reference = np.full(100, np.nan)
        current = np.concatenate([np.full(50, np.nan), np.ones(50)])
        assert ml_drift.psi_for_feature(reference, current) == pytest.approx(0.5, abs=0.01)

    def test_compute_drift_reports_every_shared_feature(self):
        rng = np.random.default_rng(3)
        reference = pd.DataFrame({"a": rng.normal(0, 1, 500), "b": rng.normal(0, 1, 500)})
        current = pd.DataFrame({"a": rng.normal(2, 1, 500), "b": rng.normal(0, 1, 500),
                                "c": rng.normal(0, 1, 500)})
        rows = ml_drift.compute_drift(reference, current)
        assert {r["feature"] for r in rows} == {"a", "b"}      # only shared columns
        assert rows[0]["feature"] == "a"                       # worst first
        assert rows[0]["psi"] > rows[1]["psi"]

    def test_summary_flags_retraining(self):
        rows = [{"feature": "x", "psi": 0.9, "verdict": "shifted",
                 "reference_missing_pct": 0, "current_missing_pct": 0}]
        summary = ml_drift.summarise(rows)
        assert summary["retrain_recommended"] is True
        assert summary["counts"]["shifted"] == 1

    def test_record_drift_writes_only_notable_rows(self, tmp_db):
        conn = database.connect(tmp_db)
        try:
            rows = [
                {"feature": "stable_one", "psi": 0.01, "verdict": "stable",
                 "reference_missing_pct": 0, "current_missing_pct": 0},
                {"feature": "shifted_one", "psi": 0.9, "verdict": "shifted",
                 "reference_missing_pct": 0, "current_missing_pct": 0},
            ]
            assert ml_drift.record_drift(conn, None, rows, only_notable=True) == 1
            names = [r[0] for r in conn.execute(
                "SELECT feature_name FROM ml_drift_log")]
            assert names == ["shifted_one"]
        finally:
            conn.close()


# --------------------------------------------------------------------------- API

class TestPhase5Endpoints:
    def test_host_risk_endpoints(self, client, seeded_host):
        assert client.get("/api/v1/ml/host-risk").status_code == 200
        single = client.get(f"/api/v1/ml/host-risk/{seeded_host['host_id']}")
        assert single.status_code == 200
        body = single.json()
        assert body["host_id"] == seeded_host["host_id"]
        # Computed on demand for a host never scored before, rather than 404.
        assert body["persisted"] is False

    def test_host_risk_recompute(self, client, seeded_host):
        response = client.post("/api/v1/ml/host-risk/recompute")
        assert response.status_code == 200
        assert response.json()["hosts_scored"] >= 1

    def test_drift_endpoint_empty(self, client):
        body = client.get("/api/v1/ml/drift").json()
        assert body["count"] == 0
        assert body["retrain_recommended"] is False
        assert "thresholds" in body
