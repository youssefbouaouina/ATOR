"""Phase 10: offline and online promotion gates.

The gate that matters most is A3, "no lost detections": it is what stops a poisoned retrain.
`test_poisoned_challenger_is_blocked` builds exactly that failure - a challenger whose benign
baseline absorbed the attack rows - and checks the gate refuses it.
"""
import json

import numpy as np
import pandas as pd
import pytest

from ml.mlops import config, evaluate, trial
from server import db as database
from server.engine import ml_anomaly, ml_features as mlf

POLICY = config.Policy()


@pytest.fixture(scope="module")
def frames():
    rng = np.random.default_rng(3)
    rows = []
    for i in range(120):
        rows.append({"id": i, "host_id": 1, "collection_id": "c", "pid": 1000 + i, "ppid": 4,
                     "name": "svchost.exe", "cmdline": f"svchost.exe -k netsvcs -s S{i % 7}",
                     "exe_path": r"C:\Windows\System32\svchost.exe",
                     "username": r"NT AUTHORITY\SYSTEM",
                     "collected_at_utc": "2026-09-20T10:00:00+00:00"})
    for i in range(12):
        blob = "".join(rng.choice(list("ABCDEFabcdef0123456789+/"), size=160))
        rows.append({"id": 500 + i, "host_id": 1, "collection_id": "c", "pid": 2000 + i,
                     "ppid": 4, "name": "evil.exe",
                     "cmdline": f"powershell.exe -nop -w hidden -enc {blob}",
                     "exe_path": rf"C:\Users\x\AppData\Local\Temp\e{i}.exe",
                     "username": r"LAB\bob", "collected_at_utc": "2026-09-20T10:00:00+00:00"})
    import sqlite3
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(database.SCHEMA)
    database.migrate(conn)
    conn.execute("INSERT INTO hosts (id, client_id, hostname, os_type, api_key_hash, "
                 "enrolled_at_utc) VALUES (1,'h','H','windows','x','t')")
    for r in rows:
        conn.execute("""INSERT INTO raw_processes (id, host_id, collection_id, collected_at_utc,
                            pid, ppid, name, cmdline, exe_path, username)
                        VALUES (:id,:host_id,:collection_id,:collected_at_utc,:pid,:ppid,:name,
                                :cmdline,:exe_path,:username)""", r)
    frame = mlf.extract_process_frame(conn)
    conn.close()
    benign = frame[frame["name"] == "svchost.exe"].reset_index(drop=True)
    attacks = frame[frame["name"] == "evil.exe"].reset_index(drop=True)
    return frame, benign, attacks


def _artefact(fit_frame, pr_auc=0.55):
    stats = mlf.fit_stats(fit_frame)
    X = mlf.transform(fit_frame, stats=stats, tier=mlf.TIER_T1)
    model = ml_anomaly.AnomalyModel(n_estimators=80, seed=7).fit(X)
    return {"payload": model.to_payload(), "feature_stats": stats.to_dict(),
            "metrics": {"pr_auc": pr_auc}}


def _anomaly_report(t1=0.55, t2=0.56, sigma=0.28, single=0.32):
    return {"results": {
        "anomaly_iforest_t1": {"metrics": {"pr_auc": t1}},
        "anomaly_iforest_t2": {"metrics": {"pr_auc": t2}},
        "baseline:sigma_rules": {"metrics": {"pr_auc": sigma}},
        "baseline:best_single_feature": {"metrics": {"pr_auc": single}}}}


def _by_name(result):
    return {g["gate"]: g for g in result["gates"]}


class TestAnomalyGates:
    def test_a_sound_challenger_passes(self, frames):
        _, benign, attacks = frames
        champion = _artefact(benign)
        challenger = _artefact(benign)
        ctx = evaluate.EvalContext(corpus_positives=attacks)
        result = evaluate.evaluate_component(
            "anomaly", _anomaly_report(), {"anomaly_t1": challenger}, {"anomaly_t1": champion},
            ctx, POLICY)
        assert result["passed"], result["failed"]
        assert "lost 0" in _by_name(result)["A3_no_lost_detections"]["detail"]

    def test_poisoned_challenger_is_blocked(self, frames):
        """The attack rows leaked into the benign baseline: the model now calls them normal."""
        frame, benign, attacks = frames
        champion = _artefact(benign)
        poisoned = _artefact(frame)
        ctx = evaluate.EvalContext(corpus_positives=attacks)
        result = evaluate.evaluate_component(
            "anomaly", _anomaly_report(), {"anomaly_t1": poisoned}, {"anomaly_t1": champion},
            ctx, POLICY)
        assert "A3_no_lost_detections" in result["failed"]

    def test_must_beat_the_rules_already_in_production(self, frames):
        _, benign, _ = frames
        result = evaluate.evaluate_component(
            "anomaly", _anomaly_report(t1=0.25), {"anomaly_t1": _artefact(benign)}, None,
            evaluate.EvalContext(), POLICY)
        assert "A1_t1_beats_baselines" in result["failed"]

    def test_ranking_regression_beyond_margin_fails(self, frames):
        _, benign, _ = frames
        result = evaluate.evaluate_component(
            "anomaly", _anomaly_report(t1=0.50), {"anomaly_t1": _artefact(benign)},
            {"anomaly_t1": _artefact(benign, pr_auc=0.55)}, evaluate.EvalContext(), POLICY)
        assert "A2_no_ranking_regression" in result["failed"]

    def test_without_a_champion_comparisons_are_skipped_not_failed(self, frames):
        _, benign, attacks = frames
        result = evaluate.evaluate_component(
            "anomaly", _anomaly_report(), {"anomaly_t1": _artefact(benign)}, None,
            evaluate.EvalContext(corpus_positives=attacks), POLICY)
        assert result["passed"]
        gates = _by_name(result)
        assert gates["A2_no_ranking_regression"]["passed"] is None
        assert gates["A3_no_lost_detections"]["passed"] is None

    def test_alert_flood_on_live_holdout_fails(self, frames, monkeypatch):
        _, benign, _ = frames
        rates = iter([(0.20, None), (0.02, None)])           # challenger, then champion
        monkeypatch.setattr(evaluate, "_flag_rate", lambda *a: next(rates))
        ctx = evaluate.EvalContext(holdout=pd.DataFrame({"x": range(200)}))
        result = evaluate.evaluate_component(
            "anomaly", _anomaly_report(), {"anomaly_t1": {}}, {"anomaly_t1": {"metrics": {}}},
            ctx, POLICY)
        assert "A4_no_alert_flood" in result["failed"]

    def test_small_holdout_is_skipped(self, frames):
        _, benign, _ = frames
        ctx = evaluate.EvalContext(holdout=benign.head(10))
        result = evaluate.evaluate_component(
            "anomaly", _anomaly_report(), {"anomaly_t1": _artefact(benign)},
            {"anomaly_t1": _artefact(benign)}, ctx, POLICY)
        assert _by_name(result)["A4_no_alert_flood"]["passed"] is None

    def test_analyst_confirmed_threats_must_still_be_caught(self, frames):
        frame, benign, attacks = frames
        ctx = evaluate.EvalContext(confirmed=attacks)
        good = evaluate.evaluate_component(
            "anomaly", _anomaly_report(), {"anomaly_t1": _artefact(benign)}, None, ctx, POLICY)
        assert _by_name(good)["A5_confirmed_threats_kept"]["passed"] is True
        bad = evaluate.evaluate_component(
            "anomaly", _anomaly_report(), {"anomaly_t1": _artefact(frame)}, None, ctx, POLICY)
        assert "A5_confirmed_threats_kept" in bad["failed"]

    def test_a_crashing_gate_fails_closed(self):
        result = evaluate.evaluate_component("anomaly", {}, {}, None, evaluate.EvalContext(),
                                             POLICY)
        assert not result["passed"]


class TestTriageAndTacticGates:
    REPORT = {"results": {"triage_gbdt_t1": {"metrics": {"pr_auc": 0.93}},
                          "triage_gbdt_t2": {"metrics": {"pr_auc": 0.93}},
                          "baseline:sigma_rules": {"metrics": {"pr_auc": 0.28}},
                          "baseline:best_single_feature": {"metrics": {"pr_auc": 0.32}}},
              "calibration": {"t1": {"expected_calibration_error": 0.016}}}

    def test_triage_passes_and_rejects_miscalibration(self):
        ok = evaluate.evaluate_component("triage", self.REPORT, {}, None, evaluate.EvalContext(),
                                         POLICY)
        assert ok["passed"], ok["failed"]
        bad = json.loads(json.dumps(self.REPORT))
        bad["calibration"]["t1"]["expected_calibration_error"] = 0.09
        assert "B2_calibrated" in evaluate.evaluate_component(
            "triage", bad, {}, None, evaluate.EvalContext(), POLICY)["failed"]

    def test_triage_calibration_regression_vs_champion(self):
        champion = {"triage_t1": {"metrics": {"pr_auc": 0.93},
                                  "calibration": {"expected_calibration_error": 0.010}}}
        report = json.loads(json.dumps(self.REPORT))
        report["calibration"]["t1"]["expected_calibration_error"] = 0.045
        result = evaluate.evaluate_component("triage", report, {}, champion,
                                             evaluate.EvalContext(), POLICY)
        assert "B4_no_calibration_regression" in result["failed"]

    def _tactic(self, precision, coverage=0.34, accuracy=0.52):
        return {"gating": {"shipped_operating_point": {"precision": precision,
                                                       "coverage": coverage}},
                "accuracy": accuracy, "majority_class_baseline": 0.40}

    def test_tactic_precision_floor_and_regression(self):
        assert evaluate.evaluate_component("tactic", self._tactic(0.80), {}, None,
                                           evaluate.EvalContext(), POLICY)["passed"]
        assert "C1_precision_floor" in evaluate.evaluate_component(
            "tactic", self._tactic(0.65), {}, None, evaluate.EvalContext(), POLICY)["failed"]
        champion = {"tactic_t1": {"metrics": self._tactic(0.80)}}
        result = evaluate.evaluate_component("tactic", self._tactic(0.72, coverage=0.1), {},
                                             champion, evaluate.EvalContext(), POLICY)
        assert set(result["failed"]) == {"C3_no_precision_regression",
                                         "C4_coverage_not_collapsed"}


def _evidence(**overrides):
    base = {"active_hours": 30, "passes": 500, "processes_scored": 4000, "errors": 0,
            "error_rate": 0.0, "champion_ms_mean": 40.0, "challenger_ms_mean": 45.0,
            "challenger_ms_max": 90.0, "last_error": None, "champion_flagged": 20,
            "challenger_flagged": 22, "both_flagged": 15, "rule_corroborated": {}}
    base.update(overrides)
    return base


class TestOnlineGates:
    def test_healthy_trial_passes(self):
        assert trial.online_gates(_evidence(), POLICY)[0] == "pass"

    def test_too_little_evidence_is_inconclusive(self):
        assert trial.online_gates(_evidence(active_hours=5), POLICY)[0] == "inconclusive"
        assert trial.online_gates(_evidence(processes_scored=50), POLICY)[0] == "inconclusive"

    def test_errors_fail_even_with_little_evidence(self):
        verdict, _ = trial.online_gates(_evidence(active_hours=2, errors=3, passes=10,
                                                  error_rate=0.3), POLICY)
        assert verdict == "fail"

    def test_alert_flood_fails(self):
        assert trial.online_gates(_evidence(challenger_flagged=60), POLICY)[0] == "fail"
        # small numbers get an absolute allowance: 0 -> 4 is not a "flood"
        assert trial.online_gates(_evidence(champion_flagged=0, challenger_flagged=4),
                                  POLICY)[0] == "pass"

    def test_slow_challenger_fails(self):
        assert trial.online_gates(_evidence(challenger_ms_mean=900.0), POLICY)[0] == "fail"


class TestEvidence:
    def test_aggregates_observations_flags_and_rule_corroboration(self, tmp_db, seeded_host):
        conn = database.connect(tmp_db)
        host = seeded_host["host_id"]
        tid = conn.execute("""INSERT INTO ml_shadow_trials (version_id, components_json,
                                  started_at_utc, status) VALUES ('v', '["anomaly"]', 't',
                                  'running')""").lastrowid
        for hour, errors in (("2026-09-20T10:00:00+00:00", 0), ("2026-09-20T11:00:00+00:00", 1)):
            conn.execute("""INSERT INTO ml_shadow_observations (trial_id, hour_utc, passes,
                                processes_scored, errors, champion_ms_total, challenger_ms_total,
                                challenger_ms_max) VALUES (?,?,10,500,?,100,150,30)""",
                         (tid, hour, errors))
        for key, pid, a, b in (("k1", 11, 1, 1), ("k2", 12, 1, 0), ("k3", 13, 0, 1)):
            conn.execute("""INSERT INTO ml_shadow_flags (trial_id, process_key, host_id, pid,
                                champion_flag, challenger_flag, first_seen_utc)
                            VALUES (?,?,?,?,?,?,'t')""", (tid, key, host, pid, a, b))
        conn.execute("""INSERT INTO detections (host_id, rule_type, rule_name, severity, summary,
                            detected_at_utc) VALUES (?, 'sigma', 'r', 'high', '{"pid": "13"}', 't')""",
                     (host,))
        conn.commit()
        ev = trial.evidence(conn, tid)
        conn.close()
        assert ev["active_hours"] == 2 and ev["passes"] == 20 and ev["errors"] == 1
        assert ev["processes_scored"] == 1000
        assert (ev["champion_flagged"], ev["challenger_flagged"], ev["both_flagged"]) == (2, 2, 1)
        assert ev["rule_corroborated"] == {"champion": 0, "challenger": 1}
        assert ev["challenger_ms_mean"] == pytest.approx(300 / 19)


class TestEquivalence:
    """Adopting a retrain without a trial is only safe if it is the SAME model."""

    def _triage(self, seed):
        from server.engine import ml_triage
        rng = np.random.default_rng(0)
        X = pd.DataFrame(rng.normal(size=(200, 4)), columns=list("abcd"))
        y = (X["a"] + rng.normal(scale=0.5, size=200) > 0.8).astype(int).to_numpy()
        model = ml_triage.TriageModel(seed=seed).fit(X, y)
        return {"payload": model.to_payload(), "feature_stats": {"s": 1},
                "feature_spec_sha256": "x"}

    def test_identical_fit_is_equivalent(self):
        assert evaluate.equivalent({"triage_t1": self._triage(1)},
                                   {"triage_t1": self._triage(1)})

    def test_different_fit_is_not(self):
        assert not evaluate.equivalent({"triage_t1": self._triage(1)},
                                       {"triage_t1": self._triage(2)})

    def test_different_feature_statistics_are_not(self):
        other = self._triage(1)
        other["feature_stats"] = {"s": 2}
        assert not evaluate.equivalent({"triage_t1": self._triage(1)}, {"triage_t1": other})

    def test_no_champion_is_not_equivalent(self):
        assert not evaluate.equivalent({"triage_t1": self._triage(1)}, None)

    def test_tree_models_are_never_falsely_equivalent(self, frames):
        """sklearn tree nodes pickle their uninitialised struct padding, so two identical
        IsolationForest fits may or may not hash equal. Either outcome is safe - equal bytes
        ARE the same model; unequal just means a trial - but a different forest must never
        be taken for the champion."""
        from ml.mlops import scoring
        _, benign, attacks = frames
        a, b = _artefact(benign), _artefact(benign)
        if evaluate.equivalent({"anomaly_t1": a}, {"anomaly_t1": b}):
            np.testing.assert_array_equal(
                scoring.score("anomaly", a, attacks, "t1", raw=True),
                scoring.score("anomaly", b, attacks, "t1", raw=True))
        stats = mlf.fit_stats(benign)
        X = mlf.transform(benign, stats=stats, tier=mlf.TIER_T1)
        other = {"payload": ml_anomaly.AnomalyModel(n_estimators=80, seed=8).fit(X).to_payload(),
                 "feature_stats": stats.to_dict()}
        assert not evaluate.equivalent({"anomaly_t1": a}, {"anomaly_t1": other})
