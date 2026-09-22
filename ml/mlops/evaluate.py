"""Offline gates: a challenger must beat the no-ML baselines AND not regress against the
deployed champion, compared on identical rows wherever the data allows it.

docs/ML_MLOPS_PLAN.md 4.6 has the table and the reasoning. Thresholds come from
`config.Policy`; reference numbers come from the artefacts and reports themselves, so no gate
compares against a figure that went stale when something was retrained.

A gate result is one of passed=True, passed=False, or passed=None ("skipped", with the reason,
e.g. no champion to compare against or too few rows). Skipped never blocks; False always does.
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass, field

import numpy as np

from ml.mlops import config, scoring


def _gate(name, passed, value=None, threshold=None, detail="") -> dict:
    return {"gate": name, "passed": passed,
            "value": None if value is None else round(float(value), 4),
            "threshold": None if threshold is None else round(float(threshold), 4),
            "detail": detail}


def _finite(value) -> bool:
    return value is not None and isinstance(value, (int, float)) and math.isfinite(value)


def _pr_auc(report: dict, name: str):
    return ((report.get("results") or {}).get(name) or {}).get("metrics", {}).get("pr_auc")


@dataclass
class EvalContext:
    """Frames shared by every comparison in one run, loaded once."""
    corpus_positives: object = None             # corpus attack rows (never in A's training)
    holdout: object = None                      # live rows inside the cooling-off window
    confirmed: object = None                    # processes analysts confirmed as threats
    notes: dict = field(default_factory=dict)


def build_context(train_db: str, snapshot: str, cooling_off_since: str) -> EvalContext:
    import pandas as pd

    from ml.datasets import assemble as A
    from server import db as database
    from server.engine import ml_features as mlf

    ctx = EvalContext()
    dataset = A.load(train_db, live_db=None, include_local=False)
    if len(dataset):
        ctx.corpus_positives = dataset.frame.loc[
            dataset.y == A.LABEL_MALICIOUS].reset_index(drop=True)

    conn = database.connect(snapshot)
    try:
        real_hosts = A._real_host_ids(conn)
        ctx.holdout = (mlf.extract_process_frame(conn, host_ids=real_hosts,
                                                 since_utc=cooling_off_since)
                       if real_hosts else pd.DataFrame())
        confirmed_ids, confirmed_keys = set(), set()
        from server.engine.ml_integration import _pid_from_summary
        for row in conn.execute(
                """SELECT d.host_id, d.summary, d.ml_explanation FROM detections d
                   JOIN ml_feedback f ON f.detection_id = d.id
                   WHERE f.verdict = 'confirmed' AND d.rule_type = 'ml_anomaly'"""):
            try:
                raw_id = (json.loads(row["ml_explanation"] or "{}") or {}).get("raw_process_id")
            except (TypeError, ValueError):
                raw_id = None
            if raw_id is not None:
                confirmed_ids.add(int(raw_id))
            pid = _pid_from_summary(row["summary"])
            if pid is not None:
                confirmed_keys.add((int(row["host_id"]), pid))
        hosts = sorted({h for h, _ in confirmed_keys})
        if confirmed_ids or hosts:
            frame = mlf.extract_process_frame(conn, host_ids=hosts or None)
            keep = frame["id"].isin(confirmed_ids) | [
                (int(h), int(p)) in confirmed_keys if pd.notna(p) else False
                for h, p in zip(frame["host_id"], frame["pid"])]
            ctx.confirmed = frame.loc[keep].reset_index(drop=True)
        else:
            ctx.confirmed = pd.DataFrame()
    finally:
        conn.close()
    ctx.notes = {"corpus_positives": 0 if ctx.corpus_positives is None else len(ctx.corpus_positives),
                 "holdout_rows": len(ctx.holdout), "confirmed_threats": len(ctx.confirmed)}
    return ctx


def _flag_rate(artefact, frame, floor: float) -> tuple[float, np.ndarray]:
    scores = scoring.score("anomaly", artefact, frame, "t1")
    flags = scores >= floor
    return float(flags.mean()) if len(flags) else float("nan"), flags


def anomaly_gates(report: dict, challenger: dict, champion: dict | None,
                  ctx: EvalContext, policy: config.Policy) -> list[dict]:
    gates = []
    sigma = _pr_auc(report, "baseline:sigma_rules") or 0.0
    single = _pr_auc(report, "baseline:best_single_feature") or 0.0
    bar = max(sigma, single)
    for tier in ("t1", "t2"):
        value = _pr_auc(report, f"anomaly_iforest_{tier}")
        gates.append(_gate(f"A1_{tier}_beats_baselines", _finite(value) and value > bar,
                           value, bar, "CV PR-AUC vs max(Sigma rules, best single feature)"))

    chall = challenger.get("anomaly_t1")
    champ = (champion or {}).get("anomaly_t1")
    value = _pr_auc(report, "anomaly_iforest_t1")
    ref = ((champ or {}).get("metrics") or {}).get("pr_auc")
    if champ is None or not _finite(ref):
        gates.append(_gate("A2_no_ranking_regression", None, value, None,
                           "skipped: no valid champion to compare against"))
    else:
        threshold = ref - policy.anomaly_pr_auc_margin
        gates.append(_gate("A2_no_ranking_regression", _finite(value) and value >= threshold,
                           value, threshold, f"champion CV PR-AUC {ref}"))

    positives = ctx.corpus_positives
    if champ is None or positives is None or len(positives) == 0:
        gates.append(_gate("A3_no_lost_detections", None, detail="skipped: "
                           + ("no champion" if champ is None else "no corpus attacks")))
    else:
        r_chall, f_chall = _flag_rate(chall, positives, policy.anomaly_floor)
        r_champ, f_champ = _flag_rate(champ, positives, policy.anomaly_floor)
        lost, gained = int((f_champ & ~f_chall).sum()), int((~f_champ & f_chall).sum())
        threshold = r_champ - policy.anomaly_recall_margin
        gates.append(_gate("A3_no_lost_detections", r_chall >= threshold, r_chall, threshold,
                           f"recall on {len(positives)} corpus attacks at the {policy.anomaly_floor} "
                           f"floor, paired: champion {r_champ:.3f}; lost {lost}, gained {gained}"))

    holdout = ctx.holdout
    if champ is None or holdout is None or len(holdout) < policy.min_holdout_rows:
        gates.append(_gate("A4_no_alert_flood", None, detail=(
            f"skipped: {0 if holdout is None else len(holdout)} live hold-out rows "
            f"(< {policy.min_holdout_rows})" if champ is not None else "skipped: no champion")))
    else:
        r_chall, _ = _flag_rate(chall, holdout, policy.anomaly_floor)
        r_champ, _ = _flag_rate(champ, holdout, policy.anomaly_floor)
        threshold = max(r_champ * policy.alert_rate_ratio, r_champ + policy.alert_rate_slack)
        gates.append(_gate("A4_no_alert_flood", r_chall <= threshold, r_chall, threshold,
                           f"share of {len(holdout)} unseen live processes over the floor; "
                           f"champion {r_champ:.4f}"))

    confirmed = ctx.confirmed
    if confirmed is None or len(confirmed) < policy.min_confirmed_for_gate:
        gates.append(_gate("A5_confirmed_threats_kept", None, detail=(
            f"skipped: {0 if confirmed is None else len(confirmed)} analyst-confirmed threats "
            f"(< {policy.min_confirmed_for_gate})")))
    else:
        kept, _ = _flag_rate(chall, confirmed, policy.anomaly_floor)
        gates.append(_gate("A5_confirmed_threats_kept", kept >= policy.confirmed_retention,
                           kept, policy.confirmed_retention,
                           f"{len(confirmed)} processes analysts confirmed as threats"))
    return gates


def triage_gates(report: dict, challenger: dict, champion: dict | None,
                 ctx: EvalContext, policy: config.Policy) -> list[dict]:
    gates = []
    bar = max(_pr_auc(report, "baseline:sigma_rules") or 0.0,
              _pr_auc(report, "baseline:best_single_feature") or 0.0)
    for tier in ("t1", "t2"):
        value = _pr_auc(report, f"triage_gbdt_{tier}")
        gates.append(_gate(f"B1_{tier}_beats_baselines", _finite(value) and value > bar,
                           value, bar, "CV PR-AUC vs max(Sigma rules, best single feature)"))
    ece = ((report.get("calibration") or {}).get("t1") or {}).get("expected_calibration_error")
    gates.append(_gate("B2_calibrated", _finite(ece) and ece <= policy.triage_max_ece,
                       ece, policy.triage_max_ece,
                       "expected calibration error; the score is shown to analysts as a %"))

    champ = (champion or {}).get("triage_t1")
    value = _pr_auc(report, "triage_gbdt_t1")
    ref = ((champ or {}).get("metrics") or {}).get("pr_auc")
    ref_ece = ((champ or {}).get("calibration") or {}).get("expected_calibration_error")
    if champ is None or not _finite(ref):
        gates.append(_gate("B3_no_ranking_regression", None, value, None,
                           "skipped: no valid champion"))
    else:
        threshold = ref - policy.triage_pr_auc_margin
        gates.append(_gate("B3_no_ranking_regression", _finite(value) and value >= threshold,
                           value, threshold, f"champion CV PR-AUC {ref}"))
    if champ is not None and _finite(ref_ece) and _finite(ece):
        threshold = ref_ece + policy.triage_ece_margin
        gates.append(_gate("B4_no_calibration_regression", ece <= threshold, ece, threshold,
                           f"champion ECE {ref_ece}"))

    if ctx.holdout is not None and len(ctx.holdout):
        probs = scoring.score("triage", challenger["triage_t1"], ctx.holdout, "t1")
        sane = bool(np.all(np.isfinite(probs)) and probs.min() >= 0 and probs.max() <= 1)
        gates.append(_gate("B5_live_scores_valid", sane, detail=
                           f"{len(probs)} live processes scored; probabilities finite, in [0, 1]"))
    return gates


def tactic_gates(report: dict, challenger: dict, champion: dict | None,
                 ctx: EvalContext, policy: config.Policy) -> list[dict]:
    gates = []
    point = (report.get("gating") or {}).get("shipped_operating_point") or {}
    precision, coverage = point.get("precision"), point.get("coverage")
    gates.append(_gate("C1_precision_floor",
                       _finite(precision) and precision >= policy.tactic_min_precision,
                       precision, policy.tactic_min_precision,
                       "precision when the hint is shown; the UI quotes it to analysts"))
    accuracy, majority = report.get("accuracy"), report.get("majority_class_baseline")
    gates.append(_gate("C2_beats_majority_class",
                       _finite(accuracy) and _finite(majority) and accuracy > majority,
                       accuracy, majority, "CV accuracy vs always predicting the commonest tactic"))
    champ = (champion or {}).get("tactic_t1")
    ref = (((champ or {}).get("metrics") or {}).get("gating") or {}).get(
        "shipped_operating_point") or {}
    if champ is None or not _finite(ref.get("precision")):
        gates.append(_gate("C3_no_precision_regression", None, precision, None,
                           "skipped: no valid champion"))
    else:
        threshold = ref["precision"] - policy.tactic_precision_margin
        gates.append(_gate("C3_no_precision_regression",
                           _finite(precision) and precision >= threshold,
                           precision, threshold, f"champion precision {ref['precision']}"))
        if _finite(ref.get("coverage")):
            threshold = ref["coverage"] * policy.tactic_min_coverage_ratio
            gates.append(_gate("C4_coverage_not_collapsed",
                               _finite(coverage) and coverage >= threshold,
                               coverage, threshold, f"champion coverage {ref['coverage']}"))
    return gates


GATES = {"anomaly": anomaly_gates, "triage": triage_gates, "tactic": tactic_gates}


def evaluate_component(component: str, report: dict, challenger: dict,
                       champion: dict | None, ctx: EvalContext,
                       policy: config.Policy) -> dict:
    try:
        gates = GATES[component](report, challenger, champion, ctx, policy)
    except Exception as exc:                     # noqa: BLE001 - a gate that crashes fails
        gates = [_gate("evaluation_error", False, detail=f"{type(exc).__name__}: {exc}")]
    failed = [g["gate"] for g in gates if g["passed"] is False]
    return {"component": component, "passed": not failed, "failed": failed, "gates": gates,
            "compared_with_champion": champion is not None}


def load_champions(component: str) -> dict | None:
    """The deployed artefacts, through the server's own loader (feature-spec guard included).

    None when the served tier is missing or refused: then there is no valid champion.
    """
    from server.engine import ml_registry

    out = {}
    for name in config.COMPONENT_FILES[component]:
        model_type, tier = name.rsplit("_", 1)
        artefact = ml_registry.load_artefact(model_type, tier)
        if artefact is not None:
            out[name] = artefact
    served = config.COMPONENT_FILES[component][0]
    return out if served in out else None


def equivalent(challenger: dict, champion: dict | None) -> bool:
    """True when the challenger IS the champion: same fitted model, same feature statistics.

    B and C train on the corpus alone, so a week without corpus or code changes retrains them
    into a byte-identical model (verified on the first real run: equal payload hashes for
    triage_t1/t2 and tactic_t1). Trialling it for a week would be churn; it is adopted
    instead, for provenance only - nothing changes for analysts.

    Identity, not similar outputs: comparing scores was tried first and is unsound - anomaly
    percentiles saturate, and on degenerate data two different forests score everything 0.5.
    """
    import joblib

    if not champion or not challenger:
        return False
    for name, artefact in challenger.items():
        other = champion.get(name)
        if other is None or artefact is None:
            return False
        if artefact.get("feature_stats") != other.get("feature_stats"):
            return False
        if artefact.get("feature_spec_sha256") != other.get("feature_spec_sha256"):
            return False
        if joblib.hash(artefact.get("payload")) != joblib.hash(other.get("payload")):
            return False
    return True
