"""Evaluation protocol for Layer 4.5 ML.

Fixed **before** any model is trained, so metrics cannot be shopped for after the fact.

Why these metrics and not accuracy
----------------------------------
The positive rate is 8.2%. A classifier that always answers "benign" scores 91.8% accuracy
and is worthless. Worse, ROC-AUC flatters detectors in exactly the regime security cares
least about - an analyst does not operate at 50% false-positive rate. So the headline numbers
are low-false-positive-regime numbers:

* **recall @ fixed FPR** (1%, 0.5%, 0.1%) - "if the analyst tolerates 1 false alert per 100
  benign processes, what fraction of attacks do we catch?"
* **FP per 1,000 benign processes @ fixed recall** - the same trade-off read the other way.
* **PR-AUC** (average precision) - the right summary under class imbalance.
* **alerts per host snapshot** - FP rate x the real mean process count of a live sweep (270
  processes, measured from the two local collections). Concrete for an analyst.

Deliberately NOT reported: "false positives per host per day". The corpus captures span
minutes of unusually dense activity, so any per-day figure would be an extrapolation from a
non-representative event rate - a fabricated number dressed as a measurement. Per-1,000-
processes is what this data actually supports, and it converts to a per-day figure for anyone
who knows their own fleet's process-creation rate.

Splitting and uncertainty
-------------------------
`GroupKFold` over captures: every row of one capture lands in one fold. Random row-level
splits would place sibling processes of the same attack on both sides - the model would then
recognise the capture, not the behaviour.

Confidence intervals come from a **group** bootstrap (resampling captures, not rows). Rows
within a capture are strongly correlated, so a row bootstrap would report intervals several
times too narrow. With 185 positives over 107 groups, intervals are wide and saying so is
part of the result.

Mandatory baselines (ML_ARCHITECTURE section 7.3)
-------------------------------------------------
1. **chance** - sanity floor.
2. **the existing Sigma rules**, run over the same rows. This is the comparison that
   matters: the question is not "is the model good?" but *"does it find anything the
   deterministic engine already in production does not?"*
3. **the single best individual feature**, selected inside each training fold. Guards against
   a 98-feature model that a one-line threshold would have matched.
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass, field

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.model_selection import GroupKFold

from ml.datasets import assemble as A
from server.engine import ml_features as mlf

RANDOM_SEED = 42

# Mean process count of a real live agent sweep, measured from the two local collections in
# ator_dfir.db (256 and 282 rows). Used only to express a false-positive rate as "alerts an
# analyst would see per host snapshot".
MEAN_PROCESSES_PER_SNAPSHOT = 270

# False-positive rates an analyst might actually tolerate.
FPR_TARGETS = (0.01, 0.005, 0.001)
# Recall levels at which to report the cost in false positives.
RECALL_TARGETS = (0.5, 0.7, 0.9)


# --------------------------------------------------------------------------- metrics

def recall_at_fpr(y: np.ndarray, scores: np.ndarray, target_fpr: float) -> dict:
    """Recall when the threshold is set to the highest FPR not exceeding `target_fpr`."""
    benign = scores[y == A.LABEL_BENIGN]
    positive = scores[y == A.LABEL_MALICIOUS]
    if len(benign) == 0 or len(positive) == 0:
        return {"recall": float("nan"), "threshold": float("nan"), "actual_fpr": float("nan")}
    # Threshold at the (1 - target_fpr) quantile of benign scores; >= threshold alerts.
    threshold = float(np.quantile(benign, 1.0 - target_fpr))
    actual_fpr = float((benign >= threshold).mean())
    return {
        "recall": float((positive >= threshold).mean()),
        "threshold": threshold,
        "actual_fpr": actual_fpr,
    }


def fp_cost_at_recall(y: np.ndarray, scores: np.ndarray, target_recall: float) -> dict:
    """False positives per 1,000 benign processes at a threshold achieving `target_recall`."""
    benign = scores[y == A.LABEL_BENIGN]
    positive = scores[y == A.LABEL_MALICIOUS]
    if len(benign) == 0 or len(positive) == 0:
        return {"fp_per_1000_benign": float("nan"), "threshold": float("nan"),
                "actual_recall": float("nan"), "alerts_per_host_snapshot": float("nan")}
    threshold = float(np.quantile(positive, 1.0 - target_recall))
    fpr = float((benign >= threshold).mean())
    return {
        "threshold": threshold,
        "actual_recall": float((positive >= threshold).mean()),
        "fp_per_1000_benign": round(fpr * 1000, 2),
        "alerts_per_host_snapshot": round(fpr * MEAN_PROCESSES_PER_SNAPSHOT, 2),
    }


def precision_at_k(y: np.ndarray, scores: np.ndarray, k: int) -> float:
    """Precision in the top-k highest-scoring rows - an analyst's triage queue."""
    if k <= 0 or len(scores) == 0:
        return float("nan")
    k = min(k, len(scores))
    top = np.argsort(scores)[::-1][:k]
    return float((y[top] == A.LABEL_MALICIOUS).mean())


def core_metrics(y: np.ndarray, scores: np.ndarray) -> dict:
    """Every headline number for one set of scores."""
    y = np.asarray(y)
    scores = np.asarray(scores, dtype="float64")
    finite = np.isfinite(scores)
    if not finite.all():
        # A non-finite score would silently corrupt every ranking metric.
        scores = np.where(finite, scores, np.nanmin(scores[finite]) if finite.any() else 0.0)

    n_pos = int((y == A.LABEL_MALICIOUS).sum())
    n_neg = int((y == A.LABEL_BENIGN).sum())
    out: dict = {"n": int(len(y)), "n_positive": n_pos, "n_benign": n_neg,
                 "positive_rate": round(n_pos / max(len(y), 1), 4)}
    if n_pos == 0 or n_neg == 0:
        out["roc_auc"] = float("nan")
        out["pr_auc"] = float("nan")
        return out

    out["roc_auc"] = round(float(roc_auc_score(y, scores)), 4)
    out["pr_auc"] = round(float(average_precision_score(y, scores)), 4)
    # A PR-AUC only just above the positive rate is chance dressed up.
    out["pr_auc_lift_over_chance"] = round(out["pr_auc"] / max(out["positive_rate"], 1e-9), 2)

    # A binary scorer (a rule set: fired / did not fire) has no ranking to threshold. Asking
    # for "recall at 1% FPR" then produces a number that looks excellent and means nothing:
    # if every benign row scores 0, the 99th-percentile threshold IS 0, "score >= 0" matches
    # everything, and recall comes back as 1.0 at an actual FPR of 100%. Same for
    # precision@k, which would be decided by how argsort happens to break ties.
    #
    # So these are reported as NaN for binary scorers, and the confusion matrix
    # (precision/recall at the rule's own operating point) is the honest summary instead.
    out["distinct_scores"] = int(len(np.unique(scores)))
    out["binary_scorer"] = bool(out["distinct_scores"] <= 2)

    for fpr in FPR_TARGETS:
        res = recall_at_fpr(y, scores, fpr)
        out[f"recall_at_fpr_{fpr}"] = (
            float("nan") if out["binary_scorer"] else round(res["recall"], 4))
        # Always surface the FPR actually achieved: when ties straddle the threshold, the
        # requested FPR and the delivered one differ, and the reader must be able to see it.
        out[f"actual_fpr_at_{fpr}"] = round(res["actual_fpr"], 5)
    for rec in RECALL_TARGETS:
        res = fp_cost_at_recall(y, scores, rec)
        out[f"fp_per_1000_at_recall_{rec}"] = (
            float("nan") if out["binary_scorer"] else res["fp_per_1000_benign"])
        out[f"alerts_per_snapshot_at_recall_{rec}"] = (
            float("nan") if out["binary_scorer"] else res["alerts_per_host_snapshot"])
    for k in (10, 25, 50):
        out[f"precision_at_{k}"] = (
            float("nan") if out["binary_scorer"] else round(precision_at_k(y, scores, k), 4))
    return out


# --------------------------------------------------------------------------- uncertainty

def group_bootstrap_ci(y: np.ndarray, scores: np.ndarray, groups: np.ndarray,
                       metric: str = "pr_auc", n_boot: int = 1000,
                       alpha: float = 0.05, seed: int = RANDOM_SEED) -> dict:
    """Percentile CI for one metric, resampling whole groups with replacement.

    Resampling rows would treat 15 processes from one attack as 15 independent observations
    and produce intervals far narrower than the evidence supports.
    """
    rng = np.random.default_rng(seed)
    unique = np.array(sorted(set(groups)))
    index_by_group = {g: np.flatnonzero(groups == g) for g in unique}
    values: list[float] = []
    for _ in range(n_boot):
        picked = rng.choice(unique, size=len(unique), replace=True)
        idx = np.concatenate([index_by_group[g] for g in picked])
        y_b, s_b = y[idx], scores[idx]
        if (y_b == A.LABEL_MALICIOUS).sum() == 0 or (y_b == A.LABEL_BENIGN).sum() == 0:
            continue                      # a resample with one class tells us nothing
        m = core_metrics(y_b, s_b).get(metric)
        if m is not None and np.isfinite(m):
            values.append(float(m))
    if not values:
        return {"metric": metric, "lo": float("nan"), "hi": float("nan"), "n_boot": 0}
    return {
        "metric": metric,
        "lo": round(float(np.quantile(values, alpha / 2)), 4),
        "hi": round(float(np.quantile(values, 1 - alpha / 2)), 4),
        "median": round(float(np.median(values)), 4),
        "n_boot": len(values),
    }


# --------------------------------------------------------------------------- CV driver

@dataclass
class CvResult:
    name: str
    scores: np.ndarray                     # out-of-fold, aligned to the dataset
    metrics: dict = field(default_factory=dict)
    ci: dict = field(default_factory=dict)
    per_fold: list = field(default_factory=list)
    extra: dict = field(default_factory=dict)


def corpus_eval_mask(dataset: A.Dataset) -> np.ndarray:
    """Rows on which ranking metrics may honestly be computed.

    **Why ranking is scored on corpus rows only.**

    Every positive lives in the corpus; the local rows are 100% benign. So *any* feature that
    distinguishes the two sources hands the model a free "this one cannot be an attack" signal.
    And one does, perfectly: `sysmon_available` is 1.000 on corpus rows and 0.000 on local ones
    (Sysmon is not installed on the live endpoints). `cmdline_present` leaks the same way, at
    1.000 vs 0.725.

    Left unchecked, the model earns credit for discarding 538 trivially-identifiable negatives,
    and every ranking metric is inflated. Restricting ranking metrics to corpus rows removes
    the confound: within the corpus, source carries no information about the label.

    The local rows still do real work - they are fitted into the benign baseline (which is how
    the model learns the `cmdline_present=0` pattern that 27% of live processes exhibit) and
    they provide an independent false-positive measurement via `local_fp_report`.
    """
    return dataset.sources == A.SOURCE_CORPUS


def local_fp_report(dataset: A.Dataset, scores: np.ndarray,
                    threshold_source: str = "corpus") -> dict:
    """False positives on genuine live benign telemetry.

    This is the operationally meaningful false-positive number: the local rows are real
    endpoint processes from a machine nobody is attacking, and they took no part in choosing
    the threshold. The threshold itself is derived from corpus benign rows.
    """
    local = dataset.sources == A.SOURCE_LOCAL
    corpus_benign = (dataset.sources == A.SOURCE_CORPUS) & (dataset.y == A.LABEL_BENIGN)
    if local.sum() == 0 or corpus_benign.sum() == 0:
        return {"n_local": int(local.sum()), "note": "no local benign rows available"}

    out = {"n_local": int(local.sum()), "threshold_source": threshold_source}
    for fpr in FPR_TARGETS:
        thr = float(np.quantile(scores[corpus_benign], 1.0 - fpr))
        flagged = int((scores[local] >= thr).sum())
        out[f"at_corpus_fpr_{fpr}"] = {
            "threshold": round(thr, 6),
            "local_flagged": flagged,
            "local_fp_rate": round(flagged / int(local.sum()), 4),
            "alerts_per_host_snapshot": round(
                flagged / int(local.sum()) * MEAN_PROCESSES_PER_SNAPSHOT, 2),
        }
    return out


def grouped_cv(dataset: A.Dataset, fit_score, tier: str = mlf.TIER_T2,
               n_splits: int = 5, name: str = "model",
               benign_only_fit: bool = True,
               feature_subset: list[str] | None = None,
               eval_mask: np.ndarray | None = None) -> CvResult:
    """Out-of-fold scoring with fold-local feature statistics.

    `fit_score(X_train, y_train, X_test) -> scores_test`.

    `benign_only_fit=True` passes only the benign training rows, which is the right contract
    for novelty detection: learn what normal looks like, then flag deviation. Supervised
    models pass False and receive both classes.

    `feature_subset` restricts the columns, for leave-one-group-out ablation.

    `eval_mask` restricts which rows the reported metrics are computed on. Scoring still
    covers everything (so `local_fp_report` can use the same scores), but ranking metrics are
    confined to rows where source carries no label information - see `corpus_eval_mask`.

    Rarity statistics are fitted inside each fold (never on the whole dataset), so the
    reported numbers are not inflated by the test folds' name distribution.
    """
    y = dataset.y
    groups = dataset.groups
    n_splits = min(n_splits, len(set(groups)))
    splitter = GroupKFold(n_splits=n_splits)
    oof = np.full(len(y), np.nan)
    per_fold = []

    for fold, (train_idx, test_idx) in enumerate(
            splitter.split(np.zeros(len(y)), y, groups)):
        train_mask = np.zeros(len(y), dtype=bool)
        train_mask[train_idx] = True
        X, _ = A.materialise(dataset, train_mask=train_mask, tier=tier)
        if feature_subset is not None:
            X = X[[c for c in feature_subset if c in X.columns]]

        X_train = X.iloc[train_idx]
        y_train = y[train_idx]
        if benign_only_fit:
            keep = y_train == A.LABEL_BENIGN
            X_train, y_train = X_train[keep], y_train[keep]

        scores = fit_score(X_train, y_train, X.iloc[test_idx])
        oof[test_idx] = np.asarray(scores, dtype="float64")

        fold_eval = test_idx if eval_mask is None else test_idx[eval_mask[test_idx]]
        if len(fold_eval) and len(set(y[fold_eval])) > 1:
            fold_metrics = core_metrics(y[fold_eval], oof[fold_eval])
            per_fold.append({"fold": fold, "n_train": int(len(X_train)),
                             "n_eval": int(len(fold_eval)), **{
                                 k: fold_metrics[k] for k in
                                 ("roc_auc", "pr_auc", "recall_at_fpr_0.01")
                                 if k in fold_metrics}})

    keep = np.ones(len(y), dtype=bool) if eval_mask is None else np.asarray(eval_mask)
    result = CvResult(name=name, scores=oof)
    result.metrics = core_metrics(y[keep], oof[keep])
    result.ci = {
        "pr_auc": group_bootstrap_ci(y[keep], oof[keep], groups[keep], "pr_auc"),
        "roc_auc": group_bootstrap_ci(y[keep], oof[keep], groups[keep], "roc_auc"),
        "recall_at_fpr_0.01": group_bootstrap_ci(
            y[keep], oof[keep], groups[keep], "recall_at_fpr_0.01"),
    }
    result.per_fold = per_fold
    result.extra["eval_rows"] = int(keep.sum())
    result.extra["n_features"] = (len(feature_subset) if feature_subset is not None
                                  else (len(mlf.FEATURE_NAMES) if tier == mlf.TIER_T2
                                        else len(mlf.T1_FEATURES)))
    return result


# --------------------------------------------------------------------------- baselines

def chance_baseline(dataset: A.Dataset, seed: int = RANDOM_SEED,
                    eval_mask: np.ndarray | None = None) -> CvResult:
    """Uniform random scores. PR-AUC should land near the positive rate."""
    rng = np.random.default_rng(seed)
    scores = rng.random(len(dataset))
    keep = np.ones(len(dataset), dtype=bool) if eval_mask is None else np.asarray(eval_mask)
    res = CvResult(name="baseline:chance", scores=scores)
    res.metrics = core_metrics(dataset.y[keep], scores[keep])
    res.ci = {"pr_auc": group_bootstrap_ci(
        dataset.y[keep], scores[keep], dataset.groups[keep], "pr_auc")}
    return res


def sigma_baseline(dataset: A.Dataset, train_db: str, rules_dir: str | None = None,
                   eval_mask: np.ndarray | None = None) -> CvResult:
    """The deployed Sigma rules, run over the same corpus rows.

    Scores are binary (1 = at least one rule fired on this process row), so ranking metrics
    are coarse by nature. That is a property of rules, not a measurement artefact, and it is
    the point of the comparison: rules give a yes/no, a model gives a ranking.

    Only corpus rows can be scored - the Sigma runner reads the training database - so live
    rows are left at 0 (no rule fired), which is what the production engine would also record
    for them.
    """
    from server import db as database
    from server.engine.sigma_runner import run as sigma_run

    conn = database.connect(train_db)
    try:
        fired, errors = sigma_run(conn, rules_dir=rules_dir)
    finally:
        conn.close()

    hit_process_ids, by_rule = set(), {}
    for hit in fired:
        evidence = hit.get("evidence") or {}
        by_rule[hit["rule_name"]] = by_rule.get(hit["rule_name"], 0) + 1
        if evidence.get("table") == "raw_processes" and evidence.get("row_id") is not None:
            hit_process_ids.add(int(evidence["row_id"]))

    row_ids = dataset.frame.get("id")
    scores = np.array([
        1.0 if (rid is not None and not pd.isna(rid) and int(rid) in hit_process_ids) else 0.0
        for rid in (row_ids if row_ids is not None else [])
    ], dtype="float64")
    if len(scores) != len(dataset):
        scores = np.zeros(len(dataset))

    # The runner caps each rule at 200 rows; a rule at the cap means the baseline is
    # truncated and its recall understated. Surface it rather than let it pass silently.
    truncated = sorted(r for r, n in by_rule.items() if n >= 200)

    keep = np.ones(len(dataset), dtype=bool) if eval_mask is None else np.asarray(eval_mask)
    res = CvResult(name="baseline:sigma_rules", scores=scores)
    res.metrics = core_metrics(dataset.y[keep], scores[keep])
    res.extra = {
        "rules_fired": by_rule,
        "total_hits": len(fired),
        "process_rows_flagged": int(scores.sum()),
        "rule_errors": errors[:10],
        "rules_hitting_200_row_cap": truncated,
    }
    # Rules are deterministic, so confusion-matrix terms are more informative than AUC.
    y = dataset.y[keep]
    flagged = scores[keep] > 0
    res.extra["confusion"] = {
        "tp": int(((y == A.LABEL_MALICIOUS) & flagged).sum()),
        "fp": int(((y == A.LABEL_BENIGN) & flagged).sum()),
        "fn": int(((y == A.LABEL_MALICIOUS) & ~flagged).sum()),
        "tn": int(((y == A.LABEL_BENIGN) & ~flagged).sum()),
    }
    c = res.extra["confusion"]
    res.extra["precision"] = round(c["tp"] / max(c["tp"] + c["fp"], 1), 4)
    res.extra["recall"] = round(c["tp"] / max(c["tp"] + c["fn"], 1), 4)
    return res


def best_single_feature_baseline(dataset: A.Dataset, tier: str = mlf.TIER_T1,
                                 n_splits: int = 5,
                                 feature_subset: list[str] | None = None,
                                 eval_mask: np.ndarray | None = None) -> CvResult:
    """The strongest individual feature, chosen inside each training fold.

    Selecting the feature on the whole dataset would leak; doing it per fold is what makes
    this a fair opponent. If a 98-feature model cannot beat one hand-picked column, the model
    is not earning its complexity.
    """
    y, groups = dataset.y, dataset.groups
    n_splits = min(n_splits, len(set(groups)))
    splitter = GroupKFold(n_splits=n_splits)
    oof = np.full(len(y), np.nan)
    chosen: list[str] = []

    for train_idx, test_idx in splitter.split(np.zeros(len(y)), y, groups):
        train_mask = np.zeros(len(y), dtype=bool)
        train_mask[train_idx] = True
        X, _ = A.materialise(dataset, train_mask=train_mask, tier=tier)
        if feature_subset is not None:
            X = X[[c for c in feature_subset if c in X.columns]]
        X_train, y_train = X.iloc[train_idx], y[train_idx]

        best_name, best_auc, best_sign = None, 0.5, 1.0
        for col in X_train.columns:
            values = X_train[col].to_numpy()
            ok = np.isfinite(values)
            if ok.sum() < 30 or len(set(y_train[ok])) < 2:
                continue
            try:
                auc = roc_auc_score(y_train[ok], values[ok])
            except ValueError:
                continue
            # A feature can be informative by pointing the other way.
            sign = 1.0 if auc >= 0.5 else -1.0
            auc = max(auc, 1.0 - auc)
            if auc > best_auc:
                best_name, best_auc, best_sign = col, auc, sign

        if best_name is None:
            oof[test_idx] = 0.0
            chosen.append("none")
            continue
        chosen.append(f"{best_name}({best_auc:.3f})")
        col_values = X[best_name].to_numpy()[test_idx] * best_sign
        median = np.nanmedian(X[best_name].to_numpy()[train_idx]) * best_sign
        oof[test_idx] = np.where(np.isfinite(col_values), col_values, median)

    keep = np.ones(len(y), dtype=bool) if eval_mask is None else np.asarray(eval_mask)
    res = CvResult(name="baseline:best_single_feature", scores=oof)
    res.metrics = core_metrics(y[keep], oof[keep])
    res.ci = {"pr_auc": group_bootstrap_ci(y[keep], oof[keep], groups[keep], "pr_auc")}
    res.extra = {"selected_per_fold": chosen}
    return res


# --------------------------------------------------------------------------- reporting

_HEADLINE = ("pr_auc", "pr_auc_lift_over_chance", "roc_auc",
             "recall_at_fpr_0.01", "recall_at_fpr_0.001",
             "fp_per_1000_at_recall_0.7", "alerts_per_snapshot_at_recall_0.7",
             "precision_at_25")


def comparison_table(results: list[CvResult]) -> pd.DataFrame:
    rows = []
    for res in results:
        row = {"model": res.name}
        for key in _HEADLINE:
            row[key] = res.metrics.get(key)
        ci = (res.ci or {}).get("pr_auc") or {}
        row["pr_auc_ci"] = (f"[{ci.get('lo')}, {ci.get('hi')}]"
                            if ci.get("lo") is not None else "")
        rows.append(row)
    return pd.DataFrame(rows)


def print_report(results: list[CvResult], title: str = "Evaluation") -> None:
    print("=" * 96)
    print(title)
    print("=" * 96)
    table = comparison_table(results)
    print(table.to_string(index=False))
    print("\nlegend: pr_auc = average precision (chance = positive rate); "
          "recall_at_fpr_X = recall when FPR is held at X;")
    print("        fp_per_1000_at_recall_0.7 = false positives per 1,000 benign processes "
          "at 70% recall;")
    print("        alerts_per_snapshot = the same, scaled to a real "
          f"{MEAN_PROCESSES_PER_SNAPSHOT}-process agent sweep.")
    for res in results:
        if res.extra:
            print(f"\n--- {res.name} details ---")
            print(json.dumps(res.extra, indent=2, default=str)[:1800])


# --------------------------------------------------------------------------- complementarity

def sigma_complementarity(dataset: A.Dataset, sigma_scores: np.ndarray,
                          model_scores: np.ndarray, target_fpr: float = 0.01,
                          eval_mask: np.ndarray | None = None) -> dict:
    """Does the model find attacks the deployed rules miss?

    This is the question that decides whether Layer 4.5 ML earns its place. A model that
    merely re-discovers what Sigma already catches adds operational cost and no detection.
    So the population that matters is the attacks the rules **miss**, and the measure is how
    the model ranks them.

    Reported:
      * `rule_missed_positives`  - attacks no rule fired on (the addressable population)
      * `model_recovers_at_fpr`  - how many of those the model surfaces at `target_fpr`
      * `union_recall`           - recall of rules OR model together
      * `model_only` / `sigma_only` / `both` - the overlap breakdown
    """
    keep = np.ones(len(dataset), dtype=bool) if eval_mask is None else np.asarray(eval_mask)
    y = dataset.y[keep]
    sig = np.asarray(sigma_scores)[keep] > 0
    mdl = np.asarray(model_scores, dtype="float64")[keep]

    benign = y == A.LABEL_BENIGN
    positive = y == A.LABEL_MALICIOUS
    if benign.sum() == 0 or positive.sum() == 0:
        return {"note": "need both classes"}

    threshold = float(np.quantile(mdl[benign], 1.0 - target_fpr))
    model_alert = mdl >= threshold

    missed = positive & ~sig
    recovered = missed & model_alert
    return {
        "target_fpr": target_fpr,
        "model_threshold": round(threshold, 6),
        "positives": int(positive.sum()),
        "sigma_recall": round(float((positive & sig).sum() / positive.sum()), 4),
        "rule_missed_positives": int(missed.sum()),
        "model_recovers_at_fpr": int(recovered.sum()),
        "model_recovery_rate_of_missed": round(
            float(recovered.sum() / max(missed.sum(), 1)), 4),
        "union_recall": round(
            float(((positive & sig) | (positive & model_alert)).sum() / positive.sum()), 4),
        "overlap": {
            "both": int((positive & sig & model_alert).sum()),
            "sigma_only": int((positive & sig & ~model_alert).sum()),
            "model_only": int((positive & ~sig & model_alert).sum()),
            "neither": int((positive & ~sig & ~model_alert).sum()),
        },
        "extra_false_positives_from_model": int((benign & model_alert & ~sig).sum()),
    }


def ablation_study(dataset: A.Dataset, fit_score_factory, tier: str = mlf.TIER_T2,
                   n_splits: int = 5, eval_mask: np.ndarray | None = None,
                   groups_to_drop: tuple[str, ...] = ()) -> list[CvResult]:
    """Leave-one-feature-group-out, so a result attaches to a kind of evidence.

    `tree` is dropped in its own run for a specific reason recorded in
    `ml_features.FEATURE_GROUPS`: `sibling_count` alone reaches ROC-AUC 0.866, which is largely
    an artefact of lineage labelling rather than a behavioural signal. The no-tree run is the
    defensible headline.
    """
    results = []
    full = mlf.FEATURE_NAMES if tier == mlf.TIER_T2 else mlf.T1_FEATURES
    results.append(grouped_cv(dataset, fit_score_factory(), tier=tier, n_splits=n_splits,
                              name=f"ablation:all_features({len(full)})",
                              feature_subset=list(full), eval_mask=eval_mask))
    for group in groups_to_drop:
        subset = mlf.features_excluding(group, tier=tier)
        if not subset or len(subset) == len(full):
            continue
        results.append(grouped_cv(dataset, fit_score_factory(), tier=tier, n_splits=n_splits,
                                  name=f"ablation:no_{group}({len(subset)})",
                                  feature_subset=subset, eval_mask=eval_mask))
    return results


# --------------------------------------------------------------------------- calibration

def brier_score(y: np.ndarray, probabilities: np.ndarray) -> float:
    """Mean squared error of predicted probabilities. Lower is better."""
    y = np.asarray(y, dtype="float64")
    p = np.clip(np.asarray(probabilities, dtype="float64"), 0.0, 1.0)
    return float(np.mean((p - y) ** 2))


def reliability_curve(y: np.ndarray, probabilities: np.ndarray, n_bins: int = 10) -> dict:
    """Observed frequency vs predicted probability, in equal-width bins.

    Calibration is not optional for Component B. Its output is rendered to an analyst as a
    confidence, so a score of 0.9 must mean "right about 90% of the time". An uncalibrated
    0.9 that is actually 0.4 is worse than no score: it manufactures false certainty and
    teaches the analyst to distrust the whole system.
    """
    y = np.asarray(y, dtype="float64")
    p = np.clip(np.asarray(probabilities, dtype="float64"), 0.0, 1.0)
    edges = np.linspace(0.0, 1.0, n_bins + 1)
    bins = []
    for i in range(n_bins):
        lo, hi = edges[i], edges[i + 1]
        mask = (p >= lo) & (p < hi if i < n_bins - 1 else p <= hi)
        if mask.sum() == 0:
            continue
        bins.append({
            "bin": f"[{lo:.1f},{hi:.1f})",
            "n": int(mask.sum()),
            "mean_predicted": round(float(p[mask].mean()), 4),
            "observed_frequency": round(float(y[mask].mean()), 4),
            "gap": round(float(p[mask].mean() - y[mask].mean()), 4),
        })
    # Expected Calibration Error: sample-weighted mean |predicted - observed|.
    ece = sum(b["n"] * abs(b["gap"]) for b in bins) / max(len(y), 1)
    return {"bins": bins, "expected_calibration_error": round(float(ece), 4),
            "brier_score": round(brier_score(y, p), 4)}


def calibration_metrics(y: np.ndarray, probabilities: np.ndarray) -> dict:
    out = reliability_curve(y, probabilities)
    p = np.clip(np.asarray(probabilities, dtype="float64"), 0.0, 1.0)
    base_rate = float(np.mean(np.asarray(y) == A.LABEL_MALICIOUS))
    # A model that always predicts the base rate is perfectly calibrated and useless; the
    # comparison shows whether calibration was bought at the price of discrimination.
    out["brier_of_base_rate_predictor"] = round(
        brier_score(y, np.full(len(y), base_rate)), 4)
    out["brier_skill_score"] = round(
        1.0 - out["brier_score"] / max(out["brier_of_base_rate_predictor"], 1e-9), 4)
    out["mean_predicted"] = round(float(p.mean()), 4)
    out["base_rate"] = round(base_rate, 4)
    return out
