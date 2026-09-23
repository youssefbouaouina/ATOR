"""Train and evaluate Component A (process anomaly detection).

    python -m ml.training.train_anomaly                 # evaluate, both tiers, all baselines
    python -m ml.training.train_anomaly --save          # also persist the final T1/T2 models
    python -m ml.training.train_anomaly --no-local      # ablate the local benign rows

Evaluation order is deliberate: baselines first, model second. The model is only worth
shipping if it beats all three - especially the Sigma rules already in production.
"""
from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone

import numpy as np

from ml.datasets import assemble as A
from ml.datasets.otrf_etl import DEFAULT_TRAIN_DB
from ml.evaluation import harness as H
from server.engine import ml_anomaly, ml_features as mlf

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# Same override the serving registry honours (server/engine/ml_registry.py).
MODELS_DIR = os.environ.get("ATOR_ML_MODEL_DIR", os.path.join(_PROJECT_ROOT, "models"))
REPORTS_DIR = os.path.join(_PROJECT_ROOT, "reports_ml")


def evaluate(dataset: A.Dataset, train_db: str, n_splits: int = 5) -> dict:
    # Ranking metrics are computed on corpus rows only. All 185 positives live in the corpus
    # and the local rows are 100% benign, so any feature separating the two sources - and
    # `sysmon_available` separates them perfectly - would hand the model a free
    # "cannot be an attack" signal. See harness.corpus_eval_mask.
    eval_mask = H.corpus_eval_mask(dataset)
    results = []

    # ---- baselines, in increasing order of seriousness
    chance = H.chance_baseline(dataset, eval_mask=eval_mask)
    sigma = H.sigma_baseline(dataset, train_db, eval_mask=eval_mask)
    single = H.best_single_feature_baseline(dataset, tier=mlf.TIER_T1, n_splits=n_splits,
                                           eval_mask=eval_mask)
    results += [chance, sigma, single]

    # ---- the model, per feature tier
    tier_results = {}
    for tier in (mlf.TIER_T1, mlf.TIER_T2):
        res = H.grouped_cv(
            dataset,
            fit_score=ml_anomaly.fit_score_factory(),
            tier=tier,
            n_splits=n_splits,
            name=f"anomaly_iforest_{tier}",
            benign_only_fit=True,
            eval_mask=eval_mask,
        )
        tier_results[tier] = res
        results.append(res)

    # ---- the honest headline: the same model without the tree-shape features, which are a
    # suspected labelling artefact (malicious median sibling_count = 0 vs benign 4-26).
    no_tree_features = mlf.features_excluding("tree", tier=mlf.TIER_T2)
    no_tree = H.grouped_cv(dataset, ml_anomaly.fit_score_factory(), tier=mlf.TIER_T2,
                           n_splits=n_splits, name="anomaly_iforest_t2_no_tree",
                           benign_only_fit=True, feature_subset=no_tree_features,
                           eval_mask=eval_mask)
    single_no_tree = H.best_single_feature_baseline(
        dataset, tier=mlf.TIER_T2, n_splits=n_splits,
        feature_subset=no_tree_features, eval_mask=eval_mask)
    single_no_tree.name = "baseline:best_single_feature_no_tree"
    results += [no_tree, single_no_tree]

    H.print_report(results, title="Component A - process anomaly detection "
                                 "(ranking metrics on corpus rows only)")

    # ---- what does the model add over the rules already in production?
    best_model = tier_results[mlf.TIER_T2]
    complementarity = {
        "with_tree_features": H.sigma_complementarity(
            dataset, sigma.scores, best_model.scores, eval_mask=eval_mask),
        "without_tree_features": H.sigma_complementarity(
            dataset, sigma.scores, no_tree.scores, eval_mask=eval_mask),
    }
    print("\n--- does the model find what the Sigma rules miss? ---")
    print(json.dumps(complementarity, indent=2))

    # ---- false positives on genuine live benign telemetry (never used for thresholding).
    # T1 is included because it is the configuration we actually recommend deploying.
    local_fp = {name: H.local_fp_report(dataset, res.scores)
                for name, res in (("anomaly_iforest_t1", tier_results[mlf.TIER_T1]),
                                  ("anomaly_iforest_t2", best_model),
                                  ("anomaly_iforest_t2_no_tree", no_tree))}
    print("\n--- false positives on real live benign endpoint data ---")
    print(json.dumps(local_fp, indent=2))

    # ---- the ablation that quantifies what installing Sysmon buys
    t1, t2 = tier_results[mlf.TIER_T1].metrics, tier_results[mlf.TIER_T2].metrics
    sysmon_ablation = {
        "pr_auc_t1": t1.get("pr_auc"),
        "pr_auc_t2": t2.get("pr_auc"),
        "pr_auc_delta": None if None in (t1.get("pr_auc"), t2.get("pr_auc"))
        else round(t2["pr_auc"] - t1["pr_auc"], 4),
        "recall_at_fpr_0.01_t1": t1.get("recall_at_fpr_0.01"),
        "recall_at_fpr_0.01_t2": t2.get("recall_at_fpr_0.01"),
    }

    # ---- leave-one-feature-group-out
    group_ablation = H.ablation_study(
        dataset, ml_anomaly.fit_score_factory, tier=mlf.TIER_T2, n_splits=n_splits,
        eval_mask=eval_mask,
        groups_to_drop=("tree", "cmdline", "path", "parent", "rarity", "conn", "sysmon"))
    print("\n--- leave-one-feature-group-out (T2) ---")
    print(H.comparison_table(group_ablation)[
        ["model", "pr_auc", "roc_auc", "recall_at_fpr_0.01", "precision_at_25"]
    ].to_string(index=False))

    print("\n--- T1 vs T2 (the value of installing Sysmon) ---")
    print(json.dumps(sysmon_ablation, indent=2))

    print("\n--- per-fold stability ---")
    for tier, res in list(tier_results.items()) + [("t2_no_tree", no_tree)]:
        pr = [f["pr_auc"] for f in res.per_fold if f.get("pr_auc") is not None]
        if pr:
            print(f"  {tier:10s}: pr_auc per fold = {[round(p, 3) for p in pr]}  "
                  f"mean={np.mean(pr):.3f} sd={np.std(pr):.3f}")

    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "feature_spec_sha256": mlf.feature_spec_sha256(),
        "dataset": dataset.summary(),
        "dataset_meta": dataset.meta,
        "n_splits": n_splits,
        "eval_population": {
            "note": "ranking metrics computed on corpus rows only; see "
                    "harness.corpus_eval_mask for why",
            "eval_rows": int(eval_mask.sum()),
            "excluded_local_rows": int((~eval_mask).sum()),
        },
        "results": {
            r.name: {"metrics": r.metrics, "ci": r.ci,
                     "per_fold": r.per_fold, "extra": r.extra}
            for r in results + group_ablation
        },
        "sigma_complementarity": complementarity,
        "local_false_positives": local_fp,
        "sysmon_ablation": sysmon_ablation,
    }


def fit_final(dataset: A.Dataset, tier: str):
    """Fit on all benign rows - the artefact that would actually be deployed."""
    X, stats = A.materialise(dataset, train_mask=None, tier=tier)
    benign = dataset.y == A.LABEL_BENIGN
    model = ml_anomaly.AnomalyModel().fit(X[benign])
    return model, stats, X


def save(model, stats, tier: str, metrics: dict,
         models_dir: str | None = None) -> str:
    import joblib
    models_dir = models_dir or MODELS_DIR
    os.makedirs(models_dir, exist_ok=True)
    path = os.path.join(models_dir, f"anomaly_{tier}.joblib")
    joblib.dump({
        "kind": "anomaly",
        "tier": tier,
        "payload": model.to_payload(),
        "feature_stats": stats.to_dict(),
        "feature_spec_sha256": mlf.feature_spec_sha256(),
        "metrics": metrics,
        "trained_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }, path)
    return path


def main() -> int:
    ap = argparse.ArgumentParser(description="Train/evaluate Component A")
    ap.add_argument("--train-db", default=DEFAULT_TRAIN_DB)
    ap.add_argument("--live-db", default=A.DEFAULT_LIVE_DB)
    ap.add_argument("--no-local", action="store_true",
                    help="exclude local benign rows (ablation)")
    ap.add_argument("--splits", type=int, default=5)
    ap.add_argument("--models-dir", default=None,
                    help="where --save writes (default: the served models/ directory). "
                         "The MLOps pipeline points this at a candidate directory.")
    ap.add_argument("--save", action="store_true", help="persist the final models")
    ap.add_argument("--report", default=os.path.join(REPORTS_DIR, "anomaly_eval.json"))
    args = ap.parse_args()

    dataset = A.load(args.train_db, args.live_db, include_local=not args.no_local)
    if len(dataset) == 0:
        print("dataset is empty - run the Phase 1 ETL first "
              "(python -m ml.datasets.otrf_etl --rebuild)")
        return 1
    print(json.dumps(dataset.summary(), indent=2))
    print()

    report = evaluate(dataset, args.train_db, n_splits=args.splits)

    os.makedirs(os.path.dirname(args.report), exist_ok=True)
    with open(args.report, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)
    print(f"\nreport written: {args.report}")

    if args.save:
        for tier in (mlf.TIER_T1, mlf.TIER_T2):
            model, stats, _ = fit_final(dataset, tier)
            metrics = report["results"][f"anomaly_iforest_{tier}"]["metrics"]
            print(f"saved: {save(model, stats, tier, metrics, models_dir=args.models_dir)}")
    return 0


if __name__ == "__main__":       # pragma: no cover - operator entry point
    raise SystemExit(main())
