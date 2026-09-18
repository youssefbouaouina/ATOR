"""Train and evaluate Component C (ATT&CK tactic suggestion).

    python -m ml.training.train_tactic
    python -m ml.training.train_tactic --save

Evaluated by **grouped cross-validation only**. The held-out split cannot be used: it
contains positives from just 3 of the 8 tactics (measured in Phase 2), so per-class numbers
from it would be meaningless.

Trained on malicious rows only - the question is "which tactic is this?", not "is this an
attack?", which is Component B's job.
"""
from __future__ import annotations

import argparse
import json
import os
from collections import Counter
from datetime import datetime, timezone

import numpy as np
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import GroupKFold

from ml.datasets import assemble as A
from ml.datasets.otrf_etl import DEFAULT_TRAIN_DB
from ml.evaluation import harness as H
from server.engine import ml_features as mlf, ml_tactic

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MODELS_DIR = os.path.join(_PROJECT_ROOT, "models")
REPORTS_DIR = os.path.join(_PROJECT_ROOT, "reports_ml")


def _positives_only(dataset: A.Dataset) -> A.Dataset:
    return dataset.subset(dataset.y == A.LABEL_MALICIOUS)


def _gating_analysis(y_true, y_pred, confidences, report_dict) -> dict:
    """Measure what the deployment gates actually buy.

    `ml_tactic` only surfaces a suggestion when the probability clears
    MIN_SUGGESTION_PROBABILITY and the tactic has MIN_SUPPORT_TO_SUGGEST training examples.
    Both numbers are claimed in the UI ("about 78% precision at this threshold"), so both are
    computed here rather than asserted: a threshold defended by a number in a report is a
    decision, a threshold defended by nothing is a guess.

    Precision, not accuracy, is the metric for a *gate*: the question an analyst cares about
    is "when it does speak, how often is it right?", and coverage is the price paid for that.
    """
    well_supported = {
        name for name, entry in report_dict.items()
        if isinstance(entry, dict) and name not in ("macro avg", "weighted avg", "accuracy")
        and int(entry.get("support", 0)) >= ml_tactic.MIN_SUPPORT_TO_SUGGEST
    }
    correct = y_true == y_pred
    shown_class = np.isin(y_pred, list(well_supported))
    total = len(y_true)

    rows = []
    for threshold in (0.0, 0.5, 0.6, 0.7, 0.8, 0.9):
        above = confidences >= threshold
        gated = above & shown_class
        rows.append({
            "min_probability": threshold,
            "n_suggested": int(above.sum()),
            "coverage": round(float(above.mean()), 4),
            "precision": round(float(correct[above].mean()), 4) if above.any() else None,
            "with_support_gate": {
                "n_suggested": int(gated.sum()),
                "coverage": round(float(gated.sum() / total), 4),
                "precision": round(float(correct[gated].mean()), 4) if gated.any() else None,
            },
        })

    print("\ngate analysis - precision when the model is allowed to speak:")
    header = ("  min p", "   shown", "  coverage", "  precision",
              "  +support", "  precision")
    print("".join(f"{h:>11s}" for h in header))
    for r in rows:
        g = r["with_support_gate"]
        print(f"{r['min_probability']:>11.2f}{r['n_suggested']:>11d}"
              f"{r['coverage']:>11.1%}{(r['precision'] or 0):>11.1%}"
              f"{g['n_suggested']:>11d}{(g['precision'] or 0):>11.1%}")

    shipped = next(r for r in rows
                   if abs(r["min_probability"] - ml_tactic.MIN_SUGGESTION_PROBABILITY) < 1e-9)
    point = shipped["with_support_gate"]
    print(f"\nSHIPPED gate: p >= {ml_tactic.MIN_SUGGESTION_PROBABILITY} and support >= "
          f"{ml_tactic.MIN_SUPPORT_TO_SUGGEST} -> {point['precision']:.1%} precision at "
          f"{point['coverage']:.1%} coverage ({point['n_suggested']} of {total} attacks).")
    print(f"The third gate - Component B confidence >= "
          f"{ml_tactic.MIN_CONFIDENCE_TO_SUGGEST} - is applied at serve time and is NOT "
          f"measurable here: this population is attacks only, and that gate exists to stop "
          f"the model answering confidently about BENIGN processes it never trained on.")

    return {
        "note": "precision/coverage of the deployment gates over CV predictions, attacks "
                "only. The serve-time Component B confidence gate is not represented: it "
                "exists for benign inputs, which this population does not contain.",
        "well_supported_classes": sorted(well_supported),
        "min_support_to_suggest": ml_tactic.MIN_SUPPORT_TO_SUGGEST,
        "shipped_min_probability": ml_tactic.MIN_SUGGESTION_PROBABILITY,
        "shipped_min_component_b_confidence": ml_tactic.MIN_CONFIDENCE_TO_SUGGEST,
        "by_threshold": rows,
        "shipped_operating_point": point,
    }



def evaluate(dataset: A.Dataset, n_splits: int = 5, tier: str = mlf.TIER_T1) -> dict:
    positives = _positives_only(dataset.subset(H.corpus_eval_mask(dataset)))
    raw_counts = Counter(str(t) for t in positives.tactics)
    labels, kept = ml_tactic.collapse_rare_classes(positives.tactics)
    collapsed_counts = Counter(labels)

    print(f"positives: {len(positives)} rows across {len(set(positives.groups))} captures")
    print(f"\nraw tactic distribution: {dict(raw_counts.most_common())}")
    print(f"learnable classes (>= {ml_tactic.MIN_EXAMPLES_PER_CLASS} examples): {kept}")
    print(f"after collapsing:        {dict(collapsed_counts.most_common())}")
    print(f"\n{sum(n for c, n in collapsed_counts.items() if c == ml_tactic.OTHER_CLASS)} "
          f"rows folded into '{ml_tactic.OTHER_CLASS}' - too few examples to learn or to "
          f"measure; reporting a per-class F1 over 3 examples would be noise.\n")

    groups = positives.groups
    n_splits = min(n_splits, len(set(groups)))
    splitter = GroupKFold(n_splits=n_splits)
    predicted = np.full(len(positives), None, dtype=object)
    confidences = np.zeros(len(positives))

    for train_idx, test_idx in splitter.split(np.zeros(len(positives)), labels, groups):
        train_mask = np.zeros(len(positives), dtype=bool)
        train_mask[train_idx] = True
        X, _ = A.materialise(positives, train_mask=train_mask, tier=tier)
        train_labels = labels[train_idx]
        if len(set(train_labels)) < 2:
            continue
        model = ml_tactic.TacticModel().fit(X.iloc[train_idx], train_labels)
        probabilities = model.predict_proba(X.iloc[test_idx])
        best = probabilities.argmax(axis=1)
        predicted[test_idx] = [model.classes_[i] for i in best]
        confidences[test_idx] = probabilities.max(axis=1)

    scored = np.array([p is not None for p in predicted])
    y_true = labels[scored]
    y_pred = np.array([p for p in predicted if p is not None])

    class_order = sorted(set(y_true) | set(y_pred))
    report_dict = classification_report(y_true, y_pred, labels=class_order,
                                        zero_division=0, output_dict=True)
    print("=" * 80)
    print("Component C - tactic suggestion (grouped 5-fold CV, positives only)")
    print("=" * 80)
    print(classification_report(y_true, y_pred, labels=class_order, zero_division=0))

    matrix = confusion_matrix(y_true, y_pred, labels=class_order)
    width = max(len(c) for c in class_order) + 2
    print("confusion matrix (rows = true, columns = predicted)")
    print(" " * width + "".join(f"{c[:12]:>14s}" for c in class_order))
    for name, row in zip(class_order, matrix):
        print(f"{name:{width}s}" + "".join(f"{int(v):>14d}" for v in row))

    accuracy = float((y_true == y_pred).mean())
    majority = Counter(y_true).most_common(1)[0]
    print(f"\naccuracy {accuracy:.3f} vs majority-class baseline "
          f"{majority[1] / len(y_true):.3f} (always predicting '{majority[0]}')")
    print(f"macro F1 {report_dict['macro avg']['f1-score']:.3f} · "
          f"weighted F1 {report_dict['weighted avg']['f1-score']:.3f}")

    # Per-class credibility: a class supported by a handful of rows is not a result.
    print("\ncredibility by class:")
    for name in class_order:
        support = int(report_dict[name]["support"])
        verdict = ("reportable" if support >= 30 else
                   "indicative" if support >= 10 else "NOT reportable")
        print(f"  {name:22s} support={support:>4d}  f1={report_dict[name]['f1-score']:.3f}"
              f"   [{verdict}]")

    gating = _gating_analysis(y_true, y_pred, confidences[scored], report_dict)

    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "feature_spec_sha256": mlf.feature_spec_sha256(),
        "tier": tier,
        "positives": len(positives),
        "capture_groups": len(set(groups)),
        "raw_tactic_counts": dict(raw_counts),
        "learnable_classes": kept,
        "collapsed_counts": {str(k): int(v) for k, v in collapsed_counts.items()},
        "min_examples_per_class": ml_tactic.MIN_EXAMPLES_PER_CLASS,
        "accuracy": round(accuracy, 4),
        "majority_class_baseline": round(majority[1] / len(y_true), 4),
        "macro_f1": round(report_dict["macro avg"]["f1-score"], 4),
        "weighted_f1": round(report_dict["weighted avg"]["f1-score"], 4),
        "per_class": {c: {k: round(v, 4) if isinstance(v, float) else v
                          for k, v in report_dict[c].items()} for c in class_order},
        "confusion_matrix": {"labels": class_order, "matrix": matrix.tolist()},
        "gating": gating,
        "note": "evaluated by grouped CV only - the held-out split contains just 3 of 8 "
                "tactics, so per-class numbers from it would be meaningless",
    }


def fit_final(dataset: A.Dataset, tier: str = mlf.TIER_T1):
    positives = _positives_only(dataset.subset(H.corpus_eval_mask(dataset)))
    X, stats = A.materialise(positives, train_mask=None, tier=tier)
    model = ml_tactic.TacticModel().fit(X, positives.tactics)
    return model, stats


def save(model, stats, tier: str, metrics: dict) -> str:
    import joblib
    os.makedirs(MODELS_DIR, exist_ok=True)
    path = os.path.join(MODELS_DIR, f"tactic_{tier}.joblib")
    joblib.dump({
        "kind": "tactic", "tier": tier, "payload": model.to_payload(),
        "feature_stats": stats.to_dict(),
        "feature_spec_sha256": mlf.feature_spec_sha256(),
        "metrics": metrics,
        "trained_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }, path)
    return path


def main() -> int:
    ap = argparse.ArgumentParser(description="Train/evaluate Component C")
    ap.add_argument("--train-db", default=DEFAULT_TRAIN_DB)
    ap.add_argument("--live-db", default=A.DEFAULT_LIVE_DB)
    ap.add_argument("--splits", type=int, default=5)
    ap.add_argument("--tier", choices=[mlf.TIER_T1, mlf.TIER_T2], default=mlf.TIER_T1)
    ap.add_argument("--save", action="store_true")
    ap.add_argument("--report", default=os.path.join(REPORTS_DIR, "tactic_eval.json"))
    args = ap.parse_args()

    dataset = A.load(args.train_db, args.live_db, include_local=True)
    if len(dataset) == 0:
        print("dataset empty - run the Phase 1 ETL first")
        return 1

    report = evaluate(dataset, n_splits=args.splits, tier=args.tier)
    os.makedirs(os.path.dirname(args.report), exist_ok=True)
    with open(args.report, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)
    print(f"\nreport written: {args.report}")

    if args.save:
        model, stats = fit_final(dataset, args.tier)
        print(f"saved: {save(model, stats, args.tier, report)}")
        print(f"classes: {model.classes_}")
    return 0


if __name__ == "__main__":       # pragma: no cover - operator entry point
    raise SystemExit(main())
