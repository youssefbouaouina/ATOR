"""Re-measure the facts the ML design rests on, and quantify train/serve skew.

Two jobs:

1. **Re-measure.** `docs/ML_ARCHITECTURE.md` section 1 records database contents and corpus
   statistics as of a point in time. Anyone resuming this work months later should not trust
   those numbers - run this and get today's.

2. **Skew audit.** The central design claim is that features computed on the OTRF-derived
   training corpus are computable the same way on live psutil/EVTX data. That claim is only
   worth something if it is measured, so this compares per-feature missingness between the
   two databases and flags any feature whose availability differs enough to be a latent
   production failure.

A feature that is 5% missing in training and 100% missing in production is not a modelling
detail - it is a feature the deployed model will never actually receive. Better to see it
in a table now than in unexplained scores later.

    python -m ml.evaluation.audit_baseline
    python -m ml.evaluation.audit_baseline --json      # machine-readable
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3

import pandas as pd

from ml.datasets import otrf, otrf_etl
from server import db as database
from server.engine import ml_features as mlf

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LIVE_DB = os.path.join(_PROJECT_ROOT, "ator_dfir.db")
TRAIN_DB = otrf_etl.DEFAULT_TRAIN_DB

# Missingness gap above which a feature is called out. 40 percentage points is well beyond
# sampling noise at these row counts and always indicates a structural difference.
SKEW_WARN_PP = 40.0


def _table_counts(db_path: str) -> dict:
    if not os.path.exists(db_path):
        return {"_error": "database not found"}
    conn = database.connect(db_path)
    try:
        names = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        out = {}
        for name in names:
            if name.startswith("sqlite_"):
                continue
            try:
                out[name] = conn.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0]
            except sqlite3.Error as exc:
                out[name] = f"error: {exc}"
        return out
    finally:
        conn.close()


def _label_summary(db_path: str) -> dict:
    if not os.path.exists(db_path):
        return {}
    conn = database.connect(db_path)
    try:
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        if "corpus_labels" not in tables:
            return {"_note": "not labelled yet - run python -m ml.datasets.labels"}
        totals = dict(conn.execute(
            "SELECT label, COUNT(*) FROM corpus_labels GROUP BY label").fetchall())
        by_tactic = dict(conn.execute(
            """SELECT tactic, COUNT(*) FROM corpus_labels
               WHERE label='malicious' GROUP BY tactic ORDER BY 2 DESC""").fetchall())
        n = sum(totals.values()) or 1
        return {
            "totals": totals,
            "positive_rate": round(totals.get("malicious", 0) / n, 4),
            "malicious_by_tactic": by_tactic,
            "capture_groups": conn.execute(
                "SELECT COUNT(*) FROM corpus_captures").fetchone()[0],
        }
    finally:
        conn.close()


def _matrix(db_path: str):
    """(feature matrix, raw frame) for a database, or (None, None) if unavailable."""
    if not os.path.exists(db_path):
        return None, None
    conn = database.connect(db_path)
    try:
        frame = mlf.extract_process_frame(conn)
        if frame.empty:
            return None, None
        stats = mlf.fit_stats(frame)
        return mlf.transform(frame, stats=stats, tier=mlf.TIER_T2), frame
    finally:
        conn.close()


def skew_report(train_matrix: pd.DataFrame, live_matrix: pd.DataFrame) -> pd.DataFrame:
    """Per-feature missingness on both sides, sorted by the size of the gap."""
    train_pct = train_matrix.isna().mean() * 100
    live_pct = live_matrix.isna().mean() * 100
    tiers = {fd.name: fd.tier for fd in mlf.FEATURE_SPEC}
    df = pd.DataFrame({
        "feature": mlf.FEATURE_NAMES,
        "tier": [tiers[n] for n in mlf.FEATURE_NAMES],
        "train_missing_pct": [round(float(train_pct.get(n, 100.0)), 2) for n in mlf.FEATURE_NAMES],
        "live_missing_pct": [round(float(live_pct.get(n, 100.0)), 2) for n in mlf.FEATURE_NAMES],
    })
    df["gap_pp"] = (df["live_missing_pct"] - df["train_missing_pct"]).round(2)
    df["flag"] = df["gap_pp"].abs().ge(SKEW_WARN_PP).map({True: "REVIEW", False: ""})
    return df.sort_values("gap_pp", key=abs, ascending=False, ignore_index=True)


def run(as_json: bool = False, top: int = 20) -> dict:
    result: dict = {
        "feature_spec_sha256": mlf.feature_spec_sha256(),
        "feature_counts": {
            "total": len(mlf.FEATURE_NAMES),
            "t1": len(mlf.T1_FEATURES),
            "t2": len(mlf.T2_FEATURES),
        },
        "live_db": {"path": LIVE_DB, "tables": _table_counts(LIVE_DB)},
        "train_db": {"path": TRAIN_DB, "tables": _table_counts(TRAIN_DB)},
        "labels": _label_summary(TRAIN_DB),
        "corpus": {
            "dir": otrf.DEFAULT_DIR,
            "host_captures": len(otrf.local_captures()),
            "av_blocked": otrf.blocked_captures(),
        },
    }

    train_matrix, train_frame = _matrix(TRAIN_DB)
    live_matrix, live_frame = _matrix(LIVE_DB)
    result["rows"] = {
        "train": 0 if train_matrix is None else len(train_matrix),
        "live": 0 if live_matrix is None else len(live_matrix),
    }

    if train_matrix is not None and live_matrix is not None:
        report = skew_report(train_matrix, live_matrix)
        flagged = report[report["flag"] == "REVIEW"]
        result["skew"] = {
            "warn_threshold_pp": SKEW_WARN_PP,
            "flagged_count": int(len(flagged)),
            "flagged": flagged.to_dict(orient="records"),
            "identical_columns": bool(
                list(train_matrix.columns) == list(live_matrix.columns)),
        }
        result["_report_df"] = report

    if not as_json:
        _print_human(result, top=top)
    return result


def _print_human(result: dict, top: int) -> None:
    print("=" * 78)
    print("ATOR DFIR - Layer 4.5 ML baseline audit")
    print("=" * 78)
    print(f"\nfeature spec sha256 : {result['feature_spec_sha256']}")
    fc = result["feature_counts"]
    print(f"features            : {fc['total']}  ({fc['t1']} T1 / {fc['t2']} T2)")
    print(f"rows                : train={result['rows']['train']}  live={result['rows']['live']}")

    print("\n--- live database (ator_dfir.db) ---")
    for name, n in sorted(result["live_db"]["tables"].items()):
        if n:
            print(f"  {name:24s} {n}")

    print("\n--- training database (ml_train.db) ---")
    for name, n in sorted(result["train_db"]["tables"].items()):
        if n:
            print(f"  {name:24s} {n}")

    labels = result.get("labels") or {}
    if labels.get("totals"):
        print(f"\n--- labels ---\n  {labels['totals']}  "
              f"positive_rate={labels['positive_rate']}  "
              f"groups={labels['capture_groups']}")
        print(f"  by tactic: {labels['malicious_by_tactic']}")

    corpus = result["corpus"]
    print(f"\n--- corpus ---\n  usable host captures: {corpus['host_captures']}"
          f"   av-blocked: {len(corpus['av_blocked'])}")

    skew = result.get("skew")
    if skew:
        print("\n" + "=" * 78)
        print("TRAIN/SERVE SKEW - per-feature missingness (percentage points)")
        print("=" * 78)
        print(f"identical feature columns on both sides: {skew['identical_columns']}")
        print(f"features flagged (|gap| >= {skew['warn_threshold_pp']}pp): "
              f"{skew['flagged_count']} / {result['feature_counts']['total']}")
        df = result.get("_report_df")
        if df is not None:
            print()
            print(df.head(top).to_string(index=False))
        print("\nA large positive gap means the feature is available in training but NOT in\n"
              "production - the model would learn to rely on something it will never see.\n"
              "T2 features at 100% live missingness are EXPECTED while Sysmon is not\n"
              "installed; that is precisely what the T1 model exists for.")


def main() -> int:
    ap = argparse.ArgumentParser(description="ML baseline + train/serve skew audit")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of a report")
    ap.add_argument("--top", type=int, default=20, help="rows of the skew table to show")
    args = ap.parse_args()
    result = run(as_json=args.json, top=args.top)
    if args.json:
        result.pop("_report_df", None)
        print(json.dumps(result, indent=2, default=str))
    return 0


if __name__ == "__main__":       # pragma: no cover - operator entry point
    raise SystemExit(main())
