"""Manual ML maintenance: check for drift, or force a retrain straight into models/.

**For scheduled, unattended retraining use the weekly MLOps pipeline instead**
(`python -m ml.mlops run`, docs/ML_MLOPS_RUNBOOK.md). It stages, gates, shadow-trials and
versions every model, and can roll back. This script writes directly into the served models/
directory with none of that, which is fine by hand and wrong on a timer. If you do use
--retrain, the pipeline's next run will find the hand-placed models and adopt them.

Patterned on scripts/update_mitre.py:

    python scripts/retrain_ml.py --check-drift          # report only, never trains
    python scripts/retrain_ml.py --retrain              # force a retrain
    python scripts/retrain_ml.py                        # retrain only if drift says so

Drift is measured with PSI between the corpus the models were trained on and the live serving
distribution (server/engine/ml_drift.py).

Retraining is deliberately **not** automatic on a schedule alone. A model performing well
should not be replaced because a day passed, and retraining on a drifted but *unlabelled*
live distribution cannot improve a supervised model anyway - there are no new labels in it.
What drift monitoring buys is knowing the ground moved, so a human can decide.

Exit codes: 0 fine - 1 error - 2 drift detected while using --check-drift, so a cron job can
alert on it.
"""
import argparse
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server import db as database                       # noqa: E402

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def measure_drift(live_db=None, train_db=None) -> dict:
    """PSI between the training corpus and the live serving distribution."""
    from ml.datasets.otrf_etl import DEFAULT_TRAIN_DB
    from server.engine import ml_drift, ml_features as mlf

    train_db = train_db or DEFAULT_TRAIN_DB
    if not os.path.exists(train_db):
        return {"error": f"training database not found: {train_db}",
                "hint": "python -m ml.datasets.otrf_etl --rebuild"}

    train_conn = database.connect(train_db)
    try:
        reference_frame = mlf.extract_process_frame(train_conn)
    finally:
        train_conn.close()
    if reference_frame.empty:
        return {"error": "training database has no processes"}

    # Reference statistics are used for BOTH sides: the point is to compare distributions
    # through the same lens the model was trained with.
    stats = mlf.fit_stats(reference_frame)
    reference = mlf.transform(reference_frame, stats=stats, tier=mlf.TIER_T1)

    conn = database.connect(live_db)
    try:
        current_frame = mlf.extract_process_frame(conn)
        if current_frame.empty:
            return {"error": "live database has no processes to compare"}
        current = mlf.transform(current_frame, stats=stats, tier=mlf.TIER_T1)
        rows = ml_drift.compute_drift(reference, current)
        summary = ml_drift.summarise(rows)
        summary["recorded"] = ml_drift.record_drift(conn, None, rows)
        database.audit(conn, "cron", "ml_drift_check",
                       {"shifted": summary["counts"].get("shifted", 0)})
        conn.commit()
        return summary
    finally:
        conn.close()


def retrain(components=("anomaly", "triage", "tactic")) -> dict:
    """Invoke the training entry points as subprocesses.

    Subprocesses rather than imports: training loads pandas/scikit-learn and builds large
    frames, and a long-lived server process should not keep that memory afterwards. It also
    means one component failing to train cannot abort the others.
    """
    results = {}
    for component in components:
        module = f"ml.training.train_{component}"
        try:
            proc = subprocess.run(
                [sys.executable, "-m", module, "--save"],
                cwd=PROJECT_ROOT, capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=3600,
            )
            results[component] = {
                "ok": proc.returncode == 0,
                "returncode": proc.returncode,
                "tail": (proc.stdout or proc.stderr or "").strip()[-400:],
            }
        except subprocess.TimeoutExpired:
            results[component] = {"ok": False, "returncode": None, "tail": "timed out"}
    return results


def main() -> int:
    ap = argparse.ArgumentParser(description="ML drift check and retraining")
    ap.add_argument("--db", default=os.environ.get("ATOR_DFIR_DB"))
    ap.add_argument("--train-db", default=None)
    ap.add_argument("--check-drift", action="store_true",
                    help="report drift and exit 2 if shifted; never trains")
    ap.add_argument("--retrain", action="store_true", help="retrain regardless of drift")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    from server.engine import ml_registry
    status = ml_registry.dependencies_available()
    if not status.available:
        print(f"ML stack unavailable: {status.reason}")
        return 1

    database.init_db(args.db)
    output = {"drift": measure_drift(args.db, args.train_db)}

    if "error" in output["drift"]:
        print(f"drift check failed: {output['drift']['error']}")
        if output["drift"].get("hint"):
            print(f"  hint: {output['drift']['hint']}")
        return 1

    drifted = bool(output["drift"].get("retrain_recommended"))
    if not args.json:
        print(f"drift: {output['drift']['counts']} over "
              f"{output['drift']['features_compared']} features")
        for row in output["drift"]["worst"][:5]:
            print(f"  {row['feature']:32s} psi={row['psi']:>8.3f} [{row['verdict']}]"
                  f"  missing {row['reference_missing_pct']}% -> "
                  f"{row['current_missing_pct']}%")

    if args.check_drift:
        if args.json:
            print(json.dumps(output, indent=2, default=str))
        return 2 if drifted else 0

    if args.retrain or drifted:
        if not args.json:
            print("\nretraining..." if args.retrain
                  else "\ndrift detected - retraining...")
        output["retrain"] = retrain()
        if not args.json:
            for component, result in output["retrain"].items():
                print(f"  {component:10s} {'OK' if result['ok'] else 'FAILED'}")
    elif not args.json:
        print("\nno retraining needed")

    if args.json:
        print(json.dumps(output, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
