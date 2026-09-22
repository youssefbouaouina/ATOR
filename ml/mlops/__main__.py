"""Operator entry point.

    python -m ml.mlops run [--force] [--no-fetch]      one pipeline run (the scheduled task)
    python -m ml.mlops status [--json]                 what is deployed, on trial, last runs
    python -m ml.mlops pause | resume                  stop / restart scheduled runs
    python -m ml.mlops freeze | unfreeze               runs continue, nothing is promoted
    python -m ml.mlops approve <capture.zip> ...       admit reviewed upstream captures
    python -m ml.mlops approve --pending               list captures awaiting review
    python -m ml.mlops rollback <component>            restore the previous champion now
    python -m ml.mlops history [<component>]           champion history
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

from ml.mlops import config, data, pipeline, store


def _set_flag(name: str, on: bool, message: str) -> int:
    home = config.mlops_home()
    os.makedirs(home, exist_ok=True)
    path = os.path.join(home, name)
    if on:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(datetime.now(timezone.utc).isoformat(timespec="seconds") + "\n")
    elif os.path.exists(path):
        os.remove(path)
    _audit(f"ml_pipeline_{name.lower()}_{'on' if on else 'off'}", {})
    print(message)
    return 0


def _audit(action: str, details: dict) -> None:
    try:
        from server import db as database
        conn = pipeline._live_conn()
        try:
            database.audit(conn, "operator", action, details)
            conn.commit()
        finally:
            conn.close()
    except Exception as exc:                     # noqa: BLE001 - the action itself succeeded
        print(f"(audit log not written: {exc})")


def status(as_json: bool) -> dict:
    from ml.mlops import evaluate, trial

    home = config.mlops_home()
    out = {"paused": os.path.exists(os.path.join(home, "PAUSED"))
           or os.environ.get("ATOR_MLOPS_DISABLED") == "1",
           "frozen": os.path.exists(os.path.join(home, "FROZEN")),
           "champions": {}, "trials": [], "runs": []}
    for component in config.COMPONENTS:
        champions = evaluate.load_champions(component)
        served = (champions or {}).get(config.COMPONENT_FILES[component][0]) or {}
        entry = store.champion_entry(component)
        out["champions"][component] = {
            "serving": bool(champions),
            "version_id": served.get("version_id") or (entry or {}).get("version_id"),
            "trained_at_utc": served.get("trained_at_utc"),
            "since": (entry or {}).get("promoted_at_utc"),
            "rollback_to": store.previous_version(component)}
    conn = pipeline._live_conn()
    try:
        for t in trial.running_trials(conn):
            item = {"component": t["component"], "version_id": t["version_id"],
                    "started_at_utc": t["started_at_utc"],
                    "extensions": t["online"].get("extensions", 0)}
            if t["component"] == "anomaly":
                item["evidence_so_far"] = trial.evidence(conn, t["id"])
            out["trials"].append(item)
        for row in conn.execute("""SELECT run_id, started_at_utc, status, trigger
                                   FROM ml_pipeline_runs ORDER BY started_at_utc DESC LIMIT 5"""):
            out["runs"].append(dict(zip(("run_id", "started_at_utc", "status", "trigger"), row)))
    finally:
        conn.close()
    admission = data.admit_captures(home)
    out["captures"] = {"admitted": len(admission["admitted"]),
                       "pending_review": [p["capture"] for p in admission["pending"]],
                       "changed": [c["capture"] for c in admission["changed"]]}
    if as_json:
        print(json.dumps(out, indent=2, default=str))
        return out
    flags = [n for n, on in (("PAUSED", out["paused"]), ("FROZEN", out["frozen"])) if on]
    print(f"MLOps pipeline{' [' + ', '.join(flags) + ']' if flags else ''}")
    print("\nDeployed models")
    for component, c in out["champions"].items():
        print(f"  {component:8s} {c['version_id'] or '-':32s} trained {c['trained_at_utc'] or '-'}"
              f"  rollback -> {c['rollback_to'] or 'none'}")
    print("\nOn trial")
    for t in out["trials"] or [{}]:
        if not t:
            print("  (none)")
            continue
        ev = t.get("evidence_so_far") or {}
        print(f"  {t['component']:8s} {t['version_id']} since {t['started_at_utc']}"
              + (f" - {ev.get('active_hours')} h, {ev.get('processes_scored')} processes, "
                 f"{ev.get('champion_flagged')} vs {ev.get('challenger_flagged')} flagged, "
                 f"{ev.get('errors')} errors" if ev else ""))
    print("\nRecent runs")
    for r in out["runs"] or [{"run_id": "(none)", "started_at_utc": "", "status": "",
                              "trigger": ""}]:
        print(f"  {r['run_id']:18s} {r['status']:10s} {r['trigger']}")
    print(f"\nCaptures: {out['captures']['admitted']} admitted, "
          f"{len(out['captures']['pending_review'])} awaiting review")
    for name in out["captures"]["pending_review"]:
        print(f"  pending: {name}")
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m ml.mlops", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="execute one pipeline run")
    run.add_argument("--force", action="store_true", help="ignore the 7-day cadence guard")
    run.add_argument("--no-fetch", action="store_true", help="do not contact GitHub")
    run.add_argument("--trigger", default="manual", choices=["manual", "schedule"])
    run.add_argument("--now", default=None, help=argparse.SUPPRESS)   # tests: ISO timestamp
    st = sub.add_parser("status")
    st.add_argument("--json", action="store_true")
    for name in ("pause", "resume", "freeze", "unfreeze"):
        sub.add_parser(name)
    ap_approve = sub.add_parser("approve")
    ap_approve.add_argument("captures", nargs="*")
    ap_approve.add_argument("--pending", action="store_true", help="list captures awaiting review")
    rb = sub.add_parser("rollback")
    rb.add_argument("component", choices=config.COMPONENTS)
    hist = sub.add_parser("history")
    hist.add_argument("component", nargs="?", choices=config.COMPONENTS)
    args = ap.parse_args(argv)

    if args.command == "run":
        now = datetime.fromisoformat(args.now) if args.now else None
        return pipeline.run_pipeline(force=args.force, now=now, trigger=args.trigger,
                                     fetch=False if args.no_fetch else None)
    if args.command == "status":
        status(args.json)
        return 0
    if args.command == "pause":
        return _set_flag("PAUSED", True, "paused: scheduled runs will exit without doing anything")
    if args.command == "resume":
        return _set_flag("PAUSED", False, "resumed")
    if args.command == "freeze":
        return _set_flag("FROZEN", True, "frozen: runs continue, no model will be promoted")
    if args.command == "unfreeze":
        return _set_flag("FROZEN", False, "unfrozen: promotions allowed again")
    if args.command == "approve":
        if args.pending or not args.captures:
            pending = data.admit_captures(config.mlops_home())["pending"]
            print("\n".join(p["capture"] for p in pending) or "no captures awaiting review")
            if pending:
                print("\nBefore approving, check ml/datasets/labels.py has signatures for the "
                      "tool each capture emulates; see docs/ML_MLOPS_PLAN.md 4.5.")
            return 0
        result = data.approve(config.mlops_home(), args.captures)
        _audit("ml_capture_approved", result)
        print(json.dumps(result, indent=2))
        return 0 if not result["not_found_or_unreadable"] else 1
    if args.command == "rollback":
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        entry = store.rollback(args.component, now, reason="operator rollback")
        from ml.mlops import trial
        from server.engine import ml_registry
        ml_registry.clear_cache()
        check = trial.smoke_test(args.component, entry["version_id"])
        _audit("ml_model_rolled_back", {"component": args.component,
                                        "restored": entry["version_id"], "smoke_test": check})
        print(f"{args.component}: now serving {entry['version_id']} "
              f"(smoke test: {'ok' if check['ok'] else check['reason']})")
        return 0
    if args.command == "history":
        history = store.load_history()["champions"]
        for component in ([args.component] if args.component else config.COMPONENTS):
            print(component)
            for entry in history.get(component, []):
                print(f"  {entry['promoted_at_utc']}  {entry['version_id']:32s} {entry['reason']}")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
