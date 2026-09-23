"""Read-only view of the weekly MLOps pipeline, for the dashboard and /api/v1/ml/ops.

Reads only tables and flag files; never imports the training stack. Worded for security
analysts (docs/ML_MLOPS_PLAN.md section 5): "model update on live trial", not "challenger
PSI". The data-science detail is in the run report, which the view links by path.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ENGINE_NAMES = {"anomaly": "Behavioural anomaly engine",
                "triage": "Threat-likelihood engine",
                "tactic": "ATT&CK tactic hints"}

# Defaults of ml/mlops/config.Policy. Duplicated rather than imported so the server never
# depends on the training package; an operator override in <home>/config.json is honoured.
_DEFAULTS = {"trial_min_hours": 24, "trial_min_processes": 200, "overdue_after_hours": 192.0,
             "min_hours_between_runs": 144.0}


def mlops_home() -> str:
    return os.environ.get("ATOR_MLOPS_HOME", os.path.join(_PROJECT_ROOT, "mlops"))


def _policy() -> dict:
    policy = dict(_DEFAULTS)
    path = os.path.join(mlops_home(), "config.json")
    try:
        with open(path, encoding="utf-8") as fh:
            overrides = json.load(fh)
        policy.update({k: v for k, v in overrides.items() if k in policy})
    except (OSError, ValueError):
        pass
    return policy


def _parse(ts: str | None):
    if not ts:
        return None
    try:
        value = datetime.fromisoformat(ts)
    except ValueError:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def ops_view(conn, models: list[dict] | None = None, now: datetime | None = None) -> dict:
    """Everything the Model operations panel shows. Never raises."""
    try:
        return _ops_view(conn, models or [], now or datetime.now(timezone.utc))
    except Exception as exc:                     # noqa: BLE001 - a panel must not break the page
        return {"available": False, "reason": f"{type(exc).__name__}: {exc}"}


def _ops_view(conn, models: list[dict], now: datetime) -> dict:
    from server.engine import ml_shadow

    policy = _policy()
    home = mlops_home()
    paused = (os.path.exists(os.path.join(home, "PAUSED"))
              or os.environ.get("ATOR_MLOPS_DISABLED") == "1")
    frozen = os.path.exists(os.path.join(home, "FROZEN"))

    runs = []
    for row in conn.execute(
            """SELECT run_id, started_at_utc, finished_at_utc, status, trigger, summary_json,
                      report_path
               FROM ml_pipeline_runs ORDER BY started_at_utc DESC LIMIT 6"""):
        item = dict(row)
        try:
            item["summary"] = json.loads(item.pop("summary_json") or "{}")
        except ValueError:
            item["summary"] = {}
        runs.append(item)
    completed = [r for r in runs if r["status"] in ("succeeded", "attention")]
    last_ok = _parse(completed[0]["started_at_utc"]) if completed else None
    next_due = (last_ok + timedelta(hours=policy["min_hours_between_runs"])) if last_ok else None
    overdue = bool(last_ok and (now - last_ok).total_seconds() / 3600 > policy["overdue_after_hours"])

    trials = []
    for row in conn.execute(
            """SELECT id, version_id, components_json, started_at_utc, online_json
               FROM ml_shadow_trials WHERE status='running' ORDER BY id"""):
        component = (json.loads(row["components_json"] or "[]") or [None])[0]
        try:
            extensions = int(json.loads(row["online_json"] or "{}").get("extensions", 0))
        except (TypeError, ValueError):
            extensions = 0
        item = {"id": row["id"], "component": component,
                "engine": ENGINE_NAMES.get(component, component),
                "version_id": row["version_id"], "started_at_utc": row["started_at_utc"],
                "extensions": extensions}
        if component == "anomaly":
            ev = ml_shadow.trial_evidence(conn, row["id"])
            hours_pct = min(100, round(100 * ev["active_hours"] / max(policy["trial_min_hours"], 1)))
            proc_pct = min(100, round(100 * ev["processes_scored"]
                                      / max(policy["trial_min_processes"], 1)))
            item.update(evidence=ev, progress_pct=min(hours_pct, proc_pct),
                        needs={"hours": policy["trial_min_hours"],
                               "processes": policy["trial_min_processes"]})
        else:
            item["progress_pct"] = 100           # replayed at the next weekly run
        trials.append(item)

    last_decisions = []
    for row in conn.execute(
            """SELECT version_id, components_json, status, ended_at_utc, decision_reason
               FROM ml_shadow_trials WHERE status IN ('promoted','rejected','aborted')
               ORDER BY ended_at_utc DESC LIMIT 5"""):
        component = (json.loads(row["components_json"] or "[]") or [None])[0]
        last_decisions.append({"engine": ENGINE_NAMES.get(component, component),
                               "version_id": row["version_id"], "status": row["status"],
                               "at": row["ended_at_utc"], "reason": row["decision_reason"]})

    feedback = dict(conn.execute(
        """SELECT f.verdict, COUNT(*) FROM ml_feedback f JOIN detections d
           ON d.id = f.detection_id WHERE d.rule_type='ml_anomaly' GROUP BY f.verdict"""
    ).fetchall())

    served = {}
    for m in models:
        if m.get("tier") == "t1" and m.get("loadable"):
            served[m["model_type"]] = {"engine": ENGINE_NAMES.get(m["model_type"], m["model_type"]),
                                       "version_id": m.get("version_id") or "initial model",
                                       "trained_at_utc": m.get("trained_at_utc")}

    attention = (runs[0]["summary"].get("attention") or []) if runs else []
    if paused:
        state = {"label": "Paused", "css": "offline",
                 "detail": "Weekly updates are paused by an operator."}
    elif not runs:
        state = {"label": "Not run yet", "css": "warn",
                 "detail": "The weekly update has not run on this server yet."}
    elif runs[0]["status"] == "running" and _parse(runs[0]["started_at_utc"]) and             (now - _parse(runs[0]["started_at_utc"])).total_seconds() > 6 * 3600:
        state = {"label": "Needs attention", "css": "offline",
                 "detail": "The last weekly update started over 6 hours ago and never finished."}
    elif runs[0]["status"] == "running":
        state = {"label": "Updating now", "css": "warn",
                 "detail": "The weekly update is running; models in service keep serving."}
    elif runs[0]["status"] == "failed" or overdue:
        state = {"label": "Needs attention", "css": "offline",
                 "detail": ("The last weekly update failed; the models in service are unchanged."
                            if runs[0]["status"] == "failed"
                            else "No successful weekly update for over a week.")}
    elif attention:
        state = {"label": "Needs a look", "css": "warn", "detail": attention[0]}
    elif frozen:
        state = {"label": "Frozen", "css": "warn",
                 "detail": "Updates are evaluated but none will be deployed until unfrozen."}
    elif trials:
        state = {"label": "Update on trial", "css": "online",
                 "detail": "A candidate model is being compared silently on live traffic."}
    else:
        state = {"label": "Up to date", "css": "online", "detail": "No update pending."}

    return {
        "available": True, "state": state, "paused": paused, "frozen": frozen,
        "served": served, "trials": trials, "decisions": last_decisions,
        "runs": runs, "last_run": runs[0] if runs else None, "attention": attention,
        "next_due_utc": (next_due.isoformat(timespec="minutes")
                         if next_due and not (runs and runs[0]["status"] == "running") else None),
        "overdue": overdue,
        "feedback": {"confirmed": int(feedback.get("confirmed", 0)),
                     "benign": int(feedback.get("benign", 0))},
    }
