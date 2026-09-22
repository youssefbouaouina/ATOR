"""Monitor stage: is the deployed model still looking at the world it was trained on, what is
it producing, what do analysts make of it, and is the pipeline itself healthy?

Never blocks a run. Its output is the `monitor` block of the run summary, which the
dashboard's Model operations panel reads, plus the drift rows `ml_drift_log` has always held.
"""
from __future__ import annotations

import json
from datetime import datetime

import pandas as pd

from ml.mlops import config


def drift(train_db: str, snapshot: str, since_utc: str, live_conn,
          min_local_rows: int = 200) -> dict:
    """PSI of the last 7 days of live traffic against a reference, through the T1 lens.

    Reference = this estate's own admitted history (the rows Component A's baseline was built
    from) when there is enough of it: that is the comparison meaning "something changed on
    our hosts" - a new rollout, an agent that lost elevation. The corpus is the fallback, and
    only informational: lab captures differ from any real estate permanently (25 of 80
    features on the first real run), so it cannot tell this week from last.
    """
    from ml.datasets import assemble as A
    from server import db as database
    from server.engine import ml_drift, ml_features as mlf

    conn = database.connect(snapshot)
    try:
        real = A._real_host_ids(conn)
        current_frame = (mlf.extract_process_frame(conn, host_ids=real, since_utc=since_utc)
                         if real else pd.DataFrame())
        history = mlf.extract_process_frame(conn, host_ids=real) if real else pd.DataFrame()
        excluded = A._training_exclusions(conn)
    finally:
        conn.close()
    if current_frame.empty:
        return {"error": "no live processes in the monitoring window", "window_since": since_utc}

    reference_frame, reference = pd.DataFrame(), "corpus"
    if not history.empty:
        reference_frame = history[~history["id"].isin(list(excluded))]
    if len(reference_frame) >= min_local_rows:
        reference = "local"
    else:
        train_conn = database.connect(train_db)
        try:
            reference_frame = mlf.extract_process_frame(train_conn)
        finally:
            train_conn.close()
    if reference_frame.empty:
        return {"error": "no reference data to compare against"}

    stats = mlf.fit_stats(reference_frame)
    rows = ml_drift.compute_drift(mlf.transform(reference_frame, stats=stats, tier=mlf.TIER_T1),
                                  mlf.transform(current_frame, stats=stats, tier=mlf.TIER_T1))
    summary = ml_drift.summarise(rows)
    summary["recorded"] = ml_drift.record_drift(live_conn, None, rows)
    summary.update(window_since=since_utc, live_rows=int(len(current_frame)),
                   reference=reference, reference_rows=int(len(reference_frame)))
    return summary


def live_outcomes(snapshot: str, since_utc: str, days: float) -> dict:
    """What the champion produced in the window, and what analysts said about it."""
    from server import db as database

    conn = database.connect(snapshot)
    try:
        leads = conn.execute(
            """SELECT COUNT(*) FROM detections
               WHERE rule_type='ml_anomaly' AND detected_at_utc >= ?""", (since_utc,)).fetchone()[0]
        hosts = conn.execute(
            "SELECT COUNT(DISTINCT host_id) FROM raw_processes WHERE collected_at_utc >= ?",
            (since_utc,)).fetchone()[0]
        verdicts = dict(conn.execute(
            """SELECT f.verdict, COUNT(*) FROM ml_feedback f
               JOIN detections d ON d.id = f.detection_id
               WHERE d.rule_type='ml_anomaly' GROUP BY f.verdict""").fetchall())
        window_verdicts = dict(conn.execute(
            """SELECT f.verdict, COUNT(*) FROM ml_feedback f
               JOIN detections d ON d.id = f.detection_id
               WHERE d.rule_type='ml_anomaly' AND d.detected_at_utc >= ?
               GROUP BY f.verdict""", (since_utc,)).fetchall())
        cmd = conn.execute(
            """SELECT COUNT(*), SUM(CASE WHEN COALESCE(cmdline,'') <> '' THEN 1 ELSE 0 END)
               FROM raw_processes WHERE collected_at_utc >= ?""", (since_utc,)).fetchone()
    finally:
        conn.close()
    confirmed, benign = int(verdicts.get("confirmed", 0)), int(verdicts.get("benign", 0))
    reviewed_window = sum(int(v) for v in window_verdicts.values())
    return {
        "window_since": since_utc,
        "ml_leads": int(leads),
        "active_hosts": int(hosts),
        "leads_per_host_day": round(leads / (hosts * days), 2) if hosts else None,
        "analyst_confirmed": confirmed,
        "analyst_dismissed": benign,
        # Only quoted once there is enough to mean something.
        "analyst_precision": round(confirmed / (confirmed + benign), 3)
        if confirmed + benign >= 5 else None,
        "review_coverage": round(reviewed_window / leads, 3) if leads else None,
        "cmdline_coverage": round((cmd[1] or 0) / cmd[0], 3) if cmd[0] else None,
    }


def pipeline_health(live_conn, policy: config.Policy, now: datetime) -> dict:
    rows = live_conn.execute(
        """SELECT run_id, started_at_utc, status FROM ml_pipeline_runs
           WHERE status <> 'running' ORDER BY started_at_utc DESC LIMIT 20""").fetchall()
    consecutive_failures = 0
    for row in rows:
        if row[2] != "failed":
            break
        consecutive_failures += 1
    last_ok = next((r[1] for r in rows if r[2] in ("succeeded", "attention")), None)
    age_hours = None
    if last_ok:
        age_hours = (pd.Timestamp(now) - pd.Timestamp(last_ok)).total_seconds() / 3600.0
    trials = live_conn.execute(
        """SELECT components_json, version_id, started_at_utc, online_json FROM ml_shadow_trials
           WHERE status='running'""").fetchall()
    running = []
    for comps, version, started, online in trials:
        extensions = 0
        try:
            extensions = int(json.loads(online or "{}").get("extensions", 0))
        except (TypeError, ValueError):
            pass
        running.append({"component": (json.loads(comps) or [None])[0], "version_id": version,
                        "started_at_utc": started, "extensions": extensions})
    return {
        "consecutive_failures": consecutive_failures,
        "last_success_utc": last_ok,
        "hours_since_success": None if age_hours is None else round(age_hours, 1),
        "overdue": age_hours is not None and age_hours > policy.overdue_after_hours,
        "running_trials": running,
    }
