"""Live shadow trials: start one, read its evidence, decide, promote safely.

The server side (recording what the challenger would have reported) is
`server/engine/ml_shadow.py`. This module is the pipeline side, run once a week.
"""
from __future__ import annotations

import json
import sqlite3

import numpy as np

from ml.mlops import config, scoring, store, train


def _row_to_trial(row) -> dict:
    components = json.loads(row[2] or "[]")
    return {"id": row[0], "version_id": row[1], "component": components[0] if components else None,
            "started_at_utc": row[3], "offline": json.loads(row[4] or "{}"),
            "online": json.loads(row[5] or "{}")}


def running_trials(conn) -> list[dict]:
    """One trial per component at most. B and C conclude by replay every week; only A can
    stay open for lack of live evidence, and it must not be lost when B changes."""
    rows = conn.execute(
        """SELECT id, version_id, components_json, started_at_utc, offline_json, online_json
           FROM ml_shadow_trials WHERE status='running' ORDER BY id""").fetchall()
    return [_row_to_trial(r) for r in rows]


def running_trial(conn, component: str) -> dict | None:
    for trial in reversed(running_trials(conn)):
        if trial["component"] == component:
            return trial
    return None


def close_trial(conn, trial_id: int, status: str, now: str, reason: str,
                online: dict | None = None) -> None:
    conn.execute(
        """UPDATE ml_shadow_trials SET status=?, ended_at_utc=?, decision_reason=?,
               online_json=COALESCE(?, online_json) WHERE id=?""",
        (status, now, reason[:2000], json.dumps(online, default=str) if online else None,
         trial_id))
    conn.commit()


def extend_trial(conn, trial_id: int, online: dict, reason: str) -> None:
    """Keep a trial open another week (not enough evidence, or promotion frozen)."""
    online = dict(online)
    previous = conn.execute("SELECT online_json FROM ml_shadow_trials WHERE id=?",
                            (trial_id,)).fetchone()
    try:
        extensions = int(json.loads(previous[0] or "{}").get("extensions", 0))
    except (TypeError, ValueError):
        extensions = 0
    online["extensions"] = extensions + 1
    conn.execute("UPDATE ml_shadow_trials SET online_json=?, decision_reason=? WHERE id=?",
                 (json.dumps(online, default=str), reason[:2000], trial_id))
    conn.commit()


def start_trial(conn, version_id: str, component: str, offline: dict, now: str) -> int:
    """Supersede this component's running trial, stage the challenger, open the new trial.

    Order matters: the shadow file is in place BEFORE the trial row exists, so the server
    can never see a running trial without its artefact (which it would count as an error).
    """
    previous = running_trial(conn, component)
    if previous:
        close_trial(conn, previous["id"], "superseded", now,
                    f"replaced by version {version_id}")
    if component == "anomaly":
        store.clear_shadow()
        store.install("anomaly", version_id, slot="shadow")
    cur = conn.execute(
        """INSERT INTO ml_shadow_trials (version_id, components_json, started_at_utc, status,
                                         offline_json)
           VALUES (?, ?, ?, 'running', ?)""",
        (version_id, json.dumps([component]), now, json.dumps(offline, default=str)))
    conn.commit()
    return int(cur.lastrowid)


def evidence(conn, trial_id: int) -> dict:
    """What the server recorded during the trial (one query, shared with the dashboard)."""
    from server.engine import ml_shadow
    return ml_shadow.trial_evidence(conn, trial_id)


def online_gates(ev: dict, policy: config.Policy) -> tuple[str, list[dict]]:
    """('pass' | 'fail' | 'inconclusive', gates) for the anomaly shadow evidence."""
    gates = []
    enough = (ev["active_hours"] >= policy.trial_min_hours
              and ev["processes_scored"] >= policy.trial_min_processes)
    gates.append({"gate": "S0_enough_evidence", "passed": enough,
                  "detail": f"{ev['active_hours']} active hours (need {policy.trial_min_hours}), "
                            f"{ev['processes_scored']} processes (need "
                            f"{policy.trial_min_processes})"})
    gates.append({"gate": "S1_no_errors", "passed": ev["error_rate"] <= policy.trial_max_error_rate,
                  "detail": f"{ev['errors']} failed passes of {ev['passes']}"
                            + (f"; last: {ev['last_error']}" if ev["last_error"] else "")})
    limit = max(ev["champion_flagged"] * policy.trial_volume_ratio,
                ev["champion_flagged"] + policy.trial_volume_slack)
    gates.append({"gate": "S2_no_alert_flood", "passed": ev["challenger_flagged"] <= limit,
                  "detail": f"challenger would have reported {ev['challenger_flagged']} "
                            f"processes, champion reported {ev['champion_flagged']} "
                            f"(limit {limit:g}); {ev['both_flagged']} in common"})
    if ev["champion_ms_mean"] is not None and ev["challenger_ms_mean"] is not None:
        limit = ev["champion_ms_mean"] * policy.trial_latency_ratio + policy.trial_latency_slack_ms
        gates.append({"gate": "S3_latency", "passed": ev["challenger_ms_mean"] <= limit,
                      "detail": f"mean scoring time {ev['challenger_ms_mean']:.1f} ms vs "
                                f"champion {ev['champion_ms_mean']:.1f} ms (limit {limit:.0f})"})
    if not gates[1]["passed"]:
        return "fail", gates                     # errors fail even with little evidence
    if not enough:
        return "inconclusive", gates
    return ("pass" if all(g["passed"] for g in gates) else "fail"), gates


def replay_check(component: str, version_id: str, snapshot: str, since_utc: str) -> dict:
    """Components B and C: run the challenger over the trial window's findings."""
    from server import db as database
    from server.engine import ml_features as mlf

    artefact = scoring.load(store.component_files(version_id, component).get(
        config.COMPONENT_FILES[component][0], ""))
    if artefact is None:
        return {"passed": False, "detail": "challenger artefact missing from the store"}
    conn = database.connect(snapshot)
    try:
        hosts = [r[0] for r in conn.execute(
            "SELECT DISTINCT host_id FROM detections WHERE detected_at_utc >= ?", (since_utc,))]
        frame = mlf.extract_process_frame(conn, host_ids=hosts) if hosts else None
    finally:
        conn.close()
    if frame is None or frame.empty:
        return {"passed": True, "detail": "no findings in the trial window to replay"}
    out = scoring.score(component, artefact, frame.tail(5000), "t1")
    valid = bool(np.all(np.isfinite(out)) and out.min() >= 0 and out.max() <= 1)
    return {"passed": valid, "detail": f"replayed on {min(len(frame), 5000)} processes from "
                                       f"hosts with findings; outputs finite, in [0, 1]"}


def smoke_test(component: str, version_id: str) -> dict:
    """After a swap: the server's own loader must serve exactly this version, intact."""
    from server.engine import ml_registry

    ml_registry.clear_cache()
    return train.canary_check(version_id, component, ml_registry.load_artefact)


def promote_with_rollback(conn, component: str, version_id: str, now: str,
                          reason: str) -> dict:
    """Promote, smoke-test, and restore the previous champion if the test fails."""
    from server import db as database

    entry = store.promote(component, version_id, reason, now)
    check = smoke_test(component, version_id)
    if check["ok"]:
        _register(conn, component, version_id)
        database.audit(conn, "mlops", "ml_model_promoted",
                       {"component": component, "version": version_id, "reason": reason})
        conn.commit()
        return {"component": component, "promoted": True, "version_id": version_id,
                "smoke_test": check, "history": entry}
    restored = None
    try:
        restored = store.rollback(component, now, reason=f"auto-rollback: {check['reason']}")
    except RuntimeError:
        pass
    from server.engine import ml_registry
    ml_registry.clear_cache()
    database.audit(conn, "mlops", "ml_model_rolled_back",
                   {"component": component, "version": version_id, "why": check["reason"],
                    "restored": restored and restored["version_id"]})
    conn.commit()
    return {"component": component, "promoted": False, "rolled_back": True,
            "version_id": version_id, "smoke_test": check,
            "restored": restored and restored["version_id"]}


def _register(conn, component: str, version_id: str) -> None:
    """Record the new champions in ml_models so detections carry correct provenance."""
    from server.engine import ml_registry

    for name in config.COMPONENT_FILES[component]:
        model_type, tier = name.rsplit("_", 1)
        artefact = ml_registry.load_artefact(model_type, tier)
        if artefact is None:
            continue
        metrics = artefact.get("metrics") or {}
        try:
            ml_registry.register(
                conn, name=name, version=str(artefact.get("trained_at_utc") or version_id),
                model_type=model_type, tier=tier,
                feature_spec_sha256=artefact.get("feature_spec_sha256", ""),
                training_rows=int(metrics.get("n") or 0),
                training_source=f"mlops:{version_id}", metrics=metrics,
                path=ml_registry.model_path(model_type, tier), activate=True)
        except sqlite3.Error as exc:             # provenance must not undo a good promotion
            print(f"[mlops] could not register {name}: {exc}")
