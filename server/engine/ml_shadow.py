"""Shadow scoring: the "A/B test in deployment" half of the weekly MLOps pipeline.

While a trial is running (a row in `ml_shadow_trials` with status 'running', and the
challenger's artefact in `models/shadow/`), every incremental engine pass scores the SAME
processes with the champion (as always) and with the challenger. The challenger's would-be
findings are recorded here and nowhere else. They never become detections, and analysts
never see them. Next week's pipeline run compares the two on identical traffic and decides
(`ml/mlops/trial.py`).

Why shadow instead of splitting hosts between the models: see docs/ML_MLOPS_PLAN.md 4.2. In
short, a split leaves half the hosts on the worse detector for a week, and with a handful of
hosts a paired comparison is the only one with any statistical power.

Isolation contract (tests/test_mlops_shadow.py):
* `record_shadow_pass` never raises. Failures are counted as trial errors, which is itself
  a trial outcome: a challenger that errors in production must not be promoted.
* it never writes to `detections` and never mutates the champion's scores or candidates.
* it adds at most one bounded write per pass (hour bucket) plus one row per distinct
  flagged process, so a week of passes cannot grow the database meaningfully.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from server.engine import ml_registry


def active_trial(conn) -> dict | None:
    """The running trial, or None. Tolerates a database that predates the tables."""
    try:
        row = conn.execute(
            """SELECT id, version_id, components_json FROM ml_shadow_trials
               WHERE status = 'running' AND components_json LIKE '%"anomaly"%'
               ORDER BY id DESC LIMIT 1""").fetchone()
    except Exception:                            # noqa: BLE001 - pre-migration database
        return None
    if row is None:
        return None
    try:
        components = json.loads(row["components_json"] or "[]")
    except (TypeError, ValueError):
        components = []
    return {"id": int(row["id"]), "version_id": row["version_id"], "components": components}


def _hour_bucket(now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:00:00+00:00")


def _record_observation(conn, trial_id: int, *, processes: int, champion_ms: float,
                        challenger_ms: float, error: str | None) -> None:
    conn.execute(
        """INSERT INTO ml_shadow_observations
               (trial_id, hour_utc, passes, processes_scored, errors, champion_ms_total,
                challenger_ms_total, challenger_ms_max, last_error)
           VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(trial_id, hour_utc) DO UPDATE SET
               passes = passes + 1,
               processes_scored = processes_scored + excluded.processes_scored,
               errors = errors + excluded.errors,
               champion_ms_total = champion_ms_total + excluded.champion_ms_total,
               challenger_ms_total = challenger_ms_total + excluded.challenger_ms_total,
               challenger_ms_max = MAX(challenger_ms_max, excluded.challenger_ms_max),
               last_error = COALESCE(excluded.last_error, last_error)""",
        (trial_id, _hour_bucket(), int(processes), 1 if error else 0,
         float(champion_ms), float(challenger_ms), float(challenger_ms),
         (error or None) and error[:500]))


def record_shadow_pass(conn, *, frame, tier: str, champion_scores, champion_candidates,
                       champion_ms: float, top_k: int, threshold: float) -> dict | None:
    """Score `frame` with the challenger and record the comparison. Never raises.

    Returns a small summary for tests and logs, or None when no trial is running.
    """
    try:
        trial = active_trial(conn)
        if trial is None or "anomaly" not in trial["components"]:
            return None
    except Exception:                            # noqa: BLE001
        return None

    try:
        return _score_challenger(conn, trial, frame=frame, tier=tier,
                                 champion_scores=champion_scores,
                                 champion_candidates=champion_candidates,
                                 champion_ms=champion_ms, top_k=top_k, threshold=threshold)
    except Exception as exc:                     # noqa: BLE001 - deliberately broad
        message = f"{type(exc).__name__}: {exc}"
        try:
            _record_observation(conn, trial["id"], processes=len(frame),
                                champion_ms=champion_ms, challenger_ms=0.0, error=message)
        except Exception:                        # noqa: BLE001 - even bookkeeping may fail
            pass
        print(f"[ml] shadow scoring failed (trial {trial['id']}): {message}")
        return {"trial_id": trial["id"], "error": message}


def _score_challenger(conn, trial: dict, *, frame, tier, champion_scores,
                      champion_candidates, champion_ms, top_k, threshold) -> dict:
    import pandas as pd

    from server.engine import ml_anomaly, ml_features as mlf
    from server.engine.ml_integration import _process_key, select_candidates

    artefact = ml_registry.load_artefact("anomaly", tier, slot="shadow")
    if artefact is None:
        raise RuntimeError(f"challenger artefact anomaly_{tier} is missing or was refused "
                           f"(feature spec mismatch?)")
    if artefact.get("version_id") != trial["version_id"]:
        # The file in models/shadow/ is not the model this trial is about. Scoring it would
        # attribute one model's behaviour to another's trial.
        raise RuntimeError(f"shadow artefact version {artefact.get('version_id')!r} does not "
                           f"match trial version {trial['version_id']!r}")

    started = time.perf_counter()
    stats = mlf.FeatureStats.from_dict(artefact.get("feature_stats") or {})
    X = mlf.transform(frame, stats=stats, tier=tier)
    model = ml_anomaly.AnomalyModel.from_payload(artefact["payload"])
    X = X[model.feature_names]
    challenger_scores = model.score(X)
    challenger_ms = (time.perf_counter() - started) * 1000.0
    challenger_candidates = select_candidates(frame, challenger_scores, top_k, threshold)

    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    champion_set, challenger_set = set(champion_candidates), set(challenger_candidates)
    rows = []
    for index in sorted(champion_set | challenger_set):
        row = frame.iloc[index]
        try:
            pid = None if pd.isna(row.get("pid")) else int(row.get("pid"))
        except (TypeError, ValueError):
            pid = None
        rows.append((trial["id"], _process_key(row), int(row["host_id"]), pid,
                     str(row.get("name") or "")[:200],
                     1 if index in champion_set else 0,
                     1 if index in challenger_set else 0,
                     float(champion_scores[index]), float(challenger_scores[index]), now))
    if rows:
        # A process flagged on several passes is one entry; a flag, once raised, stays raised.
        conn.executemany(
            """INSERT INTO ml_shadow_flags
                   (trial_id, process_key, host_id, pid, name, champion_flag, challenger_flag,
                    champion_score, challenger_score, first_seen_utc)
               VALUES (?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(trial_id, process_key) DO UPDATE SET
                   champion_flag = MAX(champion_flag, excluded.champion_flag),
                   challenger_flag = MAX(challenger_flag, excluded.challenger_flag),
                   champion_score = MAX(COALESCE(champion_score, 0), excluded.champion_score),
                   challenger_score = MAX(COALESCE(challenger_score, 0),
                                          excluded.challenger_score)""", rows)
    _record_observation(conn, trial["id"], processes=len(frame), champion_ms=champion_ms,
                        challenger_ms=challenger_ms, error=None)
    return {"trial_id": trial["id"], "processes": len(frame),
            "champion_flagged": len(champion_set), "challenger_flagged": len(challenger_set),
            "overlap": len(champion_set & challenger_set), "error": None}


def trial_evidence(conn, trial_id: int) -> dict:
    """Aggregate what shadow scoring recorded for one trial.

    Read by the weekly pipeline (to decide) and by the dashboard (to show progress), so both
    see the same numbers.
    """
    obs = conn.execute(
        """SELECT COUNT(*), COALESCE(SUM(passes),0), COALESCE(SUM(processes_scored),0),
                  COALESCE(SUM(errors),0), COALESCE(SUM(champion_ms_total),0),
                  COALESCE(SUM(challenger_ms_total),0), COALESCE(MAX(challenger_ms_max),0),
                  MAX(last_error)
           FROM ml_shadow_observations WHERE trial_id=?""", (trial_id,)).fetchone()
    flags = conn.execute(
        """SELECT COALESCE(SUM(champion_flag),0), COALESCE(SUM(challenger_flag),0),
                  COALESCE(SUM(champion_flag * challenger_flag),0)
           FROM ml_shadow_flags WHERE trial_id=?""", (trial_id,)).fetchone()
    passes = int(obs[1])
    ok_passes = max(passes - int(obs[3]), 0)
    # Rule corroboration: a flagged process that a deterministic detector also hit.
    # Informational - a proxy for precision when analysts have not labelled anything.
    corroborated = {}
    for column in ("champion_flag", "challenger_flag"):
        corroborated[column.split("_")[0]] = conn.execute(
            f"""SELECT COUNT(DISTINCT f.process_key) FROM ml_shadow_flags f
                JOIN detections d ON d.host_id = f.host_id
                 AND d.rule_type NOT IN ('ml_anomaly','ml_triage')
                 AND json_valid(d.summary)
                 AND CAST(json_extract(d.summary, '$.pid') AS INTEGER) = f.pid
                WHERE f.trial_id = ? AND f.{column} = 1""", (trial_id,)).fetchone()[0]
    return {
        "active_hours": int(obs[0]), "passes": passes, "processes_scored": int(obs[2]),
        "errors": int(obs[3]), "error_rate": (int(obs[3]) / passes) if passes else 0.0,
        "champion_ms_mean": (obs[4] / ok_passes) if ok_passes else None,
        "challenger_ms_mean": (obs[5] / ok_passes) if ok_passes else None,
        "challenger_ms_max": obs[6], "last_error": obs[7],
        "champion_flagged": int(flags[0]), "challenger_flagged": int(flags[1]),
        "both_flagged": int(flags[2]), "rule_corroborated": corroborated,
    }
