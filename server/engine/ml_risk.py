"""Host risk score - deterministic aggregation, not a model.

Deliberately not machine learning. There is no label for "how compromised is this host", so
anything learned would be fitting an invention. What an analyst actually needs is a defensible
ordering of hosts to look at first, and a weighted sum with stated weights gives that while
remaining completely explainable: every point in the score can be traced to a detection.

Formula (adapted from hazem2.md section 3.4, with the changes noted below):

    score = SUM over detections of (severity_weight * recency_decay)
          + tactic_diversity_bonus
          + ml_anomaly_spike

* **Recency decay** `0.95 ^ days` - a critical finding from 60 days ago should not keep a host
  at the top of the queue forever.
* **Tactic diversity** `+3` per distinct ATT&CK tactic. Five detections all of one tactic is
  usually one noisy rule; three detections spanning three tactics looks like a kill chain.
* **ML anomaly spike** - ML findings are capped in aggregate (`ML_SPIKE_CAP`), because
  Component A emits a fixed top-K per host per run and would otherwise let a quiet host drift
  upward simply by being observed often.

Changes from the original proposal: it assigned ML anomalies a flat `+5` with `0.9^hours`
decay, which on a 60-second engine loop would dominate the score within a day. The cap plus
per-detection weighting keeps deterministic findings in charge, which matches the evaluation's
conclusion that ML is a triage aid rather than an authority.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

SEVERITY_WEIGHTS = {"critical": 10.0, "high": 5.0, "medium": 2.0, "low": 0.5}
DAILY_DECAY = 0.95
TACTIC_DIVERSITY_BONUS = 3.0
ML_SPIKE_CAP = float(os.environ.get("ATOR_ML_RISK_SPIKE_CAP", "10.0"))

# Tier boundaries. Chosen so a single high-severity finding lands 'medium' and a multi-tactic
# chain lands 'high'; they are presentation, not science, and are tunable per estate.
TIER_THRESHOLDS = (("critical", 40.0), ("high", 20.0), ("medium", 8.0), ("low", 0.0))


def _parse(ts):
    if not ts:
        return None
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None


def tier_for(score: float) -> str:
    for name, threshold in TIER_THRESHOLDS:
        if score >= threshold:
            return name
    return "low"


def compute_host_risk(conn, host_id: int, now: datetime | None = None) -> dict:
    """Score one host. Returns the score, tier and a full breakdown."""
    now = now or datetime.now(timezone.utc)
    rows = conn.execute(
        """SELECT d.severity, d.detected_at_utc, d.rule_type, d.technique_id,
                  e.tactic AS tactic
           FROM detections d
           LEFT JOIN enriched_detections e ON e.detection_id = d.id
           WHERE d.host_id = ?""", (host_id,)).fetchall()

    detection_points = 0.0
    ml_points = 0.0
    tactics: set[str] = set()
    by_severity: dict[str, int] = {}
    counted = 0

    for row in rows:
        severity = (row["severity"] or "low").lower()
        weight = SEVERITY_WEIGHTS.get(severity, 0.5)
        detected = _parse(row["detected_at_utc"])
        days = max((now - detected).total_seconds() / 86400.0, 0.0) if detected else 0.0
        decayed = weight * (DAILY_DECAY ** days)

        if row["rule_type"] == "ml_anomaly":
            ml_points += decayed
        else:
            detection_points += decayed
            # Only deterministic findings contribute tactic diversity: an ML suggestion is a
            # hint, and letting hints inflate a kill-chain signal would be circular.
            if row["tactic"]:
                tactics.add(str(row["tactic"]))
        by_severity[severity] = by_severity.get(severity, 0) + 1
        counted += 1

    ml_points = min(ml_points, ML_SPIKE_CAP)
    diversity = TACTIC_DIVERSITY_BONUS * len(tactics)
    score = detection_points + diversity + ml_points

    return {
        "host_id": host_id,
        "score": round(score, 3),
        "tier": tier_for(score),
        "breakdown": {
            "detection_points": round(detection_points, 3),
            "tactic_diversity_bonus": round(diversity, 3),
            "distinct_tactics": sorted(tactics),
            "ml_anomaly_points": round(ml_points, 3),
            "ml_points_capped_at": ML_SPIKE_CAP,
            "detections_considered": counted,
            "by_severity": by_severity,
        },
    }


def update_all(conn, now: datetime | None = None) -> dict:
    """Recompute every active host's risk and persist it to `host_risk_scores`."""
    now = now or datetime.now(timezone.utc)
    host_ids = [r[0] for r in conn.execute("SELECT id FROM hosts WHERE is_active = 1")]
    written = []
    for host_id in host_ids:
        result = compute_host_risk(conn, host_id, now=now)
        conn.execute(
            """INSERT INTO host_risk_scores (host_id, score, tier, last_computed_utc,
                                             breakdown_json)
               VALUES (?,?,?,?,?)
               ON CONFLICT(host_id) DO UPDATE SET
                   score=excluded.score, tier=excluded.tier,
                   last_computed_utc=excluded.last_computed_utc,
                   breakdown_json=excluded.breakdown_json""",
            (host_id, result["score"], result["tier"],
             now.isoformat(timespec="seconds"),
             json.dumps(result["breakdown"], default=str)))
        written.append(result)
    conn.commit()
    return {"hosts_scored": len(written),
            "by_tier": {t: sum(1 for r in written if r["tier"] == t)
                        for t in ("critical", "high", "medium", "low")},
            "scores": sorted(written, key=lambda r: -r["score"])}


def get_host_risk(conn, host_id: int) -> dict | None:
    row = conn.execute(
        "SELECT * FROM host_risk_scores WHERE host_id = ?", (host_id,)).fetchone()
    if not row:
        return None
    out = dict(row)
    try:
        out["breakdown"] = json.loads(out.pop("breakdown_json") or "{}")
    except json.JSONDecodeError:
        out["breakdown"] = {}
    return out
