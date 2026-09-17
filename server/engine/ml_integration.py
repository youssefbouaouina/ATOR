"""Layer 4.5 ML inside `run_engine()`.

Design follows the evaluation's conclusion rather than the original proposal
(`reports_ml/ML_EVALUATION.md`):

* Component A is a **ranked triage queue, not an alarm**. Precision@25 is 0.84 - 21 of the
  top 25 ranked processes are genuine attacks - while recall at a 1% false-positive rate is
  only 22%. So scoring emits **the top-K most anomalous processes per host**, not everything
  over a threshold. That bounds the analyst's workload by construction instead of hoping a
  threshold generalises.
* Thresholds calibrated on the training corpus were measured to under-state real false
  positives by roughly 6x, so `ATOR_ML_ANOMALY_THRESHOLD` is a floor and `ATOR_ML_TOP_K` is
  the real control.
* ML findings carry `rule_type='ml_anomaly'`, which keeps them separable in the dashboard and
  routable to their own review lane.

**ML must never break deterministic detection.** Every entry point here catches broadly and
returns an empty result on failure. A missing scikit-learn, an unreadable model, a corrupt
feature frame - all degrade to "no ML detections this run" and the YARA/Sigma/IOC pipeline
proceeds untouched.
"""
from __future__ import annotations

import json
import os

from server.engine import ml_registry

# Only the most anomalous K processes per host become detections. This is the alert budget;
# see the module docstring for why it, not the threshold, is the primary control.
DEFAULT_TOP_K = int(os.environ.get("ATOR_ML_TOP_K", "10"))
# Floor beneath which nothing is reported however sparse the run.
DEFAULT_THRESHOLD = float(os.environ.get("ATOR_ML_ANOMALY_THRESHOLD", "0.99"))
# Guard-rail on a first run against a large backlog.
MAX_ROWS_PER_RUN = int(os.environ.get("ATOR_ML_MAX_ROWS", "20000"))

KV_WATERMARK = "ml_anomaly_last_run_utc"

RULE_TYPE_ANOMALY = "ml_anomaly"


def _severity_for(score: float) -> str:
    """Map an anomaly percentile to the framework's severity vocabulary.

    Conservative on purpose: the evaluation showed low recall at low false-positive rates, so
    an ML finding should not outrank a deterministic rule hit. Nothing here returns
    'critical' - that is reserved for rules that actually know what they matched.
    """
    if score >= 0.999:
        return "high"
    if score >= 0.995:
        return "medium"
    return "low"


def _summary_for(row, score: float, explanation: list) -> str:
    """Build `detections.summary` following the existing contract.

    That column is **JSON**, not prose: `sigma_runner.summarize_hit` writes a dict of
    artefact fields and `engine/timeline.py` calls `json.loads()` on it. Emitting a sentence
    here made `/api/v1/timeline` raise JSONDecodeError for every host with an ML detection -
    so ML findings use the same shape, with the ML context added as extra keys.
    """
    out = {}
    for key in ("pid", "ppid", "name", "cmdline", "exe_path", "username"):
        value = row.get(key)
        if value is not None and str(value) != "nan" and str(value):
            out[key] = str(value)[:300]
    drivers = ", ".join(f"{item['feature']}={item['deviation']}" for item in explanation[:3])
    out["ml_anomaly_score"] = f"{score:.4f}"
    out["ml_top_features"] = drivers or "n/a"
    out["ml_note"] = ("statistical deviation from this host's baseline - "
                      "not a rule match; verify before acting")
    return json.dumps(out, default=str)


def run_ml_anomaly_detection(conn, since_utc=None, host_ids=None,
                             top_k: int | None = None,
                             threshold: float | None = None) -> list[dict]:
    """Score recent processes and return detection dicts. Never raises.

    Returns rows shaped for `insert_detections`, plus the ML-specific columns.
    """
    top_k = DEFAULT_TOP_K if top_k is None else top_k
    threshold = DEFAULT_THRESHOLD if threshold is None else threshold

    status = ml_registry.dependencies_available()
    if not status.available:
        return []

    try:
        return _score(conn, since_utc, host_ids, top_k, threshold)
    except Exception as exc:                     # noqa: BLE001 - deliberately broad
        # A failure here must cost us ML findings, never rule findings.
        print(f"[ml] anomaly scoring skipped: {type(exc).__name__}: {exc}")
        return []


def _score(conn, since_utc, host_ids, top_k: int, threshold: float) -> list[dict]:
    import numpy as np

    from server.engine import ml_anomaly, ml_features as mlf

    tier = ml_registry.choose_tier(conn)
    artefact = ml_registry.load_artefact("anomaly", tier)
    if artefact is None and tier == "t2":
        tier = "t1"                              # fall back to the always-deployable model
        artefact = ml_registry.load_artefact("anomaly", tier)
    if artefact is None:
        return []

    frame = mlf.extract_process_frame(conn, host_ids=host_ids, since_utc=since_utc)
    if frame.empty:
        return []
    if len(frame) > MAX_ROWS_PER_RUN:
        frame = frame.tail(MAX_ROWS_PER_RUN)

    stats = mlf.FeatureStats.from_dict(artefact.get("feature_stats") or {})
    X = mlf.transform(frame, stats=stats, tier=tier)

    model = ml_anomaly.AnomalyModel.from_payload(artefact["payload"])
    # The artefact may have been trained on a feature subset (e.g. tier t1 within a t2 spec).
    missing = [c for c in model.feature_names if c not in X.columns]
    if missing:
        print(f"[ml] model expects {len(missing)} feature(s) not produced by the current "
              f"spec (e.g. {missing[:3]}); skipping")
        return []
    X = X[model.feature_names]

    scores = model.score(X)
    model_id = ml_registry.ensure_registered(conn, "anomaly", tier)

    # Rank within each host, then take the top-K above the floor.
    candidates = []
    frame = frame.reset_index(drop=True)
    for host_id in sorted({int(h) for h in frame["host_id"].dropna()}):
        mask = (frame["host_id"] == host_id).to_numpy()
        idx = np.flatnonzero(mask)
        if len(idx) == 0:
            continue
        ranked = idx[np.argsort(scores[idx])[::-1]]
        chosen = [i for i in ranked[:top_k] if scores[i] >= threshold]
        candidates.extend(chosen)

    if not candidates:
        return []

    explanations = model.explain(X.iloc[candidates], top_k=5)
    already = _existing_ml_detections(conn)

    detections = []
    for position, row_index in enumerate(candidates):
        row = frame.iloc[row_index]
        raw_id = row.get("id")
        key = (int(row["host_id"]), str(row.get("collection_id")), int(raw_id)
               if raw_id is not None and not _isnan(raw_id) else -1)
        if key in already:
            continue                             # already reported in an earlier run
        score = float(scores[row_index])
        explanation = explanations[position]
        detections.append({
            "host_id": int(row["host_id"]),
            "collection_id": row.get("collection_id"),
            "rule_type": RULE_TYPE_ANOMALY,
            "rule_name": f"ML Anomaly: {row.get('name') or 'process'}",
            "severity": _severity_for(score),
            "technique_id": None,
            "summary": _summary_for(row, score, explanation),
            "detected_at_utc": row.get("collected_at_utc"),
            "anomaly_score": round(score, 6),
            "ml_model_id": model_id,
            "ml_explanation": json.dumps({
                "tier": tier,
                "raw_process_id": None if raw_id is None or _isnan(raw_id) else int(raw_id),
                "top_features": explanation,
                "note": "deviation from the fitted benign baseline, in robust (MAD) units; "
                        "a hint for triage, not a causal attribution",
            }, default=str),
        })
    return detections


def _isnan(value) -> bool:
    try:
        return value != value                    # NaN is the only value unequal to itself
    except Exception:                            # noqa: BLE001
        return False


def _existing_ml_detections(conn) -> set:
    """Keys of ML detections already recorded, so repeated runs do not duplicate them."""
    out = set()
    try:
        rows = conn.execute(
            """SELECT host_id, collection_id, ml_explanation FROM detections
               WHERE rule_type = ?""", (RULE_TYPE_ANOMALY,)).fetchall()
    except Exception:                            # noqa: BLE001 - pre-migration database
        return out
    for row in rows:
        raw_id = -1
        try:
            payload = json.loads(row["ml_explanation"] or "{}")
            if payload.get("raw_process_id") is not None:
                raw_id = int(payload["raw_process_id"])
        except (json.JSONDecodeError, TypeError, ValueError):
            pass
        out.add((row["host_id"], row["collection_id"], raw_id))
    return out


def insert_ml_detections(conn, detections: list[dict]) -> list[int]:
    """Insert ML detections including their ML-specific columns.

    Separate from `engine.insert_detections` because that function writes the columns the
    deterministic detectors use; widening it would make every rule hit carry empty ML fields.
    """
    ids = []
    for det in detections:
        cur = conn.execute(
            """INSERT INTO detections (host_id, collection_id, rule_type, rule_name,
                                       severity, technique_id, summary, detected_at_utc,
                                       anomaly_score, ml_model_id, ml_explanation)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (det["host_id"], det.get("collection_id"), det["rule_type"], det["rule_name"],
             det["severity"], det.get("technique_id"), det["summary"],
             det["detected_at_utc"], det.get("anomaly_score"), det.get("ml_model_id"),
             det.get("ml_explanation")))
        ids.append(cur.lastrowid)
    conn.commit()
    return ids


# ---------------------------------------------------------------------------
# Component B - confidence scoring for detections (rule-derived AND ML-derived).
# ---------------------------------------------------------------------------

RULE_TYPE_TRIAGE = "ml_triage"


def _pid_from_summary(summary: str | None):
    """Recover the process this detection refers to.

    `detections` stores no foreign key to `raw_processes` - the deterministic engine's
    `insert_detections` never writes `evidence_json` - so the pid in the JSON summary is the
    only link available. Written defensively because that summary is produced by several
    different detectors.
    """
    if not summary:
        return None
    try:
        payload = json.loads(summary)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(payload, dict):
        return None
    for key in ("pid", "ProcessId", "process_id"):
        if payload.get(key) is not None:
            try:
                return int(str(payload[key]).strip())
            except (TypeError, ValueError):
                continue
    return None


def score_detection_confidence(conn, only_missing: bool = True,
                               limit: int = 5000) -> dict:
    """Attach a calibrated P(malicious) to detections, as `confidence_score`.

    Applies to **every** detection source, not just ML: a Sigma hit and an anomaly finding
    both point at a process, and an analyst triaging a queue wants them comparably ranked.
    That is the job `hazem2.md` intended for Component B, now trained on labels that exist.

    Never raises - a failure leaves `confidence_score` NULL, which the UI renders as
    "unscored" rather than as a low confidence.
    """
    status = ml_registry.dependencies_available()
    if not status.available:
        return {"scored": 0, "reason": status.reason}
    try:
        return _score_confidence(conn, only_missing, limit)
    except Exception as exc:                     # noqa: BLE001 - deliberately broad
        print(f"[ml] confidence scoring skipped: {type(exc).__name__}: {exc}")
        return {"scored": 0, "reason": f"{type(exc).__name__}: {exc}"}


def _score_confidence(conn, only_missing: bool, limit: int) -> dict:
    from server.engine import ml_features as mlf, ml_triage

    tier = ml_registry.choose_tier(conn)
    artefact = ml_registry.load_artefact("triage", tier)
    if artefact is None and tier == "t2":
        tier = "t1"
        artefact = ml_registry.load_artefact("triage", tier)
    if artefact is None:
        return {"scored": 0, "reason": "no triage model available"}

    sql = ("SELECT id, host_id, collection_id, summary FROM detections"
           + (" WHERE confidence_score IS NULL" if only_missing else "")
           + " ORDER BY id DESC LIMIT ?")
    rows = conn.execute(sql, (limit,)).fetchall()
    if not rows:
        return {"scored": 0, "reason": "no detections to score"}

    wanted: dict[tuple, list[int]] = {}
    for row in rows:
        pid = _pid_from_summary(row["summary"])
        if pid is None:
            continue
        wanted.setdefault((row["host_id"], row["collection_id"], pid), []).append(row["id"])
    if not wanted:
        return {"scored": 0, "reason": "no detection carried a resolvable pid"}

    host_ids = sorted({key[0] for key in wanted})
    frame = mlf.extract_process_frame(conn, host_ids=host_ids)
    if frame.empty:
        return {"scored": 0, "reason": "no process rows for those hosts"}

    stats = mlf.FeatureStats.from_dict(artefact.get("feature_stats") or {})
    X = mlf.transform(frame, stats=stats, tier=tier)
    model = ml_triage.TriageModel.from_payload(artefact["payload"])
    missing = [c for c in model.used_features if c not in X.columns]
    if missing:
        return {"scored": 0, "reason": f"model expects absent features: {missing[:3]}"}
    X = X[model.feature_names] if set(model.feature_names) <= set(X.columns) else X
    probabilities = model.score(X)

    updates, bands = [], {}
    frame = frame.reset_index(drop=True)
    for index in range(len(frame)):
        row = frame.iloc[index]
        pid = row.get("pid")
        if pid is None or _isnan(pid):
            continue
        key = (int(row["host_id"]), row.get("collection_id"), int(pid))
        for detection_id in wanted.get(key, ()):
            score = float(probabilities[index])
            band = ml_triage.confidence_band(score)
            bands[band] = bands.get(band, 0) + 1
            updates.append((round(score, 6), detection_id))

    if updates:
        conn.executemany(
            "UPDATE detections SET confidence_score = ? WHERE id = ?", updates)
        conn.commit()
    return {"scored": len(updates), "tier": tier, "by_band": bands,
            "model_trained_at": artefact.get("trained_at_utc")}
