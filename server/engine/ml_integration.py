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

import hashlib
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
    import pandas as pd

    out = {}
    for key in ("pid", "ppid", "name", "cmdline", "exe_path", "username"):
        value = row.get(key)
        # pd.isna, not a "nan" string check: pid/ppid are nullable Int64 (Phase 8), whose
        # missing value is pd.NA and stringifies to "<NA>" - which the old check let through
        # into the stored evidence as if it were a real parent pid.
        try:
            missing = value is None or bool(pd.isna(value))
        except (TypeError, ValueError):
            missing = False
        if not missing and str(value):
            out[key] = str(value)[:300]
    drivers = ", ".join(f"{item['feature']}={item['deviation']}" for item in explanation[:3])
    out["ml_anomaly_score"] = f"{score:.4f}"
    out["ml_top_features"] = drivers or "n/a"
    out["ml_note"] = ("statistical deviation from this host's baseline - "
                      "not a rule match; verify before acting")
    return json.dumps(out, default=str)


def run_ml_anomaly_detection(conn, since_utc=None, host_ids=None,
                             top_k: int | None = None,
                             threshold: float | None = None,
                             shadow: bool = False) -> list[dict]:
    """Score recent processes and return detection dicts. Never raises.

    Returns rows shaped for `insert_detections`, plus the ML-specific columns.

    `shadow=True` (the engine's incremental pass only) also scores the same processes with a
    challenger model under a live trial, if one is running - see `ml_shadow`. Manual
    "Run hunt now" rescans all history and would double-count the trial's traffic, so it
    leaves this off.
    """
    top_k = DEFAULT_TOP_K if top_k is None else top_k
    threshold = DEFAULT_THRESHOLD if threshold is None else threshold

    status = ml_registry.dependencies_available()
    if not status.available:
        return []

    try:
        return _score(conn, since_utc, host_ids, top_k, threshold, shadow)
    except Exception as exc:                     # noqa: BLE001 - deliberately broad
        # A failure here must cost us ML findings, never rule findings.
        print(f"[ml] anomaly scoring skipped: {type(exc).__name__}: {exc}")
        return []


def select_candidates(frame, scores, top_k: int, threshold: float) -> list[int]:
    """Row positions that become findings: the top-K per host, above the floor.

    Shared with the shadow challenger (`ml_shadow`), so both models are held to exactly the
    same alert budget and a trial compares models, not selection rules.
    """
    import numpy as np

    candidates = []
    for host_id in sorted({int(h) for h in frame["host_id"].dropna()}):
        mask = (frame["host_id"] == host_id).to_numpy()
        idx = np.flatnonzero(mask)
        if len(idx) == 0:
            continue
        ranked = idx[np.argsort(scores[idx])[::-1]]
        candidates.extend(i for i in ranked[:top_k] if scores[i] >= threshold)
    return candidates


def _score(conn, since_utc, host_ids, top_k: int, threshold: float,
           shadow: bool = False) -> list[dict]:
    import time

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

    started = time.perf_counter()
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
    champion_ms = (time.perf_counter() - started) * 1000.0
    model_id = ml_registry.ensure_registered(conn, "anomaly", tier)

    # Rank within each host, then take the top-K above the floor.
    frame = frame.reset_index(drop=True)
    candidates = select_candidates(frame, scores, top_k, threshold)

    if shadow:
        # Isolated like the whole ML layer: record_shadow_pass never raises, never writes a
        # detection, and cannot change `scores` or `candidates`.
        from server.engine import ml_shadow
        ml_shadow.record_shadow_pass(
            conn, frame=frame, tier=tier, champion_scores=scores,
            champion_candidates=candidates, champion_ms=champion_ms,
            top_k=top_k, threshold=threshold)

    if not candidates:
        return []

    explanations = model.explain(X.iloc[candidates], top_k=5)
    by_process, legacy = _existing_ml_detections(conn)

    detections = []
    for position, row_index in enumerate(candidates):
        row = frame.iloc[row_index]
        raw_id = row.get("id")
        process_key = _process_key(row)
        known = by_process.get(process_key)
        if known is not None:
            # Same process instance, flagged again. It is one finding: record the
            # recurrence instead of opening a new detection (see _existing_ml_detections).
            # Only an observation NEWER than the last sighting counts. Without this check
            # a manual "Run hunt now", which rescans all history, re-counted old sweeps on
            # every click and the sighting count grew with the number of clicks.
            observed = str(row.get("collected_at_utc") or "")
            if observed and observed > (known["last_seen"] or ""):
                detections.append({
                    "existing_id": known["id"],
                    "collection_id": row.get("collection_id"),
                    "detected_at_utc": observed,
                })
                known["last_seen"] = observed        # two rows in one run count once each
            continue
        legacy_key = (int(row["host_id"]), str(row.get("collection_id")), int(raw_id)
                      if raw_id is not None and not _isnan(raw_id) else -1)
        if legacy_key in legacy:
            continue                             # reported before process keys existed
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
                "process_key": process_key,
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


#: The fields that identify one process instance. They mirror the v2 raw_processes
#: dedupe key (server/db.py), so "one raw row" and "one ML finding" mean the same thing.
_PROCESS_IDENTITY = ("pid", "name", "cmdline", "exe_path", "sha256", "create_time_utc")


def _process_key(row) -> str:
    """Stable identity of a process instance, independent of which collection holds it.

    Keying findings on the collection was the defect: the DFIR ingest now moves a
    re-observed process into the newest collection, so a long-running suspicious
    process got a brand-new detection on every sweep - measured at one per sweep,
    i.e. 60 an hour with the agent's default loop.
    """
    def norm(value):
        if value is None or _isnan(value):
            return ""
        if isinstance(value, float) and value.is_integer():
            return str(int(value))                # a pid must not hash differently as 4.0
        return str(value)

    parts = [norm(row.get("host_id"))] + [norm(row.get(name)) for name in _PROCESS_IDENTITY]
    return hashlib.sha1("\x1f".join(parts).encode("utf-8", "replace")).hexdigest()


def _existing_ml_detections(conn) -> tuple[dict, set]:
    """Findings already recorded: ({process_key: {id, last_seen}}, {legacy keys}).

    `last_seen` is the newest observation already counted for the finding, so a rescan of
    old history is recognised as nothing new.

    Detections created before process keys existed carry only raw_process_id. Their
    key is rebuilt from that raw row when it still exists, so the upgrade does not
    open one more duplicate per already-flagged process. Anything that cannot be
    resolved falls back to the old (host, collection, raw id) key.
    """
    by_process: dict[str, dict] = {}
    legacy: set = set()
    try:
        rows = conn.execute(
            """SELECT id, host_id, collection_id, ml_explanation,
                      COALESCE(last_seen_utc, detected_at_utc) AS last_seen
               FROM detections WHERE rule_type = ? ORDER BY id""",
            (RULE_TYPE_ANOMALY,)).fetchall()
    except Exception:                            # noqa: BLE001 - pre-migration database
        return by_process, legacy

    unresolved: dict[int, dict] = {}
    for row in rows:
        raw_id = -1
        entry = {"id": row["id"], "last_seen": str(row["last_seen"] or "")}
        try:
            payload = json.loads(row["ml_explanation"] or "{}")
            if payload.get("process_key"):
                by_process.setdefault(payload["process_key"], entry)
                continue
            if payload.get("raw_process_id") is not None:
                raw_id = int(payload["raw_process_id"])
        except (json.JSONDecodeError, TypeError, ValueError):
            pass
        legacy.add((row["host_id"], row["collection_id"], raw_id))
        if raw_id >= 0:
            unresolved[raw_id] = entry

    if unresolved:
        wanted = ["host_id"] + list(_PROCESS_IDENTITY)
        try:
            present = {r[1] for r in conn.execute("PRAGMA table_info(raw_processes)")}
            select = ", ".join(c if c in present else f"NULL AS {c}" for c in wanted)
            ids = list(unresolved)
            for start in range(0, len(ids), 500):          # SQLite parameter limit
                chunk = ids[start:start + 500]
                marks = ",".join("?" * len(chunk))
                for raw in conn.execute(
                        f"SELECT id, {select} FROM raw_processes WHERE id IN ({marks})", chunk):
                    by_process.setdefault(_process_key(dict(raw)), unresolved[raw["id"]])
        except Exception:                        # noqa: BLE001 - legacy keys still apply
            pass
    return by_process, legacy


def insert_ml_detections(conn, detections: list[dict]) -> list[int]:
    """Write ML detections; return the ids of NEW findings only.

    A dict carrying `existing_id` is a recurrence of a finding already on record: it
    bumps that row's hit_count/last_seen_utc and moves it to the newest collection,
    the same convention `engine.insert_detections` uses for rule hits. Returning only
    new ids keeps that contract too - callers enrich and evaluate policies for genuinely
    new findings, not for every sighting of an old one.

    Separate from `engine.insert_detections` because that function writes the columns the
    deterministic detectors use; widening it would make every rule hit carry empty ML fields.
    """
    ids = []
    for det in detections:
        if det.get("existing_id") is not None:
            conn.execute(
                """UPDATE detections SET hit_count = COALESCE(hit_count, 1) + 1,
                                         last_seen_utc = ?, collection_id = ?
                   WHERE id = ?""",
                (det.get("detected_at_utc"), det.get("collection_id"), det["existing_id"]))
            continue
        cur = conn.execute(
            """INSERT INTO detections (host_id, collection_id, rule_type, rule_name,
                                       severity, technique_id, summary, detected_at_utc,
                                       anomaly_score, ml_model_id, ml_explanation,
                                       hit_count, last_seen_utc)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,1,?)""",
            (det["host_id"], det.get("collection_id"), det["rule_type"], det["rule_name"],
             det["severity"], det.get("technique_id"), det["summary"],
             det["detected_at_utc"], det.get("anomaly_score"), det.get("ml_model_id"),
             det.get("ml_explanation"), det["detected_at_utc"]))
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


# ---------------------------------------------------------------------------
# Component C - ATT&CK tactic suggestion for ML findings.
# ---------------------------------------------------------------------------

def _gate_precision(artefact: dict | None) -> float | None:
    """Measured precision at the shipped gate, read from the artefact's own evaluation.

    Returns None rather than a default when the artefact predates the gate analysis: a
    plausible-looking but wrong precision in front of an analyst is worse than no number.
    """
    gate = ((artefact or {}).get("metrics") or {}).get("gating") or {}
    value = (gate.get("shipped_operating_point") or {}).get("precision")
    return float(value) if value is not None else None


def suggest_tactics(conn, only_missing: bool = True, limit: int = 2000) -> dict:
    """Attach ranked tactic hints to ML detections that carry no technique mapping.

    Why this now runs at all: at Phase 5 the component was measured at 59.5% accuracy even at
    its best operating point and was deliberately NOT deployed. Phase 7a's label recovery
    (185 -> 205 positives, and five learnable classes instead of three) moved it to roughly
    three-in-four precision at p>=0.80 on the well-supported classes, which is worth showing
    as a hint. The exact figure is re-measured on every training run and read back out of the
    artefact - see `_gate_precision` - because it moves whenever the model is retrained.

    Two guards keep it honest, both measured rather than assumed:
      * `MIN_SUGGESTION_PROBABILITY` (0.80) - below it nothing is emitted at all;
      * `MIN_SUPPORT_TO_SUGGEST` (30 training examples) - thinly-supported classes such as
        persistence (F1 0.00 on n=10) are never suggested even when they win the argmax.

    The output is a hint and the UI must say so. Never raises.
    """
    status = ml_registry.dependencies_available()
    if not status.available:
        return {"suggested": 0, "reason": status.reason}
    try:
        return _suggest_tactics(conn, only_missing, limit)
    except Exception as exc:                     # noqa: BLE001 - deliberately broad
        print(f"[ml] tactic suggestion skipped: {type(exc).__name__}: {exc}")
        return {"suggested": 0, "reason": f"{type(exc).__name__}: {exc}"}


def _suggest_tactics(conn, only_missing: bool, limit: int) -> dict:
    from server.engine import ml_features as mlf, ml_tactic

    tier = ml_registry.choose_tier(conn)
    artefact = ml_registry.load_artefact("tactic", tier)
    if artefact is None and tier != "t1":
        tier = "t1"
        artefact = ml_registry.load_artefact("tactic", tier)
    if artefact is None:
        return {"suggested": 0, "reason": "no tactic model available"}

    # Built once here rather than quoted as a literal, so a retrain that moves the measured
    # precision cannot leave a stale claim written into every detection row.
    _precision = _gate_precision(artefact)
    _hint_note = ("ML hint, not an authoritative ATT&CK mapping"
                  + (f"; ~{round(_precision * 100)}% precision at this threshold"
                     if _precision else ""))

    # Only detections Component B already rates as probably-malicious. The tactic model was
    # trained on malicious processes alone, so asking it about a benign one is out of
    # distribution - it answered "lateral_movement, p=1.00" for chrome.exe before this gate
    # existed. Detections with no confidence score yet are skipped rather than guessed at.
    sql = ("SELECT id, host_id, collection_id, summary FROM detections "
           "WHERE rule_type = ? AND technique_id IS NULL "
           "AND confidence_score IS NOT NULL AND confidence_score >= ?"
           + (" AND suggested_tactics IS NULL" if only_missing else "")
           + " ORDER BY id DESC LIMIT ?")
    rows = conn.execute(
        sql, (RULE_TYPE_ANOMALY, ml_tactic.MIN_CONFIDENCE_TO_SUGGEST, limit)).fetchall()
    if not rows:
        return {"suggested": 0,
                "reason": "no ML detection is both unmapped and above the confidence gate",
                "confidence_gate": ml_tactic.MIN_CONFIDENCE_TO_SUGGEST}

    wanted: dict[tuple, list[int]] = {}
    for row in rows:
        pid = _pid_from_summary(row["summary"])
        if pid is not None:
            wanted.setdefault((row["host_id"], row["collection_id"], pid), []).append(row["id"])
    if not wanted:
        return {"suggested": 0, "reason": "no detection carried a resolvable pid"}

    frame = mlf.extract_process_frame(conn, host_ids=sorted({k[0] for k in wanted}))
    if frame.empty:
        return {"suggested": 0, "reason": "no process rows"}

    stats = mlf.FeatureStats.from_dict(artefact.get("feature_stats") or {})
    X = mlf.transform(frame, stats=stats, tier=tier)
    model = ml_tactic.TacticModel.from_payload(artefact["payload"])
    if [c for c in model.used_features if c not in X.columns]:
        return {"suggested": 0, "reason": "model expects features the spec no longer produces"}

    suggestions = model.suggest(X)
    updates, emitted = [], 0
    frame = frame.reset_index(drop=True)
    for index in range(len(frame)):
        row = frame.iloc[index]
        pid = row.get("pid")
        if pid is None or _isnan(pid):
            continue
        key = (int(row["host_id"]), row.get("collection_id"), int(pid))
        hits = suggestions[index]
        if not hits:
            continue                             # below threshold: emit nothing, not a guess
        payload = json.dumps({
            "suggestions": hits,
            "model_tier": tier,
            # Precision comes from the artefact's own gate analysis rather than a literal,
            # so a retrain that moves it cannot leave a stale claim in the database.
            "note": _hint_note,
        }, default=str)
        for detection_id in wanted.get(key, ()):
            updates.append((payload, detection_id))
            emitted += 1

    if updates:
        conn.executemany(
            "UPDATE detections SET suggested_tactics = ? WHERE id = ?", updates)
        conn.commit()
    return {"suggested": emitted, "tier": tier,
            "suggestable_classes": getattr(model, "suggestable_", []),
            "probability_threshold": ml_tactic.MIN_SUGGESTION_PROBABILITY,
            "confidence_gate": ml_tactic.MIN_CONFIDENCE_TO_SUGGEST}
