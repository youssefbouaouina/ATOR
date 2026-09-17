"""Model registry: load, version and validate Layer 4.5 ML artefacts.

Three jobs, all of them about not shipping a wrong answer:

1. **Availability.** scikit-learn, pandas and numpy are *optional* for this framework. The
   DFIR pipeline must start and detect normally on a machine that has none of them, so every
   import here is lazy and every failure is reported as "ML unavailable", never raised.

2. **Version safety.** A model is only valid against the exact feature contract it was
   trained on. Every artefact records `feature_spec_sha256`, and a model whose hash does not
   match the running `ml_features.FEATURE_SPEC` is **refused**, not used. Silently feeding a
   changed feature vector into a stale forest produces confident nonsense, which is worse
   than no score at all.

3. **Caching.** `run_engine()` may run every minute; deserialising a joblib forest each time
   would be wasteful. Artefacts are cached by path and mtime, so a retrain is picked up
   automatically without a restart.
"""
from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MODELS_DIR = os.environ.get("ATOR_ML_MODEL_DIR", os.path.join(_PROJECT_ROOT, "models"))

MODEL_TYPES = ("anomaly", "triage", "tactic")
TIERS = ("t1", "t2")

_cache: dict[str, tuple[float, object]] = {}
_cache_lock = threading.Lock()


@dataclass(frozen=True)
class MlStatus:
    """Why ML is or is not available - surfaced through /api/v1/ml/status."""
    available: bool
    reason: str = ""
    missing_dependency: str | None = None


def dependencies_available() -> MlStatus:
    """Whether the optional ML stack can be imported at all."""
    for module in ("numpy", "pandas", "sklearn", "joblib"):
        try:
            __import__(module)
        except ImportError:
            return MlStatus(
                available=False,
                reason=f"optional ML dependency {module!r} is not installed "
                       f"(pip install -r requirements-ml.txt)",
                missing_dependency=module,
            )
    return MlStatus(available=True)


def model_path(model_type: str, tier: str) -> str:
    return os.path.join(MODELS_DIR, f"{model_type}_{tier}.joblib")


def load_artefact(model_type: str, tier: str) -> dict | None:
    """Load a joblib artefact, cached by (path, mtime). None when unavailable or stale.

    A feature-spec mismatch returns None rather than raising: the engine should degrade to
    rule-only detection, not crash, when someone edits the feature spec and forgets to
    retrain.
    """
    status = dependencies_available()
    if not status.available:
        return None

    path = model_path(model_type, tier)
    if not os.path.exists(path):
        return None

    mtime = os.path.getmtime(path)
    with _cache_lock:
        cached = _cache.get(path)
        if cached and cached[0] == mtime:
            return cached[1]

    try:
        import joblib
        artefact = joblib.load(path)
    except Exception as exc:                     # noqa: BLE001 - corrupt artefact must not kill the engine
        print(f"[ml_registry] cannot load {path}: {type(exc).__name__}: {exc}")
        return None

    from server.engine import ml_features as mlf
    expected = mlf.feature_spec_sha256()
    actual = artefact.get("feature_spec_sha256")
    if actual != expected:
        print(f"[ml_registry] REFUSING {os.path.basename(path)}: it was trained against "
              f"feature spec {str(actual)[:12]}… but the running spec is {expected[:12]}…. "
              f"Retrain with: python -m ml.training.train_{model_type} --save")
        return None

    with _cache_lock:
        _cache[path] = (mtime, artefact)
    return artefact


def clear_cache() -> None:
    with _cache_lock:
        _cache.clear()


def choose_tier(conn, host_id: int | None = None, collection_id: str | None = None) -> str:
    """Pick the feature tier a host can actually support.

    T2 needs Sysmon rows in `raw_logs`. Scoring a Sysmon-less host with a T2 model would feed
    it a block of NaNs it never saw in training, so hosts without Sysmon get T1.

    Note the evaluation found T2 does not help *this* component (docs: ML_EVALUATION section
    6.2), so `ATOR_ML_TIER` can pin the tier; this function only decides what is *possible*.
    """
    pinned = os.environ.get("ATOR_ML_TIER")
    if pinned in TIERS:
        return pinned
    sql = "SELECT 1 FROM raw_logs WHERE source='sysmon'"
    params: list = []
    if host_id is not None:
        sql += " AND host_id=?"
        params.append(host_id)
    if collection_id is not None:
        sql += " AND collection_id=?"
        params.append(collection_id)
    sql += " LIMIT 1"
    try:
        return "t2" if conn.execute(sql, params).fetchone() else "t1"
    except Exception:                            # noqa: BLE001
        return "t1"


def register(conn, *, name: str, version: str, model_type: str, tier: str,
             feature_spec_sha256: str, training_rows: int, training_source: str,
             metrics: dict | None, path: str, activate: bool = True) -> int:
    """Record a trained model in `ml_models`, optionally making it the active one."""
    from server import db as database
    cur = conn.execute(
        """INSERT OR REPLACE INTO ml_models
               (name, version, model_type, feature_tier, feature_spec_sha256,
                trained_at_utc, training_rows, training_source, metrics_json,
                model_path, is_active)
           VALUES (?,?,?,?,?,?,?,?,?,?,0)""",
        (name, version, model_type, tier, feature_spec_sha256, database.now_iso(),
         training_rows, training_source, json.dumps(metrics or {}, default=str), path))
    model_id = cur.lastrowid
    if activate:
        # Exactly one active model per (type, tier).
        conn.execute(
            "UPDATE ml_models SET is_active=0 WHERE model_type=? AND feature_tier=?",
            (model_type, tier))
        conn.execute("UPDATE ml_models SET is_active=1 WHERE id=?", (model_id,))
    conn.commit()
    return model_id


def active_model_row(conn, model_type: str, tier: str):
    return conn.execute(
        """SELECT * FROM ml_models
           WHERE model_type=? AND feature_tier=? AND is_active=1
           ORDER BY id DESC LIMIT 1""", (model_type, tier)).fetchone()


def ensure_registered(conn, model_type: str, tier: str) -> int | None:
    """Make sure the on-disk artefact has a matching `ml_models` row, and return its id.

    Training writes joblib files; the database row is what detections reference for
    provenance. Creating it lazily here means a model dropped into `models/` by
    `scripts/retrain_ml.py` is usable immediately, without a separate registration step.
    """
    artefact = load_artefact(model_type, tier)
    if artefact is None:
        return None
    path = model_path(model_type, tier)
    version = str(artefact.get("trained_at_utc") or "unknown")
    row = conn.execute(
        "SELECT id FROM ml_models WHERE name=? AND version=?",
        (f"{model_type}_{tier}", version)).fetchone()
    if row:
        return row["id"]
    metrics = artefact.get("metrics") or {}
    return register(
        conn, name=f"{model_type}_{tier}", version=version, model_type=model_type,
        tier=tier, feature_spec_sha256=artefact.get("feature_spec_sha256", ""),
        training_rows=int(metrics.get("n") or 0),
        training_source=str(artefact.get("training_source") or "otrf+local"),
        metrics=metrics, path=path, activate=True)


def describe(conn) -> dict:
    """Everything /api/v1/ml/status needs, without importing the ML stack unless present."""
    status = dependencies_available()
    out: dict = {
        "available": status.available,
        "reason": status.reason,
        "missing_dependency": status.missing_dependency,
        "models_dir": MODELS_DIR,
        "models": [],
    }
    if status.available:
        from server.engine import ml_features as mlf
        out["feature_spec_sha256"] = mlf.feature_spec_sha256()
        out["feature_counts"] = {"total": len(mlf.FEATURE_NAMES),
                                 "t1": len(mlf.T1_FEATURES),
                                 "t2": len(mlf.T2_FEATURES)}
    for model_type in MODEL_TYPES:
        for tier in TIERS:
            path = model_path(model_type, tier)
            entry = {"model_type": model_type, "tier": tier,
                     "artefact_present": os.path.exists(path)}
            if entry["artefact_present"]:
                artefact = load_artefact(model_type, tier)
                entry["loadable"] = artefact is not None
                if artefact is not None:
                    entry["trained_at_utc"] = artefact.get("trained_at_utc")
                    entry["metrics"] = artefact.get("metrics") or {}
                else:
                    entry["note"] = ("artefact refused - feature spec mismatch or "
                                     "unreadable; see server log")
            try:
                row = active_model_row(conn, model_type, tier)
                if row:
                    entry["registered_id"] = row["id"]
                    entry["version"] = row["version"]
            except Exception:                    # noqa: BLE001 - pre-migration database
                pass
            if entry["artefact_present"] or entry.get("registered_id"):
                out["models"].append(entry)
    return out
