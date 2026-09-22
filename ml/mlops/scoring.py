"""Score any stored artefact exactly the way the server does.

Used for the post-promotion canary check and for the paired champion-vs-challenger
comparisons. It goes through the same `FeatureStats` -> `transform` -> model path as
`server/engine/ml_integration.py`, so a comparison measures the models, not two slightly
different scoring routines.
"""
from __future__ import annotations

import numpy as np


def load(path: str) -> dict | None:
    import joblib

    try:
        return joblib.load(path)
    except Exception:                            # noqa: BLE001
        return None


def score(component: str, artefact: dict, frame, tier: str, raw: bool = False) -> np.ndarray:
    """Anomaly percentile, triage P(malicious), or tactic class-probability matrix.

    `raw=True` returns the anomaly model's unbounded forest score instead of its percentile.
    Percentiles saturate at 1.0 for every clear outlier, so two different models can agree on
    them exactly; only the raw score can prove two models are the same.
    """
    from server.engine import ml_anomaly, ml_features as mlf, ml_tactic, ml_triage

    stats = mlf.FeatureStats.from_dict(artefact.get("feature_stats") or {})
    X = mlf.transform(frame, stats=stats, tier=tier)
    if component == "anomaly":
        model = ml_anomaly.AnomalyModel.from_payload(artefact["payload"])
        X = X[model.feature_names]
        return np.asarray(model.raw_scores(X) if raw else model.score(X), dtype="float64")
    if component == "triage":
        model = ml_triage.TriageModel.from_payload(artefact["payload"])
        return np.asarray(model.score(X[model.feature_names]), dtype="float64")
    if component == "tactic":
        model = ml_tactic.TacticModel.from_payload(artefact["payload"])
        return np.asarray(model.predict_proba(X), dtype="float64")
    raise ValueError(f"unknown component {component!r}")


def tier_of(name: str) -> str:
    return name.rsplit("_", 1)[-1]
