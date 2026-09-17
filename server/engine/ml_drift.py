"""Feature drift monitoring (Population Stability Index).

Why this exists
---------------
A model is fitted against one distribution and then serves a different one forever after.
Endpoints get new software, users change habits, a new build rolls out - and the model keeps
emitting confident scores while the ground shifts underneath it. Nothing in the pipeline would
notice.

PSI compares the *training* distribution of each feature with the distribution the model is
actually being served, using the bin edges fixed at training time:

    PSI = SUM over bins of (actual% - expected%) * ln(actual% / expected%)

Conventional reading, used here:

    < 0.10  stable
    0.10 - 0.25  moderate shift, worth watching
    > 0.25  shifted - retrain

The numbers are heuristics from credit-risk practice, not laws, and are reported as such. What
matters operationally is the *direction*: a feature that was 5% missing in training and is now
80% missing indicates a broken collector, which PSI surfaces immediately.

Missingness is treated as its own bin rather than dropped. For this feature set that is the
point: `sysmon_available`, `cmdline_present` and `conn_available` encode collection health,
so a jump in missingness is exactly the signal worth catching.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

PSI_STABLE = 0.10
PSI_SHIFTED = 0.25
DEFAULT_BINS = 10
# Replaces a zero proportion so the logarithm stays finite; standard PSI practice.
_EPSILON = 1e-6


def verdict_for(psi: float) -> str:
    if not np.isfinite(psi):
        return "stable"
    if psi > PSI_SHIFTED:
        return "shifted"
    if psi > PSI_STABLE:
        return "moderate"
    return "stable"


def _edges(values: np.ndarray, n_bins: int) -> np.ndarray:
    """Quantile bin edges from the reference sample, deduplicated."""
    finite = values[np.isfinite(values)]
    if len(finite) == 0:
        return np.array([])
    quantiles = np.linspace(0, 100, n_bins + 1)
    edges = np.unique(np.percentile(finite, quantiles))
    if len(edges) < 2:
        return np.array([])
    edges[0], edges[-1] = -np.inf, np.inf
    return edges


def _proportions(values: np.ndarray, edges: np.ndarray) -> np.ndarray:
    """Binned proportions, with missing as a dedicated final bin."""
    finite_mask = np.isfinite(values)
    total = max(len(values), 1)
    counts = np.histogram(values[finite_mask], bins=edges)[0].astype("float64")
    missing = float((~finite_mask).sum())
    return np.append(counts, missing) / total


def psi_for_feature(reference: np.ndarray, current: np.ndarray,
                    n_bins: int = DEFAULT_BINS) -> float:
    """PSI for one feature. 0.0 when there is nothing to compare."""
    reference = np.asarray(reference, dtype="float64")
    current = np.asarray(current, dtype="float64")
    if len(reference) == 0 or len(current) == 0:
        return 0.0

    edges = _edges(reference, n_bins)
    if len(edges) == 0:
        # Reference is entirely missing; the only meaningful comparison is missingness.
        ref_missing = float((~np.isfinite(reference)).mean())
        cur_missing = float((~np.isfinite(current)).mean())
        return abs(cur_missing - ref_missing)

    expected = np.clip(_proportions(reference, edges), _EPSILON, None)
    actual = np.clip(_proportions(current, edges), _EPSILON, None)
    return float(np.sum((actual - expected) * np.log(actual / expected)))


def compute_drift(reference: pd.DataFrame, current: pd.DataFrame,
                  n_bins: int = DEFAULT_BINS) -> list[dict]:
    """PSI per shared feature, worst first."""
    shared = [c for c in reference.columns if c in current.columns]
    out = []
    for column in shared:
        ref = reference[column].to_numpy(dtype="float64")
        cur = current[column].to_numpy(dtype="float64")
        psi = psi_for_feature(ref, cur, n_bins)
        out.append({
            "feature": column,
            "psi": round(psi, 4),
            "verdict": verdict_for(psi),
            "reference_missing_pct": round(float((~np.isfinite(ref)).mean()) * 100, 2),
            "current_missing_pct": round(float((~np.isfinite(cur)).mean()) * 100, 2),
        })
    return sorted(out, key=lambda r: r["psi"], reverse=True)


def record_drift(conn, model_id: int | None, drift_rows: list[dict],
                 only_notable: bool = True) -> int:
    """Persist drift results to `ml_drift_log`. Returns the number of rows written."""
    from server import db as database
    now = database.now_iso()
    payload = [
        (now, model_id, row["feature"], row["psi"], row["verdict"])
        for row in drift_rows
        if not only_notable or row["verdict"] != "stable"
    ]
    if payload:
        conn.executemany(
            """INSERT INTO ml_drift_log (computed_at_utc, model_id, feature_name, psi, verdict)
               VALUES (?,?,?,?,?)""", payload)
        conn.commit()
    return len(payload)


def summarise(drift_rows: list[dict]) -> dict:
    counts = {"stable": 0, "moderate": 0, "shifted": 0}
    for row in drift_rows:
        counts[row["verdict"]] = counts.get(row["verdict"], 0) + 1
    shifted = [r for r in drift_rows if r["verdict"] == "shifted"]
    return {
        "features_compared": len(drift_rows),
        "counts": counts,
        "retrain_recommended": bool(shifted),
        "worst": drift_rows[:10],
        "thresholds": {"stable_below": PSI_STABLE, "shifted_above": PSI_SHIFTED},
    }
