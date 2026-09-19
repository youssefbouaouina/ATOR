"""Component B - supervised triage: calibrated probability that a process is malicious.

Reframed from the original proposal
-----------------------------------
`hazem2.md` specified "rank every detection by the probability it is a true positive",
trained on analyst adjudications from `approvals_queue`. That table holds **zero rows** - no
analyst has ever adjudicated anything in this deployment - so the model as specified cannot
be trained. See docs/ML_ARCHITECTURE.md section 2.

What *is* trainable, with labels that actually exist, is a classifier over the same
lineage-labelled corpus: **P(this process is part of an intrusion)**. Its calibrated output
becomes `detections.confidence_score`. When analyst adjudications eventually accumulate, they
become an additional label source without changing the interface.

Why calibration is not optional here
------------------------------------
Component A produces a *ranking*; Component B produces a *number an analyst reads*. If the UI
shows "confidence 0.90" it must be right about 90% of the time. Raw gradient-boosting scores
are not probabilities - they are systematically over-confident at the extremes - so the
estimator is wrapped in `CalibratedClassifierCV`. `ml/evaluation/harness.py` reports Brier
score, expected calibration error and a reliability curve alongside the usual ranking metrics.

Two deliberate choices
----------------------
* **No `class_weight='balanced'`.** Re-weighting improves ranking slightly but shifts the
  predicted probabilities away from the true base rate, which is precisely what we are trying
  to preserve. Imbalance is handled by measuring PR-AUC rather than accuracy.
* **Corpus rows only, T1 features by default.** Every positive is a corpus row and the local
  rows are 100% benign, so a supervised learner would seize on `sysmon_available` (1.000 on
  corpus, 0.000 on local) as a free label proxy. Restricting the population removes the
  confound at the source rather than hoping regularisation hides it.

`HistGradientBoostingClassifier` consumes NaN natively, so unlike Component A there is no
imputation step - "missing" stays a distinct branch in the trees, which is what the
`*_available` feature design intends.
"""
from __future__ import annotations

import os

import numpy as np
import pandas as pd

RANDOM_SEED = 42

DEFAULT_MAX_ITER = 200
DEFAULT_LEARNING_RATE = 0.06
# Shallow trees and a high leaf minimum: with 185 positives, capacity is the enemy.
DEFAULT_MAX_DEPTH = 4
DEFAULT_MIN_LEAF = 20
DEFAULT_L2 = 1.0

# Bands used to colour the dashboard badge.
CONFIDENCE_HIGH = float(os.environ.get("ATOR_ML_CONFIDENCE_HIGH", "0.80"))
CONFIDENCE_MEDIUM = float(os.environ.get("ATOR_ML_CONFIDENCE_MEDIUM", "0.50"))


def confidence_band(score: float | None) -> str:
    """'high' | 'medium' | 'low' | 'unknown' - what the UI badge shows."""
    if score is None or not np.isfinite(score):
        return "unknown"
    if score >= CONFIDENCE_HIGH:
        return "high"
    if score >= CONFIDENCE_MEDIUM:
        return "medium"
    return "low"


def _base_estimator(seed: int):
    from sklearn.ensemble import HistGradientBoostingClassifier
    return HistGradientBoostingClassifier(
        max_iter=DEFAULT_MAX_ITER,
        learning_rate=DEFAULT_LEARNING_RATE,
        max_depth=DEFAULT_MAX_DEPTH,
        min_samples_leaf=DEFAULT_MIN_LEAF,
        l2_regularization=DEFAULT_L2,
        early_stopping=False,          # deterministic; the data is too small to hold out again
        random_state=seed,
    )


class TriageModel:
    """Calibrated malicious/benign classifier over the standard feature matrix."""

    def __init__(self, seed: int = RANDOM_SEED, calibrate: bool = True,
                 calibration_folds: int = 3, method: str = "sigmoid"):
        self.seed = seed
        self.calibrate = calibrate
        self.calibration_folds = calibration_folds
        # Sigmoid (Platt), not isotonic: isotonic is non-parametric and needs far more
        # positives than 185 to avoid fitting its own noise.
        self.method = method
        self.model = None
        self.feature_names: list[str] = []
        self.used_features: list[str] = []

    @staticmethod
    def _usable_columns(X: pd.DataFrame) -> list[str]:
        """Columns a histogram learner can actually bin.

        Two classes are excluded:

        * **All-NaN.** `HistGradientBoostingClassifier` raises
          `ValueError: window shape cannot be larger than input array shape` when a column has
          no observed value at all - its binner cannot build a single threshold. This is not
          hypothetical: on the corpus, `conn_listen_count` and `conn_established_count` are
          100% missing by design, because Sysmon EID 3 carries no TCP state while psutil does.
        * **Constant.** A column with one distinct value cannot split anything. On the
          corpus-only population that includes `sysmon_available`, which is uniformly 1.0 -
          a useful confirmation that restricting the population really did remove the
          source/label confound rather than merely hiding it.

        The surviving list is stored so scoring uses exactly the same columns as fitting.
        """
        usable = []
        for column in X.columns:
            values = X[column]
            if values.isna().all():
                continue
            if values.dropna().nunique() <= 1:
                continue
            usable.append(column)
        return usable

    def fit(self, X: pd.DataFrame, y: np.ndarray) -> "TriageModel":
        if X is None or len(X) == 0:
            raise ValueError("cannot fit a triage model on zero rows")
        y = np.asarray(y)
        if len(np.unique(y)) < 2:
            raise ValueError("triage training data contains only one class")
        self.feature_names = list(X.columns)
        self.used_features = self._usable_columns(X)
        if not self.used_features:
            raise ValueError("no usable features: every column is empty or constant")
        X = X[self.used_features]

        estimator = _base_estimator(self.seed)
        n_positive = int((y == 1).sum())
        # Calibration splits the training data again; below ~3 positives per fold it is
        # fitting noise, so fall back to the raw estimator and say so in the metrics.
        if self.calibrate and n_positive >= self.calibration_folds * 3:
            from sklearn.calibration import CalibratedClassifierCV
            from sklearn.model_selection import StratifiedKFold
            self.model = CalibratedClassifierCV(
                estimator,
                method=self.method,
                cv=StratifiedKFold(n_splits=self.calibration_folds, shuffle=True,
                                   random_state=self.seed),
            )
        else:
            self.model = estimator
        self.model.fit(X, y)
        return self

    def _check_ready(self, X: pd.DataFrame) -> None:
        if self.model is None:
            raise RuntimeError("TriageModel.fit must be called before scoring")
        if list(X.columns) != self.feature_names:
            missing = set(self.feature_names) - set(X.columns)
            raise ValueError(
                f"feature mismatch between fit and score (missing={sorted(missing)[:5]}); "
                "a feature-spec change requires retraining")

    def score(self, X: pd.DataFrame) -> np.ndarray:
        """P(malicious), in [0, 1]."""
        self._check_ready(X)
        return self.model.predict_proba(X[self.used_features])[:, 1]

    def explain(self, X: pd.DataFrame, top_k: int = 5) -> list[dict]:
        """Per-row top contributing features, by permutation-free surrogate.

        Gradient boosting offers no cheap per-row attribution, so this reports the features
        whose value is most extreme relative to the training distribution - the same honest
        heuristic used by Component A, and labelled as a triage hint rather than a cause.
        """
        self._check_ready(X)
        if not hasattr(self, "_train_median") or self._train_median is None:
            return [[] for _ in range(len(X))]
        centre = self._train_median
        spread = self._train_scale
        values = X[self.used_features].to_numpy(dtype="float64")
        deviation = np.abs(np.nan_to_num(values, nan=0.0) - centre) / spread
        out = []
        for row in deviation:
            order = np.argsort(row)[::-1][:top_k]
            out.append([{"feature": self.used_features[i],
                         "deviation": round(float(row[i]), 3)}
                        for i in order if np.isfinite(row[i]) and row[i] > 0])
        return out

    def fit_explainer(self, X: pd.DataFrame) -> "TriageModel":
        """Record the training distribution used by `explain`."""
        values = X[self.used_features].to_numpy(dtype="float64")
        self._train_median = np.nan_to_num(np.nanmedian(values, axis=0), nan=0.0)
        scale = np.nanmedian(np.abs(values - self._train_median), axis=0) * 1.4826
        self._train_scale = np.where(
            ~np.isfinite(scale) | (scale <= 1e-9), 1.0, scale)
        return self

    def to_payload(self) -> dict:
        return {
            "model": self.model,
            "feature_names": self.feature_names,
            "used_features": self.used_features,
            "seed": self.seed,
            "method": self.method,
            "calibrated": self.calibrate,
            "train_median": getattr(self, "_train_median", None),
            "train_scale": getattr(self, "_train_scale", None),
        }

    @classmethod
    def from_payload(cls, payload: dict) -> "TriageModel":
        model = cls(seed=payload.get("seed", RANDOM_SEED),
                    calibrate=payload.get("calibrated", True),
                    method=payload.get("method", "sigmoid"))
        model.model = payload["model"]
        model.feature_names = list(payload["feature_names"])
        model.used_features = list(payload.get("used_features") or payload["feature_names"])
        model._train_median = payload.get("train_median")
        model._train_scale = payload.get("train_scale")
        return model


def fit_score_factory(seed: int = RANDOM_SEED, calibrate: bool = True):
    """A `fit_score(X_train, y_train, X_test)` closure for `harness.grouped_cv`.

    Use with `benign_only_fit=False` - this model needs both classes.
    """
    def fit_score(X_train, y_train, X_test):
        model = TriageModel(seed=seed, calibrate=calibrate)
        model.fit(X_train, y_train)
        return model.score(X_test)
    return fit_score
