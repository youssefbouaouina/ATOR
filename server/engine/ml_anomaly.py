"""Component A - unsupervised process anomaly detection (IsolationForest).

What this is for
----------------
The deterministic engine answers "does this match a known rule?". Component A answers
"is this unusual for this estate?" - the threat-hunting half of the internship subject, which
is the only half that can surface behaviour nobody has written a rule for yet.

Framing: novelty detection, not outlier detection
-------------------------------------------------
The model is fitted on **benign rows only**, so it learns a baseline of normal and scores
deviation from it. That is a deliberate choice over fitting IsolationForest on everything and
relying on `contamination`:

* it matches how a DFIR baseline is actually established (observe a clean period, then watch
  for drift), which is Phase 1 of the internship timeline;
* it keeps the model honest about what it has seen - with 8.2% positives, an unsupervised fit
  on all rows would partly model the attacks as "normal";
* it means the score is interpretable: a percentile against the baseline.

Score semantics
---------------
`IsolationForest.score_samples` returns an unbounded quantity whose scale depends on the
fitted forest, which is useless to store in a database or show an analyst. So the raw score is
mapped through the **training-score distribution** to a percentile in [0, 1]:

    anomaly_score = P(baseline score <= this score)

0.99 then means "more anomalous than 99% of the benign baseline", the threshold in
`ATOR_ML_ANOMALY_THRESHOLD` is self-calibrating, and the number means the same thing across
retrains even though the underlying forest changes.

Missing values
--------------
IsolationForest cannot consume NaN, so the pipeline median-imputes. The imputer's statistics
come from the training fold only. No missing-indicator columns are added, because the feature
spec already carries purposeful availability flags (`cmdline_present`, `conn_available`,
`sysmon_available`, `conn_status_available`) - adding ~30 more indicators would inflate
dimensionality against 185 positives for information that is already present.
"""
from __future__ import annotations

import os

import numpy as np
import pandas as pd

RANDOM_SEED = 42

# Tuned for CPU-only training well under the 30 s budget in ML_ARCHITECTURE section 8.
DEFAULT_N_ESTIMATORS = 300
DEFAULT_MAX_SAMPLES = 256          # the IsolationForest paper's recommended subsample size

# Percentile above which a row is reported as an anomaly. 0.99 = "top 1% of baseline".
DEFAULT_THRESHOLD = float(os.environ.get("ATOR_ML_ANOMALY_THRESHOLD", "0.99"))


def _build_pipeline(n_estimators: int, max_samples, seed: int):
    from sklearn.ensemble import IsolationForest
    from sklearn.impute import SimpleImputer
    from sklearn.pipeline import Pipeline
    return Pipeline([
        # Median, not mean: several features are heavy-tailed counts where the mean sits
        # outside the bulk of the distribution.
        ("impute", SimpleImputer(strategy="median", keep_empty_features=True)),
        ("iforest", IsolationForest(
            n_estimators=n_estimators,
            max_samples=max_samples,
            # The fit is on benign rows only, so there is nothing to contaminate.
            contamination="auto",
            random_state=seed,
            n_jobs=-1,
            bootstrap=False,
        )),
    ])


class AnomalyModel:
    """Fit on benign features; score anything as a baseline percentile."""

    def __init__(self, n_estimators: int = DEFAULT_N_ESTIMATORS,
                 max_samples=DEFAULT_MAX_SAMPLES, seed: int = RANDOM_SEED,
                 threshold: float = DEFAULT_THRESHOLD):
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.seed = seed
        self.threshold = threshold
        self.pipeline = None
        self.feature_names: list[str] = []
        self._baseline_scores: np.ndarray | None = None

    # ------------------------------------------------------------------ fit / score

    def fit(self, X_benign: pd.DataFrame) -> "AnomalyModel":
        if X_benign is None or len(X_benign) == 0:
            raise ValueError("cannot fit an anomaly baseline on zero rows")
        self.feature_names = list(X_benign.columns)
        max_samples = self.max_samples
        if isinstance(max_samples, int):
            max_samples = min(max_samples, len(X_benign))
        self.pipeline = _build_pipeline(self.n_estimators, max_samples, self.seed)
        self.pipeline.fit(X_benign)
        # Keep the baseline score distribution: it is what turns an arbitrary forest score
        # into a percentile that means the same thing after every retrain.
        raw = self.pipeline.score_samples(X_benign)
        self._baseline_scores = np.sort(-raw)          # higher = more anomalous
        return self

    def _check_ready(self, X: pd.DataFrame) -> None:
        if self.pipeline is None or self._baseline_scores is None:
            raise RuntimeError("AnomalyModel.fit must be called before scoring")
        if list(X.columns) != self.feature_names:
            missing = set(self.feature_names) - set(X.columns)
            extra = set(X.columns) - set(self.feature_names)
            raise ValueError(
                "feature mismatch between fit and score "
                f"(missing={sorted(missing)[:5]}, unexpected={sorted(extra)[:5]}); "
                "a feature-spec change requires retraining")

    def raw_scores(self, X: pd.DataFrame) -> np.ndarray:
        """Unbounded anomaly scores; higher = more anomalous."""
        self._check_ready(X)
        return -self.pipeline.score_samples(X)

    def score(self, X: pd.DataFrame) -> np.ndarray:
        """Anomaly score in [0, 1] as a percentile of the benign baseline."""
        raw = self.raw_scores(X)
        # searchsorted over the sorted baseline gives the empirical CDF directly.
        ranks = np.searchsorted(self._baseline_scores, raw, side="right")
        return ranks / float(len(self._baseline_scores))

    def predict(self, X: pd.DataFrame, threshold: float | None = None) -> np.ndarray:
        limit = self.threshold if threshold is None else threshold
        return (self.score(X) >= limit).astype(int)

    # ------------------------------------------------------------------ explanation

    def explain(self, X: pd.DataFrame, top_k: int = 5) -> list[dict]:
        """Per-row top contributing features.

        An unexplained ML alert is unactionable, so every anomaly detection carries the
        features that drove it. IsolationForest has no per-feature attribution, so this uses
        a deviation heuristic: how far each feature sits from the benign baseline median, in
        robust (MAD) units. It is a *hint for an analyst*, not a causal attribution, and is
        labelled as such in the UI.
        """
        self._check_ready(X)
        imputer = self.pipeline.named_steps["impute"]
        centre = np.asarray(imputer.statistics_, dtype="float64")
        filled = imputer.transform(X)
        # Robust scale per feature from the baseline; guard zero-variance columns.
        spread = np.median(np.abs(filled - centre), axis=0) * 1.4826
        spread = np.where(spread <= 1e-9, 1.0, spread)
        signed = filled - centre
        deviation = np.abs(signed) / spread

        out = []
        for row, sign in zip(deviation, signed):
            order = np.argsort(row)[::-1][:top_k]
            out.append([
                # `direction` lets the UI say "spawns MORE children than normal" instead of
                # "unusual child count" - the difference between an actionable indicator
                # and a vague one. Additive: older findings without it fall back to neutral.
                {"feature": self.feature_names[i], "deviation": round(float(row[i]), 3),
                 "direction": "higher" if sign[i] > 0 else "lower"}
                for i in order if np.isfinite(row[i]) and row[i] > 0
            ])
        return out

    # ------------------------------------------------------------------ persistence

    def to_payload(self) -> dict:
        """Everything needed to reconstruct scoring, for joblib serialisation."""
        return {
            "pipeline": self.pipeline,
            "feature_names": self.feature_names,
            "baseline_scores": self._baseline_scores,
            "threshold": self.threshold,
            "n_estimators": self.n_estimators,
            "max_samples": self.max_samples,
            "seed": self.seed,
        }

    @classmethod
    def from_payload(cls, payload: dict) -> "AnomalyModel":
        model = cls(n_estimators=payload.get("n_estimators", DEFAULT_N_ESTIMATORS),
                    max_samples=payload.get("max_samples", DEFAULT_MAX_SAMPLES),
                    seed=payload.get("seed", RANDOM_SEED),
                    threshold=payload.get("threshold", DEFAULT_THRESHOLD))
        model.pipeline = payload["pipeline"]
        model.feature_names = list(payload["feature_names"])
        model._baseline_scores = np.asarray(payload["baseline_scores"])
        return model


def fit_score_factory(n_estimators: int = DEFAULT_N_ESTIMATORS,
                      max_samples=DEFAULT_MAX_SAMPLES, seed: int = RANDOM_SEED):
    """A `fit_score(X_train, y_train, X_test)` closure for `harness.grouped_cv`."""
    def fit_score(X_train, y_train, X_test):
        model = AnomalyModel(n_estimators=n_estimators, max_samples=max_samples, seed=seed)
        model.fit(X_train)
        return model.score(X_test)
    return fit_score
