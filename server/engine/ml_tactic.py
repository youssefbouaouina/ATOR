"""Component C - ATT&CK tactic suggestion for findings that have no rule mapping.

The problem it addresses
------------------------
Layer 5 enriches detections with MITRE ATT&CK data by looking up the `technique_id` a Sigma
rule declares. An `ml_anomaly` detection has no rule and therefore no technique, so it
arrives at the dashboard and the report unmapped - a finding an analyst cannot place in the
kill chain. Component C predicts the likely **tactic** from the same feature vector, so ML
findings enter the attack-chain view like everything else.

Its output is deliberately a *hint*: `detections.suggested_tactics` holds a ranked JSON array
and the UI must render it as "ML suggests…", never as an authoritative mapping.

Honest scope - three tactics, not eight
---------------------------------------
The corpus has 185 positives across 8 tactics, distributed very unevenly:

    defense_evasion 75 | lateral_movement 44 | credential_access 38
    privilege_escalation 8 | persistence 8 | discovery 7 | execution 3 | other 2

Only the first three have enough examples to learn or to measure. The rest are collapsed into
a single `other` class rather than pretending to predict them: a per-class F1 computed on 3
examples is noise, and reporting it as a result would be dishonest. The
`MIN_EXAMPLES_PER_CLASS` threshold makes that explicit and automatic, so the class list grows
by itself as more data arrives.

The held-out split cannot be used here at all - it contains only 3 of the 8 tactics
(measured, see docs/ML_PROGRESS.md Phase 2). Evaluation is grouped cross-validation only.
"""
from __future__ import annotations

import os

import numpy as np
import pandas as pd

RANDOM_SEED = 42

# Below this, a class cannot be learned or measured; it is folded into OTHER_CLASS.
MIN_EXAMPLES_PER_CLASS = int(os.environ.get("ATOR_ML_TACTIC_MIN_EXAMPLES", "10"))
OTHER_CLASS = "other"

# How many suggestions to attach to a detection.
TOP_N_SUGGESTIONS = 2
# Below this probability a suggestion is not worth showing an analyst.
MIN_SUGGESTION_PROBABILITY = float(os.environ.get("ATOR_ML_TACTIC_MIN_PROB", "0.25"))


def collapse_rare_classes(tactics, min_examples: int = MIN_EXAMPLES_PER_CLASS):
    """Fold classes with too few examples into `other`. Returns (labels, kept_class_names)."""
    series = pd.Series([t if t else OTHER_CLASS for t in tactics], dtype=object)
    counts = series.value_counts()
    keep = {name for name, n in counts.items()
            if n >= min_examples and name != OTHER_CLASS}
    collapsed = series.map(lambda t: t if t in keep else OTHER_CLASS)
    return collapsed.to_numpy(), sorted(keep)


class TacticModel:
    """Multi-class tactic suggester over the standard feature matrix.

    Multinomial logistic regression rather than a tree ensemble: with ~180 training rows over
    3-4 classes, a linear model with strong regularisation is the honest capacity choice, and
    its coefficients are inspectable - which matters for a component whose output is a hint an
    analyst is asked to trust.
    """

    def __init__(self, seed: int = RANDOM_SEED, min_examples: int = MIN_EXAMPLES_PER_CLASS):
        self.seed = seed
        self.min_examples = min_examples
        self.pipeline = None
        self.feature_names: list[str] = []
        self.used_features: list[str] = []
        self.classes_: list[str] = []

    @staticmethod
    def _usable_columns(X: pd.DataFrame) -> list[str]:
        return [c for c in X.columns
                if not X[c].isna().all() and X[c].dropna().nunique() > 1]

    def fit(self, X: pd.DataFrame, tactics) -> "TacticModel":
        from sklearn.impute import SimpleImputer
        from sklearn.linear_model import LogisticRegression
        from sklearn.pipeline import Pipeline
        from sklearn.preprocessing import StandardScaler

        if X is None or len(X) == 0:
            raise ValueError("cannot fit a tactic model on zero rows")
        y, kept = collapse_rare_classes(tactics, self.min_examples)
        if len(set(y)) < 2:
            raise ValueError("tactic training data has fewer than two usable classes")

        self.feature_names = list(X.columns)
        self.used_features = self._usable_columns(X)
        if not self.used_features:
            raise ValueError("no usable features for the tactic model")

        self.pipeline = Pipeline([
            ("impute", SimpleImputer(strategy="median", keep_empty_features=True)),
            ("scale", StandardScaler()),        # logistic regression needs comparable scales
            ("clf", LogisticRegression(
                max_iter=2000,
                C=0.5,                          # strong regularisation: ~180 rows, ~80 features
                class_weight="balanced",        # defense_evasion is 2x credential_access
                random_state=self.seed,
            )),
        ])
        self.pipeline.fit(X[self.used_features], y)
        self.classes_ = list(self.pipeline.named_steps["clf"].classes_)
        return self

    def _check_ready(self, X: pd.DataFrame) -> None:
        if self.pipeline is None:
            raise RuntimeError("TacticModel.fit must be called before predicting")
        missing = set(self.used_features) - set(X.columns)
        if missing:
            raise ValueError(f"feature mismatch: missing {sorted(missing)[:5]}")

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        self._check_ready(X)
        return self.pipeline.predict_proba(X[self.used_features])

    def suggest(self, X: pd.DataFrame, top_n: int = TOP_N_SUGGESTIONS,
                min_probability: float = MIN_SUGGESTION_PROBABILITY) -> list[list[dict]]:
        """Ranked tactic suggestions per row, as stored in `detections.suggested_tactics`.

        `other` is never suggested: it is a bucket for classes with too little data, so
        surfacing it would tell an analyst nothing. A row whose best real class falls below
        `min_probability` yields an empty list - no suggestion is better than a misleading one.
        """
        probabilities = self.predict_proba(X)
        out = []
        for row in probabilities:
            ranked = sorted(zip(self.classes_, row), key=lambda kv: kv[1], reverse=True)
            suggestions = [
                {"tactic": name, "probability": round(float(p), 4)}
                for name, p in ranked[:top_n + 1]
                if name != OTHER_CLASS and p >= min_probability
            ]
            out.append(suggestions[:top_n])
        return out

    def to_payload(self) -> dict:
        return {"pipeline": self.pipeline, "feature_names": self.feature_names,
                "used_features": self.used_features, "classes": self.classes_,
                "seed": self.seed, "min_examples": self.min_examples}

    @classmethod
    def from_payload(cls, payload: dict) -> "TacticModel":
        model = cls(seed=payload.get("seed", RANDOM_SEED),
                    min_examples=payload.get("min_examples", MIN_EXAMPLES_PER_CLASS))
        model.pipeline = payload["pipeline"]
        model.feature_names = list(payload["feature_names"])
        model.used_features = list(payload.get("used_features") or payload["feature_names"])
        model.classes_ = list(payload["classes"])
        return model
