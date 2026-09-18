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

# Below this probability a suggestion is not shown. 0.80 is not a guess - it is where the
# measurement says the component becomes useful:
#
#   threshold   coverage   accuracy (all classes)   precision (well-supported classes)
#      none       100%          57.1%                        65.9%
#      0.70        55%          67.3%                        75.0%
#      0.80        43%          71.6%                        77.6%
#
# At Phase 5, with 185 labels, the same curve topped out at 59.5% and the component was not
# shipped at all. Phase 7a's label recovery moved it enough to be worth showing - but only
# above this threshold, and only as a hint that displays its own probability.
MIN_SUGGESTION_PROBABILITY = float(os.environ.get("ATOR_ML_TACTIC_MIN_PROB", "0.80"))

# A class needs this many training examples before its predictions are shown. Distinct from
# MIN_EXAMPLES_PER_CLASS, which decides what can be *learned*: a class can be learnable
# (>=10) yet still too thinly supported to put in front of an analyst. Measured per-class F1:
# defense_evasion 0.67 (n=81), lateral_movement 0.69 (n=50), credential_access 0.60 (n=38),
# persistence 0.00 (n=10), privilege_escalation low (n=10).
MIN_SUPPORT_TO_SUGGEST = int(os.environ.get("ATOR_ML_TACTIC_MIN_SUPPORT", "30"))

# Minimum Component B confidence before a tactic is suggested at all.
#
# THIS GUARD EXISTS BECAUSE OF AN OBSERVED FAILURE, not as a precaution.
#
# The tactic model is trained on malicious processes only - the question it answers is "which
# tactic is this?", not "is this an attack?". Applied to a benign process it is out of
# distribution, has no "none of the above" class, and confidently picks the nearest one. On
# the live workstation it labelled `chrome.exe` and `System Idle Process` as
# `lateral_movement` with probability **1.0**.
#
# So a tactic is only suggested where Component B already believes the process is malicious.
# The classifier answering "is this an attack?" gates the one answering "which kind?".
MIN_CONFIDENCE_TO_SUGGEST = float(os.environ.get("ATOR_ML_TACTIC_MIN_CONFIDENCE", "0.50"))


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
        self.class_support_: dict = {}
        self.suggestable_: list[str] = []

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
        # Training support per class, so suggest() can withhold thinly-supported classes.
        counts = pd.Series(y).value_counts()
        self.class_support_ = {str(k): int(v) for k, v in counts.items()}
        self.suggestable_ = sorted(
            name for name in self.classes_
            if name != OTHER_CLASS
            and self.class_support_.get(str(name), 0) >= MIN_SUPPORT_TO_SUGGEST)
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
        allowed = set(getattr(self, "suggestable_", None)
                      or [c for c in self.classes_ if c != OTHER_CLASS])
        out = []
        for row in probabilities:
            ranked = sorted(zip(self.classes_, row), key=lambda kv: kv[1], reverse=True)
            suggestions = [
                {"tactic": name, "probability": round(float(p), 4)}
                for name, p in ranked[:top_n + 1]
                if name in allowed and p >= min_probability
            ]
            out.append(suggestions[:top_n])
        return out

    def to_payload(self) -> dict:
        return {"pipeline": self.pipeline, "feature_names": self.feature_names,
                "used_features": self.used_features, "classes": self.classes_,
                "seed": self.seed, "min_examples": self.min_examples,
                "class_support": getattr(self, "class_support_", {}),
                "suggestable": getattr(self, "suggestable_", [])}

    @classmethod
    def from_payload(cls, payload: dict) -> "TacticModel":
        model = cls(seed=payload.get("seed", RANDOM_SEED),
                    min_examples=payload.get("min_examples", MIN_EXAMPLES_PER_CLASS))
        model.pipeline = payload["pipeline"]
        model.feature_names = list(payload["feature_names"])
        model.used_features = list(payload.get("used_features") or payload["feature_names"])
        model.classes_ = list(payload["classes"])
        model.class_support_ = payload.get("class_support") or {}
        model.suggestable_ = list(payload.get("suggestable") or [])
        return model
