"""Paths and policy for the weekly pipeline.

Every threshold a gate uses lives here, with the reason it has the value it has. An operator
can override any of them in `<mlops home>/config.json` without touching code. Unknown keys are
rejected rather than ignored, so a typo cannot silently leave a gate at its default.
"""
from __future__ import annotations

import dataclasses
import json
import os
from dataclasses import dataclass, field

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

COMPONENTS = ("anomaly", "triage", "tactic")

# Artefacts each component's trainer writes with --save, first entry = the served tier.
COMPONENT_FILES = {
    "anomaly": ("anomaly_t1", "anomaly_t2"),
    "triage": ("triage_t1", "triage_t2"),
    "tactic": ("tactic_t1",),
}

# Source files whose content decides what a component's trainer produces. Hashing them is how
# the pipeline knows a retrain is needed without being told (fingerprints, plan section 4.7).
_COMMON_CODE = (
    "ml/datasets/assemble.py", "ml/datasets/otrf_etl.py", "ml/datasets/otrf.py",
    "ml/datasets/labels.py", "ml/evaluation/harness.py", "server/engine/ml_features.py",
)
COMPONENT_CODE = {
    "anomaly": _COMMON_CODE + ("ml/training/train_anomaly.py", "server/engine/ml_anomaly.py"),
    "triage": _COMMON_CODE + ("ml/training/train_triage.py", "server/engine/ml_triage.py"),
    "tactic": _COMMON_CODE + ("ml/training/train_tactic.py", "server/engine/ml_tactic.py"),
}
# What decides the content of the training database. A change here forces a full rebuild.
ETL_CODE = ("ml/datasets/otrf_etl.py", "ml/datasets/otrf.py", "ml/datasets/labels.py",
            "server/db.py")


@dataclass(frozen=True)
class Policy:
    # ---- cadence
    # The trigger fires weekly; this guard makes "once every 7 days" hold even when a missed
    # run catches up next to a regular one. 6 days, not 7, so a trigger that fires a few hours
    # early (DST change, clock drift) is not skipped for a whole extra week.
    min_hours_between_runs: float = 144.0
    # A lock older than this belongs to a crashed run and is reclaimed.
    stale_lock_hours: float = 6.0
    min_free_disk_gb: float = 3.0

    # ---- live data admitted to training (plan 4.4)
    cooling_off_days: float = 7.0
    local_window_days: float = 90.0
    max_local_rows: int = 50_000
    incident_window_hours: float = 24.0
    lineage_depth: int = 6                      # same cap as corpus labelling (labels.py)
    max_feedback_readmissions: int = 200
    # Unreviewed ML leads below this triage confidence (the "likely malicious" band edge,
    # ml_triage.CONFIDENCE_MEDIUM) stay in the benign baseline; see data.py for the measurement.
    ml_lead_readmit_below: float = 0.50

    # ---- offline gates (plan 4.6)
    anomaly_floor: float = 0.99                 # serve-time floor, ml_integration.DEFAULT_THRESHOLD
    anomaly_pr_auc_margin: float = 0.03
    # Recall at the floor moved by ~3 points (6 of 205 attacks) from benign-data perturbation
    # alone in the first real run, so a 0.03 margin sat inside the noise. A poisoned baseline
    # loses far more (tests/test_mlops_gates.py: ~1.0 -> ~0.17).
    anomaly_recall_margin: float = 0.05
    alert_rate_ratio: float = 1.5
    alert_rate_slack: float = 0.005
    min_holdout_rows: int = 100
    confirmed_retention: float = 0.90
    min_confirmed_for_gate: int = 5
    triage_pr_auc_margin: float = 0.03
    triage_max_ece: float = 0.05
    triage_ece_margin: float = 0.02
    tactic_min_precision: float = 0.70
    tactic_precision_margin: float = 0.05
    tactic_min_coverage_ratio: float = 0.5

    # ---- online (shadow trial) gates
    trial_min_hours: int = 24                   # distinct clock-hours with scoring activity
    trial_min_processes: int = 200
    trial_max_error_rate: float = 0.01
    trial_volume_ratio: float = 1.5
    trial_volume_slack: int = 5
    trial_latency_ratio: float = 3.0
    trial_latency_slack_ms: float = 250.0
    inconclusive_alert_after: int = 3

    # ---- monitoring
    # Week-over-week drift raises attention when at least this share of features shifted.
    drift_attention_share: float = 0.10
    min_local_reference_rows: int = 200

    # ---- data validation after ETL
    max_positive_drop: float = 0.10
    max_process_drop: float = 0.10

    # ---- timeouts (seconds) and retention
    fetch_timeout: int = 900
    train_timeout: int = 3600
    keep_runs: int = 8
    keep_champion_versions: int = 5
    overdue_after_hours: float = 192.0          # 8 days: one missed week plus a day

    # ---- behaviour
    allow_bootstrap_promotion: bool = True      # no valid champion -> promote after offline gates
    fetch_upstream: bool = True
    extra: dict = field(default_factory=dict)


def mlops_home() -> str:
    return os.environ.get("ATOR_MLOPS_HOME", os.path.join(PROJECT_ROOT, "mlops"))


def models_dir() -> str:
    from server.engine import ml_registry
    return ml_registry.MODELS_DIR


def registry_dir() -> str:
    return os.path.join(models_dir(), "registry")


def live_db_path() -> str:
    from server import db as database
    return os.environ.get("ATOR_DFIR_DB") or database.DB_PATH


def train_db_path() -> str:
    from ml.datasets.otrf_etl import DEFAULT_TRAIN_DB
    return os.environ.get("ATOR_ML_TRAIN_DB", DEFAULT_TRAIN_DB)


def corpus_dir() -> str:
    from ml.datasets import otrf
    return os.environ.get("ATOR_OTRF_DIR", otrf.DEFAULT_DIR)


def load_policy(home: str | None = None) -> Policy:
    """Defaults, overridden by `<home>/config.json` if present."""
    path = os.path.join(home or mlops_home(), "config.json")
    if not os.path.exists(path):
        return Policy()
    with open(path, encoding="utf-8") as fh:
        overrides = json.load(fh)
    known = {f.name for f in dataclasses.fields(Policy)}
    unknown = sorted(set(overrides) - known)
    if unknown:
        raise ValueError(f"{path}: unknown policy key(s) {unknown}; "
                         f"valid keys are listed in ml/mlops/config.py")
    return dataclasses.replace(Policy(), **overrides)
