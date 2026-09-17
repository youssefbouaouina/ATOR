# ML_EVALUATION_TRIAGE.md — Components B & C, host risk, drift

**Generated from** `reports_ml/triage_eval.json` and `reports_ml/tactic_eval.json`.
Figures in `reports_ml/figures/`. Companion to `ML_EVALUATION.md` (Component A).
**Feature spec** `9225377386b539d6…` · seed 42 · scikit-learn 1.9.1 · CPU only.

```bash
.venv-ml313/Scripts/python.exe -m ml.training.train_triage --save
.venv-ml313/Scripts/python.exe -m ml.training.train_tactic --save
.venv-ml313/Scripts/python.exe -c "from ml.evaluation import figures; figures.generate_phase5()"
```

---

## 1. Summary

| Component | Verdict |
|---|---|
| **B — supervised triage** | **Ships.** PR-AUC 0.922 (95% CI 0.878–0.963) vs 0.286 for the deployed rules. Precision@25 = 1.00. Survives a leak audit. |
| **C — tactic suggestion** | **Does not ship.** 50.8% accuracy against a 40.5% majority baseline. Measured, found insufficient, and deliberately not surfaced. |
| Host risk score | Ships. Deterministic, explainable, ordering verified. |
| Drift monitor (PSI) | Ships — and immediately found that **32 of 79 features have shifted** between training and live data. |

---

## 2. Component B — supervised triage

### 2.1 Reframing, and why it was necessary
`hazem2.md` specified training this on analyst adjudications in `approvals_queue`. That
table has **zero rows**, so the model as written could not be trained at all. It is instead
trained on the same lineage-labelled corpus to predict **P(this process is part of an
intrusion)**, whose calibrated output becomes `detections.confidence_score`. When real
adjudications accumulate they become an extra label source without an interface change.

### 2.2 Results (corpus rows only — 1,716 rows, 185 positives, 10.8% base rate)

![Component A vs B](figures/06_component_a_vs_b.png)

| Model | PR-AUC | 95% CI | ROC-AUC | Recall @1% FPR | Precision@25 |
|---|---:|---|---:|---:|---:|
| chance | 0.108 | 0.074–0.174 | 0.504 | 0.5% | 0.04 |
| Sigma rules (deployed) | 0.286 | — | 0.600 | n/a | n/a |
| best single feature | 0.260 | 0.167–0.393 | 0.777 | 70.3% | 0.32 |
| Component A (unsupervised) | 0.486 | 0.383–0.641 | 0.899 | 19.5% | 0.68 |
| **Component B, T1** | **0.922** | **0.878–0.963** | **0.989** | **71.9%** | **1.00** |
| Component B, T2 | 0.921 | 0.877–0.961 | 0.989 | 74.1% | 1.00 |
| Component B, uncalibrated | 0.926 | 0.888–0.962 | 0.990 | 74.6% | 1.00 |

Supervision is worth a great deal here: **PR-AUC 0.486 → 0.922** on identical rows and folds.
That is the expected direction — Component A is told nothing about what an attack looks like —
but the size of the gap is the argument for keeping both: A finds *unusual*, B finds *known-bad-like*.

Ranking metrics for the Sigma row are `n/a` by design; it is a binary scorer, and asking for
"recall at 1% FPR" of a yes/no rule set produces a flattering number that means nothing (see
`ML_EVALUATION.md` §3). At its own operating point: **precision 1.000, recall 0.200**.

### 2.3 The leak audit — is this just the labelling rule?

**This is the most important check in the report.** Labels come from seed signatures
(`-enc <base64>`, `-w hidden`, `IEX`, `DownloadString`), and several features restate those
patterns almost exactly. A classifier could score 0.92 by rediscovering my own labelling rule
and would be worthless.

![Leak audit](figures/08_leak_audit.png)

| Feature set | Features | PR-AUC |
|---|---:|---:|
| all T1 features | 79 | 0.922 |
| − seed-echo features | 69 | 0.913 |
| − seed-echo − tree (the `sibling_count` artefact) | 65 | 0.900 |
| − seed-echo − tree − **all** command-line features | 53 | 0.876 |
| − seed-echo − tree − command-line − rarity | 50 | **0.868** |

Removing every feature that restates a seed signature costs **0.009**. Removing the seed
echoes *and* the known labelling artefact *and* the entire command-line family *and* the
fitted rarity features — 79 features down to 50 — still leaves **0.868**.

The result is not circular. What remains (path category, parent identity, account type,
connection aggregates, timing) is genuine behavioural signal.

### 2.4 Calibration — and a finding against my own design

![Reliability](figures/07_reliability_curve.png)

| Variant | Brier ↓ | Brier skill ↑ | ECE ↓ |
|---|---:|---:|---:|
| T1 calibrated (Platt) | 0.0257 | 0.733 | 0.0174 |
| T2 calibrated | 0.0258 | 0.732 | 0.0181 |
| **T1 uncalibrated** | **0.0237** | **0.754** | **0.0085** |

**Wrapping the model in `CalibratedClassifierCV` made calibration worse, not better** — ECE
0.0174 vs 0.0085. `HistGradientBoostingClassifier` optimises log-loss and is already close to
calibrated; Platt scaling on 3 inner folds over 185 positives adds variance without removing
bias. The architecture document declared calibration mandatory, and measuring it showed the
wrapper was the wrong instrument for this data size.

**Recommendation: ship the uncalibrated model** and keep reporting Brier/ECE, so the decision
is revisited automatically when the dataset grows.

### 2.5 Complementarity with the deployed rules
At a 1% false-positive threshold, over 185 attacks:

| | attacks |
|---|---:|
| rules only | 2 |
| both | 35 |
| **model only** | **98** |
| neither | 50 |

**Union recall 20.0% → 73.0%**, recovering **98 of the 148 attacks the rules miss** (66%), for
16 extra false positives. Compare Component A, which recovered 13. The `neither` bucket falls
from 135 to 50.

### 2.6 Stability
Per-fold PR-AUC `[0.941, 0.969, 0.934, 0.794, 0.972]` — mean 0.922, **sd 0.066**, tighter than
Component A's 0.141. One weak fold (0.794) is a reminder that a single number over 105
captures still hides real variation.

---

## 3. Component C — tactic suggestion: a negative result

### 3.1 What was attempted
Predict the ATT&CK tactic for findings with no rule mapping, so ML detections can enter the
attack-chain view. Trained on the 185 positives; classes with fewer than 10 examples folded
into `other` (`persistence` 8, `privilege_escalation` 8, `discovery` 7, `execution` 3,
`other` 2 — 28 rows), leaving `defense_evasion` 75, `lateral_movement` 44,
`credential_access` 38.

### 3.2 Results (grouped 5-fold CV — the holdout has only 3 of 8 tactics)

| Class | Precision | Recall | F1 | Support |
|---|---:|---:|---:|---:|
| defense_evasion | 0.70 | 0.60 | **0.65** | 75 |
| lateral_movement | 0.58 | 0.50 | 0.54 | 44 |
| credential_access | 0.33 | 0.39 | 0.36 | 38 |
| other | 0.32 | 0.43 | 0.37 | 28 |

**Accuracy 0.508 against a majority-class baseline of 0.405.** Macro F1 0.478.

Thresholding on confidence barely helps — at p ≥ 0.8 accuracy reaches only 59.5% while
coverage falls to 45%. A hint that is wrong four times in ten is worse than no hint: it spends
analyst attention and erodes trust in every other ML output.

### 3.3 Why it fails, and what would fix it
The dominant confusion is **`defense_evasion` ↔ `credential_access`** (25 of the errors).
That is not really model error — **ATT&CK tactics are not mutually exclusive**. A
credential-dumping tool that disables logging and injects into LSASS is genuinely performing
both. The corpus assigns each capture *one* tactic from its directory, so single-label
classification is imposed by the label format, not by the phenomenon.

To make this work: multi-**label** classification against technique-level labels, with
hundreds of examples per class. Neither exists here.

**Decision: the code ships, disabled.** `ml_tactic.py` is complete, tested and re-runnable —
so the moment enough labelled data exists it can be re-evaluated — but it is **not wired into
the engine and its output is not shown in the UI**. Reporting a measured negative result is
more useful than shipping a misleading feature.

---

## 4. Host risk score

Deliberately **not** machine learning: there is no label for "how compromised is this host",
so anything learned would be fitting an invention. A weighted sum with stated weights gives a
defensible ordering that is fully explainable — every point traces to a detection.

```
score = Σ (severity_weight × 0.95^days)  +  3 × distinct_tactics  +  min(ml_points, 10)
```

Verified on live data:

| Host | Score | Tier | Why |
|---|---:|---|---|
| WIN-ATOR-LAB | 22.70 | high | 5 rule detections spanning 5 tactics |
| DESKTOP-68VLDRS | 9.70 | medium | ML anomalies only, capped contribution |
| UBUNTU-VM-01 | 4.40 | low | 1 detection, 1 tactic |

Two deliberate departures from `hazem2.md` §3.4:
* **ML contribution is capped** (default 10). The original assigned a flat +5 per ML anomaly
  with `0.9^hours` decay, which on a 60-second engine loop would let a *quiet* host climb
  simply by being observed often.
* **ML findings earn no tactic-diversity bonus.** Letting a hint inflate a kill-chain signal
  would be circular.

---

## 5. Drift monitoring (PSI) — and what it immediately found

PSI between the training corpus and the live serving distribution, per feature, with
missingness as its own bin.

**32 of 79 features are `shifted` (PSI > 0.25); 9 moderate; 38 stable.**

| Feature | PSI | Missing: train → live |
|---|---:|---|
| `hour_of_day` | 8.67 | 0% → 0% |
| `cmdline_len` | 4.03 | 0% → **27.3%** |
| `sibling_count` | 4.02 | 21.0% → 0% |
| `cmdline_entropy` | 3.88 | 0% → **27.3%** |

This quantifies the train/serve gap that `ML_EVALUATION.md` §5 observed behaviourally (corpus
thresholds under-stating real false positives ~6×). Two specific findings:

1. **`hour_of_day` should be dropped from the feature set.** PSI 8.67 means it encodes *when
   the 2020 lab captures were recorded*, not attacker behaviour. It is a feature that cannot
   generalise and the drift monitor caught it without being asked.
2. **The `cmdline_*` shift is the unelevated-agent problem** already documented: 0% → 27.3%
   missing, because psutil cannot read command lines for protected processes. PSI turns that
   from a footnote into an alert.

Operationally this is the value of drift monitoring: it flags a broken or changed collector
before anyone notices the scores have quietly stopped meaning anything.

---

## 6. Threats to validity

Everything in `ML_EVALUATION.md` §8 still applies (weak labels, one benign workstation,
Windows only, snapshot-vs-event skew, small N). Additional to this phase:

1. **Component B's headline rests on the same weak labels.** The leak audit shows it is not
   *circular*, but it cannot show the labels are *correct*. 26 captures yield no seed and are
   labelled entirely benign; any attacks in them are counted as false positives, so precision
   is a lower bound.
2. **Calibration is measured on the same folds as discrimination.** With 185 positives there
   is not enough data for a separate calibration holdout.
3. **`hour_of_day` is still in the trained models.** It is flagged for removal here; removing
   it changes `feature_spec_sha256` and requires a retrain, so it is a deliberate follow-up
   rather than a silent edit.

---

## 7. Recommendations

1. **Ship Component B uncalibrated** as `confidence_score` on every detection, rule-derived
   and ML-derived alike, so one queue ranks comparably across sources.
2. **Do not ship Component C.** Revisit when technique-level, multi-label data exists.
3. **Drop `hour_of_day`** at the next retrain (PSI 8.67 — it encodes lab scheduling).
4. **Run `scripts/retrain_ml.py --check-drift` on a schedule.** It exits 2 when features have
   shifted, which is directly usable as a cron alert.
5. **Keep Components A and B together.** A answers "is this unusual?", B answers "does this
   look like known-bad?". On the live workstation A flagged `NVIDIA Overlay.exe` as highly
   anomalous (0.993) while B assigned it a low malicious probability — the combination is what
   makes the queue trustworthy.
