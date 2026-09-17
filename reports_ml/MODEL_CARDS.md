# Model cards — ATOR DFIR Layer 4.5 ML

One card per model, following the Mitchell et al. (2019) model-card structure: what it is
for, what it was trained on, how it performs, and — the part that matters most in security —
**what it must not be used for**.

Common to all: scikit-learn 1.9.1 · CPU only · seed 42 · feature spec
`9225377386b539d6e1ea89c7ae7e37ec0c25a41fe405a810feefd4b10c47637c` · artefacts in `models/`.
A model whose recorded spec hash differs from the running one is **refused at load time**,
not used (`server/engine/ml_registry.py`).

---

## Card 1 — `anomaly_t1` / `anomaly_t2` (Component A)

| | |
|---|---|
| **Task** | Unsupervised novelty detection over process behaviour |
| **Algorithm** | IsolationForest (300 trees, max_samples 256) + median imputation |
| **Output** | `detections.anomaly_score` ∈ [0,1] — a **percentile against the fitted benign baseline** |
| **Fitted on** | Benign rows only (novelty detection, not outlier detection) |
| **Status** | **Deployed.** T1 recommended |

### Intended use
Produce a **ranked triage queue**: "which processes on this host are least like normal?"
Intended to be reviewed top-down by an analyst, a fixed number per host per run.

### Performance (corpus rows, grouped 5-fold CV, 1,716 rows / 185 positives)
| Metric | T1 | T2 |
|---|---:|---:|
| PR-AUC (95% CI) | **0.557** (0.455–0.697) | 0.502 (0.414–0.632) |
| ROC-AUC | 0.910 | 0.909 |
| Recall @1% FPR | 22.2% | 16.8% |
| Precision@25 | **0.84** | 0.64 |

Chance = 0.108. Deployed Sigma rules = 0.286.

### Out-of-scope / must not be used for
* **Not an alarm.** 22% recall at 1% FPR. Auto-alerting on it would miss most attacks while
  generating noise. Use the top-K queue.
* **Not a verdict.** A high score means *unusual*, not *malicious*. On a real workstation the
  top-ranked items were `opencode.exe`, `chrome.exe` and an NVIDIA overlay.
* **Not calibrated across estates.** The score is a percentile of *its own* training baseline.
  A corpus-derived threshold under-stated real false positives by ~6× — re-fit on the target
  estate's benign data.
* **Not validated on Linux.** Corpus is Windows-only.

### Ethical / operational considerations
The score is a statistical deviation, so it can flag legitimate-but-unusual work — a
developer's tooling, an admin's scripts. Treating it as evidence of wrongdoing would be
unfair to the user and wrong on the facts. Every finding carries `ml_explanation` and the UI
labels it "not a rule match".

---

## Card 2 — `triage_t1` / `triage_t2` (Component B)

| | |
|---|---|
| **Task** | Supervised binary classification: is this process part of an intrusion? |
| **Algorithm** | HistGradientBoostingClassifier (200 iters, depth 4, min_leaf 20, L2 1.0) |
| **Output** | `detections.confidence_score` ∈ [0,1] — calibrated P(malicious) |
| **Trained on** | 1,716 corpus rows, 185 positives, 105 capture groups |
| **Status** | **Deployed.** T1, **uncalibrated** variant recommended |

### Intended use
Rank **all** detections — rule-derived and ML-derived alike — by probability that the
underlying process is genuinely malicious, so one analyst queue is comparable across sources.

### Performance (corpus rows, grouped 5-fold CV)
| Metric | Value |
|---|---:|
| PR-AUC (95% CI) | **0.922** (0.878–0.963) |
| ROC-AUC | 0.989 |
| Recall @1% FPR | 71.9% |
| Precision@25 | **1.00** |
| Brier / ECE (uncalibrated) | 0.0237 / **0.0085** |
| Brier / ECE (Platt-calibrated) | 0.0257 / 0.0174 |

Recovers **98 of the 148 attacks the Sigma rules miss** (union recall 20% → 73%) at 16 extra
false positives.

### Robustness — the leak audit
Labels were generated from command-line seed signatures, so the obvious failure mode is the
model rediscovering the labelling rule. Measured:

| Features removed | Remaining | PR-AUC |
|---|---:|---:|
| none | 79 | 0.922 |
| seed-echo features | 69 | 0.913 |
| + tree (`sibling_count` artefact) | 65 | 0.900 |
| + all command-line features | 53 | 0.876 |
| + rarity | 50 | **0.868** |

Stripping 29 of 79 features — including every one that restates a seed signature — costs
0.054. **The result is not circular.**

### Out-of-scope / must not be used for
* **Not a basis for automated action.** The framework is DRY-RUN by design; this changes nothing.
* **Labels are weak.** Heuristic seeds plus lineage propagation, not ground truth. 26 captures
  yield no seed and are labelled entirely benign, so precision is a **lower bound**.
* **`hour_of_day` is a known-bad feature** still present in the trained artefact (PSI 8.67 —
  it encodes when the 2020 lab captures ran). Flagged for removal at the next retrain.
* Trained on Windows adversary-emulation data. Behaviour on Linux or on a genuinely novel
  toolset is unmeasured.

### Calibration note
Wrapping in `CalibratedClassifierCV` made calibration **worse** (ECE 0.0174 vs 0.0085).
HistGradientBoosting already optimises log-loss; Platt scaling over 3 inner folds on 185
positives added variance without removing bias. Ship uncalibrated; revisit as data grows.

---

## Card 3 — `tactic_t1` (Component C)

| | |
|---|---|
| **Task** | Multi-class ATT&CK tactic suggestion for unmapped findings |
| **Algorithm** | Multinomial logistic regression (C=0.5, balanced classes) |
| **Output** | `detections.suggested_tactics` (ranked JSON array) |
| **Status** | ⛔ **NOT DEPLOYED — measured and found insufficient** |

### Performance (grouped 5-fold CV, 185 positives, 4 classes after collapsing)
| Class | F1 | Support |
|---|---:|---:|
| defense_evasion | 0.65 | 75 |
| lateral_movement | 0.54 | 44 |
| credential_access | 0.36 | 38 |
| other | 0.37 | 28 |

**Accuracy 0.508 vs a 0.405 majority-class baseline.** Macro F1 0.478. Thresholding on
confidence reaches only 59.5% accuracy at 45% coverage.

### Why it is not deployed
A suggestion wrong ~45% of the time spends analyst attention and erodes trust in the ML
outputs that *do* work. The dominant confusion (`defense_evasion` ↔ `credential_access`, 25
errors) is not really model error: **ATT&CK tactics are not mutually exclusive** — a
credential dumper that disables logging is doing both — but the corpus assigns one tactic per
capture from its directory. Single-label classification is imposed by the label format.

**What would fix it:** multi-label learning against technique-level labels, with hundreds of
examples per class. Neither exists in this data.

The artefact and code are retained, tested and re-runnable so the decision can be revisited,
but the model is not wired into `run_engine()` and its output is never shown in the UI.

---

## Card 4 — host risk score (not a model)

| | |
|---|---|
| **Task** | Order hosts by investigation priority |
| **Method** | Deterministic weighted aggregation — **no learning** |
| **Output** | `host_risk_scores.score` / `.tier` |
| **Status** | **Deployed** |

```
score = Σ(severity_weight × 0.95^days) + 3 × distinct_tactics + min(ml_points, 10)
```

Deliberately not ML: there is no label for "how compromised is this host", so anything
learned would be fitting an invention. Every point traces to a specific detection, which is
what makes it defensible to an analyst who disagrees with the ordering.

**Weights are policy, not science.** They encode a judgement (a multi-tactic chain matters
more than repeated hits from one noisy rule) and should be tuned per estate. Two guards:
ML contribution is capped, and ML findings earn no tactic-diversity bonus — letting a hint
inflate a kill-chain signal would be circular.

---

## Retraining and monitoring

```bash
python scripts/retrain_ml.py --check-drift    # exits 2 when features have shifted
python scripts/retrain_ml.py                  # retrains only if drift says so
python scripts/update_risk_scores.py
```

Retraining is **not** automatic on a schedule. A model performing well should not be replaced
because a day passed, and retraining on a drifted but *unlabelled* live distribution cannot
improve a supervised model — there are no new labels in it. Drift monitoring exists so a
human knows the ground moved.

Current drift status: **32 of 79 features shifted** between the training corpus and live data.
See `ML_EVALUATION_TRIAGE.md` §5.
