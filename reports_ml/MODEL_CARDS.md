# Model cards — ATOR DFIR Layer 4.5 ML

One card per model, following the Mitchell et al. (2019) model-card structure: what it is
for, what it was trained on, how it performs, and — the part that matters most in security —
**what it must not be used for**.

Common to all: scikit-learn 1.9.1 · CPU only · seed 42 · feature spec
`d00ba3e2feead75b…` (full hash in any artefact) · artefacts in `models/`.
A model whose recorded spec hash differs from the running one is **refused at load time**,
not used (`server/engine/ml_registry.py`).

**Feature tiers are cumulative** (as of Phase 7): T1 ⊂ T2 ⊂ T3.

| Tier | Features | Needs | Availability |
|---|---:|---|---|
| **T1** | 80 | psutil only — what the agent always collects | every host |
| T2 | +19 = 99 | Sysmon in `raw_logs` | hosts with Sysmon deployed |
| T3 | +11 = 110 | PowerShell module / script-block logging (GPO) | rare; off by default |

> **Phase 8 changed these counts and every number on these cards.** Four features added in
> Phase 7b.2 were found to be NaN on every production host and were deleted; the corpus
> metrics fell accordingly. The lower numbers are the ones a deployed host can actually
> reproduce. `docs/ML_PHASE8_PLAN.md` carries the argument and the per-feature measurements.

A host is scored at the highest tier its telemetry actually supports
(`ml_registry.choose_tier`), because feeding a T2 model a block of NaNs it never saw in
training is worse than using T1. **T1 is the recommended deployment tier for all three
components** — the measured gains from T2 and T3 both sit inside the confidence intervals.

---

## Card 1 — `anomaly_t1` / `anomaly_t2` (Component A)

| | |
|---|---|
| **Task** | Unsupervised novelty detection over process behaviour |
| **Algorithm** | IsolationForest (300 trees, max_samples 256) + median imputation |
| **Output** | `detections.anomaly_score` in [0,1] — a **percentile against the fitted benign baseline** |
| **Fitted on** | Benign rows only (novelty detection, not outlier detection) |
| **Status** | **Deployed.** T1 recommended |

### Intended use

Produce a **ranked triage queue**: which processes on this host are least like normal?
Intended to be reviewed top-down by an analyst, a fixed number per host per run.

### Performance (corpus rows, grouped 5-fold CV, 1,716 rows / 205 positives, 11.9% base rate)

| Metric | T1 (80 feat) | T2 (99 feat) |
|---|---:|---:|
| PR-AUC (95% CI) | 0.549 (0.449–0.692) | **0.553** (0.461–0.683) |
| ROC-AUC | 0.893 | **0.908** |
| Recall @1% FPR | **22.0%** | 19.0% |
| Precision@25 | **0.92** | 0.80 |
| Alerts/sweep @50% recall | 18.4 | 15.6 |

Chance = 0.125. Deployed Sigma rules = 0.278. Best single feature = 0.325.

**T1 is recommended despite T2 edging it on PR-AUC**, because the deployed use is a top-K
queue: precision@25 is 0.92 against 0.80, and 22.0% recall at 1% FPR against 19.0%. The two
are indistinguishable on PR-AUC (0.549 vs 0.553, intervals almost entirely overlapping).

Phase 7 reported **0.588 / 0.92**; Phase 8 reports **0.549 / 0.92**. PR-AUC fell because four
features that were measuring the lab recording rather than the process were removed.
**Precision@25 did not move at all** — the deleted features were inflating the tail of the
ranking, which a top-K queue never reaches. The algorithm has never been touched in any phase.

### Out-of-scope / must not be used for

* **Not an alarm.** 22% recall at 1% FPR. Auto-alerting on it would miss most attacks while
  generating noise. Use the top-K queue.
* **Not a verdict.** A high score means *unusual*, not *malicious*. On a real workstation the
  top-ranked items were `opencode.exe`, `chrome.exe` and an NVIDIA overlay.
* **Not calibrated across estates.** The score is a percentile of *its own* training baseline.
  A corpus-derived threshold under-stated real false positives by ~8× — re-fit on the target
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
| **Output** | `detections.confidence_score` in [0,1] — calibrated P(malicious) |
| **Trained on** | 1,716 corpus rows, 205 positives, 105 capture groups |
| **Status** | **Deployed.** T1, **Platt-calibrated** — the Phase 5 recommendation reversed, see below |

### Intended use

Rank **all** detections — rule-derived and ML-derived alike — by probability that the
underlying process is genuinely malicious, so one analyst queue is comparable across sources.
It is also the **gate on Component C**: a tactic hint is only surfaced where this model's
confidence is at least 0.50.

### Performance (corpus rows, grouped 5-fold CV)

| Metric | T1 | T2 |
|---|---:|---:|
| PR-AUC (95% CI) | **0.927** (0.884–0.965) | 0.932 (0.887–0.970) |
| ROC-AUC | 0.988 | 0.989 |
| Recall @1% FPR | **82.4%** | 84.4% |
| Precision@25 | **0.96** | 0.96 |
| Alerts/sweep @90% recall | 10.4 | 7.9 |
| Brier / ECE (calibrated) | **0.0251** / **0.0161** | 0.0234 / 0.0160 |
| Brier / ECE (uncalibrated) | 0.0262 / 0.0194 | — |
| Brier skill score | **0.761** | 0.778 |

Recovers **135 of the 168 attacks the Sigma rules miss** (union recall 18.1% → **83.9%**) for
**16 extra false positives**. Attacks caught by neither the rules nor the model: **33 of 205**,
down from 50 at Phase 6.

Phase 7 reported 0.942 / 87.3% / 25-caught-by-neither. Those figures depended on features that
do not exist on a live host (see the box at the top); these do.

### Robustness — the leak audit

Labels were generated from command-line seed signatures, so the obvious failure mode is the
model rediscovering the labelling rule. Measured:

| Features removed | Remaining (T1) | PR-AUC | Recall @1% FPR |
|---|---:|---:|---:|
| none | 80 | 0.9265 | 82.4% |
| seed-echo features | 70 | **0.9297** | 81.5% |
| + all command-line features | 58 | 0.9258 | 81.0% |

**Removing every feature that restates a seed signature now makes the model _better_, by
0.0032.** The progression across phases is the clearest single indicator of how much
circularity there was: **0.0088** (Phase 6) → 0.0073 (7a) → 0.0001 (7b) → **−0.0032** (Phase 8).
Stripping command-line evidence *entirely* — 22 of 80 features, which no real detector would
do — still leaves 0.926. **The result is not circular.**

(The audit names 13 seed-echo features; 10 are in T1, the other 3 are T3 `psh_*` features.)

### Out-of-scope / must not be used for

* **Not a basis for automated action.** The framework is DRY-RUN by design; this changes nothing.
* **Labels are weak.** Heuristic seeds plus lineage propagation, not ground truth. **17**
  captures still yield no seed and are labelled entirely benign, so precision is a **lower
  bound**. (Phase 7a cut this from 26.)
* Trained on Windows adversary-emulation data. Behaviour on Linux, or on a genuinely novel
  toolset, is unmeasured.
* **T3 buys nothing for detection** — see the tier note below.

### Calibration note — the recommendation reversed in Phase 7

At Phase 5, with 185 positives, wrapping in `CalibratedClassifierCV` made calibration
**worse** (ECE 0.0174 vs 0.0085) and this card said to ship uncalibrated. At 205 positives the
answer flipped, and after the Phase 8 feature correction it is no longer close: calibrated
wins on **Brier (0.0251 vs 0.0262)**, on **skill score (0.761 vs 0.751)** *and* on **ECE
(0.0161 vs 0.0194)**. At Phase 7 the ECE comparison still favoured uncalibrated; it no longer
does. **Ships calibrated**, and the recommendation is now consistent across all three measures
rather than resting on Brier alone.

Still provisional: it changed direction once, on 20 extra positives, and the margins are small
in absolute terms. What improved is the *agreement* between measures. Both variants are
re-measured on every training run.

### Tier note — the T3 null result

PowerShell module logging (T3, +11 features) changes PR-AUC by **+0.004** and recall @1% FPR
by +2.4pp — both inside the confidence interval, so still a null result and reported as one. The features are strikingly discriminative *where they exist* — `psh_has_url`,
`psh_has_crypto_loop` and `psh_host_app_encoded` are 0.000 on benign and 0.32–0.35 on
malicious, and the deobfuscated payload exposes Empire's literal C2 URIs. But only 45 of 1,716
processes have attributable PowerShell events, 32 of them malicious, and those 32 are already
classified confidently by the command-line, parent and path features. **The evidence is real
but already covered.** T3 is retained and wired because it is valuable for *investigation*,
not because it improves *detection*.

---

## Card 3 — `tactic_t1` (Component C)

| | |
|---|---|
| **Task** | Multi-class ATT&CK tactic suggestion for unmapped findings |
| **Algorithm** | Multinomial logistic regression (C=0.5, balanced classes) |
| **Output** | `detections.suggested_tactics` (ranked JSON array) |
| **Trained on** | 205 malicious corpus rows only, 88 capture groups |
| **Status** | ⚠️ **Ships as a gated hint** — changed in Phase 7, was NOT DEPLOYED |

> **This card previously read "⛔ NOT DEPLOYED — measured and found insufficient".** That was
> the right call on the Phase 5 evidence (50.8% accuracy against a 40.5% baseline). Phase 7a's
> label recovery — 185 → 205 positives, and five learnable classes instead of three — moved it
> far enough to ship, but only **behind three gates**. The reasoning that kept it switched off
> is exactly what defines those gates, so it is preserved below rather than deleted.

### Performance (grouped 5-fold CV, 205 positives, 6 classes after collapsing)

| Class | F1 | Support | Ever suggested? |
|---|---:|---:|---|
| lateral_movement | 0.69 | 50 | yes |
| defense_evasion | 0.63 | 81 | yes |
| credential_access | 0.51 | 38 | yes |
| other | 0.15 | 16 | no — support < 30 |
| persistence | **0.00** | 10 | no — support < 30 |
| privilege_escalation | **0.00** | 10 | no — support < 30 |

**Accuracy 0.522 against a 0.395 majority-class baseline.** Macro F1 0.330.
Every F1 above still improves on Phase 5 (credential_access 0.36 → 0.51, lateral_movement
0.54 → 0.69), but by less than Phase 7 reported: those figures also depended on the features
Phase 8 removed.

### The three gates, and the number behind each

Ungated, this model is right 52% of the time — not good enough to put in front of an analyst.
Gated, it is right **~80%** of the time and stays silent the rest of the time. **The gate is
the product.** Every threshold is regenerated into `reports_ml/tactic_eval.json` → `gating` on
each `python -m ml.training.train_tactic` run, so none of these numbers is an assertion:

| min probability | suggestions | coverage | precision | + support gate | precision |
|---:|---:|---:|---:|---:|---:|
| 0.00 (ungated) | 205 | 100.0% | 52.2% | 170 | 61.2% |
| 0.50 | 166 | 81.0% | 56.0% | 141 | 64.5% |
| 0.70 | 110 | 53.7% | 65.5% | 92 | 73.9% |
| **0.80 (shipped)** | 83 | 40.5% | 71.1% | **69** | **79.7%** |
| 0.90 | 58 | 28.3% | 74.1% | 49 | 79.6% |

1. **`MIN_SUGGESTION_PROBABILITY = 0.80`** — the coverage-for-precision trade above, and
   after Phase 8 it is the **maximum of the curve rather than a compromise**: raising the gate
   to 0.90 buys no precision at all (79.6% against 79.7%) and costs a third of the coverage.
2. **`MIN_SUPPORT_TO_SUGGEST = 30`** training examples — `persistence` and
   `privilege_escalation` score **F1 0.00** on n=10. They are *nominally* learnable classes and
   are never surfaced even when they win the argmax.
3. **`MIN_CONFIDENCE_TO_SUGGEST = 0.50`** on Component B — next section. This gate exists
   because of an observed failure, not as a precaution.

All three are environment-overridable (`ATOR_ML_TACTIC_MIN_PROB`, `ATOR_ML_TACTIC_MIN_SUPPORT`,
`ATOR_ML_TACTIC_MIN_CONFIDENCE`) so an estate can re-tune them against its own evidence.

### The out-of-distribution failure that forced gate 3

This model is trained on **malicious rows only**: it answers "which tactic?", never "is this an
attack?". Applied to a benign process it is out of distribution, has no *none-of-the-above*
class, and confidently picks the nearest one. On a real workstation, before the gate existed:

```
chrome.exe            ->  lateral_movement, probability 1.00
System Idle Process   ->  lateral_movement, probability 1.00
SearchApp.exe         ->  lateral_movement, probability 1.00
```

The fix is to let the model that answers *"is this an attack?"* gate the one that answers
*"which kind?"*. Requiring Component B confidence ≥ 0.50 took the same workstation from **11
hints across 16 detections to 2**, both on high-confidence findings. **A probability gate alone
would not have caught this** — the model was at p = 1.00. That is the whole argument for
gate 3, and it is why the probability threshold is not sufficient on its own.

### Out-of-scope / must not be used for

* **Not an ATT&CK mapping.** ~80% precision. The rule-derived `technique_id` is authoritative;
  this is a hint, and the UI labels it as one on the badge and in the table footer.
* **Never the raw six-class argmax.** Only the three well-supported tactics are surfaced.
* **Not a reason to reclassify a finding.** It suggests where to look, not what happened.
* **Excluded from the host risk score's tactic-diversity term** (Card 4) — letting a hint
  inflate a kill-chain signal would be circular.

### The structural limit that gating does not fix

The dominant confusion (`defense_evasion` ↔ `credential_access`) is not really
model error: **ATT&CK tactics are not mutually exclusive** — a credential dumper that disables
logging is doing both — but the corpus assigns one tactic per capture, from its directory name.
Single-label classification is imposed by the label format, so a ceiling below 100% is built
into the evaluation and no amount of gating removes it.

**What would lift it:** multi-label learning against technique-level labels, with hundreds of
examples per class. Neither exists in this data.

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

Deliberately not ML: there is no label for "how compromised is this host", so anything learned
would be fitting an invention. Every point traces to a specific detection, which is what makes
it defensible to an analyst who disagrees with the ordering.

**Weights are policy, not science.** They encode a judgement — a multi-tactic chain matters
more than repeated hits from one noisy rule — and should be tuned per estate. Two guards: the
ML contribution is capped, and ML findings earn no tactic-diversity bonus. Component C's
suggested tactics are excluded from that term for the same reason.

---

## Retraining and monitoring

```bash
python scripts/retrain_ml.py --check-drift    # exits 2 when features have shifted
python scripts/retrain_ml.py                  # retrains only if drift says so
python scripts/update_risk_scores.py
```

Retraining is **not** automatic on a schedule. A model performing well should not be replaced
because a day passed, and retraining on a drifted but *unlabelled* live distribution cannot
improve a supervised model — there are no new labels in it. Drift monitoring exists so a human
knows the ground moved.

**Changing the feature spec invalidates every artefact.** The Phase 7 bump
(`9225377386b5…` → `685ea57b3ba8…`) and the two Phase 8 bumps (→ `66b5b6f9e8ec…` →
`d00ba3e2feea…`) each made all three models refuse to load until retrained, which is the
intended behaviour: a stale forest fed a changed feature vector produces confident nonsense,
which is worse than no score at all. It is also how the Phase 8 verification run was caught
using stale artefacts before it could report a wrong number.
