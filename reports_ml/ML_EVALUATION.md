# ML_EVALUATION.md — Component A: process anomaly detection

**Generated from** `reports_ml/anomaly_eval.json` (produced by
`python -m ml.training.train_anomaly`). Figures in `reports_ml/figures/`.
**Feature spec** `d00ba3e2feead75b…` · **seed** 42 · **scikit-learn** 1.9.1 · CPU only.
**Last measured** 2026-09-18, after Phase 8 (train/serve correction).

Reproduce end to end:
```bash
.venv-ml313/Scripts/python.exe -m ml.datasets.otrf fetch
.venv-ml313/Scripts/python.exe -m ml.datasets.otrf_etl --rebuild
.venv-ml313/Scripts/python.exe -m ml.datasets.labels
.venv-ml313/Scripts/python.exe -m ml.training.train_anomaly --save
.venv-ml313/Scripts/python.exe -m ml.evaluation.figures
```
The `labels` step is not optional after `--rebuild`: the ETL rewrites `corpus_lineage` and the
labels have to be regenerated onto it, or training silently sees a corpus with no positives.

---

## 1. Summary

The deterministic engine answers *"does this match a known rule?"*. Component A answers
*"is this unusual?"* — the proactive threat-hunting capability the internship subject asks
for, and the only one that can surface behaviour nobody has written a rule for.

**It works, with a clearly bounded scope.** An IsolationForest baseline of normal process
behaviour reaches **PR-AUC 0.549 (95% CI 0.449–0.692)** against a chance floor of 0.125 — a
**4.6× lift** — and beats all three mandatory baselines with non-overlapping intervals against
the best of them. Of the top 25 ranked processes, **23 are genuine attacks**.

**It is not an alerting mechanism.** At a 1% false-positive rate it recovers only 22% of
attacks, and at thresholds low enough to keep false alerts tolerable on real endpoints its
recall collapses to a few percent. Component A should ship as a **ranked triage queue**, not
as something that raises alarms on its own.

**It adds detections the rules miss.** The Sigma ruleset catches 37 of 205 attacks (18%) with
*perfect precision*. The model surfaces **19 more that no rule fired on**, lifting union
recall from 18.1% → 27.3%, at a cost of 16 additional false positives.

### 1.1 Phase 8 removed features that were measuring the lab, not the behaviour

| | Phase 7 | Phase 8 | |
|---|---:|---:|---|
| PR-AUC | 0.588 | **0.549** | −0.039 |
| **Precision@25** | 0.92 | **0.92** | **unchanged** |
| Recall @1% FPR | 25.9% | **22.0%** | −3.9pp |
| local false-positive rate at a 1% corpus threshold | 10.2% | **7.8%** | better |

Phase 7b.2 added five "burst" features and reported them as that phase's headline win. The PSI
drift monitor subsequently showed **all five were NaN on every live host** — they were computed
from a column holding a per-process launch time in the corpus and a single per-sweep timestamp
in production. Measuring them individually then showed one contributed exactly 0.0000, one was
collection-constant, and one was a **lab-capture artefact**: malicious processes sat a median
0.5 s into the capture against 26.9 s for benign ones, so the feature encoded *when in the
recording something happened*. Four were deleted; `docs/ML_PHASE8_PLAN.md` has the per-feature
numbers.

**The claim here is narrow and worth stating precisely.** These measurements do not show that
production performance improved — nothing in this corpus can show that. They show the previous,
higher numbers were **unattainable in production**. A lower number a deployed host can actually
reproduce is worth more than a higher one it cannot.

**Precision@25 did not move.** The metric that describes how this component is actually
deployed — "review the 25 most anomalous processes per host" — is identical before and after.
What fell was PR-AUC, a whole-ranking measure that the deleted features flattered. That is a
strong indication the artefacts were inflating the *tail* of the ranking rather than the head.

Two independent signs this was a real cleanup rather than a regression:

* the **local false-positive rate improved** (§5) — the corpus-fitted threshold now transfers
  7.8× worse to a real workstation, against 10.2× before;
* Component B's **leak audit went negative** (`ML_EVALUATION_TRIAGE.md` §2.3): removing every
  feature that restates the labelling rule now makes that model *better*, where at Phase 7 it
  was neutral and at Phase 6 it cost 0.0088.

---

## 2. What was measured, and on what

| | |
|---|---|
| Rows | 2,254 (1,716 OTRF corpus + 538 real local benign) |
| Positives | 205 (11.9% of the evaluated population) |
| CV groups | 107 captures/collections; `GroupKFold`, 5 folds |
| Features | 110 total — **80 T1** (psutil-computable) / +19 T2 (Sysmon) / +11 T3 (PowerShell) |

Tiers are cumulative, so the T1 model uses 80 features and the T2 model 99. T3 is not evaluated
for this component: it adds only PowerShell-derived columns, which are NaN for 97% of rows.

**Ranking metrics are computed on corpus rows only (1,716).** Every positive lives in the
corpus and the local rows are 100% benign, so any feature separating the two sources hands the
model a free "this cannot be an attack" signal — and `sysmon_available` separates them perfectly
(1.000 corpus vs 0.000 local), as does `cmdline_present` (1.000 vs 0.725). Scoring across both
would have credited the model for discarding 538 trivially-identifiable negatives. The local
rows are still used for two things: they join the benign baseline the model is fitted on, and
they provide an **independent false-positive measurement** (§5).

Accuracy is never reported. At an 11.9% positive rate, answering "benign" always scores 88.1%.

---

## 3. Headline results

![Model versus baselines](figures/01_model_vs_baselines.png)

| Model | PR-AUC | 95% CI | lift | ROC-AUC | Recall @1% FPR | Precision@25 |
|---|---|---|---|---|---|---|
| chance | 0.125 | 0.087–0.199 | 1.0× | 0.518 | 0.5% | 0.04 |
| **Sigma rules (deployed)** | 0.278 | — | 2.3× | 0.590 | n/a | n/a |
| best single feature | 0.325 | 0.253–0.413 | 2.7× | 0.819 | 67.3% | 0.28 |
| best single feature (no tree) | 0.177 | 0.115–0.326 | 1.5× | 0.602 | 10.2% | 0.64 |
| IsolationForest **T2** (99 feat) | **0.553** | 0.461–0.683 | 4.6× | **0.908** | 19.0% | 0.80 |
| IsolationForest T2, no tree (95) | 0.491 | 0.402–0.623 | 4.1× | 0.898 | 13.2% | 0.68 |
| **IsolationForest T1 (80 feat)** | 0.549 | 0.449–0.692 | 4.6× | 0.893 | **22.0%** | **0.92** |

The Sigma row carries `n/a` deliberately. It is a **binary** scorer, so "recall at 1% FPR" is
meaningless for it: every benign row scores 0, the 99th-percentile threshold is therefore 0,
`score ≥ 0` matches everything, and the metric returns *recall 1.0 at an actual FPR of 100%*.
The harness detects binary scorers and refuses to print the flattering number
(`core_metrics.binary_scorer`); the confusion matrix below is the honest summary.

**Sigma rules, at their own operating point:** TP 37 · FP 0 · FN 168 · TN 1,511 →
**precision 1.000, recall 0.181**. Exactly what good rules do: narrow, certain. Four of the ten
rules fired (encoded PowerShell 31, schtasks 3, whoami 2, mimikatz 1).

**T1 and T2 are now indistinguishable on PR-AUC (0.549 vs 0.553) and separate clearly on the
metrics that matter operationally** — T1 reaches precision@25 of 0.92 against 0.80, and 22.0%
recall at 1% FPR against 19.0%. The recommendation stays T1, now on stronger grounds than at
Phase 7: it is the tier every host can supply *and* the better model where it is used.

---

## 4. Does the model add anything the rules don't?

This is the question that decides whether Layer 4.5 ML earns its operational cost.

![Detection overlap](figures/04_sigma_complementarity.png)

At a 1% false-positive threshold, over 205 labelled attacks:

| | attacks |
|---|---:|
| Caught by rules only | 17 |
| Caught by both | 20 |
| **Caught by the model only** | **19** |
| Caught by neither | 149 |

**Union recall 27.3% vs 18.1% for rules alone** — a **+9.2pp absolute gain**, recovering 11.3%
of the attacks rules miss, for **16 extra false positives**.

Honest reading: a real but modest gain. It supports running ML findings in a **separate review
lane** rather than merging them into the main detection stream — which is what the
`approvals_queue` workflow already in the framework is built for. And 149 attacks (73%) are
caught by *neither*, which is the strongest argument in this report for continued detection
engineering rather than for more ML.

**This is Component A alone.** The supervised Component B closes most of that gap — union
recall **83.9%**, with only 33 of 205 attacks caught by neither — which is the reason the two
components ship together rather than either one alone. See `ML_EVALUATION_TRIAGE.md` §2.5.

---

## 5. False positives on real endpoint data — and a calibration trap

The 538 local rows are genuine processes from a live workstation that nobody is attacking. They
took no part in choosing the threshold, so they are an honest test of what an analyst would
actually experience.

![Operating points](figures/03_operating_points.png)

Alerts per 270-process host sweep, thresholds set on **corpus** benign rows:

| Threshold (corpus FPR) | IF T1 | IF T2 | IF T2 no-tree |
|---|---:|---:|---:|
| 1.0% | 21.1 | 14.1 | 9.0 |
| 0.5% | 15.6 | 9.0 | 8.0 |
| 0.1% | 8.0 | 0.5 | **0.0** |

**Finding — thresholds calibrated on the corpus still under-state real false positives.**
A threshold set to 1% FPR on corpus benign rows produces a **7.8% false-positive rate on real
local benign data** — roughly **8× worse than advertised**. The corpus's benign background (lab
domain controllers and workstations) is simply cleaner and more uniform than a real developer
workstation full of browsers, updaters and vendor agents.

That ratio was **10.2× at Phase 7** and is 7.8× now. Removing the artefact features made the
corpus-fitted threshold transfer *better*, which is the second independent sign (after the leak
audit) that Phase 8 removed something that was not generalising.

**Operational consequence:** the deployment threshold must be calibrated on *each estate's own
benign baseline*, never inherited from training. This is implemented as the percentile mapping
in `ml_anomaly.AnomalyModel` — the stored score is a percentile of whatever baseline the model
was fitted on, so re-fitting on a customer's own data re-calibrates automatically.

**Finding — best ranking and lowest false positives are still different models.** T2-no-tree is
by far the cleanest in practice (9.0 alerts/sweep at 1%, and 0.0 at 0.1%) and the weakest at
ranking (0.491, precision@25 0.68). T1 ranks and triages best and carries the worst nuisance
rate (21.1). Corpus ranking performance and deployed nuisance rate are not the same objective.

The recommendation stays T1 **because the deployed use is a top-K queue, not a threshold**. An
estate that instead wants a fixed alerting threshold should prefer T2-no-tree, and this remains
the clearest case in the project of the operating mode deciding the model.

---

## 6. Ablations

![Feature group ablation](figures/02_feature_group_ablation.png)

Leave-one-feature-group-out, from the 99-feature T2 model (PR-AUC 0.553):

| Removed | PR-AUC | Δ | Reading |
|---|---:|---:|---|
| parent | 0.345 | **−0.207** | Parent/lineage context is the single most load-bearing family — consistent with DFIR practice, where *what spawned it* matters more than the process itself |
| cmdline | 0.423 | **−0.129** | Command-line content is the second pillar |
| tree | 0.491 | −0.062 | See §6.1 |
| path | 0.502 | −0.051 | |
| rarity | 0.509 | −0.044 | Fitted name/lineage rarity contributes real signal |
| sysmon | 0.549 | −0.004 | Now roughly neutral — see §6.2, this reverses an earlier finding |
| conn | 0.558 | +0.006 | Do not act on this — see below |

**Six of seven families now earn their place.** At the intermediate 111-feature spec, five of
seven *improved* the model when removed — a clear symptom of over-dimensioning — and dropping
`procs_within_60s` removed it. That is the same evidence, seen from the other side, as the
+0.0154 PR-AUC that feature cost when it was present.

**The `conn` row is the one number in this table not to act on.** The corpus sees a connection
for only 6.1% of processes and carries **zero** TCP state; a live psutil sweep sees 13.0% and
100% TCP state. Deleting features on evidence from a source that systematically under-represents
them would be the wrong inference from a biased sample, so they were **kept against this
measurement** — see `docs/ML_PHASE7_PLAN.md` §7c.

### 6.1 The `sibling_count` artefact — and why it turned out not to matter
Malicious processes have a median `sibling_count` of **0**, against 4 (corpus benign) and 26
(local benign), and that one feature alone reaches ROC-AUC 0.86 in every fold. That is largely
an artefact of **lineage labelling**: labelling an attacker's subtree produces small families by
construction, while benign background is dominated by `services.exe`/`svchost.exe` sibling sets.
A real deployment would not enjoy that separation.

Removing the tree family costs the *model* 0.062 (0.553 → 0.491) and costs the *single-feature
baseline* 0.147 (0.325 → 0.177), with its ROC-AUC collapsing from 0.819 to 0.602. So the
artefact was inflating the **baseline** more than twice as much as the model. The conclusion
survives the correction.

### 6.2 Sysmon features no longer hurt — a finding that reversed
**This section reported −0.056 at Phase 3 and −0.020 at Phase 7. It is now −0.004: neutral.**

The original explanation still holds as a mechanism: IsolationForest isolates points by random
axis-aligned splits, so additional low-variance columns dilute the probability of splitting on
an informative one, and that dilution is worst when the informative columns are few. What
changed is the ratio. Removing four features that carried no generalising signal left a feature
set in which the Sysmon block is no longer the marginal cost it was, and T2 now edges T1 on
PR-AUC (0.553 vs 0.549) while remaining clearly worse on precision@25 (0.80 vs 0.92).

**The honest reading is that this was never a fact about Sysmon.** It was a fact about
dimensionality at 205 positives, and it moved when the dimensionality did. Anyone quoting
"Sysmon features hurt the anomaly model" from an earlier version of this report should stop; the
defensible statement is that **T1 and T2 are within noise of each other for this component, and
T1 is preferred because precision@25 is the metric that matches its deployment.**

**None of this is an argument against installing Sysmon.** Sysmon is what gives the *rules*
their coverage, and what gives the corpus its command lines.

---

## 7. Stability and uncertainty

![Fold stability](figures/05_fold_stability.png)

Per-fold PR-AUC: T1 `[0.635, 0.835, 0.448, 0.463, 0.596]` — mean 0.595, **sd 0.157**.

The spread is wide, and it widened in Phase 8 (from sd 0.136). That is the honest headline
rather than a footnote: the removed features were partly *stabilising* the folds, in the way a
capture-identifying feature would. With 205 positives across 105 captures, each fold rests on
~41 positives, and the folds range from 0.448 to 0.835.

All intervals are **group** bootstraps (resampling whole captures): a row bootstrap would treat
15 processes from one attack as 15 independent observations and report intervals several times
too narrow.

**What survives the uncertainty**, and what does not:

* **Survives:** the model beats chance by 4.6× and the best single-feature baseline with
  non-overlapping intervals (0.449–0.692 against 0.253–0.413). Precision@25 of 0.92 against 0.28
  is a wide, operationally meaningful margin.
* **Does not:** the T1-vs-T2 difference (0.549 vs 0.553), and the Sysmon ablation (−0.004). Both
  sit far inside fold-to-fold noise and neither should be quoted as a finding.

---

## 8. Threats to validity

1. **Weak labels.** Labels come from heuristic seed signatures plus lineage propagation, not
   from ground truth emitted by the emulation harness. **17** captures yield no seed at all and
   are therefore entirely benign-labelled — some of those almost certainly contain attacks that
   are silently counted as false positives, so reported precision is a **lower bound**.
   (Phase 7a cut this from 26 captures by adding mechanism-based seeds.)
2. **Seed/feature overlap.** Seeds match encoded-PowerShell patterns, and
   `cmdline_has_encoded_flag` is a feature. This is now **measured rather than argued**: for
   Component B, removing every seed-echoing feature *improves* PR-AUC by 0.0032
   (`ML_EVALUATION_TRIAGE.md` §2.3). The audit cannot be run the same way on an unsupervised
   model — there is no label in its objective to leak — so for Component A the overlap remains a
   bounded but unquantified concern.
3. **One benign workstation.** All 538 local rows come from a single physical machine (live
   hosts 5 and 7 are the same box enrolled twice). The real-world false-positive estimate in §5
   rests on that one machine and should not be read as a fleet-wide figure.
4. **Windows only.** The subject covers Linux; the corpus does not. Linux behaviour is
   **not validated** by this evaluation.
5. **Snapshot vs event-stream skew.** Sysmon EID 1 records every launch; a psutil sweep sees
   only survivors. Short-lived attacker processes are over-represented in training relative to
   what a 60-second sweep would capture, so corpus recall is an **upper bound** for a
   psutil-only deployment.
6. **Small N.** 205 positives, 8 tactics, 3 of which have fewer than 10 examples.
7. **The corpus cannot judge the network features.** Stated in §6: 6.1% connection coverage and
   0% TCP state against 13.0% and 100% live. Any conclusion about `conn_*` features from this
   evaluation is unsafe in both directions.
8. **Cross-validation on this corpus has already been wrong once about generalisation.**
   Phase 7b.2's five features scored well here and were unusable in production. Grouped CV
   protects against leakage *between captures*; it says nothing about whether a column means the
   same thing on the other side of the deployment boundary. Only the drift monitor and a live
   sweep can answer that, and `tests/test_ml_phase8.py` now fails the build when a T1 feature is
   well-populated in training and near-absent at serve time.
9. **Two findings in this report have already reversed** — Sysmon's effect (§6.2) and
   calibration (`ML_EVALUATION_TRIAGE.md` §2.4). Both reversed because the data underneath them
   changed, not because they were measured badly. At 205 positives, any result inside the fold
   sd should be read as provisional by default.

---

## 9. Recommendations

**For the framework**
1. **Deploy Component A as a ranked triage queue**, not an alarm. Precision@25 of 0.92 makes
   "review the 25 most anomalous processes per host" a good use of an analyst's time; 22% recall
   at 1% FPR does not make a good alert.
2. **Route ML findings to a separate review lane** (`approvals_queue` with
   `rule_type='ml_anomaly'`) until the false-positive rate is measured on the target estate.
3. **Calibrate the threshold on the target estate's own benign baseline.** §5 shows a corpus
   threshold under-states real false positives ~8×.
4. **Run the agent elevated.** It currently cannot read the command line of **27% of live
   processes** — `svchost.exe`, `System`, `Registry`, `csrss.exe`, `LsaIso.exe` — i.e. precisely
   the names attackers masquerade as, and `cmdline` is the second most load-bearing feature
   family (−0.129 when removed). Unelevated, that figure was measured at 52% on a fresh sweep.
5. **Keep writing rules.** 73% of attacks are caught by neither rules nor *this* component. The
   rules that exist have *perfect precision*; the gap is coverage, not quality. (With Component
   B the figure falls to 16%, which is the case for shipping both.)

**For the ML work**
6. Use **T1 features** for this component — not because Sysmon hurts (it no longer does, §6.2)
   but because T1 wins on precision@25 and is the tier every host can supply. Prefer T2-no-tree
   only if the deployment uses a fixed threshold rather than a top-K queue (§5).
7. Report **precision@k** as the operational headline, not recall-at-FPR and not PR-AUC.
   Precision@25 is the only headline metric that did not move across the Phase 8 correction,
   which is itself a reason to trust it more than the others.
8. **Label quality remains the highest-yield lever.** Phase 7a's nine recovered captures were
   worth more than any feature work in this project, and the **17** captures that remain
   unseeded are the next cheapest improvement available.
9. **Bound or log-scale the surviving burst features before adding anything new.**
   `seconds_since_parent_start` runs to 7,203 s at p75 on a live host against 13 s in the corpus
   (`ML_EVALUATION_TRIAGE.md` §5.3). It would not affect Component B, which is tree-based and
   invariant to monotone transforms, but it would affect this one.
10. Do not tune hyperparameters against these numbers. There is no tuning split, so a search
    here would be fitting the evaluation. Add nested CV first, or leave it untuned and say so —
    which is what this report does.
