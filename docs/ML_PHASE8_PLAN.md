# Phase 8 — correcting the Phase 7b.2 burst features

**Status:** complete · 2026-09-18
**Trigger:** the drift monitor, doing exactly what it was built for.

---

## 0. What happened

Phase 7b.2 added five "temporal burst" features and reported **+0.0134 PR-AUC** and
**recall @1% FPR 0.790 → 0.873**, recorded in `docs/ML_PHASE7_PLAN.md` as the headline win of
Phase 7. Re-running the PSI drift monitor at the Phase 7 feature spec produced this:

| Feature | PSI | missing: train → live |
|---|---:|---|
| `seconds_since_collection_start` | **15.17** | 2.1% → **100.0%** |
| `proc_spawn_rate_per_min` | **15.16** | 2.1% → **100.0%** |
| `procs_within_5s` | **15.12** | 2.1% → **100.0%** |
| `seconds_since_parent_start` | **10.13** | 22.6% → **100.0%** |

**All five burst features are NaN on every live row.** They are the four worst-drifting
features in the entire 83-feature T1 set, and the fifth (`collection_has_timespan`) is
constant.

### Why

`_temporal_features()` derives everything from `raw_processes.collected_at_utc` and returns
NaN unless a collection contains **two or more distinct** values of it. Measured:

| | rows per collection | distinct `collected_at_utc` |
|---|---:|---:|
| corpus (Sysmon EID 1) | 226 | **212** |
| live (psutil sweep) | 282 | **1** |

In the corpus each row *is* a launch event, so `collected_at_utc` is that process's start
time. In production the agent stamps every process in a sweep with **one** timestamp — the
sweep time — because `raw_processes` has no column for a process's own start time and
`agent/collectors/processes.py` never asked psutil for one.

The docstring asserted the opposite: *"the production agent sweeps every 60 seconds, so the
same quantities are computable on both sides."* The sweep cadence was never the issue. The
schema was.

**This is the exact train/serve skew the whole data strategy was built to prevent** — the
corpus was converted into ATOR's own schema so that one `ml_features.py` serves training and
inference. That guarantees the same *code* runs on both sides. It does not guarantee the same
*columns are populated*, and nothing was checking that until the drift monitor was pointed at
the new spec.

---

## 1. Is the gain even real? (measured first, before any redesign)

`reports_ml/burst_audit.json`. Leave-one-out from the 83-feature T1 model:

| Variant | PR-AUC | Δ | recall @1% FPR |
|---|---:|---:|---:|
| T1 (all 83) | 0.9415 | — | 0.8732 |
| T1 − all 5 burst | 0.9281 | **−0.0134** | 0.7902 |
| T1 − `collection_has_timespan` | 0.9415 | **+0.0000** | 0.8732 |
| T1 − `proc_spawn_rate_per_min` | 0.9355 | −0.0060 | 0.8732 |
| T1 − `procs_within_5s` | 0.9418 | **+0.0003** | 0.8683 |
| T1 − `seconds_since_collection_start` | 0.9444 | **+0.0029** | 0.8488 |
| T1 − `seconds_since_parent_start` | 0.9428 | **+0.0013** | 0.8878 |

And per-feature separation on the corpus:

| Feature | AUC | median malicious | median benign | %NaN |
|---|---:|---:|---:|---:|
| `collection_has_timespan` | 0.479 | 1.0 | 1.0 | 0.0% |
| `proc_spawn_rate_per_min` | 0.565 | 39.0 | 33.6 | 2.1% |
| `procs_within_5s` | 0.238 | 3.0 | 7.0 | 2.1% |
| `seconds_since_collection_start` | 0.287 | **0.5 s** | **26.9 s** | 2.1% |
| `seconds_since_parent_start` | 0.361 | 0.1 | 2.6 | 22.6% |

### Three things this says

**1. The block effect does not decompose.** Removing all five costs 0.0134. The individual
contributions sum to −0.0015, and four of the five are **zero or positive** when removed on
their own. A block delta that no member accounts for, at a fold sd of 0.054 and a bootstrap CI
of roughly ±0.035, is **inside the noise floor**. The +0.0134 should never have been reported
as a win; it is not established.

**2. `collection_has_timespan` is provably dead.** AUC 0.479, median 1.0 in both classes,
Δ exactly 0.0000. It is a gate flag that is always open.

**3. `seconds_since_collection_start` is a capture-window artefact.** Malicious processes sit
at a median of **0.5 s** into the capture against **26.9 s** for benign ones — it is measuring
*when in the lab recording something happened*, not anything about the process. It is the same
class of feature as `hour_of_day`, which Phase 7b.1 removed for the same reason. Removing it
*improves* PR-AUC. Keeping it while having removed `hour_of_day` would be inconsistent.

The one feature with a defensible negative delta, `proc_spawn_rate_per_min`, is
**collection-constant**: every row in a capture gets the same value. Under GroupKFold the
model cannot memorise a held-out capture, but a collection-level feature is still closer to a
capture descriptor than a process descriptor, and its −0.0060 is well inside the noise band.

---

## 2. What Phase 8 does

| # | Change | Why |
|---|---|---|
| **8a** | Delete `collection_has_timespan` and `seconds_since_collection_start` | Measured at zero and at *negative* contribution respectively; the second is a lab-capture artefact of the `hour_of_day` class |
| **8b** | Add `create_time_utc` to `raw_processes`, collect it in the agent, populate it in the ETL, and compute the surviving burst features from it | Makes them computable on a psutil sweep instead of NaN — the actual defect |
| **8c** | Re-measure everything and report whatever comes out | Including, explicitly, a null result |
| **8d** | Add a **train/serve coverage guard** to the test suite | So a feature that is computable only in training can never ship silently again |

8d is the part that matters beyond this phase. The drift monitor caught this, but only because
someone ran it after a spec change. A test that fails when a feature's live coverage is far
below its training coverage turns that from a discipline into a property of the build.

---

## 3. Commitments for this phase

The same one Phase 7 was held to: **a change that does not improve a metric gets reported as a
null result, not quietly kept.** Applied here in its harder form — a *previous* claim that does
not survive re-measurement gets corrected in the documents that made it, not left standing
because it is already written down.

Concretely, `docs/ML_PHASE7_PLAN.md`, `docs/ML_PROGRESS.md`, `reports_ml/ML_EVALUATION.md`,
`reports_ml/ML_EVALUATION_TRIAGE.md` and `reports_ml/MODEL_CARDS.md` all currently state the
+0.0134 as a Phase 7 win. All of them get corrected.

---

## 4. Results

### 8a - the deletions

Four features removed, each on a measurement rather than a judgement:

| Feature | Why it went |
|---|---|
| `collection_has_timespan` | AUC 0.479, leave-one-out delta **exactly 0.0000**, median 1.0 in both classes. A gate flag that is always open. |
| `seconds_since_collection_start` | Malicious median **0.5 s** into the capture against **26.9 s** benign. It measured position within a lab recording - the same artefact `hour_of_day` was removed for in 7b.1 - and removing it *improved* PR-AUC by 0.0029. |
| `proc_spawn_rate_per_min` | Identical for every row in a collection, and defined over a span that is ~3 minutes for a capture and can be weeks for a live host. Not comparable across sources at any value. |
| `procs_within_60s` | **Added in this phase and removed in it.** See 8c. |

### 8b - making the survivors computable

`create_time_utc` added to `raw_processes` as a nullable column through the existing ML
migration; collected by `agent/collectors/processes.py` from `psutil` `create_time`;
populated by the ETL for corpus rows, where it equals `collected_at_utc` because a Sysmon
EID 1 record's UtcTime *is* the launch time.

**No fallback.** When `create_time_utc` is NULL the features are NaN. Falling back to
`collected_at_utc` would have reintroduced the bug quietly - one column meaning "started at"
for some rows and "observed at" for others - and NaN is the honest value for "this host did
not say". `tests/test_ml_phase8.py::TestCollectedAtIsNeverUsedAsAStartTime` pins that.

Verified end to end on a real sweep of this workstation, through the real `/api/v1/ingest`:

| | before | after |
|---|---:|---:|
| processes reporting a start time | 0 of 296 | **294 of 296 (99.3%)** |
| distinct `collected_at_utc` in the sweep | 1 | 1 *(unchanged - that is correct)* |
| distinct `create_time_utc` | n/a | **120** |
| `procs_within_5s` populated | **0.0%** | **99.3%** |
| `seconds_since_parent_start` populated | **0.0%** | **93.6%** |
| worst burst-feature PSI | **15.17** | **0.97** |

The two processes without a start time are `System Idle Process` and `System`, which do not
have one. `_iso_utc` returns None for epoch 0 rather than 1970, because a plausible wrong
timestamp is worse than a missing one.

### 8c - and then the replacement failed its own test

`procs_within_60s` was added in 8b as the scale-free replacement for the deleted
collection-wide rate. Measured against the same standard applied to everything else:

| Variant | PR-AUC | delta | recall @1% FPR | delta |
|---|---:|---:|---:|---:|
| T1 (all 81) | 0.9111 | - | 0.8488 | - |
| T1 - all 3 burst | 0.9281 | **+0.0170** | 0.7902 | -0.0586 |
| T1 - `procs_within_5s` | 0.9061 | **-0.0050** | 0.7707 | **-0.0781** |
| T1 - `procs_within_60s` | 0.9265 | **+0.0154** | 0.8244 | -0.0244 |
| T1 - `seconds_since_parent_start` | 0.9116 | +0.0005 | 0.8439 | -0.0049 |

Noise floor for the same run: fold sd **0.0515**, 95% CI width **0.0995**. Every PR-AUC delta
in that table is inside it, which is the standard the withdrawn +0.0134 failed and it applies
here equally.

* **`procs_within_5s` stays.** It is the only feature that costs something on both metrics
  when removed, and **-7.8pp of recall at the operating point** is the largest single effect
  in the table. It also has the lowest residual drift of the three (PSI 0.97).
* **`procs_within_60s` goes.** Removing it *improves* PR-AUC and costs 2.4pp of recall, and it
  carried the worst residual shift (PSI 3.94). It was my hypothesis in this phase; it was
  tested in this phase; it failed. Keeping it because it was already written is precisely the
  mistake that produced Phase 8.
* **`seconds_since_parent_start` stays, as a stated null result.** +0.0005 and -0.0049 are
  both nothing. It is retained on the same grounds as the T3 PowerShell tier: evidence an
  analyst reads during an investigation, recorded as not moving a detection metric.

Final spec: **110 features, 80 T1**, `feature_spec_sha256` `d00ba3e2feead75b...`.

### 8d - the guard

`tests/test_ml_phase8.py::TestTrainServeCoverageGuard` fails the build when a T1 feature is
>=90% populated on corpus-shaped data and <10% populated on sweep-shaped data. The fixtures
are two *differently shaped* databases built from the real `database.SCHEMA`, because the
shape difference is the bug and a fixture that only ever produces one shape cannot see it.

This is the part meant to outlive Phase 8. The drift monitor caught this defect, but only
because someone re-ran it after a spec change. The guard makes that a property of the build
rather than a matter of discipline.

Two further defects fell out of writing these tests:

1. **An all-NULL `ppid` column made the parent self-join raise.** pandas refuses to merge an
   `object` column against an `int64` one, and a collection consisting only of container
   process mappings - which carry no ppid - infers as `object`. `run_engine` would have
   caught it as `ml_error` and degraded, but the feature layer's contract is that missing
   telemetry becomes NaN, not an exception. Both join keys are now coerced first.
2. **The first draft of the test file declared its own schema and got the column names
   wrong** (`event_data` for `payload_json`, a `hosts` row missing three NOT NULL columns).
   That is the same category of mistake as the bug under test - a fixture that does not match
   production cannot test against production - so the fixtures now build from
   `database.SCHEMA` and apply the real migration.

### 8e - what it cost, and why the cost is the point

Every corpus metric fell. That is what removing an artefact looks like, and it is the result:

| | Phase 7 | Phase 8 | |
|---|---:|---:|---|
| **A** PR-AUC | 0.588 | **0.549** | −0.039 |
| **A** precision@25 | 0.92 | **0.92** | **unchanged** |
| **A** recall @1% FPR | 25.9% | 22.0% | −3.9pp |
| **B** PR-AUC | 0.942 | **0.927** | −0.015 |
| **B** recall @1% FPR | 87.3% | 82.4% | −4.9pp |
| **B** union recall with rules | 87.8% | 83.9% | −3.9pp |
| **B** attacks caught by neither | 25 | 33 | +8 |
| **C** accuracy | 57.1% | 52.2% | −4.9pp |
| | | | |
| **B** leak-audit drop | 0.0001 | **−0.0032** | better |
| **C** gated precision | 77.6% | **79.7%** | better |
| **A** corpus-to-live threshold error | 10.2x | **7.8x** | better |
| features | 113 | 110 | |

**Three things went the other way, and they are the ones that say the cleanup was real:**

1. **The leak audit went negative.** Removing every feature that restates the labelling rule
   now makes Component B *better* by 0.0032. The progression across the project is
   0.0088 (Phase 6) -> 0.0073 (7a) -> 0.0001 (7b) -> **-0.0032** (Phase 8). There is no
   circularity left to find.
2. **The corpus-fitted threshold transfers better to a real workstation** - 7.8x error against
   10.2x. A model leaning on lab-recording artefacts is exactly a model whose thresholds do
   not travel, so this is the mechanism showing up in the operational measurement.
3. **Component C's gated precision went up**, and 0.80 is now the *maximum* of its
   precision/coverage curve rather than a compromise: 0.90 buys nothing (79.6% against 79.7%)
   and costs a third of the coverage.

**And one metric did not move at all: Component A's precision@25, at 0.92 both sides.** That is
the metric describing how the component is actually deployed - "review the 25 most anomalous
processes per host". The deleted features were inflating the *tail* of the ranking, which
PR-AUC integrates over and a top-K queue never reaches.

### A finding that reversed on the way through

"Sysmon features actively hurt the anomaly model" has been in `ML_EVALUATION.md` since Phase 3
at -0.056, was -0.020 at Phase 7, and is now **-0.004: neutral**. It was never a fact about
Sysmon. It was a fact about dimensionality at 205 positives, and it moved when the
dimensionality did. The report now says so explicitly, because the earlier phrasing invited
an operational conclusion ("do not bother with Sysmon") that the evidence never supported.

### What this phase cost, and what it bought

It cost four features, a feature-spec bump, a full retrain, and every headline number in three
reports. It bought a feature set where **six of seven families earn their place** (five of
seven *improved* the model when removed at the intermediate spec), a leak audit at zero, and -
the actual point - a set of timing features that are computed on a real host instead of
silently imputed to the training median.

The measurable lesson is in the first table of section 0: the four worst-drifting features in
the entire T1 set were the four most recently added, and they were added on a
cross-validation result. **Grouped CV cannot see across the deployment boundary.** Only the
drift monitor and a live sweep can, and until Phase 8 neither was part of the loop.
