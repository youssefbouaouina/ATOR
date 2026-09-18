# ML_PHASE7_PLAN.md — improvement phase

**Status:** COMPLETE (7a, 7b, 7c) — measured 2026-09-18
**Baseline to beat:** Component B PR-AUC **0.922** [0.878–0.963]; Component A **0.557**
[0.455–0.697]; union recall with rules **73%**; 335 tests green at commit `2106b2d`.

Phases 0–6 built and measured the ML layer. This phase attacks the things the measurements
themselves identified as limiting. Everything here is re-measured against the numbers above;
**a change that does not improve a metric gets reported as a null result, not quietly kept.**

---

## The binding constraint

Every metric is capped by **185 weak labels over 105 capture groups**. Model choice stopped
being the bottleneck several phases ago. So this phase targets, in order: *label quality*,
then *signal coverage*, then *feature hygiene*. Algorithm changes are explicitly out of scope.

---

## 7a — Label quality (do first; it changes every downstream number)

**Problem, measured.** 26 captures contain process rows but match no seed signature, so their
attacks are labelled **benign**. They are counted as false positives against the model, which
is why every precision figure in the current reports is stated as a *lower bound*.

**Work**
1. Enumerate the 26 captures and inspect their process rows.
2. Extend `_TOOL_SIGNATURES` in `ml/datasets/labels.py` with mechanism-specific patterns —
   never anything a feature already encodes (the seed/feature separation rule from Phase 1).
3. Re-label, re-measure, and report the delta on both components.

**Risk.** Over-broad seeds poison the benign class, which would *inflate* results. Mitigations:
the existing seed-rule audit trail, the `MAX_DEPTH` propagation cap, and re-running the leak
audit afterwards. If the leak audit degrades, the new seeds are wrong.

**Success:** more positives, no degradation in the leak audit, and an honest delta either way.

### 7a RESULT (measured 2026-09-18) — clear win

Read the 26 captures. **9 had an identifiable mechanism**; nine mechanism-specific signatures
were added (`sc config binPath=`, `Register-CimProvider -Path`, `hh.exe <chm>`,
`python -m http.server`, `New-Object IO.MemoryStream`, `scrcons.exe`, `wsmprovhost.exe`
scoped to psremoting captures, `public-poc.py`, registry-query discovery).

**The other 17 are genuinely invisible in process-creation telemetry** — in-memory injection
(`psinject`, `dllinjection`), in-memory PowerView, DCERPC service manipulation (`sharpsc`),
Meterpreter mic capture. This is a finding in its own right: two thirds of what the labeller
misses cannot be seen in EID 1 at all, which is precisely the argument for 7b.3.

| | before | after |
|---|---:|---:|
| malicious / benign | 185 / 1531 | **205 / 1511** |
| positive rate | 10.8% | 11.9% |
| unseeded captures | 26 | **17** |
| large captures entirely malicious (over-labelling check) | 0 | **0** |

| Component B | before | after |
|---|---:|---:|
| PR-AUC | 0.922 [0.878–0.963] | **0.934 [0.897–0.969]** |
| Recall @1% FPR | 71.9% | **80.5%** |
| without cmdline features | 0.887 | **0.915** |
| **leak-audit drop** | 0.0088 | **0.0073** |
| union recall with rules | 73.0% | **80.5%** |
| recovered of rules-missed | 98 / 148 (66%) | **128 / 168 (76%)** |
| caught by neither | 50 | **40** |
| `sigma_only` | 2 | **0** |

| Component A | before | after |
|---|---:|---:|
| PR-AUC | 0.557 | **0.571** |
| Precision@25 | 0.84 | **0.88** |

Two things worth stating plainly:

* **The leak audit got *better*, not worse** (0.0088 → 0.0073). Adding seeds could have
  increased circularity; measured, it did the opposite, because the new signatures key on
  utility invocations rather than on anything the feature set computes.
* **`sigma_only` fell to 0** — Component B now ranks every attack the deployed rules catch
  above the 1% FPR threshold, and adds 128 more.

One reversal to report honestly: with 205 positives, Platt calibration now gives a *better*
ECE than uncalibrated (0.0113 vs 0.0139), where at 185 it was worse (0.0174 vs 0.0085).
Brier and skill still favour uncalibrated (0.0238/0.774 vs 0.0254/0.759). The Phase 5
conclusion was data-size-dependent exactly as suspected; the recommendation stays
"uncalibrated" on Brier, but the margin is now thin and should be re-checked as data grows.

---

> ## Correction issued in Phase 8
>
> **The 7b.2 result below does not stand as written.** The five burst features it added were
> keyed off `collected_at_utc`, which is a per-process launch time in the corpus and a single
> per-sweep timestamp in production. The PSI drift monitor later showed **all five were NaN on
> every live row** - they were the four worst-drifting features in the entire T1 set - so the
> reported +0.0134 PR-AUC could never have reached a deployed host.
>
> Re-measuring feature by feature also showed the block delta does not decompose: four of the
> five contribute **zero or negatively** on their own, and the sum of individual contributions
> is -0.0015 against a fold sd of 0.054. **The +0.0134 was inside the noise floor and should
> not have been reported as a win.**
>
> Three of the five were deleted on that evidence and two were rebuilt to work on both data
> shapes. See **`docs/ML_PHASE8_PLAN.md`** for the measurements, and read every 7b.2 number
> below as superseded.

## 7b — Feature spec v2

All three changes below alter `feature_spec_sha256`, so they are bundled into **one** spec
bump, one retrain and one re-evaluation. The registry refuses stale models automatically, so
a partial rollout cannot silently mis-score.

### 7b.1 — Remove `hour_of_day`
PSI **8.67** between train and live: it encodes *when the 2020 lab captures ran*, not
behaviour. A feature that cannot generalise. Also remove `is_weekend` if it behaves the same
way (to be measured, not assumed).

### 7b.2 — Temporal / burst features
Deferred in Phase 2 on incomplete evidence: the *live* database had single snapshots, but
corpus captures span **1.8–6.3 minutes with 88–226 processes**, and the production agent
sweeps every 60 s. So inter-arrival and burst features are computable on both sides.

Candidates (all from `raw_processes.collected_at_utc`, already available):
`proc_spawn_rate_1m`, `siblings_spawned_within_5s`, `time_since_parent_start`,
`host_burst_z` (this collection's spawn count vs the host's other collections).

Gated on `>= 2` timestamps in the collection; NaN otherwise — never silently zero.

### 7b.3 — PowerShell script-block features (largest potential gain)
**Verified feasible today.** 79,921 PowerShell events sit unused in `ml_train.db`. They carry
no `ProcessId`, but `ExecutionProcessID` **is** the generating `powershell.exe` pid: 7 distinct
values across the sampled captures, including **pid 1648 — the Empire agent identified in
Phase 1**. (Contrast Sysmon, where `ExecutionProcessID` is Sysmon's own service and constant
per capture — the trap documented in Phase 1. The field means different things per channel.)

~53% of PowerShell events have `ExecutionProcessID = 0` and are unattributable; those are
dropped rather than guessed.

Three pieces of work:
1. **Agent** — `agent/collectors/logs.py` collects sysmon/security/system/application but
   **not** the PowerShell channels. Without this the features would be pure train/serve skew.
2. **ETL** — stop discarding `ExecutionProcessID` for PowerShell events (it is currently in
   `_ENVELOPE_KEYS`), and keep `ScriptBlockText` / `ContextInfo` / `Payload`.
3. **Features** — a new availability-gated group: script-block count, total script length,
   entropy, obfuscation markers, `Invoke-Expression`/download-cradle markers, and the
   deobfuscated-length-to-command-line-length ratio.

**Tier.** These need PowerShell *script-block logging*, which is GPO-controlled and off by
default. So this becomes a third availability tier, measured exactly like the Sysmon T1-vs-T2
ablation: the question answered is "what would enabling script-block logging buy?" — a
deployment recommendation backed by a number, not an opinion.

**Honest expectation.** Only 799 EID 4104 events exist corpus-wide; the bulk is EID 800
(40,849) and 4103 (35,753), which are coarser. This may well produce a *small* gain. It is
worth measuring because command-line features are already the second most load-bearing family
and 73% of attacks are currently caught by nothing.

### 7b RESULT (measured 2026-09-18)

One spec bump: **98 → 113 features**, `feature_spec_sha256` 9225377386b5… → 685ea57b3ba8….
Tiers became cumulative (t1 ⊂ t2 ⊂ t3).

| Change | Δ PR-AUC | Verdict |
|---|---:|---|
| ~~**7b.2 burst/temporal features**~~ | ~~+0.0134~~ | **withdrawn in Phase 8 - see the correction above** |
| 7b.1 `hour_of_day` removed | included above | **kept** |
| 7b.3 PowerShell module logging (T3) | **−0.0008** | **null result** |
| (reference) Sysmon T2 over T1 | +0.0037 | within noise |

**7b.2 was reported as the win. It was not one** - see the Phase 8 correction above. The
recall @1% FPR move of 0.790 to 0.873 was real *on the corpus* and unreachable in
production, because every feature producing it was NaN on a live host.

The `hour_of_day` removal in 7b.1 does stand: it cost nothing and removed a feature with
PSI 8.67 that could only ever have transferred badly. The irony is precisely that 7b.2
then introduced five features with PSI 10-15, worse than the one 7b.1 had just removed,
in the same phase - and nothing measured that until the drift monitor was re-run against
the new spec.

**7b.3 is a null result, and is reported as one.** The individual features are strikingly
discriminative *where they exist*: on processes with PowerShell logging, `psh_has_url`,
`psh_has_crypto_loop` and `psh_host_app_encoded` are **0.000 on benign** and 0.32–0.35 on
malicious. The deobfuscated payload even exposes Empire's literal C2 URIs — `/admin/get.php`,
`/news.php`, `/login/process.php` — which are invisible in the base64 command line.

And yet the model gains nothing (−0.0008). The reason is redundancy, not weakness: only 45 of
1,716 processes have attributable PowerShell events, 32 of them malicious, and those 32 are
Empire agents that the command-line, parent and path features already classify confidently.
The evidence is *real* but *already covered*.

**The distinction worth keeping:** this is a null result for **detection**, not for
**investigation**. An analyst triaging one of those alerts gets the C2 endpoints and the
decryption routine handed to them. The T3 tier is therefore retained and wired, but the
recommended deployment tier stays **T1**, and the null result is stated in the model card.

**The leak audit now reads 0.0001.** Removing every seed-echoing feature costs essentially
nothing, down from 0.0088 at Phase 6. The model no longer leans on anything that restates the
labelling rule at all.

---

## 7c — Network features: fix or drop — RESULT: **keep, and here is why**

The corpus says drop them: removing all 13 gives PR-AUC 0.9434 vs 0.9415 with them, CIs fully
overlapping. But the corpus cannot fairly judge this, which the measurement shows directly:

| | processes with ≥1 connection | connections carrying TCP state |
|---|---:|---:|
| corpus (Sysmon EID 3) | 105/1716 (**6.1%**) | **0 / 3,778** |
| live (psutil) | 71/545 (**13.0%**) | **1,049 / 1,049** |

Production sees **2.1× the connection coverage and 100% of the TCP state that the corpus
entirely lacks** — `conn_listen_count` and `conn_established_count` are unconditionally NaN in
training. Deleting features on evidence from a source that systematically under-represents
them would be the wrong inference from a biased sample.

**Decision: keep, and record that the corpus cannot settle the question.** Re-evaluate once
enough live labelled data exists.

---

## Out of scope, deliberately

| Not doing | Why |
|---|---|
| Deep learning | 205 positives; also violates the stated CPU-only/no-PyTorch constraint |
| More Kaggle data | The constraint is labelled endpoint behaviour *in this schema*, not row count |
| Hyperparameter tuning | Untuned is currently defensible ("no tuning set, so no tuning leakage"). Revisit only if nested CV is added |
| ~~Re-attempting Component C~~ | **Done after all.** 7a's labels made it viable and it now ships behind three gates (`reports_ml/MODEL_CARDS.md` Card 3). This row was wrong when written. |
| Linux | Needs a labelled Linux corpus; honestly scoped out and stated in the reports |

---

## Method

Each step: measure → change → re-measure → record the delta → commit. Every step keeps the
suite green. Results — including null and negative ones — land in `docs/ML_PROGRESS.md` and
the `reports_ml/` evaluations, matching the existing format.

Ordering was deliberate: **7a before 7b**, because changing labels changes every number, and
measuring a feature change against stale labels would attribute the gain to the wrong cause.

---

## Phase 7 overall

| | Phase 6 | after 7a | after 7b | change |
|---|---:|---:|---:|---:|
| labelled positives | 185 | 205 | 205 | +11% |
| unseeded captures | 26 | 17 | 17 | −35% |
| features | 98 | 98 | 113 | |
| **Component B PR-AUC** | 0.922 | 0.934 | 0.942 (*) | +0.020 (*) |
| Component B recall @1% FPR | 71.9% | 80.5% | **87.3%** | **+15.4pp** |
| **union recall with rules** | 73.0% | 80.5% | **87.8%** | **+14.8pp** |
| attacks caught by neither | 50 | 40 | **25** | **−50%** |
| **leak-audit drop** | 0.0088 | 0.0073 | **0.0001** | ~0 |
| Component A PR-AUC | 0.557 | 0.571 | **0.588** | +0.031 |
| Component A precision@25 | 0.84 | 0.88 | **0.92** | +0.08 |

The number that matters most is the last-but-two: **the attacks caught by neither the rules
nor the model halved, from 50 to 25 of 205.** And the leak audit fell to ~0, so none of that
gain is the model rediscovering its own labelling rule.

Two of four changes were kept on their merits, one is a documented null result, and one was
kept *against* the corpus evidence because the corpus was shown to be a biased test. All four
are recorded either way.


**(*) Superseded.** Every figure in this table that includes 7b.2 is corpus-only, and was
re-measured in Phase 8 after three of the five burst features were deleted. The Phase 7a
label-recovery gains - 185 to 205 positives, 26 to 17 unseeded captures, and the leak audit
falling to ~0 - are unaffected and stand: they are a property of the labels, not of the
withdrawn features. `docs/ML_PHASE8_PLAN.md` carries the corrected numbers.