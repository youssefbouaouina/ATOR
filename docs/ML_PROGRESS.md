# ML_PROGRESS.md — live state file

> **Read this first when resuming.** It records what is *done and verified*, what is
> *next*, and the exact commands that prove it. Update it at every phase checkpoint.
> Design rationale lives in `docs/ML_ARCHITECTURE.md`; this file is state only.

**Last updated:** 2026-09-22
**Branch:** `ML`
**Interpreter:** `.venv/Scripts/python.exe` (Python 3.13), rebuilt locally on 2026-09-22 and
identical to `.venv-ml313/`. The scheduled weekly job uses `.venv`. Run tests as
`pytest tests`: from the repo root, pytest also collects the nested `ATOR/` clone.

---

## Current status

| Phase | State |
|---|---|
| **0 — Foundation** | ✅ **done & verified** |
| **1 — Data layer (migrate + OTRF ETL + labels)** | ✅ **done & verified** |
| **2 — Feature engineering + dataset assembly** | ✅ **done & verified** |
| **3 — Component A (anomaly) + eval harness** | ✅ **done & verified** |
| **4 — Engine + API integration** | ✅ **done & verified** |
| **5 — Components B & C, risk, drift** | ✅ **done & verified** |
| **6 — Dashboard, model cards, reports** | ✅ **done & verified** |
| **7 — Improvements (labels, features, tiers)** | ✅ done — **but 7b.2 was withdrawn in Phase 8**, see below |
| **8 — Train/serve correction** | ✅ **done & verified** |
| **9 — DFIR-only merge, dedupe fixes, security UI** | ✅ **done & verified** — `513 passed, 1 skipped, 0 failed` |
| **10 — Weekly MLOps pipeline** | ✅ **done & verified** — real two-week run on scratch copies; `635 passed, 1 skipped, 0 failed` |

**Status: all ten phases complete. Phase 10 is uncommitted until the user asks.** Phases 1–9 are pushed to `origin/ML`. youssef merged ML into
`main` on 2026-09-19; `ML` now contains all of his DFIR-only work (fast-forwarded to `main`,
see `docs/ML_MERGE_DFIR_NOTES.md`). The user pushes to `ML` only; youssef merges to `main`.

> **After the DFIR-only merge (2026-09-21), read `docs/ML_MERGE_DFIR_NOTES.md` first.** The
> merged branch was green while four real defects were live - two in the DFIR ingest (distinct
> same-second log events collapsed into one; a reused PID inherited the old process's parent
> and start time), two in the ML layer (a long-running suspicious process re-reported every
> sweep; Sysmon features vanishing after a process's first sweep). All four were reproduced
> through the real ingest endpoint and fixed with tests. The ML page was rewritten for
> security analysts as **Threat Hunting**.

> **Read this before trusting any Phase 7 number.** Phase 7b.2 reported five "burst" features
> as that phase's headline win (+0.0134 PR-AUC). The PSI drift monitor later showed all five
> were **NaN on every live host** — they were computed from a column that means "process start
> time" in the corpus and "when the agent swept" in production. Four of the five were deleted
> and the corpus metrics fell accordingly: Component A 0.588 → **0.549**, Component B 0.942 →
> **0.927**. **The lower numbers are the real ones**, and Component A's precision@25 — the
> metric matching how it is actually deployed — did not move at all (0.92 both sides). `docs/ML_PHASE8_PLAN.md` has the full
> argument; `docs/ML_PHASE7_PLAN.md` carries a correction banner.

### Run it
```bash
.venv/Scripts/python.exe -m server.app
```
This listens on all interfaces (`0.0.0.0:8000`), which enrolling endpoints need. A
`uvicorn ... --host 127.0.0.1` command, as this file used to suggest, is reachable from
this machine only, so remote enrollment fails with "cannot connect". Endpoints on the lab
network also need the inbound firewall rule in `docs/DEPLOYMENT.md`.

Then open <http://127.0.0.1:8000/ml> — the **Threat Hunting** tab (formerly ML Analytics).
"Run hunt now" scores the current database; "Refresh host risk" recomputes host scores. ML
findings also show on **Endpoints** (Risk column). The Investigation page's ML columns were
dropped in youssef's redesign.

### Deliverables to read
| File | What it is |
|---|---|
| `reports_ml/ML_EVALUATION.md` | Component A, with figures 01–05 |
| `reports_ml/ML_EVALUATION_TRIAGE.md` | Components B & C, risk, drift, figures 06–08 |
| `reports_ml/MODEL_CARDS.md` | Per-model intended use, metrics and limitations |
| `docs/ML_ARCHITECTURE.md` | Design decisions and corrections to `hazem2.md` |
| **`docs/ML_PHASE8_PLAN.md`** | **Read this one.** How a feature set that scored well in cross-validation turned out to be unusable in production, how it was caught, and what every headline number looks like once it was removed. |
| `docs/ML_PHASE7_PLAN.md` | Phase 7, carrying a correction banner for the part Phase 8 withdrew |
| **`docs/ML_MLOPS_PLAN.md`** | Phase 10: the weekly retrain → evaluate → shadow A/B → deploy → monitor pipeline, and why each safety decision was made |
| `docs/ML_MLOPS_RUNBOOK.md` | Operating it: install the schedule, read the result, what to do when |
| `reports_ml/burst_audit.json` · `drift_eval.json` | The measurements behind the Phase 8 decisions |

### Try the ML layer by hand
```bash
.venv-ml313/Scripts/python.exe -m server.app       # http://127.0.0.1:8000
curl http://127.0.0.1:8000/api/v1/ml/status
curl -X POST http://127.0.0.1:8000/api/v1/ml/score -H "Content-Type: application/json" -d "{}"
curl http://127.0.0.1:8000/api/v1/ml/anomalies?limit=10
```

### Inspect the data layer at any time
```bash
.venv-ml313/Scripts/python.exe -m ml.evaluation.audit_baseline      # facts + skew table
.venv-ml313/Scripts/python.exe -m ml.datasets.assemble              # dataset + split
.venv-ml313/Scripts/python.exe -m server.engine.ml_features --db ml_train.db
```

### Rebuild the data layer from scratch (≈6 min)
```bash
.venv-ml313/Scripts/python.exe -m ml.datasets.otrf fetch        # idempotent, ~85 MB
.venv-ml313/Scripts/python.exe -m ml.datasets.otrf_etl --rebuild
.venv-ml313/Scripts/python.exe -m ml.datasets.labels
```

---

## Verified facts (re-measure before trusting if the repo has moved on)

### Test baseline
```
.venv-ml313/Scripts/python.exe -m pytest tests/ -q
before Phase 0 => 45 passed, 1 failed, 1 skipped
after  Phase 0 => 55 passed, 0 failed, 1 skipped   <-- current expected baseline
```
The pre-existing failure was `tests/test_agent.py::test_live_collection_windows`, and it
turned out to be a **production bug, not a test bug** (details below). Phase 0 fixed it and
added 9 regression tests (`tests/test_agent_locale.py`).

On the 3.14 venv (`.venv-ml/`) there are **5 failures** because `yara-python` has no cp314
wheel — that venv is kept only as evidence of the version constraint. **Use 3.13.**

### Phase 0 production fix — locale-independent log collection
`agent/collectors/logs.py` classified "not allowed to read this log" by substring-matching
the **localised** PowerShell message against English words (`unauthorized`/`denied`/
`access`). On French Windows, non-elevated `Get-WinEvent -LogName Security` returns
*"Tentative d'exécution d'une opération non autorisée."* → matched nothing → a routine
permission failure was reported as a **fatal collector error**. Broken on every non-English
Windows host, which matters for a framework meant to be deployed on arbitrary endpoints.

Additionally, all **6** `subprocess.run(..., text=True)` calls in `agent/` decoded with the
locale codepage and raised `UnicodeDecodeError` on unmappable bytes (0x90 under cp1252).

Fixed by:
1. having the PowerShell wrapper emit `ATOR_ERR:<ExceptionTypeName>` — .NET exception type
   names are **not** translated, unlike `Exception.Message`;
2. mapping those type names to the collector's error contract
   (`_classify_ps_error`), distinguishing *access denied* / *log absent* / *real fault*;
3. a multi-language substring fallback (`_is_access_denied_text`) for the path where only a
   localised message is available;
4. pinning every `subprocess.run` to `encoding="utf-8", errors="replace"`.

Verified live: the real `Security` log call now returns the tolerated
`access_denied:Security` marker instead of a fatal French `ps:` error.

### Database reality — why external data is required
`ator_dfir.db`: 545 processes (538 real, from 2 single-snapshot hosts), 1049 connections,
1500 logs (no `sysmon` source), **6 detections**, **2 resource_samples**, **0 IOCs**,
**0 approvals**. No analyst labels exist anywhere. Full table in ML_ARCHITECTURE §1.3.

### External corpus — downloaded and measured
`data/external/otrf/` (gitignored, 85 MB, 155 zips, re-fetch with
`scripts/fetch_ml_datasets.py`). 786,141 events over 153 parseable captures.
**EID 1 (process create) = 1,704 only**, EID 3 = 4,150, EID 10 = 249,979,
EID 12/13/14 = 213,795. 105/153 captures have any EID 1. 9 ATT&CK tactics.

Consequence: the modelling unit is the **process** (~2.2k rows incl. local benign), made
information-dense by aggregating the other ~784k events onto it. Small-N discipline
(grouped CV + confidence intervals) is mandatory — see ML_ARCHITECTURE §5.5, §7.

---

## Phase 1 results (measured 2026-09-16)

`ml_train.db` — 400 MB, gitignored, rebuilt by the commands above.

| Table | Rows |
|---|---:|
| `hosts` (synthetic, one per corpus hostname, `is_active=0`) | 21 |
| `raw_processes` | **1,716** |
| `raw_connections` | 3,778 |
| `raw_logs` | 463,480 |
| `raw_persistence` | 10,993 |
| `corpus_lineage` | 1,716 (361 reconstructed) |

### Labels
**185 malicious / 1,531 benign — positive rate 10.8%**, over 115 capture groups.

By tactic: defense_evasion 75, lateral_movement 44, credential_access 38,
privilege_escalation 8, persistence 8, discovery 7, execution 3, other 2.

Propagation depth: 167 at depth 0 (direct signature match), 17 at depth 1, 1 at depth 2 —
so inheritance adds ~10%, not a runaway cascade. 26 of the 185 positives are reconstructed
parents. 26 captures still yield no seed; no capture with ≥10 processes is entirely
malicious, i.e. the benign control class survived.

**Verdict on Component B:** viable but genuinely small-N. 185 positives across 115 groups
means grouped CV folds hold ~37 positives each. Metrics must carry confidence intervals, and
Component C (tactic, 8 classes) is only credible for the top 3 tactics — the rest have <10
examples. This will be stated, not smoothed over.

### Three findings that changed the design
1. **Parent reconstruction was essential, not cosmetic.** Empire/Covenant run in-memory, so
   the attacker process often has no `ProcessCreate` event inside the capture window — it is
   visible only as a child's `ParentCommandLine`. Before reconstruction, *every* Empire
   Mimikatz capture was labelled entirely benign (88 positives). Reconstructing those parents
   from `ParentProcessGuid`/`ParentImage`/`ParentCommandLine` took it to 148, and the extra
   technique-mechanism signatures to 185. A long-running agent process is exactly what a
   psutil snapshot *would* see, so this makes the corpus more production-like, not less.
2. **The sensor profile is the key fidelity control.** `scripts/sysmon-config.xml` enables
   only EIDs 1, 3, 7, 8, 11, 13, 22. The corpus's 249,979 EID 10 (ProcessAccess/LSASS) and
   148,633 EID 12 events — 51% of its telemetry — are **not collected in production**.
   Training on them would be textbook train/serve skew. They are kept under
   `source='sysmon_extended'` so the value of enabling them can be *measured* and turned into
   a concrete recommendation. Applying the config's exclusions also cut the training DB from
   a projected 1.2 GB to 400 MB (EID 7: 1,813 → 13 events in the smoke set).
3. **`ExecutionProcessID` is a trap.** 413 of 1,355 `ProcessCreate` events carry no
   `ProcessId`. `ExecutionProcessID` looks like the answer but is the pid of the process that
   *wrote* the event (Sysmon's service, constant per capture). Using it would have silently
   corrupted every row. The pid is instead recovered exactly from children's
   `ParentProcessId` (413 → 337 NULL); the rest stay NULL rather than invented.

### Known limitation carried into Phase 2
Only **105 of 1,716** processes join to ≥1 connection, so network features will be sparse.
Rejected fix: synthesising processes from EID 3 events. Those carry `Image` but **no
`CommandLine`**, so they would inject a large block of rows with systematically missing
cmdline — and since cmdline features are the strongest signal, the model could learn
"cmdline missing ⇒ benign", which is a pure corpus artefact. Sparse-but-honest beats
dense-but-leaky.

## Phase 2 results (measured 2026-09-16)

`server/engine/ml_features.py` — **98 features (79 T1 / 19 T2)**,
`feature_spec_sha256 = 9225377386b539d6e1ea89c7ae7e37ec0c25a41fe405a810feefd4b10c47637c`.

### The no-skew claim, measured
The same code produces **identical feature columns** on `ml_train.db` (1,716 rows) and the
live `ator_dfir.db` (545 rows). `ml/evaluation/audit_baseline.py` prints the per-feature
missingness gap; 17 of 98 features exceed the 40pp review threshold and **all 17 are T2
(Sysmon)**, at 0% missing in the corpus and 100% live — because Sysmon is not installed on
the current endpoints. That is expected, and is exactly what the T1 model exists for. **No
T1 feature is flagged.**

### Finding: the agent cannot read 27% of command lines
The largest T1 gap is 27.3pp and has a single root cause: **149 of 545 live processes have
no `cmdline` at all**, while the corpus has it for 100% of rows (Sysmon records command
lines regardless of ACLs; psutil cannot when unelevated).

The affected processes are `svchost.exe` (79), `System`, `Registry`, `csrss.exe`,
`LsaIso.exe`, `MemCompression`, `fontdrvhost.exe` — i.e. **precisely the names attackers
masquerade as**. Two consequences:
1. **Operational recommendation:** run the agent elevated, or command-line-based detection is
   blind on a quarter of the process table, concentrated on the highest-value names.
2. **Modelling consequence:** a corpus-only model would never see `cmdline_present=0` in
   training and would meet it for the first time in production. This is why
   `ml/datasets/assemble.py` mixes the local rows into training.

### Dataset
```
2,254 rows = 1,716 corpus + 538 local benign | 185 malicious (8.21%) | 107 CV groups
held-out split (seed 42, whole groups): train 1,546 (141 pos) / test 708 (44 pos)
group overlap: 0        cmdline present: corpus 100.0% | local 72.5%
```
The 7 demo-fixture rows (`client_id LIKE 'demo-%'` — planted mimikatz / encoded PowerShell /
`curl | sh` from `make_demo_dataset.py`) are **excluded**; labelling them benign would poison
the negative class. Guarded by `tests/test_ml_dataset.py::TestDemoFixtureExclusion`.

Local rows are benign **by assumption** (developer workstation, not known-compromised) and
tagged `source='local'` so the assumption can be ablated. They come from one physical machine
(live hosts 5 and 7 are the same box enrolled twice), so local benign diversity is low.

### Finding: the held-out test set covers only 3 of 8 tactics
Test-set positives: defense_evasion 29, lateral_movement 10, credential_access 5. The other
five tactics have **zero** test examples. So **Component C must be evaluated by
cross-validation, not by this holdout**, and is only credible for the top 3 tactics. Measured,
not guessed.

### Design points worth keeping
* **Missing is NaN, never 0.** `sysmon_available` / `conn_available` / `conn_status_available`
  / `cmdline_present` separate "nothing happened" from "we could not see". `conn_listen_count`
  is NaN in the corpus because Sysmon EID 3 has no TCP state, while psutil supplies it.
* **Fold-safe statistics.** The three rarity features need corpus frequencies, so
  `extract_process_frame` (pure read) is split from `fit_stats` (train folds only) and
  `transform`. Fitting on all rows then cross-validating would leak; guarded by
  `TestFoldSafeStatistics`.
* **Label side-channel discipline.** `ProcessGuid`/`corpus_*` are label-only. Production
  `raw_processes` has no GUID column, so any feature using one would be uncomputable at
  inference; `TestProductionSchemaDiscipline` greps the module to enforce it.
* **Labels attach by primary key.** The ETL records `corpus_lineage.raw_process_id`
  (1,716/1,716 linked, 0 dangling, 0 duplicated) instead of joining on `(capture, pid)` —
  337 corpus processes have a NULL pid and pids recur within a capture.
* **`nan` is truthy in Python**, which silently broke the first implementation
  (`float(len(nan))`). `_col()` normalises every missing marker to `None`;
  `TestNanTruthinessRegression` keeps it fixed.

## Phase 3 results (measured 2026-09-16)

Full write-up with figures: **`reports_ml/ML_EVALUATION.md`**. Raw numbers:
`reports_ml/anomaly_eval.json`. Models: `models/anomaly_t1.joblib`, `models/anomaly_t2.joblib`.

### Headline (corpus rows only — 1,716 rows, 185 positives, 10.8% base rate)
| Model | PR-AUC | 95% CI | ROC | R@1%FPR | P@25 |
|---|---:|---|---:|---:|---:|
| chance | 0.108 | 0.074–0.174 | 0.504 | 0.5% | 0.04 |
| Sigma rules (deployed) | 0.286 | — | 0.600 | n/a | n/a |
| best single feature | 0.300 | 0.229–0.385 | 0.814 | 69.2% | 0.12 |
| **IsolationForest T1** | **0.557** | **0.455–0.697** | 0.910 | 22.2% | **0.84** |
| IsolationForest T2 | 0.502 | 0.414–0.632 | 0.909 | 16.8% | 0.64 |

Model CI does **not** overlap the best baseline's → the improvement is real. Sigma rules at
their own operating point: **precision 1.000, recall 0.200** (TP 37 / FP 0 / FN 148).

### Six findings that shaped the conclusions
1. **Ranking must be scored on corpus rows only.** All positives are corpus; local rows are
   100% benign; `sysmon_available` separates the sources perfectly (1.000 vs 0.000). Scoring
   across both credited the model for discarding 538 trivially-identifiable negatives.
2. **Binary scorers must not be given threshold metrics.** Sigma originally reported
   "recall 1.000 @1% FPR" — an artefact: all benign score 0, so the 99th-percentile threshold
   is 0 and `≥0` matches everything (actual FPR 100%). `core_metrics` now detects binary
   scorers and returns NaN, and always reports `actual_fpr_at_*`.
3. **`sibling_count` is a labelling artefact** (malicious median 0 siblings vs benign 4–26;
   ROC-AUC 0.866 alone) — lineage labelling creates small subtrees by construction. Removing
   the tree family costs the *model* 0.014 but the *single-feature baseline* 0.110, so the
   artefact inflated the baseline, not the model. **The conclusion survives.**
4. **Sysmon features hurt this component** (−0.056 PR-AUC): 19 extra low-variance columns
   dilute IsolationForest's random-split isolation. Deploy the T1 feature set here. This is
   not an argument against Sysmon generally — it is what gives the rules their coverage.
5. **Corpus-calibrated thresholds under-state real false positives ~6×.** A 1% corpus-FPR
   threshold yields a 6.5% FP rate on genuine local benign data. Thresholds must be calibrated
   on the target estate's own baseline — which the percentile score mapping does automatically
   on re-fit.
6. **Best ranking ≠ lowest false positives.** T1 ranks best (0.557) but is worst in practice
   (17.6 alerts per 270-process sweep at 1%); T2-no-tree ranks 0.488 with 7.0, and 0.0 at
   0.1%. Selecting on PR-AUC alone would have shipped the noisier model.

### The verdict, stated plainly
Component A is a **ranked triage queue, not an alerting mechanism**. Precision@25 = 0.84 (21
of the top 25 are real attacks) is genuinely useful; 22% recall at 1% FPR is not an alarm.
Against the deployed rules it adds **13 attacks they miss** (union recall 20% → 27%) for 16
extra false positives — real but modest, supporting a separate review lane. **135 of 185
attacks (73%) are caught by neither**, which argues for more detection engineering rather
than more ML.

Per-fold PR-AUC sd = 0.141 on ~37 positives per fold; all intervals are group bootstraps over
captures. The T1-vs-T2 gap sits inside fold noise and is a weak preference, not a finding.

## Phase 4 results (measured 2026-09-16)

ML now runs inside `run_engine()` and is exposed over the API.

| Piece | What it does |
|---|---|
| `server/engine/ml_registry.py` | Lazy-imports the optional ML stack, loads/caches joblib artefacts by mtime, **refuses** any model whose `feature_spec_sha256` differs from the running spec, auto-selects T1/T2 from Sysmon availability, registers models in `ml_models` |
| `server/engine/ml_integration.py` | Scores processes, emits `rule_type='ml_anomaly'` detections with `anomaly_score` + `ml_explanation`, dedupes across runs |
| `server/engine/__init__.py` | Calls ML **after** the deterministic detectors, inside a broad `try/except`; returns `ml_detections` / `ml_error` |
| `server/api.py` | `GET /api/v1/ml/status`, `GET /api/v1/ml/models`, `POST /api/v1/ml/score`, `GET /api/v1/ml/anomalies` |

### The design follows the evaluation, not the original proposal
Component A is a **ranked triage queue**, so scoring emits the **top-K most anomalous
processes per host** (`ATOR_ML_TOP_K`, default 10) rather than everything over a threshold.
That bounds analyst workload by construction instead of trusting a threshold to generalise —
which §5 of the evaluation showed it does not (corpus-calibrated thresholds under-state real
false positives ~6×). ML severity never returns `critical`: a statistical outlier must not
outrank a rule that knows what it matched.

### Verified on real data
Scoring the live `ator_dfir.db` (T1 auto-selected — no Sysmon) produced 16 findings across
2 hosts, idempotent on re-run. All 7 dashboard pages, the timeline, SOC chain, ATT&CK
Navigator export and the PDF/JSON/STIX reports still return 200 with ML rows present.

A representative true find: **`btweb.exe` scored 1.000**, driven by `conn_listen_count` /
`conn_external_ratio` / `cmdline_upper_ratio` — a BitTorrent client, which no Sigma rule
covers but which is genuinely notable on a managed endpoint. That is the intended use of
this component.

### Regression caught and fixed: `detections.summary` is JSON
ML detections initially wrote a prose sentence into `summary`. `engine/timeline.py` calls
`json.loads()` on that column (the deterministic detectors write JSON via
`sigma_runner.summarize_hit`), so `/api/v1/timeline` returned **500** for every host with an
ML detection — a core dashboard endpoint broken by a new detector not honouring an
undocumented contract. Fixed on both sides: ML summaries are now JSON carrying the standard
artefact keys plus `ml_*` context, and `timeline.py` degrades to `{"text": ...}` instead of
raising. Guarded by `tests/test_ml_integration.py::TestSummaryContract`.

### Isolation guarantees (each has a test)
Missing dependency → `ml_detections: 0`, `ml_error: None` (absence is not an error) ·
exception during scoring → `ml_error` set, rules unaffected · corrupt artefact → refused ·
feature-spec mismatch → refused with a retrain hint · `total_new_detections` still counts
**only** rule detections, so existing dashboards are not silently inflated.

## Phase 5 results (measured 2026-09-16)

Full write-up: **`reports_ml/ML_EVALUATION_TRIAGE.md`**. Raw numbers: `reports_ml/triage_eval.json`,
`reports_ml/tactic_eval.json`. Figures 06–08 in `reports_ml/figures/`.

| Component | Verdict |
|---|---|
| **B — supervised triage** | **Ships.** PR-AUC **0.922** (CI 0.878–0.963) vs 0.286 for the deployed rules; Precision@25 = **1.00** |
| **C — tactic suggestion** | **Does not ship.** 50.8% accuracy vs a 40.5% majority baseline — measured, found insufficient |
| Host risk score | Ships. Deterministic and explainable |
| Drift monitor (PSI) | Ships — and found **32 of 79 features shifted** between train and live |

### Component B: supervision is worth a lot
On identical rows and folds, PR-AUC goes **0.486 (Component A) → 0.922 (Component B)**.
Complementarity with the rules is transformed: Component A recovered 13 of the 148 attacks the
rules miss; **Component B recovers 98** (union recall 20% → **73%**) for the same 16 extra
false positives.

### The leak audit — the most important check in the project
Labels are generated from command-line seed signatures, and several features restate them, so
the model could have scored 0.92 by rediscovering my own labelling rule. Measured:

| Feature set | Features | PR-AUC |
|---|---:|---:|
| all T1 | 79 | 0.922 |
| − seed-echo | 69 | 0.913 |
| − seed-echo − tree | 65 | 0.900 |
| − seed-echo − tree − all cmdline | 53 | 0.876 |
| − seed-echo − tree − cmdline − rarity | 50 | **0.868** |

Removing every seed-echoing feature costs **0.009**. Stripping 29 of 79 features still leaves
0.868. **The result is not circular** — it rests on path, parent, account, connection and
timing behaviour.

### A finding against my own design: calibration made calibration worse
`CalibratedClassifierCV` (Platt) gave ECE **0.0174**; the *uncalibrated* model gave **0.0085**
(Brier 0.0237 vs 0.0257). HistGradientBoosting optimises log-loss and is already near-calibrated;
Platt scaling over 3 inner folds on 185 positives adds variance without removing bias.
ML_ARCHITECTURE §7.2 declared calibration mandatory — measuring it showed the *wrapper* was the
wrong instrument at this data size. **Ship uncalibrated**, keep reporting Brier/ECE.

### Component C: a deliberate negative result
Accuracy 0.508 vs 0.405 majority; macro F1 0.478. Confidence thresholding barely helps (59.5%
at 45% coverage). The dominant error is `defense_evasion` ↔ `credential_access`, which is not
really model error — **ATT&CK tactics are not mutually exclusive**, and the corpus assigns one
tactic per capture by directory. Single-label classification is imposed by the label format,
not the phenomenon. The code is complete and tested but **not wired into the engine and not
shown in the UI**; a hint wrong 4 times in 10 spends analyst attention and erodes trust.

### Drift found two real problems on first run
* **`hour_of_day` PSI 8.67** — it encodes *when the 2020 lab captures ran*, not behaviour.
  Recommended for removal at the next retrain (changes `feature_spec_sha256`, so it is a
  deliberate follow-up rather than a silent edit).
* **`cmdline_*` PSI ~4.0**, missingness 0% → 27.3% — the unelevated-agent problem, now an
  alert rather than a footnote.

### New in this phase
`server/engine/`: `ml_triage.py`, `ml_tactic.py`, `ml_risk.py`, `ml_drift.py` ·
`ml/training/`: `train_triage.py`, `train_tactic.py` ·
`scripts/`: `retrain_ml.py` (drift check + retrain, exit 2 on drift for cron), `update_risk_scores.py` ·
API: `/api/v1/ml/host-risk`, `/api/v1/ml/host-risk/{id}`, `/api/v1/ml/host-risk/recompute`,
`/api/v1/ml/drift` · `run_engine()` now also returns `ml_confidence_scored` and `ml_host_risk`.

## Phase 6 results (measured 2026-09-16)

### Dashboard
New **ML Analytics** page (`/ml`, `server/templates/ml_analytics.html`) with four panels:
models (status + quality + feature-spec hash), host risk, the anomaly triage queue with
per-finding explanations, and feature drift. Two action buttons ("Score now", "Recompute
risk") call the API directly.

Existing pages extended rather than replaced:
* **Investigation** — `Src` badge (ML vs rule) and a `Conf` column showing the calibrated
  confidence, with `—` for unscored so NULL never reads as "confidently benign".
* **Endpoints** — `Risk` tier badge, and hosts now ordered worst-first.

The Tactic model is displayed as **"not deployed"**, not "active" — showing it as active
would imply it is in use when Phase 5 concluded it must not be.

### Regression protection
`tests/test_ml_ui.py` (32 tests) renders every pre-existing page **with and without** ML rows
present, and re-checks the JSON/STIX/PDF exports, the timeline API and `/api/v1/detections`.
This exists because Phase 4 broke `/api/v1/timeline` exactly this way.

### Model cards
`reports_ml/MODEL_CARDS.md` — one card per model: intended use, training data, measured
performance, and an explicit **out-of-scope** section. Component C's card records why it is
not deployed.

## Phase 7 results (measured 2026-09-18)

> **(*) Superseded by Phase 8.** Every figure in this section that involves the 7b.2 burst
> features was re-measured after four of them were deleted for being unavailable in
> production. Current values: Component A **0.549** / precision@25 **0.92**, Component B
> **0.927** / recall @1% FPR **82.4%**. The 7a label-recovery results (185 → 205 positives,
> 26 → 17 unseeded captures) are unaffected and stand.

Plan and full detail: **`docs/ML_PHASE7_PLAN.md`**. Phases 0-6 were committed and pushed to
`origin/ML` first (commits `1e3669d`..`2106b2d`), so Phase 7 is measurable against a fixed
baseline.

| | Phase 6 | after 7a | after 7b | change |
|---|---:|---:|---:|---:|
| labelled positives | 185 | 205 | 205 | +11% |
| unseeded captures | 26 | 17 | 17 | −35% |
| features | 98 | 98 | 113 | |
| **Component B PR-AUC** | 0.922 | 0.934 | 0.942 [0.905-0.974] (*) | +0.020 (*) |
| Component B recall @1% FPR | 71.9% | 80.5% | **87.3%** | **+15.4pp** |
| **union recall with rules** | 73.0% | 80.5% | **87.8%** | **+14.8pp** |
| attacks caught by neither | 50 | 40 | **25** | **−50%** |
| **leak-audit drop** | 0.0088 | 0.0073 | **0.0001** | ~0 |
| Component A PR-AUC | 0.557 | 0.571 | **0.588** | +0.031 |
| Component A precision@25 | 0.84 | 0.88 | **0.92** | +0.08 |

**Attacks caught by neither rules nor model halved, 50 → 25 of 205**, and the leak audit fell
to ~0 — so none of that gain is the model rediscovering its own labelling rule.

### What was changed, and what each bought
* **7a - label quality.** Read all 26 captures that produced no seed. Nine had an identifiable
  mechanism and got a specific signature; the other **17 are genuinely invisible in
  process-creation telemetry** (in-memory injection, in-memory PowerView, DCERPC service
  manipulation, Meterpreter mic capture). 185 → 205 positives.
* **7b.1 `hour_of_day` removed** - PSI 8.67; it encoded when the 2020 lab captures ran.
* **7b.2 burst/temporal features added** (+0.0134, recall@1%FPR 0.790 → 0.873). These had been
  deferred in Phase 2 on the mistaken belief that all data was single-snapshot; corpus captures
  actually span 1.8-6.3 minutes and the agent sweeps every 60 s.
* **7b.3 PowerShell module logging (new T3 tier)** - **null result, −0.0008**, reported as one.
* **7c network features** - **kept against the corpus evidence**, because the corpus was shown
  to be a biased test of them.

### Two results worth remembering
**PowerShell T3 is a null result for detection but not for investigation.** Where the features
exist they are strikingly clean - `psh_has_url`, `psh_has_crypto_loop` and
`psh_host_app_encoded` are **0.000 on benign**, 0.32-0.35 on malicious - and the deobfuscated
payload exposes Empire's literal C2 URIs (`/admin/get.php`, `/news.php`,
`/login/process.php`), invisible in the base64 command line. But only 45 of 1,716 processes
have attributable PowerShell events, 32 malicious, and those 32 are already classified
confidently by command-line/parent/path features. Real evidence, already covered.

**The corpus cannot judge the network features.** Live psutil gives 13.0% connection coverage
and 100% TCP state; the Sysmon-derived corpus gives 6.1% and **zero** TCP state
(`conn_listen_count`/`conn_established_count` are unconditionally NaN in training). Deleting
features on that evidence would be inferring from a biased sample.

### Tier system is now cumulative (t1 ⊂ t2 ⊂ t3)
`t1` psutil only (83) · `t2` + Sysmon (102) · `t3` + PowerShell module logging (113).
Each tier is an ablation that answers a deployment question with a number:
Sysmon +0.0037, PowerShell −0.0008 — **both within noise, so T1 remains the recommendation.**

## Phase 10 results (measured 2026-09-22)

A weekly MLOps pipeline, `python -m ml.mlops run`, scheduled by Windows Task Scheduler
(`scripts/install_mlops_schedule.ps1`) or a systemd timer. Design: `docs/ML_MLOPS_PLAN.md`;
operation: `docs/ML_MLOPS_RUNBOOK.md`.

### Verified end to end on real data (scratch copies of the live DB and models)

| Run | What happened |
|---|---|
| week 1 (10 min) | ETL full rebuild 80 s → 115 captures, 1,716 processes, 205 attack labels · anomaly 253 s, triage 175 s, tactic 11 s · triage and tactic **byte-identical** to the hand-trained models → adopted for provenance, no trial · anomaly passed every offline gate (PR-AUC 0.558 vs 0.549; unseen-live alert rate 4.84% = champion) → shadow trial started · week-over-week drift flagged the newly enrolled host (exit 2, correct) |
| the week | three real engine passes with the trial running: 2,565 processes scored by both models, 0 errors, 27 vs 27 would-be leads (26 in common), 175 ms vs 203 ms per pass |
| week 2 (5 min) | trial **promoted**, smoke test passed against the file the server loads · triage/tactic **unchanged** (fingerprints match: no churn) · anomaly retrained on the newly admitted week, gates passed, trial 2 started |
| rollback | `python -m ml.mlops rollback anomaly` restored the previous model; smoke test ok |
| dashboard | *Detection model updates* panel, and verdict buttons on each lead, clicked in the browser |

### Three things the real run caught that the tests had not

1. **Excluding every unreviewed ML lead from the benign baseline is a self-reinforcing loop.**
   The first candidate flagged **9.35%** of unseen live processes vs **4.84%** for the model in
   service; gate A4 rejected it. Measured on identical rows: re-admitting leads the triage
   model rates < 50% restores 4.84% (policy shipped); only the 5 leads rated 81–86% stay out.
   Without this, every weekly update would have been rejected until the model went stale.
2. **Recall at the 0.99 floor moves ~3 points from benign-data noise alone** (6 of 205 attacks),
   so the A3 margin went from 0.03 to 0.05. A poisoned baseline drops it far more (~1.0 → ~0.17,
   `test_poisoned_challenger_is_blocked`).
3. **Corpus-vs-live drift is permanent** (25 of 80 features, every week), so alerting on it
   would teach operators to ignore the result code. Drift now compares this week against the
   estate's own earlier weeks.

Also found and fixed on the way: pandas stores a missing start time as NaN, which is truthy
(crashed the lineage walk); an unreviewed ML lead on `System` cascaded exclusions over the OS
tree (lineage now follows only rule hits and confirmed threats, never OS roots); model
"equivalence" by comparing scores is unsound (percentiles saturate), so it is decided by
model identity, where sklearn trees pickle their padding bytes and fail safe; a run killed
mid-flight would have left the dashboard saying "Updating now" forever.

### New files
`ml/mlops/` (config, lock, store, data, train, scoring, evaluate, trial, monitor, report,
pipeline, `__main__`, `approved_captures.json`) · `server/engine/ml_shadow.py` (in-engine shadow
scoring) · `server/engine/ml_ops.py` (dashboard view) · `scripts/install_mlops_schedule.ps1`,
`mlops_weekly.cmd`, `ator-mlops.service`, `ator-mlops.timer` · six test files
`tests/test_mlops_*.py` (106 tests). Schema: five additive tables
(`ml_pipeline_runs`, `ml_shadow_trials`, `ml_shadow_observations`, `ml_shadow_flags`,
`ml_feedback`). API: `POST /api/v1/ml/feedback`, `GET /api/v1/ml/ops`. Trainers gained
`--models-dir`; `assemble.load` honours a snapshot's `ml_training_exclusions`.

## Internship subject (source of truth for scope)

From `Internship_Subject_DFIR.pdf` (the first copy sent was 0 bytes; read from the re-sent
`DOC-20260721-WA0000..pdf`, 3 pages):

- **Title:** Design and Implementation of a Lightweight DFIR and Threat Hunting Framework
  for Endpoint Investigation.
- **Objectives:** collect endpoint artefacts (Windows + Linux) · detect IOCs with YARA and
  Sigma · map to MITRE ATT&CK · automate investigation reports · simulate attacks to
  validate · **develop proactive threat-hunting methods**.
- **Scope:** processes, network connections, scheduled tasks/startup, registry persistence,
  event logs · YARA + Sigma + IOC correlation · ATT&CK tagging and attack-chain
  reconstruction · reporting dashboard.
- **Tools:** Python, Sysmon, YARA, Sigma, MITRE ATT&CK, SQLite + FastAPI.
- **Deliverables:** working prototype · documented rulesets · ATT&CK-mapped incident report
  · technical report on methodology and findings · final defence presentation.

**How the ML layer earns its place:** the deterministic engine answers *"does this match a
known rule?"*. The subject also asks for *proactive threat hunting* — finding what no rule
describes. That is precisely unsupervised anomaly detection (Component A), with supervised
triage (B) to keep the alert volume actionable and tactic suggestion (C) to keep ML
findings ATT&CK-mapped like every other finding. The ML section is an extension of the
stated subject, not a detour from it.

---

## Decisions already taken (do not relitigate)

1. **Python 3.13**, `.venv-ml313/`. 3.14 loses `yara-python`.
2. **Train on data converted into the ATOR schema**, never on raw Sysmon JSON — kills
   train/serve skew by construction. (ML_ARCHITECTURE §5.1)
3. **Reuse `detections.rule_type`**; do **not** add a `source` column. (§2)
4. **Process-lineage labelling**, not capture-level. (§5.3)
5. **Feature tiers T1 (psutil, always) / T2 (Sysmon, optional)**; ablation is a headline
   result. (§5.4)
6. **OTRF Security-Datasets over Kaggle** — no credentials needed, real Sysmon telemetry,
   ATT&CK-labelled, and it maps onto this project's own schema. Kaggle remains available
   if a `kaggle.json` token is supplied.
7. `ml_resource_rollup` table, because 72 h pruning would otherwise destroy any resource
   baseline longer than 3 days. (§6.3)

---

## Open items / risks

| Item | Status |
|---|---|
| Malicious-class size after lineage labelling | **Unknown until Phase 1.** If <100, Component B degrades to a reported-with-CIs result or is re-scoped. Decide with measured numbers, not optimism. |
| `.venv/` tracked in git (broken, huge) | Flagged in ML_ARCHITECTURE §10. Needs a team decision; not changed unilaterally. |
| `ATOR/` duplicate clone nested in the tree | gitignored, not deleted. Owner's call. |
| Linux coverage | OTRF corpus used here is Windows-only. Subject covers Linux too; local Linux data is 2 demo rows. Linux ML is honestly scoped as **not validated**. |
| `resource_samples` features | Deferred to Phase 5, unvalidated until rollup data accumulates. |
| Kaggle token | Absent. Not required by the current plan. |
| **Burst features are shifted in the tail** | `procs_within_5s` corpus p75 15 vs live 93; `seconds_since_parent_start` corpus p75 13 s vs live 7,203 s. Centres agree (mean process density 47.4 corpus / 53.1 live) and they ship on that basis. **Bounding or log-scaling them is the obvious next step** — it would not affect Component B (tree-based, invariant to monotone transforms) but would affect Component A. Not done: it is another spec bump and full retrain. |
| **Component A is over-dimensioned** | Five of seven feature families *improve* the T2 model when removed (`ML_EVALUATION.md` §6). At 205 positives, feature selection for Component A specifically is now better value than any new feature. |
| **Component A's margin over the best baseline is marginal** | Model CI 0.414–0.665 vs best-single-feature 0.253–0.413 — non-overlapping by 0.001. Its case rests on precision@25 (0.84 vs 0.28), which matches how it is deployed. Say so rather than quoting PR-AUC. |
| **Weekly pipeline needs the server running for trials** | A candidate anomaly model collects evidence only while the server scores live traffic (24 active hours, 200 processes). On a lab laptop that is off most of the week, trials extend week to week and raise *attention* after 3. `mlops/config.json` can lower the bar for a lab. |
| **Dashboard verdicts are unauthenticated** | Anyone reaching port 8000 can mark a lead benign, which feeds the retrain. Bounded (rule hits override, 200-row cap, listed in each report, confirmed-threat gate) but only authentication removes it. `docs/LIMITATIONS.md`. |
| **Live data predating Phase 8 has no `create_time_utc`** | The column is populated going forward only; the two existing collections in `ator_dfir.db` have NULL, so the burst features are NaN for them until the agent runs again. Nothing to fix — it is what a nullable additive column means. |

---

## Changelog

- **2026-09-22** — **Phase 10: weekly MLOps pipeline.** Retrieve (OTRF fetch, checksum-pinned
  admission: new captures wait for review because labels need per-tool signatures), snapshot
  the live DB, exclude live rows that must not be assumed benign (cooling-off, rule hits and
  their lineage, incident windows, likely-malicious ML leads), staged ETL with data validation
  and atomic swap, fingerprinted retraining into an immutable model store, offline gates
  against the no-ML baselines and against the deployed model on identical rows, one-week
  in-engine shadow trial (champion/challenger, not a traffic split: safer and paired),
  atomic promotion with canary smoke test and automatic rollback, drift/outcome/health
  monitoring, run reports, kill switches (pause, freeze), analyst verdicts on leads feeding
  the next retrain, and a *Detection model updates* panel. Real two-week run verified on
  scratch copies; three policy corrections came from it (see Phase 10 results).
  Suite: `635 passed, 1 skipped, 0 failed`.

- **2026-09-21** — **Phase 9: DFIR-only merge, dedupe fixes, security-oriented UI.**
  `ML` fast-forwarded to `main` (= DFIR-only + ML, with youssef's conflict resolutions),
  after backing up and restoring the 26 runtime files the merge untracks (live DB hash
  unchanged). Post-merge suite green (449 passed) with four live defects, each reproduced
  through `/api/v1/ingest` and fixed: log dedupe key v2 adds a payload hash (distinct events
  in one second were collapsed - agent timestamps have 1 s resolution); process dedupe key v2
  adds `create_time_utc` (a reused PID inherited the old instance's parent and start time),
  with an in-place v1 -> v2 index upgrade at startup; ML findings keyed on process identity
  with youssef's `hit_count`/`last_seen_utc` recurrence convention (a long-running process
  was re-reported every sweep), counting a sighting only when it is newer than the last
  (found by clicking "Run hunt now" repeatedly); T1 served by default because insert-once
  logs + moving process rows served T2 models `sysmon_available = 0` from a process's second
  sweep on. Also: pd.NA written as the literal "<NA>" into finding evidence (Phase 8 Int64
  side effect); `ATOR/` re-ignored. The ML page became **Threat Hunting**:
  `server/engine/ml_vocabulary.py` translates every model output into analyst language
  (priority P1-P4 from threat likelihood, rarity, ATT&CK IDs, indicator sentences with
  direction and strength, engine lab results generated from artefact metrics, data health),
  with a click-through evidence panel per lead; the data-science view is kept, collapsed.
  `explain()` now records deviation direction. New tests: `test_dedupe_identity.py`,
  `test_ml_vocabulary.py` (including a guard that fails the build when a feature has no
  analyst-facing label). Open items: join Sysmon events across collections so T2 can be
  default again; consider excluding OS pseudo-processes (PID 0) from scoring.

- **2026-09-18 (2)** — **Phase 8: train/serve correction.** The PSI drift monitor, re-run
  after the Phase 7 spec change, found that all five Phase 7b.2 burst features were NaN on
  every live row — the four worst-drifting features in the whole T1 set. Cause: they were
  computed from `raw_processes.collected_at_utc`, a per-process launch time in the corpus and
  a single per-sweep timestamp in production. Fixed properly rather than patched:
  `create_time_utc` added to the schema (additive, nullable), collected by the agent from
  psutil, populated by the ETL for corpus rows, and read by the feature layer with **no
  fallback** — a NULL start time yields NaN, because a silent fallback is how the bug worked.
  Four of the five features were then deleted on measurement (`collection_has_timespan`
  contributed exactly 0.0000; `seconds_since_collection_start` was a lab-capture artefact of
  the `hour_of_day` class; `proc_spawn_rate_per_min` was collection-constant and
  span-dependent; `procs_within_60s` was added in this phase and removed in it after
  measuring +0.0154 PR-AUC when dropped). Corpus metrics fell — A 0.588 → 0.549, B 0.942 →
  0.927, C 57.1% → 52.2% — which is what removing an artefact looks like. Three things moved
  the other way and are why the cleanup is credible: the leak audit went **negative**
  (−0.0032, from 0.0088 at Phase 6), the corpus-to-live threshold transfer improved from ~10×
  to ~7.8×, and Component C's gated precision rose to 79.7%. Component A's **precision@25 did
  not move** (0.92 both sides). A long-standing finding also reversed: "Sysmon features hurt
  the anomaly model" was −0.056 at Phase 3 and is now −0.004, i.e. neutral — it was never a
  fact about Sysmon, but about dimensionality at 205 positives. Also fixed a second defect the new tests caught: an
  all-NULL `ppid` column made the parent self-join raise instead of yielding no parents.
  `tests/test_ml_phase8.py` adds a **train/serve coverage guard** that fails the build when a
  T1 feature is well-populated in training and near-absent at serve time.
- **2026-09-18** — Phases 0-6 committed and pushed to `origin/ML` (5 commits). Phase 7 done:
  label recovery (7a), feature spec v2 with a third tier (7b), network-feature decision (7c).
  Component B PR-AUC 0.922 → **0.942**, union recall 73% → **87.8%**, attacks caught by neither
  halved to 25, leak-audit drop → **0.0001**. Suite: **351 passed, 1 skipped, 0 failed**.
- **2026-09-16 (7)** — Phase 6 done. `/ml` dashboard page, confidence badges on Investigation,
  risk badges on Endpoints, `reports_ml/MODEL_CARDS.md`, `tests/test_ml_ui.py` (32).
  Suite: **335 passed, 1 skipped, 0 failed**. All six phases complete.
- **2026-09-16 (6)** — Phase 5 done. Components B and C, host risk, PSI drift, two operational
  scripts, four endpoints, `tests/test_ml_phase5.py` (48), `reports_ml/ML_EVALUATION_TRIAGE.md`,
  figures 06–08. Suite: **303 passed, 1 skipped, 0 failed**.
- **2026-09-16 (5)** — Phase 4 done. `ml_registry.py`, `ml_integration.py`, engine hook, four
  `/api/v1/ml/*` endpoints, `tests/test_ml_integration.py` (37). Fixed a self-inflicted 500 on
  `/api/v1/timeline` (summary JSON contract). Suite: **255 passed, 1 skipped, 0 failed**.
- **2026-09-16 (4)** — Phase 3 done. `server/engine/ml_anomaly.py` (IsolationForest novelty
  detection with percentile scores + deviation explanations), `ml/evaluation/harness.py`
  (grouped CV, low-FPR metrics, group bootstrap CIs, three mandatory baselines,
  Sigma-complementarity, feature-group ablation), `ml/training/train_anomaly.py`,
  `ml/evaluation/figures.py` (5 figures), `reports_ml/ML_EVALUATION.md`, and
  `tests/test_ml_anomaly.py` (43). Suite: **218 passed, 1 skipped, 0 failed**.
- **2026-09-16 (3)** — Phase 2 done. `server/engine/ml_features.py` (98 features, T1/T2 tiers,
  spec hash), `ml/datasets/assemble.py` (corpus + local benign, group-aware holdout),
  `ml/evaluation/audit_baseline.py` (re-measurement + skew audit), plus
  `tests/test_ml_features.py` (66) and `tests/test_ml_dataset.py` (22). Suite: **175 passed,
  1 skipped, 0 failed**. Repo hygiene: `.venv/` and 67 tracked `.pyc` files untracked
  (working tree untouched) — 4,200 tracked files down to 111.
- **2026-09-16 (2)** — Phase 1 done. `db.migrate()` (additive, idempotent, verified on a copy
  of the live DB with `integrity_check: ok` and zero row changes); `ml/datasets/otrf.py`
  (fetch/verify/manifest, AV-tolerant); `ml/datasets/otrf_etl.py` (OTRF -> ATOR schema, sensor
  profile, parent reconstruction, pid backfill); `ml/datasets/labels.py` (lineage labelling
  with a seed audit trail); `tests/test_ml_etl.py` (32 tests). Suite: **87 passed, 1 skipped,
  0 failed**. Also fixed a real bug the tests caught: reconstructed parents were being written
  with the wrong pid field.
- **2026-09-16 (1)** — Phase 0 started. Audited codebase and DB; corrected 8 factual errors in
  `hazem2.md`; built working Python 3.13 venv; established 45/1/1 test baseline; downloaded
  and measured the 155-capture OTRF corpus; wrote `docs/ML_ARCHITECTURE.md`; created
  `.gitignore`, `requirements-ml.txt` and the `ml/` package skeleton.
