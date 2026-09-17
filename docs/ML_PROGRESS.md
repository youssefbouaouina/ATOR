# ML_PROGRESS.md — live state file

> **Read this first when resuming.** It records what is *done and verified*, what is
> *next*, and the exact commands that prove it. Update it at every phase checkpoint.
> Design rationale lives in `docs/ML_ARCHITECTURE.md`; this file is state only.

**Last updated:** 2026-09-16
**Branch:** `ML`
**Interpreter:** `.venv-ml313/Scripts/python.exe` (Python 3.13.14) — **not** the committed
`.venv/`, which is broken (points at `C:\Users\SidikRoyale\...`).

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
| **6 — Dashboard, model cards, reports** | ✅ **done & verified** — `335 passed, 1 skipped, 0 failed` |

**Status: all six phases complete.** Awaiting your review in the UI before any commit.

### Run it
```bash
.venv-ml313/Scripts/python.exe -m uvicorn server.app:app --host 127.0.0.1 --port 8000
```
Then open <http://127.0.0.1:8000/ml> — the **ML Analytics** tab. "Score now" runs the models
against the current database; "Recompute risk" refreshes host scores. ML findings also appear
on **Investigation** (Src + Conf columns) and **Endpoints** (Risk column).

### Deliverables to read
| File | What it is |
|---|---|
| `reports_ml/ML_EVALUATION.md` | Component A, with figures 01–05 |
| `reports_ml/ML_EVALUATION_TRIAGE.md` | Components B & C, risk, drift, figures 06–08 |
| `reports_ml/MODEL_CARDS.md` | Per-model intended use, metrics and limitations |
| `docs/ML_ARCHITECTURE.md` | Design decisions and corrections to `hazem2.md` |

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

---

## Changelog

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
