# ML_ARCHITECTURE.md — Layer 4.5 ML: Behavioural Analytics

**Status:** design accepted, implementation in progress
**Owner:** Hazem (data-science track) — security framework by the DFIR track
**Audience:** internship jury, future maintainers, and any AI coding assistant resuming this work
**Supersedes:** `hazem2.md` (v2 integration proposal). Where this document and `hazem2.md`
disagree, **this document wins** — §2 lists exactly where and why.

---

## 0. TL;DR

The existing framework is a deterministic 6-layer DFIR pipeline (collect → detect with
YARA/Sigma/IOC → map to ATT&CK → report). It answers *"does this artefact match a known
rule?"*. It cannot answer *"is this behaviour unusual for this host?"*, which is the
threat-hunting half of the internship subject (§3 of the subject: *"develop proactive
threat hunting methods"*).

Layer 4.5 ML adds three models on top of the **existing schema, without touching the agent**:

| # | Model | Task | Learning | Answers |
|---|-------|------|----------|---------|
| **A** | `ml_anomaly` | Per-process / per-connection outlier scoring | Unsupervised (IsolationForest) | "Is this rare for this host?" |
| **B** | `ml_triage` | Malicious-vs-benign process classification → calibrated confidence | Supervised (HistGradientBoosting + calibration) | "How likely is this a real threat?" |
| **C** | `ml_tactic` | ATT&CK tactic suggestion for unmapped findings | Supervised multi-class | "Which tactic does this look like?" |

Plus a deterministic **host risk score** (not ML — weighted aggregation) that consumes all
detection sources including ML.

**The single most important design decision:** feature extraction reads **only the ATOR
schema** (`raw_processes`, `raw_connections`, `raw_logs`, `raw_persistence`,
`resource_samples`). Third-party training corpora are first **converted into that schema**.
Therefore the exact same code path computes features at training time and at inference
time — there is no train/serve skew by construction. See §5.

---

## 1. Verified baseline (measured, not assumed — 2026-09-16)

Everything below was measured on this machine before any design work. Re-verify with
`ml/evaluation/audit_baseline.py` (Phase 0 deliverable) if resuming much later.

### 1.1 Test suite
```
.venv-ml313\Scripts\python -m pytest tests/ -q
=> 45 passed, 1 failed, 1 skipped  (47 collected)
```
The single failure is **pre-existing and environmental**, not a code defect:
`tests/test_agent.py::test_live_collection_windows` asserts no fatal collector errors and
whitelists Security-log access-denied by matching the English strings `"Security"` /
`"access_denied"`. On this French-locale Windows host, non-elevated `Get-WinEvent` returns
`"Tentative d'exécution d'une opération non autorisée."`, which the whitelist misses.
Locale-brittle test, fixed in Phase 0 by matching the collector's structured error instead
of a localised message.

### 1.2 Environment
| Item | Finding |
|------|---------|
| Committed `.venv/` | **Broken.** Hard-codes `C:\Users\SidikRoyale\AppData\Local\Python\pythoncore-3.12-64\python.exe`. Unusable on any other machine. |
| Python available | 3.14.4 (`C:\Python314`), 3.13.14 (Store) |
| `yara-python` | Wheels exist only for cp39–cp313. On 3.14 it tries to build from source → needs MSVC 14+ → **4 test failures**. |
| **Chosen interpreter** | **Python 3.13** → `.venv-ml313/`. Gets `yara-python` 4.5.4 *and* scikit-learn. Yields the 45/1/1 baseline above. |
| ML stack verified | scikit-learn 1.9.1, pandas 3.0.5, numpy 2.5.3, joblib 1.6.0, matplotlib 3.11.2 |

> Note: pandas **3.x** is installed. Copy-on-write is the default and several 2.x idioms
> (chained assignment, `inplace=`) are removed. Write pandas-3-clean code.

### 1.3 Live database contents (`ator_dfir.db`) — the reason external data is required
| Table | Rows | Consequence for ML |
|-------|-----:|--------------------|
| `raw_processes` | 545 | Only **538** from 2 real hosts (id 5, 7); rest is the demo fixture |
| `raw_connections` | 1049 | usable as benign |
| `raw_logs` | 1500 | sources are only `application`/`security`/`system` — **no `sysmon`** |
| `raw_persistence` | 1241 | `service` 1209, `registry_run` 26, `startup_folder` 6 |
| `raw_files` | 400 | |
| `detections` | **6** | all `rule_type='sigma'`, all from the demo fixture |
| `resource_samples` | **2** | telemetry table exists but is effectively empty |
| `ioc_store` | **0** | IOC-reputation features are unavailable |
| `approvals_queue` | **0** | **no analyst labels exist** |

Real host collections are **single snapshots** (host 5: 256 processes at one timestamp;
host 7: 282 at one timestamp), not time series.

### 1.4 External corpus (OTRF Security-Datasets, downloaded & measured)
`data/external/otrf/` — 155 Windows "atomic" captures, 85 MB, real Sysmon + Security +
PowerShell telemetry from adversary-emulation runs, organised by ATT&CK tactic.
Licence: MIT/open, no credentials needed (Kaggle needs a token we do not have; GitHub does not).

Measured over 153 parseable captures, **786,141 events**:

| Sysmon EID | Meaning | Count | Maps to |
|-----------:|---------|------:|---------|
| 10 | ProcessAccess (LSASS!) | 249,979 | `raw_logs` → Tier-2 features |
| 12/13/14 | Registry | 213,795 | `raw_persistence` + Tier-2 |
| 7 | ImageLoad | 76,389 | Tier-2 |
| 11 | FileCreate | 6,685 | Tier-2 |
| **3** | **NetworkConnect** | **4,150** | **`raw_connections`** |
| **1** | **ProcessCreate** | **1,704** | **`raw_processes`** |
| 22 | DnsQuery | 711 | Tier-2 |

Tactic coverage: lateral_movement 55 captures, defense_evasion 40, credential_access 29,
discovery 14, persistence 7, execution 4, privilege_escalation 2, collection 1, other 3.
17 distinct hosts, 27 distinct users. Only **105/153** captures contain any EID 1.

---

## 2. Corrections to `hazem2.md`

`hazem2.md` is a good skeleton but was written without measuring the database. These claims
are false and the plan is adjusted accordingly.

| `hazem2.md` claim | Measured reality | Adjustment |
|---|---|---|
| "46/46 tests green" | 45 pass / 1 fail / 1 skip | Baseline recorded honestly (§1.1); test fixed in Phase 0 |
| "trains in <1s on 10k rows" / per-host trailing **7 days** | 545 process rows total; real hosts are single snapshots | Train on the OTRF corpus + local benign; window is configurable but **7 days of history does not exist** |
| Train Component A on `resource_samples` over 7 days | `prune_old_resource_samples()` **deletes anything older than 72 h** (`ATOR_RES_RETENTION_HOURS=72`), and the table holds 2 rows | **Blocking conflict.** Resolved by a rollup table that survives pruning (§6.3). Resource features are deferred to Phase 5 and clearly marked unvalidated. |
| `scripts/atomic_runner.py` "produces known-true detections → labels" | It **generates no data**. It re-runs `sigma_run()` over rows already in the DB and checks for matches. A regression checker, not a label generator. | Labels come from the OTRF corpus (§5.3). `atomic_runner.py` stays a regression check. |
| `approvals_queue` rejected decisions as negative labels | 0 rows | Not a label source. Kept as a *future* feedback loop (§9). |
| "Component B ranks detections by P(true positive)" | Requires analyst-adjudicated detections; none exist | **Reframed**: B classifies *malicious vs benign process behaviour*; its calibrated probability becomes the confidence score. Trainable and honest. |
| `ALTER TABLE detections ADD COLUMN source TEXT` | `detections.rule_type` already exists and already carries `'sigma'`/`'yara'`/`'ioc'` | **Do not add `source`.** Reuse `rule_type` with new values `'ml_anomaly'`/`'ml_triage'`. Avoids two columns of record. |
| Features `spawn_rate_per_min`, `conn_interval_cv` (beaconing) | Real data is single snapshots; no inter-arrival times | Implemented but **gated**: emitted only when ≥2 collections exist for the host, else marked missing. Never silently zero. |
| `remote_ip_reputation` from IOC table | `ioc_store` is empty | Feature present, degrades to "unknown"; excluded from headline metrics |

---

## 3. Where ML sits in the pipeline

```
L3  SQLite WAL  ──┬── L4a  YARA / Sigma / IOC        (deterministic) ──┐
                  ├── L4b  Resource telemetry        (rolling stats)   ├──> detections
                  └── L4.5 ML behavioural analytics  (NEW)  ───────────┘      │
                            A anomaly → B confidence → C tactic hint          │
                                          │                                   ▼
                            host_risk_scores ◄─────────────  L5 ATT&CK enrichment
                                          │                                   │
                                          └──────────────► L6 dashboard / reports
```

ML runs **after** the deterministic detectors inside `run_engine()`, in the same
transaction, so a single engine run produces rule hits *and* ML findings, and B can score
rule hits too.

---

## 4. Module layout

Production inference lives under `server/engine/` (imported by the API). Offline training
lives under `ml/` (**never** imported by the server).

```
server/engine/
  ml_features.py     feature extraction: ATOR schema -> matrix  [SHARED train+serve]
  ml_registry.py     model load/save, versioning, ml_models table, active-model cache
  ml_anomaly.py      Component A: IsolationForest train/score
  ml_triage.py       Component B: calibrated classifier train/score
  ml_tactic.py       Component C: tactic suggestion
  ml_risk.py         host risk score (deterministic)
  ml_drift.py        PSI feature-drift monitor
ml/
  datasets/otrf.py       fetch + verify the corpus (idempotent, checksummed)
  datasets/otrf_etl.py   Sysmon JSON -> ATOR schema rows in ml_train.db
  datasets/labels.py     process-lineage labelling (§5.3)
  training/train_*.py    one entry point per component
  evaluation/harness.py  grouped CV, metrics, figures
  evaluation/audit_baseline.py   re-measure §1 facts on demand
scripts/
  fetch_ml_datasets.py   thin CLI wrapper over ml/datasets/otrf.py
  retrain_ml.py          daily retrain (patterned on scripts/update_mitre.py)
  update_risk_scores.py  host risk recomputation
models/                  *.joblib artefacts (gitignored, regenerable)
reports_ml/              evaluation report + figures (committed: it is a deliverable)
```

---

## 5. Data strategy

### 5.1 The train/serve-skew problem and its solution

A model trained on Sysmon JSON but served on psutil snapshots would be broken in
production. So the corpus is **converted into the ATOR schema first**:

```
OTRF Sysmon JSON ──ETL──► ml_train.db  (raw_processes / raw_connections /
                                        raw_logs / raw_persistence)
                                              │
                          ml_features.py ─────┤  ← ONE implementation
                                              │
live ator_dfir.db (psutil + EVTX) ────────────┘
```

Field mapping for `raw_processes` (Sysmon EID 1 → ATOR), all fields verified present:

| ATOR column | Sysmon EID 1 field |
|---|---|
| `pid` | `ProcessId` |
| `ppid` | `ParentProcessId` |
| `name` | `basename(Image)` |
| `cmdline` | `CommandLine` |
| `exe_path` | `Image` |
| `sha256` | parsed from `Hashes` (`SHA256=…`; may be absent → NULL) |
| `username` | `User` |
| `collected_at_utc` | `UtcTime` |
| `create_time_utc` | `UtcTime` — the *same* value, deliberately (see below) |

**`create_time_utc` was added in Phase 8 and the duplication above is the point.** In a corpus
row the two columns hold the same value, because a Sysmon EID 1 record's `UtcTime` *is* the
moment the process started. On a live host they differ completely: `collected_at_utc` is when
the agent swept, identical across every process in that sweep, while `create_time_utc` comes
from `psutil.Process.create_time()` per process. Timing features read `create_time_utc` only,
with no fallback.

Before this column existed, every timing feature was computable in training and **NaN on every
production host**, while cross-validation reported them as the best thing in the feature set.
That is the failure the whole "corpus into ATOR's own schema" strategy was supposed to prevent:
converting the corpus guarantees the same *code* runs on both sides, but not that the same
*columns are populated*. See `docs/ML_PHASE8_PLAN.md`.

`raw_connections` (EID 3): `ProcessId`, `basename(Image)`→`process_name`, `SourceIp/Port`,
`DestinationIp/Port`, `Protocol`. Every remaining event type is stored in `raw_logs` with
`source='sysmon'`, exactly as the real agent's log collector does.

### 5.2 Residual skew — documented, not hidden

**psutil snapshots see survivors; Sysmon EID 1 sees every launch.** A 200 ms
`whoami.exe` appears in Sysmon and is invisible to a 60 s psutil sweep. So the
Sysmon-derived training distribution contains more short-lived processes than the
psutil-derived serving distribution.

Consequences, stated in the evaluation report:
1. Recall measured on the corpus is an **upper bound** for a psutil-only deployment.
2. This is a direct argument for `scripts/install_sysmon.ps1` on monitored hosts — the
   framework already ships it.
3. Mitigated by the **feature tiers** below, and quantified by the Tier-1 vs Tier-2 ablation.

### 5.3 Labelling — process-lineage, not capture-level

Naive labelling ("every event in `credential_access/empire_mimikatz_*.zip` is malicious")
gives grossly noisy labels: a capture holds thousands of background events and a handful of
attack events. The model would learn the capture, not the behaviour — classic leakage.

Instead, **label the attacker's process subtree**:
1. Per capture, locate seed processes matching that capture's attack signature
   (curated `Image`/`CommandLine` patterns, e.g. `mimikatz`, `sekurlsa`, Empire
   launcher base64, `ntdsutil`, `schtasks /create`).
2. Walk `ProcessGuid` → `ParentProcessGuid` (both verified present on EID 1) and label
   all descendants `malicious`.
3. Every other process in the same capture is `benign` background.
4. `tactic` label for C = the capture's directory tactic, applied only to malicious rows.

This yields event-level labels with real provenance, and the benign class comes from the
*same hosts and captures* as the malicious class — which controls for host-specific
confounders instead of letting the model separate classes by hostname.

Labels are **weak** (heuristic seeds). Stated as a limitation; the seed catalogue is
version-controlled and reviewable in `ml/datasets/labels.py`.

### 5.4 Feature tiers — availability-aware, because Sysmon is optional

The agent collects the `sysmon` channel *when Sysmon is installed*
(`agent/collectors/logs.py:20`). It is **not** installed on the current hosts — the live DB
has no `sysmon` rows. So features are split and each model is trained twice:

| Tier | Source | Available | Use |
|------|--------|-----------|-----|
| **T1** | `raw_processes` + `raw_connections` (psutil-computable) | **Every host, today** | Always-deployable baseline model |
| **T2** | T1 + Sysmon-derived (`raw_logs` EID 1/3/7/8/10/11/12/13/22) | Sysmon hosts only | Enhanced model |

At inference, `ml_registry` picks the T2 model if the host has Sysmon rows in the scoring
window, else T1. The **T1 vs T2 ablation is a headline result**: it quantifies what
installing Sysmon buys, in detection terms.

### 5.5 Class balance and honesty about N

Expected usable process rows: ~1,704 (OTRF EID 1) + ~538 (real benign hosts) ≈ **2,242**,
of which malicious is a minority (estimated 150–400 after lineage labelling). This is
**small-N**. Therefore:
- grouped cross-validation, never a single split (§7.1);
- report **confidence intervals**, never bare point estimates;
- prefer regularised models; no deep learning (also an explicit constraint, §8);
- if a metric cannot be measured credibly, the report says so instead of quoting a number.

Each row is information-dense: per-process aggregates pull the other 784k events in as
features on those ~2.2k rows (entity-centric aggregation), which is what makes small-N
workable.

---

## 6. Schema changes

Applied by `migrate()` in `server/db.py` — additive, idempotent, safe on the live DB.
`SCHEMA` keeps the `CREATE TABLE IF NOT EXISTS` style; `ALTER TABLE` needs guarding
because SQLite has no `ADD COLUMN IF NOT EXISTS`.

### 6.1 `detections` — new columns (NOT `source`; see §2)
```sql
ALTER TABLE detections ADD COLUMN confidence_score  REAL;  -- B, calibrated 0..1
ALTER TABLE detections ADD COLUMN anomaly_score     REAL;  -- A, 0..1
ALTER TABLE detections ADD COLUMN suggested_tactics TEXT;  -- C, JSON array
ALTER TABLE detections ADD COLUMN ml_model_id       INTEGER REFERENCES ml_models(id);
ALTER TABLE detections ADD COLUMN ml_explanation    TEXT;  -- JSON: top contributing features
```
`rule_type` gains the values `'ml_anomaly'` and `'ml_triage'`.
`ml_explanation` exists because an unexplained ML alert is unactionable for an analyst —
it carries the top-k features and their contributions.

### 6.2 New tables
```sql
CREATE TABLE IF NOT EXISTS ml_models (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,              -- 'anomaly_t1', 'triage_t2', 'tactic_t2'
    version TEXT NOT NULL,           -- semver + short git sha
    model_type TEXT NOT NULL CHECK (model_type IN ('anomaly','triage','tactic')),
    feature_tier TEXT NOT NULL CHECK (feature_tier IN ('t1','t2')),
    feature_spec_sha256 TEXT NOT NULL,  -- guards against feature/model mismatch
    trained_at_utc TEXT NOT NULL,
    training_rows INTEGER,
    training_source TEXT,            -- 'otrf+local' | 'local'
    metrics_json TEXT,
    model_path TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 0,
    UNIQUE (name, version)
);

CREATE TABLE IF NOT EXISTS host_risk_scores (
    host_id INTEGER PRIMARY KEY REFERENCES hosts(id),
    score REAL NOT NULL,
    tier TEXT NOT NULL CHECK (tier IN ('low','medium','high','critical')),
    last_computed_utc TEXT NOT NULL,
    breakdown_json TEXT
);

-- Survives prune_old_resource_samples() (§2, §6.3)
CREATE TABLE IF NOT EXISTS ml_resource_rollup (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL REFERENCES hosts(id),
    window_start_utc TEXT NOT NULL,
    window_end_utc TEXT NOT NULL,
    sample_count INTEGER NOT NULL,
    stats_json TEXT NOT NULL,        -- per-metric mean/std/p50/p95/max
    UNIQUE (host_id, window_start_utc)
);

CREATE TABLE IF NOT EXISTS ml_drift_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    computed_at_utc TEXT NOT NULL,
    model_id INTEGER REFERENCES ml_models(id),
    feature_name TEXT NOT NULL,
    psi REAL NOT NULL,
    verdict TEXT NOT NULL CHECK (verdict IN ('stable','moderate','shifted'))
);

CREATE INDEX IF NOT EXISTS ix_det_rule_type  ON detections(rule_type);
CREATE INDEX IF NOT EXISTS ix_det_confidence ON detections(confidence_score);
CREATE INDEX IF NOT EXISTS ix_ml_models_active ON ml_models(model_type, feature_tier, is_active);
```

### 6.3 Why `ml_resource_rollup` exists
`prune_old_resource_samples()` hard-deletes `resource_samples` older than 72 h. Any model
trained on a longer window would silently lose its training data. An hourly rollup is
written **before** pruning, so long-horizon resource baselines survive at ~1/240 the
storage. Without this, `hazem2.md`'s 7-day resource baseline is impossible.

---

## 7. Evaluation protocol

Security ML is easy to make look good and hard to make useful. The protocol is fixed
*before* training so metrics cannot be shopped for.

### 7.1 Splitting
- **`GroupKFold` by capture** (and by host where possible). All rows from one capture land
  in one fold. Random row-level splits would put sibling processes from the same attack on
  both sides — leakage that inflates every metric.
- Exactly one **held-out test set of whole captures**, touched once, at the end.
- Hyperparameters tuned only inside training folds.
- `random_state=42` everywhere; `ml_features.py` emits a `feature_spec_sha256` recorded on
  every model row.

### 7.2 Metrics that matter
| Model | Primary | Also reported |
|---|---|---|
| A anomaly | **FP per host per day** at fixed recall; recall @ 1 FP/host/day | ROC-AUC, PR-AUC, precision@k |
| B triage | **PR-AUC** (imbalanced) + **Brier score / reliability curve** | ROC-AUC, P/R/F1 @ tuned threshold, confusion matrix |
| C tactic | macro-F1, per-class F1, confusion matrix | top-2 accuracy |
| Risk score | rank correlation vs severity-weighted ground truth | qualitative analyst review |

**Accuracy is never a headline metric** — with this base rate a "benign always" classifier
scores >85%. **Calibration is mandatory for B** because its output is displayed to an
analyst as a confidence: an uncalibrated 0.9 that means 0.4 is actively harmful.

### 7.3 Mandatory baselines
No model ships without beating, on the same splits:
1. **Random** / stratified-chance.
2. **Existing Sigma rules** on the same data — the honest question is not "is the ML good?"
   but *"does the ML add anything the rules do not already catch?"* This is the single most
   important comparison in the report.
3. **Single best hand feature** (e.g. cmdline entropy threshold) — guards against a
   50-feature model that a one-liner matches.

### 7.4 Ablations
T1 vs T2 (value of Sysmon) · with/without lineage labelling · with/without per-process
aggregates · feature-group leave-one-out.

---

## 8. Operational constraints (non-negotiable)

| Constraint | How it is met |
|---|---|
| No PyTorch / TensorFlow | scikit-learn + joblib only |
| No GPU, CPU-only | IsolationForest / HistGradientBoosting; target <30 s retrain |
| Offline-first at inference | Models loaded from `models/`; **zero** network calls at request time. Corpus download is offline-only and explicit. |
| **Agent untouched** | All ML is server-side. No new agent dependency, no RAM increase. |
| Non-blocking API | SQLite reads via `run_in_threadpool`; scoring is batched inside the engine run, never per-request |
| Model versioning | `joblib` artefact + `ml_models` row + `feature_spec_sha256` guard |
| Graceful degradation | If scikit-learn is missing or no active model exists, `run_engine()` logs and continues. **ML failure must never break deterministic detection.** |
| Reproducibility | fixed seeds, pinned `requirements-ml.txt`, idempotent checksummed ETL |

---

## 9. Deliberately out of scope
Deep learning / sequence models (no data, violates constraints) · online learning ·
graph neural networks on process trees · the analyst-feedback loop that would make
`approvals_queue` a real label source (designed in §9 of the report, not built) ·
automated response (framework is DRY-RUN by design).

---

## 10. Repository hygiene (flagged, not unilaterally changed)

1. **`.venv/` is tracked in git.** Thousands of files, broken on every machine but its
   author's. Recommended: `git rm -r --cached .venv && git commit`. Not done here — it
   rewrites shared repo state and will conflict with the DFIR track's working copies, so
   it needs a team decision. `.gitignore` now prevents recurrence.
2. **`ATOR/` is a second clone** of the same repository (on `main`) nested inside this
   working tree. Added to `.gitignore`; **not deleted** — deletion is the owner's call.
3. `Internship_Subject_DFIR.pdf` as first supplied was 0 bytes; content was read from the
   re-sent copy and is summarised in `docs/ML_PROGRESS.md`.

---

## 11. Phase plan

Each phase ends at a **verifiable checkpoint** (a command whose output proves the phase
works). `docs/ML_PROGRESS.md` is the live state file — update it at every checkpoint.

| Phase | Deliverable | Checkpoint |
|---|---|---|
| **0** | Env, `.gitignore`, `requirements-ml.txt`, these docs, locale test fix | `pytest tests/ -q` → 46 passed, 1 skipped, **0 failed** |
| **1** | `db.migrate()`, OTRF fetch + ETL → `ml_train.db`, lineage labels | `pytest tests/test_ml_etl.py -q` green; label counts reported |
| **2** | `ml_features.py` (T1+T2), feature spec hash, unit tests per feature | `pytest tests/test_ml_features.py -q` green; matrix built from both DBs |
| **3** | Component A + eval harness + `retrain_ml.py` | FP/host/day and recall vs all three §7.3 baselines |
| **4** | Engine integration, `/api/v1/ml/*`, `ml_registry` | `run_engine()` writes `rule_type='ml_anomaly'` rows; API tests green |
| **5** | Components B & C, calibration, host risk, PSI drift | PR-AUC + reliability curve + macro-F1, all with CIs |
| **6** | Dashboard badges, `reports_ml/ML_EVALUATION.md`, model cards | Full suite green; report renders with figures |

---

## 12. Resuming this work in a new session

Read, in order: this file → `docs/ML_PROGRESS.md` (current state + next action) →
the test file for the phase in progress. Then:

```bash
cd "C:/Users/Lenovo/Desktop/ATOR ML"
.venv-ml313/Scripts/python.exe -m pytest tests/ -q          # expect the ML_PROGRESS baseline
.venv-ml313/Scripts/python.exe -m ml.evaluation.audit_baseline   # re-measure §1 facts
```

**Do not trust `hazem2.md` for facts about the codebase — see §2.** Do not trust §1 numbers
blindly if the DB has changed; re-run the audit.
