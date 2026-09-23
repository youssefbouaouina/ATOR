# Phase 10 — Weekly MLOps pipeline

> Status: **implemented** (see `docs/ML_PROGRESS.md`, Phase 10). This file is the design and
> the reasons behind it. Operator commands are in `docs/ML_MLOPS_RUNBOOK.md`.

## 1. The goal, and the constraint that shapes everything

Once every 7 days, with nobody watching: retrieve new data, ETL it, retrain, evaluate,
A/B-test the new model in deployment, deploy it if it earned it, and monitor the result.

The constraint is the word *nobody*. A pipeline that retrains every week is easy. The hard
part is one that can run for months unattended without **either** of the two failure modes
that matter here:

1. **Silently shipping a worse detector.** Here that means missing attacks, and no one would
   notice until an incident review.
2. **Needing a human to unstick it.** For example a half-finished run holding a lock, a corrupt
   staging DB, or a model file replaced halfway.

Every design choice below serves one of those two. §6 lists the invariants, and each has a test.

## 2. What already existed, and what was missing

| Stage | Before Phase 10 | Missing |
|---|---|---|
| Retrieve | `ml.datasets.otrf fetch` (idempotent, checksummed) | nothing scheduled; new captures would be labelled blind |
| ETL | `otrf_etl --rebuild` + `labels` (two commands, easy to forget one — it happened, Phase 8) | staging, validation, atomic swap |
| Train | `ml.training.train_*` `--save` | writes straight into `models/`, the directory the server serves from |
| Evaluate | grouped CV + baselines + CIs, per component | no comparison against the model currently deployed |
| A/B | — | everything |
| Deploy | copy a file into `models/` by hand | versioning, atomicity, smoke test, rollback |
| Monitor | PSI drift (`scripts/retrain_ml.py --check-drift`) | model/pipeline health, analyst outcomes |

The old `scripts/retrain_ml.py` says in its docstring that retraining should not happen
*because a day passed*. That still holds, and the pipeline keeps it: a weekly run **retrains**
when its inputs changed, but it only **replaces** the deployed model when the new one has
proved itself offline *and* in a live shadow trial. A model that is performing well is never
replaced just because a week went by.

## 3. The weekly cycle

```
 week N                                   week N+1
 ──────────────────────────────────────── ────────────────────────────────────────
 [run N] conclude trial(N-1)              [run N+1] conclude trial(N):
         retrieve → ETL → train(N)                  online gates pass → PROMOTE(N)
         offline gates(N vs champion)               smoke test fails → auto-ROLLBACK
         start shadow trial(N) ──────────────────►  retrieve → ETL → train(N+1) → ...
                 │
                 └─ all week: the server scores live traffic with BOTH models;
                    only the champion's findings reach analysts
```

A model trained in week N can reach analysts at week N+1 at the earliest, after 7 days of
evidence from live traffic. The one-week lag is deliberate.

### Stages of one run (`python -m ml.mlops run`)

| # | Stage | Does | If it fails |
|---|---|---|---|
| 0 | **Preflight** | lock; pause flag; 7-day cadence guard; disk space; ML stack importable; reconcile the model store | exit, nothing touched |
| 1 | **Conclude trial** | online gates on last week's shadow evidence → promote / reject / inconclusive | champion unchanged |
| 2 | **Retrieve** | OTRF fetch (network optional); manifest verify; **admission** of new captures; live DB snapshot (SQLite online backup); anti-poisoning exclusions | network failure → uses cached corpus (warning); others abort the run |
| 3 | **ETL** | build the training DB **in staging** (incremental, or full when the ETL code changed); label; **validate**; atomic swap into `ml_train.db` | staging discarded; live training DB untouched |
| 4 | **Train** | skip components whose inputs are unchanged (fingerprint); train the rest as subprocesses into the run's candidate directory — never `models/` | component marked failed; others continue |
| 5 | **Evaluate** | offline gates: challenger vs baselines **and** vs the deployed champion, on identical rows | candidate rejected |
| 6 | **Stage** | passing components start a shadow trial (`models/shadow/`) | — |
| 7 | **Monitor** | drift on the last 7 days of live traffic; champion live metrics; analyst outcomes; pipeline health | recorded; never blocks |
| 8 | **Report** | run report (JSON + Markdown), DB row, audit log, retention clean-up, lock release | — |

## 4. Design decisions

### 4.1 Scheduler: the OS, not the web server

The run is a separate process started by **Windows Task Scheduler** (or a **systemd timer**
on Linux), not a loop inside FastAPI:

* training loads pandas and scikit-learn and builds frames of 20k+ rows. A web server should
  not hold that memory afterwards, and the old `retrain_ml.py` already uses subprocesses for
  the same reason;
* a crash in training cannot take the DFIR server down with it;
* the OS scheduler survives reboots and has **catch-up** semantics (`StartWhenAvailable` /
  `Persistent=true`). A laptop that is asleep at the scheduled time runs the job when it wakes
  instead of skipping a week.

"Once every 7 days" is enforced **twice**: by the trigger, and by a cadence guard inside the
pipeline (no two completed runs less than 6 days apart unless `--force`). So a catch-up run and
the regular trigger can never produce two runs in one week.

### 4.2 A/B in deployment = shadow (champion/challenger), not a traffic split

A classic A/B test sends half the traffic to each model. For a detector that is the wrong
design:

* **Safety.** The hosts assigned to the worse model get worse protection for a week. In
  security the cost of the experiment falls on whichever hosts happen to be attacked.
* **Statistical power.** The lab has a handful of hosts. A split compares different
  processes on different machines, and the host-to-host variance swamps any model
  difference. A **shadow** trial scores the *same* processes with both models, which gives a
  paired comparison with far more power per observation.

So during the trial the server scores every new process with the champion (as always) **and**
the challenger. The challenger's would-be findings are recorded in `ml_shadow_flags`, and
**never** become detections. This is the standard champion/challenger pattern. It has one
known limitation: analysts only see champion findings, so they can label only those. That
limitation is handled by replaying analyst-confirmed threats against the challenger (§4.6, gate A5).

Only Component A (anomaly) is shadowed inside the server, because it is the only component
that decides *what analysts see*. Components B (confidence) and C (tactic hint) annotate
findings that already exist. They are checked at trial conclusion by replaying them over the
trial window's detections, which runs the same code on the same stored rows.

### 4.3 Deployment is a file swap the server already understands

The server loads `models/<type>_<tier>.joblib` and caches by modification time
(`ml_registry.load_artefact`). Promotion therefore needs **no server change and no
restart**:

1. The artefact is copied from the immutable store (`models/registry/<version>/`) to
   `models/.<name>.incoming`.
2. `os.replace` moves it onto the serving path. This is atomic on one volume, and it is
   retried because Windows refuses to replace a file another process has open.
3. **Smoke test**: the pipeline clears the registry cache, loads the new champion through the
   same `load_artefact` the server uses, feature-spec guard included, and scores a stored
   canary frame. It checks the scores against those recorded at training time.
4. If loading or the canary check fails, the previous champion is restored automatically.

Every champion is kept in the store (last 5), so `python -m ml.mlops rollback <component>` is
one command.

### 4.4 Automated retraining on live data is a poisoning channel, so it is closed

Component A learns "normal" from local benign telemetry, and that telemetry is only *assumed*
benign (`ml/datasets/assemble.py`). Once retraining is automatic, an attacker who stays quiet
on a host gets their activity folded into next week's baseline, and the model learns that the
intrusion is normal. The pipeline admits a live process into training only if **all** of these hold:

| Exclusion | Why |
|---|---|
| collected in the last **7 days** (cooling-off) | detections and analyst review need time to happen. These rows double as the temporal hold-out in §4.6 |
| hit by a **deterministic rule** (Sigma, YARA, IOC), and its descendants | a rule hit is high-precision evidence of compromise |
| an **ML lead** confirmed by an analyst, or unreviewed and rated **likely malicious** (triage ≥ 50%) or unscored, plus descendants of confirmed ones | see the measurement below |
| on a host within **±24 h of a high/critical rule detection** | the undetected parts of an incident sit next to the detected ones |
| demo fixture hosts | already excluded, see `assemble.py` |
| older than 90 days, or beyond 50,000 rows (oldest first) | bounds training time as the DB grows |

Lineage never propagates from an OS root process (`System`, `services.exe`, ...), which is the
same deny-list the corpus labeller uses. An unreviewed ML lead on `System` would otherwise
exclude most of the process tree.

**Why unreviewed low-likelihood ML leads stay in: a measured feedback loop.** The first
design excluded *every* ML lead. On the first real run, the candidate it produced flagged
**9.35%** of unseen live processes against the deployed model's **4.84%**. Gate A4 rejected
it, correctly. The cause was the exclusion itself: removing the model's own unreviewed false
positives from "normal" makes the next model find them rarer still. Left alone, this loop
rejects every weekly update until the model goes stale. The experiment on identical rows
(`docs/ML_PROGRESS.md`, Phase 10):

| Policy for unreviewed ML leads | Alert rate, unseen live traffic | Corpus attacks caught at the floor |
|---|---|---|
| deployed model (reference) | 4.84% | 16.6% |
| exclude all | 9.35% | 18.5% |
| **re-admit those triage rates < 50%** (shipped) | **4.84%** | 13.7% |
| re-admit all | 4.84% | 16.6% |

The shipped policy uses the calibrated triage model, whose job is exactly this question, to
keep out the leads that resemble attacks (5 of the 29 on the lab data, rated 81–86%). The
low-likelihood outliers are kept. Gates A3 and A5 remain the backstop if that judgement is wrong.

An ML finding that an analyst marked *benign* is re-admitted too, unless a deterministic
rule also fired on that process. This is the feedback loop that makes the system learn: a
false positive the analyst dismisses becomes part of next week's baseline. Re-admission is
capped at 200 rows per run and listed in the run report, because the dashboard has no
authentication (`LIMITATIONS.md`) and feedback is therefore forgeable.

Exclusions are written into the **snapshot** (`ml_training_exclusions`), never into the live
DB, and `assemble.load` honours them. Every model can therefore be traced back to exactly the
rows that were excluded, and why.

### 4.5 New labelled data needs a human; new unlabelled data does not

Corpus labels come from per-capture attack signatures curated in `ml/datasets/labels.py`. If a
new upstream capture had no curated signature, the narrow fallback would miss its attack
processes. Every process would then be labelled **benign**, and the attack would enter the
negative class. So automation stops at **admission**:

* new captures are downloaded and checksummed automatically;
* they are **not** imported into training until approved (`python -m ml.mlops approve
  <capture>`), and they are listed on the dashboard as *awaiting review*;
* the 154 captures present when Phase 10 shipped are the approved baseline.

Live telemetry is unlabelled and is admitted automatically under the rules in §4.4. The
split is simple: labels need a human to verify them, unlabelled data does not.

### 4.6 Offline gates: against baselines, against the champion, on identical rows

Gates read the challenger's own evaluation report and the pipeline's paired comparisons. Numbers
are taken from the artefacts, not hard-coded, so they cannot go stale the way the tactic
precision did (Phase 9).

**Component A — anomaly** (served tier T1; T2 must also load and beat its baselines)
| Gate | Rule | Why |
|---|---|---|
| A1 beats the no-ML alternatives | CV PR-AUC > Sigma baseline and > best single feature, same folds | the project's shipping criterion since Phase 3 |
| A2 no regression in ranking | CV PR-AUC ≥ champion's − 0.03 | the champion CI half-width is ≈ 0.12, so 0.03 is strict |
| A3 no lost detections | recall on corpus attacks at the deployed floor (0.99) ≥ champion's − 0.05, **paired on identical rows** | A fits benign rows only, so attacks are out-of-sample for **both** models, which makes this an unbiased paired test. The margin is 0.05, not 0.03: small benign-data changes alone moved recall by about 3 points (6 of 205 attacks) on the first real run, while a poisoned baseline loses far more (~1.0 → ~0.17 in the test) |
| A4 no alert flood | alert rate on the 7-day live hold-out ≤ 1.5 × champion's (+0.5 pt) | the hold-out is excluded from training by §4.4, so it is out-of-sample for both |
| A5 confirmed threats kept | challenger still scores ≥ floor on ≥ 90% of **analyst-confirmed** threats (when ≥ 5 exist) | a growing regression suite of real attacks from this deployment |

**Component B — confidence**: beats baselines · PR-AUC ≥ champion − 0.03 · ECE ≤ 0.05 and
≤ champion + 0.02. Calibration is what B exists for; it is displayed to analysts as a percentage.

**Component C — tactic hint**: precision at the shipped gate ≥ 0.70 and ≥ champion − 0.05 ·
coverage ≥ ½ champion's · accuracy > majority-class baseline.

**Online gates (trial conclusion, Component A)**: enough evidence (≥ 24 h, ≥ 200 processes;
otherwise *inconclusive*, and the champion stays) · shadow error rate ≤ 1% · distinct
would-be findings ≤ 1.5 × champion's (+5) · mean scoring time ≤ 3 × champion's (+250 ms).
B and C replay without errors, with finite scores.

### 4.7 Fingerprints and identity stop churn

Every component's inputs are hashed: approved corpus and labels, code (ETL, features, trainer,
model), library versions, and (for A only) the admitted live rows. If the hash equals the
champion's, the component is **not retrained**. B and C train on the corpus only, so they
retrain only when the corpus, the code or the libraries change. A retrains weekly, because its
baseline grows weekly.

A retrain can still produce the *same* model, for example the first run after the hand-trained
models, which carry no fingerprint. When the candidate's fitted parameters and feature
statistics are byte-identical to the champion's (`evaluate.equivalent`), it is adopted at once
for provenance only, with no week-long trial. It is still smoke-tested, and nothing changes
for analysts. On the first real run, triage and tactic matched exactly. Identity is judged on
the model, not on outputs: comparing scores was tried first and is unsound, because anomaly
percentiles saturate at 1.0 and two different forests can agree everywhere on small data.
sklearn tree nodes also pickle their uninitialised padding bytes. Two identical forests may
therefore compare as different, which is the safe direction (they go to a trial), and never
the reverse.

### 4.8 Kill switches

| Switch | Effect |
|---|---|
| `python -m ml.mlops pause` (file `mlops/PAUSED`) | scheduled runs exit immediately, successfully |
| `python -m ml.mlops freeze` (file `mlops/FROZEN`) | runs train and evaluate, trials run, **nothing is promoted**. Use before a demo or an audit |
| `python -m ml.mlops rollback <component>` | restore the previous champion now |
| `ATOR_MLOPS_DISABLED=1` | same as pause, for a service environment |

## 5. Monitoring

Recorded every run in `ml_pipeline_runs.summary_json` and shown on the Threat Hunting page
(*Model operations*), in security vocabulary rather than data-science vocabulary:

* **model health**: champion version and age, trial progress, last run result, next run;
* **drift**: PSI of the last 7 days of live traffic against *this estate's own earlier
  weeks*, recorded in the existing `ml_drift_log`. The training corpus is not the reference.
  It is lab captures, and its gap to a real estate is permanent: 25 of 80 features showed as
  shifted on the first run, and would every week. Alerting on that would teach operators to
  ignore the result code. Attention is raised when ≥ 10% of features shift week over week;
  the corpus comparison is used only when there is too little local history;
* **outcomes**: leads per host-day, analyst-confirmed vs dismissed, the share of leads reviewed;
* **pipeline health**: *overdue* if no successful run in 8 days, consecutive failures,
  captures awaiting review, trials inconclusive 3 weeks running (the server was not up long
  enough to collect evidence).

Exit codes for the scheduler: `0` OK or nothing to do · `1` the run failed · `2` completed but
a human should look (captures awaiting review, drift shifted, a rollback happened, overdue
trial). Task Scheduler shows it as *Last Run Result*.

## 6. Invariants (each is a test in `tests/test_mlops_*.py`)

1. A failure in any stage before promotion leaves `models/` byte-identical.
2. The live DFIR database is read only through a snapshot. The pipeline writes only its own
   bookkeeping rows (runs, trials, audit), never telemetry or detections.
3. Nothing reaches analysts without passing offline gates **and** a live trial. There are two
   exceptions: no valid champion exists (serving nothing is worse), or the candidate is
   byte-identical to the champion (nothing changes).
4. Promotion is atomic per file, smoke-tested, and rolled back automatically on failure.
5. One run at a time. A crashed run's lock is reclaimed rather than blocking forever.
6. Shadow scoring cannot change champion scores, create detections, or raise into the engine.
7. Unapproved captures never reach training.
8. Excluded live rows (§4.4) never reach training.
9. Pause means no side effects. Freeze means no promotion.

## 7. Failure modes considered

| Situation | Behaviour |
|---|---|
| no internet / GitHub down | fetch skipped with a warning; cached corpus used |
| antivirus blocks an archive | skipped (existing `is_av_blocked`); counted in the report |
| laptop asleep at trigger time | runs at next wake (`StartWhenAvailable`); cadence guard prevents doubles |
| server off during the trial week | trial *inconclusive*; champion kept; new challenger supersedes; alert after 3 weeks |
| disk nearly full | preflight refuses (< 3 GB free); nothing touched |
| crash / power loss mid-run | stale lock reclaimed next run; staging and run dirs are disposable; the store is reconciled against `history.json` |
| crash between two artefact swaps | reconcile step detects a mixed champion set and re-applies the recorded state |
| feature spec changed by a developer | current champion is refused by the server anyway; the challenger is the only valid model → bootstrap promotion after offline gates |
| scikit-learn upgraded | fingerprint changes → retrain under the new version; smoke test proves loadability in the server's interpreter |
| someone deletes `ml_train.db` | rebuilt from the cached corpus in staging |
| a new challenger is much worse | rejected by gates; reasons in the report; champion keeps serving |

## 8. What remains a human's job

Three things, and each is surfaced on the dashboard:

1. approve a new upstream capture after checking that `labels.py` has signatures for it;
2. look at a run that exits `2`;
3. mark ML leads as confirmed or benign. This is optional, and it is what makes the loop learn.

## 9. Out of scope, stated plainly

* No true randomized A/B (§4.2 explains why this is a feature).
* No email or chat alerting: there are no credentials for it, and the dashboard plus the
  scheduler's result code are the channel.
* Shadow evaluation cannot measure analyst precision on challenger-only findings.
* The dashboard has no authentication, so analyst feedback can be forged by anyone who can
  reach port 8000. It is capped and listed in each report (§4.4); the underlying fix is
  authentication, which is outside the ML layer.
