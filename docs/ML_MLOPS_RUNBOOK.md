# MLOps runbook — the weekly model update

The *why* is in `docs/ML_MLOPS_PLAN.md`. This page is the *how*: install it, read it, and
act on it. All commands run from the repository root with the project venv
(`.venv\Scripts\python.exe` on Windows, `.venv/bin/python` on Linux; written as `python` below).

## Install the schedule

**Windows** (current user, no admin needed):
```powershell
powershell -ExecutionPolicy Bypass -File scripts\install_mlops_schedule.ps1                 # Sundays 03:00
powershell -ExecutionPolicy Bypass -File scripts\install_mlops_schedule.ps1 -Day Wednesday -At 13:00
powershell -ExecutionPolicy Bypass -File scripts\install_mlops_schedule.ps1 -Status
powershell -ExecutionPolicy Bypass -File scripts\install_mlops_schedule.ps1 -Uninstall
```
The default task runs only while that user is logged on. On a dedicated server, use an
elevated shell and `-AsSystem` so it runs regardless.

**Linux** (systemd): edit the paths and `User=` in `scripts/ator-mlops.service`, then
```bash
sudo cp scripts/ator-mlops.service scripts/ator-mlops.timer /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now ator-mlops.timer
```

**The server must be running the Phase 10 code for live trials to collect evidence.** A
server started before the update needs one restart. The weekly job itself does not need the
server running.

## What happens each week, in one paragraph

The job snapshots the live database, decides any live trial that has run for a week (deploys
the candidate or rejects it), downloads new attack datasets (it holds them back until you
approve them), rebuilds the training database in staging, retrains whatever changed, tests
each candidate against the detection rules and against the model in service, and starts a
one-week silent trial for any candidate that passed. It then checks the week's telemetry for
drift and writes a report. A typical run takes about 10 minutes.

## Reading the result

| Where | What |
|---|---|
| Threat Hunting page → **Detection model updates** | state, models in service, trial progress, last/next run |
| `python -m ml.mlops status` | the same, plus rollback targets and captures awaiting review |
| `mlops\runs\<run id>\REPORT.md` | every gate, with its value and threshold, and every decision with its reason |
| `mlops\scheduler.log` | start/finish and exit code of each scheduled run, including crashes before Python starts |
| Task Scheduler / `systemctl status ator-mlops` | last result code |

Exit codes: **0** OK · **1** failed, with the models in service unchanged · **2** completed,
but the report has a *Needs attention* section.

## What to do when

| You see | Meaning | Do |
|---|---|---|
| *N new attack capture(s) await review* | upstream published new OTRF captures; they are not used until approved | check `ml/datasets/labels.py` has signatures for the tool each one emulates (add them if not), then `python -m ml.mlops approve <capture.zip>` |
| *approved capture(s) changed on disk* | a file no longer matches its pinned checksum | re-download (`python -m ml.datasets.otrf fetch`) or investigate; it stays excluded meanwhile |
| *trial has lacked live evidence for N weeks* | the server was not running long enough to compare the candidate (24 h, 200 processes) | keep the server running, or lower `trial_min_hours` in `mlops\config.json` for a lab |
| *this week's telemetry differs from earlier weeks* | a new host, a new software rollout, or a broken sensor (e.g. agent lost elevation → no command lines) | check the agents first; if the change is real, it is absorbed into the baseline after the 7-day cooling-off |
| *failed its post-deployment smoke test and was rolled back* | a deployed file did not load or did not reproduce its canary scores | nothing is broken for analysts (the previous model is back); read the run log |
| *a hand-placed model was found in models/* | someone ran `train_* --save` by hand | nothing; it was adopted and can be rolled back |
| run **failed** (exit 1) | a stage raised; models in service unchanged | read the stage error in the report; the next run retries (failed runs do not count toward the 7-day cadence) |

## Operator commands

```bash
python -m ml.mlops status                 # deployed, on trial, recent runs, pending captures
python -m ml.mlops run                    # run now (refuses within 6 days of the last run)
python -m ml.mlops run --force            # run now regardless
python -m ml.mlops run --no-fetch         # do not contact GitHub
python -m ml.mlops freeze                 # keep evaluating, deploy nothing (demos, audits)
python -m ml.mlops unfreeze
python -m ml.mlops pause                  # scheduled runs exit immediately
python -m ml.mlops resume
python -m ml.mlops rollback anomaly       # restore the previous model now (anomaly|triage|tactic)
python -m ml.mlops history                # every model each component has served
python -m ml.mlops approve --pending      # captures awaiting review
```
`ATOR_MLOPS_DISABLED=1` in the environment has the same effect as `pause`.

## Tuning

Every threshold lives in `ml/mlops/config.py`, with the reason for its value. To override one,
put it in `mlops\config.json`. Unknown keys are rejected, so a typo cannot silently leave a
gate at its default:
```json
{ "trial_min_hours": 8, "cooling_off_days": 5 }
```

## Where things live

| Path | Content | In git |
|---|---|---|
| `ml/mlops/` | the pipeline | yes |
| `ml/mlops/approved_captures.json` | the 153 OTRF captures approved at ship time, pinned by SHA-256 | yes |
| `mlops/` | runs, reports, staging DB, lock, `PAUSED`/`FROZEN`, local approvals, `config.json` | no |
| `models/*.joblib` | models in service (unchanged path, so the server needed no new loader) | no |
| `models/shadow/` | the candidate on live trial | no |
| `models/registry/<version>/` | every model produced, with `card.json` and canary; `history.json` | no |

Environment overrides: `ATOR_MLOPS_HOME`, `ATOR_ML_MODEL_DIR`, `ATOR_DFIR_DB`,
`ATOR_ML_TRAIN_DB`, `ATOR_OTRF_DIR`.
