# Running ATOR from scratch

Everything needed to go from `git clone` to a working server, an enrolled endpoint, and a
trained ML layer. `README.md` describes what the framework is; this file is how to run it.

> **Kept current with every push.** Last verified 2026-09-22 on branch `ML` (Phase 10),
> Windows 11 + Python 3.13, `pytest tests` → 635 passed, 1 skipped.

## 0. What the clone does *not* contain

These are all regenerable and deliberately git-ignored, so a fresh clone is small and carries
no data:

| Missing after clone | What creates it | Needed for |
|---|---|---|
| `ator_dfir.db` | the server, on first start | everything |
| `data/external/otrf/` corpus (~85 MB) | `python -m ml.datasets.otrf fetch` | training the ML models |
| `ml_train.db` | the ETL | training the ML models |
| `models/*.joblib` | training, or the MLOps pipeline | the ML layer (Layer 4.5) |
| `mlops/` | the weekly pipeline | pipeline state and reports |

Without the ML artefacts the framework still detects normally with YARA, Sigma and IOC
matching — the ML layer reports itself as unavailable and nothing else changes.

## 1. Prerequisites

* **Python 3.13** is what the project is developed and tested on. 3.10–3.13 work.
  **Avoid 3.14**: `yara-python` has no wheel for it yet, and YARA scanning is a core detector.
* Git, and ~1.5 GB free disk (corpus + training database + models).
* Windows or Linux. Commands below show Windows first; the Linux form is in brackets.

## 2. Install

```powershell
git clone <repo-url> ator
cd ator
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt          # [.venv/bin/pip]
.venv\Scripts\pip install -r requirements-ml.txt       # optional: the ML layer
```

`requirements-ml.txt` (scikit-learn, pandas, numpy, joblib) is optional by design. Skip it
and the server runs rules-only; install it later and restart.

The MITRE ATT&CK bundle (46 MB) ships in the repository at `dfir-refs/cti/`, so technique
enrichment works offline from the start. Refresh it whenever you want with
`python scripts\update_mitre.py`.

Everything below uses `.venv\Scripts\python` on Windows and `.venv/bin/python` on Linux;
written as `python` from here on.

## 3. Start the server

```powershell
python -m server.app
```

Listens on `0.0.0.0:8000` and creates `ator_dfir.db` on first start. Dashboard:
<http://127.0.0.1:8000>.

**If endpoints are on another machine**, they need to reach this port, so add a firewall rule
scoped to your endpoint subnet — do not open it to every network, because the dashboard has
no authentication:

```powershell
New-NetFirewallRule -DisplayName "ATOR Server (lab subnet)" -Direction Inbound -Protocol TCP `
  -LocalPort 8000 -RemoteAddress 192.168.50.0/24 -Action Allow
```

Do not start it with `--host 127.0.0.1`: remote enrollment then fails with "cannot connect".
Full deployment notes, including how the enrollment command picks the server address on a
multi-homed host (`ATOR_PUBLIC_URL`, `ATOR_ENROLL_SUBNET`): `docs/DEPLOYMENT.md`.

## 4. Enroll an endpoint

**Same machine, quickest:**

```powershell
$env:ATOR_SERVER_URL="http://127.0.0.1:8000"
python -m agent.agent enroll
python -m agent.agent once          # or: loop  (collects every 60 s)
```

**A real endpoint (recommended):** open `http://SERVER:8000/enroll`, submit the hostname and
OS, accept the request on `/enrollments`, then run the one-line command the status page shows
on the endpoint. It installs Python if needed, deploys the agent, enrolls it, collects once,
and sets it to start at boot. Both bootstraps are covered in `docs/DEPLOYMENT.md`.

Within a minute the dashboard shows the host, its processes and any detections.

## 5. Train the ML layer (Layer 4.5)

A fresh clone has no models. The simplest path is the MLOps pipeline, which does the whole
chain — fetch corpus, ETL, label, train, evaluate — and, because there is no model in service
yet, deploys the result immediately instead of running a week-long trial:

```powershell
python -m ml.mlops run --force
```

About 15 minutes: ~85 MB download, ~80 s ETL, ~8 min training, then gates and deployment.
It needs `ator_dfir.db` to exist, so start the server once first (§3). Reload the Threat
Hunting page afterwards and the three engines report themselves online.

<details>
<summary>Or do it by hand, one step at a time</summary>

```powershell
python -m ml.datasets.otrf fetch            # corpus download, idempotent, checksummed
python -m ml.datasets.otrf_etl --rebuild    # corpus -> ml_train.db in ATOR's own schema
python -m ml.datasets.labels                # process-lineage labels  (do not skip this)
python -m ml.training.train_anomaly --save  # Component A  (~4 min)
python -m ml.training.train_triage --save   # Component B  (~3 min)
python -m ml.training.train_tactic --save   # Component C  (~10 s)
```

Antivirus blocks two corpus archives (they are real adversary-emulation telemetry); they are
skipped automatically and nothing needs fixing.
</details>

## 6. Keep the models current (optional, recommended)

Install the weekly job, which retrains, evaluates, A/B-tests on live traffic and deploys only
what passes:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install_mlops_schedule.ps1     # Sundays 03:00
python -m ml.mlops status                                                       # what is live
```

Linux: `scripts/ator-mlops.service` + `scripts/ator-mlops.timer`. How it works:
`docs/ML_MLOPS_PLAN.md`. Operating it day to day, and what each alert means:
`docs/ML_MLOPS_RUNBOOK.md`.

## 7. Verify the install

```powershell
python -m pytest tests -q        # full suite; ~8 min
python run_e2e.py                # end-to-end simulation against a scratch database
```

Run pytest on `tests` rather than the repository root, so it does not try to collect any
nested checkout.

## 8. When something does not work

| Symptom | Cause and fix |
|---|---|
| `yara-python` fails to install | Python 3.14. Use 3.13. |
| Threat Hunting page says the ML layer is unavailable | `pip install -r requirements-ml.txt`, then restart the server |
| Threat Hunting page loads but every engine is offline | no models yet — §5 |
| Endpoint bootstrap: "cannot connect" | the server is bound to 127.0.0.1, the firewall rule is missing, or the advertised address is on a network the endpoint cannot reach (`docs/DEPLOYMENT.md`) |
| `python -m ml.mlops run` → "live database not found" | start the server once first (§3) |
| Weekly job exits 2 | not a failure: the run completed and its report has a *Needs attention* section (`mlops\runs\<run id>\REPORT.md`) |
| A model looks wrong after an update | `python -m ml.mlops rollback <anomaly\|triage\|tactic>` restores the previous one |

## Where to read further

| File | Content |
|---|---|
| `README.md` | what the framework is, layer by layer |
| `docs/DEPLOYMENT.md` | servers, agents, enrollment, Sysmon, scheduled collection |
| `docs/ML_ARCHITECTURE.md` · `docs/ML_PROGRESS.md` | ML design, and the measured state of every phase |
| `docs/ML_MLOPS_PLAN.md` · `docs/ML_MLOPS_RUNBOOK.md` | the weekly pipeline: design, then operation |
| `reports_ml/MODEL_CARDS.md` | each model's intended use, metrics and limits |
| `docs/LIMITATIONS.md` | what this framework does not do |
