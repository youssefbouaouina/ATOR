# ATOR DFIR — Endpoint Investigation & Threat Hunting Framework

Lightweight, automated DFIR and threat-hunting framework for endpoint investigation.
Collects forensic artifacts from Windows / Linux / Docker-host endpoints, detects
threats with YARA + Sigma + IOC correlation, enriches findings with official MITRE
ATT&CK data (fully offline), reconstructs the attack chain, and produces
investigator-ready reports.

## Architecture (6 layers)

```
L0  Target endpoints      Windows / Linux VMs / Docker hosts
L1  Collector agent       Python, volatility-first order, SHA-256 evidence manifests
L2  Ingestion API         FastAPI, bearer-token auth, audit log, 202-accepted queue
L3  Storage               SQLite (WAL), raw_* tables + detections + manifests
L4  Detection engine      YARA scanner, Sigma->SQL runner (pySigma validated),
                          IOC correlator against local watchlist/feeds
L5  Enrichment & mapper   Official MITRE STIX JSON parsed locally; tactic/technique/
                          data-sources enrichment; SoC attack-chain builder
L6  Dashboard & reports   Jinja2+Bootstrap+Chart.js UI, PDF (ReportLab),
                          JSON, STIX 2.1 bundle, ATT&CK Navigator layer export
```

## Quick start (Windows)

```powershell
cd ator-dfir
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt

# one-time: fetch MITRE ATT&CK data (~46 MB)
.venv\Scripts\python scripts\update_mitre.py

# terminal 1 - server
.venv\Scripts\python -m server.app          # http://127.0.0.1:8000

# terminal 2 - enroll an endpoint & collect once
$env:ATOR_SERVER_URL="http://127.0.0.1:8000"
.venv\Scripts\python scripts\linux_enroll_once.py   # works on Windows too
```

Open the dashboard: `http://127.0.0.1:8000`

## Verification status (all live)

| Check | Result |
|---|---|
| Unit + integration tests (`pytest`) | 30/30 PASS |
| Full E2E simulation (`run_e2e.py`) | 20/20 PASS |
| Real Windows collection → detection → PDF | PASS |
| Real Ubuntu (WSL) collection (34 proc, 582 log events, cron persistence) | PASS |
| Linux attack simulation detected (T1059.004, T1071.001) enriched | PASS |
| Docker-host agent inventorying containers via socket | PASS |

## Repository layout

```
agent/            portable collector (volatile-first ordering)
server/           FastAPI app, engine modules, dashboard templates
rules/malware     YARA rules (.yar)
rules/behavioral  Sigma rules (.yml)
scripts/          update_mitre, atomic_runner, bootstraps, sysmon installer
tests/            pytest suite
docs/             deployment, methodology, limitations, validation
run_e2e.py        end-to-end verification harness
```

## Safety model

Containment runs in **DRY-RUN mode**: the approval workflow, cooldowns and audit
trail are fully functional but no action is ever executed on an endpoint.
See docs/LIMITATIONS.md for the full honest-limits statement.
