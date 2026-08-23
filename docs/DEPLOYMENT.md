# Deployment Guide

## Server (central)

Requirements: Python 3.10+, pip. Tested on 3.12 (Windows) and 3.14 (Ubuntu).

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt     # Windows: .venv\Scripts\pip
python scripts/update_mitre.py                # one-time ATT&CK data download
python -m server.app                          # binds 127.0.0.1:8000
```

Production notes:
- Bind to `0.0.0.0:8000` only behind TLS (reverse proxy such as Caddy/Nginx).
- Set `ATOR_DFIR_DB=/var/lib/ator/ator.db` to control DB location.
- The database auto-creates with WAL journaling; schedule filesystem backups of
  the single `.db` file plus its `-wal` companion.

## Agents

Each endpoint needs: this repository (or a packaged copy), Python, and outbound
HTTPS to the server.

Windows (PowerShell):
```powershell
scripts\bootstrap_agent.ps1 -BaseUrl http://SERVER:8000
```

Linux / Docker host (bash):
```bash
scripts/bootstrap_agent.sh http://SERVER:8000
```

Continuous mode: `python -m agent.agent loop` collects every N seconds
(configurable via `agent/config.json`) and spools+retries on server outage
(exponential-safe local queue in `spool/`).

Environment overrides:
- `ATOR_AGENT_CONFIG` — alternate config file path (multi-agent hosts)
- `ATOR_DFIR_DB` — server DB location

## Sysmon (recommended on Windows endpoints)

Run once from an elevated PowerShell:
```powershell
scripts\install_sysmon.ps1
```
Installs Sysmon64 with the bundled baseline config (`scripts/sysmon-config.xml`).
The agent automatically prefers the Sysmon operational log when present.

## Atomic Red Team validation

See docs/VALIDATION.md. Requires an isolated test VM with admin PowerShell.
