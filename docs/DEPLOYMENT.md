# Deployment Guide

## Server (central)

Requirements: Python 3.10+, pip. Tested on 3.12 (Windows) and 3.14 (Ubuntu).

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt     # Windows: .venv\Scripts\pip
python scripts/update_mitre.py                # one-time ATT&CK data download
python -m server.app                          # binds 0.0.0.0:8000
```

If agents run on VMs/LAN (e.g. VMware VMnet lab, 192.168.50.0/24), allow inbound
TCP 8000 on the host and point endpoints at the **host LAN IP** (`ipconfig`),
never `127.0.0.1`:

```powershell
New-NetFirewallRule -DisplayName "ATOR Server" -Direction Inbound -Protocol TCP -LocalPort 8000 -Action Allow
```

Production notes:
- Bind to `0.0.0.0:8000` only behind TLS (reverse proxy such as Caddy/Nginx).
- Set `ATOR_DFIR_DB=/var/lib/ator/ator.db` to control DB location.
- The database auto-creates with WAL journaling; schedule filesystem backups of
  the single `.db` file plus its `-wal` companion.

## Agents

Each endpoint needs only the agent package, Python, and outbound connectivity
to the server. Two deployment paths:

### Path A — full repo already on the machine (dev / same-box testing)
```powershell
scripts\bootstrap_agent.ps1 -BaseUrl http://SERVER:8000
```
Linux (bash): `scripts/bootstrap_agent.sh http://SERVER:8000`
(This installs `agent/requirements.txt` — the agent's own dependency set.)

### Path B — packaged deploy to a remote endpoint (recommended for VMs)
On the host:
```powershell
scripts\deploy_agent.ps1 -Mode package          # -> scripts\out\ator-agent-deploy.zip
```
Ship + extract on the endpoint, then:
```powershell
scripts\deploy_agent.ps1 -Mode endpoint `
    -BaseUrl http://192.168.50.1:8000 `
    -AgentRoot <extract-dir> -InstallDir C:\ator-agent `
    [-InstallScheduledTask]
```
Installs venv with agent-only deps, enrolls (`os_type` = real OS; Docker engine
presence is recorded separately as `docker_engine_flag`), runs a verification
collection.

Missing Python on a fresh Windows VM (winget absent in some images):
```powershell
Invoke-WebRequest https://www.python.org/ftp/python/3.12.10/python-3.12.10-amd64.exe -OutFile py-inst.exe
.\py-inst.exe /quiet InstallAllUsers=1 PrependPath=1 Include_test=0   # new shell afterwards
```

## Scheduled automatic diagnostics

Two layers:

| Layer | Mechanism | Config |
|---|---|---|
| Collection cadence (once process runs) | `loop` mode: flush spool -> collect -> POST -> sleep | `collection_interval_seconds` in `agent/config.json` (default 60) |
| Auto-start at boot (survives reboot) | Windows Scheduled Task or systemd unit | see below |

Windows — automatic via deploy script or manual:
```powershell
Register-ScheduledTask -TaskName "ATOR Agent Loop" -Force `
  -Action   (New-ScheduledTaskAction -Execute "C:\ator-agent\.venv\Scripts\python.exe" -Argument "-m agent.agent loop" -WorkingDirectory "C:\ator-agent") `
  -Trigger  (New-ScheduledTaskTrigger -AtStartup) `
  -Principal (New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest)
schtasks /run /tn "ATOR Agent Loop"
```

Linux — template provided; edit install dir/URL then:
```bash
sudo cp scripts/ator-agent.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now ator-agent
```

Server-side dedup/watermarking makes repeated loop collections idempotent —
no duplicate detections accrue.

Environment overrides:
- `ATOR_SERVER_URL` — server URL; precedence: env var > config.json > built-in default
- `ATOR_AGENT_CONFIG` — alternate config file path (multi-agent hosts)
- `ATOR_DFIR_DB` — server DB location

## Sysmon (recommended on Windows endpoints)

Run once from an elevated PowerShell:
```powershell
scripts\install_sysmon.ps1
```
Downloads Sysmon64 from Sysinternals Live and installs it with the bundled
tuned config (`scripts/sysmon-config.xml`). Enabled Event IDs are chosen to
match what the collector forwards and the timeline consumes:

| EID | Channel purpose | Noise handling |
|-----|------------------|----------------|
| 1 ProcessCreate | cmdline/exe/sha256 evidence | conhost + EdgeUpdate excluded |
| 3 NetworkConnect | beacon/C2 evidence | loopback/broadcast excluded |
| 7 ImageLoad | LOLBIN & injection DLL evidence | System32/SysWOW64/WinSxS loads excluded |
| 8 CreateRemoteThread | injection (T1055) | none |
| 11 FileCreate | droppers/artifacts | browser-cache/temp churn excluded |
| 13 RegistryEvent(Value) | Run keys/services persistence | MuiCache/HKU\.DEFAULT excluded |
| 22 DnsQuery | domain-based hunting | MS/NCSOCDN probers excluded |

Service name is `Sysmon64` (verify: `Get-Service Sysmon64`). Update an existing
install later with `Sysmon64.exe -c sysmon-config.xml`. The rolling collection
window per source defaults to 300 events (`max_events_per_source`) — keep
chatty exclusions in place so interesting events survive the window.

The agent automatically prefers the Sysmon operational log when present;
otherwise falls back to PowerShell `Get-WinEvent`.

## Atomic Red Team validation

See docs/VALIDATION.md. Requires an isolated test VM with admin PowerShell.
