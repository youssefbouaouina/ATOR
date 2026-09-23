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

Prefer limiting that rule to the endpoint subnet. The dashboard and the enrollment-approval
API have no login, so anything that can reach port 8000 can approve an enrollment. A
server on a laptop would otherwise also be open on its home or office Wi-Fi:

```powershell
New-NetFirewallRule -DisplayName "ATOR Server (lab subnet)" -Direction Inbound -Protocol TCP -LocalPort 8000 -RemoteAddress 192.168.50.0/24 -Action Allow
```

### The address in generated enrollment commands

The enrollment status page (`/enroll/status/<token>`) builds a copy-paste bootstrap command
that embeds the server's URL. That URL is chosen in this order (`server/ui.py`,
`enrollment_server_url`):

1. **`ATOR_PUBLIC_URL`**, if set, is used as-is. Use it for a DNS name, a reverse proxy or NAT.
2. **The address the page was opened with**, unless it is loopback. Whoever is viewing the
   page already reached the server there.
3. **This server's address on `ATOR_ENROLL_SUBNET`** (comma-separated CIDRs, default
   `192.168.50.0/24`). This covers viewing the page on the server itself via `localhost`.
4. The default-route interface, as a last resort.

A multi-homed host is why step 3 exists. A laptop running the server with Wi-Fi plus
several VMware adapters would otherwise advertise its Wi-Fi address, which lab VMs on
VMnet2 cannot reach:

```powershell
$env:ATOR_ENROLL_SUBNET = "192.168.50.0/24"      # the default; set it for other networks
python -m server.app
```

Production notes:
- Bind to `0.0.0.0:8000` only behind TLS (reverse proxy such as Caddy/Nginx).
- Set `ATOR_DFIR_DB=/var/lib/ator/ator.db` to control DB location.
- The database auto-creates with WAL journaling; schedule filesystem backups of
  the single `.db` file plus its `-wal` companion.

## Agents

Each endpoint needs only the agent package, Python, and outbound connectivity
to the server.

### Recommended: approval-based token enrollment (Windows and Linux)

1. On the endpoint (or for it), open `http://SERVER:8000/enroll` and submit a
   request with the hostname and OS (Windows, Linux, or Docker Host).
2. An analyst accepts it on `/enrollments`.
3. The status page (`/enroll/status/<request-token>`) then shows a one-line
   command for that OS. Run it on the endpoint:

   Windows (cmd or PowerShell, self-elevates):
   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest -UseBasicParsing -Uri 'http://SERVER:8000/static/bootstrap_endpoint.ps1' -OutFile ([IO.Path]::GetTempPath() + 'ator_bootstrap.ps1'); & ([IO.Path]::GetTempPath() + 'ator_bootstrap.ps1') -ServerUrl 'http://SERVER:8000' -EnrollmentToken '<token>' -EnablePersistence"
   ```
   Linux, including Docker hosts (needs curl or wget and sudo):
   ```bash
   (curl -fsSL 'http://SERVER:8000/static/bootstrap_endpoint.sh' || wget -qO- 'http://SERVER:8000/static/bootstrap_endpoint.sh') > /tmp/ator_bootstrap.sh && sudo bash /tmp/ator_bootstrap.sh --server 'http://SERVER:8000' --token '<token>'
   ```

Both bootstraps follow the same steps: check the server is reachable, install
Python if needed, download the agent package, create a venv, enroll with the
token, run one verification collection, and set the agent to start at boot.

| | Windows (`bootstrap_endpoint.ps1`) | Linux (`bootstrap_endpoint.sh`) |
|---|---|---|
| Python | installs 3.12 from python.org if no 3.8+ found (ignores the Store stub) | installs via apt / dnf / yum / zypper / apk / pacman (RHEL 8: python3.11 or python39) |
| Package | `/static/ator-agent-deploy.zip` | `/static/ator-agent-deploy.tar.gz` |
| Install dir | `C:\ator-agent` (`-InstallDir`) | `/opt/ator-agent` (`--install-dir`) |
| Persistence | Scheduled Task `ATOR Agent Loop` (SYSTEM) | systemd unit `ator-agent` (falls back to cron `@reboot`); `--no-persistence` to skip |
| Log | `C:\enroll_debug.log` | `/var/log/ator_enroll.log` |

The server builds both packages from the current `agent/` source (plus
`rules/malware` for local YARA) on each request, so endpoints never receive a
stale agent. `config.json` is never shipped. Re-running a bootstrap upgrades the
agent in place and keeps the existing credentials: if the token was already
used and the saved credentials still work, the agent reports `already_enrolled`.

Tested: Windows 10 (PowerShell 5.1); Ubuntu 22.04, Debian 12, Rocky Linux 9,
including a systemd install that runs the continuous loop.

### Manual deployment paths

#### Path A — full repo already on the machine (dev / same-box testing)
```powershell
scripts\bootstrap_agent.ps1 -BaseUrl http://SERVER:8000
```
Linux (bash): `scripts/bootstrap_agent.sh http://SERVER:8000`
(This installs `agent/requirements.txt` — the agent's own dependency set.)

#### Path B — packaged deploy to a remote endpoint (no approval step)
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

## Velociraptor (optional, for deep-dive artifacts)

The `/velociraptor` page runs forensic artifacts on an endpoint on demand. It
needs a standalone `velociraptor` binary present on that endpoint — ATOR does not
ship one. Download it from the
[Velociraptor releases page](https://github.com/Velocidex/velociraptor/releases)
and place it where the agent looks, in priority order:

1. `velociraptor_path` in `agent/config.json` (absolute path)
2. the `ATOR_VELOCIRAPTOR` environment variable
3. a `tools/` directory beside the agent install (`C:\ator-agent\tools\velociraptor.exe`)
elociraptor.exe`)
4. anywhere on `PATH`

**The agent must run elevated on Windows.** The binary's manifest requests
`highestAvailable`, so a non-elevated agent cannot launch it (WinError 740). The
scheduled-task deployment (SYSTEM) satisfies this; a manual `python -m agent.agent
loop` needs an Administrator shell.

The agent probes for it on heartbeat (cached 15 min) and the Velociraptor page
reports `ready` / `absent` / `unknown` per endpoint, so you can confirm placement
before queueing a sweep. Endpoints without the binary are unaffected — every
other part of the agent works exactly as before.

Full design, the artifact allow-list and its limits: docs/VELOCIRAPTOR.md.

## Weekly ML model updates (server)

The ML models retrain, evaluate, trial and deploy themselves once a week. That is optional:
without the schedule, the models in `models/` keep serving unchanged. To install it on the
server (Windows, current user, no admin):

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install_mlops_schedule.ps1
```

On Linux, use `scripts/ator-mlops.service` and `scripts/ator-mlops.timer`. Restart the server
once after updating, so the live trials can collect evidence. New models reach analysts only
after offline gates and a week of silent side-by-side scoring. Operation, reading the results
and every command: `docs/ML_MLOPS_RUNBOOK.md`. Design: `docs/ML_MLOPS_PLAN.md`.

## Atomic Red Team validation

See docs/VALIDATION.md. Requires an isolated test VM with admin PowerShell.
