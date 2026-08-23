# Validation & Regression

## Automated regression (runs anywhere)

```bash
pytest tests -q          # 30 unit/integration tests
python run_e2e.py        # 20-check end-to-end pipeline verification
```

`run_e2e.py` boots a real server on a scratch DB, enrolls three hosts
(Windows live agent + synthetic Linux + Docker host), runs the detection
engine and asserts: sigma rules fire, MITRE enrichment attaches official
names/tactics, SoC chain builds, timeline is UTC-sorted, dry-run containment
workflow completes, PDF/JSON/STIX/Navigator exports generate, all six
dashboard pages render.

## Atomic Red Team (isolated test VM)

1. Create a snapshot-protected Windows test VM.
2. Install Sysmon: elevated `scripts\install_sysmon.ps1`.
3. Enroll the VM's agent to the server.
4. From an admin PowerShell on the VM:
   ```powershell
   Install-Module -Name Invoke-AtomicRedTeam -Force
   Invoke-AtomicTest T1059.001          # PowerShell encoded command
   Invoke-AtomicTest T1053.005          # Scheduled task creation
   ```
5. On the server host, verify detections:
   ```powershell
   .venv\Scripts\python scripts\atomic_runner.py --technique T1059.001 --check-db
   # or the whole catalog:
   .venv\Scripts\python scripts\atomic_runner.py --check-db
   ```

The runner prints `[PASS] T1059.001 detected and enriched successfully.` style
lines and exits non-zero on regression — usable as a CI gate after any rule
change.

## Live multi-platform evidence (2026-08-23)

| Platform | Method | Evidence |
|---|---|---|
| Windows 10 host | native agent run | manifest `beca9998…`, processes+evtx+registry collected |
| Ubuntu 26.04 (WSL2) | in-distro venv + agent | 34 processes, 582 log events, cron persistence |
| Docker host | agent container w/ `--pid=host` + socket mount | inventoried running containers incl. third-party image |
| Linux attack sim | synthetic dropper artifacts | T1059.004 "Unix Shell" + T1071.001 fired & enriched |

## Rule change protocol

1. Edit/add rule under `rules/`.
2. `pytest tests/test_sigma.py tests/test_ioc_yara.py` — validation + fixture hits.
3. Run ART catalog against the test VM (`atomic_runner.py --check-db`).
4. Commit with the technique ID in the message.
