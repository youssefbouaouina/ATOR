# Capability Demo (Windows + Linux)

The capability demos put **harmless, uniquely-marked** signals on a live
endpoint and let the normal agent collection + server engine turn them into
real detections spanning the full attack kill chain, then remove everything
again. Nothing malicious happens: holder processes only print a marker string
and sleep, the "trojan" is a text file, and the only real network connection is
a loopback socket to a local listener.

| Stage (MITRE tactic) | Signal | Rule that fires | Technique |
|---|---|---|---|
| Initial Access | phishing link clicked / attachment opened | Phishing Link Click / Malicious Attachment (Demo) | T1204.001 / T1566.002 |
| Execution | malware dropper (`curl … \| bash`) | Malware Dropper (Demo) + Linux Curl/Wget Piped to Shell | T1105 / T1059.004 |
| Execution | suspected internal / intentional run | Suspected Internal Execution (Demo) | T1059 |
| Persistence | cron + base64 obfuscation | Base64 Cron Persistence Modification | T1053.003 |
| Command & Control | botnet beacon + real loopback:4444 socket | Botnet / C2 Beacon (Demo) + Reverse Shell Destination Ports | T1071.001 / T1571 |
| Collection | spyware / keylogger | Spyware / Keylogger Activity (Demo) | T1056.001 |
| Impact | ransomware file-encryption | Ransomware Encryption Activity (Demo) | T1486 / T1490 |
| Delivery | dropped "trojan" file + hash watchlist | YARA `ATOR_DFIR_Demo_Trojan_Payload` + IOC hash match | T1204.002 |

Every detection is written to the report's **Root Cause Analysis** section with
its inferred root cause, where it happened (host + exact process / file /
network locus), and when (first-last seen, UTC).

## Prerequisite: the server must have pySigma

Behavioral (Sigma) rules only run when the server process has **pySigma**
installed. Start the server from the project venv:

```bash
.venv/Scripts/python -m server.app      # Windows
./.venv/bin/python -m server.app        # Linux
```

If it is missing, only YARA + IOC detections appear; the demo prints a warning
saying so. Verify quickly with `POST /api/v1/engine/run` - the `errors` array
must not contain `pysigma-not-installed`.

## Windows endpoint

Run on the enrolled Windows host (same machine as the server, or adjust
`-ServerUrl` / `-DbPath`):

```powershell
powershell -ExecutionPolicy Bypass -File scripts\demo_windows_capabilities.ps1 -ServerUrl http://127.0.0.1:8000
# undo a run early:
powershell -ExecutionPolicy Bypass -File scripts\demo_windows_capabilities.ps1 -Cleanup
```

The Windows demo self-elevates (the agent runs as SYSTEM), deploys the YARA
rules into the agent, drops the marker files, registers the hash IOC, starts the
marker + encoded-PowerShell + reverse-shell processes, forces a scan, then
purges everything after `-CleanupAfterMinutes` (default 3).

## Linux endpoint

Run on the enrolled Linux endpoint (needs the agent at `--agent-root`, default
`/opt/ator-agent`). Use the server's LAN IP, not `127.0.0.1`, from a VM:

```bash
sudo bash scripts/demo_linux_capabilities.sh --server http://SERVER:8000
# undo a run early:
sudo bash scripts/demo_linux_capabilities.sh --server http://SERVER:8000 --cleanup
```

Options: `--hold-seconds` (how long signals stay live; must exceed the agent
collection interval, default 150), `--cleanup-after-minutes` (total window
before auto-purge, default 3), `--agent-root`.

The Linux demo talks to the server over the API only. It resolves its own host
by client-id, registers the hash IOC, spawns the marker holders (via `exec -a`
so the marker is the process command line) plus a loopback:4444 socket, waits
for a collection, forces a scan, then calls the host-authenticated
`POST /api/v1/demo/purge` to remove its own demo data from the server - so it
works on a remote VM with no shell access to the server host.

## What "delete everything after" removes

Both demos, on cleanup, remove: the holder processes, the dropped marker files,
the demo hash IOC, and - scoped to the demo markers, the demo IOC source, and
loopback port 4444, for that host only - the collected raw rows, the demo
detections, and the demo-only evidence manifests. Real telemetry collected
during the demo window is untouched.

Tested live: Windows 10 sandbox; Ubuntu 22.04 / Debian 12 / Rocky 9 containers
enrolled via the bootstrap, producing all twelve kill-chain detections and a
clean purge.
