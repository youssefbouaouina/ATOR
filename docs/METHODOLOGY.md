# Investigation Methodology

## Collection order (RFC 3227 volatility-first)

The agent collects in this fixed order and records it in every evidence manifest:

1. **Network connections** — most volatile; lost on reboot
2. **Running processes** — with SHA-256 of each executable image
3. **Persistence mechanisms** — registry Run/RunOnce, services, scheduled tasks,
   startup folders (Windows); cron + systemd timers (Linux)
4. **Logs** — Sysmon/Security/System/Application via evtx parsing with
   PowerShell EventLog-API fallback; auth.log/syslog/journald (Linux)
5. **Targeted file triage** — temp dirs, startup folders, cron.d; hashed;
   optional local YARA pre-scan
6. **Container inventory** — docker socket inspection, cgroup process mapping,
   port-mapping attribution

## Forensic soundness

- Every collection produces an **evidence manifest**: UTC start/end timestamps,
  hostname, agent version, per-collector artifact counts and SHA-256 of the
  serialized artifact sets, plus a manifest-level SHA-256.
- The server verifies and stores manifests in `evidence_manifests`; reports
  include the manifest hashes so any post-hoc tampering is detectable.
- All timestamps are normalized to UTC at ingestion; the timeline engine flags
  events that deviate from the host baseline by more than 45 days (time skew).

## Detection pipeline

1. Raw artifacts land in `raw_*` tables (processes, connections, persistence,
   logs, files).
2. **Sigma rules** (`rules/behavioral/*.yml`) are validated by pySigma then
   translated into parameterized SQLite queries against those tables.
   Supported modifiers: `contains`, `endswith`, `startswith`, `re`, `base64`,
   `gt/gte/lt/lte`, `all`, wildcards. Conditions support `and/or/not`,
   `1 of X*`, `all of them`.
3. **YARA rules** (`rules/malware/*.yar`) run agent-side during file triage
   (metadata-only upload: paths+hashes+match names) and server-side on uploaded
   samples (`POST /api/v1/samples`).
4. **IOC correlation** matches collected hashes/IPs against `ioc_store`
   (analyst watchlist or imported feeds such as abuse.ch/MISP exports).
5. The **MITRE mapper** enriches every detection carrying a technique ID from
   the official STIX bundle: technique name, tactics, platforms, data sources,
   description. No hardcoded mappings — 100% derived from MITRE data.
6. The **SoC builder** orders enriched detections along the ATT&CK kill chain
   (execution → persistence → privilege-escalation → … → C2) to reconstruct
   the attack story per host.

## Reporting

PDF report structure: verdict-first executive summary with risk level →
observed attack chain table → color-coded ATT&CK matrix (observed tactics
highlighted) → technical annex (key detections, evidence manifest integrity,
timeline statistics). Machine-readable outputs: JSON report, STIX 2.1 bundle
of observed indicators, ATT&CK Navigator layer JSON showing detection coverage.
