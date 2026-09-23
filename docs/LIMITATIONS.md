# Honest Limits — What This Framework Does NOT Detect

Stating blind spots is part of the methodology. This tool is a triage and
threat-hunting aid, not a full EDR.

## Collection gaps

- **No memory acquisition.** Fileless malware, injected code and in-memory
  credentials are invisible. Integrate Volatility 3 workflows before relying on
  this for such cases.
- **No full disk forensics.** Prefetch, Shimcache, Amcache, UserAssist,
  ShellBags, LNK/Jump Lists, $MFT, USN journal, RDP cache and USB history are
  not collected. The framework is KAPE-*inspired*, not KAPE-equivalent.
- **Security.evtx requires elevation** on Windows; without admin the agent
  falls back to the EventLog API (works for System/Application, may still fail
  for Security depending on policy) and records the access denial as evidence.
- **Linux coverage is log/cron/process based** — no auditd/eBPF telemetry.
- **Container attribution is best-effort**: inventory via the Docker socket is
  reliable; process↔container mapping relies on cgroup paths visible to the
  agent (`--pid=host` or native engine). Port-mapping attribution is heuristic.

### Velociraptor deep-dive artifacts

- Require a `velociraptor` binary on the endpoint; without it a sweep fails with
  that reason recorded and nothing is collected.
- On Windows the agent must run elevated (SYSTEM via the scheduled task, or an
  Administrator shell). The binary's manifest requests `highestAvailable`, so a
  non-elevated agent cannot launch it at all - WinError 740, reported as the
  sweep's failure reason.
- Restricted to the allow-list in `agent/velociraptor_catalog.py`. This is
  deliberate (the command channel would otherwise be arbitrary VQL execution)
  but it does mean the full Velociraptor artifact library is not reachable.
- Artifact parameters are not exposed; every artifact runs with its defaults.
- Capped at 500 rows per artifact and 8 KB per row. A truncation marker row is
  stored so the cap is visible, but the discarded rows are gone.
- Run on demand only. A sweep reflects the endpoint at the moment it ran, so an
  artifact that came back clean says nothing about the hours before or after.

## Detection gaps

- Sigma translation covers field-based selections over process/network tables;
  correlation rules, aggregations (`count() by`) and non-process/network
  log sources fall back to documented "unsupported" status rather than
  silently misfiring.
- YARA scanning depends on what file triage reaches (< cap sizes); large or
  excluded paths are never scanned.
- IOC feeds are only as good as their curation; no automatic reputation
  scoring, no sandbox detonation.

## Operational limits

- SQLite suits lab/small-fleet use (tens of endpoints). At hundreds of hosts,
  move to PostgreSQL + queue.
- Containment is **dry-run by design** in this build: approvals are audited but
  never executed. Wire real actions only after testing `agent` task-polling
  command channels with allow-listing for the server IP.
- The web UI has no authentication (bind it to localhost or front it with an
  authenticating proxy). Since Phase 10 this also covers the analyst verdicts on ML leads,
  which feed the weekly retrain: anyone who can reach the dashboard can mark a lead benign.
  The pipeline limits the damage (a rule hit always overrides a verdict, re-admissions are
  capped at 200 per run and listed in each run report, and every future model must still
  catch confirmed threats), but only authentication removes it.
- Agent-server channel uses HTTPS bearer tokens; mTLS and payload signing are
  future work.

## Privacy & compliance notes

Collection includes command lines, usernames and file paths — personal data in
most jurisdictions. Apply data-minimization config, retention limits and
workplace-monitoring disclosure obligations (e.g., GDPR) before production use.
