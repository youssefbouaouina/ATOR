# Merging DFIR-only into ML — what was found, and what changed

**Date:** 2026-09-21 · **Branch:** `ML` · **Audience:** youssef (DFIR track) and hazem (ML track)

This note exists because the merge touched DFIR code, not just ML code. Every change below
was **reproduced through the real `/api/v1/ingest` endpoint before it was fixed**, has a test
that fails on the original code and passes on the fix, and is listed here with its reason so
it can be reviewed rather than discovered.

---

## 1. How the merge was done

`main` (`abf3b6a`, 2026-09-19) is *already* DFIR-only (`8c99869`) merged with ML (`49f608e`),
including youssef's resolution of the 11 files both branches had changed. So `ML` was
**fast-forwarded to `main`** rather than merging `DFIR-only` again:

* it contains 100% of DFIR-only — verified with `git merge-base --is-ancestor`;
* it keeps youssef's conflict resolutions instead of re-resolving the same 11 files
  differently, which would have created divergent history to reconcile later.

youssef's merge resolutions were reviewed file by file. They are sound: the ML code arrived
intact, and the two places he adapted (the ETL and one test drop the new dedupe indexes)
were correct calls. The one product decision worth recording is that **the ML Conf/Src
columns on the Investigation page were dropped** in favour of his grouped-findings redesign;
ML confidence now lives only on the ML page. That was left as he decided it.

**Runtime files.** DFIR-only stops tracking databases, `agent/config.json` and
`reports_out/`. A fast-forward deletes such files from the working tree, which would have
removed the live `ator_dfir.db` and the agent's enrollment. All 26 were backed up to
`backups/pre-dfir-merge-20260921/`, byte-verified, and restored after the merge; they are
now ignored by the merged `.gitignore`. The live database hash was unchanged.

**`.gitignore`.** The merge lost the `ATOR/` line that ignores a duplicate clone nested in
the working tree; without it `git add -A` would stage it as an embedded repository.
Restored.

---

## 2. Defects found after the merge

The merged branch was green — **449 passed, 0 failed** — while all four of these were live.
None of them was covered by a test.

### 2.1 Distinct log events in the same second were collapsed into one  · DFIR

| | |
|---|---|
| **Where** | `server/db.py` `ux_raw_logs_dedupe`, `server/api.py` `_insert_log` |
| **Key was** | `(host, source, event_time, event_id, provider)` |
| **Problem** | The agent records event times **to the second** (`timespec="seconds"`). Any two *different* events from one source with the same event id in the same second collided; all but the first were silently dropped. |
| **Reproduced** | `whoami`, `net user`, `ipconfig` launched together → **1** process-creation event stored out of 3. youssef's own test hit the same thing with two DNS queries in one second (one of them to a C2 domain) and worked around it by dropping the index. |
| **Security impact** | Exactly the bursts attackers produce: a discovery chain, a brute force of failed logons in one second. Any rule that counts events under-counts. |
| **Fix** | New `raw_logs.payload_sha256` (hash of the canonical payload), added to the key as `ux_raw_logs_dedupe_v2`. Re-sent copies of an event are byte-identical, so the original intent — the agent's overlapping re-send window is still stored once — is preserved and tested. |

### 2.2 A new process that reused a PID inherited the old one's identity  · DFIR

| | |
|---|---|
| **Where** | `ux_raw_processes_dedupe`, the process `_upsert_observation` call |
| **Key was** | `(host, pid, name, cmdline, exe, sha256)` |
| **Problem** | Windows recycles PIDs. A new process with a reused PID and an identical command line (e.g. `conhost.exe 0xffffffff -ForceV1`, or a scheduled task re-launching the same script) matched the old row, and the refresh kept the **old instance's parent PID and start time**. |
| **Reproduced** | New instance (parent 900, started 11:00) recorded as parent 700, started 09:00. |
| **Fix** | `create_time_utc` added to the key (`ux_raw_processes_dedupe_v2`). (PID, start time) is how the OS itself identifies a process. For agents that do not report a start time the column is NULL and **v2 behaves exactly like v1** — tested. |

**Upgrade path.** `upgrade_dedupe_indexes()` runs at startup and swaps a v1 index for its v2
successor. It cannot fail: each v2 key is its v1 key plus one column, so rows unique under v1
stay unique under v2. A legacy store that never had the indexes is left alone — building
them is still `scripts/purge_host_data.py`'s job, exactly as before. `drop_dedupe_indexes()`
replaces the hard-coded list of index names in the ML ETL, which would otherwise have missed
the v2 rename.

### 2.3 A long-running suspicious process was re-reported on every sweep  · ML

| | |
|---|---|
| **Where** | `server/engine/ml_integration.py` |
| **Problem** | ML findings were keyed on `(host, collection, raw row)`. The merged ingest moves a re-observed process into the newest collection, so the key changed every sweep. |
| **Reproduced** | 1, 2, 3 detections for the same process over three sweeps — 60 an hour with the agent's default loop. It already happened in a weaker form before the merge. |
| **Fix** | Findings are keyed on a **process identity** mirroring the v2 process key. A process flagged again is folded into its finding (`hit_count`, `last_seen_utc`), the convention youssef's `insert_detections` uses for rule hits, and only genuinely new findings return ids for enrichment and policies. Findings recorded before this change have their identity rebuilt from the raw row, so the upgrade does not create one last duplicate. |
| **Found in the UI** | A sighting only counts when the observation is **newer** than the last one counted. Without that check, each manual "Run hunt now" (which rescans history) re-counted old sweeps. |

### 2.4 Sysmon features vanished after a process's first sweep  · ML

| | |
|---|---|
| **Problem** | Logs are stored **once**, in the collection where they first arrive; a re-observed process **moves** to the newest collection. Sysmon (T2) features join events to processes within one collection. |
| **Reproduced** | Sweep 1: 5 unsigned image loads. Sweep 2, same process still running: served to the T2 model as `sysmon_available = 0`, image loads NaN. Every T2 training row has `sysmon_available = 1`, so this is input the model never saw. |
| **Fix (interim)** | `choose_tier` now serves **T1 by default**. It previously auto-upgraded any Sysmon host to T2. T1 reads no logs and is unaffected; it is also what the evaluation already recommended for all three models, since T2 has never beaten T1 outside the noise band. `ATOR_ML_TIER=t2` still opts in, but only on hosts with Sysmon. |
| **Still to do** | Join Sysmon/PowerShell events to a process by **(host, pid, start time)** across collections, instead of within one collection. That is a feature-computation change and must be re-validated against the corpus before T2 can be the default again. |

---

## 3. The ML page, rewritten for security readers

The page is now **Threat Hunting** (`/ml`). It is written for a security analyst, not a data
scientist. All translation happens in `server/engine/ml_vocabulary.py`, so it is testable:

| Before | After |
|---|---|
| ML Behavioural Analytics | Behavioural Threat Hunting |
| Anomaly triage queue | Behavioural leads, ordered by threat likelihood |
| Sev (from rarity alone) | Priority P1–P4, from threat likelihood; severity moved into the evidence |
| Confidence 0.81 | Threat likelihood: High · 81% |
| Anomaly 0.9990 | Rarity: Top 0.1% |
| `lateral_movement 100%` | Lateral Movement TA0008 (advisory) |
| `conn_max_remote_port ×51665.0` | "Connects to an unusually high remote port", with strength bars |
| Models / PR-AUC 0.549 | Detection engines: "23 of its 25 highest-ranked leads were real attacks" |
| Feature drift (PSI) | Data health: Healthy / Watch / Degraded |
| Score now / Recompute risk | Run hunt now / Refresh host risk |

Also new:

* A click-to-expand **evidence** panel per lead: PID, parent, account, image path, full
  command line, first and last seen, sighting count, and every indicator.
* Indicators now say *which way* a process differs ("spawns many child processes" versus
  "spawns fewer"), because `explain()` now records direction.
* Guards: a new feature without an analyst-facing label fails the build, and no performance
  sentence can appear unless the model artefact carries the number behind it.
* Nothing was removed. Raw feature names stay as tooltips, and a collapsed **Technical
  details** section keeps PR-AUC, the spec hash and the gate thresholds.

The nav entry "ML Analytics" in `base.html` became "Threat Hunting"; the URL is unchanged.

---

## 4. Known and not changed

* **`System Idle Process` (PID 0) appears as a lead.** psutil attributes leftover TIME_WAIT
  sockets to it, which the anomaly engine finds unusual. Its threat likelihood is 0%, so it
  sorts to the bottom as P4. Excluding OS pseudo-processes from scoring is a sensible
  follow-up; it was not done because it changes what the model scores.
* **Agent command-line visibility.** Data health reads *Degraded* on this workstation
  because an unelevated agent cannot read 36% of command lines, and command-line features are
  the second most important family. Run the agent elevated.

---

## 5. Verification

| | |
|---|---|
| Post-merge suite, before fixes | 449 passed, 1 skipped, 0 failed |
| Final suite | **513 passed, 1 skipped, 0 failed** (from 449 after the merge) |
| New tests | `test_dedupe_identity.py` (17 test functions). Run against the original merged code, 14 of the first 16 fail; the other 2 guard behaviour that must not change. The 17th covers the sighting inflation found in the UI. |
| | `test_ml_vocabulary.py` (27 test functions, parametrised): every translation rule, plus the guards |
| Live check | real agent sweep of this workstation → scratchpad copy of `ator_dfir.db` → **Run hunt now** clicked in the browser; evidence panel, priorities and data health inspected |
| Live database | never written; hash `fae2a103…` before and after |
