# Deep-Dive Artifact Collection (Velociraptor)

ATOR's routine collectors take a broad, cheap snapshot every cycle. Some
questions need a narrower and far deeper look — what is in the prefetch cache,
which WMI event consumers are registered, what is in every user's
`authorized_keys`. This feature answers those on demand by running
[Velociraptor](https://docs.velociraptor.app/) artifacts on the endpoint.

Velociraptor is used here as a **tool, not a deployment**. There is no
Velociraptor server, no second enrolment, and no extra listening port on the
endpoint: a single standalone binary sits beside the ATOR agent and is executed
per sweep. Rows come home over the ingest path the agent already uses.

## How a sweep flows

```
Analyst (/velociraptor)                 Endpoint
   |  POST /api/v1/hosts/{id}/velociraptor
   |  -> validate against allow-list
   |  -> queue agent_commands('velociraptor_collect', args)
   |                                        |
   |         heartbeat (every ~20s) ------->|  claims the command
   |                                        |  re-validates the allow-list
   |                                        |  execs: velociraptor artifacts
   |                                        |         collect <name> --format json
   |<--- POST /api/v1/ingest ---------------|  rows + its own evidence manifest
   |
   v
 raw_velociraptor -> IOC / YARA correlation -> detections -> ATT&CK enrichment
```

A sweep is its own collection, with its own `collection_id` and evidence
manifest, because the rows are evidence and need the same integrity record as
everything else — and because an analyst-requested sweep should be attributable
to the moment it was asked for.

## The allow-list is the security boundary

`velociraptor_collect` travels over the same heartbeat command channel as
`collect_now`. Without a constraint, that channel would be able to run arbitrary
VQL on every endpoint. So artifact names are checked against
`agent/velociraptor_catalog.py` **twice**:

* the **server** validates before it queues a command, and
* the **agent** validates again before it execs anything.

Neither side alone decides what runs. Every catalog entry is a read-only,
data-gathering query; none modify the endpoint. Requests are also capped at
`MAX_ARTIFACTS_PER_REQUEST` artifacts and each artifact carries its own timeout.

Adding an artifact means adding it to the catalog — deliberately, so the set of
things ATOR can execute on an endpoint is reviewable in one file.

## Installing the binary on an endpoint

ATOR does not ship the Velociraptor binary (it is ~50 MB and separately
licensed). Download it from the
[Velociraptor releases page](https://github.com/Velocidex/velociraptor/releases)
and make it findable by one of, in priority order:

1. `velociraptor_path` in `agent/config.json` (absolute path)
2. the `ATOR_VELOCIRAPTOR` environment variable
3. a `tools/` directory beside the agent install — e.g. `C:\ator-agent\tools\velociraptor.exe`
4. anywhere on `PATH`

### The agent must run elevated

The Velociraptor Windows binary ships with an embedded manifest of
`requestedExecutionLevel level="highestAvailable"`. Under UAC that means it will
not launch at all from a non-elevated process - not "collects less", but refuses
to start, surfacing as:

    OSError: [WinError 740] The requested operation requires elevation

Install the agent as a SYSTEM scheduled task and this is solved permanently -
SYSTEM sits above Administrator, so there is no UAC prompt, and the task starts
at boot and restarts if it dies:

    # from an Administrator PowerShell, once:
    .\scripts\install_agent_service.ps1 -ServerUrl http://<server>:8000

That script also pins `ATOR_SERVER_URL`, which switches off the agent's LAN
auto-discovery. Discovery scans the subnet for anything answering `/health`, so
on a network with more than one ATOR server it can silently re-point an agent at
the wrong one.

Running `python -m agent.agent loop` in an ordinary shell does NOT satisfy the
elevation requirement, and running it in an Administrator window only satisfies
it for as long as that window stays open.

The probe reports this honestly rather than guessing: the page shows `absent`
with WinError 740 as the reason, and a sweep queued anyway comes back `failed`
with the same text, rather than a silent success with zero rows.

The agent probes for it and reports the result on each heartbeat (cached for 15
minutes, since the probe execs the binary). The `/velociraptor` page shows one of
three states per endpoint:

| State     | Meaning |
|-----------|---------|
| `ready`   | binary found; version reported |
| `absent`  | the agent looked and did not find it — the reason is shown |
| `unknown` | the agent has not reported a probe: it may predate this feature, or not have heartbeated since install |

`unknown` is deliberately distinct from `absent`. An agent that has not told us
the binary is missing has not told us it is present either.

## Artifact catalog

Defined in `agent/velociraptor_catalog.py`. Each entry declares its platforms,
category, cost, timeout and the ATT&CK technique it speaks to — the technique
feeds the normal enrichment path, so a finding from an artifact is mapped exactly
like a Sigma or IOC hit.

| Platform | Artifacts |
|----------|-----------|
| Windows | `System.Pslist`, `Network.Netstat`, `System.Services`, `System.TaskScheduler`, `Persistence.PermanentWMIEvents`, `Forensics.Prefetch`, `Sysinternals.Autoruns` |
| Linux | `Sys.Pslist`, `Network.Netstat`, `Sys.Crontab`, `Sys.SUID`, `Ssh.AuthorizedKeys` |

`Windows.Sysinternals.Autoruns` is marked `requires_tool`: Velociraptor
implements it by downloading Autoruns. It is listed for completeness and is not
in the default triage set — an endpoint that fetches tools mid-investigation is
its own problem.

Submitting an empty artifact list runs `DEFAULT_TRIAGE` for the endpoint's
platform: the cheap artifacts only, so one button press cannot stall a host.

## Storage and correlation

Rows land in `raw_velociraptor`. Artifact schemas vary far too much to model as
columns, so the VQL row is stored verbatim in `row_json`, and the fields ATOR
correlates on are promoted alongside it:

`path`, `sha256`, `remote_ip`, `process_name`, `pid`

`row_sha256` is the natural dedupe key — re-running an artifact on an unchanged
host bumps `observation_count` instead of storing a second copy of the same
evidence.

`server/engine/velociraptor.py` reshapes those rows into the structures the
existing detectors already understand, so artifact rows are correlated by the
same IOC and YARA code paths as routine telemetry rather than a parallel engine.
What it adds on top is **provenance**: a detection raised from a sweep carries

```json
{"collector": "velociraptor", "velociraptor_artifact": "Windows.System.Pslist"}
```

in its evidence, because an analyst needs to know the finding came from an
artifact and not from the routine psutil snapshot — the two have different
coverage and different blind spots.

## API

| Endpoint | Purpose |
|----------|---------|
| `GET /api/v1/velociraptor/catalog[?os_type=]` | the artifacts an analyst may request |
| `POST /api/v1/hosts/{id}/velociraptor` | queue a sweep (`{"artifacts": [...]}`; empty = triage set) |
| `GET /api/v1/hosts/{id}/velociraptor[?artifact=]` | collected rows, per-artifact summary, recent sweeps |

A request against a revoked host returns 409, as does one against a paused agent.
A request whose artifacts are all rejected returns 400 with the reason per
artifact, rather than silently queueing a shorter sweep.

## Where it shows up

* **`/velociraptor`** — pick an endpoint, see its probe state, choose artifacts,
  queue a sweep, read recent sweep outcomes and browse collected rows.
* **Endpoints** — an *Artifacts* action per row linking to the page for that host.
* **Investigation timeline** — one event per artifact per sweep, not per row: a
  single Pslist run returns hundreds of rows and would otherwise bury everything
  else on the timeline.
* **Reports** — section 10 of the PDF and the `velociraptor` key of the JSON
  export list which artifacts were collected and when. When none were, the
  section says so explicitly: absence of a finding there means the deep-dive
  artifacts were never run, not that they came back clean.

## Limitations

* The agent must run elevated - install it as a SYSTEM service (see above).
* Artifact output is written to a file and read back, never scraped from a pipe,
  so Velociraptor's own logging (stderr) cannot contaminate the rows. A file
  that produces no rows from non-empty output is KEPT and its path reported in
  the error, because a parse that silently yields nothing is the one failure
  mode that looks like success.
* Artifacts run with the agent's privileges. An artifact needing more will
  report a partial result.
* Rows are capped at `MAX_ROWS_PER_ARTIFACT` (500) per artifact and 8 KB per row;
  beyond that a truncation marker row is stored so the cap is visible rather than
  silent.
* Artifact *parameters* are not exposed. Every catalog entry runs with its
  defaults — parameters are the obvious next step, and the place they would go is
  the `args` column already carried on `agent_commands`.
* A sweep is delivered on the next heartbeat (~20 s), not instantly.
