"""Convert OTRF Security-Datasets captures into the ATOR DFIR schema.

Why convert instead of modelling the raw JSON
---------------------------------------------
A model trained on Sysmon JSON but served on ATOR's psutil-derived rows would be broken in
production: different field names, different distributions, different missingness. So the
corpus is written into a database with **ATOR's own schema** (`ml_train.db`), and feature
extraction then reads only that schema. One implementation therefore serves both training
and live inference, and train/serve skew is eliminated by construction rather than by
hoping the two code paths stay in sync.

    OTRF Sysmon JSON --[this module]--> ml_train.db (ATOR schema)
                                             |
                          ml_features.py  <--+--  ator_dfir.db (live, psutil + EVTX)

Field mappings (all verified present in the corpus)
---------------------------------------------------
Sysmon EID 1  (ProcessCreate)  -> raw_processes
Sysmon EID 3  (NetworkConnect) -> raw_connections
Sysmon EID 12/13/14 (Registry) -> raw_persistence, when the key is a persistence location
Every event                    -> raw_logs, payload shaped exactly like the real agent's
                                  (`{"fields": {...}}`) so Tier-2 features read one format

Residual skew, deliberately documented rather than hidden
---------------------------------------------------------
psutil snapshots see *surviving* processes; Sysmon EID 1 sees *every launch*. A 200 ms
`whoami.exe` is in the corpus and would be invisible to a 60 s psutil sweep. Recall measured
here is therefore an upper bound for a psutil-only deployment, and an argument for
`scripts/install_sysmon.ps1`. See docs/ML_ARCHITECTURE.md section 5.2.

Also: Sysmon EID 3 carries no TCP state, so `raw_connections.status` is NULL here while
production psutil fills it. Features must treat it as missing, never as a category.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import zipfile
from datetime import datetime, timezone

from server import db as database

from ml.datasets import otrf

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_TRAIN_DB = os.path.join(_PROJECT_ROOT, "ml_train.db")

# Mirrors agent.collectors.logs.MAX_EVENT_DATA_FIELDS so the corpus and the live agent
# store the same number of EventData fields per event.
MAX_EVENT_DATA_FIELDS = 40

# Sysmon event IDs we map into first-class ATOR tables.
EID_PROCESS_CREATE = 1
EID_NETWORK_CONNECT = 3
EID_REGISTRY = (12, 13, 14)

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"

# Channel -> ATOR raw_logs.source, matching agent/collectors/logs.py's source names so
# feature code can filter identically on corpus and live data.
_CHANNEL_SOURCE = {
    SYSMON_CHANNEL: "sysmon",
    "Security": "security",
    "System": "system",
    "Application": "application",
    "Windows PowerShell": "powershell",
    "Microsoft-Windows-PowerShell/Operational": "powershell",
    "Microsoft-Windows-WMI-Activity/Operational": "wmi",
}

# Channels with no bearing on endpoint behavioural analysis. Dropped from raw_logs to keep
# the training database a manageable size; excluding them cannot bias the models because no
# feature reads them.
_SKIP_CHANNELS = frozenset({
    "Microsoft-Windows-Kernel-IO/Operational",
    "Directory Service",
})

# Sysmon EventData fields kept per event ID.
#
# Two reasons for an allowlist rather than "store everything":
#   1. Size. Unfiltered, this corpus produces a ~1.2 GB training database; the single worst
#      offender is EID 10's CallTrace at 11 MB per 23k events (66% of all Sysmon payload).
#   2. Contract clarity. Features may only use fields declared here, which makes it
#      impossible to accidentally train on a corpus-only field that production never has.
#
# This is a strict SUBSET of what the live agent stores (it keeps up to
# MAX_EVENT_DATA_FIELDS per event), so anything computable from the corpus is also
# computable in production - the direction that matters.
_COMMON = ("UtcTime", "ProcessGuid", "ProcessId", "Image", "User")
SYSMON_FIELD_ALLOWLIST: dict[int, tuple[str, ...]] = {
    1:  _COMMON + ("CommandLine", "CurrentDirectory", "ParentProcessGuid", "ParentProcessId",
                   "ParentImage", "ParentCommandLine", "IntegrityLevel", "OriginalFileName",
                   "Hashes", "LogonId", "TerminalSessionId", "Description", "Company",
                   "Product", "FileVersion"),
    5:  _COMMON,                                                    # ProcessTerminate
    7:  _COMMON + ("ImageLoaded", "Signed", "Signature", "SignatureStatus", "OriginalFileName"),
    8:  ("UtcTime", "SourceProcessGuid", "SourceProcessId", "SourceImage",
         "TargetProcessGuid", "TargetProcessId", "TargetImage", "StartFunction",
         "StartModule", "NewThreadId"),                             # CreateRemoteThread
    9:  _COMMON + ("Device",),                                      # RawAccessRead
    10: ("UtcTime", "SourceProcessGUID", "SourceProcessId", "SourceImage", "SourceUser",
         "TargetProcessGUID", "TargetProcessId", "TargetImage", "TargetUser",
         "GrantedAccess", "CallTrace"),                             # ProcessAccess (LSASS)
    11: _COMMON + ("TargetFilename", "CreationUtcTime"),            # FileCreate
    12: _COMMON + ("EventType", "TargetObject"),                    # Registry add/delete
    13: _COMMON + ("EventType", "TargetObject", "Details"),         # Registry value set
    14: _COMMON + ("EventType", "TargetObject", "NewName"),         # Registry rename
    15: _COMMON + ("TargetFilename", "Hash"),                       # FileCreateStreamHash
    17: _COMMON + ("EventType", "PipeName"),                        # PipeCreated
    18: _COMMON + ("EventType", "PipeName"),                        # PipeConnected
    19: ("UtcTime", "Operation", "User", "EventNamespace", "Name", "Query"),   # WmiFilter
    20: ("UtcTime", "Operation", "User", "Name", "Type", "Destination"),       # WmiConsumer
    21: ("UtcTime", "Operation", "User", "Consumer", "Filter"),                # WmiBinding
    22: _COMMON + ("QueryName", "QueryStatus", "QueryResults"),     # DnsQuery
    23: _COMMON + ("TargetFilename", "Hashes", "IsExecutable"),     # FileDelete
    25: _COMMON + ("Type",),                                        # ProcessTampering
    26: _COMMON + ("TargetFilename",),                              # FileDeleteDetected
}

# Sysmon EID 3 is fully represented in raw_connections; duplicating it in raw_logs would
# cost space and invite double counting.
_SYSMON_SKIP_IN_LOGS = frozenset({EID_NETWORK_CONNECT})

# ---------------------------------------------------------------------------
# Sensor profile: which Sysmon events this deployment actually collects.
#
# THIS IS THE MOST IMPORTANT FIDELITY CONTROL IN THE ETL.
#
# `scripts/sysmon-config.xml` - the config this framework installs on endpoints - enables
# ONLY event IDs 1, 3, 7, 8, 11, 13 and 22. It does not enable ProcessAccess (10),
# Registry-Add/Delete (12), RawAccessRead (9), PipeEvent (17/18), WmiEvent (19/20/21) or
# FileDelete (23). The corpus, captured with a far more verbose config, contains 249,979
# EID 10 and 148,633 EID 12 events - 51% of all its telemetry.
#
# Training on events the production sensor never emits would be textbook train/serve skew:
# the model would lean on a signal that is simply absent at inference time. So the
# production-faithful events are stored under source='sysmon', exactly as the live agent
# stores them, and the rest go under source='sysmon_extended'.
#
# Keeping (rather than discarding) the extended events lets us *quantify* what enabling them
# would buy - turning "should we log ProcessAccess?" into a measured recommendation instead
# of an opinion. Tier-2 features read only source='sysmon'; the extended ablation reads both.
# On live data, source='sysmon_extended' is always empty, so extended features degrade to
# missing rather than silently wrong.
# ---------------------------------------------------------------------------
SYSMON_ATOR_EIDS = frozenset({1, 3, 7, 8, 11, 13, 22})
SOURCE_SYSMON = "sysmon"
SOURCE_SYSMON_EXTENDED = "sysmon_extended"

# ProcessAccess is only worth logging against sensitive targets - an unfiltered
# ProcessAccess rule produces the 250k-event flood seen in this corpus. Any realistic
# config (e.g. SwiftOnSecurity's) restricts it to credential-bearing processes, so the
# extended profile mirrors that rather than the corpus's unfiltered capture.
_SENSITIVE_TARGET_IMAGES = (
    "lsass.exe", "winlogon.exe", "services.exe", "csrss.exe", "lsm.exe", "samss.exe",
)

# Exclusions transcribed from scripts/sysmon-config.xml so the corpus is filtered through
# the same sensor policy as a real endpoint. Each entry: (field, predicate).
# Paths are compared after normalising to lowercase forward slashes (see _np). Windows path
# literals are backslash-heavy and escaping them is an easy place to introduce a silent bug,
# so the comparison form contains no backslashes at all.
def _np(value) -> str:
    """Normalise a Windows path for comparison: lowercase, forward slashes."""
    return str(value or "").replace(chr(92), "/").lower()


_SYSMON_EXCLUSIONS: dict[int, tuple[tuple[str, object], ...]] = {
    1: (
        ("Image", lambda v: _np(v) == "c:/windows/system32/conhost.exe"),
        ("Image", lambda v: _np(v).startswith("c:/program files (x86)/microsoft/edgeupdate/")),
    ),
    3: (
        ("SourceIp", lambda v: v == "127.0.0.1"),
        ("DestinationIp", lambda v: v == "255.255.255.255"),
    ),
    7: (
        ("ImageLoaded", lambda v: _np(v).startswith("c:/windows/system32/")),
        ("ImageLoaded", lambda v: _np(v).startswith("c:/windows/syswow64/")),
        ("ImageLoaded", lambda v: _np(v).startswith("c:/windows/winsxs/")),
        ("Image", lambda v: _np(v).startswith("c:/program files/vmware/vmware tools/")),
    ),
    11: (
        ("TargetFilename",
         lambda v: "/appdata/local/temp/__psscriptpolicytest_" in _np(v)),
        ("TargetFilename", lambda v: _np(v).endswith(".avb")),
        ("Image",
         lambda v: _np(v).startswith("c:/program files/google/chrome/application/chrome.exe")),
    ),
    13: (
        ("TargetObject", lambda v: _np(v).endswith("/muicache")),
        ("TargetObject", lambda v: _np(v).startswith("hku/.default")),
    ),
    22: (
        ("QueryName", lambda v: str(v).lower().endswith("msftconnecttest.com")),
        ("QueryName", lambda v: str(v).lower().endswith("ocsp.digicert.com")),
        ("QueryName", lambda v: "tlsprober" in str(v).lower()),
    ),
}


def _excluded_by_sensor_config(event: dict, eid: int | None) -> bool:
    """True when scripts/sysmon-config.xml would have filtered this event out."""
    for field, predicate in _SYSMON_EXCLUSIONS.get(eid, ()):
        value = event.get(field)
        if isinstance(value, str) and predicate(value):
            return True
    return False


def _extended_event_kept(event: dict, eid: int | None) -> bool:
    """Whether an extended-profile event is worth storing for the ablation."""
    if eid == 10:
        target = str(event.get("TargetImage") or "").lower()
        return any(target.endswith(name) for name in _SENSITIVE_TARGET_IMAGES)
    return True

# Per-field value cap. Production already truncates payloads (agent stores xml[:4000]), so
# bounding field length here is consistent with live behaviour rather than a corpus-only
# quirk. CallTrace gets a tighter cap: the signal analysts use - unbacked "UNKNOWN(...)"
# frames indicating injected code - appears in the leading frames.
_FIELD_CAP_DEFAULT = 512
_FIELD_CAPS = {"CallTrace": 256, "ParentCommandLine": 1024, "CommandLine": 1024,
               "Query": 512, "QueryResults": 256}

# Registry paths that constitute persistence. Used to populate raw_persistence, which in
# production is a *snapshot* of persistence mechanisms - here we reconstruct it from the
# registry-write events that created them.
_PERSISTENCE_PATTERNS = (
    (re.compile(r"\\CurrentVersion\\Run(Once)?(Ex)?\\", re.I), "registry_run"),
    (re.compile(r"\\CurrentVersion\\Windows\\(Load|Run)\b", re.I), "registry_run"),
    (re.compile(r"\\Winlogon\\(Shell|Userinit|Notify)", re.I), "winlogon"),
    (re.compile(r"\\CurrentControlSet\\Services\\", re.I), "service"),
    (re.compile(r"\\Schedule\\TaskCache\\", re.I), "scheduled_task"),
    (re.compile(r"\\CurrentVersion\\Explorer\\(User )?Shell Folders", re.I), "startup_folder"),
)

# Training-database-only side tables.
#
# corpus_captures  : provenance + the cross-validation group key.
# corpus_lineage   : ProcessGuid -> ParentProcessGuid, needed for label propagation.
#
# corpus_lineage is a LABELLING side-channel and must never be read by feature code:
# production raw_processes has no ProcessGuid column, so any feature derived from it would
# be uncomputable at inference time. Enforced by tests/test_ml_etl.py.
CORPUS_SCHEMA = """
CREATE TABLE IF NOT EXISTS corpus_captures (
    capture_id TEXT PRIMARY KEY,
    tactic TEXT NOT NULL,
    scope TEXT NOT NULL,
    name TEXT NOT NULL,
    source_file TEXT NOT NULL,
    sha256 TEXT,
    events_total INTEGER NOT NULL DEFAULT 0,
    events_process INTEGER NOT NULL DEFAULT 0,
    events_network INTEGER NOT NULL DEFAULT 0,
    events_registry INTEGER NOT NULL DEFAULT 0,
    hosts_seen INTEGER NOT NULL DEFAULT 0,
    imported_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS corpus_lineage (
    capture_id TEXT NOT NULL,
    host_id INTEGER NOT NULL,
    pid INTEGER,
    process_guid TEXT,
    parent_process_guid TEXT,
    image TEXT,
    cmdline TEXT,
    utc_time TEXT,
    parent_image TEXT,
    parent_cmdline TEXT,
    parent_pid INTEGER,
    -- 1 = reconstructed from a child's ParentImage/ParentCommandLine because the process's
    -- own EID 1 fell outside the capture window. See _synthesise_parents().
    is_reconstructed INTEGER NOT NULL DEFAULT 0,
    -- raw_processes.id of the row this node produced. Recorded explicitly so labels
    -- attach to feature rows by primary key. Joining on (capture_id, pid) instead
    -- would be ambiguous: 337 corpus processes have a NULL pid and pids repeat
    -- within a long capture.
    raw_process_id INTEGER,
    PRIMARY KEY (capture_id, process_guid)
);
CREATE INDEX IF NOT EXISTS ix_lineage_parent ON corpus_lineage(capture_id, parent_process_guid);
CREATE INDEX IF NOT EXISTS ix_lineage_pid ON corpus_lineage(capture_id, host_id, pid);
CREATE INDEX IF NOT EXISTS ix_lineage_rawproc ON corpus_lineage(raw_process_id);
"""


# --------------------------------------------------------------------------- helpers

def _norm_ts(*candidates) -> str | None:
    """Normalise a Sysmon/WEF timestamp to ISO-8601 UTC.

    Accepts the several shapes the corpus uses:
      UtcTime     '2020-08-07 14:32:45.881'
      @timestamp  '2020-08-07T14:32:25.358Z'
      EventTime   '2020-08-07 14:32:25'
    Sub-second precision is preserved - process-creation ordering within a capture matters
    for lineage, and truncating to whole seconds collapses bursts.
    """
    for raw in candidates:
        if not raw:
            continue
        text = str(raw).strip()
        if not text:
            continue
        candidate = text.replace("Z", "+00:00")
        if " " in candidate and "T" not in candidate:
            candidate = candidate.replace(" ", "T", 1)
        try:
            dt = datetime.fromisoformat(candidate)
        except ValueError:
            continue
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    return None


def _parse_hashes(raw) -> dict:
    """'SHA1=AB..,MD5=CD..,SHA256=EF..' -> {'SHA1': 'AB..', ...} (upper-cased keys)."""
    out = {}
    if not raw:
        return out
    for part in str(raw).split(","):
        if "=" in part:
            key, _, value = part.partition("=")
            out[key.strip().upper()] = value.strip()
    return out


def _basename(path) -> str | None:
    if not path:
        return None
    return str(path).replace("/", "\\").rsplit("\\", 1)[-1] or None


def _as_int(value):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


# Non-EventData keys the corpus adds (WEF/NXLog envelope). Excluded so `fields` holds the
# event's own EventData, matching what the agent's EVTX parser produces.
_ENVELOPE_KEYS = frozenset({
    "@timestamp", "@version", "host", "port", "tags", "Channel", "Hostname",
    "EventID", "EventReceivedTime", "EventTime", "EventType", "Keywords", "Message",
    "OpcodeValue", "ProviderGuid", "RecordNumber", "Severity", "SeverityValue",
    "SourceModuleName", "SourceModuleType", "SourceName", "Task", "ThreadID",
    "ExecutionProcessID", "UserID", "Version", "Opcode", "Domain", "AccountName",
    "AccountType",
})


def _cap(key: str, value):
    """Bound a single field's length. Non-strings pass through untouched."""
    if not isinstance(value, str):
        return value
    limit = _FIELD_CAPS.get(key, _FIELD_CAP_DEFAULT)
    return value if len(value) <= limit else value[:limit]


def _event_data_fields(event: dict, eid: int | None, is_sysmon: bool) -> dict:
    """The event's own EventData fields, shaped like the agent's payload['fields'].

    Sysmon events are restricted to SYSMON_FIELD_ALLOWLIST (see its docstring). Other
    channels keep whatever EventData they carry, capped at MAX_EVENT_DATA_FIELDS to match
    the agent.
    """
    if is_sysmon and eid in SYSMON_FIELD_ALLOWLIST:
        allowed = SYSMON_FIELD_ALLOWLIST[eid]
        return {k: _cap(k, event[k]) for k in allowed if k in event and event[k] is not None}
    fields = {}
    for key, value in event.items():
        if key in _ENVELOPE_KEYS:
            continue
        fields[key] = _cap(key, value)
        if len(fields) >= MAX_EVENT_DATA_FIELDS:
            break
    return fields


def _persistence_type(target_object) -> str | None:
    if not target_object:
        return None
    for pattern, ptype in _PERSISTENCE_PATTERNS:
        if pattern.search(str(target_object)):
            return ptype
    return None


def iter_events(zip_path: str):
    """Stream events from a capture archive. Malformed lines are skipped, not fatal."""
    with zipfile.ZipFile(zip_path) as archive:
        for member in archive.namelist():
            if not member.endswith(".json"):
                continue
            with archive.open(member) as handle:
                for line in handle.read().decode("utf-8", "replace").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        continue


# --------------------------------------------------------------------------- the ETL

def _backfill_pids(lineage: list[tuple]) -> list[tuple]:
    """Recover ProcessId values the corpus omits, from children's ParentProcessId.

    413 of the 1,355 ProcessCreate events in this corpus carry no `ProcessId` field at all
    (the WEF/NXLog pipeline that produced them dropped it). Production psutil always supplies
    a pid, so leaving these NULL would be a corpus-only artefact that breaks the
    process->connection join for ~30% of rows.

    The pid is recoverable without guessing: a child event records its parent's real pid in
    `ParentProcessId`, keyed by `ParentProcessGuid`. So any process that has at least one
    child in the capture can have its pid restored exactly.

    NOT usable for this: `ExecutionProcessID`. Despite the name it is the pid of the process
    that *wrote* the event - Sysmon's own service, constant across a capture (3172 in the
    observed case). Treating it as the subject's pid would silently corrupt every row.

    Leaf processes with no children keep pid = NULL, which is honest rather than invented.
    """
    pid_by_guid: dict[str, int] = {}
    for row in lineage:
        parent_guid, parent_pid = row[4], row[10]
        if parent_guid and parent_pid is not None:
            pid_by_guid.setdefault(parent_guid, parent_pid)
    out = []
    for row in lineage:
        if row[2] is None and row[3] in pid_by_guid:
            patched = list(row)
            patched[2] = pid_by_guid[row[3]]
            row = tuple(patched)
        out.append(row)
    return out


def _synthesise_parents(lineage: list[tuple], capture_id: str) -> list[tuple]:
    """Reconstruct parent processes that have no ProcessCreate event of their own.

    Why this is necessary
    ---------------------
    A capture is a time window. Any process started before that window has no EID 1 inside
    it, so the process tree arrives with dangling roots. This is not an edge case - it is
    the norm for the most interesting processes:

    In `credential_access__host__empire_mimikatz_logonpasswords` the ONLY EID 1 is
    `whoami.exe`, whose parent is
        "powershell.exe" -noP -sta -w 1 -enc SQBGA...
    That parent *is* the Empire agent - the actual attacker - running Mimikatz in-memory so
    it never spawns a process of its own. Without reconstruction the capture has no
    attacker-matching process at all and the entire intrusion is labelled benign. With it,
    the agent becomes a node, matches the Empire signature, and its children inherit the
    label.

    The parent's identity is not guessed: Sysmon puts `ParentProcessGuid`, `ParentImage`
    and `ParentCommandLine` on every child event, so we have its real GUID, path and command
    line. What we lack is its own parent, its hashes and its start time - left NULL rather
    than invented. `is_reconstructed=1` marks these rows so their contribution can be
    ablated.

    Returns new lineage tuples in the same layout as the live ones.
    """
    known = {row[3] for row in lineage if row[3]}
    out: dict[str, tuple] = {}
    for row in lineage:
        parent_guid = row[4]
        parent_image, parent_cmdline = row[8], row[9]
        if not parent_guid or parent_guid in known or parent_guid in out:
            continue
        if not parent_image and not parent_cmdline:
            continue          # nothing to reconstruct from
        out[parent_guid] = (
            capture_id,
            row[1],           # host_id - the child's host; a parent is always local
            row[10],          # pid: the child's ParentProcessId IS the parent's real pid
            parent_guid,
            None,             # grandparent unknown
            parent_image,
            parent_cmdline,
            row[7],           # timestamp: the child's, an upper bound on the parent's start
            None, None,       # its own parent image/cmdline are unknown
            None,             # its own parent's pid is unknown
            1,                # is_reconstructed
        )
    return list(out.values())


class _HostRegistry:
    """Maps a corpus Hostname to a `hosts` row, creating it on first sight."""

    def __init__(self, conn):
        self.conn = conn
        self.cache: dict[str, int] = {}
        for row in conn.execute("SELECT client_id, id FROM hosts"):
            self.cache[row["client_id"]] = row["id"]

    def resolve(self, hostname: str | None, seen_at: str | None) -> int:
        hostname = (hostname or "UNKNOWN-HOST").strip() or "UNKNOWN-HOST"
        client_id = f"otrf-{hostname.lower()}"
        if client_id in self.cache:
            return self.cache[client_id]
        now = seen_at or database.now_iso()
        cur = self.conn.execute(
            """INSERT INTO hosts (client_id, hostname, os_type, api_key_hash,
                                  enrolled_at_utc, last_seen_utc, agent_version, is_active)
               VALUES (?,?,'windows',?,?,?,'otrf-corpus',0)""",
            # Training database only: never served, never authenticated against.
            (client_id, hostname, "corpus-not-a-real-credential", now, now),
        )
        self.cache[client_id] = cur.lastrowid
        return cur.lastrowid


def import_capture(conn, capture: otrf.Capture, host_registry: _HostRegistry) -> dict:
    """Import one capture. Idempotent: re-importing replaces that capture's rows."""
    capture_id = capture.capture_id

    # Delete-then-insert keeps re-runs clean without needing a migration story.
    for table in ("raw_processes", "raw_connections", "raw_logs", "raw_persistence"):
        conn.execute(f"DELETE FROM {table} WHERE collection_id = ?", (capture_id,))
    conn.execute("DELETE FROM corpus_lineage WHERE capture_id = ?", (capture_id,))

    procs, conns, logs, pers, lineage = [], [], [], [], []
    proc_row_by_guid: dict[str, int] = {}
    counts = {"total": 0, "process": 0, "network": 0, "registry": 0,
              "excluded_by_sensor": 0, "extended": 0, "dropped_extended": 0}
    hosts_seen: set[int] = set()

    for event in iter_events(capture.local_path):
        counts["total"] += 1
        eid = _as_int(event.get("EventID"))
        channel = event.get("Channel") or ""
        ts = _norm_ts(event.get("UtcTime"), event.get("@timestamp"), event.get("EventTime"))
        hostname = event.get("Hostname")
        host_id = host_registry.resolve(hostname, ts)
        hosts_seen.add(host_id)
        is_sysmon = channel == SYSMON_CHANNEL

        # ---- sensor policy, applied before anything is stored.
        # An event that scripts/sysmon-config.xml would have filtered out never reached the
        # server in production, so it must not reach the training set either - including the
        # raw_processes / raw_connections rows derived from it further down.
        if is_sysmon:
            in_ator_profile = eid in SYSMON_ATOR_EIDS
            if in_ator_profile:
                if _excluded_by_sensor_config(event, eid):
                    counts["excluded_by_sensor"] += 1
                    continue
                log_source = SOURCE_SYSMON
            else:
                # Not collected by this deployment. Retained separately so the value of
                # enabling it can be measured rather than guessed.
                if not _extended_event_kept(event, eid):
                    counts["dropped_extended"] += 1
                    continue
                log_source = SOURCE_SYSMON_EXTENDED
                counts["extended"] += 1
        else:
            in_ator_profile = True
            log_source = _CHANNEL_SOURCE.get(channel, "other")

        # ---- raw_logs, in the agent's payload shape. Redundant or irrelevant events are
        # skipped here but still counted above, so events_total stays a true event count.
        if channel not in _SKIP_CHANNELS and not (is_sysmon and eid in _SYSMON_SKIP_IN_LOGS):
            logs.append((
                host_id, capture_id, ts or database.now_iso(),
                log_source, eid, ts,
                event.get("SourceName") or event.get("provider"),
                hostname,
                json.dumps({"fields": _event_data_fields(event, eid, is_sysmon),
                            "log": channel, "corpus": capture_id}, default=str),
            ))

        if not is_sysmon:
            continue

        # ---- raw_processes
        if eid == EID_PROCESS_CREATE:
            counts["process"] += 1
            image = event.get("Image")
            hashes = _parse_hashes(event.get("Hashes"))
            # Kept as a list so a pid recovered by _backfill_pids can be patched in.
            proc_row_by_guid[event.get("ProcessGuid")] = len(procs)
            procs.append([
                host_id, capture_id, ts, _as_int(event.get("ProcessId")),
                _as_int(event.get("ParentProcessId")), _basename(image),
                event.get("CommandLine"), image, hashes.get("SHA256"),
                event.get("User"), None,
            ])
            lineage.append((
                capture_id, host_id, _as_int(event.get("ProcessId")),
                event.get("ProcessGuid"), event.get("ParentProcessGuid"),
                image, event.get("CommandLine"), ts,
                event.get("ParentImage"), event.get("ParentCommandLine"),
                _as_int(event.get("ParentProcessId")), 0,
            ))

        # ---- raw_connections
        elif eid == EID_NETWORK_CONNECT:
            counts["network"] += 1
            conns.append((
                host_id, capture_id, ts, _as_int(event.get("ProcessId")),
                _basename(event.get("Image")),
                event.get("SourceIp"), _as_int(event.get("SourcePort")),
                event.get("DestinationIp"), _as_int(event.get("DestinationPort")),
                (event.get("Protocol") or "").lower() or None,
                # Sysmon reports no TCP state - NULL, never a fabricated value.
                None, None,
            ))

        # ---- raw_persistence (only writes to persistence locations)
        #
        # SKEW NOTE: in production raw_persistence is a *snapshot* produced by
        # agent/collectors/persistence.py enumerating Run keys, services and startup
        # folders directly - it is not derived from Sysmon at all. The corpus has no such
        # snapshot, so persistence rows are reconstructed from registry-write events, which
        # approximates "what persistence was established" rather than "what exists".
        # Registry EIDs 12/14 are outside the ATOR sensor profile, but they are used here
        # anyway because this table emulates a snapshot rather than an event stream.
        # Features over raw_persistence must therefore be treated as weakly comparable
        # between corpus and live data; see docs/ML_ARCHITECTURE.md section 5.2.
        elif eid in EID_REGISTRY:
            counts["registry"] += 1
            ptype = _persistence_type(event.get("TargetObject"))
            if ptype:
                pers.append((
                    host_id, capture_id, ts, ptype,
                    _basename(event.get("TargetObject")),
                    event.get("Details"), event.get("TargetObject"), None,
                ))

    # Reconstruct parents whose own EID 1 fell outside the capture window, so the process
    # tree is connected and a seed can match the real attacker process (see module docstring
    # and _synthesise_parents). This must happen BEFORE any insert, because the
    # reconstructed rows feed both corpus_lineage and raw_processes.
    lineage = lineage + _synthesise_parents(lineage, capture_id)
    lineage = _backfill_pids(lineage)
    for row in lineage:
        idx = proc_row_by_guid.get(row[3])
        if idx is not None and procs[idx][3] is None and row[2] is not None:
            procs[idx][3] = row[2]

    # A reconstructed parent is a real, running process that a psutil snapshot WOULD have
    # captured, so it belongs in raw_processes too - omitting it would make the corpus less
    # like production, not more. sha256/username are NULL, which psutil also often lacks.
    # Tuple layout: 0 capture_id, 1 host_id, 2 pid, 3 guid, 4 parent_guid, 5 image,
    #               6 cmdline, 7 utc_time, 8 parent_image, 9 parent_cmdline,
    #               10 parent_pid, 11 is_reconstructed
    # pid comes from index 2 (the row's OWN pid, which _synthesise_parents filled from the
    # child's ParentProcessId) - not index 10, which is this row's parent's pid and is NULL
    # for a reconstructed node.
    for row in lineage:
        if row[11] == 1:                       # reconstructed node
            proc_row_by_guid[row[3]] = len(procs)
            procs.append([
                row[1], capture_id, row[7], row[2], None, _basename(row[5]), row[6],
                row[5], None, None, None,
            ])

    # Inserted individually (not executemany) so each row's primary key can be captured
    # and written back into corpus_lineage. ~1.7k rows, so the cost is irrelevant.
    proc_ids: list[int] = []
    for values in procs:
        cur = conn.execute(
            """INSERT INTO raw_processes (host_id, collection_id, collected_at_utc, pid, ppid,
                                          name, cmdline, exe_path, sha256, username,
                                          container_id)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""", values)
        proc_ids.append(cur.lastrowid)
    raw_id_by_guid = {
        guid: proc_ids[idx]
        for guid, idx in proc_row_by_guid.items()
        if guid is not None and idx < len(proc_ids)
    }
    lineage = [tuple(row) + (raw_id_by_guid.get(row[3]),) for row in lineage]
    conn.executemany(
        """INSERT INTO raw_connections (host_id, collection_id, collected_at_utc, pid,
                                         process_name, local_ip, local_port, remote_ip,
                                         remote_port, proto, status, container_id)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""", conns)
    conn.executemany(
        """INSERT INTO raw_logs (host_id, collection_id, collected_at_utc, source, event_id,
                                  event_time_utc, provider, computer, payload_json)
           VALUES (?,?,?,?,?,?,?,?,?)""", logs)
    conn.executemany(
        """INSERT INTO raw_persistence (host_id, collection_id, collected_at_utc, ptype,
                                         name, command, location, container_id)
           VALUES (?,?,?,?,?,?,?,?)""", pers)
    conn.executemany(
        """INSERT OR REPLACE INTO corpus_lineage (capture_id, host_id, pid, process_guid,
                                       parent_process_guid, image, cmdline, utc_time,
                                       parent_image, parent_cmdline, parent_pid,
                                       is_reconstructed, raw_process_id)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        [row for row in lineage if row[3]])      # a row without a GUID cannot be linked

    conn.execute(
        """INSERT OR REPLACE INTO corpus_captures
               (capture_id, tactic, scope, name, source_file, sha256, events_total,
                events_process, events_network, events_registry, hosts_seen, imported_at_utc)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (capture_id, capture.tactic, capture.scope, capture.name, capture.filename,
         otrf.sha256_file(capture.local_path), counts["total"], counts["process"],
         counts["network"], counts["registry"], len(hosts_seen), database.now_iso()),
    )
    conn.commit()

    return {"capture_id": capture_id, "tactic": capture.tactic, **counts,
            "rows": {"processes": len(procs), "connections": len(conns),
                     "logs": len(logs), "persistence": len(pers)}}


def build(train_db: str = DEFAULT_TRAIN_DB, corpus_dir: str = otrf.DEFAULT_DIR,
          captures: list[otrf.Capture] | None = None, rebuild: bool = False,
          verbose: bool = True) -> dict:
    """Build (or incrementally extend) the training database.

    `rebuild=True` deletes the database first - use it after changing the mapping, so a
    stale schema can never be mistaken for a fresh one.
    """
    if rebuild:
        for suffix in ("", "-wal", "-shm"):
            path = train_db + suffix
            if os.path.exists(path):
                os.remove(path)

    database.init_db(train_db)            # ATOR schema + ML overlay
    conn = database.connect(train_db)
    try:
        conn.executescript(CORPUS_SCHEMA)
        conn.commit()

        if captures is None:
            captures = otrf.local_captures(corpus_dir, scope="host")
        registry = _HostRegistry(conn)

        done = {r[0] for r in conn.execute("SELECT capture_id FROM corpus_captures")}
        results, skipped = [], 0
        for i, capture in enumerate(captures, 1):
            if capture.capture_id in done and not rebuild:
                skipped += 1
                continue
            try:
                results.append(import_capture(conn, capture, registry))
            except (zipfile.BadZipFile, OSError, sqlite3.Error) as exc:
                # An unreadable archive (antivirus) or a corrupt zip must not abort a
                # 115-capture import.
                if verbose:
                    print(f"  [skip] {capture.filename}: {type(exc).__name__}: {exc}", flush=True)
                continue
            if verbose and i % 20 == 0:
                print(f"  {i}/{len(captures)} imported", flush=True)

        summary = {
            "train_db": train_db,
            "captures_imported": len(results),
            "captures_skipped_already_present": skipped,
            "totals": {
                "hosts": conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0],
                "raw_processes": conn.execute("SELECT COUNT(*) FROM raw_processes").fetchone()[0],
                "raw_connections": conn.execute("SELECT COUNT(*) FROM raw_connections").fetchone()[0],
                "raw_logs": conn.execute("SELECT COUNT(*) FROM raw_logs").fetchone()[0],
                "raw_persistence": conn.execute("SELECT COUNT(*) FROM raw_persistence").fetchone()[0],
                "corpus_lineage": conn.execute("SELECT COUNT(*) FROM corpus_lineage").fetchone()[0],
            },
        }
        return summary
    finally:
        conn.close()


if __name__ == "__main__":       # pragma: no cover - operator entry point
    import argparse
    ap = argparse.ArgumentParser(description="OTRF -> ATOR schema ETL")
    ap.add_argument("--train-db", default=DEFAULT_TRAIN_DB)
    ap.add_argument("--corpus-dir", default=otrf.DEFAULT_DIR)
    ap.add_argument("--rebuild", action="store_true", help="delete and rebuild from scratch")
    ap.add_argument("--limit", type=int, default=None, help="import only the first N captures")
    args = ap.parse_args()
    caps = otrf.local_captures(args.corpus_dir, scope="host")
    if args.limit:
        caps = caps[:args.limit]
    print(json.dumps(build(args.train_db, args.corpus_dir, caps, rebuild=args.rebuild), indent=2))
