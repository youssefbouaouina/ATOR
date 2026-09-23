import json
import os
import sqlite3

DB_PATH = os.environ.get(
    "ATOR_DFIR_DB",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ator_dfir.db"),
)

SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id TEXT UNIQUE NOT NULL,
    hostname TEXT NOT NULL,
    os_type TEXT NOT NULL CHECK (os_type IN ('windows','linux','docker_host')),
    docker_engine_flag INTEGER NOT NULL DEFAULT 0,
    api_key_hash TEXT NOT NULL,
    agent_version TEXT,
    enrolled_at_utc TEXT NOT NULL,
    last_seen_utc TEXT,
    is_active INTEGER NOT NULL DEFAULT 1,
    -- agent lifecycle control (see /api/v1/agent/heartbeat)
    agent_desired_state TEXT NOT NULL DEFAULT 'running',
    agent_reported_state TEXT NOT NULL DEFAULT 'unknown',
    agent_state_changed_at_utc TEXT,
    last_heartbeat_utc TEXT,
    -- last agent-reported Velociraptor probe (JSON), so the UI can say whether
    -- an endpoint can run artifacts before the analyst queues a sweep
    velociraptor_status TEXT,
    velociraptor_checked_at_utc TEXT
);

CREATE TABLE IF NOT EXISTS containers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL REFERENCES hosts(id),
    container_id TEXT NOT NULL,
    container_name TEXT,
    image_name TEXT,
    status TEXT,
    ip_address TEXT,
    seen_at_utc TEXT,
    UNIQUE (host_id, container_id)
);

CREATE TABLE IF NOT EXISTS raw_processes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL REFERENCES hosts(id),
    collection_id TEXT,
    collected_at_utc TEXT NOT NULL,
    pid INTEGER,
    ppid INTEGER,
    name TEXT,
    cmdline TEXT,
    exe_path TEXT,
    sha256 TEXT,
    username TEXT,
    container_id TEXT,
    first_seen_utc TEXT,
    last_seen_utc TEXT,
    observation_count INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS ix_raw_processes_host ON raw_processes(host_id, collected_at_utc);
CREATE INDEX IF NOT EXISTS ix_raw_processes_name ON raw_processes(name);
CREATE INDEX IF NOT EXISTS ix_raw_processes_sha ON raw_processes(sha256);

CREATE TABLE IF NOT EXISTS raw_connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL REFERENCES hosts(id),
    collection_id TEXT,
    collected_at_utc TEXT NOT NULL,
    pid INTEGER,
    process_name TEXT,
    local_ip TEXT,
    local_port INTEGER,
    remote_ip TEXT,
    remote_port INTEGER,
    remote_domain TEXT,
    proto TEXT,
    status TEXT,
    container_id TEXT,
    first_seen_utc TEXT,
    last_seen_utc TEXT,
    observation_count INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS ix_raw_conn_host ON raw_connections(host_id, collected_at_utc);
CREATE INDEX IF NOT EXISTS ix_raw_conn_remote ON raw_connections(remote_ip);

CREATE TABLE IF NOT EXISTS raw_persistence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL REFERENCES hosts(id),
    collection_id TEXT,
    collected_at_utc TEXT NOT NULL,
    ptype TEXT NOT NULL,
    name TEXT,
    command TEXT,
    location TEXT,
    container_id TEXT,
    first_seen_utc TEXT,
    last_seen_utc TEXT,
    observation_count INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS ix_raw_pers_host ON raw_persistence(host_id, ptype);

CREATE TABLE IF NOT EXISTS raw_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL REFERENCES hosts(id),
    collection_id TEXT,
    collected_at_utc TEXT NOT NULL,
    source TEXT NOT NULL,
    event_id INTEGER,
    event_time_utc TEXT,
    provider TEXT,
    computer TEXT,
    payload_json TEXT
);
CREATE INDEX IF NOT EXISTS ix_raw_logs_host ON raw_logs(host_id, event_time_utc);
CREATE INDEX IF NOT EXISTS ix_raw_logs_eid ON raw_logs(source, event_id);

CREATE TABLE IF NOT EXISTS raw_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL REFERENCES hosts(id),
    collection_id TEXT,
    collected_at_utc TEXT NOT NULL,
    path TEXT NOT NULL,
    sha256 TEXT,
    size_bytes INTEGER,
    yara_matches TEXT,
    first_seen_utc TEXT,
    last_seen_utc TEXT,
    observation_count INTEGER NOT NULL DEFAULT 1
);

-- Rows returned by an on-demand Velociraptor artifact sweep.
--
-- row_json holds the VQL row verbatim (artifact schemas vary far too much to
-- model as columns); the promoted path/sha256/remote_ip/process_name columns
-- exist so IOC correlation and the UI have something indexable. row_sha256 is
-- the natural key: the same artifact re-run on an unchanged host must update
-- one row rather than append a second copy of the same evidence.
CREATE TABLE IF NOT EXISTS raw_velociraptor (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL REFERENCES hosts(id),
    collection_id TEXT,
    collected_at_utc TEXT NOT NULL,
    artifact TEXT NOT NULL,
    row_sha256 TEXT NOT NULL,
    row_json TEXT NOT NULL,
    path TEXT,
    sha256 TEXT,
    remote_ip TEXT,
    process_name TEXT,
    pid INTEGER,
    first_seen_utc TEXT,
    last_seen_utc TEXT,
    observation_count INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS ix_raw_velo_host ON raw_velociraptor(host_id, collected_at_utc);
CREATE INDEX IF NOT EXISTS ix_raw_velo_artifact ON raw_velociraptor(artifact);
CREATE INDEX IF NOT EXISTS ix_raw_velo_sha ON raw_velociraptor(sha256);
CREATE INDEX IF NOT EXISTS ix_raw_velo_collection ON raw_velociraptor(collection_id);

CREATE TABLE IF NOT EXISTS ioc_store (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_type TEXT NOT NULL CHECK (ioc_type IN ('hash','ip','domain')),
    value TEXT NOT NULL,
    threat_source TEXT,
    description TEXT,
    added_at_utc TEXT,
    UNIQUE (ioc_type, value)
);

CREATE TABLE IF NOT EXISTS detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL REFERENCES hosts(id),
    collection_id TEXT,
    rule_type TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low')),
    technique_id TEXT,
    summary TEXT,
    detected_at_utc TEXT NOT NULL,
    evidence_json TEXT,
    -- recurrence tracking: identical rule firings are folded into one row
    hit_count INTEGER NOT NULL DEFAULT 1,
    last_seen_utc TEXT
);
CREATE INDEX IF NOT EXISTS ix_det_host ON detections(host_id, detected_at_utc);
CREATE INDEX IF NOT EXISTS ix_det_tech ON detections(technique_id);

CREATE TABLE IF NOT EXISTS enriched_detections (
    detection_id INTEGER PRIMARY KEY REFERENCES detections(id),
    technique_name TEXT,
    tactic TEXT,
    platforms TEXT,
    data_sources TEXT,
    description TEXT,
    kill_chain TEXT
);

CREATE TABLE IF NOT EXISTS policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    min_severity TEXT NOT NULL,
    technique_ids TEXT,
    mode TEXT NOT NULL DEFAULT 'notify' CHECK (mode IN ('notify','approve')),
    action TEXT NOT NULL DEFAULT 'isolate',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at_utc TEXT,
    updated_at_utc TEXT,
    -- minutes before the same detection may raise another approval request
    cooldown_minutes INTEGER NOT NULL DEFAULT 60
);

CREATE TABLE IF NOT EXISTS approvals_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    detection_id INTEGER NOT NULL REFERENCES detections(id),
    policy_id INTEGER REFERENCES policies(id),
    action TEXT NOT NULL DEFAULT 'isolate',
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected','executed_dryrun')),
    requested_at_utc TEXT,
    decided_at_utc TEXT,
    decided_by TEXT,
    result_note TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_utc TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    details TEXT
);

CREATE TABLE IF NOT EXISTS evidence_manifests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL REFERENCES hosts(id),
    collection_id TEXT UNIQUE NOT NULL,
    started_at_utc TEXT,
    finished_at_utc TEXT,
    agent_version TEXT,
    collector_order TEXT,
    artifact_count INTEGER,
    manifest_json TEXT NOT NULL,
    manifest_sha256 TEXT NOT NULL,
    received_at_utc TEXT,
    engine_processed_at_utc TEXT
);

CREATE TABLE IF NOT EXISTS kv (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS resource_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL REFERENCES hosts(id),
    sampled_at_utc TEXT NOT NULL,
    cpu_pct REAL,
    mem_used_mb REAL,
    mem_pct REAL,
    swap_pct REAL,
    disk_read_kbps REAL,
    disk_write_kbps REAL,
    net_sent_kbps REAL,
    net_recv_kbps REAL,
    gpu_present INTEGER DEFAULT 0,
    gpu_util_pct REAL,
    gpu_mem_used_mb REAL,
    battery_pct REAL,
    battery_plugged INTEGER,
    hw_tier TEXT CHECK (hw_tier IN ('low','mid','high','unknown')),
    cpu_cores INTEGER,
    mem_total_mb REAL,
    anomaly INTEGER NOT NULL DEFAULT 0,
    anomaly_json TEXT
);
CREATE INDEX IF NOT EXISTS ix_res_host_time ON resource_samples(host_id, sampled_at_utc);
CREATE INDEX IF NOT EXISTS ix_res_time ON resource_samples(sampled_at_utc);

CREATE TABLE IF NOT EXISTS resource_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL REFERENCES hosts(id),
    ts_utc TEXT NOT NULL,
    metric TEXT NOT NULL,
    value REAL NOT NULL,
    baseline REAL,
    message TEXT,
    severity TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low')),
    acknowledged INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_res_alerts_host_time ON resource_alerts(host_id, ts_utc);

CREATE TABLE IF NOT EXISTS enrollment_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_token TEXT UNIQUE NOT NULL,
    hostname TEXT NOT NULL,
    os_type TEXT NOT NULL CHECK (os_type IN ('windows','linux','docker_host')),
    docker_engine_flag INTEGER NOT NULL DEFAULT 0,
    requested_features TEXT,
    agent_version TEXT,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','accepted','rejected','enrolled','expired')),
    requested_at_utc TEXT NOT NULL,
    reviewed_at_utc TEXT,
    reviewed_by TEXT,
    rejection_reason TEXT,
    enrollment_token TEXT UNIQUE,
    enrolled_at_utc TEXT,
    expires_at_utc TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_enrollment_status ON enrollment_requests(status);
CREATE INDEX IF NOT EXISTS ix_enrollment_token ON enrollment_requests(request_token);
CREATE INDEX IF NOT EXISTS ix_enrollment_enroll_token ON enrollment_requests(enrollment_token);

CREATE TABLE IF NOT EXISTS agent_self_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL REFERENCES hosts(id),
    sampled_at_utc TEXT NOT NULL,
    agent_cpu_pct REAL,
    agent_mem_mb REAL,
    agent_threads INTEGER,
    agent_fds INTEGER,
    agent_cpu_time_user REAL,
    agent_cpu_time_system REAL,
    collection_duration_ms REAL,
    payload_size_bytes INTEGER,
    spool_count INTEGER,
    telemetry_mode TEXT NOT NULL DEFAULT 'lightweight'
);
CREATE INDEX IF NOT EXISTS ix_agent_self_host_time ON agent_self_samples(host_id, sampled_at_utc);

CREATE TABLE IF NOT EXISTS agent_commands (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL REFERENCES hosts(id),
    command TEXT NOT NULL CHECK (command IN ('collect_now','detect_now','velociraptor_collect')),
    args TEXT,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','claimed','done','failed','expired')),
    requested_by TEXT,
    created_at_utc TEXT NOT NULL,
    claimed_at_utc TEXT,
    finished_at_utc TEXT,
    result TEXT
);
CREATE INDEX IF NOT EXISTS ix_agent_commands_host ON agent_commands(host_id, status);

CREATE TABLE IF NOT EXISTS report_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL REFERENCES hosts(id),
    kind TEXT NOT NULL DEFAULT 'pdf' CHECK (kind IN ('pdf','json','stix')),
    filename TEXT NOT NULL,
    path TEXT NOT NULL,
    generated_at_utc TEXT NOT NULL,
    generated_by TEXT,
    size_bytes INTEGER,
    detection_total INTEGER NOT NULL DEFAULT 0,
    critical INTEGER NOT NULL DEFAULT 0,
    high INTEGER NOT NULL DEFAULT 0,
    medium INTEGER NOT NULL DEFAULT 0,
    low INTEGER NOT NULL DEFAULT 0,
    risk_level TEXT
);
CREATE INDEX IF NOT EXISTS ix_report_history_host ON report_history(host_id, generated_at_utc);
"""


# Columns added after the first release, migrated in place for existing DBs.
MIGRATIONS = {
    "hosts": (
        ("agent_desired_state", "TEXT NOT NULL DEFAULT 'running'"),
        ("agent_reported_state", "TEXT NOT NULL DEFAULT 'unknown'"),
        ("agent_state_changed_at_utc", "TEXT"),
        ("last_heartbeat_utc", "TEXT"),
        ("velociraptor_status", "TEXT"),
        ("velociraptor_checked_at_utc", "TEXT"),
    ),
    "agent_commands": (
        ("args", "TEXT"),
    ),
    "detections": (
        ("hit_count", "INTEGER NOT NULL DEFAULT 1"),
        ("last_seen_utc", "TEXT"),
    ),
    "evidence_manifests": (
        ("engine_processed_at_utc", "TEXT"),
    ),
    "policies": (
        ("updated_at_utc", "TEXT"),
        ("cooldown_minutes", "INTEGER NOT NULL DEFAULT 60"),
    ),
    "raw_processes": (
        ("first_seen_utc", "TEXT"),
        ("last_seen_utc", "TEXT"),
        ("observation_count", "INTEGER NOT NULL DEFAULT 1"),
        # Part of the v2 process identity (see DEDUPE_INDEXES), so it has to
        # exist before the dedupe indexes are built. The ML overlay also adds
        # it, but migrate() runs after the indexes; declaring it here keeps a
        # fresh store from failing to build ux_raw_processes_dedupe_v2.
        ("create_time_utc", "TEXT"),
    ),
    "raw_logs": (
        # sha256 of the canonical event payload - part of the v2 log identity.
        ("payload_sha256", "TEXT"),
    ),
    "raw_connections": (
        ("remote_domain", "TEXT"),
        ("first_seen_utc", "TEXT"),
        ("last_seen_utc", "TEXT"),
        ("observation_count", "INTEGER NOT NULL DEFAULT 1"),
    ),
    "raw_persistence": (
        ("first_seen_utc", "TEXT"),
        ("last_seen_utc", "TEXT"),
        ("observation_count", "INTEGER NOT NULL DEFAULT 1"),
    ),
    "raw_files": (
        ("first_seen_utc", "TEXT"),
        ("last_seen_utc", "TEXT"),
        ("observation_count", "INTEGER NOT NULL DEFAULT 1"),
    ),
}

# Natural-key uniqueness so repeated agent observations update one row instead
# of inserting a new one every collection cycle.
#
# The logs and processes keys are v2. Their v1 keys were too coarse and merged
# records that are genuinely different (reproduced through the real ingest
# endpoint; see tests/test_dedupe_identity.py):
#
#   raw_logs v1       (host, source, second, event_id, provider). The agent
#                     records event times to the SECOND, so distinct events in
#                     the same second collapsed into one: `whoami`, `net user`
#                     and `ipconfig` launched together were stored as a single
#                     process-creation event. v2 adds a hash of the payload.
#                     Re-sent copies of an event are byte-identical, so they are
#                     still dropped exactly as before.
#   raw_processes v1  (host, pid, name, cmdline, exe, sha256). A NEW process
#                     that reused a PID with an identical command line was
#                     folded into the old row and kept the OLD instance's parent
#                     and start time. v2 adds create_time_utc: (pid, start time)
#                     is how an operating system itself identifies a process.
#                     For agents that do not report a start time the column is
#                     NULL, and v2 then behaves exactly like v1.
DEDUPE_INDEXES = (
    ("ux_raw_logs_dedupe_v2",
     "CREATE UNIQUE INDEX IF NOT EXISTS ux_raw_logs_dedupe_v2 ON raw_logs"
     "(host_id, source, COALESCE(event_time_utc,''), COALESCE(event_id,-1), COALESCE(provider,''),"
     " COALESCE(payload_sha256,''))"),
    ("ux_raw_processes_dedupe_v2",
     "CREATE UNIQUE INDEX IF NOT EXISTS ux_raw_processes_dedupe_v2 ON raw_processes"
     "(host_id, COALESCE(pid,-1), COALESCE(name,''), COALESCE(cmdline,''),"
     " COALESCE(exe_path,''), COALESCE(sha256,''), COALESCE(create_time_utc,''))"),
    ("ux_raw_connections_dedupe",
     "CREATE UNIQUE INDEX IF NOT EXISTS ux_raw_connections_dedupe ON raw_connections"
     "(host_id, COALESCE(pid,-1), COALESCE(local_ip,''), COALESCE(local_port,-1),"
     " COALESCE(remote_ip,''), COALESCE(remote_port,-1), COALESCE(proto,''))"),
    ("ux_raw_persistence_dedupe",
     "CREATE UNIQUE INDEX IF NOT EXISTS ux_raw_persistence_dedupe ON raw_persistence"
     "(host_id, ptype, COALESCE(name,''), COALESCE(command,''), COALESCE(location,''))"),
    ("ux_raw_files_dedupe",
     "CREATE UNIQUE INDEX IF NOT EXISTS ux_raw_files_dedupe ON raw_files"
     "(host_id, path, COALESCE(sha256,''))"),
    ("ux_raw_velociraptor_dedupe",
     "CREATE UNIQUE INDEX IF NOT EXISTS ux_raw_velociraptor_dedupe ON raw_velociraptor"
     "(host_id, artifact, row_sha256)"),
    # Non-unique: speeds up the detection dedupe/recurrence lookup.
    ("ix_detections_dedupe",
     "CREATE INDEX IF NOT EXISTS ix_detections_dedupe ON detections"
     "(host_id, rule_name, severity, last_seen_utc)"),
)

# v1 index name -> the v2 index that replaces it. Stores built by an earlier
# release carry the v1 index; upgrade_dedupe_indexes() swaps it at startup.
SUPERSEDED_DEDUPE_INDEXES = {
    "ux_raw_logs_dedupe": "ux_raw_logs_dedupe_v2",
    "ux_raw_processes_dedupe": "ux_raw_processes_dedupe_v2",
}

# ---------------------------------------------------------------------------
# Layer 4.5 ML schema.
#
# Kept separate from SCHEMA so the ML layer is an additive, reversible overlay on
# the DFIR track's schema rather than an edit to it. Applied by migrate(), which
# init_db() calls - so every entry point (API startup, tests, demo seeding) gets
# it automatically.
#
# Design notes (full rationale in docs/ML_ARCHITECTURE.md section 6):
#   * detections.rule_type is REUSED for 'ml_anomaly'/'ml_triage'. We deliberately
#     do NOT add a 'source' column: rule_type already carries sigma/yara/ioc, and a
#     second column of record would be a data-integrity trap.
#   * ml_resource_rollup exists because prune_old_resource_samples() hard-deletes
#     resource_samples older than 72h. Any baseline longer than that must be
#     summarised before pruning or it is lost.
#   * feature_spec_sha256 pins the exact feature contract a model was trained
#     against, so a stale model can never be fed a changed feature vector.
# ---------------------------------------------------------------------------
ML_SCHEMA = """
CREATE TABLE IF NOT EXISTS ml_models (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    model_type TEXT NOT NULL CHECK (model_type IN ('anomaly','triage','tactic')),
    feature_tier TEXT NOT NULL CHECK (feature_tier IN ('t1','t2')),
    feature_spec_sha256 TEXT NOT NULL,
    trained_at_utc TEXT NOT NULL,
    training_rows INTEGER,
    training_source TEXT,
    metrics_json TEXT,
    model_path TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 0,
    UNIQUE (name, version)
);
CREATE INDEX IF NOT EXISTS ix_ml_models_active
    ON ml_models(model_type, feature_tier, is_active);

CREATE TABLE IF NOT EXISTS host_risk_scores (
    host_id INTEGER PRIMARY KEY REFERENCES hosts(id),
    score REAL NOT NULL,
    tier TEXT NOT NULL CHECK (tier IN ('low','medium','high','critical')),
    last_computed_utc TEXT NOT NULL,
    breakdown_json TEXT
);

CREATE TABLE IF NOT EXISTS ml_resource_rollup (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL REFERENCES hosts(id),
    window_start_utc TEXT NOT NULL,
    window_end_utc TEXT NOT NULL,
    sample_count INTEGER NOT NULL,
    stats_json TEXT NOT NULL,
    UNIQUE (host_id, window_start_utc)
);
CREATE INDEX IF NOT EXISTS ix_ml_rollup_host
    ON ml_resource_rollup(host_id, window_start_utc);

CREATE TABLE IF NOT EXISTS ml_drift_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    computed_at_utc TEXT NOT NULL,
    model_id INTEGER REFERENCES ml_models(id),
    feature_name TEXT NOT NULL,
    psi REAL NOT NULL,
    verdict TEXT NOT NULL CHECK (verdict IN ('stable','moderate','shifted'))
);
CREATE INDEX IF NOT EXISTS ix_ml_drift_time ON ml_drift_log(computed_at_utc);

CREATE INDEX IF NOT EXISTS ix_det_rule_type ON detections(rule_type);

-- ---- Phase 10: weekly MLOps pipeline (docs/ML_MLOPS_PLAN.md).
-- One row per pipeline run; the dashboard's "Model operations" panel reads it.
CREATE TABLE IF NOT EXISTS ml_pipeline_runs (
    run_id TEXT PRIMARY KEY,
    started_at_utc TEXT NOT NULL,
    finished_at_utc TEXT,
    status TEXT NOT NULL CHECK (status IN
        ('running','succeeded','attention','failed','skipped')),
    trigger TEXT NOT NULL DEFAULT 'schedule',
    summary_json TEXT,
    report_path TEXT
);
CREATE INDEX IF NOT EXISTS ix_ml_pipeline_started ON ml_pipeline_runs(started_at_utc);

-- A challenger model scored silently beside the champion (champion/challenger shadow).
CREATE TABLE IF NOT EXISTS ml_shadow_trials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    version_id TEXT NOT NULL,
    components_json TEXT NOT NULL,
    started_at_utc TEXT NOT NULL,
    ended_at_utc TEXT,
    status TEXT NOT NULL CHECK (status IN
        ('running','promoted','rejected','inconclusive','superseded','aborted')),
    offline_json TEXT,
    online_json TEXT,
    decision_reason TEXT
);
CREATE INDEX IF NOT EXISTS ix_ml_shadow_trials_status ON ml_shadow_trials(status);

-- Per-hour aggregate of shadow scoring passes; bounded at 168 rows per weekly trial.
CREATE TABLE IF NOT EXISTS ml_shadow_observations (
    trial_id INTEGER NOT NULL REFERENCES ml_shadow_trials(id),
    hour_utc TEXT NOT NULL,
    passes INTEGER NOT NULL DEFAULT 0,
    processes_scored INTEGER NOT NULL DEFAULT 0,
    errors INTEGER NOT NULL DEFAULT 0,
    champion_ms_total REAL NOT NULL DEFAULT 0,
    challenger_ms_total REAL NOT NULL DEFAULT 0,
    challenger_ms_max REAL NOT NULL DEFAULT 0,
    last_error TEXT,
    PRIMARY KEY (trial_id, hour_utc)
);

-- Distinct processes either model would have reported during a trial.
CREATE TABLE IF NOT EXISTS ml_shadow_flags (
    trial_id INTEGER NOT NULL REFERENCES ml_shadow_trials(id),
    process_key TEXT NOT NULL,
    host_id INTEGER,
    pid INTEGER,
    name TEXT,
    champion_flag INTEGER NOT NULL DEFAULT 0,
    challenger_flag INTEGER NOT NULL DEFAULT 0,
    champion_score REAL,
    challenger_score REAL,
    first_seen_utc TEXT NOT NULL,
    PRIMARY KEY (trial_id, process_key)
);

-- Analyst verdicts on ML leads. They feed the next retrain (see ml/mlops/data.py) and
-- the online "confirmed threats kept" gate.
CREATE TABLE IF NOT EXISTS ml_feedback (
    detection_id INTEGER PRIMARY KEY REFERENCES detections(id),
    verdict TEXT NOT NULL CHECK (verdict IN ('confirmed','benign')),
    note TEXT,
    recorded_at_utc TEXT NOT NULL,
    recorded_by TEXT NOT NULL DEFAULT 'analyst'
);
"""

# Indexes over the columns added by ML_DETECTION_COLUMNS. These MUST be created
# after the ALTER TABLE statements, so they cannot live in ML_SCHEMA - indexing a
# column that does not exist yet fails the whole script on a fresh database.
ML_DETECTION_INDEXES = (
    "CREATE INDEX IF NOT EXISTS ix_det_confidence ON detections(confidence_score)",
    "CREATE INDEX IF NOT EXISTS ix_det_anomaly ON detections(anomaly_score)",
    # The Threat Hunting queue filters on rule_type and orders by these two scores; this
    # covers that path so the page stays fast as findings accumulate.
    "CREATE INDEX IF NOT EXISTS ix_det_ml_queue ON detections(rule_type, confidence_score DESC, anomaly_score DESC)",
)

# Columns added to the existing raw_processes table.
#
# A psutil sweep stamps every process it sees with ONE collection timestamp, so
# `collected_at_utc` says when the agent looked, not when the process started. The corpus,
# built from Sysmon EID 1, has a real per-process launch time in that same column - which
# meant every timing feature was computable in training and NaN on every live host. Giving a
# process its own start time closes that gap; it is also ordinary DFIR telemetry that every
# EDR records, so it earns its place in the schema independently of the ML layer.
ML_RAW_PROCESS_COLUMNS = (
    ("create_time_utc", "TEXT"),       # ISO-8601 UTC; NULL when the OS would not say
)

# Columns added to the existing detections table. SQLite has no
# "ADD COLUMN IF NOT EXISTS", so each is applied only when absent.
ML_DETECTION_COLUMNS = (
    ("confidence_score", "REAL"),      # Component B, calibrated 0..1
    ("anomaly_score", "REAL"),         # Component A, 0..1
    ("suggested_tactics", "TEXT"),     # Component C, JSON array
    ("ml_model_id", "INTEGER"),        # provenance -> ml_models.id
    ("ml_explanation", "TEXT"),        # JSON: top contributing features
)

# Values rule_type may take once the ML layer is active.
ML_RULE_TYPES = ("ml_anomaly", "ml_triage")


def _table_columns(conn, table):
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}


def migrate(conn):
    """Apply the Layer 4.5 ML schema overlay. Idempotent and additive.

    Safe to run on a populated production database: it only creates tables that
    do not exist and adds nullable columns. No existing row is rewritten and no
    column is ever dropped or retyped.

    Returns a dict describing what actually changed, so callers/tests can assert
    on it rather than guessing.
    """
    changed = {"tables_created": [], "columns_added": []}

    before = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    conn.executescript(ML_SCHEMA)
    after = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    changed["tables_created"] = sorted(after - before)

    for table, columns in (("detections", ML_DETECTION_COLUMNS),
                           ("raw_processes", ML_RAW_PROCESS_COLUMNS)):
        existing = _table_columns(conn, table)
        if not existing:
            continue                    # table absent on a partially-built database
        for column, coltype in columns:
            if column not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}")
                changed["columns_added"].append(f"{table}.{column}")

    # Only now that the columns exist can they be indexed.
    for statement in ML_DETECTION_INDEXES:
        conn.execute(statement)
    conn.commit()
    return changed


def connect(db_path=None):
    conn = sqlite3.connect(db_path or DB_PATH, timeout=15, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=15000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def ensure_schema(conn):
    """Add columns/tables that databases created before a release are missing.

    Only additive ALTERs run here, so startup stays fast even on a large DB.
    """
    added = []
    for table, columns in MIGRATIONS.items():
        existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
        if not existing:
            continue  # table absent; SCHEMA will create it
        for name, ddl in columns:
            if name not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")
                added.append(f"{table}.{name}")
    conn.commit()
    return added


def ensure_command_types(conn):
    """Widen agent_commands.command to accept newer command types.

    SQLite cannot ALTER a CHECK constraint, so a database created before
    velociraptor_collect existed still carries the two-value constraint and
    would reject the INSERT. The table is small and append-only, so it is
    rebuilt in place: create, copy, drop, rename, inside one transaction.

    Returns True when a rebuild happened.
    """
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='agent_commands'"
    ).fetchone()
    if not row or not row["sql"]:
        return False                      # absent; SCHEMA creates it correctly
    if "velociraptor_collect" in row["sql"]:
        return False                      # already current
    columns = [r[1] for r in conn.execute("PRAGMA table_info(agent_commands)")]
    carried = [c for c in columns if c != "args"]
    conn.executescript(
        """
        PRAGMA foreign_keys=OFF;
        BEGIN;
        CREATE TABLE agent_commands__new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL REFERENCES hosts(id),
            command TEXT NOT NULL
                CHECK (command IN ('collect_now','detect_now','velociraptor_collect')),
            args TEXT,
            status TEXT NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending','claimed','done','failed','expired')),
            requested_by TEXT,
            created_at_utc TEXT NOT NULL,
            claimed_at_utc TEXT,
            finished_at_utc TEXT,
            result TEXT
        );
        INSERT INTO agent_commands__new (%(cols)s)
            SELECT %(cols)s FROM agent_commands;
        DROP TABLE agent_commands;
        ALTER TABLE agent_commands__new RENAME TO agent_commands;
        CREATE INDEX IF NOT EXISTS ix_agent_commands_host ON agent_commands(host_id, status);
        COMMIT;
        PRAGMA foreign_keys=ON;
        """ % {"cols": ",".join(carried)}
    )
    return True


def dedupe_index_status(conn):
    """Return {index_name: exists} for the natural-key dedupe indexes."""
    present = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    return {name: (name in present) for name, _ in DEDUPE_INDEXES}


def ensure_dedupe_indexes(conn):
    """Create the natural-key unique indexes; skip any that duplicates forbid.

    Returns (created, skipped). Callers should surface 'skipped' because dedupe
    is inactive until the duplicates are purged.
    """
    created, skipped = [], []
    # A superseded v1 index would keep enforcing the old, too-coarse key.
    for old in SUPERSEDED_DEDUPE_INDEXES:
        conn.execute(f"DROP INDEX IF EXISTS {old}")
    for name, ddl in DEDUPE_INDEXES:
        try:
            conn.execute(ddl)
            created.append(name)
        except sqlite3.IntegrityError:
            skipped.append(name)
    conn.commit()
    return created, skipped


def drop_dedupe_indexes(conn):
    """Drop every natural-key unique index, current and superseded.

    For stores that must keep every raw row as a distinct sample - the offline ML
    training corpus above all, which loads with plain INSERTs. Driven by the
    registry, so a renamed or added index cannot be silently left behind; a
    hard-coded list of names already missed the v2 rename once.
    """
    names = [name for name, ddl in DEDUPE_INDEXES if "UNIQUE" in ddl]
    names += list(SUPERSEDED_DEDUPE_INDEXES)
    for name in names:
        conn.execute(f"DROP INDEX IF EXISTS {name}")
    conn.commit()
    return names


def upgrade_dedupe_indexes(conn):
    """Replace v1 dedupe indexes with their v2 successors. Returns the swaps made.

    Runs at every startup but only does work on a store that still carries a v1
    index. Building the v2 index there cannot fail: each v2 key is its v1 key
    plus one more column, so rows that were unique under v1 stay unique under v2.
    The one-off cost is a single index build.

    A store with no v1 index is left alone. In particular this does not create
    dedupe indexes on a legacy store that never had them; that stays the job of
    scripts/purge_host_data.py, so startup is never blocked by a large scan.
    """
    present = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    ddl_by_name = dict(DEDUPE_INDEXES)
    swapped = []
    for old, new in SUPERSEDED_DEDUPE_INDEXES.items():
        if old not in present:
            continue
        conn.execute(f"DROP INDEX {old}")
        conn.execute(ddl_by_name[new])
        swapped.append(f"{old} -> {new}")
    conn.commit()
    return swapped


def init_db(db_path=None):
    conn = connect(db_path)
    try:
        conn.executescript(SCHEMA)
        ensure_schema(conn)
        # Table-shape migrations first, then index work over the settled shape.
        ensure_command_types(conn)
        upgrade_dedupe_indexes(conn)
        conn.commit()
        # raw_velociraptor is newer than the legacy-store guard below, so its
        # dedupe index is built here regardless of how much history the database
        # already holds; IntegrityError only if duplicates already exist.
        try:
            conn.execute(dict(DEDUPE_INDEXES)["ux_raw_velociraptor_dedupe"])
            conn.commit()
        except sqlite3.IntegrityError:
            pass
        # A brand new (or freshly purged) store has no duplicates yet, so the
        # dedupe indexes build instantly. On a legacy store they are left for
        # scripts/purge_host_data.py so startup is never blocked by a 4M-row scan.
        if conn.execute("SELECT 1 FROM raw_logs LIMIT 1").fetchone() is None:
            ensure_dedupe_indexes(conn)
        # Layer 4.5 ML overlay. Additive and idempotent; failing to apply it must
        # not prevent the DFIR pipeline from starting, so it is best-effort.
        try:
            migrate(conn)
        except sqlite3.Error as exc:            # pragma: no cover - defensive
            print(f"[db] ML migration skipped: {exc}")
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        return mode
    finally:
        conn.close()


def audit(conn, actor, action, details=None):
    from datetime import datetime, timezone
    conn.execute(
        "INSERT INTO audit_log (ts_utc, actor, action, details) VALUES (?,?,?,?)",
        (datetime.now(timezone.utc).isoformat(timespec="seconds"), actor, action,
         details if isinstance(details, str) else json.dumps(details or {})),
    )


def now_iso():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def prune_old_resource_samples(conn, hours=None):
    """Delete resource samples and alerts older than retention window.
    Default 72 hours (configurable via ATOR_RES_RETENTION_HOURS).
    Triggered opportunistically; safe to call frequently."""
    from datetime import datetime, timedelta, timezone
    if hours is None:
        import os
        hours = int(os.environ.get("ATOR_RES_RETENTION_HOURS", "72"))
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    cutoff_iso = cutoff.isoformat(timespec="seconds")
    conn.execute(
        "DELETE FROM resource_samples WHERE sampled_at_utc < ?",
        (cutoff_iso,),
    )
    conn.execute(
        "DELETE FROM resource_alerts WHERE ts_utc < ?",
        (cutoff_iso,),
    )
    conn.commit()


def prune_old_enrollment_requests(conn, hours=None):
    """Delete expired enrollment requests older than retention window.
    Default 168 hours (7 days, configurable via ATOR_ENROLLMENT_RETENTION_HOURS)."""
    from datetime import datetime, timedelta, timezone
    if hours is None:
        import os
        hours = int(os.environ.get("ATOR_ENROLLMENT_RETENTION_HOURS", "168"))
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    cutoff_iso = cutoff.isoformat(timespec="seconds")
    conn.execute(
        "DELETE FROM enrollment_requests WHERE expires_at_utc < ?",
        (cutoff_iso,),
    )
    conn.commit()


def prune_old_agent_self_samples(conn, hours=None):
    """Delete old agent self-monitoring samples.
    Default 72 hours (configurable via ATOR_SELF_RETENTION_HOURS)."""
    from datetime import datetime, timedelta, timezone
    if hours is None:
        import os
        hours = int(os.environ.get("ATOR_SELF_RETENTION_HOURS", "72"))
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    cutoff_iso = cutoff.isoformat(timespec="seconds")
    conn.execute(
        "DELETE FROM agent_self_samples WHERE sampled_at_utc < ?",
        (cutoff_iso,),
    )
    conn.commit()
