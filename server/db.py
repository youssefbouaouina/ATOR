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
    last_heartbeat_utc TEXT
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
    command TEXT NOT NULL CHECK (command IN ('collect_now','detect_now')),
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
DEDUPE_INDEXES = (
    ("ux_raw_logs_dedupe",
     "CREATE UNIQUE INDEX IF NOT EXISTS ux_raw_logs_dedupe ON raw_logs"
     "(host_id, source, COALESCE(event_time_utc,''), COALESCE(event_id,-1), COALESCE(provider,''))"),
    ("ux_raw_processes_dedupe",
     "CREATE UNIQUE INDEX IF NOT EXISTS ux_raw_processes_dedupe ON raw_processes"
     "(host_id, COALESCE(pid,-1), COALESCE(name,''), COALESCE(cmdline,''),"
     " COALESCE(exe_path,''), COALESCE(sha256,''))"),
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
    # Non-unique: speeds up the detection dedupe/recurrence lookup.
    ("ix_detections_dedupe",
     "CREATE INDEX IF NOT EXISTS ix_detections_dedupe ON detections"
     "(host_id, rule_name, severity, last_seen_utc)"),
)


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
    for name, ddl in DEDUPE_INDEXES:
        try:
            conn.execute(ddl)
            created.append(name)
        except sqlite3.IntegrityError:
            skipped.append(name)
    conn.commit()
    return created, skipped


def init_db(db_path=None):
    conn = connect(db_path)
    try:
        conn.executescript(SCHEMA)
        ensure_schema(conn)
        conn.commit()
        # A brand new (or freshly purged) store has no duplicates yet, so the
        # dedupe indexes build instantly. On a legacy store they are left for
        # scripts/purge_host_data.py so startup is never blocked by a 4M-row scan.
        if conn.execute("SELECT 1 FROM raw_logs LIMIT 1").fetchone() is None:
            ensure_dedupe_indexes(conn)
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
