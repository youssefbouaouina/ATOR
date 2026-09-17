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
    is_active INTEGER NOT NULL DEFAULT 1
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
    container_id TEXT
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
    proto TEXT,
    status TEXT,
    container_id TEXT
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
    container_id TEXT
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
    yara_matches TEXT
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
    evidence_json TEXT
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
    created_at_utc TEXT
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
    received_at_utc TEXT
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
"""


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
"""

# Indexes over the columns added by ML_DETECTION_COLUMNS. These MUST be created
# after the ALTER TABLE statements, so they cannot live in ML_SCHEMA - indexing a
# column that does not exist yet fails the whole script on a fresh database.
ML_DETECTION_INDEXES = (
    "CREATE INDEX IF NOT EXISTS ix_det_confidence ON detections(confidence_score)",
    "CREATE INDEX IF NOT EXISTS ix_det_anomaly ON detections(anomaly_score)",
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

    existing = _table_columns(conn, "detections")
    for column, coltype in ML_DETECTION_COLUMNS:
        if column not in existing:
            conn.execute(f"ALTER TABLE detections ADD COLUMN {column} {coltype}")
            changed["columns_added"].append(column)

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


def init_db(db_path=None):
    conn = connect(db_path)
    try:
        conn.executescript(SCHEMA)
        conn.commit()
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
