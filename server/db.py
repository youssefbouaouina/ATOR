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
