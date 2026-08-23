import json
from datetime import datetime, timezone

from server import db as database
from server.engine import attack_mapper
from server.engine.ioc_correlator import correlate_batch as ioc_correlate
from server.engine.sigma_runner import run as sigma_run
from server.engine.yara_scanner import correlate_files

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _kv_get(conn, key):
    row = conn.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
    return row["value"] if row else None


def _kv_set(conn, key, value):
    conn.execute(
        "INSERT INTO kv (key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value),
    )


def insert_detections(conn, detections):
    ids = []
    for d in detections:
        cur = conn.execute(
            """
            INSERT INTO detections (host_id, collection_id, rule_type, rule_name, severity,
                                    technique_id, summary, detected_at_utc)
            VALUES (?,?,?,?,?,?,?,?)
            """,
            (
                d["host_id"], d.get("collection_id"), d["rule_type"], d["rule_name"],
                d["severity"], d.get("technique_id"), d["summary"], d["detected_at_utc"],
            ),
        )
        ids.append(cur.lastrowid)
    conn.commit()
    return ids


def correlate_collection(conn, collection_id):
    manifest = conn.execute(
        "SELECT host_id, started_at_utc FROM evidence_manifests WHERE collection_id=?",
        (collection_id,),
    ).fetchone()
    if not manifest:
        return []
    host_id = manifest["host_id"]
    ts = manifest["started_at_utc"] or datetime.now(timezone.utc).isoformat(timespec="seconds")

    artifacts = {"processes": [], "network": [], "files_triage": []}
    for r in conn.execute(
        "SELECT pid, ppid, name, cmdline, exe_path, sha256, username FROM raw_processes WHERE collection_id=?",
        (collection_id,),
    ):
        artifacts["processes"].append(dict(r))
    for r in conn.execute(
        "SELECT pid, process_name, remote_ip, remote_port FROM raw_connections WHERE collection_id=?",
        (collection_id,),
    ):
        item = dict(r)
        if item["remote_ip"]:
            port = item.get("remote_port") or ""
            item["remote"] = f"{item['remote_ip']}:{port}" if port else str(item["remote_ip"])
        artifacts["network"].append(item)
    for r in conn.execute(
        "SELECT path, sha256, size_bytes, yara_matches FROM raw_files WHERE collection_id=?",
        (collection_id,),
    ):
        item = dict(r)
        try:
            item["yara_matches"] = json.loads(item["yara_matches"]) if item["yara_matches"] else None
        except json.JSONDecodeError:
            item["yara_matches"] = None
        artifacts["files_triage"].append(item)

    detections = []
    detections += ioc_correlate(conn, host_id, collection_id, ts, artifacts)
    detections += correlate_files(
        conn, host_id, collection_id, ts,
        [f for f in artifacts["files_triage"] if f.get("yara_matches")],
    )
    return detections


def evaluate_policies(conn, detection_ids=None):
    created = 0
    policies = conn.execute("SELECT * FROM policies WHERE enabled=1").fetchall()
    if not policies:
        return created
    if detection_ids:
        placeholders = ",".join("?" for _ in detection_ids)
        rows = conn.execute(
            f"SELECT id, severity, technique_id, detected_at_utc FROM detections WHERE id IN ({placeholders})",
            list(detection_ids),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT id, severity, technique_id, detected_at_utc FROM detections"
        ).fetchall()
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    for det in rows:
        for pol in policies:
            threshold = SEVERITY_ORDER.get(pol["min_severity"].lower(), 2)
            level = SEVERITY_ORDER.get(det["severity"].lower(), 0)
            tech_match = False
            if pol["technique_ids"]:
                try:
                    wanted = json.loads(pol["technique_ids"])
                    tech_match = bool(det["technique_id"] and det["technique_id"].upper() in [w.upper() for w in wanted])
                except json.JSONDecodeError:
                    pass
            if level >= threshold and (pol["mode"] == "approve" or tech_match):
                existing = conn.execute(
                    "SELECT id FROM approvals_queue WHERE detection_id=? AND policy_id=? AND status='pending'",
                    (det["id"], pol["id"]),
                ).fetchone()
                if not existing:
                    conn.execute(
                        """INSERT INTO approvals_queue (detection_id, policy_id, action, status, requested_at_utc)
                           VALUES (?,?,'isolate','pending',?)""",
                        (det["id"], pol["id"], now),
                    )
                    created += 1
    conn.commit()
    return created


def run_engine(conn=None, rules_dir=None):
    own_conn = conn is None
    conn = conn or database.connect()
    try:
        watermark = _kv_get(conn, "engine_last_run_utc")
        sigma_hits, errors = sigma_run(conn, since_utc=watermark)

        unprocessed = conn.execute(
            """
            SELECT m.collection_id FROM evidence_manifests m
            WHERE NOT EXISTS (SELECT 1 FROM detections d WHERE d.collection_id = m.collection_id)
            LIMIT 100
            """
        ).fetchall()
        batch_detections = list(sigma_hits)
        for row in unprocessed:
            batch_detections += correlate_collection(conn, row["collection_id"])

        ids = insert_detections(conn, batch_detections)
        enrich_result = attack_mapper.enrich_detections(conn, detection_ids=ids)
        approvals = evaluate_policies(conn, detection_ids=ids if ids else None)
        _kv_set(conn, "engine_last_run_utc", datetime.now(timezone.utc).isoformat(timespec="seconds"))
        return {
            "sigma_hits": len(sigma_hits),
            "total_new_detections": len(ids),
            "enriched": enrich_result,
            "approvals_created": approvals,
            "errors": errors[:20],
        }
    finally:
        if own_conn:
            conn.close()


if __name__ == "__main__":
    print(json.dumps(run_engine(), indent=2))
