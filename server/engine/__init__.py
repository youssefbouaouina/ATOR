import json
import os
import threading
from datetime import datetime, timedelta, timezone

from server import db as database
from server.engine import attack_mapper
from server.engine.ioc_correlator import correlate_batch as ioc_correlate
from server.engine.ioc_correlator import correlate_domains as domain_correlate
from server.engine.sigma_runner import run as sigma_run
from server.engine.yara_scanner import correlate_files

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

DETECTION_DEDUPE_HOURS_DEFAULT = 24
POLICY_MAX_PER_RUN_DEFAULT = 200

_ENGINE_LOCK = threading.RLock()


def _int_env(name, default):
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _dedupe_window_hours():
    return max(0, _int_env("ATOR_DETECTION_DEDUPE_HOURS", DETECTION_DEDUPE_HOURS_DEFAULT))


def _kv_get(conn, key):
    row = conn.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
    return row["value"] if row else None


def _kv_set(conn, key, value):
    conn.execute(
        "INSERT INTO kv (key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value),
    )


def insert_detections(conn, detections):
    """Insert detections, folding repeat firings of the same rule into one row.

    A rule that keeps firing on the same host inside the dedupe window bumps
    hit_count/last_seen_utc instead of appending another near-identical row, so
    the dashboard shows real findings rather than one row per collection cycle.

    Returns only the ids of newly created rows, so callers enrich and evaluate
    policies for genuinely new findings.
    """
    ids = []
    window = _dedupe_window_hours()
    cutoff = None
    if window:
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=window)).isoformat(timespec="seconds")
    for d in detections:
        if cutoff:
            existing = conn.execute(
                """SELECT id FROM detections
                   WHERE host_id=? AND rule_type=? AND rule_name=? AND severity=?
                     AND COALESCE(technique_id,'')=COALESCE(?,'')
                     AND COALESCE(last_seen_utc, detected_at_utc) >= ?
                   ORDER BY id DESC LIMIT 1""",
                (d["host_id"], d["rule_type"], d["rule_name"], d["severity"],
                 d.get("technique_id"), cutoff),
            ).fetchone()
            if existing:
                conn.execute(
                    """UPDATE detections SET hit_count=hit_count+1, last_seen_utc=?,
                                            collection_id=?, summary=?
                       WHERE id=?""",
                    (d["detected_at_utc"], d.get("collection_id"), d.get("summary"),
                     existing["id"]),
                )
                continue
        cur = conn.execute(
            """
            INSERT INTO detections (host_id, collection_id, rule_type, rule_name, severity,
                                    technique_id, summary, detected_at_utc, hit_count, last_seen_utc)
            VALUES (?,?,?,?,?,?,?,?,1,?)
            """,
            (
                d["host_id"], d.get("collection_id"), d["rule_type"], d["rule_name"],
                d["severity"], d.get("technique_id"), d["summary"], d["detected_at_utc"],
                d["detected_at_utc"],
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


def correlate_domain_iocs(conn, host_ids=None):
    """Correlate watchlist domain IOCs against recent process telemetry.

    Agents surface remote domains (e.g. DNS-over-HTTPS / C2 beacons) in their
    network artifacts; matching them here lets a domain IOC fire exactly like a
    hash or IP IOC already does. host_ids optionally scopes the sweep.
    """
    conditions, params = [], []
    if host_ids:
        marks = ",".join("?" for _ in host_ids)
        conditions.append(f"rc.host_id IN ({marks})")
        params += list(host_ids)
    if conditions:
        conditions_sql = " AND " + " AND ".join(conditions)
    else:
        conditions_sql = ""
    rows = conn.execute(
        f"""SELECT rc.remote_domain, rc.process_name, rc.remote_ip, rc.remote_port,
                   h.id AS host_id, m.collection_id, m.started_at_utc
            FROM raw_connections rc
            JOIN hosts h ON h.id = rc.host_id
            JOIN evidence_manifests m ON m.collection_id = rc.collection_id
            WHERE rc.remote_domain IS NOT NULL{conditions_sql}
            LIMIT 5000""",
        params,
    ).fetchall()
    if not rows:
        return []
    return domain_correlate(
        conn,
        [{"remote_domain": r["remote_domain"], "process_name": r["process_name"],
          "remote_ip": r["remote_ip"], "remote_port": r["remote_port"],
          "host_id": r["host_id"], "collection_id": r["collection_id"],
          "detected_at_utc": r["started_at_utc"]
          or datetime.now(timezone.utc).isoformat(timespec="seconds")}
         for r in rows],
    )


def evaluate_policies(conn, detection_ids=None, limit=None):
    """Queue containment approvals for detections that match a policy.

    detection_ids=None means "scan history" and is capped (default 200) so a
    broad policy cannot flood the queue; pass an explicit list (possibly empty)
    to scope the evaluation to specific detections. A per-policy cooldown stops
    the same detection raising repeated requests.
    """
    created = 0
    policies = conn.execute(
        """SELECT *, COALESCE(cooldown_minutes, 60) AS cooldown_minutes
           FROM policies WHERE enabled=1"""
    ).fetchall()
    if not policies:
        return created

    if detection_ids is not None:
        if not detection_ids:
            return created
        placeholders = ",".join("?" for _ in detection_ids)
        rows = conn.execute(
            f"SELECT id, severity, technique_id, detected_at_utc FROM detections WHERE id IN ({placeholders})",
            list(detection_ids),
        ).fetchall()
    else:
        cap = limit if limit is not None else _int_env("ATOR_POLICY_MAX_PER_RUN", POLICY_MAX_PER_RUN_DEFAULT)
        cap = max(0, cap)
        if not cap:
            return created
        rows = conn.execute(
            """SELECT id, severity, technique_id, detected_at_utc FROM detections
               ORDER BY detected_at_utc DESC LIMIT ?""",
            (cap,),
        ).fetchall()

    now_dt = datetime.now(timezone.utc)
    now = now_dt.isoformat(timespec="seconds")
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
            if not (level >= threshold and (pol["mode"] == "approve" or tech_match)):
                continue
            cooldown = max(0, int(pol["cooldown_minutes"] or 0))
            cutoff = (now_dt - timedelta(minutes=cooldown)).isoformat(timespec="seconds")
            existing = conn.execute(
                """SELECT id FROM approvals_queue
                   WHERE detection_id=? AND policy_id=?
                     AND status IN ('pending','approved','executed_dryrun')
                     AND COALESCE(requested_at_utc,'') >= ?
                   LIMIT 1""",
                (det["id"], pol["id"], cutoff),
            ).fetchone()
            if existing:
                continue
            conn.execute(
                """INSERT INTO approvals_queue (detection_id, policy_id, action, status, requested_at_utc)
                   VALUES (?,?,?,?,?)""",
                (det["id"], pol["id"], pol["action"] or "isolate", "pending", now),
            )
            created += 1
    conn.commit()
    return created


def _run_engine(conn=None, rules_dir=None, host_ids=None, scan_history=False):
    """Run detection over collections that have not been processed yet.

    host_ids scopes both the sigma pass and manifest correlation so a single
    endpoint can be scanned on demand. scan_history additionally re-evaluates
    containment policies over recent detections (capped) - useful right after
    creating a policy, and never applied to a full unfiltered history by
    accident.
    """
    own_conn = conn is None
    conn = conn or database.connect()
    try:
        watermark = _kv_get(conn, "engine_last_run_utc")
        sigma_hits, errors = sigma_run(conn, since_utc=watermark, host_ids=host_ids, rules_dir=rules_dir)

        conditions = ["m.engine_processed_at_utc IS NULL"]
        params = []
        if host_ids:
            marks = ",".join("?" for _ in host_ids)
            conditions.append(f"m.host_id IN ({marks})")
            params += list(host_ids)
        unprocessed = conn.execute(
            f"""SELECT m.collection_id FROM evidence_manifests m
                WHERE {' AND '.join(conditions)} LIMIT 100""",
            params,
        ).fetchall()

        batch_detections = list(sigma_hits)
        for row in unprocessed:
            batch_detections += correlate_collection(conn, row["collection_id"])

        # Watchlist domain IOCs fire from stored network telemetry as well, so
        # domain indicators behave like hash/ip IOCs that need a manifest.
        domain_hits = correlate_domain_iocs(conn, host_ids)
        batch_detections += domain_hits

        ids = insert_detections(conn, batch_detections)
        processed_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        for row in unprocessed:
            conn.execute(
                "UPDATE evidence_manifests SET engine_processed_at_utc=? WHERE collection_id=?",
                (processed_at, row["collection_id"]),
            )

        enrich_result = attack_mapper.enrich_detections(conn, detection_ids=ids)
        if scan_history:
            approvals = evaluate_policies(conn, detection_ids=None)
        else:
            approvals = evaluate_policies(conn, detection_ids=ids)
        _kv_set(conn, "engine_last_run_utc", processed_at)
        conn.commit()
        return {
            "sigma_hits": len(sigma_hits),
            "total_new_detections": len(ids),
            "detections_deduped": max(0, len(batch_detections) - len(ids)),
            "domain_ioc_hits": len(domain_hits),
            "manifests_processed": len(unprocessed),
            "host_scope": sorted(host_ids) if host_ids else None,
            "enriched": enrich_result,
            "approvals_created": approvals,
            "errors": errors[:20],
        }
    finally:
        if own_conn:
            conn.close()


def run_engine(conn=None, rules_dir=None, host_ids=None, scan_history=False):
    """Serialize detection runs within the server process.

    Ingest requests schedule background engine runs while the dashboard can
    request a synchronous host-scoped scan. SQLite permits concurrent readers,
    but overlapping write transactions can raise ``database is locked``.
    """
    with _ENGINE_LOCK:
        return _run_engine(
            conn=conn,
            rules_dir=rules_dir,
            host_ids=host_ids,
            scan_history=scan_history,
        )


if __name__ == "__main__":
    print(json.dumps(run_engine(), indent=2))
