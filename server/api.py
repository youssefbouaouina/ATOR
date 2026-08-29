import json
from datetime import datetime, timedelta, timezone

import requests as http_requests
from fastapi import BackgroundTasks, Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from server import db as database
from server import security
from server.engine import run_engine
from server.engine import attack_mapper, reporter, soc_chain, timeline
from server.engine.ioc_correlator import correlate_batch
from server.engine.yara_scanner import compile_rules, scan_file

templates = Jinja2Templates(directory="server/templates")


class EnrollRequest(BaseModel):
    hostname: str = Field(min_length=1, max_length=255)
    os_type: str = Field(pattern="^(windows|linux|docker_host)$")
    docker_engine_flag: int = 0
    agent_version: str | None = None


class IngestRequest(BaseModel):
    manifest: dict
    artifacts: dict


class PolicyRequest(BaseModel):
    name: str
    min_severity: str = "high"
    technique_ids: list[str] | None = None
    mode: str = "notify"
    action: str = "isolate"


class DecisionRequest(BaseModel):
    decision: str = Field(pattern="^(approved|rejected)$")
    analyst: str = "analyst"


class IocRequest(BaseModel):
    ioc_type: str = Field(pattern="^(hash|ip|domain)$")
    value: str
    threat_source: str = "analyst-watchlist"
    description: str | None = None


class ResourceSampleIn(BaseModel):
    sampled_at_utc: str | None = None
    cpu_pct: float | None = None
    mem_used_mb: float | None = None
    mem_pct: float | None = None
    swap_pct: float | None = None
    disk_read_kbps: float | None = None
    disk_write_kbps: float | None = None
    net_sent_kbps: float | None = None
    net_recv_kbps: float | None = None
    gpu_present: int | None = 0
    gpu_util_pct: float | None = None
    gpu_mem_used_mb: float | None = None
    battery_pct: float | None = None
    battery_plugged: int | None = None
    hw_tier: str | None = None
    cpu_cores: int | None = None
    mem_total_mb: float | None = None


class SamplesRequest(BaseModel):
    samples: list[ResourceSampleIn]


app = FastAPI(title="ATOR DFIR Framework", version="1.0.0")


@app.on_event("startup")
def startup():
    database.init_db()


def get_conn():
    conn = database.connect()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def auth_host(request: Request, conn=Depends(get_conn)):
    header = request.headers.get("authorization", "")
    client_id = request.headers.get("x-client-id", "")
    if not header.lower().startswith("bearer ") or not client_id:
        raise HTTPException(status_code=401, detail="missing credentials")
    key = header.split(" ", 1)[1].strip()
    host = conn.execute(
        "SELECT * FROM hosts WHERE client_id=? AND is_active=1", (client_id,)
    ).fetchone()
    if not host or not security.verify_secret(key, host["api_key_hash"]):
        database.audit(conn, client_id or "unknown", "auth_failure")
        conn.commit()
        raise HTTPException(status_code=403, detail="invalid credentials")
    return {"host": host, "conn": conn}


@app.post("/api/v1/enroll")
def enroll(body: EnrollRequest, conn=Depends(get_conn)):
    api_key = security.generate_api_key()
    client_id = security.new_client_id()
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    cur = conn.execute(
        """INSERT INTO hosts (client_id, hostname, os_type, docker_engine_flag, api_key_hash,
                              agent_version, enrolled_at_utc, last_seen_utc)
           VALUES (?,?,?,?,?,?,?,?)""",
        (client_id, body.hostname, body.os_type, body.docker_engine_flag,
         security.hash_secret(api_key), body.agent_version, now, now),
    )
    database.audit(conn, "server", "host_enrolled",
                   {"client_id": client_id, "hostname": body.hostname, "os_type": body.os_type})
    conn.commit()
    return {"host_id": cur.lastrowid, "client_id": client_id, "api_key": api_key}


@app.post("/api/v1/ingest", status_code=202)
def ingest(payload: IngestRequest, background: BackgroundTasks, ctx=Depends(auth_host)):
    conn = ctx["conn"]
    host = ctx["host"]
    manifest = payload.manifest
    artifacts = payload.artifacts
    collection_id = manifest.get("collection_id")
    if not collection_id:
        raise HTTPException(status_code=400, detail="manifest.collection_id required")

    claimed = conn.execute(
        "SELECT id FROM evidence_manifests WHERE collection_id=?", (collection_id,)
    ).fetchone()
    if claimed:
        return {"status": "duplicate", "collection_id": collection_id}

    received = manifest.get("finished_at_utc") or datetime.now(timezone.utc).isoformat(timespec="seconds")

    for item in artifacts.get("processes") or []:
        if not isinstance(item, dict) or "_error" in item:
            continue
        conn.execute(
            """INSERT INTO raw_processes (host_id, collection_id, collected_at_utc, pid, ppid,
                                          name, cmdline, exe_path, sha256, username)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (host["id"], collection_id, received, item.get("pid"), item.get("ppid"),
             item.get("name"), item.get("cmdline"), item.get("exe_path"),
             item.get("sha256"), item.get("username")),
        )
    for item in artifacts.get("network") or []:
        if not isinstance(item, dict) or "_error" in item:
            continue
        local = item.get("local") or ""
        remote = item.get("remote") or ""
        lip, lport = _split_addr(local)
        rip, rport = _split_addr(remote)
        conn.execute(
            """INSERT INTO raw_connections (host_id, collection_id, collected_at_utc, pid,
                                            process_name, local_ip, local_port, remote_ip,
                                            remote_port, proto, status)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (host["id"], collection_id, received, item.get("pid"), item.get("process_name"),
             lip, lport, rip, rport, item.get("proto"), item.get("status")),
        )
    for item in artifacts.get("persistence") or []:
        if not isinstance(item, dict) or "_error" in item:
            continue
        conn.execute(
            """INSERT INTO raw_persistence (host_id, collection_id, collected_at_utc, ptype,
                                            name, command, location)
               VALUES (?,?,?,?,?,?,?)""",
            (host["id"], collection_id, received, item.get("ptype"), item.get("name"),
             item.get("command"), item.get("location")),
        )
    for item in artifacts.get("logs") or []:
        if not isinstance(item, dict) or "_error" in item:
            continue
        log_payload = item.get("payload_json")
        if not isinstance(log_payload, str):
            log_payload = json.dumps(log_payload or {k: v for k, v in item.items() if k != "payload_json"})
        conn.execute(
            """INSERT INTO raw_logs (host_id, collection_id, collected_at_utc, source, event_id,
                                     event_time_utc, provider, computer, payload_json)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (host["id"], collection_id, received, item.get("source"), item.get("event_id"),
             item.get("event_time_utc"), item.get("provider"), item.get("computer"),
             log_payload),
        )
    for item in artifacts.get("files_triage") or []:
        if not isinstance(item, dict) or "_error" in item:
            continue
        matches = json.dumps(item.get("yara_matches")) if item.get("yara_matches") else None
        conn.execute(
            """INSERT INTO raw_files (host_id, collection_id, collected_at_utc, path, sha256,
                                      size_bytes, yara_matches)
               VALUES (?,?,?,?,?,?,?)""",
            (host["id"], collection_id, received, item.get("path"), item.get("sha256"),
             item.get("size_bytes"), matches),
        )
    containers_seen = set()
    for item in artifacts.get("containers") or []:
        if not isinstance(item, dict) or "_error" in item:
            continue
        cid = item.get("container_id")
        if item.get("record") == "process_mapping":
            conn.execute(
                """INSERT INTO raw_processes (host_id, collection_id, collected_at_utc, pid,
                                              name, cmdline, exe_path, sha256, username,
                                              container_id)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (host["id"], collection_id, received, item.get("pid"),
                 item.get("process_name"), None, None, None, None, cid),
            )
            continue
        if item.get("record") != "inventory" or not cid or cid in containers_seen:
            continue
        containers_seen.add(cid)
        conn.execute(
            """INSERT INTO containers (host_id, container_id, container_name, image_name,
                                       status, ip_address, seen_at_utc)
               VALUES (?,?,?,?,?,?,?)
               ON CONFLICT(host_id, container_id) DO UPDATE SET
                   status=excluded.status, ip_address=excluded.ip_address,
                   seen_at_utc=excluded.seen_at_utc""",
            (host["id"], cid, item.get("container_name"), item.get("image_name"),
             item.get("status"), item.get("ip_address"), received),
        )

    manifest_json = json.dumps(manifest, default=str)
    artifact_count = sum(len(v) for v in artifacts.values() if isinstance(v, list))
    conn.execute(
        """INSERT INTO evidence_manifests (host_id, collection_id, started_at_utc, finished_at_utc,
                                           agent_version, collector_order, artifact_count,
                                           manifest_json, manifest_sha256, received_at_utc)
           VALUES (?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(collection_id) DO NOTHING""",
        (host["id"], collection_id, manifest.get("started_at_utc"), manifest.get("finished_at_utc"),
         manifest.get("agent_version"), json.dumps(manifest.get("collector_order") or []),
         artifact_count, manifest_json, manifest.get("manifest_sha256", ""), datetime.now(timezone.utc).isoformat(timespec="seconds")),
    )
    conn.execute(
        "UPDATE hosts SET last_seen_utc=?, agent_version=? WHERE id=?",
        (datetime.now(timezone.utc).isoformat(timespec="seconds"), manifest.get("agent_version"), host["id"]),
    )
    database.audit(conn, f"host:{host['hostname']}", "artifacts_ingested",
                   {"collection_id": collection_id, "artifact_count": artifact_count})
    conn.commit()

    background.add_task(_run_engine_task)
    return {"status": "accepted", "collection_id": collection_id}


def _run_engine_task():
    run_engine()


def _split_addr(addr):
    if not addr or ":" not in addr:
        return addr or None, None
    ip, _, port = addr.rpartition(":")
    try:
        return ip.strip("[]"), int(port)
    except ValueError:
        return addr, None


@app.post("/api/v1/samples")
async def upload_sample(background: BackgroundTasks, file: UploadFile = File(...),
                        note: str = Form(""), ctx=Depends(auth_host)):
    conn = ctx["conn"]
    host = ctx["host"]
    data = await file.read()
    if len(data) > 20 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="sample too large")
    import hashlib
    sha = hashlib.sha256(data).hexdigest()
    tmp_dir = "samples"
    import os
    os.makedirs(tmp_dir, exist_ok=True)
    tmp_path = os.path.join(tmp_dir, sha[:16] + "_" + (file.filename or "sample.bin").replace("\\", "_"))
    with open(tmp_path, "wb") as fh:
        fh.write(data)

    compiled, errors = compile_rules()
    matches = scan_file(tmp_path, compiled=compiled)
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")

    detections = []
    ioc_row = conn.execute("SELECT threat_source FROM ioc_store WHERE ioc_type='hash' AND value=?", (sha,)).fetchone()
    if ioc_row:
        detections.append({
            "host_id": host["id"], "collection_id": None, "detected_at_utc": ts,
            "rule_type": "ioc", "rule_name": f"IOC hash ({ioc_row['threat_source']})",
            "severity": "high", "technique_id": None,
            "summary": json.dumps({"sha256": sha, "filename": file.filename}),
            "evidence": {},
        })
    from server.engine.yara_scanner import _det
    sev_map = {"eicar_test_file": "medium"}
    for m in matches:
        if "rule" not in m:
            continue
        detections.append({
            "host_id": host["id"], "collection_id": None, "detected_at_utc": ts,
            "rule_type": "yara", "rule_name": f"YARA:{m['rule']}",
            "severity": sev_map.get(m["rule"].lower(), "high"), "technique_id": None,
            "summary": json.dumps({"sha256": sha, "filename": file.filename, "note": note}),
            "evidence": m,
        })
    ids = []
    if detections:
        from server.engine import insert_detections
        ids = insert_detections(conn, detections)
        attack_mapper.enrich_detections(conn, detection_ids=ids)
        background.add_task(lambda: None)
    database.audit(conn, f"host:{host['hostname']}", "sample_uploaded",
                   {"sha256": sha, "matches": len(matches)})
    conn.commit()
    return {"sha256": sha, "yara_matches": matches, "detections_created": len(ids), "errors": errors}


@app.post("/api/v1/engine/run")
def engine_run(conn=Depends(get_conn)):
    result = run_engine(conn)
    database.audit(conn, "analyst", "engine_manual_run", result)
    return result


@app.get("/api/v1/hosts")
def list_hosts(conn=Depends(get_conn)):
    rows = conn.execute(
        """SELECT h.id, h.client_id, h.hostname, h.os_type, h.docker_engine_flag,
                  h.enrolled_at_utc, h.last_seen_utc, h.is_active,
                  (SELECT COUNT(*) FROM detections d WHERE d.host_id=h.id) AS detection_count
           FROM hosts h ORDER BY h.id"""
    ).fetchall()
    return [dict(r) for r in rows]


@app.post("/api/v1/hosts/{host_id}/revoke")
def revoke_host(host_id: int, conn=Depends(get_conn)):
    row = conn.execute("SELECT hostname FROM hosts WHERE id=?", (host_id,)).fetchone()
    if not row:
        raise HTTPException(404, "host not found")
    conn.execute("UPDATE hosts SET is_active=0 WHERE id=?", (host_id,))
    database.audit(conn, "analyst", "host_revoked", {"host_id": host_id, "hostname": row["hostname"]})
    conn.commit()
    return {"status": "revoked", "host_id": host_id}


@app.get("/api/v1/detections")
def list_detections(host_id: int | None = None, conn=Depends(get_conn)):
    where, params = "", []
    if host_id:
        where = "WHERE d.host_id = ?"
        params = [host_id]
    rows = conn.execute(
        f"""SELECT d.*, h.hostname, e.technique_name, e.tactic
            FROM detections d JOIN hosts h ON h.id=d.host_id
            LEFT JOIN enriched_detections e ON e.detection_id=d.id {where}
            ORDER BY d.detected_at_utc DESC LIMIT 500""",
        params,
    ).fetchall()
    out = []
    for r in rows:
        item = dict(r)
        if item.get("tactic"):
            try:
                item["tactics_parsed"] = json.loads(item["tactic"])
            except json.JSONDecodeError:
                item["tactics_parsed"] = []
        out.append(item)
    return out


@app.get("/api/v1/timeline")
def get_timeline(host_id: int | None = None, conn=Depends(get_conn)):
    return timeline.build(conn, host_id)


@app.get("/api/v1/soc/{host_id}")
def get_soc(host_id: int, conn=Depends(get_conn)):
    return soc_chain.build(conn, host_id)


@app.post("/api/v1/policies")
def create_policy(body: PolicyRequest, conn=Depends(get_conn)):
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    conn.execute(
        """INSERT INTO policies (name, min_severity, technique_ids, mode, action, enabled, created_at_utc)
           VALUES (?,?,?,?,?,1,?)
           ON CONFLICT(name) DO UPDATE SET min_severity=excluded.min_severity,
               mode=excluded.mode, action=excluded.action""",
        (body.name, body.min_severity, json.dumps(body.technique_ids) if body.technique_ids else None,
         body.mode, body.action, now),
    )
    database.audit(conn, "analyst", "policy_upserted", body.model_dump())
    conn.commit()
    return {"status": "ok"}


@app.get("/api/v1/policies")
def list_policies(conn=Depends(get_conn)):
    return [dict(r) for r in conn.execute("SELECT * FROM policies ORDER BY id DESC")]


@app.get("/api/v1/approvals")
def list_approvals(status: str = "pending", conn=Depends(get_conn)):
    rows = conn.execute(
        """SELECT q.*, d.rule_name, d.severity, d.summary, d.host_id, h.hostname, d.detected_at_utc
           FROM approvals_queue q JOIN detections d ON d.id=q.detection_id
           JOIN hosts h ON h.id=d.host_id
           WHERE q.status=? ORDER BY q.requested_at_utc DESC""",
        (status,),
    ).fetchall()
    return [dict(r) for r in rows]


@app.post("/api/v1/approvals/{approval_id}/decide")
def decide_approval(approval_id: int, body: DecisionRequest, conn=Depends(get_conn)):
    approval = conn.execute("SELECT * FROM approvals_queue WHERE id=?", (approval_id,)).fetchone()
    if not approval:
        raise HTTPException(404, "approval not found")
    if approval["status"] != "pending":
        raise HTTPException(409, f"already decided: {approval['status']}")
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    det = conn.execute("SELECT * FROM detections WHERE id=?", (approval["detection_id"],)).fetchone()
    host = conn.execute("SELECT hostname FROM hosts WHERE id=?", (det["host_id"],)).fetchone() if det else None
    note = {
        "mode": "DRY-RUN (containment actions disabled by policy)",
        "would_execute": approval["action"],
        "target_host": host["hostname"] if host else None,
        "detection": det["rule_name"] if det else None,
    }
    conn.execute(
        """UPDATE approvals_queue SET status=?, decided_at_utc=?, decided_by=?, result_note=?
           WHERE id=?""",
        ("executed_dryrun" if body.decision == "approved" else "rejected",
         now, body.analyst, json.dumps(note), approval_id),
    )
    database.audit(conn, body.analyst, "containment_decision",
                   {"approval_id": approval_id, "decision": body.decision, **note})
    conn.commit()
    return {"status": "ok", "result": note}


@app.post("/api/v1/iocs")
def add_ioc(body: IocRequest, conn=Depends(get_conn)):
    conn.execute(
        """INSERT INTO ioc_store (ioc_type, value, threat_source, description, added_at_utc)
           VALUES (?,?,?,?,?)
           ON CONFLICT(ioc_type, value) DO UPDATE SET threat_source=excluded.threat_source""",
        (body.ioc_type, body.value.lower() if body.ioc_type == "hash" else body.value,
         body.threat_source, body.description, datetime.now(timezone.utc).isoformat(timespec="seconds")),
    )
    database.audit(conn, "analyst", "ioc_added", body.model_dump())
    conn.commit()
    return {"status": "ok"}


@app.get("/api/v1/iocs/search")
def search_ioc(q: str, conn=Depends(get_conn)):
    ql = q.lower().strip()
    pivot = {"processes": [], "connections": [], "files": []}
    if len(ql) == 64:
        pivot["processes"] = [
            dict(r) for r in conn.execute(
                """SELECT r.*, h.hostname FROM raw_processes r JOIN hosts h ON h.id=r.host_id
                   WHERE r.sha256=? LIMIT 50""", (ql,))
        ]
        pivot["files"] = [
            dict(r) for r in conn.execute(
                """SELECT r.*, h.hostname FROM raw_files r JOIN hosts h ON h.id=r.host_id
                   WHERE r.sha256=? LIMIT 50""", (ql,))
        ]
    else:
        pivot["connections"] = [
            dict(r) for r in conn.execute(
                """SELECT r.*, h.hostname FROM raw_connections r JOIN hosts h ON h.id=r.host_id
                   WHERE r.remote_ip LIKE ? OR r.remote_port=? LIMIT 50""",
                (f"%{q}%", q if q.isdigit() else -1))
        ]
    hits = conn.execute(
        "SELECT COUNT(*) AS n FROM ioc_store WHERE value=?", (ql,)
    ).fetchone()["n"]
    return {"query": q, "known_ioc": bool(hits), "pivot": pivot}


@app.get("/api/v1/export/report/{host_id}.pdf")
def export_pdf(host_id: int, conn=Depends(get_conn)):
    path = reporter.generate_pdf(conn, host_id)
    if not path:
        raise HTTPException(404, "host not found")
    return FileResponse(path, media_type="application/pdf", filename=os_path(path))


def os_path(p):
    import os
    return os.path.basename(p)


@app.get("/api/v1/export/report/{host_id}.json")
def export_json(host_id: int, conn=Depends(get_conn)):
    path = reporter.generate_json(conn, host_id)
    if not path:
        raise HTTPException(404, "host not found")
    return FileResponse(path, media_type="application/json", filename=os_path(path))


@app.get("/api/v1/export/stix/{host_id}.json")
def export_stix(host_id: int, conn=Depends(get_conn)):
    path = reporter.generate_stix(conn, host_id)
    return FileResponse(path, media_type="application/json", filename=os_path(path))


@app.get("/api/v1/export/navigator.json")
def export_navigator(conn=Depends(get_conn)):
    path = reporter.generate_navigator_layer(conn)
    return FileResponse(path, media_type="application/json", filename=os_path(path))


@app.get("/health")
def health():
    return {"status": "ok", "time": datetime.now(timezone.utc).isoformat(timespec="seconds")}


@app.get("/api/v1/stats/overview")
def stats_overview(conn=Depends(get_conn)):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for r in conn.execute("SELECT severity, COUNT(*) AS n FROM detections GROUP BY severity"):
        if r["severity"] in counts:
            counts[r["severity"]] = r["n"]
    total = sum(counts.values())
    hosts_active = conn.execute("SELECT COUNT(*) AS n FROM hosts WHERE is_active=1").fetchone()["n"]
    manifests = conn.execute("SELECT COUNT(*) AS n FROM evidence_manifests").fetchone()["n"]
    pending = conn.execute(
        "SELECT COUNT(*) AS n FROM approvals_queue WHERE status='pending'").fetchone()["n"]

    now = datetime.now(timezone.utc)
    cutoff = (now - timedelta(hours=23)).strftime("%Y-%m-%dT%H")
    buckets = {}
    for r in conn.execute(
        "SELECT substr(detected_at_utc,1,13) AS h, COUNT(*) AS n FROM detections"
        " WHERE detected_at_utc >= ? GROUP BY h",
        (cutoff,),
    ):
        buckets[r["h"]] = r["n"]
    trend = []
    for i in range(23, -1, -1):
        hr = (now - timedelta(hours=i)).strftime("%Y-%m-%dT%H")
        trend.append({"hour": hr[11:] + ":00", "count": buckets.get(hr, 0)})
    return {
        "counts": counts,
        "total": total,
        "hosts_active": hosts_active,
        "manifests": manifests,
        "approvals_pending": pending,
        "trend": trend,
        "generated_at": now.isoformat(timespec="seconds"),
    }


@app.get("/api/v1/stream/events")
async def stream_events(request: Request, interval: float = 5.0, limit: int = 15):
    from asyncio import sleep
    from starlette.concurrency import run_in_threadpool

    interval = max(2.0, min(interval, 60.0))
    limit = max(1, min(limit, 50))

    def _query(cursor):
        c = database.connect()
        try:
            rows = c.execute(
                """SELECT d.id, d.detected_at_utc, d.rule_name, d.rule_type, d.severity,
                          d.technique_id, h.hostname
                   FROM detections d JOIN hosts h ON h.id = d.host_id
                   WHERE d.id > ? ORDER BY d.id ASC LIMIT ?""",
                (cursor, limit),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            c.close()

    async def gen():
        def _initial():
            c = database.connect()
            try:
                rows = c.execute(
                    """SELECT d.id, d.detected_at_utc, d.rule_name, d.rule_type, d.severity,
                              d.technique_id, h.hostname
                       FROM detections d JOIN hosts h ON h.id = d.host_id
                       ORDER BY d.id DESC LIMIT ?""",
                    (limit,),
                ).fetchall()
                return [dict(r) for r in rows]
            finally:
                c.close()

        rows = await run_in_threadpool(_initial)
        rows.reverse()
        last_id = 0
        for r in rows:
            last_id = max(last_id, r["id"])
            yield f"data: {json.dumps(r)}\n\n"
        yield ": stream-ready\n\n"
        while True:
            if await request.is_disconnected():
                break
            new_rows = await run_in_threadpool(_query, last_id)
            for r in new_rows:
                last_id = max(last_id, r["id"])
                yield f"data: {json.dumps(r)}\n\n"
            yield f": heartbeat {datetime.now(timezone.utc).isoformat(timespec='seconds')}\n\n"
            await sleep(interval)

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# =============================================================================
# RESOURCE TELEMETRY ENDPOINTS
# =============================================================================

# Anomaly detection thresholds (can be overridden via env)
# dir: "high" fires when value >= abs; "low" fires when value <= abs
_RESOURCE_THRESHOLDS = {
    "cpu_pct": {"abs": 90.0, "z": 3.0, "sev": "high", "dir": "high"},
    "mem_pct": {"abs": 92.0, "z": 3.0, "sev": "high", "dir": "high"},
    "swap_pct": {"abs": 85.0, "z": 3.0, "sev": "medium", "dir": "high"},
    "disk_read_kbps": {"abs": 50000.0, "z": 3.0, "sev": "medium", "dir": "high"},
    "disk_write_kbps": {"abs": 50000.0, "z": 3.0, "sev": "medium", "dir": "high"},
    "net_sent_kbps": {"abs": 20000.0, "z": 3.0, "sev": "medium", "dir": "high"},
    "net_recv_kbps": {"abs": 20000.0, "z": 3.0, "sev": "medium", "dir": "high"},
    "gpu_util_pct": {"abs": 95.0, "z": 3.0, "sev": "medium", "dir": "high"},
    "battery_pct": {"abs": 15.0, "z": 3.0, "sev": "high", "dir": "low"},
}
_ALERT_COOLDOWN_S = 120  # per host+metric


def _check_resource_anomalies(conn, host_id: int, sample: dict) -> list[dict]:
    """Check sample against rolling baseline + absolute thresholds.
    Returns list of alert dicts to insert."""
    import statistics
    alerts = []
    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
    cooldown_cutoff = datetime.now(timezone.utc) - timedelta(seconds=_ALERT_COOLDOWN_S)
    cooldown_iso = cooldown_cutoff.isoformat(timespec="seconds")

    for metric, thresh in _RESOURCE_THRESHOLDS.items():
        val = sample.get(metric)
        if val is None:
            continue
        low_dir = thresh.get("dir") == "low"

        # Check absolute threshold (direction-aware)
        abs_trigger = (val <= thresh["abs"]) if low_dir else (val >= thresh["abs"])

        # Rolling baseline from last 20 samples
        rows = conn.execute(
            f"SELECT {metric} FROM resource_samples WHERE host_id=? AND {metric} IS NOT NULL ORDER BY id DESC LIMIT 20",
            (host_id,),
        ).fetchall()
        vals = [r[0] for r in rows if r[0] is not None]

        stat_trigger = False
        baseline = None
        if len(vals) >= 10:
            try:
                mean = statistics.mean(vals)
                stdev = statistics.stdev(vals) if len(vals) > 1 else 0.0
                baseline = mean
                # Avoid tiny stdev causing false positives
                if stdev < 1.0:
                    stdev = 1.0
                if low_dir:
                    stat_trigger = val <= mean - thresh["z"] * stdev
                else:
                    stat_trigger = val >= mean + thresh["z"] * stdev
            except Exception:
                pass

        if abs_trigger or stat_trigger:
            # Check cooldown: has same metric alerted recently for this host?
            recent = conn.execute(
                "SELECT 1 FROM resource_alerts WHERE host_id=? AND metric=? AND ts_utc > ? LIMIT 1",
                (host_id, metric, (datetime.now(timezone.utc) - timedelta(seconds=_ALERT_COOLDOWN_S)).isoformat(timespec="seconds")),
            ).fetchone()
            if recent:
                continue  # still in cooldown

            if abs_trigger and stat_trigger:
                sev = thresh["sev"]
            elif abs_trigger:
                sev = "medium" if thresh["sev"] == "high" else "low"
            else:
                sev = "low"

            msg = f"{metric} = {val:.1f}"
            if baseline is not None:
                msg += f" (baseline {baseline:.1f})"
            arrow = "<=" if low_dir else ">="
            if abs_trigger:
                msg += f" {arrow} absolute {_RESOURCE_THRESHOLDS[metric]['abs']}"
            if stat_trigger:
                sig = "-" if low_dir else "+"
                msg += f" {arrow} baseline {sig} {thresh['z']}σ"

            alerts.append({
                "host_id": host_id,
                "ts_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "metric": metric,
                "value": float(val),
                "baseline": baseline,
                "message": msg,
                "severity": sev,
            })
    return alerts


def _maybe_prune_resources(conn):
    """Opportunistic pruning: every ~100th insert triggers a prune."""
    cnt = conn.execute("SELECT value FROM kv WHERE key='res_insert_count'").fetchone()
    cnt = int(cnt["value"]) if cnt else 0
    cnt += 1
    if cnt % 100 == 0:
        database.prune_old_resource_samples(conn)
    conn.execute(
        "INSERT OR REPLACE INTO kv (key, value) VALUES ('res_insert_count', ?)",
        (str(cnt),),
    )


@app.post("/api/v1/ingest/resources", status_code=202)
def ingest_resources(body: SamplesRequest, ctx=Depends(auth_host)):
    conn = ctx["conn"]
    host = ctx["host"]
    samples = [s.model_dump() for s in body.samples]
    if not samples:
        raise HTTPException(status_code=400, detail="no samples provided")
    # Limit batch size
    if len(samples) > 24:
        raise HTTPException(status_code=400, detail="too many samples in batch (max 24)")

    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
    alerts_all = []

    for s in samples:
        ts = s.get("sampled_at_utc") or datetime.now(timezone.utc).isoformat(timespec="seconds")
        # Insert sample
        conn.execute(
            """INSERT INTO resource_samples (
                host_id, sampled_at_utc, cpu_pct, mem_used_mb, mem_pct, swap_pct,
                disk_read_kbps, disk_write_kbps, net_sent_kbps, net_recv_kbps,
                gpu_present, gpu_util_pct, gpu_mem_used_mb,
                battery_pct, battery_plugged, hw_tier, cpu_cores, mem_total_mb,
                anomaly, anomaly_json
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                host["id"],
                ts,
                s.get("cpu_pct"),
                s.get("mem_used_mb"),
                s.get("mem_pct"),
                s.get("swap_pct"),
                s.get("disk_read_kbps"),
                s.get("disk_write_kbps"),
                s.get("net_sent_kbps"),
                s.get("net_recv_kbps"),
                s.get("gpu_present", 0),
                s.get("gpu_util_pct"),
                s.get("gpu_mem_used_mb"),
                s.get("battery_pct"),
                s.get("battery_plugged"),
                s.get("hw_tier"),
                s.get("cpu_cores"),
                s.get("mem_total_mb"),
                0,  # anomaly (set below if any)
                None,
            ),
        )
        sample_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        # Anomaly check
        alerts = _check_resource_anomalies(conn, host["id"], s)
        if alerts:
            conn.execute(
                "UPDATE resource_samples SET anomaly=1, anomaly_json=? WHERE id=?",
                (json.dumps([a["message"] for a in alerts]), sample_id),
            )
            for a in alerts:
                conn.execute(
                    """INSERT INTO resource_alerts (host_id, ts_utc, metric, value, baseline, message, severity)
                       VALUES (?,?,?,?,?,?,?)""",
                    (a["host_id"], a["ts_utc"], a["metric"], a["value"], a["baseline"], a["message"], a["severity"]),
                )
            alerts_all.extend(alerts)

    _maybe_prune_resources(conn)
    conn.commit()
    database.audit(conn, f"host:{host['hostname']}", "resources_ingested", {"count": len(samples), "alerts": len(alerts_all)})
    return {"status": "accepted", "count": len(samples), "alerts": len(alerts_all)}


@app.get("/api/v1/resources/latest")
def resources_latest(conn=Depends(get_conn)):
    """Latest resource sample per active host."""
    rows = conn.execute(
        """SELECT h.id, h.hostname, h.os_type, h.docker_engine_flag, h.last_seen_utc,
                  s.sampled_at_utc, s.cpu_pct, s.mem_used_mb, s.mem_pct, s.swap_pct,
                  s.disk_read_kbps, s.disk_write_kbps, s.net_sent_kbps, s.net_recv_kbps,
                  s.gpu_present, s.gpu_util_pct, s.gpu_mem_used_mb,
                  s.battery_pct, s.battery_plugged, s.hw_tier, s.cpu_cores, s.mem_total_mb,
                  s.anomaly
           FROM hosts h
           LEFT JOIN resource_samples s ON s.id = (
               SELECT MAX(id) FROM resource_samples WHERE host_id = h.id
           )
           WHERE h.is_active=1
           ORDER BY h.hostname"""
    ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        # compute staleness (datetime/timezone are module-level imports)
        if d.get("sampled_at_utc"):
            try:
                ts = datetime.fromisoformat(str(d["sampled_at_utc"]).replace("Z", "+00:00"))
                age = (datetime.now(timezone.utc) - ts).total_seconds()
                d["stale"] = age > 60  # > 60s = stale
            except Exception:
                d["stale"] = True
        else:
            d["stale"] = True
        out.append(d)
    return {"hosts": out, "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}


@app.get("/api/v1/resources/history")
def resources_history(
    host_id: int,
    minutes: int = 30,
    metrics: str = "cpu_pct,mem_pct,net_recv_kbps,net_sent_kbps",
    limit: int = 500,
    conn=Depends(get_conn),
):
    """Time-series history for charts. Returns up to `limit` points."""
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat(timespec="seconds")
    metric_list = [m.strip() for m in metrics.split(",") if m.strip()]
    allowed = {"cpu_pct", "mem_pct", "mem_used_mb", "swap_pct",
               "disk_read_kbps", "disk_write_kbps", "net_sent_kbps", "net_recv_kbps",
               "gpu_util_pct", "battery_pct"}
    metric_list = [m for m in metric_list if m in allowed]
    if not metric_list:
        metric_list = ["cpu_pct", "mem_pct", "net_recv_kbps", "net_sent_kbps"]
    cols = ", ".join(metric_list)
    rows = conn.execute(
        f"SELECT sampled_at_utc, {cols} FROM resource_samples WHERE host_id=? AND sampled_at_utc >= ? ORDER BY id ASC",
        (host_id, cutoff),
    ).fetchall()
    # Downsample to `limit` points if needed
    if len(rows) > limit:
        step = len(rows) / limit
        rows = [rows[int(i * step)] for i in range(limit)]
    return {"host_id": host_id, "points": [dict(r) for r in rows]}


@app.get("/api/v1/resources/alerts")
def resources_alerts(
    host_id: int | None = None,
    limit: int = 50,
    conn=Depends(get_conn),
):
    """Recent resource alerts."""
    sql = "SELECT a.*, h.hostname FROM resource_alerts a JOIN hosts h ON h.id=a.host_id"
    params = []
    if host_id is not None:
        sql += " WHERE a.host_id=?"
        params.append(host_id)
    sql += " ORDER BY a.ts_utc DESC LIMIT ?"
    params.append(min(limit, 200))
    rows = conn.execute(sql, params).fetchall()
    return {"alerts": [dict(r) for r in rows]}


@app.get("/api/v1/stream/resources")
async def stream_resources(request: Request, interval: float = 5.0, limit: int = 15):
    """SSE stream: {samples: [...], alerts: [...]} frames."""
    from asyncio import sleep
    from starlette.concurrency import run_in_threadpool

    interval = max(2.0, min(interval, 60.0))
    limit = max(1, min(limit, 50))

    def _query(cursor):
        c = database.connect()
        try:
            rows = c.execute(
                """SELECT s.*, h.hostname, h.os_type, h.docker_engine_flag
                   FROM resource_samples s JOIN hosts h ON h.id=s.host_id
                   WHERE s.id > ? ORDER BY s.id ASC LIMIT ?""",
                (cursor, limit),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            c.close()

    def _alert_query(cursor):
        c = database.connect()
        try:
            rows = c.execute(
                """SELECT a.*, h.hostname FROM resource_alerts a
                   JOIN hosts h ON h.id=a.host_id
                   WHERE a.id > ? ORDER BY a.id ASC LIMIT ?""",
                (cursor, limit),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            c.close()

    async def gen():
        def _initial():
            c = database.connect()
            try:
                # latest sample per host
                rows = c.execute(
                    """SELECT s.*, h.hostname, h.os_type, h.docker_engine_flag
                       FROM resource_samples s JOIN hosts h ON h.id=s.host_id
                       WHERE s.id IN (
                           SELECT MAX(id) FROM resource_samples GROUP BY host_id
                       )"""
                ).fetchall()
                alerts = c.execute(
                    """SELECT a.*, h.hostname FROM resource_alerts a
                       JOIN hosts h ON h.id=a.host_id
                       ORDER BY a.id DESC LIMIT ?""",
                    (limit,),
                ).fetchall()
                return [dict(r) for r in rows], [dict(r) for r in alerts[::-1]]
            finally:
                c.close()

        samples, alerts = await run_in_threadpool(_initial)
        last_sample_id = max((s["id"] for s in samples), default=0)
        last_alert_id = max((a["id"] for a in alerts), default=0)
        for s in samples:
            yield f"data: {json.dumps({'samples': [s], 'alerts': []})}\n\n"
        for a in alerts:
            yield f"data: {json.dumps({'samples': [], 'alerts': [a]})}\n\n"
        yield ": stream-ready\n\n"
        while True:
            if await request.is_disconnected():
                break
            new_samples = await run_in_threadpool(_query, last_sample_id)
            new_alerts = await run_in_threadpool(_alert_query, last_alert_id)
            for s in new_samples:
                last_sample_id = max(last_sample_id, s["id"])
                yield f"data: {json.dumps({'samples': [s], 'alerts': []})}\n\n"
            for a in new_alerts:
                last_alert_id = max(last_alert_id, a["id"])
                yield f"data: {json.dumps({'samples': [], 'alerts': [a]})}\n\n"
            yield f": heartbeat {datetime.now(timezone.utc).isoformat(timespec='seconds')}\n\n"
            await sleep(interval)

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
