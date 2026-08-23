import json
from datetime import datetime, timezone

import requests as http_requests
from fastapi import BackgroundTasks, Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
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
