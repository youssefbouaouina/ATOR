import hashlib
import json
import os
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
    cooldown_minutes: int | None = None


class DecisionRequest(BaseModel):
    decision: str = Field(pattern="^(approved|rejected)$")
    analyst: str = "analyst"


class IocRequest(BaseModel):
    ioc_type: str = Field(pattern="^(hash|ip|domain)$")
    value: str
    threat_source: str = "analyst-watchlist"
    description: str | None = None


class HeartbeatRequest(BaseModel):
    """Agent-reported liveness/state, sent on a short interval."""
    state: str = Field(default="running", pattern="^(running|paused|stopping)$")
    agent_version: str | None = None
    telemetry_mode: str | None = None
    spool_count: int | None = None


class AgentStateRequest(BaseModel):
    """Analyst-requested agent lifecycle state for an endpoint."""
    state: str = Field(pattern="^(running|paused)$")
    requested_by: str = "analyst-ui"


class CommandResultRequest(BaseModel):
    status: str = Field(pattern="^(done|failed)$")
    detail: dict | None = None


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


class AgentSelfSampleIn(BaseModel):
    sampled_at_utc: str | None = None
    agent_cpu_pct: float | None = None
    agent_mem_mb: float | None = None
    agent_threads: int | None = None
    agent_fds: int | None = None
    agent_cpu_time_user: float | None = None
    agent_cpu_time_system: float | None = None
    collection_duration_ms: float | None = None
    payload_size_bytes: int | None = None
    spool_count: int | None = None


class AgentSelfSamplesRequest(BaseModel):
    samples: list[AgentSelfSampleIn]


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


# Natural-key columns stored bare in the ux_raw_*_dedupe indexes; every other
# key column is indexed as COALESCE(col, default) (see server/db.py).
_DEDUPE_BARE_COLUMNS = {"host_id", "ptype", "path"}
_DEDUPE_INT_COLUMNS = {"pid", "local_port", "remote_port", "event_id"}


def _dedupe_key_term(name):
    """WHERE term matching the dedupe index expression for ``name``.

    The terms must mirror the index expressions exactly: with plain
    ``col IS ?`` SQLite can only use the host_id prefix and scans every row of
    the host for each artifact, holding the write lock for about a minute per
    ingest on a busy Windows host (other writes then fail with "database is
    locked").
    """
    if name in _DEDUPE_BARE_COLUMNS:
        return f"{name} IS ?"
    default = "-1" if name in _DEDUPE_INT_COLUMNS else "''"
    return f"COALESCE({name},{default}) = COALESCE(?,{default})"


def _upsert_observation(conn, table, columns, values, key_columns, received, collection_id):
    """Insert a new artifact row or refresh the one matching its natural key.

    Agents re-report the same processes/connections/persistence/files every
    collection cycle, so repeated observations update the existing row
    (last_seen_utc + observation_count) instead of inserting a duplicate.

    UPDATE-then-INSERT is used deliberately: it behaves correctly whether or not
    the natural-key unique index exists yet, and the index simply makes the
    lookup O(log n).
    """
    key_values = [values[columns.index(name)] for name in key_columns]
    where = " AND ".join(_dedupe_key_term(name) for name in key_columns)
    updated = conn.execute(
        f"UPDATE {table} SET collection_id=?, collected_at_utc=?, last_seen_utc=?,"
        f" observation_count=observation_count+1 WHERE {where}",
        [collection_id, received, received] + key_values,
    ).rowcount
    if updated:
        return False
    placeholders = ",".join("?" for _ in columns)
    conn.execute(
        f"INSERT INTO {table} ({','.join(columns)}, first_seen_utc, last_seen_utc, observation_count)"
        f" VALUES ({placeholders},?,?,1)",
        list(values) + [received, received],
    )
    return True


def _payload_sha256(payload_json):
    """Hash of the event payload in canonical form - the v2 log identity.

    Key order is normalised first. Two re-sends of one event must hash the same
    even if a serialiser orders keys differently, or the agent's overlapping
    re-send window would be stored twice. A payload that is not valid JSON is
    hashed as-is.
    """
    text = payload_json if isinstance(payload_json, str) else json.dumps(payload_json)
    try:
        text = json.dumps(json.loads(text), sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        pass
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def _insert_log(conn, row):
    """Insert a log event once; identical events re-sent by the agent are dropped.

    "Identical" includes the payload. The agent timestamps events to the second,
    so source+second+event_id+provider alone collapsed genuinely different events
    that shared a second (a burst of process creations kept only its first).
    """
    return conn.execute(
        """INSERT INTO raw_logs (host_id, collection_id, collected_at_utc, source, event_id,
                                 event_time_utc, provider, computer, payload_json, payload_sha256)
           VALUES (?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT DO NOTHING""",
        tuple(row) + (_payload_sha256(row[8]),),
    ).rowcount


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

    counts = {"inserted": 0, "deduped": 0}
    for item in artifacts.get("processes") or []:
        if not isinstance(item, dict) or "_error" in item:
            continue
        inserted = _upsert_observation(
            conn, "raw_processes",
            ["host_id", "collection_id", "collected_at_utc", "pid", "ppid", "name",
             "cmdline", "exe_path", "sha256", "username", "create_time_utc"],
            [host["id"], collection_id, received, item.get("pid"), item.get("ppid"),
             item.get("name"), item.get("cmdline"), item.get("exe_path"),
             item.get("sha256"), item.get("username"),
             # Older agents do not send this; NULL is the honest value for "not reported"
             # and the ML timing features skip the row rather than inventing a time.
             item.get("create_time_utc")],
            # create_time_utc is part of the identity: a new process that reuses a PID
            # with the same command line is a different process, not a re-observation.
            # Without it the new instance inherited the old one's parent and start time.
            ["host_id", "pid", "name", "cmdline", "exe_path", "sha256", "create_time_utc"],
            received, collection_id,
        )
        counts["inserted" if inserted else "deduped"] += 1
    for item in artifacts.get("network") or []:
        if not isinstance(item, dict) or "_error" in item:
            continue
        local = item.get("local") or ""
        remote = item.get("remote") or ""
        lip, lport = _split_addr(local)
        rip, rport = _split_addr(remote)
        rdomain = item.get("remote_domain")
        counts["inserted" if _upsert_observation(
            conn, "raw_connections",
            ["host_id", "collection_id", "collected_at_utc", "pid", "process_name",
             "local_ip", "local_port", "remote_ip", "remote_port", "remote_domain", "proto", "status"],
            [host["id"], collection_id, received, item.get("pid"), item.get("process_name"),
             lip, lport, rip, rport, rdomain, item.get("proto"), item.get("status")],
            ["host_id", "pid", "local_ip", "local_port", "remote_ip", "remote_port", "proto"],
            received, collection_id,
        ) else "deduped"] += 1
    for item in artifacts.get("persistence") or []:
        if not isinstance(item, dict) or "_error" in item:
            continue
        counts["inserted" if _upsert_observation(
            conn, "raw_persistence",
            ["host_id", "collection_id", "collected_at_utc", "ptype", "name", "command", "location"],
            [host["id"], collection_id, received, item.get("ptype"), item.get("name"),
             item.get("command"), item.get("location")],
            ["host_id", "ptype", "name", "command", "location"],
            received, collection_id,
        ) else "deduped"] += 1
    for item in artifacts.get("logs") or []:
        if not isinstance(item, dict) or "_error" in item:
            continue
        log_payload = item.get("payload_json")
        if not isinstance(log_payload, str):
            log_payload = json.dumps(log_payload or {k: v for k, v in item.items() if k != "payload_json"})
        counts["inserted" if _insert_log(conn, (
            host["id"], collection_id, received, item.get("source"), item.get("event_id"),
            item.get("event_time_utc"), item.get("provider"), item.get("computer"), log_payload,
        )) else "deduped"] += 1
    for item in artifacts.get("files_triage") or []:
        if not isinstance(item, dict) or "_error" in item:
            continue
        matches = json.dumps(item.get("yara_matches")) if item.get("yara_matches") else None
        counts["inserted" if _upsert_observation(
            conn, "raw_files",
            ["host_id", "collection_id", "collected_at_utc", "path", "sha256",
             "size_bytes", "yara_matches"],
            [host["id"], collection_id, received, item.get("path"), item.get("sha256"),
             item.get("size_bytes"), matches],
            ["host_id", "path", "sha256"],
            received, collection_id,
        ) else "deduped"] += 1
    containers_seen = set()
    for item in artifacts.get("containers") or []:
        if not isinstance(item, dict) or "_error" in item:
            continue
        cid = item.get("container_id")
        if item.get("record") == "process_mapping":
            counts["inserted" if _upsert_observation(
                conn, "raw_processes",
                ["host_id", "collection_id", "collected_at_utc", "pid", "name", "cmdline",
                 "exe_path", "sha256", "username", "container_id"],
                [host["id"], collection_id, received, item.get("pid"),
                 item.get("process_name"), None, None, None, None, cid],
                ["host_id", "pid", "name", "cmdline", "exe_path", "sha256"],
                received, collection_id,
            ) else "deduped"] += 1
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
    received_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    conn.execute(
        """UPDATE hosts SET last_seen_utc=?, agent_version=?, last_heartbeat_utc=? WHERE id=?""",
        (received_at, manifest.get("agent_version"), received_at, host["id"]),
    )
    database.audit(conn, f"host:{host['hostname']}", "artifacts_ingested",
                   {"collection_id": collection_id, "artifact_count": artifact_count,
                    "inserted": counts["inserted"], "deduped": counts["deduped"]})
    conn.commit()

    background.add_task(_run_engine_task)
    return {"status": "accepted", "collection_id": collection_id,
            "inserted": counts["inserted"], "deduped": counts["deduped"]}


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
def engine_run(host_id: int | None = None, scan_history: bool = False, conn=Depends(get_conn)):
    """Run the detection engine, optionally scoped to a single endpoint.

    host_id limits the scan to that host's unprocessed collections. scan_history
    additionally queues containment approvals for recent detections (capped), so
    a newly created policy can be applied without a full unfiltered history scan.
    """
    host_ids = [host_id] if host_id else None
    result = run_engine(conn, host_ids=host_ids, scan_history=scan_history)
    database.audit(conn, "analyst", "engine_manual_run", result)
    return result


class DemoPurgeRequest(BaseModel):
    ioc_source: str | None = None
    port: int = 4444


@app.post("/api/v1/demo/purge")
def demo_purge(body: DemoPurgeRequest, ctx=Depends(auth_host)):
    """Remove only this host's demo-scoped signals (auth: the host itself).

    Lets a remote endpoint self-clean after running the capability demo without
    shell access to the server. Scoped to demo markers + the demo IOC source +
    loopback port, and to the authenticated host, so real telemetry is untouched.
    """
    from server import demo
    conn = ctx["conn"]
    host = ctx["host"]
    result = demo.purge_host_demo_data(conn, host["id"], body.ioc_source, body.port)
    database.audit(conn, f"host:{host['hostname']}", "demo_data_purged", result)
    conn.commit()
    return result


@app.get("/api/v1/hosts")
def list_hosts(conn=Depends(get_conn)):
    rows = conn.execute(
        """SELECT h.id, h.client_id, h.hostname, h.os_type, h.docker_engine_flag,
                  h.enrolled_at_utc, h.last_seen_utc, h.is_active, h.agent_version,
                  h.agent_desired_state, h.agent_reported_state, h.last_heartbeat_utc,
                  h.agent_state_changed_at_utc,
                  (SELECT COUNT(*) FROM detections d WHERE d.host_id=h.id) AS detection_count,
                  (SELECT COUNT(*) FROM agent_commands c
                    WHERE c.host_id=h.id AND c.status IN ('pending','claimed')) AS commands_active
           FROM hosts h ORDER BY h.id"""
    ).fetchall()
    out = []
    for row in rows:
        item = dict(row)
        item["agent_status"] = classify_agent_status(row)
        out.append(item)
    return out


@app.post("/api/v1/hosts/{host_id}/revoke")
def revoke_host(host_id: int, conn=Depends(get_conn)):
    row = conn.execute("SELECT hostname FROM hosts WHERE id=?", (host_id,)).fetchone()
    if not row:
        raise HTTPException(404, "host not found")
    conn.execute("UPDATE hosts SET is_active=0 WHERE id=?", (host_id,))
    database.audit(conn, "analyst", "host_revoked", {"host_id": host_id, "hostname": row["hostname"]})
    conn.commit()
    return {"status": "revoked", "host_id": host_id}


def classify_agent_status(row, now=None):
    """Derive the effective agent status for an endpoint record.

    revoked  - API key disabled by an analyst
    paused   - analyst asked the agent to stop collecting
    never    - enrolled but no heartbeat ever received
    offline  - no recent heartbeat (endpoint down, agent stopped or unreachable)
    running  - fresh heartbeat and collecting
    """
    def field(name):
        try:
            return row[name]
        except (KeyError, IndexError, TypeError):
            return None

    if not field("is_active"):
        return "revoked"
    if (field("agent_desired_state") or "running") == "paused":
        return "paused"
    last = field("last_heartbeat_utc")
    if not last:
        return "never"
    now = now or datetime.now(timezone.utc)
    try:
        seen = datetime.fromisoformat(str(last).replace("Z", "+00:00"))
        if seen.tzinfo is None:
            seen = seen.replace(tzinfo=timezone.utc)
    except ValueError:
        return "never"
    stale_after = int(os.environ.get("ATOR_HEARTBEAT_STALE_SECONDS", "180"))
    if (now - seen).total_seconds() > stale_after:
        return "offline"
    return "running"


def _agent_state_changed(conn, host_id, desired, actor):
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    conn.execute(
        "UPDATE hosts SET agent_desired_state=?, agent_state_changed_at_utc=? WHERE id=?",
        (desired, now, host_id),
    )
    database.audit(conn, actor, "agent_state_changed", {"host_id": host_id, "desired_state": desired})


def _queue_command(conn, host_id, command, actor="analyst-ui"):
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    cur = conn.execute(
        """INSERT INTO agent_commands (host_id, command, status, requested_by, created_at_utc)
           VALUES (?,?,'pending',?,?)""",
        (host_id, command, actor, now),
    )
    return cur.lastrowid


@app.post("/api/v1/agent/heartbeat")
def agent_heartbeat(body: HeartbeatRequest, ctx=Depends(auth_host)):
    """Agent liveness + control channel.

    The server cannot dial the endpoint, so the agent polls here: each call
    records liveness and returns the desired state plus any queued commands
    (manual collection requests). Pending commands are claimed on delivery.
    """
    conn = ctx["conn"]
    host = ctx["host"]
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    conn.execute(
        """UPDATE hosts SET last_seen_utc=?, last_heartbeat_utc=?, agent_reported_state=?,
                            agent_version=COALESCE(?, agent_version)
           WHERE id=?""",
        (now, now, body.state, body.agent_version, host["id"]),
    )
    desired = conn.execute(
        "SELECT agent_desired_state FROM hosts WHERE id=?", (host["id"],)
    ).fetchone()["agent_desired_state"] or "running"

    commands = []
    if desired == "running":
        commands = [
            dict(r) for r in conn.execute(
                """SELECT id, command FROM agent_commands
                   WHERE host_id=? AND status='pending' ORDER BY id LIMIT 5""",
                (host["id"],),
            )
        ]
        for cmd in commands:
            conn.execute(
                "UPDATE agent_commands SET status='claimed', claimed_at_utc=? WHERE id=?",
                (now, cmd["id"]),
            )
    conn.commit()
    return {
        "desired_state": desired,
        "heartbeat_interval_seconds": int(os.environ.get("ATOR_HEARTBEAT_INTERVAL", "20")),
        "commands": commands,
        "server_time_utc": now,
    }


@app.post("/api/v1/agent/commands/{command_id}/result")
def agent_command_result(command_id: int, body: CommandResultRequest, ctx=Depends(auth_host)):
    conn = ctx["conn"]
    host = ctx["host"]
    row = conn.execute(
        "SELECT * FROM agent_commands WHERE id=? AND host_id=?", (command_id, host["id"])
    ).fetchone()
    if not row:
        raise HTTPException(404, "command not found")
    if row["status"] in ("done", "failed"):
        raise HTTPException(409, f"already finished: {row['status']}")
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    conn.execute(
        "UPDATE agent_commands SET status=?, finished_at_utc=?, result=? WHERE id=?",
        (body.status, now, json.dumps(body.detail or {}), command_id),
    )
    database.audit(conn, f"host:{host['hostname']}", f"agent_command_{body.status}",
                   {"command_id": command_id, "command": row["command"]})
    conn.commit()
    return {"status": "ok", "command_id": command_id, "command_status": body.status}


@app.get("/api/v1/hosts/{host_id}/commands")
def list_host_commands(host_id: int, limit: int = 20, conn=Depends(get_conn)):
    rows = conn.execute(
        "SELECT * FROM agent_commands WHERE host_id=? ORDER BY id DESC LIMIT ?",
        (host_id, max(1, min(limit, 200))),
    ).fetchall()
    return [dict(r) for r in rows]


@app.post("/api/v1/hosts/{host_id}/agent/state")
def set_agent_state(host_id: int, body: AgentStateRequest, conn=Depends(get_conn)):
    """Pause or resume an endpoint's agent (applied on its next heartbeat)."""
    row = conn.execute("SELECT * FROM hosts WHERE id=?", (host_id,)).fetchone()
    if not row:
        raise HTTPException(404, "host not found")
    if not row["is_active"]:
        raise HTTPException(409, "host API key is revoked")
    _agent_state_changed(conn, host_id, body.state, body.requested_by)
    conn.commit()
    return {"status": "ok", "host_id": host_id, "desired_state": body.state,
            "note": "the agent applies this on its next heartbeat"}


@app.post("/api/v1/hosts/{host_id}/collect")
def request_collection(host_id: int, conn=Depends(get_conn)):
    """Queue an immediate collection on the endpoint (delivered via heartbeat)."""
    row = conn.execute("SELECT * FROM hosts WHERE id=?", (host_id,)).fetchone()
    if not row:
        raise HTTPException(404, "host not found")
    if not row["is_active"]:
        raise HTTPException(409, "host API key is revoked")
    if (row["agent_desired_state"] or "running") == "paused":
        raise HTTPException(409, "agent is paused - resume it before requesting a collection")
    command_id = _queue_command(conn, host_id, "collect_now")
    database.audit(conn, "analyst-ui", "collection_requested",
                   {"host_id": host_id, "command_id": command_id})
    conn.commit()
    return {"status": "queued", "host_id": host_id, "command_id": command_id,
            "note": "the endpoint collects on its next heartbeat"}


@app.post("/api/v1/hosts/{host_id}/scan")
def scan_host(host_id: int, scan_history: bool = False, conn=Depends(get_conn)):
    """Run detection immediately over this endpoint's unprocessed collections.

    Server-side and synchronous, so the analyst gets results now instead of
    waiting for the next agent cycle.
    """
    row = conn.execute("SELECT * FROM hosts WHERE id=?", (host_id,)).fetchone()
    if not row:
        raise HTTPException(404, "host not found")
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    command_id = conn.execute(
        """INSERT INTO agent_commands (host_id, command, status, requested_by,
                                       created_at_utc, claimed_at_utc, finished_at_utc)
           VALUES (?,'detect_now','claimed','analyst-ui',?,?,?)""",
        (host_id, now, now, now),
    ).lastrowid
    result = run_engine(conn, host_ids=[host_id], scan_history=scan_history)
    conn.execute(
        "UPDATE agent_commands SET status='done', result=? WHERE id=?",
        (json.dumps(result, default=str), command_id),
    )
    database.audit(conn, "analyst-ui", "host_scan_requested",
                   {"host_id": host_id, "command_id": command_id, **result})
    conn.commit()
    return {"status": "ok", "host_id": host_id, "command_id": command_id, "result": result}


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
    cooldown = body.cooldown_minutes if body.cooldown_minutes is not None else 60
    conn.execute(
        """INSERT INTO policies (name, min_severity, technique_ids, mode, action,
                                 cooldown_minutes, enabled, created_at_utc)
           VALUES (?,?,?,?,?,?,1,?)
           ON CONFLICT(name) DO UPDATE SET min_severity=excluded.min_severity,
               mode=excluded.mode, action=excluded.action,
               technique_ids=excluded.technique_ids,
               cooldown_minutes=excluded.cooldown_minutes""",
        (body.name, body.min_severity,
         json.dumps(body.technique_ids) if body.technique_ids else None,
         body.mode, body.action, max(0, cooldown), now),
    )
    database.audit(conn, "analyst", "policy_upserted", body.model_dump())
    conn.commit()
    # Evaluate the new/updated policy against recent telemetry right away so an
    # analyst sees the effect without waiting for the next background cycle.
    created = run_engine(conn, scan_history=True).get("approvals_created", 0)
    return {"status": "ok", "approvals_created": created}


@app.get("/api/v1/policies")
def list_policies(conn=Depends(get_conn)):
    return [dict(r) for r in conn.execute("SELECT * FROM policies ORDER BY id DESC")]


@app.post("/api/v1/policies/{policy_id}/delete")
def delete_policy(policy_id: int, conn=Depends(get_conn)):
    row = conn.execute("SELECT name FROM policies WHERE id=?", (policy_id,)).fetchone()
    if not row:
        raise HTTPException(404, "policy not found")
    conn.execute("DELETE FROM policies WHERE id=?", (policy_id,))
    database.audit(conn, "analyst", "policy_deleted",
                   {"policy_id": policy_id, "name": row["name"]})
    conn.commit()
    return {"status": "ok", "policy_id": policy_id}


@app.post("/api/v1/policies/{policy_id}/toggle")
def toggle_policy(policy_id: int, conn=Depends(get_conn)):
    """Enable or disable a containment policy (analyst quick toggle)."""
    row = conn.execute("SELECT enabled, name FROM policies WHERE id=?", (policy_id,)).fetchone()
    if not row:
        raise HTTPException(404, "policy not found")
    new_state = 0 if row["enabled"] else 1
    conn.execute("UPDATE policies SET enabled=? WHERE id=?", (new_state, policy_id))
    database.audit(conn, "analyst", "policy_toggled",
                   {"policy_id": policy_id, "name": row["name"], "enabled": new_state})
    conn.commit()
    return {"status": "ok", "policy_id": policy_id, "enabled": new_state}


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


def _report_history_filter(year, month, day, date_from, date_to):
    """Build a (sql, params) fragment for flexible generated_at_utc filtering.

    Supports a Y / Y-M / Y-M-D prefix match and/or an explicit from..to range,
    so the UI can filter by year, month, day, or an arbitrary window.
    """
    clauses, params = [], []
    if year:
        prefix = f"{int(year):04d}"
        if month:
            prefix += f"-{int(month):02d}"
            if day:
                prefix += f"-{int(day):02d}"
        clauses.append("generated_at_utc LIKE ?")
        params.append(prefix + "%")
    if date_from:
        clauses.append("generated_at_utc >= ?")
        params.append(date_from)
    if date_to:
        # Inclusive end-of-day when only a date is supplied.
        params.append(date_to if "T" in date_to else date_to + "T23:59:59")
        clauses.append("generated_at_utc <= ?")
    return (" AND " + " AND ".join(clauses) if clauses else ""), params


@app.get("/api/v1/reports")
def list_reports(host_id: int | None = None, kind: str | None = None,
                 year: int | None = None, month: int | None = None, day: int | None = None,
                 date_from: str | None = None, date_to: str | None = None,
                 limit: int = 200, conn=Depends(get_conn)):
    """Report history, filterable by endpoint, kind, and time (year/month/day
    or an explicit from..to range)."""
    sql = ("SELECT r.*, h.hostname, h.os_type FROM report_history r "
           "JOIN hosts h ON h.id = r.host_id WHERE 1=1")
    params = []
    if host_id:
        sql += " AND r.host_id=?"
        params.append(host_id)
    if kind:
        sql += " AND r.kind=?"
        params.append(kind)
    frag, fparams = _report_history_filter(year, month, day, date_from, date_to)
    sql += frag.replace("generated_at_utc", "r.generated_at_utc")
    params += fparams
    sql += " ORDER BY r.generated_at_utc DESC LIMIT ?"
    params.append(max(1, min(limit, 1000)))
    rows = [dict(r) for r in conn.execute(sql, params).fetchall()]
    for r in rows:
        r["available"] = bool(r.get("path") and os.path.exists(r["path"]))
    return rows


@app.get("/api/v1/reports/facets")
def report_facets(host_id: int | None = None, conn=Depends(get_conn)):
    """Distinct years / months available for the date-filter controls."""
    sql = "SELECT generated_at_utc FROM report_history"
    params = []
    if host_id:
        sql += " WHERE host_id=?"
        params.append(host_id)
    stamps = [r["generated_at_utc"] for r in conn.execute(sql, params).fetchall()]
    years = sorted({s[:4] for s in stamps if s}, reverse=True)
    months = sorted({s[:7] for s in stamps if s}, reverse=True)
    return {"years": years, "months": months, "total": len(stamps)}


@app.get("/api/v1/reports/{report_id}/download")
def download_report(report_id: int, conn=Depends(get_conn)):
    row = conn.execute("SELECT * FROM report_history WHERE id=?", (report_id,)).fetchone()
    if not row:
        raise HTTPException(404, "report not found")
    if not row["path"] or not os.path.exists(row["path"]):
        raise HTTPException(410, "report file no longer on disk; regenerate it")
    media = {"pdf": "application/pdf", "json": "application/json",
             "stix": "application/json"}.get(row["kind"], "application/octet-stream")
    return FileResponse(row["path"], media_type=media, filename=row["filename"])


@app.post("/api/v1/hosts/{host_id}/reports")
def generate_report(host_id: int, kind: str = "pdf", conn=Depends(get_conn)):
    """Generate a fresh report for an endpoint and record it in history."""
    gen = {"pdf": reporter.generate_pdf, "json": reporter.generate_json,
           "stix": reporter.generate_stix}.get(kind)
    if not gen:
        raise HTTPException(400, "kind must be pdf, json, or stix")
    path = gen(conn, host_id)
    if not path:
        raise HTTPException(404, "host not found")
    row = conn.execute(
        "SELECT * FROM report_history WHERE host_id=? AND path=? ORDER BY id DESC LIMIT 1",
        (host_id, path)).fetchone()
    return {"report_id": row["id"] if row else None, "filename": os_path(path), "kind": kind}


@app.get("/api/v1/stats/endpoints")
def stats_endpoints(conn=Depends(get_conn)):
    """Per-endpoint detection breakdown for the overview page (separation +
    filters happen client-side)."""
    rows = conn.execute(
        """SELECT h.id, h.hostname, h.os_type, h.is_active, h.docker_engine_flag,
                  h.last_seen_utc, h.last_heartbeat_utc, h.agent_desired_state,
                  COALESCE(SUM(CASE WHEN d.severity='critical' THEN 1 ELSE 0 END),0) AS critical,
                  COALESCE(SUM(CASE WHEN d.severity='high'     THEN 1 ELSE 0 END),0) AS high,
                  COALESCE(SUM(CASE WHEN d.severity='medium'   THEN 1 ELSE 0 END),0) AS medium,
                  COALESCE(SUM(CASE WHEN d.severity='low'      THEN 1 ELSE 0 END),0) AS low,
                  COUNT(d.id) AS detection_total,
                  MAX(d.detected_at_utc) AS last_detection_utc
           FROM hosts h LEFT JOIN detections d ON d.host_id = h.id
           GROUP BY h.id ORDER BY critical DESC, high DESC, detection_total DESC, h.hostname"""
    ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["agent_status"] = classify_agent_status(r)
        if (d.get("agent_desired_state") == "paused") and d["agent_status"] == "running":
            d["agent_status"] = "paused"
        out.append(d)
    return out


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


@app.get("/api/v1/stats/footprint")
def stats_footprint(conn=Depends(get_conn)):
    """Fleet-wide 'how heavy is ATOR on endpoints' metrics.

    Aggregates the latest agent self-impact + system resource sample per active
    host into headline KPIs and a lightweight/moderate/heavy verdict.
    """
    now = datetime.now(timezone.utc)
    self_rows = conn.execute(
        """SELECT h.id, s.agent_cpu_pct, s.agent_mem_mb, s.agent_threads, s.agent_fds,
                  s.collection_duration_ms, s.payload_size_bytes, s.spool_count,
                  s.telemetry_mode, s.sampled_at_utc
           FROM hosts h LEFT JOIN agent_self_samples s ON s.id = (
               SELECT MAX(id) FROM agent_self_samples WHERE host_id=h.id)
           WHERE h.is_active=1"""
    ).fetchall()
    res_rows = {r["id"]: r for r in conn.execute(
        """SELECT h.id, s.cpu_pct, s.mem_pct, s.sampled_at_utc
           FROM hosts h LEFT JOIN resource_samples s ON s.id = (
               SELECT MAX(id) FROM resource_samples WHERE host_id=h.id)
           WHERE h.is_active=1""").fetchall()}

    def _fresh(ts, secs=120):
        if not ts:
            return False
        try:
            return (now - datetime.fromisoformat(str(ts).replace("Z", "+00:00"))).total_seconds() <= secs
        except ValueError:
            return False

    active = total = 0
    agent_cpu, agent_mem, coll_ms, sys_cpu, sys_mem = [], [], [], [], []
    total_agent_mem = 0.0
    modes = {"full": 0, "lightweight": 0}
    for r in self_rows:
        total += 1
        reporting = _fresh(r["sampled_at_utc"])
        if reporting:
            active += 1
            if r["agent_cpu_pct"] is not None:
                agent_cpu.append(r["agent_cpu_pct"])
            if r["agent_mem_mb"] is not None:
                agent_mem.append(r["agent_mem_mb"]); total_agent_mem += r["agent_mem_mb"]
            if r["collection_duration_ms"] is not None:
                coll_ms.append(r["collection_duration_ms"])
            if r["telemetry_mode"] in modes:
                modes[r["telemetry_mode"]] += 1
        res = res_rows.get(r["id"])
        if res and _fresh(res["sampled_at_utc"]):
            if res["cpu_pct"] is not None:
                sys_cpu.append(res["cpu_pct"])
            if res["mem_pct"] is not None:
                sys_mem.append(res["mem_pct"])

    def avg(xs):
        return round(sum(xs) / len(xs), 2) if xs else 0.0

    day_ago = (now - timedelta(hours=24)).isoformat(timespec="seconds")
    telemetry_bytes = conn.execute(
        "SELECT COALESCE(SUM(payload_size_bytes),0) n FROM agent_self_samples WHERE sampled_at_utc >= ?",
        (day_ago,)).fetchone()["n"]
    collections_24h = conn.execute(
        "SELECT COUNT(*) n FROM evidence_manifests WHERE received_at_utc >= ?", (day_ago,)).fetchone()["n"]
    spool_backlog = conn.execute(
        "SELECT COALESCE(SUM(spool_count),0) n FROM (SELECT host_id, spool_count FROM agent_self_samples s "
        "WHERE s.id=(SELECT MAX(id) FROM agent_self_samples WHERE host_id=s.host_id))").fetchone()["n"]

    a_cpu, a_mem = avg(agent_cpu), avg(agent_mem)
    if a_cpu <= 3 and a_mem <= 90:
        verdict = "Lightweight"
    elif a_cpu <= 8 and a_mem <= 180:
        verdict = "Moderate"
    else:
        verdict = "Heavy"
    return {
        "reporting": active, "endpoints": total,
        "avg_agent_cpu_pct": a_cpu, "avg_agent_mem_mb": a_mem,
        "total_agent_mem_mb": round(total_agent_mem, 1),
        "avg_collection_ms": avg(coll_ms),
        "avg_sys_cpu_pct": avg(sys_cpu), "avg_sys_mem_pct": avg(sys_mem),
        "telemetry_bytes_24h": telemetry_bytes, "collections_24h": collections_24h,
        "spool_backlog": spool_backlog, "telemetry_modes": modes,
        "verdict": verdict, "generated_at": now.isoformat(timespec="seconds"),
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


@app.post("/api/v1/agent-self/ingest", status_code=202)
def ingest_agent_self(body: AgentSelfSamplesRequest, ctx=Depends(auth_host)):
    """Ingest lightweight agent self-monitoring samples."""
    conn = ctx["conn"]
    host = ctx["host"]
    samples = [s.model_dump() for s in body.samples]
    if not samples:
        raise HTTPException(status_code=400, detail="no samples provided")
    if len(samples) > 24:
        raise HTTPException(status_code=400, detail="too many samples in batch (max 24)")

    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")

    for s in samples:
        ts = s.get("sampled_at_utc") or now_iso
        conn.execute(
            """INSERT INTO agent_self_samples (
                host_id, sampled_at_utc, agent_cpu_pct, agent_mem_mb, agent_threads,
                agent_fds, agent_cpu_time_user, agent_cpu_time_system,
                collection_duration_ms, payload_size_bytes, spool_count, telemetry_mode
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                host["id"],
                ts,
                s.get("agent_cpu_pct"),
                s.get("agent_mem_mb"),
                s.get("agent_threads"),
                s.get("agent_fds"),
                s.get("agent_cpu_time_user"),
                s.get("agent_cpu_time_system"),
                s.get("collection_duration_ms"),
                s.get("payload_size_bytes"),
                s.get("spool_count"),
                "lightweight",
            ),
        )

    _maybe_prune_resources(conn)
    conn.commit()
    database.audit(conn, f"host:{host['hostname']}", "agent_self_ingested", {"count": len(samples)})
    return {"status": "accepted", "count": len(samples)}


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


# =============================================================================
# ENROLLMENT REQUEST ENDPOINTS
# =============================================================================

class EnrollmentRequestCreate(BaseModel):
    hostname: str = Field(min_length=1, max_length=255)
    os_type: str = Field(pattern="^(windows|linux|docker_host)$")
    docker_engine_flag: int = 0
    requested_features: dict | None = None
    agent_version: str | None = None


class EnrollmentRequestReview(BaseModel):
    action: str = Field(pattern="^(accept|reject)$")
    analyst: str = "analyst"
    rejection_reason: str | None = None


class AgentEnrollWithToken(BaseModel):
    enrollment_token: str
    agent_version: str | None = None


@app.post("/api/v1/enroll/request")
def create_enrollment_request(body: EnrollmentRequestCreate, conn=Depends(get_conn)):
    """Submit a new enrollment request from an endpoint user."""
    import uuid
    request_token = str(uuid.uuid4())
    enrollment_token = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    expires = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat(timespec="seconds")

    requested_features_json = json.dumps(body.requested_features) if body.requested_features else None

    cur = conn.execute(
        """INSERT INTO enrollment_requests
           (request_token, hostname, os_type, docker_engine_flag, requested_features,
            agent_version, status, requested_at_utc, expires_at_utc, enrollment_token)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (request_token, body.hostname, body.os_type, body.docker_engine_flag,
         requested_features_json, body.agent_version, "pending", datetime.now(timezone.utc).isoformat(timespec="seconds"),
         (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat(timespec="seconds"),
         enrollment_token),
    )

    database.audit(conn, "server", "enrollment_requested",
                   {"request_token": request_token, "hostname": body.hostname, "os_type": body.os_type})
    conn.commit()

    return {
        "request_token": request_token,
        "enrollment_token": enrollment_token,
        "status": "pending",
        "message": "Enrollment request submitted. Awaiting admin approval."
    }


@app.get("/api/v1/enroll/status/{request_token}")
def get_enrollment_status(request_token: str, conn=Depends(get_conn)):
    """Check the status of an enrollment request."""
    row = conn.execute(
        "SELECT * FROM enrollment_requests WHERE request_token=?", (request_token,)
    ).fetchone()

    if not row:
        raise HTTPException(404, "Enrollment request not found")

    return dict(row)


@app.post("/api/v1/enroll/enroll")
def enroll_with_token(body: AgentEnrollWithToken, conn=Depends(get_conn)):
    """Agent enrolls using an enrollment token issued after admin approval."""
    row = conn.execute(
        "SELECT * FROM enrollment_requests WHERE enrollment_token=?", (body.enrollment_token,)
    ).fetchone()

    if not row:
        raise HTTPException(404, "Invalid enrollment token")

    # Checked before the status gate: a consumed token has status 'enrolled',
    # and agents rely on 409 to recognise an idempotent bootstrap re-run.
    if row["enrolled_at_utc"] or row["status"] == "enrolled":
        raise HTTPException(409, "This enrollment token has already been used")

    if row["status"] != "accepted":
        raise HTTPException(403, f"Enrollment request not accepted (status: {row['status']})")

    # Generate credentials
    api_key = security.generate_api_key()
    client_id = security.new_client_id()
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    # Create host record
    cur = conn.execute(
        """INSERT INTO hosts (client_id, hostname, os_type, docker_engine_flag, api_key_hash,
                              agent_version, enrolled_at_utc, last_seen_utc)
           VALUES (?,?,?,?,?,?,?,?)""",
        (client_id,
         row["hostname"], row["os_type"], row["docker_engine_flag"],
         security.hash_secret(api_key), body.agent_version or row["agent_version"], now, now),
    )
    host_id = cur.lastrowid

    # Update enrollment request
    conn.execute(
        "UPDATE enrollment_requests SET status='enrolled', enrolled_at_utc=? WHERE id=?",
        (datetime.now(timezone.utc).isoformat(timespec="seconds"), row["id"]),
    )

    database.audit(conn, "server", "host_enrolled_via_token",
                   {"host_id": host_id, "request_token": row["request_token"]})
    conn.commit()

    return {
        "host_id": host_id,
        "client_id": client_id,
        "api_key": api_key,
        "message": "Enrollment successful"
    }


# Agent package + bootstrap downloads. These shadow the /static mount (routes
# are matched before mounts) so endpoints always get an agent built from the
# current source instead of a stale pre-built archive.
@app.get("/static/ator-agent-deploy.zip")
def download_agent_zip():
    from fastapi.responses import Response
    from server import agent_package
    return Response(agent_package.build("zip"), media_type="application/zip",
                    headers={"Content-Disposition": 'attachment; filename="ator-agent-deploy.zip"',
                             "Cache-Control": "no-store"})


@app.get("/static/ator-agent-deploy.tar.gz")
def download_agent_targz():
    from fastapi.responses import Response
    from server import agent_package
    return Response(agent_package.build("tar.gz"), media_type="application/gzip",
                    headers={"Content-Disposition": 'attachment; filename="ator-agent-deploy.tar.gz"',
                             "Cache-Control": "no-store"})


def _bootstrap_script_response(script_name):
    from fastapi.responses import Response
    from server import agent_package
    return Response(agent_package.bootstrap_script(script_name),
                    media_type=agent_package.BOOTSTRAP_SCRIPTS[script_name],
                    headers={"Cache-Control": "no-store"})


@app.get("/static/bootstrap_endpoint.ps1")
def download_windows_bootstrap():
    return _bootstrap_script_response("bootstrap_endpoint.ps1")


@app.get("/static/bootstrap_endpoint.sh")
def download_linux_bootstrap():
    return _bootstrap_script_response("bootstrap_endpoint.sh")


# Admin endpoints for managing enrollment requests
@app.get("/api/v1/enrollments")
def list_enrollment_requests(
    status: str = "all",
    platform: str | None = None,
    q: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    limit: int = 500,
    conn=Depends(get_conn),
):
    """List enrollment requests with optional status / platform / search / time
    filters. status='all' returns every request."""
    sql = "SELECT * FROM enrollment_requests WHERE 1=1"
    params = []
    if status and status != "all":
        sql += " AND status=?"
        params.append(status)
    if platform:
        sql += " AND os_type=?"
        params.append(platform)
    if q:
        sql += " AND (LOWER(hostname) LIKE ? OR request_token LIKE ?)"
        like = f"%{q.lower()}%"
        params += [like, f"%{q}%"]
    if date_from:
        sql += " AND requested_at_utc >= ?"
        params.append(date_from)
    if date_to:
        sql += " AND requested_at_utc <= ?"
        params.append(date_to if "T" in date_to else date_to + "T23:59:59")
    sql += " ORDER BY requested_at_utc DESC LIMIT ?"
    params.append(max(1, min(limit, 2000)))
    return [dict(r) for r in conn.execute(sql, params).fetchall()]


class EnrollmentPurgeRequest(BaseModel):
    """Bulk-delete filter. Any combination narrows the deletion; an empty body
    with confirm=all clears every request."""
    statuses: list[str] | None = None
    platform: str | None = None
    before: str | None = None          # delete requests requested before this ISO date
    tokens: list[str] | None = None    # explicit request_tokens
    analyst: str = "analyst"


@app.delete("/api/v1/enrollments/{request_token}")
def delete_enrollment_request(request_token: str, conn=Depends(get_conn)):
    """Delete a single enrollment request record (does not affect an already
    enrolled host)."""
    row = conn.execute(
        "SELECT id FROM enrollment_requests WHERE request_token=?", (request_token,)).fetchone()
    if not row:
        raise HTTPException(404, "Enrollment request not found")
    conn.execute("DELETE FROM enrollment_requests WHERE request_token=?", (request_token,))
    database.audit(conn, "analyst", "enrollment_deleted", {"request_token": request_token})
    conn.commit()
    return {"status": "deleted", "request_token": request_token}


@app.post("/api/v1/enrollments/purge")
def purge_enrollment_requests(body: EnrollmentPurgeRequest, conn=Depends(get_conn)):
    """Bulk-delete enrollment requests matching the given filters.

    Deleting a request record never touches an enrolled host - it only clears
    the request log. With no filter at all this deletes every request, so the
    caller (the UI) confirms first.
    """
    where, params = ["1=1"], []
    if body.tokens:
        marks = ",".join("?" for _ in body.tokens)
        where.append(f"request_token IN ({marks})")
        params += body.tokens
    if body.statuses:
        marks = ",".join("?" for _ in body.statuses)
        where.append(f"status IN ({marks})")
        params += body.statuses
    if body.platform:
        where.append("os_type=?")
        params.append(body.platform)
    if body.before:
        where.append("requested_at_utc < ?")
        params.append(body.before if "T" in body.before else body.before + "T00:00:00")
    sql = "DELETE FROM enrollment_requests WHERE " + " AND ".join(where)
    deleted = conn.execute(sql, params).rowcount
    database.audit(conn, body.analyst, "enrollment_bulk_deleted",
                   {"deleted": deleted, "statuses": body.statuses, "platform": body.platform,
                    "before": body.before, "tokens": len(body.tokens or [])})
    conn.commit()
    return {"status": "ok", "deleted": deleted}


@app.post("/api/v1/enrollments/{request_token}/accept")
def accept_enrollment_request(request_token: str, body: EnrollmentRequestReview, conn=Depends(get_conn)):
    """Accept an enrollment request (admin)."""
    row = conn.execute("SELECT * FROM enrollment_requests WHERE request_token=?", (request_token,)).fetchone()
    if not row:
        raise HTTPException(404, "Enrollment request not found")

    if row["status"] != "pending":
        raise HTTPException(409, f"Request already {row['status']}")

    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    conn.execute(
        "UPDATE enrollment_requests SET status='accepted', reviewed_at_utc=?, reviewed_by=? WHERE request_token=?",
        (now, body.analyst, request_token)
    )
    database.audit(conn, body.analyst, "enrollment_accepted", {"request_token": request_token})
    conn.commit()
    return {"status": "accepted", "request_token": request_token}


@app.post("/api/v1/enrollments/{request_token}/reject")
def reject_enrollment_request(request_token: str, body: EnrollmentRequestReview, conn=Depends(get_conn)):
    """Reject an enrollment request (admin)."""
    row = conn.execute("SELECT * FROM enrollment_requests WHERE request_token=?", (request_token,)).fetchone()
    if not row:
        raise HTTPException(404, "Enrollment request not found")

    if row["status"] != "pending":
        raise HTTPException(409, f"Request already {row['status']}")

    if not body.rejection_reason:
        raise HTTPException(400, "Rejection reason required")

    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    conn.execute(
        "UPDATE enrollment_requests SET status='rejected', reviewed_at_utc=?, reviewed_by=?, rejection_reason=? WHERE request_token=?",
        (now, body.analyst, body.rejection_reason, request_token)
    )
    database.audit(conn, body.analyst, "enrollment_rejected",
                   {"request_token": request_token, "reason": body.rejection_reason})
    conn.commit()
    return {"status": "rejected", "request_token": request_token}


# =============================================================================
# LIGHTWEIGHT AGENT SELF TELEMETRY ENDPOINTS
# =============================================================================


@app.get("/api/v1/agent-self/latest")
def agent_self_latest(conn=Depends(get_conn)):
    """Latest lightweight agent self sample per active host."""
    rows = conn.execute(
        """SELECT h.id, h.hostname, h.os_type, h.docker_engine_flag, h.last_seen_utc,
                  s.sampled_at_utc, s.agent_cpu_pct, s.agent_mem_mb, s.agent_threads,
                  s.agent_fds, s.agent_cpu_time_user, s.agent_cpu_time_system,
                  s.collection_duration_ms, s.payload_size_bytes, s.spool_count,
                  s.telemetry_mode
           FROM hosts h
           LEFT JOIN agent_self_samples s ON s.id = (
               SELECT MAX(id) FROM agent_self_samples WHERE host_id = h.id
           )
           WHERE h.is_active=1
           ORDER BY h.hostname"""
    ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        if d.get("sampled_at_utc"):
            try:
                ts = datetime.fromisoformat(d["sampled_at_utc"].replace("Z", "+00:00"))
                age = (datetime.now(timezone.utc) - ts).total_seconds()
                d["stale"] = age > 90  # > 6 missed 30s samples
            except Exception:
                d["stale"] = True
        else:
            d["stale"] = True
        out.append(d)
    return {"hosts": out, "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}


@app.get("/api/v1/agent-self/history")
def agent_self_history(
    host_id: int,
    minutes: int = 30,
    metrics: str = "agent_cpu_pct,agent_mem_mb,agent_threads",
    limit: int = 500,
    conn=Depends(get_conn),
):
    """Time-series history for agent self-monitoring charts."""
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat(timespec="seconds")
    metric_list = [m.strip() for m in metrics.split(",") if m.strip()]
    allowed = {"agent_cpu_pct", "agent_mem_mb", "agent_threads", "agent_fds",
               "agent_cpu_time_user", "agent_cpu_time_system", "collection_duration_ms",
               "payload_size_bytes", "spool_count"}
    metric_list = [m for m in metric_list if m in allowed]
    if not metric_list:
        metric_list = ["agent_cpu_pct", "agent_mem_mb", "agent_threads"]
    cols = ", ".join(metric_list)
    rows = conn.execute(
        f"SELECT sampled_at_utc, {cols} FROM agent_self_samples WHERE host_id=? AND sampled_at_utc >= ? ORDER BY id ASC",
        (host_id, cutoff),
    ).fetchall()
    if len(rows) > limit:
        step = len(rows) / limit
        rows = [rows[int(i * step)] for i in range(limit)]
    return {"host_id": host_id, "points": [dict(r) for r in rows]}


@app.get("/api/v1/stream/agent-self")
async def stream_agent_self(request: Request, interval: float = 5.0, limit: int = 15):
    """SSE stream for lightweight agent self telemetry."""
    from asyncio import sleep
    from starlette.concurrency import run_in_threadpool

    interval = max(2.0, min(interval, 60.0))
    limit = max(1, min(limit, 50))

    def _query(cursor):
        c = database.connect()
        try:
            rows = c.execute(
                """SELECT s.*, h.hostname, h.os_type, h.docker_engine_flag
                   FROM agent_self_samples s JOIN hosts h ON h.id=s.host_id
                   WHERE s.id > ? ORDER BY s.id ASC LIMIT ?""",
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
                    """SELECT s.*, h.hostname, h.os_type, h.docker_engine_flag
                       FROM agent_self_samples s JOIN hosts h ON h.id=s.host_id
                       WHERE s.id IN (
                           SELECT MAX(id) FROM agent_self_samples GROUP BY host_id
                       )"""
                ).fetchall()
                return [dict(r) for r in rows]
            finally:
                c.close()

        samples = await run_in_threadpool(_initial)
        last_sample_id = max((s["id"] for s in samples), default=0)
        for s in samples:
            yield f"data: {json.dumps({'samples': [s], 'alerts': []})}\n\n"
        yield ": stream-ready\n\n"
        while True:
            if await request.is_disconnected():
                break
            new_samples = await run_in_threadpool(_query, last_sample_id)
            for s in new_samples:
                last_sample_id = max(last_sample_id, s["id"])
                yield f"data: {json.dumps({'samples': [s], 'alerts': []})}\n\n"
            yield f": heartbeat {datetime.now(timezone.utc).isoformat(timespec='seconds')}\n\n"
            await sleep(interval)

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
# ---------------------------------------------------------------------------
# Layer 4.5 ML endpoints.
#
# Every one of these degrades rather than fails when the optional ML stack is absent:
# /status reports why, and the others return an explanatory 503. The DFIR pipeline is
# unaffected either way.
#
# Scoring runs in a threadpool because it reads SQLite and runs a CPU-bound forest; doing
# that on the event loop would stall every other request (ML_ARCHITECTURE section 8).
# ---------------------------------------------------------------------------

class MlScoreRequest(BaseModel):
    host_id: int | None = None
    top_k: int | None = Field(default=None, ge=1, le=200)
    threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    persist: bool = True


def _ml_unavailable(status) -> HTTPException:
    return HTTPException(
        status_code=503,
        detail={"error": "ml_unavailable", "reason": status.reason,
                "missing_dependency": status.missing_dependency,
                "hint": "pip install -r requirements-ml.txt, then "
                        "python -m ml.training.train_anomaly --save"},
    )


@app.get("/api/v1/ml/status")
def ml_status(conn=Depends(get_conn)):
    """Is ML available, which models are loadable, and against which feature spec."""
    from server.engine import ml_registry
    return ml_registry.describe(conn)


@app.get("/api/v1/ml/models")
def ml_models(conn=Depends(get_conn)):
    rows = conn.execute(
        """SELECT id, name, version, model_type, feature_tier, feature_spec_sha256,
                  trained_at_utc, training_rows, training_source, metrics_json,
                  model_path, is_active
           FROM ml_models ORDER BY id DESC"""
    ).fetchall()
    out = []
    for row in rows:
        item = dict(row)
        try:
            item["metrics"] = json.loads(item.pop("metrics_json") or "{}")
        except json.JSONDecodeError:
            item["metrics"] = {}
        out.append(item)
    return {"models": out, "count": len(out)}


@app.post("/api/v1/ml/score")
async def ml_score(body: MlScoreRequest):
    """Score processes now and (by default) persist the findings as detections."""
    from starlette.concurrency import run_in_threadpool
    from server.engine import ml_registry

    status = ml_registry.dependencies_available()
    if not status.available:
        raise _ml_unavailable(status)

    def _work():
        from server.engine.ml_integration import (
            insert_ml_detections, run_ml_anomaly_detection,
        )
        conn = database.connect()
        try:
            host_ids = [body.host_id] if body.host_id is not None else None
            hits = run_ml_anomaly_detection(
                conn, host_ids=host_ids, top_k=body.top_k, threshold=body.threshold)
            ids = insert_ml_detections(conn, hits) if (hits and body.persist) else []
            # A hit carrying existing_id is a process already on record, seen again. It
            # updates that finding's hit count; it is not a new finding.
            new_hits = [h for h in hits if h.get("existing_id") is None]
            recurring = len(hits) - len(new_hits)
            database.audit(conn, "analyst", "ml_manual_score",
                           {"host_id": body.host_id, "found": len(new_hits),
                            "recurring": recurring, "persisted": len(ids)})
            conn.commit()
            return {
                "scored": True,
                "detections_found": len(new_hits),
                "detections_recurring": recurring,
                "detections_persisted": len(ids),
                "detection_ids": ids,
                # Returned even when persist=False, so the UI can preview without writing.
                "findings": [
                    {k: v for k, v in hit.items() if k != "ml_explanation"} | {
                        "explanation": json.loads(hit.get("ml_explanation") or "{}")}
                    for hit in new_hits
                ],
            }
        finally:
            conn.close()

    return await run_in_threadpool(_work)


@app.get("/api/v1/ml/anomalies")
def ml_anomalies(host_id: int | None = None, limit: int = 50, conn=Depends(get_conn)):
    """ML anomaly detections with their scores and explanations, newest first."""
    sql = """SELECT d.id, d.host_id, h.hostname, d.collection_id, d.rule_name, d.severity,
                    d.summary, d.detected_at_utc, d.anomaly_score, d.confidence_score,
                    d.suggested_tactics, d.ml_model_id, d.ml_explanation
             FROM detections d LEFT JOIN hosts h ON h.id = d.host_id
             WHERE d.rule_type = 'ml_anomaly'"""
    params: list = []
    if host_id is not None:
        sql += " AND d.host_id = ?"
        params.append(host_id)
    sql += " ORDER BY d.anomaly_score DESC, d.id DESC LIMIT ?"
    params.append(max(1, min(limit, 500)))

    out = []
    for row in conn.execute(sql, params):
        item = dict(row)
        for field in ("ml_explanation", "suggested_tactics"):
            try:
                item[field] = json.loads(item[field]) if item[field] else None
            except (json.JSONDecodeError, TypeError):
                pass
        out.append(item)
    return {"anomalies": out, "count": len(out)}


@app.get("/api/v1/ml/host-risk")
def ml_host_risk_all(conn=Depends(get_conn)):
    """Risk score for every host, worst first - the endpoints-page ordering."""
    rows = conn.execute(
        """SELECT r.host_id, h.hostname, h.os_type, r.score, r.tier, r.last_computed_utc,
                  r.breakdown_json
           FROM host_risk_scores r LEFT JOIN hosts h ON h.id = r.host_id
           ORDER BY r.score DESC"""
    ).fetchall()
    out = []
    for row in rows:
        item = dict(row)
        try:
            item["breakdown"] = json.loads(item.pop("breakdown_json") or "{}")
        except json.JSONDecodeError:
            item["breakdown"] = {}
        out.append(item)
    return {"hosts": out, "count": len(out)}


@app.get("/api/v1/ml/host-risk/{host_id}")
def ml_host_risk_one(host_id: int, conn=Depends(get_conn)):
    from server.engine import ml_risk
    stored = ml_risk.get_host_risk(conn, host_id)
    if stored is None:
        # Never computed yet - compute on demand rather than 404, so the UI always has
        # something to show for a freshly enrolled host.
        return ml_risk.compute_host_risk(conn, host_id) | {"persisted": False}
    return stored | {"persisted": True}


@app.post("/api/v1/ml/host-risk/recompute")
async def ml_host_risk_recompute():
    from starlette.concurrency import run_in_threadpool

    def _work():
        from server.engine import ml_risk
        conn = database.connect()
        try:
            result = ml_risk.update_all(conn)
            database.audit(conn, "analyst", "ml_risk_recompute",
                           {"hosts": result["hosts_scored"]})
            conn.commit()
            return {"hosts_scored": result["hosts_scored"], "by_tier": result["by_tier"],
                    "top": result["scores"][:10]}
        finally:
            conn.close()

    return await run_in_threadpool(_work)


@app.get("/api/v1/ml/drift")
def ml_drift_status(limit: int = 50, conn=Depends(get_conn)):
    """Most recent feature-drift findings (PSI) recorded by the retrain job."""
    rows = conn.execute(
        """SELECT computed_at_utc, model_id, feature_name, psi, verdict
           FROM ml_drift_log ORDER BY computed_at_utc DESC, psi DESC LIMIT ?""",
        (max(1, min(limit, 500)),)).fetchall()
    entries = [dict(r) for r in rows]
    latest = entries[0]["computed_at_utc"] if entries else None
    shifted = [e for e in entries if e["verdict"] == "shifted"]
    return {
        "entries": entries,
        "count": len(entries),
        "last_computed_utc": latest,
        "shifted_features": len(shifted),
        "retrain_recommended": bool(shifted),
        "thresholds": {"stable_below": 0.10, "shifted_above": 0.25},
    }


# ---------------------------------------------------------------------------
# Phase 10: analyst verdicts on ML leads, and the weekly MLOps pipeline status.
# ---------------------------------------------------------------------------

class MlFeedbackRequest(BaseModel):
    detection_id: int
    # 'clear' removes an earlier verdict, so a mis-click is never permanent.
    verdict: str = Field(pattern="^(confirmed|benign|clear)$")
    note: str | None = Field(default=None, max_length=500)


@app.post("/api/v1/ml/feedback")
def ml_feedback(body: MlFeedbackRequest, conn=Depends(get_conn)):
    """Record an analyst's verdict on an ML lead.

    It feeds the weekly retrain (ml/mlops/data.py): a lead dismissed as benign rejoins the
    benign baseline, unless a deterministic rule also fired on that process. A confirmed
    threat is never used as benign, and becomes part of the "confirmed threats kept"
    regression check every future model must pass.
    """
    row = conn.execute("SELECT rule_type FROM detections WHERE id=?",
                       (body.detection_id,)).fetchone()
    if row is None:
        raise HTTPException(404, "detection not found")
    if row["rule_type"] != "ml_anomaly":
        raise HTTPException(400, "verdicts are recorded for behavioural (ML) leads only")
    if body.verdict == "clear":
        conn.execute("DELETE FROM ml_feedback WHERE detection_id=?", (body.detection_id,))
    else:
        conn.execute(
            """INSERT INTO ml_feedback (detection_id, verdict, note, recorded_at_utc)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(detection_id) DO UPDATE SET verdict=excluded.verdict,
                   note=excluded.note, recorded_at_utc=excluded.recorded_at_utc""",
            (body.detection_id, body.verdict, body.note, database.now_iso()))
    database.audit(conn, "analyst", "ml_feedback",
                   {"detection_id": body.detection_id, "verdict": body.verdict})
    conn.commit()
    return {"detection_id": body.detection_id, "verdict": None if body.verdict == "clear"
            else body.verdict}


@app.get("/api/v1/ml/ops")
def ml_ops_status(conn=Depends(get_conn)):
    """Weekly MLOps pipeline: models in service, trials, recent runs, attention items."""
    from server.engine import ml_ops, ml_registry
    try:
        models = ml_registry.describe(conn).get("models") or []
    except Exception:                            # noqa: BLE001
        models = []
    return ml_ops.ops_view(conn, models)
