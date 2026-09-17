import json
from datetime import datetime, timezone


def _parse(ts):
    if not ts:
        return None
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None


def _parse_summary(raw):
    """Decode detections.summary defensively.

    The column is documented as JSON, but a plain string is a plausible mistake for any
    future detector to make, and a malformed summary must never be able to take down the
    whole timeline for a host. Returns the decoded object, or the raw text wrapped so the
    information still reaches the analyst.
    """
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return {"text": str(raw)[:600]}


def build(conn, host_id=None, limit=500):
    conditions = []
    params = []
    if host_id:
        conditions.append("host_id = ?")
        params.append(host_id)

    where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
    events = []

    for row in conn.execute(
        f"SELECT id, host_id, detected_at_utc, rule_type, rule_name, severity, technique_id, summary FROM detections{where}",
        params,
    ):
        events.append({
            "ts": row["detected_at_utc"],
            "kind": "detection",
            "severity": row["severity"],
            "title": f"[{row['rule_type'].upper()}] {row['rule_name']}",
            "detail": json.dumps({"technique_id": row["technique_id"],
                                  "summary": _parse_summary(row["summary"])},
                                 default=str)[:800],
            "ref": f"detection:{row['id']}",
        })

    log_where = (" WHERE " + " AND ".join(f"l.{c}" for c in conditions)) if conditions else ""
    for row in conn.execute(
        f"""SELECT l.id, l.host_id, l.event_time_utc, l.source, l.event_id, l.provider, l.payload_json
            FROM raw_logs l{log_where}""",
        params,
    ):
        payload = {}
        try:
            payload = json.loads(row["payload_json"] or "{}")
        except json.JSONDecodeError:
            pass
        msg = payload.get("message") or payload.get("fields") or ""
        events.append({
            "ts": row["event_time_utc"],
            "kind": "log",
            "severity": None,
            "title": f"[LOG {row['source']}" + (f" EID {row['event_id']}" if row["event_id"] else "") + "]",
            "detail": str(msg)[:400],
            "ref": f"log:{row['id']}",
        })

    pers_where = (" WHERE " + " AND ".join(f"p.{c}" for c in conditions)) if conditions else ""
    for row in conn.execute(
        f"SELECT p.id, p.host_id, p.collected_at_utc, p.ptype, p.name, p.command FROM raw_persistence p{pers_where}",
        params,
    ):
        events.append({
            "ts": row["collected_at_utc"],
            "kind": "persistence",
            "severity": "low",
            "title": f"[PERSISTENCE {row['ptype']}] {row['name'] or ''}",
            "detail": (row["command"] or "")[:400],
            "ref": f"persistence:{row['id']}",
        })

    coll_where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
    for row in conn.execute(
        f"""
        SELECT m.id, m.host_id, m.started_at_utc, m.finished_at_utc, m.collection_id, m.artifact_count
        FROM evidence_manifests m{coll_where}
        """,
        params,
    ):
        events.append({
            "ts": row["finished_at_utc"] or row["started_at_utc"],
            "kind": "collection",
            "severity": None,
            "title": "[COLLECTION] artifact snapshot",
            "detail": f"collection_id={row['collection_id']} artifacts={row['artifact_count']}",
            "ref": f"collection:{row['collection_id']}",
        })

    for e in events:
        e["_dt"] = _parse(e["ts"])
    undated = [e for e in events if e["_dt"] is None]
    dated = [e for e in events if e["_dt"] is not None]
    dated.sort(key=lambda e: e["_dt"])

    skew_flags = _detect_skew(dated)

    merged = dated + undated
    return {"events": merged[:limit], "total": len(events), "skew": skew_flags}


def _detect_skew(sorted_events, threshold_days=45):
    if len(sorted_events) < 5:
        return []
    now = datetime.now(timezone.utc)
    flags = []
    old_cutoff = now.timestamp() - threshold_days * 86400
    recent = [e for e in sorted_events[-20:] if e["_dt"].timestamp() > old_cutoff]
    if not recent:
        return [{"issue": "all-recent-events-missing"}]
    baseline = recent[-1]["_dt"]
    for e in sorted_events:
        delta_days = abs((baseline - e["_dt"]).total_seconds()) / 86400
        if delta_days > threshold_days:
            flags.append({
                "ref": e.get("ref"),
                "ts": e["ts"],
                "skew_days": round(delta_days, 1),
            })
    return flags[:50]


def process_tree(conn, host_id):
    latest = conn.execute(
        """
        SELECT collection_id, MAX(collected_at_utc) AS mx
        FROM raw_processes WHERE host_id = ?
        GROUP BY collection_id ORDER BY mx DESC LIMIT 1
        """,
        (host_id,),
    ).fetchone()
    if not latest:
        return {"nodes": [], "edges": [], "collection_id": None}
    rows = conn.execute(
        "SELECT pid, ppid, name, cmdline FROM raw_processes WHERE host_id=? AND collection_id=?",
        (host_id, latest["collection_id"]),
    ).fetchall()
    nodes = {}
    edges = []
    for r in rows:
        nodes[r["pid"]] = {"pid": r["pid"], "ppid": r["ppid"], "name": r["name"],
                           "cmdline": (r["cmdline"] or "")[:160]}
    for pid, node in nodes.items():
        if node["ppid"] is not None and node["ppid"] in nodes and node["ppid"] != pid:
            edges.append({"from": node["ppid"], "to": pid})
    return {
        "nodes": list(nodes.values()),
        "edges": edges,
        "collection_id": latest["collection_id"],
    }
