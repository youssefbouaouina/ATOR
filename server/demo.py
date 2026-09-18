"""Shared constants and cleanup logic for the ATOR capability demos.

The Windows (demo_windows_capabilities.ps1) and Linux
(demo_linux_capabilities.sh) demos deploy the same harmless, uniquely-marked
signals so both platforms tell the same attack story. Everything they create is
scoped by these markers so it can be removed again without touching real
telemetry.
"""

# Command-line markers embedded in demo holder processes. Each maps to one
# *_demo.yml behavioral rule (matched against raw_processes.cmdline).
CMDLINE_MARKERS = (
    "ATOR_DEMO_PHISHING_LINK_CLICKED",
    "ATOR_DEMO_EMAIL_ATTACHMENT_OPENED",
    "ATOR_DEMO_MALWARE_DROPPER",
    "ATOR_DEMO_SPYWARE_KEYLOGGER",
    "ATOR_DEMO_BOTNET_BEACON",
    "ATOR_DEMO_RANSOMWARE_ENCRYPT",
    "ATOR_DEMO_INTERNAL_EXECUTION",
)
# Marker written into the dropped trojan file (matched by demo_trojan_payload.yar).
FILE_MARKER = "ATOR_DEMO_TROJAN_PAYLOAD"
# Prefix of every file/path/IOC-source the demo creates.
NAME_PREFIX = "ator_demo"
# Loopback port used by the harmless reverse-shell / C2 network signal.
REVERSE_SHELL_PORT = 4444
LOOPBACK_IPS = ("127.0.0.1", "::1")

_RAW_TABLES = ("raw_processes", "raw_connections", "raw_persistence", "raw_logs", "raw_files")


def _demo_collection_ids(conn, host_id, port):
    """Collection ids that contain any demo-marked artifact for this host."""
    ids = set()
    like = f"%{NAME_PREFIX}%"
    marker_or = " OR ".join("cmdline LIKE ?" for _ in CMDLINE_MARKERS)
    rows = conn.execute(
        f"""SELECT DISTINCT collection_id FROM raw_processes
            WHERE host_id=? AND collection_id IS NOT NULL AND ({marker_or})""",
        (host_id, *[f"%{m}%" for m in CMDLINE_MARKERS]),
    ).fetchall()
    ids.update(r["collection_id"] for r in rows)
    for sql, params in (
        (f"""SELECT DISTINCT collection_id FROM raw_connections
             WHERE host_id=? AND remote_port=? AND collection_id IS NOT NULL""", (host_id, port)),
        (f"""SELECT DISTINCT collection_id FROM raw_files
             WHERE host_id=? AND collection_id IS NOT NULL
               AND (path LIKE ? OR yara_matches LIKE ?)""", (host_id, like, "%Demo%")),
        (f"""SELECT DISTINCT collection_id FROM raw_logs
             WHERE host_id=? AND collection_id IS NOT NULL AND payload_json LIKE ?""",
         (host_id, "%ATOR_DEMO_%")),
    ):
        ids.update(r["collection_id"] for r in conn.execute(sql, params).fetchall())
    ids.discard(None)
    return sorted(ids)


def purge_host_demo_data(conn, host_id, ioc_source=None, port=REVERSE_SHELL_PORT):
    """Delete only demo-scoped rows for one host. Returns a per-table count.

    Scope is limited to the demo markers, the demo IOC source, and loopback
    port 4444, so a host that keeps collecting real telemetry during the demo
    is unaffected.
    """
    deleted = {}
    collection_ids = _demo_collection_ids(conn, host_id, port)

    # Detections: demo-marked evidence, demo collections, or the demo IOC value.
    conditions = ["(host_id=? AND summary LIKE ?)"]
    params = [host_id, "%ATOR_DEMO_%"]
    if collection_ids:
        marks = ",".join("?" for _ in collection_ids)
        conditions.append(f"(host_id=? AND collection_id IN ({marks}))")
        params += [host_id, *collection_ids]
    det_ids = [r["id"] for r in conn.execute(
        f"SELECT id FROM detections WHERE {' OR '.join(conditions)}", params).fetchall()]
    if det_ids:
        marks = ",".join("?" for _ in det_ids)
        deleted["enriched_detections"] = conn.execute(
            f"DELETE FROM enriched_detections WHERE detection_id IN ({marks})", det_ids).rowcount
        deleted["approvals_queue"] = conn.execute(
            f"DELETE FROM approvals_queue WHERE detection_id IN ({marks})", det_ids).rowcount
        deleted["detections"] = conn.execute(
            f"DELETE FROM detections WHERE id IN ({marks})", det_ids).rowcount

    # Raw artifact rows: demo markers / loopback:port for this host.
    marker_or = " OR ".join("cmdline LIKE ?" for _ in CMDLINE_MARKERS)
    deleted["raw_processes"] = conn.execute(
        f"DELETE FROM raw_processes WHERE host_id=? AND ({marker_or})",
        (host_id, *[f"%{m}%" for m in CMDLINE_MARKERS])).rowcount
    deleted["raw_connections"] = conn.execute(
        "DELETE FROM raw_connections WHERE host_id=? AND remote_port=?", (host_id, port)).rowcount
    like = f"%{NAME_PREFIX}%"
    deleted["raw_files"] = conn.execute(
        "DELETE FROM raw_files WHERE host_id=? AND (path LIKE ? OR yara_matches LIKE ?)",
        (host_id, like, "%Demo%")).rowcount
    deleted["raw_logs"] = conn.execute(
        "DELETE FROM raw_logs WHERE host_id=? AND payload_json LIKE ?",
        (host_id, "%ATOR_DEMO_%")).rowcount

    # Evidence manifests that were purely demo collections.
    if collection_ids:
        marks = ",".join("?" for _ in collection_ids)
        remaining = {}
        for table in _RAW_TABLES:
            for r in conn.execute(
                f"SELECT collection_id, COUNT(*) c FROM {table} "
                f"WHERE collection_id IN ({marks}) GROUP BY collection_id", collection_ids):
                remaining[r["collection_id"]] = remaining.get(r["collection_id"], 0) + r["c"]
        empty = [cid for cid in collection_ids if not remaining.get(cid)]
        if empty:
            emarks = ",".join("?" for _ in empty)
            deleted["evidence_manifests"] = conn.execute(
                f"DELETE FROM evidence_manifests WHERE host_id=? AND collection_id IN ({emarks})",
                (host_id, *empty)).rowcount

    if ioc_source:
        deleted["demo_iocs"] = conn.execute(
            "DELETE FROM ioc_store WHERE threat_source=?", (ioc_source,)).rowcount
    conn.commit()
    return {"host_id": host_id, "collection_ids": collection_ids,
            "deleted": {k: v for k, v in deleted.items() if v}}
