import json


def correlate_batch(conn, host_id, collection_id, collected_at_utc, artifacts):
    detections = []
    iocs = conn.execute("SELECT ioc_type, value, threat_source FROM ioc_store").fetchall()
    if not iocs:
        return detections
    hash_iocs = {r["value"].lower(): r["threat_source"] for r in iocs if r["ioc_type"] == "hash"}
    ip_iocs = {r["value"]: r["threat_source"] for r in iocs if r["ioc_type"] == "ip"}
    domain_iocs = {r["value"].lower(): r["threat_source"] for r in iocs if r["ioc_type"] == "domain"}

    for proc in artifacts.get("processes") or []:
        if not isinstance(proc, dict):
            continue
        sha = (proc.get("sha256") or "").lower()
        if sha and sha in hash_iocs:
            detections.append(_det(host_id, collection_id, collected_at_utc,
                                   f"IOC hash ({hash_iocs[sha]})", "critical", None, {
                                       "kind": "process_hash",
                                       "sha256": sha,
                                       "pid": proc.get("pid"),
                                       "name": proc.get("name"),
                                       "exe_path": proc.get("exe_path"),
                                   }))
        # Domain IOC pivoting: anything we recorded about this process
        # (cmdline, exe path) may name a watchlisted domain.
        proc_text = " ".join(str(proc.get(k) or "") for k in
                             ("cmdline", "exe_path", "name")).lower()
        for dom, source in domain_iocs.items():
            if dom in proc_text:
                detections.append(_det(host_id, collection_id, collected_at_utc,
                                       f"IOC domain ({source})", "high", None, {
                                           "kind": "domain_reference",
                                           "domain": dom,
                                           "pid": proc.get("pid"),
                                           "name": proc.get("name"),
                                           "cmdline": proc.get("cmdline"),
                                           "exe_path": proc.get("exe_path"),
                                       }))
    for f in artifacts.get("files_triage") or []:
        if not isinstance(f, dict):
            continue
        sha = (f.get("sha256") or "").lower()
        if sha and sha in hash_iocs:
            detections.append(_det(host_id, collection_id, collected_at_utc,
                                   f"IOC hash ({hash_iocs[sha]})", "high", None, {
                                       "kind": "file_hash",
                                       "sha256": sha,
                                       "path": f.get("path"),
                                   }))
    for conn_item in artifacts.get("network") or []:
        if not isinstance(conn_item, dict):
            continue
        remote = conn_item.get("remote") or ""
        ip = remote.rsplit(":", 1)[0].strip("[]") if remote else None
        port = remote.rsplit(":", 1)[1] if ":" in remote else None
        if ip in ip_iocs:
            detections.append(_det(host_id, collection_id, collected_at_utc,
                                   f"IOC ip ({ip_iocs[ip]})", "critical", None, {
                                       "kind": "c2_connection",
                                       "remote_ip": ip,
                                       "remote_port": port,
                                       "pid": conn_item.get("pid"),
                                       "process_name": conn_item.get("process_name"),
                                   }))
    return detections


def correlate_domains(conn, events):
    """Match watchlist domain IOCs against observed remote domains.

    events: iterable of dicts with remote_domain/host_id/collection_id/
    detected_at_utc (plus optional process_name/remote_ip/remote_port).
    Returns detection dicts in the standard shape.
    """
    detections = []
    domains = {
        r["value"].lower().rstrip("."): r["threat_source"]
        for r in conn.execute(
            "SELECT value, threat_source FROM ioc_store WHERE ioc_type='domain'"
        ).fetchall()
    }
    if not domains:
        return detections
    for ev in events:
        dom = (ev.get("remote_domain") or "").lower().rstrip(".")
        if not dom or dom not in domains:
            continue
        detections.append(_det(
            ev["host_id"], ev.get("collection_id"), ev["detected_at_utc"],
            f"IOC domain ({domains[dom]})", "critical", None,
            {
                "kind": "domain_ioc",
                "domain": dom,
                "threat_source": domains[dom],
                "process_name": ev.get("process_name"),
                "remote_ip": ev.get("remote_ip"),
                "remote_port": ev.get("remote_port"),
            },
        ))
    return detections


def _det(host_id, collection_id, ts, rule_name, severity, technique_id, evidence):
    return {
        "host_id": host_id,
        "collection_id": collection_id,
        "detected_at_utc": ts,
        "rule_type": "ioc",
        "rule_name": rule_name,
        "severity": severity,
        "technique_id": technique_id,
        "summary": json.dumps(evidence, default=str),
        "evidence": evidence,
    }
