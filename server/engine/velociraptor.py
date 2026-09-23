"""Correlate Velociraptor artifact rows against the existing detection engines.

Artifact rows are just another source of hashes, paths and remote addresses, so
they are folded into the detectors ATOR already has rather than given a parallel
one: the IOC correlator sees them as processes/files/connections, and a row the
agent's local YARA pass flagged is converted exactly as a triaged file is.

What this module adds on top is provenance. A hash IOC that fires from a
Velociraptor sweep must say so - an analyst reading the finding needs to know
the evidence came from ``Windows.System.Pslist`` and not from the routine psutil
snapshot, because the two have different coverage and different blind spots.
"""
import json

from server.engine.ioc_correlator import correlate_batch as ioc_correlate
from server.engine.yara_scanner import correlate_files


def _rows_for(conn, collection_id):
    return [dict(r) for r in conn.execute(
        """SELECT artifact, row_json, path, sha256, remote_ip, process_name, pid
           FROM raw_velociraptor WHERE collection_id=?""",
        (collection_id,),
    )]


def _as_artifacts(rows):
    """Reshape artifact rows into the dict the existing correlators expect.

    One row can legitimately look like more than one thing - a process row with
    a hash is both a process and a file on disk - so it is offered to every
    correlator whose fields it satisfies rather than being forced into one bucket.
    """
    artifacts = {"processes": [], "network": [], "files_triage": []}
    origin = {}
    for row in rows:
        artifact = row.get("artifact")
        sha = (row.get("sha256") or "").lower() or None
        path = row.get("path")
        if sha or row.get("process_name"):
            artifacts["processes"].append({
                "pid": row.get("pid"),
                "name": row.get("process_name"),
                "exe_path": path,
                "cmdline": None,
                "sha256": sha,
            })
        if sha and path:
            artifacts["files_triage"].append({
                "path": path, "sha256": sha, "yara_matches": _yara_matches(row),
            })
        if row.get("remote_ip"):
            artifacts["network"].append({
                "pid": row.get("pid"),
                "process_name": row.get("process_name"),
                "remote": str(row["remote_ip"]),
            })
        for key in _identity_keys(row):
            origin.setdefault(key, artifact)
    return artifacts, origin


def _yara_matches(row):
    """YARA rule names an artifact row carries, if any.

    Velociraptor's YARA artifacts report a ``Rule`` column; the agent keeps the
    row verbatim, so the names are read back out of it here.
    """
    try:
        payload = json.loads(row.get("row_json") or "{}")
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(payload, dict):
        return None
    lowered = {str(k).lower(): v for k, v in payload.items()}
    value = lowered.get("rule") or lowered.get("rules") or lowered.get("yara_matches")
    if not value:
        return None
    return [str(v) for v in value] if isinstance(value, list) else [str(value)]


def _identity_keys(row):
    """Keys by which a detection's evidence can be traced back to its artifact."""
    keys = []
    sha = (row.get("sha256") or "").lower()
    if sha:
        keys.append(("sha256", sha))
    if row.get("path"):
        keys.append(("path", str(row["path"])))
    if row.get("remote_ip"):
        keys.append(("remote_ip", str(row["remote_ip"])))
    return keys


def _stamp(detections, origin):
    """Record on each detection that a Velociraptor artifact produced it."""
    for det in detections:
        evidence = det.get("evidence")
        if not isinstance(evidence, dict):
            continue
        artifact = None
        for field in ("sha256", "path", "remote_ip"):
            value = evidence.get(field)
            if value:
                key = ("sha256", str(value).lower()) if field == "sha256" else (field, str(value))
                artifact = origin.get(key)
                if artifact:
                    break
        evidence["collector"] = "velociraptor"
        if artifact:
            evidence["velociraptor_artifact"] = artifact
        # summary is the stored copy of evidence, so it is rebuilt after editing.
        det["summary"] = json.dumps(evidence, default=str)
    return detections


def correlate_collection(conn, host_id, collection_id, collected_at_utc):
    """Run the standard detectors over one sweep's artifact rows."""
    rows = _rows_for(conn, collection_id)
    if not rows:
        return []
    artifacts, origin = _as_artifacts(rows)
    detections = ioc_correlate(conn, host_id, collection_id, collected_at_utc, artifacts)
    detections += correlate_files(
        conn, host_id, collection_id, collected_at_utc,
        [f for f in artifacts["files_triage"] if f.get("yara_matches")],
    )
    return _stamp(detections, origin)


def summarise(conn, host_id, limit_per_artifact=5):
    """Per-artifact roll-up for the UI and the report annex."""
    out = []
    for row in conn.execute(
        """SELECT artifact, COUNT(*) AS rows,
                  MIN(first_seen_utc) AS first_seen_utc,
                  MAX(last_seen_utc) AS last_seen_utc,
                  COUNT(DISTINCT collection_id) AS sweeps
           FROM raw_velociraptor WHERE host_id=?
           GROUP BY artifact ORDER BY artifact""",
        (host_id,),
    ):
        item = dict(row)
        item["samples"] = [dict(s) for s in conn.execute(
            """SELECT row_json, path, sha256, remote_ip, process_name, last_seen_utc
               FROM raw_velociraptor WHERE host_id=? AND artifact=?
               ORDER BY last_seen_utc DESC LIMIT ?""",
            (host_id, item["artifact"], max(0, int(limit_per_artifact))),
        )]
        out.append(item)
    return out
