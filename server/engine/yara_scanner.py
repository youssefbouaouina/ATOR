import glob
import json
import os

RULES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "rules", "malware",
)


def compile_rules(rules_dir=None):
    try:
        import yara
    except ImportError:
        return None, ["yara-python-not-installed"]
    directory = rules_dir or RULES_DIR
    paths = sorted(glob.glob(os.path.join(directory, "*.yar")))
    if not paths:
        return None, []
    filepaths = {f"ns{i}": p for i, p in enumerate(paths)}
    errors = []
    for path in paths:
        try:
            yara.compile(filepath=path)
        except Exception as exc:
            errors.append({"rule": os.path.basename(path), "error": str(exc)})
    try:
        compiled = yara.compile(filepaths=filepaths)
        return compiled, errors
    except Exception as exc:
        errors.append({"rule": "*", "error": str(exc)})
        return None, errors


def scan_bytes(data, compiled=None, rules_dir=None):
    compiled = compiled or compile_rules(rules_dir)[0]
    if compiled is None:
        return []
    matches = []
    try:
        for m in compiled.match(data=data, timeout=30):
            matches.append({
                "rule": m.rule,
                "namespace": m.namespace,
                "strings": [str(s) for s in getattr(m, "strings", [])][:10],
            })
    except Exception as exc:
        matches.append({"error": str(exc)})
    return matches


def scan_file(path, compiled=None, rules_dir=None):
    compiled = compiled or compile_rules(rules_dir)[0]
    if compiled is None or not os.path.isfile(path):
        return []
    matches = []
    try:
        for m in compiled.match(path, timeout=30):
            matches.append({
                "rule": m.rule,
                "namespace": m.namespace,
                "sha256": _file_sha256(path),
                "size_bytes": os.path.getsize(path),
            })
    except Exception as exc:
        matches.append({"error": str(exc)})
    return matches


def _file_sha256(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def correlate_files(conn, host_id, collection_id, collected_at_utc, files, compiled=None):
    detections = []
    for f in files:
        if not isinstance(f, dict) or "path" not in f:
            continue
        sha = f.get("sha256")
        row_hash = conn.execute(
            "SELECT id FROM ioc_store WHERE ioc_type='hash' AND value=?", (sha,)
        ).fetchone()
        if row_hash:
            detections.append(_det(host_id, collection_id, collected_at_utc, "ioc",
                                   "Known-Bad Hash Match", "high", None,
                                   {"path": f["path"], "sha256": sha}))
        matches = f.get("yara_matches")
        for rule_name in matches or []:
            sev_map = {"eicar_test_file": "medium"}
            detections.append(_det(
                host_id, collection_id, collected_at_utc, "yara",
                f"YARA:{rule_name}", sev_map.get(rule_name.lower(), "high"), None,
                {"path": f["path"], "sha256": sha},
            ))
    return detections


def _det(host_id, collection_id, ts, rule_type, rule_name, severity, technique_id, evidence):
    return {
        "host_id": host_id,
        "collection_id": collection_id,
        "detected_at_utc": ts,
        "rule_type": rule_type,
        "rule_name": rule_name,
        "severity": severity,
        "technique_id": technique_id,
        "summary": json.dumps(evidence, default=str),
        "evidence": evidence,
    }
