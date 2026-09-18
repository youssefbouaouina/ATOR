import json
import os
import threading

STIX_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "dfir-refs", "cti", "enterprise-attack", "enterprise-attack.json",
)

TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]

_lock = threading.Lock()
_index_cache = None


def _short_name_map(bundle):
    phases = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") == "attack-pattern":
            continue
        if obj.get("type") in ("x-mitre-tactic",):
            phases[obj.get("x_mitre_shortname")] = obj.get("name")
    return phases


def load_index(force=False):
    global _index_cache
    with _lock:
        if _index_cache is not None and not force:
            return _index_cache
        if not os.path.exists(STIX_PATH):
            _index_cache = {"available": False, "techniques": {}}
            return _index_cache
        with open(STIX_PATH, "r", encoding="utf-8") as fh:
            bundle = json.load(fh)
        tactic_names = _short_name_map(bundle)
        techniques = {}
        for obj in bundle.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("revoked"):
                continue
            ext_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                    ext_id = ref["external_id"]
                    break
            if not ext_id:
                continue
            tactics = []
            for phase in obj.get("kill_chain_phases", []):
                if phase.get("kill_chain_name") == "mitre-attack":
                    sn = phase.get("phase_name")
                    tactics.append({"short": sn, "name": tactic_names.get(sn, sn.replace("-", " ").title())})
            techniques[ext_id] = {
                "id": ext_id,
                "name": obj.get("name"),
                "description": (obj.get("description") or "")[:1500],
                "tactics": tactics,
                "platforms": obj.get("x_mitre_platforms", []),
                "data_sources": obj.get("x_mitre_data_sources", []),
                "deprecated": obj.get("x_mitre_deprecated", False),
                "is_subtechnique": "." in ext_id,
            }
        _index_cache = {"available": True, "techniques": techniques}
        return _index_cache


def lookup(technique_id):
    idx = load_index()
    return idx["techniques"].get((technique_id or "").upper())


def load_techniques():
    """Flat technique list for pickers (policy builder, coverage views)."""
    idx = load_index()
    techs = [
        t for t in idx["techniques"].values()
        if not t.get("deprecated") and not t.get("revoked")
    ]
    techs.sort(key=lambda t: (t["id"], t["name"] or ""))
    return techs


def load_techniques_by_tactic():
    """Techniques grouped by tactic for hierarchical picker UI."""
    idx = load_index()
    techs = [
        t for t in idx["techniques"].values()
        if not t.get("deprecated") and not t.get("revoked")
    ]
    by_tactic = {}
    for t in techs:
        for tactic in t.get("tactics", []):
            key = tactic["short"]
            if key not in by_tactic:
                by_tactic[key] = {"short": key, "name": tactic["name"], "techniques": []}
            by_tactic[key]["techniques"].append({
                "id": t["id"],
                "name": t["name"],
                "is_subtechnique": t.get("is_subtechnique", False),
            })
    # Sort tactics by TACTIC_ORDER
    ordered = []
    for short in TACTIC_ORDER:
        if short in by_tactic:
            tactics_entry = by_tactic[short]
            tactics_entry["techniques"].sort(key=lambda x: (not x["is_subtechnique"], x["id"]))
            ordered.append(tactics_entry)
    # Add any tactics not in TACTIC_ORDER
    for short, entry in by_tactic.items():
        if short not in TACTIC_ORDER:
            entry["techniques"].sort(key=lambda x: (not x["is_subtechnique"], x["id"]))
            ordered.append(entry)
    return ordered


def enrich_detections(conn, detection_ids=None):
    idx = load_index()
    if detection_ids:
        placeholders = ",".join("?" for _ in detection_ids)
        rows = conn.execute(
            f"SELECT id, technique_id FROM detections WHERE id IN ({placeholders})",
            list(detection_ids),
        ).fetchall()
    else:
        rows = conn.execute("SELECT id, technique_id FROM detections").fetchall()
    enriched = 0
    missing = []
    for row in rows:
        tid = row["technique_id"]
        tech = lookup(tid) if tid else None
        if tech is None:
            if tid:
                missing.append(tid)
            continue
        conn.execute(
            """
            INSERT INTO enriched_detections (detection_id, technique_name, tactic, platforms,
                                             data_sources, description, kill_chain)
            VALUES (?,?,?,?,?,?,?)
            ON CONFLICT(detection_id) DO UPDATE SET
                technique_name=excluded.technique_name,
                tactic=excluded.tactic,
                platforms=excluded.platforms,
                data_sources=excluded.data_sources,
                description=excluded.description,
                kill_chain=excluded.kill_chain
            """,
            (
                row["id"],
                tech["name"],
                json.dumps(tech["tactics"]),
                json.dumps(tech["platforms"]),
                json.dumps(tech["data_sources"]),
                tech["description"],
                "mitre-attack",
            ),
        )
        enriched += 1
    conn.commit()
    return {"enriched": enriched, "missing": sorted(set(missing)), "cti_available": idx["available"]}


def coverage(conn):
    rows = conn.execute(
        """
        SELECT d.technique_id AS tid, COUNT(*) AS hits
        FROM detections d WHERE d.technique_id IS NOT NULL
        GROUP BY d.technique_id
        """
    ).fetchall()
    rule_rows = conn.execute("SELECT COUNT(DISTINCT rule_name) AS n FROM detections").fetchone()
    return {r["tid"]: r["hits"] for r in rows}, rule_rows["n"] if rule_rows else 0
