import json

from server.engine.attack_mapper import TACTIC_ORDER


def build(conn, host_id):
    rows = conn.execute(
        """
        SELECT d.id, d.detected_at_utc, d.severity, d.rule_type, d.rule_name,
               d.technique_id, e.technique_name, e.tactic
        FROM detections d
        LEFT JOIN enriched_detections e ON e.detection_id = d.id
        WHERE d.host_id = ?
        ORDER BY d.detected_at_utc ASC
        """,
        (host_id,),
    ).fetchall()

    steps = {}
    unplaced = []
    for r in rows:
        tactics = []
        if r["tactic"]:
            try:
                tactics = [t.get("short") for t in json.loads(r["tactic"])]
            except (json.JSONDecodeError, TypeError):
                tactics = []
        if not tactics:
            if r["technique_id"] or r["rule_type"] == "ioc":
                unplaced.append(_entry(r))
            continue
        for tactic in tactics:
            step = steps.setdefault(tactic, {
                "tactic": tactic,
                "display": _tactic_display(tactic),
                "order": TACTIC_ORDER.index(tactic) if tactic in TACTIC_ORDER else 99,
                "techniques": {},
                "first_seen": r["detected_at_utc"],
                "last_seen": r["detected_at_utc"],
            })
            key = r["technique_id"] or f"rule:{r['rule_name']}"
            tech = step["techniques"].setdefault(key, {
                "id": r["technique_id"],
                "name": r["technique_name"] or r["rule_name"],
                "hits": 0,
                "times": [],
            })
            tech["hits"] += 1
            tech["times"].append(r["detected_at_utc"])
            step["first_seen"] = min(step["first_seen"], r["detected_at_utc"])
            step["last_seen"] = max(step["last_seen"], r["detected_at_utc"])

    ordered = sorted(steps.values(), key=lambda s: s["order"])
    for step in ordered:
        step["techniques"] = list(step["techniques"].values())
    return {"host_id": host_id, "chain": ordered, "unplaced": unplaced}


def _entry(r):
    return {
        "technique_id": r["technique_id"],
        "name": r["technique_name"] or r["rule_name"],
        "time": r["detected_at_utc"],
        "severity": r["severity"],
    }


def _tactic_display(short):
    for t in TACTIC_ORDER:
        if t == short:
            return short.replace("-", " ").title()
    return str(short).replace("-", " ").title()


def risk_assessment(conn, host_id):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    row = conn.execute(
        "SELECT severity, COUNT(*) AS n FROM detections WHERE host_id=? GROUP BY severity",
        (host_id,),
    ).fetchall()
    for r in row:
        counts[r["severity"]] = r["n"]
    score = counts["critical"] * 25 + counts["high"] * 10 + counts["medium"] * 3 + counts["low"]
    if counts["critical"]:
        verdict, level = "CONFIRMED COMPROMISE INDICATORS", "CRITICAL"
    elif counts["high"] >= 2:
        verdict, level = "HIGH CONFIDENCE SUSPICIOUS ACTIVITY", "HIGH"
    elif counts["high"] == 1 or counts["medium"] >= 3:
        verdict, level = "SUSPICIOUS ACTIVITY REQUIRES REVIEW", "MEDIUM"
    elif counts["medium"] or counts["low"]:
        verdict, level = "LOW SEVERITY FINDINGS ONLY", "LOW"
    else:
        verdict, level = "NO DETECTIONS", "CLEAN"
    chain = build(conn, host_id)
    progressions = len(chain["chain"])
    if progressions >= 4 and level in ("CRITICAL", "HIGH"):
        verdict += " - MULTI-STAGE ATTACK CHAIN"
    return {
        "counts": counts,
        "score": score,
        "verdict": verdict,
        "risk_level": level,
        "attack_stages_observed": progressions,
    }
