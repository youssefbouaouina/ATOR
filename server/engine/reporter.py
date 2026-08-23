import json
import os
import uuid
from datetime import datetime, timezone

from server.engine import soc_chain, timeline
from server.engine.attack_mapper import TACTIC_ORDER

REPORTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "reports_out",
)

TACTIC_HEX = {
    "reconnaissance": "#7f8c8d", "resource-development": "#95a5a6",
    "initial-access": "#c0392b", "execution": "#e74c3c",
    "persistence": "#8e44ad", "privilege-escalation": "#9b59b6",
    "defense-evasion": "#34495e", "credential-access": "#2c3e50",
    "discovery": "#16a085", "lateral-movement": "#27ae60",
    "collection": "#f39c12", "command-and-control": "#d35400",
    "exfiltration": "#c0392b", "impact": "#7b241c",
}


def _ensure_dir():
    os.makedirs(REPORTS_DIR, exist_ok=True)
    return REPORTS_DIR


def host_report_data(conn, host_id):
    host = conn.execute("SELECT * FROM hosts WHERE id=?", (host_id,)).fetchone()
    if not host:
        return None
    risk = soc_chain.risk_assessment(conn, host_id)
    chain = soc_chain.build(conn, host_id)
    tl = timeline.build(conn, host_id, limit=120)
    detections = conn.execute(
        """
        SELECT d.*, e.technique_name FROM detections d
        LEFT JOIN enriched_detections e ON e.detection_id = d.id
        WHERE d.host_id=? ORDER BY d.detected_at_utc DESC LIMIT 200
        """,
        (host_id,),
    ).fetchall()
    manifests = conn.execute(
        "SELECT collection_id, started_at_utc, finished_at_utc, agent_version, artifact_count, manifest_sha256 "
        "FROM evidence_manifests WHERE host_id=? ORDER BY received_at_utc DESC LIMIT 10",
        (host_id,),
    ).fetchall()
    ioc_hits = [d for d in detections if d["rule_type"] == "ioc"]
    return {
        "host": dict(host),
        "risk": risk,
        "chain": chain,
        "timeline": tl,
        "detections": [dict(d) for d in detections],
        "ioc_hits": [dict(d) for d in ioc_hits],
        "manifests": [dict(m) for m in manifests],
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def generate_pdf(conn, host_id, out_path=None):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        Paragraph, SimpleDocTemplate, Spacer, Table as RLTable, TableStyle,
    )

    data = host_report_data(conn, host_id)
    if data is None:
        return None
    _ensure_dir()
    out_path = out_path or os.path.join(
        _ensure_dir(), f"incident_report_host{host_id}_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.pdf"
    )

    styles = getSampleStyleSheet()
    story = []

    risk = data["risk"]
    title_style = styles["Title"]
    story.append(Paragraph("ATOR DFIR - Incident Investigation Report", title_style))
    story.append(Spacer(1, 4 * mm))

    verdict_color = {
        "CRITICAL": colors.HexColor("#c0392b"),
        "HIGH": colors.HexColor("#d35400"),
        "MEDIUM": colors.HexColor("#f39c12"),
        "LOW": colors.HexColor("#27ae60"),
        "CLEAN": colors.HexColor("#16a085"),
    }.get(risk["risk_level"], colors.black)

    summary_rows = [
        ["Verdict", risk["verdict"]],
        ["Risk Level", risk["risk_level"]],
        ["Host", f"{data['host']['hostname']} ({data['host']['os_type']})"],
        ["Attack Stages Observed", str(risk["attack_stages_observed"])],
        ["Detections (C/H/M/L)", f"{risk['counts']['critical']} / {risk['counts']['high']} / {risk['counts']['medium']} / {risk['counts']['low']}"],
        ["Generated (UTC)", data["generated_at_utc"]],
    ]
    t = RLTable(summary_rows, colWidths=[55 * mm, 105 * mm])
    t.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#ecf0f1")),
        ("TEXTCOLOR", (1, 0), (1, 0), verdict_color),
        ("FONTNAME", (1, 0), (1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(t)
    story.append(Spacer(1, 6 * mm))

    story.append(Paragraph("Executive Summary", styles["Heading2"]))
    exec_text = (
        f"An automated investigation of endpoint <b>{data['host']['hostname']}</b> identified "
        f"{sum(risk['counts'].values())} detection(s) across {risk['attack_stages_observed']} ATT&amp;CK tactic stage(s). "
        f"The overall assessment is <b><font color='#{verdict_color.hexval()[2:]}'>{risk['risk_level']}</font></b>: {risk['verdict']}. "
        f"Recommended actions: preserve evidence manifests, review the technical annex timeline, and apply containment "
        f"via the approval workflow if compromise indicators are confirmed."
    )
    story.append(Paragraph(exec_text, styles["BodyText"]))
    story.append(Spacer(1, 6 * mm))

    story.append(Paragraph("Observed Attack Chain (Source of Compromise)", styles["Heading2"]))
    if data["chain"]["chain"]:
        chain_rows = [["#", "Tactic", "Techniques", "First Seen (UTC)", "Last Seen (UTC)"]]
        for i, step in enumerate(data["chain"]["chain"], 1):
            tech_str = "; ".join(
                f"{t['id'] or '-'} {t['name']} (x{t['hits']})" for t in step["techniques"]
            )[:220]
            chain_rows.append([str(i), step["display"], tech_str, step["first_seen"], step["last_seen"]])
        ct = RLTable(chain_rows, colWidths=[8 * mm, 32 * mm, 78 * mm, 21 * mm, 21 * mm])
        ct.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(ct)
    else:
        story.append(Paragraph("No attack chain reconstructed.", styles["BodyText"]))
    story.append(Spacer(1, 6 * mm))

    story.append(Paragraph("ATT&CK Matrix Coverage (observed tactics highlighted)", styles["Heading2"]))
    observed = {step["tactic"]: True for step in data["chain"]["chain"]}
    matrix_cells = []
    row_cells = []
    for tactic in TACTIC_ORDER:
        style_cmd = ("BACKGROUND", (len(row_cells) % 7 + 0, len(matrix_cells)),) if False else None
        row_cells.append(tactic.replace("-", "\n").title() if not observed.get(tactic) else tactic.replace("-", "\n").title() + " *")
        if len(row_cells) == 7:
            matrix_cells.append(row_cells)
            row_cells = []
    if row_cells:
        while len(row_cells) < 7:
            row_cells.append("")
        matrix_cells.append(row_cells)
    mt = RLTable(matrix_cells, colWidths=[24 * mm] * 7)
    mt_style = [
        ("FONTSIZE", (0, 0), (-1, -1), 6.5),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]
    for r_idx, r_row in enumerate(matrix_cells):
        for c_idx, cell in enumerate(r_row):
            base = cell.split("\n")[0].lower().replace("\n", "-")
            matched_tactic = next((t for t in TACTIC_ORDER if t.startswith(base.split(" ")[0])), None)
            if observed.get(matched_tactic):
                mt_style.append(("BACKGROUND", (c_idx, r_idx), (c_idx, r_idx),
                                 colors.HexColor(TACTIC_HEX.get(matched_tactic, "#7f8c8d"))))
                mt_style.append(("TEXTCOLOR", (c_idx, r_idx), (c_idx, r_idx), colors.white))
                mt_style.append(("FONTNAME", (c_idx, r_idx), (c_idx, r_idx), "Helvetica-Bold"))
    mt.setStyle(TableStyle(mt_style))
    story.append(mt)
    story.append(Paragraph("* = tactic observed on this host", styles["Italic"]))
    story.append(Spacer(1, 6 * mm))

    story.append(Paragraph("Technical Annex - Key Detections", styles["Heading2"]))
    det_rows = [["Time (UTC)", "Type", "Rule", "Sev", "MITRE", "Detail"]]
    for d in data["detections"][:40]:
        detail = ""
        try:
            ev = json.loads(d["summary"] or "{}")
            detail = "; ".join(f"{k}={v}" for k, v in list(ev.items())[:4])[:150]
        except json.JSONDecodeError:
            pass
        det_rows.append([
            d["detected_at_utc"], d["rule_type"], d["rule_name"][:40],
            d["severity"], d["technique_id"] or "-", detail,
        ])
    dt = RLTable(det_rows, colWidths=[26 * mm, 14 * mm, 45 * mm, 12 * mm, 18 * mm, 45 * mm], repeatRows=1)
    dt.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 6.5),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(dt)
    story.append(Spacer(1, 6 * mm))

    story.append(Paragraph("Evidence Integrity (Manifests)", styles["Heading2"]))
    man_rows = [["Collection ID", "Started (UTC)", "Agent Ver", "Artifacts", "Manifest SHA-256"]]
    for m in data["manifests"]:
        man_rows.append([m["collection_id"][:13] + "...", m["started_at_utc"] or "",
                         m["agent_version"] or "", str(m["artifact_count"]), m["manifest_sha256"][:32] + "..."])
    mtbl = RLTable(man_rows, colWidths=[28 * mm, 30 * mm, 20 * mm, 18 * mm, 64 * mm])
    mtbl.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 6.5),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
    ]))
    story.append(mtbl)
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(
        f"Timeline events analyzed: {data['timeline']['total']}; time-skew anomalies flagged: {len(data['timeline']['skew'])}. "
        "All timestamps normalized to UTC at ingestion.",
        styles["BodyText"],
    ))

    doc = SimpleDocTemplate(out_path, pagesize=A4)
    doc.build(story)
    return out_path


def generate_json(conn, host_id, out_path=None):
    data = host_report_data(conn, host_id)
    if data is None:
        return None
    out_path = out_path or os.path.join(_ensure_dir(), f"report_host{host_id}.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str)
    return out_path


def generate_stix(conn, host_id, out_path=None):
    now = datetime.now(timezone.utc)
    ts = now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"
    objects = [{
        "type": "identity",
        "spec_version": "2.1",
        "id": "identity--" + str(uuid.uuid5(uuid.NAMESPACE_URL, "ator-dfir-suite")),
        "created": ts,
        "modified": ts,
        "name": "ATOR DFIR Framework",
        "identity_class": "system",
    }]
    host = conn.execute("SELECT hostname FROM hosts WHERE id=?", (host_id,)).fetchone()
    if host:
        ioc_rows = conn.execute(
            "SELECT summary FROM detections WHERE host_id=? AND rule_type='ioc'", (host_id,)
        ).fetchall()
        seen_indicators = set()
        for r in ioc_rows:
            try:
                ev = json.loads(r["summary"])
            except json.JSONDecodeError:
                continue
            pattern = None
            if ev.get("kind") in ("process_hash", "file_hash") and ev.get("sha256"):
                pattern = f"[file:hashes.'SHA-256' = '{ev['sha256']}']"
            elif ev.get("kind") == "c2_connection" and ev.get("remote_ip"):
                pattern = f"[ipv4-addr:value = '{ev['remote_ip']}']"
            if pattern and pattern not in seen_indicators:
                seen_indicators.add(pattern)
                objects.append({
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": "indicator--" + str(uuid.uuid5(uuid.NAMESPACE_URL, "ator:" + pattern)),
                    "created": ts,
                    "modified": ts,
                    "name": f"IoC observed on {host['hostname']}",
                    "pattern": pattern,
                    "pattern_type": "stix",
                    "valid_from": ts,
                })
    bundle = {
        "type": "bundle",
        "id": "bundle--" + str(uuid.uuid5(uuid.NAMESPACE_URL, f"ator:host{host_id}:{ts}")),
        "objects": objects,
    }
    out_path = out_path or os.path.join(_ensure_dir(), f"stix_host{host_id}.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(bundle, fh, indent=2)
    return out_path


def generate_navigator_layer(conn, out_path=None):
    rows = conn.execute(
        """
        SELECT d.technique_id AS tid, e.tactic AS tactic_json
        FROM detections d LEFT JOIN enriched_detections e ON e.detection_id=d.id
        WHERE d.technique_id IS NOT NULL
        """
    ).fetchall()
    scores = {}
    for r in rows:
        tid = r["tid"]
        entry = scores.setdefault(tid, {"score": 0, "tactics": []})
        entry["score"] += 1
        if r["tactic_json"]:
            try:
                for t in json.loads(r["tactic_json"]):
                    short = t.get("short")
                    if short and short not in entry["tactics"]:
                        entry["tactics"].append(short)
            except (json.JSONDecodeError, TypeError):
                pass
    max_score = max([v["score"] for v in scores.values()], default=1)
    techniques = []
    for tid, entry in scores.items():
        tactics = entry["tactics"] or [None]
        for tactic in tactics:
            item = {
                "techniqueID": tid,
                "score": round(entry["score"] / max_score * 100),
                "enabled": True,
                "showSubtechniques": True,
            }
            if tactic:
                item["tactic"] = tactic
            techniques.append(item)
    layer = {
        "name": "ATOR DFIR Detection Coverage",
        "versions": {"layer": "4.5", "navigator": "5.1.1"},
        "domain": "enterprise-attack",
        "description": "Techniques detected by ATOR DFIR framework during investigations.",
        "filters": {"platforms": []},
        "layout": {"layout": "side"},
        "gradient": {"colors": ["#ff6666", "#ffe766", "#8ec843"], "minValue": 0, "maxValue": 100},
        "legendItems": [{"label": "Detected", "color": "#8ec843"}],
        "techniques": techniques,
    }
    out_path = out_path or os.path.join(_ensure_dir(), "attack_navigator_layer.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(layer, fh, indent=2)
    return out_path
