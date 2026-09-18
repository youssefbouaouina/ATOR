import html
import json
import os
import re

from datetime import datetime, timedelta, timezone

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

MITRE_BASE_URL = "https://attack.mitre.org/techniques/"
LINK_COLOR = "#2456a6"


def _ensure_dir():
    os.makedirs(REPORTS_DIR, exist_ok=True)
    return REPORTS_DIR


# Human-readable root cause when a detection carries no explicit x-ator-cause.
# Keyed first by rule_type, then refined by technique / rule-name keywords, so
# every detection - not just the demo ones - gets a "why did this fire" line.
_ROOT_CAUSE_BY_TYPE = {
    "ioc": "Match against a known-bad threat-intel indicator (watchlist hash/IP/domain)",
    "yara": "File content matched a malicious-signature (YARA) rule",
}

_ROOT_CAUSE_KEYWORDS = [
    (("reverse shell", "4444", "beacon", "c2"), "Outbound connection to a reverse-shell / C2 destination"),
    (("download cradle", "pipe", "curl", "wget", "certutil"), "Remote payload fetched and executed on the host"),
    (("encoded command", "obfuscat"), "Obfuscated / encoded command execution"),
    (("cron", "run key", "runonce", "scheduled task", "schtask", "persistence", "systemd"),
     "Persistence mechanism registered to survive logoff/reboot"),
    (("mimikatz", "credential", "lsass", "sam"), "Credential-theft tooling executed"),
    (("whoami", "discovery", "enumeration"), "Host / account discovery activity"),
    (("ransom", "encrypt"), "Destructive file-encryption (ransomware) activity"),
    (("phishing", "attachment", "link"), "User executed attacker-delivered phishing content"),
    (("spyware", "keylog"), "Spyware / keylogger capturing user input"),
]


def _detection_evidence(detection):
    try:
        return json.loads(detection["summary"] or "{}")
    except (TypeError, KeyError, json.JSONDecodeError):
        return {}


def detection_root_cause(detection, evidence=None):
    """Return (root_cause_text, investigation_hint) for one detection.

    Prefers the rule-authored x-ator-cause; otherwise infers a plain-language
    cause from the rule type, MITRE technique, and rule name so the report can
    state a root cause for *every* alert.
    """
    ev = evidence if evidence is not None else _detection_evidence(detection)
    category = ev.get("cause_category")
    hint = ev.get("investigation_hint", "")
    if category:
        return category.replace("_", " ").strip().capitalize(), hint
    rtype = (detection["rule_type"] if "rule_type" in detection.keys() else "") or ""
    if rtype in _ROOT_CAUSE_BY_TYPE:
        return _ROOT_CAUSE_BY_TYPE[rtype], hint
    haystack = " ".join(str(detection[k]) for k in ("rule_name", "technique_id")
                        if k in detection.keys() and detection[k]).lower()
    for needles, cause in _ROOT_CAUSE_KEYWORDS:
        if any(n in haystack for n in needles):
            return cause, hint
    return "Behavioral rule matched suspicious activity", hint


def detection_locus(detection, host, evidence=None):
    """Return a 'where' string: which host, and the exact process/file/network
    locus the detection fired on."""
    ev = evidence if evidence is not None else _detection_evidence(detection)
    machine = "-"
    if host:
        hostname = host["hostname"] if "hostname" in host.keys() else None
        os_type = host["os_type"] if "os_type" in host.keys() else None
        machine = f"{hostname or '?'} ({os_type})" if os_type else (hostname or "-")
    parts = []
    if ev.get("exe_path") or ev.get("name") or ev.get("process_name"):
        proc = ev.get("exe_path") or ev.get("name") or ev.get("process_name")
        pid = ev.get("pid")
        parts.append(f"process {proc}" + (f" (pid {pid})" if pid else ""))
    if ev.get("path"):
        parts.append(f"file {ev['path']}")
    if ev.get("remote_ip"):
        port = ev.get("remote_port")
        parts.append(f"network {ev['remote_ip']}" + (f":{port}" if port else ""))
    if not parts and ev.get("cmdline"):
        parts.append(f"cmd: {str(ev['cmdline'])[:80]}")
    locus = "; ".join(parts) if parts else "see evidence annex"
    return machine, locus


def host_report_data(conn, host_id):
    host = conn.execute("SELECT * FROM hosts WHERE id=?", (host_id,)).fetchone()
    if not host:
        return None
    risk = soc_chain.risk_assessment(conn, host_id)
    chain = soc_chain.build(conn, host_id)
    tl = timeline.build(conn, host_id, limit=120)
    detections = conn.execute(
        """
        SELECT d.*, e.technique_name, e.tactic FROM detections d
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
    source_hypotheses = []
    detection_dicts = []
    root_cause_rows = []
    for detection in detections:
        evidence = _detection_evidence(detection)
        cause_text, hint = detection_root_cause(detection, evidence)
        machine, locus = detection_locus(detection, host, evidence)
        d = dict(detection)
        # Root cause / where / when attached to every detection so the dashboard
        # JSON and the PDF share one source of truth.
        d["root_cause"] = cause_text
        d["investigation_hint"] = hint
        d["where_machine"] = machine
        d["where_locus"] = locus
        d["when_first_utc"] = detection["detected_at_utc"]
        d["when_last_utc"] = (detection["last_seen_utc"] if "last_seen_utc" in detection.keys()
                              else None) or detection["detected_at_utc"]
        d["hit_count"] = detection["hit_count"] if "hit_count" in detection.keys() else 1
        detection_dicts.append(d)
        root_cause_rows.append({
            "rule_name": detection["rule_name"], "rule_type": detection["rule_type"],
            "severity": detection["severity"], "technique_id": detection["technique_id"],
            "root_cause": cause_text, "where_machine": machine, "where_locus": locus,
            "when_first_utc": d["when_first_utc"], "when_last_utc": d["when_last_utc"],
            "hit_count": d["hit_count"], "investigation_hint": hint,
        })
        category = evidence.get("cause_category")
        if category:
            item = {
                "category": category,
                "rule_name": detection["rule_name"],
                "severity": detection["severity"],
                "detected_at_utc": detection["detected_at_utc"],
                "investigation_hint": hint,
            }
            if item not in source_hypotheses:
                source_hypotheses.append(item)
    return {
        "host": dict(host),
        "risk": risk,
        "chain": chain,
        "timeline": tl,
        "detections": detection_dicts,
        "ioc_hits": [dict(d) for d in ioc_hits],
        "source_hypotheses": source_hypotheses,
        "root_cause_rows": root_cause_rows,
        "manifests": [dict(m) for m in manifests],
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def _short_ts(ts):
    if not ts:
        return "-"
    return str(ts).replace("T", " ")[:19]


def _mitre_link(technique_id, style):
    tid = technique_id if isinstance(technique_id, str) else ""
    if not re.fullmatch(r"T\d{4}(?:\.\d{3})?", tid, re.ASCII):
        return html.escape(str(technique_id)) if technique_id else "-"
    url = f"{MITRE_BASE_URL}{tid.replace('.', '/')}/"
    return (
        f'<a href="{url}" color="{LINK_COLOR}">'
        f'<u>{html.escape(tid)}</u></a>'
    )


def _severity_pie(counts):
    import reportlab.lib.colors as rl_colors
    from reportlab.graphics.charts.legends import Legend
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics.shapes import Drawing

    d = Drawing(250, 165)
    values = [counts.get("critical", 0), counts.get("high", 0),
              counts.get("medium", 0), counts.get("low", 0)]
    pc = Pie()
    pc.x, pc.y = 55, 28
    pc.width = 110
    pc.height = 110
    pc.data = values or [1]
    pc.labels = None
    palette = ["#c0392b", "#d35400", "#b7791f", "#1e8e5a"]
    for i, hexcolor in enumerate(palette):
        pc.slices[i].fillColor = rl_colors.HexColor(hexcolor)
        pc.slices[i].strokeColor = None
    d.add(pc)

    leg = Legend()
    leg.x, leg.y = 168, 118
    leg.deltax = 0
    leg.deltay = 16
    leg.fontSize = 7.5
    leg.strokeColor = None
    leg.columnMaximum = 4
    names = ["critical", "high", "medium", "low"]
    leg.colorNamePairs = [
        (rl_colors.HexColor(palette[i]), f"{names[i]} ({values[i]})") for i in range(4)
    ]
    d.add(leg)
    return d


def _tactic_bars(tactic_counts):
    from reportlab.graphics.charts.barcharts import HorizontalBarChart
    from reportlab.graphics.shapes import Drawing
    import reportlab.lib.colors as rl_colors

    ordered = [t for t in TACTIC_ORDER if t in tactic_counts]
    if not ordered:
        return None
    labels = [t.replace("-", " ").title() for t in ordered]
    values = [tactic_counts[t] for t in ordered]

    d = Drawing(265, max(120, 20 * len(labels) + 40))
    bc = HorizontalBarChart()
    bc.x = 92
    bc.y = 18
    bc.width = 150
    bc.height = max(90, 20 * len(labels))
    bc.data = [values]
    bc.categoryAxis.categoryNames = labels
    bc.categoryAxis.labels.fontName = "Helvetica"
    bc.categoryAxis.labels.fontSize = 7
    bc.categoryAxis.labels.dx = -4
    bc.valueAxis.valueMin = 0
    bc.valueAxis.valueMax = max(values) + 1
    bc.valueAxis.valueStep = max(1, max(values) // 5)
    bc.valueAxis.labels.fontSize = 6.5
    bc.valueAxis.strokeColor = rl_colors.HexColor("#cbd5e1")
    bc.categoryAxis.strokeColor = rl_colors.HexColor("#cbd5e1")
    bc.bars[(0, 0)].fillColor = rl_colors.HexColor("#2456a6")
    bc.barLabels.fontName = "Helvetica"
    bc.barLabels.fontSize = 7
    bc.barLabelFormat = "%d"
    bc.barLabels.nudge = 6
    for i, t in enumerate(ordered):
        bc.bars[(0, i)].fillColor = rl_colors.HexColor(TACTIC_HEX.get(t, "#2456a6"))
    d.add(bc)
    return d


def _trend_chart(conn, host_id):
    from reportlab.graphics.charts.linecharts import HorizontalLineChart
    from reportlab.graphics.shapes import Drawing
    import reportlab.lib.colors as rl_colors

    now = datetime.now(timezone.utc)
    cutoff = (now - timedelta(hours=23)).strftime("%Y-%m-%dT%H")
    buckets = {}
    for row in conn.execute(
        "SELECT substr(detected_at_utc,1,13) AS h, COUNT(*) AS n FROM detections"
        " WHERE host_id=? AND detected_at_utc >= ? GROUP BY h",
        (host_id, cutoff),
    ):
        buckets[row["h"]] = row["n"]
    labels = []
    values = []
    for i in range(23, -1, -1):
        hr = (now - timedelta(hours=i)).strftime("%Y-%m-%dT%H")
        labels.append(hr[11:] + "h")
        values.append(buckets.get(hr, 0))

    d = Drawing(500, 130)
    lc = HorizontalLineChart()
    lc.x = 38
    lc.y = 22
    lc.width = 430
    lc.height = 88
    lc.data = [values]
    lc.lines[0].strokeColor = rl_colors.HexColor("#2456a6")
    lc.lines[0].strokeWidth = 1.6
    lc.lines[0].symbol = None
    lc.categoryAxis.categoryNames = labels
    lc.categoryAxis.labels.fontName = "Helvetica"
    lc.categoryAxis.labels.fontSize = 6
    lc.categoryAxis.labels.dy = -3
    lc.categoryAxis.strokeColor = rl_colors.HexColor("#cbd5e1")
    lc.valueAxis.valueMin = 0
    lc.valueAxis.valueMax = max(values + [4])
    lc.valueAxis.valueStep = max(1, int(max(values + [4]) / 4))
    lc.valueAxis.labels.fontName = "Helvetica"
    lc.valueAxis.labels.fontSize = 6
    lc.valueAxis.strokeColor = rl_colors.HexColor("#cbd5e1")
    d.add(lc)
    return d


def record_report(conn, host_id, kind, path, data=None, generated_by="analyst"):
    """Record a generated report in report_history (best-effort).

    Gives every endpoint a downloadable, filterable report history. Never raises
    - a history-write failure must not break the actual report download.
    """
    try:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        risk_level = None
        if data and data.get("risk"):
            counts.update(data["risk"].get("counts") or {})
            risk_level = data["risk"].get("risk_level")
        else:
            for r in conn.execute(
                "SELECT severity, COUNT(*) n FROM detections WHERE host_id=? GROUP BY severity",
                (host_id,)):
                if r["severity"] in counts:
                    counts[r["severity"]] = r["n"]
        total = sum(counts.values())
        size = os.path.getsize(path) if path and os.path.exists(path) else None
        conn.execute(
            """INSERT INTO report_history
               (host_id, kind, filename, path, generated_at_utc, generated_by, size_bytes,
                detection_total, critical, high, medium, low, risk_level)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (host_id, kind, os.path.basename(path), path,
             datetime.now(timezone.utc).isoformat(timespec="seconds"), generated_by, size,
             total, counts["critical"], counts["high"], counts["medium"], counts["low"], risk_level),
        )
        conn.commit()
    except Exception:
        pass


def generate_pdf(conn, host_id, out_path=None):
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        Paragraph, SimpleDocTemplate, Spacer, Table as RLTable, TableStyle,
    )
    from reportlab.lib.colors import HexColor

    data = host_report_data(conn, host_id)
    if data is None:
        return None
    _ensure_dir()
    out_path = out_path or os.path.join(
        _ensure_dir(),
        f"incident_report_host{host_id}_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.pdf",
    )

    styles = getSampleStyleSheet()
    h2 = ParagraphStyle("ATORH2", parent=styles["Heading2"], spaceBefore=6, spaceAfter=4)
    body = ParagraphStyle("ATORBody", parent=styles["BodyText"], fontSize=9, leading=12.5)
    cell = ParagraphStyle("ATORCell", parent=styles["BodyText"], fontSize=7.5, leading=9.5)
    cellB = ParagraphStyle("ATORCellB", parent=cell, fontName="Helvetica-Bold")
    cellMono = ParagraphStyle("ATORCellMono", parent=cell, fontName="Courier", fontSize=6.8, leading=8.4)
    tocLink = ParagraphStyle("ATORToc", parent=body, leading=15)
    note = ParagraphStyle("ATORNote", parent=styles["BodyText"], fontSize=8, textColor=colors.HexColor("#64748b"))

    def P(text, st=cell):
        return Paragraph(html.escape(str(text)), st)

    def PH(markup, st=cell):
        return Paragraph(markup, st)

    story = []

    def outline_heading(text, key, level=0):
        p = Paragraph(html.escape(text), h2)
        p._ator_outline = (text, key, level)
        return p

    def anchored_heading(text, key, level=0):
        p = Paragraph(f'<a name="{key}"/>' + html.escape(text), h2)
        p._ator_outline = (text, key, level)
        return p

    risk = data["risk"]
    host = data["host"]
    generated_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    story.append(Paragraph("ATOR DFIR - Incident Investigation Report", styles["Title"]))
    story.append(Spacer(1, 3 * mm))

    story.append(Paragraph("<b>Contents</b>", styles["Heading3"]))
    for label, key in [
        ("1. Executive Summary", "sec-exec"),
        ("2. Detection Analytics", "sec-analytics"),
        ("3. Observed Attack Chain", "sec-chain"),
        ("4. ATT&amp;CK Coverage Matrix", "sec-matrix"),
        ("5. Root Cause Analysis (What / Where / When)", "sec-rootcause"),
        ("6. Technical Annex - Detections", "sec-detections"),
        ("7. Source of Compromise Assessment", "sec-source"),
        ("8. Timeline Highlights", "sec-timeline"),
        ("9. Evidence Integrity", "sec-manifests"),
    ]:
        story.append(PH(f'<a href="#{key}" color="{LINK_COLOR}">{label}</a>', tocLink))
    story.append(Spacer(1, 4 * mm))

    verdict_color = {
        "CRITICAL": "#c0392b", "HIGH": "#d35400",
        "MEDIUM": "#b7791f", "LOW": "#1e8e5a", "CLEAN": "#16a085",
    }.get(risk["risk_level"], "#000000")

    summary_rows = [
        ["Verdict", PH(f'<font color="{verdict_color}"><b>{risk["verdict"]}</b></font>', cell)],
        ["Risk Level", P(risk["risk_level"])],
        ["Host", P(f'{host["hostname"]} ({host["os_type"]})')],
        ["Agent Version", P(host["agent_version"] or "-")],
        ["Attack Stages Observed", P(str(risk["attack_stages_observed"]))],
        ["Detections (C/H/M/L)", P(f'{risk["counts"]["critical"]} / {risk["counts"]["high"]} / '
                                   f'{risk["counts"]["medium"]} / {risk["counts"]["low"]}')],
        ["Generated (UTC)", P(generated_ts)],
    ]
    t = RLTable(summary_rows, colWidths=[48 * mm, 134 * mm])
    t.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BACKGROUND", (0, 0), (0, -1), HexColor("#ecf0f1")),
        ("TEXTCOLOR", (1, 0), (1, 0), HexColor(verdict_color)),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t)
    story.append(Spacer(1, 5 * mm))

    story.append(anchored_heading("Executive Summary", "sec-exec"))
    exec_text = (
        f'An automated investigation of endpoint <b>{html.escape(host["hostname"])}</b> identified '
        f'{sum(risk["counts"].values())} detection(s) across {risk["attack_stages_observed"]} ATT&amp;CK '
        f'tactic stage(s). The overall assessment is <b><font color="{verdict_color}">'
        f'{risk["risk_level"]}</font></b>: {html.escape(risk["verdict"])}. Recommended actions: preserve '
        f'evidence manifests (section 7), review the attack chain (section 3) and technical annex '
        f'(sections 5-6), and apply containment through the approval workflow if compromise indicators '
        f'are confirmed. All timestamps are normalized to UTC.'
    )
    story.append(Paragraph(exec_text, body))
    story.append(Spacer(1, 5 * mm))

    story.append(anchored_heading("Detection Analytics", "sec-analytics"))
    tactic_counts = {}
    for d in data["detections"]:
        if not d.get("tactic"):
            continue
        try:
            parsed = json.loads(d["tactic"])
            for entry in parsed:
                short = entry.get("short")
                if short:
                    tactic_counts[short] = tactic_counts.get(short, 0) + 1
        except json.JSONDecodeError:
            continue

    pie = _severity_pie(risk["counts"])
    bars = _tactic_bars(tactic_counts)
    analytics_cells = [[pie, bars or P("No tactic data yet.")]]
    at = RLTable(analytics_cells, colWidths=[91 * mm, 91 * mm])
    at.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (0, 0), "CENTER"),
        ("BOX", (0, 0), (0, 0), 0.4, HexColor("#e2e8f0")),
        ("BOX", (1, 0), (1, 0), 0.4, HexColor("#e2e8f0")),
    ]))
    story.append(at)
    story.append(Spacer(1, 3 * mm))
    story.append(P("Detections per hour - last 24 hours (UTC):", ParagraphStyle(
        "ATORMiniHead", parent=styles["BodyText"], fontSize=8, textColor=colors.HexColor("#64748b"))))
    trend = _trend_chart(conn, host_id)
    story.append(trend)
    story.append(Spacer(1, 5 * mm))

    story.append(anchored_heading("Observed Attack Chain (Source of Compromise)", "sec-chain"))
    if data["chain"]["chain"]:
        chain_rows = [["#", "Tactic", "Techniques (click ID for MITRE reference)", "Observed Window (UTC)"]]
        for i, step in enumerate(data["chain"]["chain"], 1):
            tech_parts = []
            for tech in step["techniques"]:
                tid = tech["id"]
                id_html = _mitre_link(tid, cell) if tid else "-"
                tech_parts.append(f'{id_html} {html.escape(tech["name"])} (x{tech["hits"]})')
            window = PH(
                f'{_short_ts(step["first_seen"])}<br/>&#8594; {_short_ts(step["last_seen"])}',
                cellMono,
            )
            chain_rows.append([
                P(str(i)),
                P(step["display"]),
                PH("<br/>".join(tech_parts)),
                window,
            ])
        ct = RLTable(chain_rows, colWidths=[8 * mm, 32 * mm, 98 * mm, 44 * mm], repeatRows=1)
        ct.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("BACKGROUND", (0, 0), (-1, 0), HexColor("#2c3e50")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, HexColor("#f8fafc")]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(ct)
    else:
        story.append(P("No attack chain reconstructed.", body))
    story.append(Spacer(1, 5 * mm))

    story.append(anchored_heading("ATT&CK Coverage Matrix (observed tactics highlighted)", "sec-matrix"))
    observed = {step["tactic"]: True for step in data["chain"]["chain"]}
    matrix_cells = []
    row_cells = []
    for tactic in TACTIC_ORDER:
        marker = " *" if observed.get(tactic) else ""
        row_cells.append(tactic.replace("-", "\n").title() + marker)
        if len(row_cells) == 7:
            matrix_cells.append(row_cells)
            row_cells = []
    if row_cells:
        while len(row_cells) < 7:
            row_cells.append("")
        matrix_cells.append(row_cells)
    mt = RLTable(matrix_cells, colWidths=[26 * mm] * 7)
    mt_style = [
        ("FONTSIZE", (0, 0), (-1, -1), 6.5),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]
    for r_idx, r_row in enumerate(matrix_cells):
        for c_idx, raw_cell in enumerate(r_row):
            base = raw_cell.split("\n")[0].lower().strip(" *")
            matched_tactic = next((tc for tc in TACTIC_ORDER if tc.startswith(base)), None) if base else None
            if matched_tactic and observed.get(matched_tactic):
                mt_style.append(("BACKGROUND", (c_idx, r_idx), (c_idx, r_idx),
                                 HexColor(TACTIC_HEX.get(matched_tactic, "#7f8c8d"))))
                mt_style.append(("TEXTCOLOR", (c_idx, r_idx), (c_idx, r_idx), colors.white))
                mt_style.append(("FONTNAME", (c_idx, r_idx), (c_idx, r_idx), "Helvetica-Bold"))
    mt.setStyle(TableStyle(mt_style))
    story.append(mt)
    story.append(P("* = tactic observed on this host", note))
    story.append(Spacer(1, 5 * mm))

    story.append(anchored_heading("Root Cause Analysis (What / Where / When)", "sec-rootcause"))
    rc_rows = data.get("root_cause_rows") or []
    if rc_rows:
        story.append(P(
            "Every detection below is stated as: what fired, its inferred root "
            "cause, where it happened (host and the exact process / file / "
            "network locus), and when (first seen - last seen, UTC). Root cause "
            "is an evidence-based inference, not confirmed attribution.",
            body,
        ))
        root_head = [["When (UTC, first - last)", "What (rule)", "Sev", "Root cause", "Where"]]
        for item in rc_rows[:60]:
            when = _short_ts(item["when_first_utc"])
            if item["when_last_utc"] and item["when_last_utc"] != item["when_first_utc"]:
                when += "\n- " + _short_ts(item["when_last_utc"])
            if item.get("hit_count", 1) > 1:
                when += f"\n(x{item['hit_count']})"
            where = item["where_machine"]
            if item.get("where_locus"):
                where += "\n" + item["where_locus"]
            root_head.append([
                P(when, cellMono),
                P(item["rule_name"], cellB),
                P(item["severity"]),
                P(item["root_cause"]),
                P(where, cellMono),
            ])
        rc_table = RLTable(root_head, colWidths=[30 * mm, 34 * mm, 13 * mm, 45 * mm, 60 * mm],
                           repeatRows=1)
        rc_table.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 7.5),
            ("BACKGROUND", (0, 0), (-1, 0), HexColor("#2c3e50")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, HexColor("#f8fafc")]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(rc_table)
    else:
        story.append(P("No detections recorded for this host.", body))
    story.append(Spacer(1, 5 * mm))

    story.append(anchored_heading("Technical Annex - Key Detections", "sec-detections"))
    det_rows = [["Time (UTC)", "Type", "Rule", "Sev", "MITRE", "Detail"]]
    for d in data["detections"][:40]:
        detail = ""
        try:
            ev = json.loads(d["summary"] or "{}")
            detail = "; ".join(f"{k}={v}" for k, v in list(ev.items())[:5])
        except json.JSONDecodeError:
            pass
        det_rows.append([
            P(_short_ts(d["detected_at_utc"]), cellMono),
            P(d["rule_type"]),
            P(d["rule_name"]),
            P(d["severity"]),
            PH(_mitre_link(d["technique_id"], cell)) if d["technique_id"] else P("-"),
            P(detail[:220], cellMono),
        ])
    dt = RLTable(det_rows, colWidths=[27 * mm, 13 * mm, 40 * mm, 15 * mm, 21 * mm, 66 * mm],
                 repeatRows=1)
    dt.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 7.5),
        ("BACKGROUND", (0, 0), (-1, 0), HexColor("#2c3e50")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, HexColor("#f8fafc")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(dt)
    story.append(Spacer(1, 5 * mm))

    story.append(anchored_heading("Source of Compromise Assessment", "sec-source"))
    source_hypotheses = data.get("source_hypotheses") or []
    if source_hypotheses:
        story.append(P(
            "The following are evidence-based investigation hypotheses, not "
            "confirmed attribution or proof of user fault. Correlate mail, "
            "browser, proxy, authentication, endpoint, and change-management "
            "records before assigning responsibility.",
            body,
        ))
        source_rows = [["Hypothesis", "Detection", "Severity", "Investigation guidance"]]
        for item in source_hypotheses[:20]:
            source_rows.append([
                P(item["category"], cellMono),
                P(item["rule_name"]),
                P(item["severity"]),
                P(item["investigation_hint"] or "-"),
            ])
        source_table = RLTable(
            source_rows, colWidths=[42 * mm, 42 * mm, 18 * mm, 80 * mm], repeatRows=1
        )
        source_table.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("BACKGROUND", (0, 0), (-1, 0), HexColor("#2c3e50")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, HexColor("#f8fafc")]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(source_table)
    else:
        story.append(P(
            "No source-of-compromise hypothesis was attached to the available "
            "detections. Review the timeline and raw evidence for delivery and "
            "user-action telemetry.",
            body,
        ))
    story.append(Spacer(1, 5 * mm))

    story.append(anchored_heading("Timeline Highlights", "sec-timeline"))
    tl_events = [e for e in data["timeline"]["events"] if e.get("ts")][:25]
    if tl_events:
        tl_rows = [["Time (UTC)", "Kind", "Event", "Detail"]]
        for e in tl_events:
            tl_rows.append([
                P(_short_ts(e["ts"]), cellMono),
                P(e["kind"]),
                P(e["title"]),
                P(str(e.get("detail", ""))[:180], cellMono),
            ])
        tt = RLTable(tl_rows, colWidths=[30 * mm, 21 * mm, 58 * mm, 73 * mm], repeatRows=1)
        tt.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 7.5),
            ("BACKGROUND", (0, 0), (-1, 0), HexColor("#2c3e50")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, HexColor("#f8fafc")]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(tt)
    else:
        story.append(P("No timeline events recorded for this host.", body))
    story.append(Spacer(1, 5 * mm))

    story.append(anchored_heading("Evidence Integrity (Manifests)", "sec-manifests"))
    man_rows = [["Collection ID", "Started (UTC)", "Agent Ver", "Artifacts", "Manifest SHA-256"]]
    for m in data["manifests"]:
        man_rows.append([
            P(m["collection_id"], cellMono),
            P(_short_ts(m["started_at_utc"]), cell),
            P(m["agent_version"] or "-", cell),
            P(str(m["artifact_count"]), cell),
            P((m["manifest_sha256"] or "")[:64], cellMono),
        ])
    mtbl = RLTable(man_rows, colWidths=[34 * mm, 32 * mm, 18 * mm, 16 * mm, 82 * mm])
    mtbl.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 7.5),
        ("BACKGROUND", (0, 0), (-1, 0), HexColor("#2c3e50")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(mtbl)
    story.append(Spacer(1, 3 * mm))
    story.append(P(
        f'Timeline events analyzed: {data["timeline"]["total"]}; time-skew anomalies flagged: '
        f'{len(data["timeline"]["skew"])}. Every manifest SHA-256 is verified server-side at ingestion; '
        'hashes above let recipients re-verify collection integrity independently.',
        body,
    ))

    from reportlab.lib.pagesizes import A4

    class _DocTemplate(SimpleDocTemplate):
        def afterFlowable(self, flowable):
            outline = getattr(flowable, "_ator_outline", None)
            if outline:
                title, key, level = outline
                self.canv.bookmarkPage(key)
                self.canv.addOutlineEntry(title, key, level=level, closed=False)

    doc = _DocTemplate(
        out_path,
        pagesize=A4,
        leftMargin=14 * mm,
        rightMargin=14 * mm,
        topMargin=17 * mm,
        bottomMargin=15 * mm,
        title=f"ATOR DFIR Incident Report - {host['hostname']}",
        author="ATOR DFIR Framework",
        subject=f"Investigation report for {host['hostname']} ({host['os_type']})",
    )

    def decorate(canvas, _doc):
        canvas.saveState()
        w, hgt = A4
        gray = HexColor("#94a3b8")
        line = HexColor("#e2e8f0")
        canvas.setFont("Helvetica", 6.5)
        canvas.setFillColor(gray)
        canvas.drawString(doc.leftMargin, hgt - 30, "CONFIDENTIAL // DFIR INVESTIGATION REPORT")
        canvas.drawRightString(w - doc.rightMargin, hgt - 30, f"host: {host['hostname']}")
        canvas.setStrokeColor(line)
        canvas.line(doc.leftMargin, hgt - 34, w - doc.rightMargin, hgt - 34)
        canvas.drawString(doc.leftMargin, 24,
                          f"ATOR DFIR Framework · generated {generated_ts} UTC · containment mode: DRY-RUN")
        canvas.drawRightString(w - doc.rightMargin, 24, f"Page {canvas.getPageNumber()}")
        canvas.restoreState()

    doc.build(story, onFirstPage=decorate, onLaterPages=decorate)
    record_report(conn, host_id, "pdf", out_path, data)
    return out_path

def generate_json(conn, host_id, out_path=None):
    data = host_report_data(conn, host_id)
    if data is None:
        return None
    stamped = out_path is None
    out_path = out_path or os.path.join(
        _ensure_dir(),
        f"report_host{host_id}_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str)
    if stamped:
        record_report(conn, host_id, "json", out_path, data)
    return out_path


def generate_stix(conn, host_id, out_path=None):
    import uuid

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
    stamped = out_path is None
    out_path = out_path or os.path.join(
        _ensure_dir(),
        f"stix_host{host_id}_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(bundle, fh, indent=2)
    if stamped:
        record_report(conn, host_id, "stix", out_path, None)
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
