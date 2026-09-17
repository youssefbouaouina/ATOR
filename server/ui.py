import json
from datetime import datetime, timezone

from fastapi import Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from server import db as database
from server.engine import soc_chain, timeline


def create_app():
    from server.api import app as api_app
    return api_app


templates = None


def _get_templates():
    global templates
    if templates is None:
        from fastapi.templating import Jinja2Templates
        templates = Jinja2Templates(directory="server/templates")
    return templates


def register_ui(target_app):
    tpl = _get_templates()

    @target_app.get("/", response_class=HTMLResponse)
    def overview(request: Request, conn=Depends(database.connect)):
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for r in conn.execute("SELECT severity, COUNT(*) AS n FROM detections GROUP BY severity"):
            counts[r["severity"]] = r["n"]
        hosts = conn.execute("SELECT COUNT(*) AS n FROM hosts WHERE is_active=1").fetchone()["n"]
        total_dets = sum(counts.values())
        recent = conn.execute(
            """SELECT d.*, h.hostname FROM detections d JOIN hosts h ON h.id=d.host_id
               ORDER BY d.detected_at_utc DESC LIMIT 15"""
        ).fetchall()
        manifests = conn.execute("SELECT COUNT(*) AS n FROM evidence_manifests").fetchone()["n"]
        conn.close()
        return tpl.TemplateResponse(request, "overview.html", {
            "counts": counts, "hosts": hosts, "total_dets": total_dets,
            "recent": [dict(r) for r in recent], "manifests": manifests,
            "page": "overview",
        })

    @target_app.get("/investigation", response_class=HTMLResponse)
    def investigation(request: Request, host_id: int = 0, conn=Depends(database.connect)):
        hosts = [dict(r) for r in conn.execute("SELECT id, hostname, os_type FROM hosts ORDER BY hostname")]
        selected = host_id or (hosts[0]["id"] if hosts else 0)
        tl = timeline.build(conn, selected or None, limit=200) if selected else {"events": [], "total": 0, "skew": []}
        soc = soc_chain.build(conn, selected) if selected else {"chain": []}
        tree = timeline.process_tree(conn, selected) if selected else {"nodes": [], "edges": [], "collection_id": None}
        detections = [dict(r) for r in conn.execute(
            """SELECT d.*, e.technique_name FROM detections d
               LEFT JOIN enriched_detections e ON e.detection_id=d.id
               WHERE d.host_id=? ORDER BY d.detected_at_utc DESC LIMIT 50""", (selected,))]
        # Confidence band drives the badge colour. Imported lazily and defensively: the ML
        # stack is optional, and the investigation page must render without it.
        try:
            from server.engine.ml_triage import confidence_band
            for d in detections:
                d["confidence_band"] = confidence_band(d.get("confidence_score"))
        except Exception:                            # noqa: BLE001
            for d in detections:
                d["confidence_band"] = "unknown"
        conn.close()
        return tpl.TemplateResponse(request, "investigation.html", {
            "hosts": hosts, "selected": selected, "timeline": tl, "soc": soc,
            "tree": tree, "detections": detections, "page": "investigation",
        })

    @target_app.get("/ml", response_class=HTMLResponse)
    def ml_analytics(request: Request, conn=Depends(database.connect)):
        """Layer 4.5 ML dashboard: models, triage queue, host risk, drift.

        Degrades rather than fails when the optional ML stack is absent - the template
        renders an explanatory banner and the rest of the dashboard is unaffected.
        """
        from server.engine import ml_registry, ml_triage

        try:
            ml = ml_registry.describe(conn)
        except Exception as exc:                     # noqa: BLE001
            ml = {"available": False, "reason": f"{type(exc).__name__}: {exc}", "models": []}

        anomalies = []
        for row in conn.execute(
            """SELECT d.id, d.host_id, h.hostname, d.rule_name, d.severity, d.summary,
                      d.detected_at_utc, d.anomaly_score, d.confidence_score, d.ml_explanation
               FROM detections d LEFT JOIN hosts h ON h.id = d.host_id
               WHERE d.rule_type = 'ml_anomaly'
               ORDER BY d.anomaly_score DESC, d.id DESC LIMIT 40"""):
            item = dict(row)
            try:
                item["ml_explanation"] = json.loads(item["ml_explanation"] or "{}")
            except (json.JSONDecodeError, TypeError):
                item["ml_explanation"] = {}
            item["confidence_band"] = ml_triage.confidence_band(item.get("confidence_score"))
            anomalies.append(item)

        risk = []
        for row in conn.execute(
            """SELECT r.host_id, h.hostname, r.score, r.tier, r.breakdown_json
               FROM host_risk_scores r LEFT JOIN hosts h ON h.id = r.host_id
               ORDER BY r.score DESC LIMIT 20"""):
            item = dict(row)
            try:
                item["breakdown"] = json.loads(item.pop("breakdown_json") or "{}")
            except json.JSONDecodeError:
                item["breakdown"] = {}
            risk.append(item)

        entries = [dict(r) for r in conn.execute(
            """SELECT computed_at_utc, feature_name, psi, verdict FROM ml_drift_log
               ORDER BY computed_at_utc DESC, psi DESC LIMIT 20""")]
        drift = {
            "entries": entries,
            "shifted_features": sum(1 for e in entries if e["verdict"] == "shifted"),
            "retrain_recommended": any(e["verdict"] == "shifted" for e in entries),
        }
        conn.close()
        return tpl.TemplateResponse(request, "ml_analytics.html", {
            "ml": ml, "anomalies": anomalies, "risk": risk, "drift": drift, "page": "ml",
        })

    @target_app.get("/endpoints", response_class=HTMLResponse)
    def endpoints(request: Request, conn=Depends(database.connect)):
        hosts = [dict(r) for r in conn.execute(
            """SELECT h.*,
                      (SELECT COUNT(*) FROM detections d WHERE d.host_id=h.id) AS detection_count,
                      r.score AS risk_score, r.tier AS risk_tier
               FROM hosts h
               LEFT JOIN host_risk_scores r ON r.host_id = h.id
               ORDER BY COALESCE(r.score, -1) DESC, h.id"""
        )]
        conn.close()
        return tpl.TemplateResponse(request, "endpoints.html", {
            "hosts": hosts, "page": "endpoints",
        })

    @target_app.get("/containment", response_class=HTMLResponse)
    def containment(request: Request, conn=Depends(database.connect)):
        policies = [dict(r) for r in conn.execute("SELECT * FROM policies ORDER BY id DESC")]
        pending = [dict(r) for r in conn.execute(
            """SELECT q.*, d.rule_name, d.severity, h.hostname, d.summary
               FROM approvals_queue q JOIN detections d ON d.id=q.detection_id
               JOIN hosts h ON h.id=d.host_id WHERE q.status='pending'
               ORDER BY q.requested_at_utc DESC"""
        )]
        decided = [dict(r) for r in conn.execute(
            """SELECT q.*, d.rule_name, h.hostname FROM approvals_queue q
               JOIN detections d ON d.id=q.detection_id JOIN hosts h ON h.id=d.host_id
               WHERE q.status!='pending' ORDER BY q.decided_at_utc DESC LIMIT 20"""
        )]
        conn.close()
        return tpl.TemplateResponse(request, "containment.html", {
            "policies": policies, "pending": pending, "decided": decided, "page": "containment",
        })

    @target_app.get("/intel", response_class=HTMLResponse)
    def intel(request: Request, q: str = "", conn=Depends(database.connect)):
        iocs = [dict(r) for r in conn.execute(
            "SELECT * FROM ioc_store ORDER BY added_at_utc DESC LIMIT 50")]
        results = None
        if q:
            ql = q.lower().strip()
            results = {"query": q, "processes": [], "connections": [], "known": False}
            if len(ql) == 64:
                results["processes"] = [dict(r) for r in conn.execute(
                    """SELECT r.name, r.exe_path, r.sha256, h.hostname FROM raw_processes r
                       JOIN hosts h ON h.id=r.host_id WHERE r.sha256=? LIMIT 25""", (ql,))]
                results["known"] = bool(conn.execute(
                    "SELECT 1 FROM ioc_store WHERE value=?", (ql,)).fetchone())
            else:
                results["connections"] = [dict(r) for r in conn.execute(
                    """SELECT r.remote_ip, r.remote_port, r.process_name, h.hostname
                       FROM raw_connections r JOIN hosts h ON h.id=r.host_id
                       WHERE r.remote_ip LIKE ? OR CAST(r.remote_port AS TEXT)=?
                       LIMIT 25""", (f"%{q}%", q))]
        conn.close()
        return tpl.TemplateResponse(request, "intel.html", {
            "iocs": iocs, "results": results, "q": q, "page": "intel",
        })

    @target_app.get("/reports", response_class=HTMLResponse)
    def reports(request: Request, conn=Depends(database.connect)):
        hosts = [dict(r) for r in conn.execute(
            """SELECT h.id, h.hostname, h.os_type,
                      (SELECT COUNT(*) FROM detections d WHERE d.host_id=h.id) AS detection_count
               FROM hosts h ORDER BY h.id""")]
        navigator_exists = True
        conn.close()
        return tpl.TemplateResponse(request, "reports.html", {
            "hosts": hosts, "navigator_exists": navigator_exists, "page": "reports",
        })

    @target_app.post("/ui/endpoints/{host_id}/revoke")
    def ui_revoke(host_id: int, conn=Depends(database.connect)):
        conn.execute("UPDATE hosts SET is_active=0 WHERE id=?", (host_id,))
        database.audit(conn, "analyst-ui", "host_revoked", {"host_id": host_id})
        conn.commit()
        conn.close()
        return RedirectResponse("/endpoints", status_code=303)

    @target_app.post("/ui/policies")
    async def ui_add_policy(request: Request, conn=Depends(database.connect)):
        form = await request.form()
        from server.engine import evaluate_policies as _ep
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        techs = [t.strip().upper() for t in str(form.get("techniques") or "").split(",") if t.strip()]
        conn.execute(
            """INSERT INTO policies (name, min_severity, technique_ids, mode, action, enabled, created_at_utc)
               VALUES (?,?,?,?, 'isolate', 1, ?)
               ON CONFLICT(name) DO UPDATE SET min_severity=excluded.min_severity,
                   mode=excluded.mode""",
            (form.get("name"), form.get("min_severity", "high"),
             json.dumps(techs) if techs else None, form.get("mode", "notify"), now),
        )
        database.audit(conn, "analyst-ui", "policy_upserted", dict(form))
        conn.commit()
        conn.close()
        return RedirectResponse("/containment", status_code=303)

    @target_app.post("/ui/approvals/{approval_id}/decide")
    async def ui_decide(approval_id: int, request: Request, conn=Depends(database.connect)):
        form = await request.form()
        decision = form.get("decision")
        approval = conn.execute("SELECT * FROM approvals_queue WHERE id=?", (approval_id,)).fetchone()
        if approval and approval["status"] == "pending":
            det = conn.execute("SELECT * FROM detections WHERE id=?", (approval["detection_id"],)).fetchone()
            host = conn.execute("SELECT hostname FROM hosts WHERE id=?", (det["host_id"],)).fetchone() if det else None
            note = {
                "mode": "DRY-RUN (containment disabled by policy)",
                "would_execute": approval["action"],
                "target_host": host["hostname"] if host else None,
                "detection": det["rule_name"] if det else None,
            }
            conn.execute(
                "UPDATE approvals_queue SET status=?, decided_at_utc=?, decided_by=?, result_note=? WHERE id=?",
                ("executed_dryrun" if decision == "approved" else "rejected",
                 datetime.now(timezone.utc).isoformat(timespec="seconds"), "analyst-ui",
                 json.dumps(note), approval_id),
            )
            database.audit(conn, "analyst-ui", "containment_decision",
                           {"approval_id": approval_id, "decision": decision})
        conn.commit()
        conn.close()
        return RedirectResponse("/containment", status_code=303)

    @target_app.post("/ui/iocs")
    async def ui_add_ioc(request: Request, conn=Depends(database.connect)):
        form = await request.form()
        value = str(form.get("value") or "").strip()
        ioc_type = str(form.get("ioc_type") or "hash")
        if value:
            conn.execute(
                """INSERT INTO ioc_store (ioc_type, value, threat_source, description, added_at_utc)
                   VALUES (?,?,?,?,?)
                   ON CONFLICT(ioc_type, value) DO UPDATE SET threat_source=excluded.threat_source""",
                (ioc_type, value.lower() if ioc_type == "hash" else value, "analyst-watchlist",
                 form.get("description"), datetime.now(timezone.utc).isoformat(timespec="seconds")),
            )
            database.audit(conn, "analyst-ui", "ioc_added", {"ioc_type": ioc_type, "value": value[:64]})
        conn.commit()
        conn.close()
        return RedirectResponse("/intel", status_code=303)

    @target_app.get("/telemetry", response_class=HTMLResponse)
    def telemetry(request: Request, conn=Depends(database.connect)):
        """Resource telemetry dashboard: live gauges, trends, alerts."""
        hosts = [dict(r) for r in conn.execute(
            "SELECT id, hostname, os_type, docker_engine_flag FROM hosts WHERE is_active=1 ORDER BY hostname"
        )]
        conn.close()
        return tpl.TemplateResponse(request, "telemetry.html", {
            "hosts": hosts, "page": "telemetry",
        })
