import json
import os
import socket
from datetime import datetime, timezone

from fastapi import Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from server import db as database
from server.engine import attack_mapper, soc_chain, timeline


def create_app():
    from server.api import app as api_app
    return api_app


#: Subnet(s) the enrolled endpoints live on. The generated enrollment command must carry
#: an address those endpoints can actually reach. Comma-separated CIDRs; override with
#: ATOR_ENROLL_SUBNET. The default is the project's lab network (VMware VMnet2).
DEFAULT_ENROLL_SUBNETS = "192.168.50.0/24"


def _default_route_ip():
    """The interface the OS would use to reach the internet (no packet is sent)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and not ip.startswith("127."):
            return ip
    except Exception:
        pass
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return "127.0.0.1"


def _local_ipv4_addresses():
    """Every IPv4 address bound on this machine, loopback excluded."""
    try:
        import psutil
        return [a.address for addrs in psutil.net_if_addrs().values() for a in addrs
                if a.family == socket.AF_INET and not a.address.startswith("127.")]
    except Exception:
        return []


def _enroll_subnets():
    import ipaddress
    out = []
    raw = os.environ.get("ATOR_ENROLL_SUBNET", DEFAULT_ENROLL_SUBNETS)
    for part in raw.split(","):
        try:
            out.append(ipaddress.ip_network(part.strip(), strict=False))
        except ValueError:
            continue
    return out


def detect_lan_ip():
    """The address of this server that enrolling endpoints can reach.

    Previously this returned the default-route interface. On a machine with several
    interfaces that is wrong for a lab network: this server has Wi-Fi (192.168.0.x)
    plus six VMware adapters, and the endpoints on 192.168.50.0/24 can only reach it
    at 192.168.50.1 - so every command generated while viewing the page via
    localhost pointed them at an address they could not reach.

    Order: an address of this machine inside ATOR_ENROLL_SUBNET, then the
    default-route interface, then loopback.
    """
    import ipaddress
    local = _local_ipv4_addresses()
    for subnet in _enroll_subnets():
        for ip in local:
            try:
                if ipaddress.ip_address(ip) in subnet:
                    return ip
            except ValueError:
                continue
    return _default_route_ip()


def enrollment_server_url(request):
    """Base URL to put in generated enrollment commands.

    1. ATOR_PUBLIC_URL, if set - explicit wins (NAT, reverse proxy, DNS name).
    2. The address the page was opened with, when it is not loopback: whoever is
       viewing it already reached the server there.
    3. Otherwise (page opened on the server itself via localhost) the server's
       address on the enrollment subnet - see detect_lan_ip().
    """
    explicit = os.environ.get("ATOR_PUBLIC_URL", "").strip().rstrip("/")
    if explicit:
        return explicit
    base = str(request.base_url).rstrip("/")
    host = request.url.hostname or ""
    if host not in ("localhost", "127.0.0.1", "::1", "[::1]") and not host.startswith("127."):
        return base
    port = request.url.port
    return f"{request.url.scheme}://{detect_lan_ip()}" + (f":{port}" if port else "")


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
        selected_host = next((h for h in hosts if h["id"] == selected), None)
        selected = selected_host["id"] if selected_host else 0
        tl = timeline.build(conn, selected or None, limit=200) if selected else {"events": [], "total": 0, "skew": []}
        soc = soc_chain.build(conn, selected) if selected else {"chain": []}
        tree = timeline.process_tree(conn, selected) if selected else {"nodes": [], "edges": [], "collection_id": None}
        detections = [dict(r) for r in conn.execute(
            """SELECT d.rule_type, d.rule_name, d.severity, d.technique_id,
                      COUNT(*) AS hits, MIN(d.detected_at_utc) AS first_seen,
                      MAX(d.detected_at_utc) AS last_seen,
                      MAX(e.technique_name) AS technique_name
               FROM detections d
               LEFT JOIN enriched_detections e ON e.detection_id=d.id
               WHERE d.host_id=?
               GROUP BY d.rule_type, d.rule_name, d.severity, d.technique_id
               ORDER BY CASE d.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                            WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
                        last_seen DESC, d.rule_type, d.rule_name, d.technique_id""", (selected,))]
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for detection in detections:
            counts[detection["severity"]] += detection["hits"]
        detection_total = sum(counts.values())
        conn.close()
        return tpl.TemplateResponse(request, "investigation.html", {
            "hosts": hosts, "selected": selected, "selected_host": selected_host,
            "timeline": tl, "soc": soc, "tree": tree, "detections": detections,
            "detection_total": detection_total, "counts": counts, "page": "investigation",
        })

    @target_app.get("/ml", response_class=HTMLResponse)
    def ml_analytics(request: Request, conn=Depends(database.connect)):
        """Layer 4.5 ML dashboard: models, triage queue, host risk, drift.

        Degrades rather than fails when the optional ML stack is absent - the template
        renders an explanatory banner and the rest of the dashboard is unaffected.
        """
        from server.engine import ml_registry, ml_triage
        from server.engine import ml_vocabulary as vocab

        try:
            ml = ml_registry.describe(conn)
        except Exception as exc:                     # noqa: BLE001
            ml = {"available": False, "reason": f"{type(exc).__name__}: {exc}", "models": []}

        # Leads are worked in threat-likelihood order (how much the process resembles known
        # attack activity), then by rarity. Unscored leads sort last rather than as zero.
        anomalies = []
        for row in conn.execute(
            """SELECT d.id, d.host_id, h.hostname, d.rule_name, d.severity, d.summary,
                      d.detected_at_utc, d.anomaly_score, d.confidence_score,
                      d.ml_explanation, d.suggested_tactics,
                      COALESCE(d.hit_count, 1) AS hit_count, d.last_seen_utc,
                      f.verdict AS analyst_verdict, f.recorded_at_utc AS verdict_at
               FROM detections d LEFT JOIN hosts h ON h.id = d.host_id
               LEFT JOIN ml_feedback f ON f.detection_id = d.id
               WHERE d.rule_type = 'ml_anomaly'
               ORDER BY d.confidence_score IS NULL, d.confidence_score DESC,
                        d.anomaly_score DESC, d.id DESC LIMIT 60"""):
            item = dict(row)
            for field in ("ml_explanation", "suggested_tactics", "summary"):
                try:
                    item[field] = json.loads(item[field]) if item[field] else {}
                except (json.JSONDecodeError, TypeError):
                    item[field] = {}
                if not isinstance(item[field], dict):
                    item[field] = {}
            item["confidence_band"] = ml_triage.confidence_band(item.get("confidence_score"))
            item["process"] = (item["summary"].get("name")
                               or (item.get("rule_name") or "").replace("ML Anomaly: ", ""))
            item["indicators"] = vocab.indicators(item["ml_explanation"])
            item["likelihood"] = vocab.likelihood(item.get("confidence_score"))
            item["rarity"] = vocab.rarity(item.get("anomaly_score"))
            item["priority"] = vocab.priority(item.get("confidence_score"),
                                              item.get("anomaly_score"))
            item["tactics"] = [
                vocab.tactic(t.get("tactic")) | {"pct": round(float(t.get("probability") or 0) * 100)}
                for t in (item["suggested_tactics"].get("suggestions") or []) if isinstance(t, dict)]
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
            item["tactic_names"] = [vocab.tactic(t)["name"]
                                    for t in item["breakdown"].get("distinct_tactics") or []]
            risk.append(item)

        entries = [dict(r) for r in conn.execute(
            """SELECT computed_at_utc, feature_name, psi, verdict FROM ml_drift_log
               ORDER BY computed_at_utc DESC, psi DESC LIMIT 20""")]
        for entry in entries:
            entry["label"] = vocab.feature_label(entry["feature_name"])
            entry["health"] = vocab.health(entry["verdict"])
        shifted = sum(1 for e in entries if e["verdict"] == "shifted")
        moderate = sum(1 for e in entries if e["verdict"] == "moderate")
        drift = {
            "entries": entries,
            "shifted_features": shifted,
            "retrain_recommended": shifted > 0,
            "overall": vocab.health("shifted" if shifted else "moderate" if moderate
                                    else "stable") if entries else None,
        }

        engines = vocab.engine_cards(ml)
        from server.engine import ml_ops
        ops = ml_ops.ops_view(conn, ml.get("models") or [])
        kpis = {
            "leads": len(anomalies),
            "high": sum(1 for a in anomalies if a["likelihood"] and a["likelihood"]["raw"] >= 0.5),
            "with_tactic": sum(1 for a in anomalies if a["tactics"]),
            "hosts_elevated": sum(1 for r in risk if r.get("tier") in ("high", "critical")),
            "hosts_scored": len(risk),
            "engines_online": sum(1 for e in engines if e["status"].startswith("Online")),
            "engines_total": len(engines),
        }
        conn.close()
        return tpl.TemplateResponse(request, "ml_analytics.html", {
            "ml": ml, "anomalies": anomalies, "risk": risk, "drift": drift, "page": "ml",
            "engines": engines, "kpis": kpis, "ops": ops,
        })

    @target_app.get("/endpoints", response_class=HTMLResponse)
    def endpoints(request: Request, conn=Depends(database.connect)):
        hosts = [dict(r) for r in conn.execute(
            """SELECT h.*,
                      h.agent_desired_state,
                      (SELECT COUNT(*) FROM detections d WHERE d.host_id=h.id) AS detection_count,
                      r.score AS risk_score, r.tier AS risk_tier,
                      (SELECT status FROM enrollment_requests er
                       WHERE er.hostname = h.hostname AND er.status IN ('pending','accepted','enrolled')
                       ORDER BY er.requested_at_utc DESC LIMIT 1) AS enrollment_status,
                      (SELECT enrollment_token FROM enrollment_requests er
                       WHERE er.hostname = h.hostname AND er.status = 'accepted'
                       ORDER BY er.requested_at_utc DESC LIMIT 1) AS enrollment_token
               FROM hosts h
               LEFT JOIN host_risk_scores r ON r.host_id = h.id
               ORDER BY COALESCE(r.score, -1) DESC, h.id"""
        )]
        from server.api import classify_agent_status
        for h in hosts:
            h["agent_status"] = classify_agent_status(h)
            h["agent_desired_state"] = h.get("agent_desired_state") or "running"
            if h["agent_desired_state"] == "paused" and h["agent_status"] == "running":
                h["agent_status"] = "paused"
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
        try:
            technique_choices = attack_mapper.load_techniques()
            techniques_by_tactic = attack_mapper.load_techniques_by_tactic()
            cti_available = bool(attack_mapper.load_index().get("available"))
        except Exception:
            technique_choices, techniques_by_tactic, cti_available = [], [], False
        conn.close()
        return tpl.TemplateResponse(request, "containment.html", {
            "policies": policies, "pending": pending, "decided": decided,
            "technique_choices": technique_choices, "techniques_by_tactic": techniques_by_tactic,
            "cti_available": cti_available, "page": "containment",
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
            # Domain IOCs / hostnames mentioned in process command lines or
            # observed remote domains - a domain watchlist hit pivot.
            results["domains"] = [dict(r) for r in conn.execute(
                """SELECT r.remote_domain, r.remote_ip, r.remote_port, r.process_name,
                          h.hostname
                   FROM raw_connections r JOIN hosts h ON h.id=r.host_id
                   WHERE r.remote_domain LIKE ? LIMIT 25""", (f"%{ql}%",))]
            if results["domains"]:
                results["known"] = results["known"] or bool(conn.execute(
                    "SELECT 1 FROM ioc_store WHERE ioc_type='domain' AND value=?",
                    (ql.rstrip("."),)).fetchone())
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

    @target_app.post("/ui/endpoints/{host_id}/agent-state")
    async def ui_agent_state(host_id: int, request: Request, conn=Depends(database.connect)):
        from server.api import _agent_state_changed
        form = await request.form()
        desired = "paused" if str(form.get("state")) == "paused" else "running"
        row = conn.execute("SELECT is_active FROM hosts WHERE id=?", (host_id,)).fetchone()
        if row and row["is_active"]:
            _agent_state_changed(conn, host_id, desired, "analyst-ui")
            conn.commit()
        conn.close()
        return RedirectResponse("/endpoints", status_code=303)

    @target_app.post("/ui/endpoints/{host_id}/collect")
    def ui_collect(host_id: int, conn=Depends(database.connect)):
        from server.api import _queue_command
        row = conn.execute(
            "SELECT hostname, is_active, COALESCE(agent_desired_state,'running') AS desired FROM hosts WHERE id=?",
            (host_id,),
        ).fetchone()
        if row and row["is_active"] and row["desired"] != "paused":
            _queue_command(conn, host_id, "collect_now")
            database.audit(conn, "analyst-ui", "collection_requested",
                           {"host_id": host_id, "hostname": row["hostname"]})
        conn.commit()
        conn.close()
        return RedirectResponse("/endpoints", status_code=303)

    @target_app.post("/ui/endpoints/{host_id}/scan")
    def ui_scan(host_id: int, conn=Depends(database.connect)):
        from server.engine import run_engine
        row = conn.execute("SELECT hostname, is_active FROM hosts WHERE id=?", (host_id,)).fetchone()
        if row and row["is_active"]:
            result = run_engine(conn, host_ids=[host_id])
            database.audit(conn, "analyst-ui", "host_scan_requested",
                           {"host_id": host_id, "hostname": row["hostname"],
                            "new_detections": result.get("total_new_detections")})
        conn.commit()
        conn.close()
        return RedirectResponse("/endpoints", status_code=303)

    @target_app.post("/ui/policies")
    async def ui_add_policy(request: Request, conn=Depends(database.connect)):
        form = await request.form()
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        techs = [t.strip().upper() for t in str(form.get("techniques") or "").split(",") if t.strip()]
        try:
            cooldown = max(0, int(form.get("cooldown_minutes") or 60))
        except (TypeError, ValueError):
            cooldown = 60
        enabled = 1 if str(form.get("enabled") or "1") not in ("0", "false", "off") else 0
        conn.execute(
            """INSERT INTO policies (name, min_severity, technique_ids, mode, action,
                                     cooldown_minutes, enabled, created_at_utc)
               VALUES (?,?,?,?,?,?,?,?)
               ON CONFLICT(name) DO UPDATE SET min_severity=excluded.min_severity,
                   mode=excluded.mode, action=excluded.action,
                   technique_ids=excluded.technique_ids,
                   cooldown_minutes=excluded.cooldown_minutes,
                   enabled=excluded.enabled""",
            (form.get("name"), form.get("min_severity", "high"),
             json.dumps(techs) if techs else None, form.get("mode", "notify"),
             form.get("action", "isolate"), cooldown, enabled, now),
        )
        database.audit(conn, "analyst-ui", "policy_upserted", dict(form))
        conn.commit()
        # Queue an engine scan over recent collections so the new/updated policy
        # is evaluated against existing telemetry immediately (API does the same
        # in POST /api/v1/policies).
        from server.engine import run_engine
        result = run_engine(conn, scan_history=True)
        database.audit(conn, "analyst-ui", "policy_scan_queued",
                       {"name": form.get("name"), "new_detections": result.get("total_new_detections"),
                        "approvals_created": result.get("approvals_created")})
        conn.commit()
        conn.close()
        return RedirectResponse("/containment", status_code=303)

    @target_app.post("/ui/policies/{policy_id}/toggle")
    def ui_toggle_policy(policy_id: int, conn=Depends(database.connect)):
        row = conn.execute("SELECT enabled, name FROM policies WHERE id=?", (policy_id,)).fetchone()
        if row:
            new_val = 0 if row["enabled"] else 1
            conn.execute("UPDATE policies SET enabled=? WHERE id=?", (new_val, policy_id))
            database.audit(conn, "analyst-ui", "policy_toggled",
                           {"policy_id": policy_id, "name": row["name"], "enabled": bool(new_val)})
        conn.commit()
        conn.close()
        return RedirectResponse("/containment", status_code=303)

    @target_app.post("/ui/policies/{policy_id}/delete")
    def ui_delete_policy(policy_id: int, conn=Depends(database.connect)):
        row = conn.execute("SELECT name FROM policies WHERE id=?", (policy_id,)).fetchone()
        if row:
            conn.execute("DELETE FROM policies WHERE id=?", (policy_id,))
            database.audit(conn, "analyst-ui", "policy_deleted",
                           {"policy_id": policy_id, "name": row["name"]})
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
        # A newly added domain IOC should be able to fire against network
        # telemetry already collected (hash/ip IOCs wait for the next
        # collection; domains can be matched immediately here).
        if value and ioc_type == "domain":
            try:
                from server.engine import correlate_domain_iocs, insert_detections
                from server.engine import attack_mapper as _am
                hits = correlate_domain_iocs(conn)
                if hits:
                    ids = insert_detections(conn, hits)
                    _am.enrich_detections(conn, detection_ids=ids)
            except Exception:
                pass  # correlation is best-effort; the IOC is stored regardless
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

    @target_app.get("/enroll", response_class=HTMLResponse)
    def enroll_page(request: Request):
        """Public enrollment request page."""
        return tpl.TemplateResponse(request, "enroll.html", {"page": "enroll"})

    @target_app.get("/enroll/status/{request_token}", response_class=HTMLResponse)
    def enroll_status(request: Request, request_token: str):
        """Enrollment request status page."""
        return tpl.TemplateResponse(request, "enroll_status.html", {
            "page": "enroll", "lan_ip": detect_lan_ip(),
            "server_url": enrollment_server_url(request),
        })

    @target_app.get("/enrollments", response_class=HTMLResponse)
    def enrollments(request: Request):
        """Admin page for managing enrollment requests.

        The table is populated client-side from /api/v1/enrollments (with
        status/platform/search/time filters and full CRUD), so the page shell
        renders instantly without a server-side query or LAN-IP probe.
        """
        return tpl.TemplateResponse(request, "enrollments.html", {"page": "enrollments"})
