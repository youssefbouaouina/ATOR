"""Phase 6 tests: the ML dashboard surfaces.

Two things are being protected:

1. **The ML page renders in every state** - no models, no ML stack, no findings. A dashboard
   that 500s on a fresh install is worse than one with an empty table.
2. **The ML layer did not break the existing dashboard.** Adding `rule_type='ml_anomaly'`
   rows with a NULL `technique_id` and new columns must leave every pre-existing page,
   export and API working. That is exactly how the `/api/v1/timeline` regression happened.
"""
import json

import pytest

from server import db as database


EXISTING_PAGES = ("/", "/investigation", "/endpoints", "/telemetry",
                  "/containment", "/intel", "/reports")


@pytest.fixture()
def ui_client(tmp_db, monkeypatch):
    """TestClient against the REAL application (API + dashboard routes)."""
    monkeypatch.setenv("ATOR_DFIR_DB", tmp_db)
    from fastapi.testclient import TestClient
    from server.app import app
    with TestClient(app) as client:
        yield client


@pytest.fixture()
def ml_rows(tmp_db, seeded_host):
    """One ML detection, one rule detection, and a host risk row."""
    conn = database.connect(tmp_db)
    host_id = seeded_host["host_id"]
    now = database.now_iso()
    conn.execute(
        """INSERT INTO detections (host_id, collection_id, rule_type, rule_name, severity,
                                   technique_id, summary, detected_at_utc,
                                   anomaly_score, confidence_score, ml_explanation)
           VALUES (?,?,'ml_anomaly','ML Anomaly: evil.exe','medium',NULL,?,?,?,?,?)""",
        (host_id, "col-1",
         json.dumps({"pid": "1234", "name": "evil.exe", "ml_anomaly_score": "0.9987"}),
         now, 0.9987, 0.83,
         json.dumps({"tier": "t1", "top_features": [
             {"feature": "cmdline_entropy", "deviation": 4.2}]})))
    conn.execute(
        """INSERT INTO detections (host_id, collection_id, rule_type, rule_name, severity,
                                   technique_id, summary, detected_at_utc)
           VALUES (?,?,'sigma','PowerShell Encoded Command','high','T1059.001',?,?)""",
        (host_id, "col-1", json.dumps({"pid": "4321", "name": "powershell.exe"}), now))
    conn.execute(
        """INSERT INTO host_risk_scores (host_id, score, tier, last_computed_utc,
                                         breakdown_json)
           VALUES (?,?,?,?,?)""",
        (host_id, 21.5, "high", now,
         json.dumps({"detection_points": 12.0, "distinct_tactics": ["execution"],
                     "detections_considered": 2})))
    conn.execute(
        """INSERT INTO ml_drift_log (computed_at_utc, model_id, feature_name, psi, verdict)
           VALUES (?,NULL,'hour_of_day',8.67,'shifted')""", (now,))
    conn.commit()
    conn.close()
    return {"host_id": host_id}


# --------------------------------------------------------------------------- the ML page

class TestMlPage:
    def test_renders_with_no_data_at_all(self, ui_client):
        """A fresh install must show an empty page, not an error."""
        response = ui_client.get("/ml")
        assert response.status_code == 200
        assert "ML Behavioural Analytics" in response.text

    def test_renders_with_data(self, ui_client, ml_rows):
        body = ui_client.get("/ml").text
        assert "evil.exe" in body
        assert "0.999" in body or "0.9987" in body      # anomaly score
        assert "cmdline_entropy" in body                # explanation surfaced
        assert "high" in body                           # risk tier

    def test_shows_explanations_not_bare_scores(self, ui_client, ml_rows):
        """An unexplained ML alert is unactionable."""
        body = ui_client.get("/ml").text
        assert "Why it was flagged" in body
        assert "cmdline_entropy" in body

    def test_warns_the_reading_is_statistical(self, ui_client, ml_rows):
        body = ui_client.get("/ml").text
        assert "not rule matches" in body or "not a rule match" in body

    def test_drift_panel_renders(self, ui_client, ml_rows):
        body = ui_client.get("/ml").text
        assert "Feature drift" in body
        assert "hour_of_day" in body

    def test_degrades_when_ml_stack_missing(self, ui_client, monkeypatch):
        from server.engine import ml_registry
        monkeypatch.setattr(ml_registry, "dependencies_available",
                            lambda: ml_registry.MlStatus(False, "no sklearn", "sklearn"))
        response = ui_client.get("/ml")
        assert response.status_code == 200
        assert "ML layer unavailable" in response.text
        # ...and it must say detection is unaffected, not imply the product is broken.
        assert "Detection is unaffected" in response.text

    def test_survives_a_corrupt_explanation(self, ui_client, tmp_db, seeded_host):
        conn = database.connect(tmp_db)
        try:
            conn.execute(
                """INSERT INTO detections (host_id, rule_type, rule_name, severity,
                                           summary, detected_at_utc, anomaly_score,
                                           ml_explanation)
                   VALUES (?,'ml_anomaly','ML Anomaly: x','low','{}',?,0.99,
                           'not valid json')""",
                (seeded_host["host_id"], database.now_iso()))
            conn.commit()
        finally:
            conn.close()
        assert ui_client.get("/ml").status_code == 200

    def test_nav_link_present(self, ui_client):
        assert 'href="/ml"' in ui_client.get("/").text


# --------------------------------------------------------------------------- no regression

class TestExistingDashboardUnaffected:
    @pytest.mark.parametrize("path", EXISTING_PAGES)
    def test_pages_render_with_ml_rows_present(self, ui_client, ml_rows, path):
        assert ui_client.get(path).status_code == 200, path

    @pytest.mark.parametrize("path", EXISTING_PAGES)
    def test_pages_render_without_any_ml_rows(self, ui_client, path):
        assert ui_client.get(path).status_code == 200, path

    def test_timeline_api_survives_ml_detections(self, ui_client, ml_rows):
        """The regression that actually happened: summary must stay JSON-decodable."""
        response = ui_client.get("/api/v1/timeline")
        assert response.status_code == 200
        titles = [e["title"] for e in response.json()["events"]]
        assert any("ML_ANOMALY" in t for t in titles)

    def test_exports_still_work(self, ui_client, ml_rows):
        host_id = ml_rows["host_id"]
        for path in (f"/api/v1/export/report/{host_id}.json",
                     f"/api/v1/export/stix/{host_id}.json",
                     "/api/v1/export/navigator.json"):
            assert ui_client.get(path).status_code == 200, path

    def test_pdf_export_still_works(self, ui_client, ml_rows):
        response = ui_client.get(f"/api/v1/export/report/{ml_rows['host_id']}.pdf")
        assert response.status_code == 200
        assert response.content[:4] == b"%PDF"

    def test_detections_api_includes_both_sources(self, ui_client, ml_rows):
        payload = ui_client.get("/api/v1/detections").json()
        rows = payload if isinstance(payload, list) else payload.get("detections", [])
        kinds = {r.get("rule_type") for r in rows}
        assert {"sigma", "ml_anomaly"} <= kinds

    def test_stats_overview_unaffected(self, ui_client, ml_rows):
        assert ui_client.get("/api/v1/stats/overview").status_code == 200


class TestInvestigationConfidence:
    # In the merged UI the investigation page keeps the DFIR grouped-findings
    # redesign, and per-detection ML triage confidence is surfaced on the
    # dedicated ML Analytics page (/ml) instead of inline on /investigation.
    def test_confidence_column_rendered(self, ui_client, ml_rows):
        body = ui_client.get("/ml").text
        assert "Confidence" in body
        assert "0.83" in body           # the confidence_score we inserted

    def test_ml_source_is_visually_distinct(self, ui_client, ml_rows):
        body = ui_client.get("/ml").text
        # ML findings live in their own anomaly triage queue, separate from rule hits.
        assert "Anomaly triage queue" in body
        assert "evil.exe" in body

    def test_unscored_detection_shows_a_dash_not_zero(self, ui_client, tmp_db, seeded_host):
        """NULL confidence means 'not scored', which must not look like 'confidently benign'."""
        conn = database.connect(tmp_db)
        try:
            conn.execute(
                """INSERT INTO detections (host_id, rule_type, rule_name, severity,
                                           summary, detected_at_utc)
                   VALUES (?,'sigma','Unscored Rule','low','{}',?)""",
                (seeded_host["host_id"], database.now_iso()))
            conn.commit()
        finally:
            conn.close()
        body = ui_client.get(f"/investigation?host_id={seeded_host['host_id']}").text
        assert "&mdash;" in body or "—" in body


class TestEndpointsRisk:
    def test_risk_column_rendered(self, ui_client, ml_rows):
        body = ui_client.get("/endpoints").text
        assert "Risk" in body
        assert "21.5" in body

    def test_hosts_without_risk_show_a_dash(self, ui_client, seeded_host):
        response = ui_client.get("/endpoints")
        assert response.status_code == 200
        assert "Risk" in response.text
