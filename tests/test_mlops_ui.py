"""Phase 10: analyst verdicts on ML leads, and the Model operations panel.

The verdict API is an input to automated retraining, so its validation matters as much as its
happy path: a verdict on a non-ML detection, or on nothing, must be refused.
"""
import json

import pytest

from server import db as database
from server.engine import ml_ops


def _detection(db, host, rule_type="ml_anomaly", confidence=None):
    conn = database.connect(db)
    det = conn.execute(
        """INSERT INTO detections (host_id, rule_type, rule_name, severity, summary,
                                    detected_at_utc, anomaly_score, confidence_score)
           VALUES (?, ?, 'ML Anomaly: tool.exe', 'medium', ?, ?, 0.995, ?)""",
        (host, rule_type, json.dumps({"pid": "42", "name": "tool.exe"}), database.now_iso(),
         confidence)).lastrowid
    conn.commit()
    conn.close()
    return det


def _verdict(db, det):
    conn = database.connect(db)
    row = conn.execute("SELECT verdict FROM ml_feedback WHERE detection_id=?", (det,)).fetchone()
    conn.close()
    return row[0] if row else None


class TestFeedbackApi:
    def test_confirm_dismiss_and_clear(self, client, tmp_db, seeded_host):
        det = _detection(tmp_db, seeded_host["host_id"])
        for verdict, stored in (("confirmed", "confirmed"), ("benign", "benign"), ("clear", None)):
            r = client.post("/api/v1/ml/feedback", json={"detection_id": det, "verdict": verdict})
            assert r.status_code == 200, r.text
            assert _verdict(tmp_db, det) == stored

    def test_is_audited(self, client, tmp_db, seeded_host):
        det = _detection(tmp_db, seeded_host["host_id"])
        client.post("/api/v1/ml/feedback", json={"detection_id": det, "verdict": "benign"})
        conn = database.connect(tmp_db)
        actions = [r[0] for r in conn.execute("SELECT action FROM audit_log")]
        conn.close()
        assert "ml_feedback" in actions

    def test_rule_detections_cannot_be_dismissed_here(self, client, tmp_db, seeded_host):
        """A Sigma/YARA/IOC hit must never be laundered into the benign baseline."""
        det = _detection(tmp_db, seeded_host["host_id"], rule_type="sigma")
        r = client.post("/api/v1/ml/feedback", json={"detection_id": det, "verdict": "benign"})
        assert r.status_code == 400
        assert _verdict(tmp_db, det) is None

    @pytest.mark.parametrize("body", [{"detection_id": 999999, "verdict": "benign"},
                                      {"detection_id": 1, "verdict": "maybe"}])
    def test_invalid_requests_are_refused(self, client, body):
        assert client.post("/api/v1/ml/feedback", json=body).status_code in (404, 422)


class TestOpsView:
    def test_fresh_install_says_not_run_yet(self, tmp_db, tmp_path, monkeypatch):
        monkeypatch.setenv("ATOR_MLOPS_HOME", str(tmp_path))
        conn = database.connect(tmp_db)
        view = ml_ops.ops_view(conn, [])
        conn.close()
        assert view["available"] and view["state"]["label"] == "Not run yet"

    def test_running_trial_shows_progress(self, tmp_db, tmp_path, monkeypatch):
        monkeypatch.setenv("ATOR_MLOPS_HOME", str(tmp_path))
        conn = database.connect(tmp_db)
        conn.execute("""INSERT INTO ml_pipeline_runs (run_id, started_at_utc, status, summary_json)
                        VALUES ('r1', ?, 'succeeded', '{}')""", (database.now_iso(),))
        tid = conn.execute("""INSERT INTO ml_shadow_trials (version_id, components_json,
                                  started_at_utc, status) VALUES ('v1', '["anomaly"]', 't',
                                  'running')""").lastrowid
        conn.execute("""INSERT INTO ml_shadow_observations (trial_id, hour_utc, passes,
                            processes_scored) VALUES (?, 'h1', 3, 100)""", (tid,))
        conn.commit()
        view = ml_ops.ops_view(conn, [])
        conn.close()
        assert view["state"]["label"] == "Update on trial"
        trial = view["trials"][0]
        assert trial["engine"] == "Behavioural anomaly engine"
        assert trial["progress_pct"] == 4                 # 1 of 24 hours is the binding limit

    def test_failed_run_and_pause_are_surfaced(self, tmp_db, tmp_path, monkeypatch):
        monkeypatch.setenv("ATOR_MLOPS_HOME", str(tmp_path))
        conn = database.connect(tmp_db)
        conn.execute("""INSERT INTO ml_pipeline_runs (run_id, started_at_utc, status, summary_json)
                        VALUES ('r1', ?, 'failed', '{}')""", (database.now_iso(),))
        conn.commit()
        assert ml_ops.ops_view(conn, [])["state"]["label"] == "Needs attention"
        (tmp_path / "PAUSED").write_text("x")
        assert ml_ops.ops_view(conn, [])["state"]["label"] == "Paused"
        conn.close()

    def test_a_run_in_progress_is_shown_as_such(self, tmp_db, tmp_path, monkeypatch):
        monkeypatch.setenv("ATOR_MLOPS_HOME", str(tmp_path))
        conn = database.connect(tmp_db)
        conn.execute("""INSERT INTO ml_pipeline_runs (run_id, started_at_utc, status)
                        VALUES ('r0', '2026-09-20T03:00:00+00:00', 'succeeded')""")
        conn.execute("""INSERT INTO ml_pipeline_runs (run_id, started_at_utc, status)
                        VALUES ('r1', ?, 'running')""", (database.now_iso(),))
        conn.commit()
        view = ml_ops.ops_view(conn, [])
        conn.close()
        assert view["state"]["label"] == "Updating now"
        assert view["next_due_utc"] is None

    def test_never_raises(self):
        class Broken:
            def execute(self, *a):
                raise RuntimeError("db gone")
        assert ml_ops.ops_view(Broken(), [])["available"] is False


class TestPage:
    @pytest.fixture()
    def client(self, tmp_db, tmp_path, monkeypatch):
        """The full application (API + dashboard), not the API-only conftest client."""
        monkeypatch.setenv("ATOR_MLOPS_HOME", str(tmp_path / "mlops"))
        monkeypatch.setenv("ATOR_DFIR_DB", tmp_db)
        from fastapi.testclient import TestClient
        from server.app import app
        with TestClient(app) as tc:
            yield tc

    def test_threat_hunting_page_shows_updates_and_verdicts(self, client, tmp_db, seeded_host):
        det = _detection(tmp_db, seeded_host["host_id"], confidence=0.2)
        client.post("/api/v1/ml/feedback", json={"detection_id": det, "verdict": "confirmed"})
        html = client.get("/ml").text
        assert "Detection model updates" in html
        assert "Confirmed threat" in html and "Benign &middot; false positive" in html
        assert 'verdict-tag verdict-confirmed' in html
        # analyst vocabulary, not data-science vocabulary, in the new panel
        panel = html[html.index('id="modelOps"'):html.index("Data health")]
        for jargon in ("PR-AUC", "PSI", "challenger", "champion", "ECE"):
            assert jargon not in panel

    def test_ops_api(self, client):
        body = client.get("/api/v1/ml/ops").json()
        assert body["available"] is True
        assert body["state"]["label"] == "Not run yet"
