from html.parser import HTMLParser
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from server import db as database
from server import ui


class Sections(HTMLParser):
    def __init__(self):
        super().__init__()
        self.sections = {}

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "details" and "data-investigation-section" in attrs:
            self.sections[attrs["id"]] = "open" in attrs


def page(host_id=None):
    app = FastAPI()
    ui.register_ui(app)
    return TestClient(app).get("/investigation", params={} if host_id is None else {"host_id": host_id})


def test_investigation_empty_database(tmp_db):
    response = page()
    assert response.status_code == 200
    assert "No endpoints available" in response.text
    assert "data-investigation-section" not in response.text


def test_investigation_empty_host_and_invalid_selection(seeded_host):
    response = page(seeded_host["host_id"])
    assert response.status_code == 200
    for text in ("No detections recorded", "No timeline events", "No process snapshot", "No mapped ATT&amp;CK tactics"):
        assert text in response.text
    invalid = page(999999)
    assert invalid.status_code == 200
    assert "Select a valid endpoint" in invalid.text
    assert "data-investigation-section" not in invalid.text


def test_investigation_grouped_findings_and_evidence(seeded_host):
    host_id = seeded_host["host_id"]
    name = "A complete finding name that is longer than forty characters <script>alert(1)</script>"
    first, last = "2020-01-01T01:02:03+00:00", "2020-01-02T04:05:06+00:00"
    conn = database.connect()
    try:
        for ts in (first, last):
            conn.execute(
                "INSERT INTO detections (host_id, rule_type, rule_name, severity, technique_id, detected_at_utc, summary) VALUES (?,?,?,?,?,?,?)",
                (host_id, "ioc", name, "high", "T0000", ts, '{"detail":"<script>evidence</script>"}'),
            )
        conn.execute(
            "INSERT INTO raw_processes (host_id, collection_id, collected_at_utc, pid, ppid, name, cmdline) VALUES (?,?,?,?,?,?,?)",
            (host_id, "snapshot-full-id", last, 10, 0, "test-process", "<script>command</script>"),
        )
        for i in range(5):
            conn.execute(
                "INSERT INTO raw_logs (host_id, collected_at_utc, event_time_utc, source, event_id, payload_json) VALUES (?,?,?,?,?,?)",
                (host_id, first, first, "test", 1000 + i, '{"message":"old event"}'),
            )
        conn.commit()
    finally:
        conn.close()
    response = page(host_id)
    assert response.status_code == 200
    html = response.text
    sections = Sections()
    sections.feed(html)
    assert sections.sections == {
        "investigation-findings": True, "investigation-attack": False,
        "investigation-timeline": False, "investigation-processes": False,
    }
    for text in ("2</strong>", "1 grouped findings", first, last,
                 "longer than forty characters &lt;script&gt;", "snapshot-full-id",
                 "&lt;script&gt;command&lt;/script&gt;", "Findings without tactic placement (2)",
                 "No recent events available for a reliable time baseline.", "Showing 7 of 7"):
        assert text in html
    assert "<script>alert(1)</script>" not in html
    assert 'class="mono text-truncate"' not in html


def test_investigation_mapped_tactic(seeded_host):
    conn = database.connect()
    try:
        det = conn.execute(
            "INSERT INTO detections (host_id, rule_type, rule_name, severity, technique_id, detected_at_utc) VALUES (?,?,?,?,?,?)",
            (seeded_host["host_id"], "sigma", "Example finding", "medium", "T1059", "2026-01-01T00:00:00Z"),
        )
        conn.execute(
            "INSERT INTO enriched_detections (detection_id, technique_name, tactic) VALUES (?,?,?)",
            (det.lastrowid, "Command interpreter", '[{"short":"execution"}]'),
        )
        conn.commit()
    finally:
        conn.close()
    response = page(seeded_host["host_id"])
    assert response.status_code == 200
    assert "Execution" in response.text
    assert "Command interpreter" in response.text
    assert "not a proven chronological attack path" in response.text


def test_investigation_javascript():
    import shutil
    import subprocess
    import pytest

    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is required for JavaScript regression tests")
    script = Path(__file__).with_name("investigation_ui_check.js")
    result = subprocess.run([node, str(script)], capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
