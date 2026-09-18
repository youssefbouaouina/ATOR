import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _enroll(client, hostname):
    resp = client.post("/api/v1/enroll", json={"hostname": hostname, "os_type": "windows"})
    return resp.json()


def _ingest_detection(client, enrolled, cid, rule="Test Rule", severity="high"):
    from datetime import datetime, timezone
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    manifest = {
        "collection_id": cid, "hostname": "stats-host", "os_type": "windows",
        "agent_version": "t", "started_at_utc": ts, "finished_at_utc": ts,
        "collector_order": [],
        "manifest_sha256": hashlib.sha256(cid.encode()).hexdigest(),
    }
    headers = {
        "Authorization": "Bearer " + enrolled["api_key"],
        "X-Client-ID": enrolled["client_id"],
    }
    artifacts = {"processes": [
                     {"pid": 7777, "ppid": 4, "name": "powershell.exe",
                      "cmdline": r"powershell.exe -nop -w hidden -enc SQBFAFgA",
                      "exe_path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"}],
                 "network": [], "persistence": [],
                 "files_triage": [], "logs": [
                     {"source": "system", "event_time_utc": ts,
                      "payload_json": {"message": f"simulated {rule}"}},
                 ], "containers": []}
    resp = client.post("/api/v1/ingest",
                       json={"manifest": manifest, "artifacts": artifacts},
                       headers=headers)
    assert resp.status_code == 202


def _ingest_detection_at(client, enrolled, cid, rule, severity, ts):
    manifest = {
        "collection_id": cid, "hostname": "stats-host", "os_type": "windows",
        "agent_version": "t", "started_at_utc": ts, "finished_at_utc": ts,
        "collector_order": [],
        "manifest_sha256": hashlib.sha256(cid.encode()).hexdigest(),
    }
    headers = {
        "Authorization": "Bearer " + enrolled["api_key"],
        "X-Client-ID": enrolled["client_id"],
    }
    artifacts = {"processes": [
                     {"pid": 7777, "ppid": 4, "name": "powershell.exe",
                      "cmdline": r"powershell.exe -nop -w hidden -enc SQBFAFgA",
                      "exe_path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"}],
                 "network": [], "persistence": [],
                 "files_triage": [], "logs": [
                     {"source": "system", "event_time_utc": ts,
                      "payload_json": {"message": f"simulated {rule}"}},
                 ], "containers": []}
    resp = client.post("/api/v1/ingest",
                       json={"manifest": manifest, "artifacts": artifacts},
                       headers=headers)
    assert resp.status_code == 202


def _run_inline_scripts(markup, setup, assertions):
    import re
    import shutil
    import pytest

    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is required for template JavaScript regression tests")
    scripts = re.findall(r"<script>(.*?)</script>", markup, re.S)
    result = subprocess.run(
        [node, "-"], input=setup + "\n" + "\n".join(scripts) + "\n" + assertions,
        text=True, capture_output=True, timeout=15,
    )
    assert result.returncode == 0, result.stderr


def test_enrollment_status_links(monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from server import ui
    from server.ui import register_ui

    monkeypatch.setattr(ui, "detect_lan_ip", lambda: "192.0.2.10")
    app = FastAPI()
    register_ui(app)
    client = TestClient(app)
    response = client.get('/enroll', params={"token": 'test? &"token'})
    assert response.status_code == 200
    assert 'href="/enroll/status/"' not in response.text
    _run_inline_scripts(response.text, """
const assert = require('node:assert/strict');
const handlers = {};
const window = {location: {href: ''}};
const document = {
  readyState: 'complete',
  getElementById: id => ({addEventListener: (event, fn) => {handlers[id] = fn;}})
};
const FormData = class {get() {return 'test? &"token';}};
""", """
handlers.statusForm({preventDefault() {}, target: {}});
assert.equal(window.location.href, '/enroll/status/test%3F%20%26%22token');
""")
    assert client.get('/enroll/status/test-token').status_code == 200


def test_enrollment_status_uses_path_token_and_server_origin(monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from server import ui

    monkeypatch.setattr(ui, "detect_lan_ip", lambda: "192.0.2.10")
    app = FastAPI()
    ui.register_ui(app)
    for origin, expected in [
        ("https://dfir.example:8443", "https://dfir.example:8443"),
        ("http://127.0.0.1:9000", "http://192.0.2.10:9000"),
        ("https://[2001:db8::1]:8443", "https://[2001:db8::1]:8443"),
    ]:
        client = TestClient(app, base_url=origin if "[" not in origin else "https://testserver:8443")
        response = client.get('/enroll/status/path-token?token=stale-query',
                              headers={"host": origin.split("://", 1)[1]})
        assert response.status_code == 200
        _run_inline_scripts(response.text, """
const assert = require('node:assert/strict');
const nodes = {};
const document = {getElementById: id => nodes[id] ||= {
  style: {}, classList: {remove() {}}, value: '', textContent: ''
}};
const window = {addEventListener() {}};
const sessionStorage = {getItem() {throw new Error('stale storage must not be used');}};
const setInterval = () => 1;
const clearInterval = () => {};
let fetched;
const fetch = async url => {
  fetched = url;
  return {ok: true, json: async () => ({status: 'accepted', enrollment_token: 'enroll-token'})};
};
""", """
setImmediate(() => {
  assert.equal(fetched, '/api/v1/enroll/status/path-token');
  assert.ok(nodes.enrollCommand.textContent.includes(EXPECTED + '/static/bootstrap_endpoint.ps1'));
  assert.ok(nodes.enrollCommand.textContent.includes("-ServerUrl '" + EXPECTED + "'"));
});
""".replace("EXPECTED", json.dumps(expected)))


@pytest.mark.parametrize("os_type,script,flag", [
    ("windows", "/static/bootstrap_endpoint.ps1", "-EnrollmentToken 'enroll-token'"),
    ("linux", "/static/bootstrap_endpoint.sh", "--token 'enroll-token'"),
    ("docker_host", "/static/bootstrap_endpoint.sh", "--token 'enroll-token'"),
])
def test_enrollment_status_command_matches_os(monkeypatch, os_type, script, flag):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from server import ui

    monkeypatch.setattr(ui, "detect_lan_ip", lambda: "192.0.2.10")
    app = FastAPI()
    ui.register_ui(app)
    response = TestClient(app, base_url="http://127.0.0.1:8000").get('/enroll/status/tok')
    assert response.status_code == 200
    _run_inline_scripts(response.text, """
const assert = require('node:assert/strict');
const nodes = {};
const document = {getElementById: id => nodes[id] ||= {
  style: {}, classList: {remove() {}}, value: '', textContent: ''
}};
const window = {addEventListener() {}};
const setInterval = () => 1;
const clearInterval = () => {};
const fetch = async () => ({ok: true, json: async () => (
  {status: 'accepted', os_type: OS_TYPE, enrollment_token: 'enroll-token'})});
""".replace("OS_TYPE", json.dumps(os_type)), """
setImmediate(() => {
  const cmd = nodes.enrollCommand.textContent;
  assert.ok(cmd.includes('http://192.0.2.10:8000' + SCRIPT), cmd);
  assert.ok(cmd.includes(FLAG), cmd);
  // No paths with backslashes: they get mangled between JS, cmd and PowerShell.
  assert.ok(!cmd.includes(String.fromCharCode(92)), cmd);
});
""".replace("SCRIPT", json.dumps(script)).replace("FLAG", json.dumps(flag)))


def test_generated_template_links_match_routes(seeded_host, monkeypatch):
    from html.parser import HTMLParser
    from pathlib import Path
    from urllib.parse import urlsplit
    from fastapi.testclient import TestClient
    from starlette.routing import Match
    from server.app import app
    from server import ui

    monkeypatch.setattr(ui, "detect_lan_ip", lambda: "192.0.2.10")
    targets = []

    class Links(HTMLParser):
        def handle_starttag(self, tag, attrs):
            attrs = dict(attrs)
            for attr in ("href", "src", "action", "data-api"):
                if attrs.get(attr, "").startswith("/"):
                    method = attrs.get("method", "GET").upper() if tag == "form" else "GET"
                    targets.append((urlsplit(attrs[attr]).path, method))

    client = TestClient(app)
    for page in ("/", "/investigation", "/endpoints", "/telemetry", "/containment",
                 "/intel", "/reports", "/enroll", "/enrollments", "/enroll/status/test-token"):
        response = client.get(page)
        assert response.status_code == 200, page
        Links().feed(response.text)
    # The reports page links the fleet ATT&CK Navigator export (per-host PDFs
    # are now generated + downloaded dynamically via the report-history API).
    assert ('/api/v1/export/navigator.json', "GET") in targets
    for path, method in targets:
        if path.startswith("/static/"):
            assert (Path(PROJECT_ROOT) / "server" / path.lstrip("/")).is_file(), path
        else:
            scope = {"type": "http", "path": path, "root_path": "", "method": method}
            assert any(route.matches(scope)[0] == Match.FULL for route in app.routes), (path, method)


def test_stats_overview_shape(client):
    enrolled = _enroll(client, "stats-host")
    _ingest_detection(client, enrolled, "stat-col-1")
    client.post("/api/v1/engine/run")
    resp = client.get("/api/v1/stats/overview")
    assert resp.status_code == 200
    body = resp.json()
    for key in ("counts", "total", "hosts_active", "manifests", "approvals_pending", "trend"):
        assert key in body, key
    assert len(body["trend"]) == 24
    assert all("hour" in p and "count" in p for p in body["trend"])
    assert isinstance(body["total"], int)


def test_sse_stream_emits_history():
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(db_fd)
    os.remove(db_path)
    env = dict(os.environ)
    env["ATOR_DFIR_DB"] = db_path
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    log_path = db_path + ".server.log"
    log_fh = open(log_path, "w", encoding="utf-8")
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "server.app:app",
         "--host", "127.0.0.1", "--port", str(port)],
        cwd=PROJECT_ROOT, env=env,
        stdout=log_fh, stderr=subprocess.STDOUT,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        deadline = time.time() + 30
        up = False
        while time.time() < deadline:
            try:
                urllib.request.urlopen(base + "/health", timeout=2).read()
                up = True
                break
            except Exception:
                time.sleep(0.4)
        assert up, "server did not start"

        req = urllib.request.Request(base + "/api/v1/enroll", method="POST",
                                     data=json.dumps({"hostname": "sse-host",
                                                      "os_type": "windows"}).encode(),
                                     headers={"Content-Type": "application/json"})
        enrollment = json.loads(urllib.request.urlopen(req, timeout=10).read())
        ts = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())
        manifest = {"collection_id": "sse-live-1", "hostname": "sse-host",
                    "os_type": "windows", "agent_version": "t",
                    "started_at_utc": ts, "finished_at_utc": ts,
                    "collector_order": [],
                    "manifest_sha256": hashlib.sha256(b"sse-live-1").hexdigest()}
        req = urllib.request.Request(
            base + "/api/v1/ingest", method="POST",
            data=json.dumps({"manifest": manifest,
                             "artifacts": {
                                 "processes": [
                                     {"pid": 7777, "ppid": 4, "name": "powershell.exe",
                                      "cmdline": r"powershell.exe -nop -w hidden -enc SQBFAFgA",
                                      "exe_path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"}],
                                 "network": [], "persistence": [],
                                 "files_triage": [], "logs": [], "containers": []}}).encode(),
            headers={"Content-Type": "application/json",
                     "Authorization": "Bearer " + enrollment["api_key"],
                     "X-Client-ID": enrollment["client_id"]})
        urllib.request.urlopen(req, timeout=15)

        deadline = time.time() + 15
        detections = []
        while time.time() < deadline:
            dets_resp = urllib.request.urlopen(base + "/api/v1/detections", timeout=10)
            detections = json.loads(dets_resp.read())
            if detections:
                break
            time.sleep(0.5)
        assert detections, "background engine produced no detections"
        stream_req = urllib.request.Request(base + "/api/v1/stream/events?interval=2")
        seen = b""
        with urllib.request.urlopen(stream_req, timeout=12) as resp:
            ctype = resp.headers.get("content-type", "")
            deadline = time.time() + 8
            while time.time() < deadline and b"rule_name" not in seen:
                chunk = resp.read1(4096)
                if not chunk:
                    break
                seen += chunk
        assert ctype.startswith("text/event-stream"), ctype
        assert b"rule_name" in seen
        assert b"manifest_sha256" not in seen.split(b"rule_name")[0][:200]
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
        log_fh.close()
        if os.environ.get("ATOR_DUMP_SERVER_LOG"):
            with open(log_path, encoding="utf-8", errors="replace") as fh:
                print("\n--- server log ---\n" + fh.read()[-4000:])
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(db_path + suffix)
            except OSError:
                pass
