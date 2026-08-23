import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

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
