"""Token enrollment flow shared by Windows and Linux endpoints."""
import io
import json
import tarfile
import zipfile

import pytest


def _request_and_accept(client, hostname, os_type):
    created = client.post("/api/v1/enroll/request", json={"hostname": hostname, "os_type": os_type})
    assert created.status_code == 200, created.text
    body = created.json()
    accepted = client.post(f"/api/v1/enrollments/{body['request_token']}/accept",
                           json={"action": "accept", "analyst": "tester"})
    assert accepted.status_code == 200, accepted.text
    return body


@pytest.mark.parametrize("os_type", ["windows", "linux", "docker_host"])
def test_token_enrollment_lifecycle(client, os_type):
    body = _request_and_accept(client, f"host-{os_type}", os_type)
    token = body["enrollment_token"]

    enrolled = client.post("/api/v1/enroll/enroll", json={"enrollment_token": token, "agent_version": "1.0.0"})
    assert enrolled.status_code == 200, enrolled.text
    creds = enrolled.json()

    host = next(h for h in client.get("/api/v1/hosts").json() if h["id"] == creds["host_id"])
    assert host["os_type"] == os_type
    assert host["agent_version"] == "1.0.0"
    status = client.get(f"/api/v1/enroll/status/{body['request_token']}").json()
    assert status["status"] == "enrolled"

    # Issued credentials authenticate the agent control channel.
    hb = client.post("/api/v1/agent/heartbeat", json={"state": "running"},
                     headers={"Authorization": "Bearer " + creds["api_key"], "X-Client-ID": creds["client_id"]})
    assert hb.status_code == 200, hb.text

    # A consumed token is reported as 409 so bootstrap re-runs are recognisable.
    again = client.post("/api/v1/enroll/enroll", json={"enrollment_token": token})
    assert again.status_code == 409


def test_token_rejected_until_accepted(client):
    created = client.post("/api/v1/enroll/request", json={"hostname": "pending-host", "os_type": "linux"}).json()
    resp = client.post("/api/v1/enroll/enroll", json={"enrollment_token": created["enrollment_token"]})
    assert resp.status_code == 403
    assert client.post("/api/v1/enroll/enroll", json={"enrollment_token": "nope"}).status_code == 404


def test_agent_packages_are_built_from_source(client):
    zresp = client.get("/static/ator-agent-deploy.zip")
    assert zresp.status_code == 200
    names = zipfile.ZipFile(io.BytesIO(zresp.content)).namelist()
    assert "agent/agent.py" in names and "agent/collectors/processes.py" in names
    assert "agent/requirements.txt" in names
    # Never ship this machine's credentials or bytecode.
    assert not any(n.endswith("config.json") or "__pycache__" in n for n in names)

    tresp = client.get("/static/ator-agent-deploy.tar.gz")
    assert tresp.status_code == 200
    with tarfile.open(fileobj=io.BytesIO(tresp.content), mode="r:gz") as tf:
        members = {m.name: m for m in tf.getmembers()}
        assert set(names) <= set(members)
        agent_py = tf.extractfile(members["agent/agent.py"]).read()
    assert b"\r\n" not in agent_py
    with open("agent/agent.py", "rb") as fh:
        assert agent_py == fh.read().replace(b"\r\n", b"\n")


def test_bootstrap_scripts_served(client):
    ps1 = client.get("/static/bootstrap_endpoint.ps1")
    assert ps1.status_code == 200 and "EnrollmentToken" in ps1.text
    sh = client.get("/static/bootstrap_endpoint.sh")
    assert sh.status_code == 200
    assert sh.text.startswith("#!/usr/bin/env bash") and "\r\n" not in sh.text
    assert "agent.agent enroll --token" in sh.text


def test_agent_reads_config_with_bom(tmp_path, monkeypatch):
    from agent import agent as ag
    monkeypatch.delenv("ATOR_SERVER_URL", raising=False)
    path = tmp_path / "config.json"
    # Windows PowerShell writes UTF-8 with a BOM.
    path.write_bytes(b"\xef\xbb\xbf" + json.dumps({"server_url": "http://srv:8000"}).encode())
    assert ag.load_config(str(path))["server_url"] == "http://srv:8000"


def test_agent_token_enroll_rerun_is_idempotent(tmp_path, monkeypatch, capsys):
    from agent import agent as ag

    class Resp:
        status_code = 409

        def json(self):
            return {"detail": "This enrollment token has already been used"}

    config = tmp_path / "config.json"
    config.write_text(json.dumps({"server_url": "http://srv:8000", "api_key": "k", "client_id": "c"}))
    monkeypatch.setattr(ag, "CONFIG_PATH", str(config))
    monkeypatch.delenv("ATOR_SERVER_URL", raising=False)
    monkeypatch.setattr("requests.post", lambda *a, **k: Resp())

    # Saved credentials still valid -> success; otherwise a clear failure.
    monkeypatch.setattr(ag, "heartbeat", lambda cfg, state=None: {"desired_state": "running"})
    monkeypatch.setattr("sys.argv", ["agent", "enroll", "--token", "t"])
    assert ag.main() == 0
    assert "already_enrolled" in capsys.readouterr().out

    def dead(cfg, state=None):
        raise RuntimeError("403")
    monkeypatch.setattr(ag, "heartbeat", dead)
    assert ag.main() == 2
    assert "already been used" in capsys.readouterr().err
