"""Seed a realistic Velociraptor artifact sweep for demos, without an endpoint.

Why this exists
---------------
Running artifacts for real needs the Velociraptor binary on the endpoint AND an
elevated agent (the Windows binary's manifest refuses to launch otherwise). That
is the right production setup, but it is a poor thing to depend on five minutes
before a demo.

This script seeds the same evidence through the SAME code paths the live feature
uses, so what a demo shows is the real pipeline rather than a mock-up:

  * rows are shaped exactly like real Velociraptor output (nested Hash.SHA256,
    Raddr.IP, OSPath ...) and are put through the real agent-side normaliser,
    ``agent.collectors.velociraptor.normalise_row``
  * they are stored through the real server ingest helper,
    ``server.api._upsert_observation``, so dedupe/observation counting apply
  * a real ``evidence_manifests`` row is written, so the sweep is covered by the
    integrity annex like any other collection
  * detection is the real ``run_engine()`` - IOC correlation, provenance
    stamping and ATT&CK enrichment all happen for real

The ONLY thing skipped is the subprocess exec of velociraptor.exe.

The seeded data tells one coherent story on a Windows host: a masquerading
binary running from a world-writable directory, beaconing to a C2 address, held
on the box by a scheduled task and a WMI event consumer, with prefetch proving
it executed.

Everything it writes is tagged so it can be removed again:

    python scripts/demo_velociraptor.py --hostname tet
    python scripts/demo_velociraptor.py --hostname tet --purge
"""
import argparse
import hashlib
import json
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.collectors.velociraptor import normalise_row       # noqa: E402
from server import db as database                             # noqa: E402
from server.api import _upsert_observation                    # noqa: E402
from server.engine import run_engine                          # noqa: E402

# Tags that make every seeded artefact removable again.
DEMO_IOC_SOURCE = "demo-velociraptor"
DEMO_AGENT_VERSION = "1.0.0-demo-velociraptor"

# The implant's hash: what the watchlist knows and what the sweep finds.
IMPLANT_SHA256 = "3f7a1c9e52b84d06af1e9c3d5b7082e4c6a9d1f38b504e27ac6f9182d3e40b5c"
IMPLANT_PATH = r"C:\Users\Public\Libraries\svch0st.exe"
C2_IP = "185.220.101.47"
C2_PORT = 4444


def _iso(minutes_ago=0):
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat(
        timespec="seconds")


def artifact_rows():
    """Velociraptor-shaped rows, exactly as the real artifacts emit them.

    Column names and nesting are deliberately verbatim (``Hash.SHA256``,
    ``Raddr.IP``, ``OSPath``) - that is what exercises the normaliser's
    field-promotion rather than a convenient flat shape it would never see.
    """
    return {
        "Windows.System.Pslist": [
            {"Pid": 4, "Ppid": 0, "Name": "System", "Exe": "", "Username": "NT AUTHORITY\\SYSTEM",
             "CommandLine": "", "Hash": {"SHA256": ""}},
            {"Pid": 812, "Ppid": 640, "Name": "svchost.exe",
             "Exe": r"C:\Windows\System32\svchost.exe", "Username": "NT AUTHORITY\\SYSTEM",
             "CommandLine": r"C:\Windows\system32\svchost.exe -k netsvcs -p",
             "Hash": {"SHA256": "b4f1c2a7d9e08536ac4b1f7e2d3908c5b6a7f4e1d2c3b0a998877665544332211"}},
            {"Pid": 2284, "Ppid": 1120, "Name": "explorer.exe",
             "Exe": r"C:\Windows\explorer.exe", "Username": "TET\\SidikRoyale",
             "CommandLine": r"C:\Windows\Explorer.EXE",
             "Hash": {"SHA256": "a1b2c3d4e5f60718293a4b5c6d7e8f901122334455667788990011223344556677"[:64]}},
            # --- the finding
            {"Pid": 6612, "Ppid": 2284, "Name": "svch0st.exe", "Exe": IMPLANT_PATH,
             "Username": "TET\\SidikRoyale",
             "CommandLine": f'"{IMPLANT_PATH}" -conn {C2_IP}:{C2_PORT}',
             "Hash": {"SHA256": IMPLANT_SHA256}},
        ],
        "Windows.Network.Netstat": [
            {"Pid": 812, "Name": "svchost.exe", "Family": "IPv4", "Type": "TCP",
             "Laddr": {"IP": "0.0.0.0", "Port": 135}, "Raddr": {"IP": "", "Port": 0},
             "Status": "LISTEN"},
            # --- the beacon
            {"Pid": 6612, "Name": "svch0st.exe", "Family": "IPv4", "Type": "TCP",
             "Laddr": {"IP": "192.168.1.158", "Port": 51844},
             "Raddr": {"IP": C2_IP, "Port": C2_PORT}, "Status": "ESTABLISHED"},
        ],
        "Windows.System.TaskScheduler": [
            {"OSPath": r"C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Refresh",
             "Name": "Refresh", "Enabled": True,
             "Command": r"C:\Windows\System32\usoclient.exe", "Arguments": "StartScan"},
            # --- the persistence
            {"OSPath": r"C:\Windows\System32\Tasks\WindowsUpdateCheck",
             "Name": "WindowsUpdateCheck", "Enabled": True,
             "Command": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
             "Arguments": "-NoP -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"},
        ],
        "Windows.Persistence.PermanentWMIEvents": [
            # --- fileless persistence: the reason you run this artifact at all
            {"Name": "SystemPerfMonitor",
             "ConsumerDetails": {"Name": "SystemPerfMonitor", "__CLASS": "CommandLineEventConsumer",
                                 "CommandLineTemplate": IMPLANT_PATH},
             "FilterDetails": {"Name": "SystemPerfFilter",
                               "Query": "SELECT * FROM __InstanceModificationEvent WITHIN 60 "
                                        "WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"}},
        ],
        "Windows.Forensics.Prefetch": [
            {"OSPath": r"C:\Windows\Prefetch\SVCH0ST.EXE-A1B2C3D4.pf",
             "Executable": "SVCH0ST.EXE", "RunCount": 7, "FileSize": 28114,
             "LastRunTimes": [_iso(12), _iso(190), _iso(1450)]},
            {"OSPath": r"C:\Windows\Prefetch\POWERSHELL.EXE-9F8E7D6C.pf",
             "Executable": "POWERSHELL.EXE", "RunCount": 23, "FileSize": 41220,
             "LastRunTimes": [_iso(11), _iso(188)]},
        ],
    }


def resolve_host(conn, hostname, host_id):
    if host_id:
        row = conn.execute("SELECT id, hostname, os_type FROM hosts WHERE id=?",
                           (host_id,)).fetchone()
    else:
        row = conn.execute(
            "SELECT id, hostname, os_type FROM hosts WHERE hostname=? AND is_active=1"
            " ORDER BY id DESC LIMIT 1", (hostname,)).fetchone()
    if not row:
        sys.exit(f"no such host: {hostname or host_id}. Enrolled hosts:\n" + "\n".join(
            f"  id={r['id']} {r['hostname']} ({r['os_type']})"
            for r in conn.execute("SELECT id, hostname, os_type FROM hosts ORDER BY id")))
    return row


def seed(conn, host):
    now = _iso()
    collection_id = f"demo-velo-{uuid.uuid4()}"

    # The watchlist entry the sweep is going to collide with.
    conn.execute(
        """INSERT INTO ioc_store (ioc_type, value, threat_source, description, added_at_utc)
           VALUES (?,?,?,?,?)
           ON CONFLICT(ioc_type, value) DO UPDATE SET threat_source=excluded.threat_source""",
        ("hash", IMPLANT_SHA256, DEMO_IOC_SOURCE,
         "Demo implant hash - seeded by scripts/demo_velociraptor.py", now))
    conn.execute(
        """INSERT INTO ioc_store (ioc_type, value, threat_source, description, added_at_utc)
           VALUES (?,?,?,?,?)
           ON CONFLICT(ioc_type, value) DO UPDATE SET threat_source=excluded.threat_source""",
        ("ip", C2_IP, DEMO_IOC_SOURCE,
         "Demo C2 address - seeded by scripts/demo_velociraptor.py", now))

    inserted = deduped = 0
    per_artifact = {}
    for artifact, raw_rows in artifact_rows().items():
        for raw in raw_rows:
            row = normalise_row(artifact, raw)          # the real agent-side normaliser
            row_sha = hashlib.sha256(row["row_json"].encode("utf-8", "replace")).hexdigest()
            created = _upsert_observation(              # the real server-side ingest
                conn, "raw_velociraptor",
                ["host_id", "collection_id", "collected_at_utc", "artifact", "row_sha256",
                 "row_json", "path", "sha256", "remote_ip", "process_name", "pid"],
                [host["id"], collection_id, now, artifact, row_sha, row["row_json"],
                 row["path"], row["sha256"], row["remote_ip"], row["process_name"],
                 row["pid"]],
                ["host_id", "artifact", "row_sha256"], now, collection_id,
            )
            inserted += 1 if created else 0
            deduped += 0 if created else 1
        per_artifact[artifact] = len(raw_rows)

    manifest = {
        "collection_id": collection_id, "hostname": host["hostname"],
        "os_type": host["os_type"], "agent_version": DEMO_AGENT_VERSION,
        "started_at_utc": now, "finished_at_utc": now,
        "trigger": "velociraptor_collect",
        "requested_artifacts": sorted(per_artifact),
        "collector_order": ["velociraptor"],
        "artifacts": [{"collector": "velociraptor",
                       "count": sum(per_artifact.values()), "sha256": ""}],
    }
    manifest["manifest_sha256"] = hashlib.sha256(
        json.dumps(manifest, sort_keys=True, default=str).encode()).hexdigest()
    conn.execute(
        """INSERT INTO evidence_manifests (host_id, collection_id, started_at_utc,
               finished_at_utc, agent_version, collector_order, artifact_count,
               manifest_json, manifest_sha256, received_at_utc)
           VALUES (?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(collection_id) DO NOTHING""",
        (host["id"], collection_id, now, now, DEMO_AGENT_VERSION,
         json.dumps(["velociraptor"]), sum(per_artifact.values()),
         json.dumps(manifest), manifest["manifest_sha256"], now))

    # A sweep command row, so the Velociraptor page's "Recent sweeps" table has
    # the analyst-facing history a real request would have left behind.
    conn.execute(
        """INSERT INTO agent_commands (host_id, command, args, status, requested_by,
               created_at_utc, claimed_at_utc, finished_at_utc, result)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (host["id"], "velociraptor_collect",
         json.dumps({"artifacts": sorted(per_artifact)}), "done", DEMO_IOC_SOURCE,
         now, now, now,
         json.dumps({"action": "velociraptor_collect", "artifacts": sorted(per_artifact),
                     "rows": sum(per_artifact.values()), "delivery": "sent"})))
    conn.commit()
    return collection_id, per_artifact, inserted, deduped


def purge(conn, host):
    counts = {}
    counts["raw_velociraptor"] = conn.execute(
        "DELETE FROM raw_velociraptor WHERE host_id=? AND collection_id LIKE 'demo-velo-%'",
        (host["id"],)).rowcount
    counts["evidence_manifests"] = conn.execute(
        "DELETE FROM evidence_manifests WHERE host_id=? AND collection_id LIKE 'demo-velo-%'",
        (host["id"],)).rowcount
    counts["agent_commands"] = conn.execute(
        "DELETE FROM agent_commands WHERE host_id=? AND requested_by=?",
        (host["id"], DEMO_IOC_SOURCE)).rowcount
    detection_ids = [r["id"] for r in conn.execute(
        """SELECT id FROM detections WHERE host_id=?
           AND (collection_id LIKE 'demo-velo-%' OR summary LIKE ?)""",
        (host["id"], f"%{DEMO_IOC_SOURCE}%"))]
    if detection_ids:
        marks = ",".join("?" for _ in detection_ids)
        conn.execute(f"DELETE FROM approvals_queue WHERE detection_id IN ({marks})",
                     detection_ids)
        conn.execute(f"DELETE FROM enriched_detections WHERE detection_id IN ({marks})",
                     detection_ids)
        counts["detections"] = conn.execute(
            f"DELETE FROM detections WHERE id IN ({marks})", detection_ids).rowcount
    counts["ioc_store"] = conn.execute(
        "DELETE FROM ioc_store WHERE threat_source=?", (DEMO_IOC_SOURCE,)).rowcount
    conn.commit()
    return counts


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--hostname", help="target host by name (e.g. tet)")
    ap.add_argument("--host-id", type=int, help="target host by id")
    ap.add_argument("--db", help="database path (default: the configured one)")
    ap.add_argument("--purge", action="store_true", help="remove everything this script seeded")
    args = ap.parse_args()
    if not args.hostname and not args.host_id:
        ap.error("one of --hostname or --host-id is required")

    if args.db:
        database.DB_PATH = args.db
    database.init_db(args.db)
    conn = database.connect(args.db)
    try:
        host = resolve_host(conn, args.hostname, args.host_id)
        if args.purge:
            counts = purge(conn, host)
            print(f"purged demo Velociraptor data for {host['hostname']} (id {host['id']}):")
            for table, n in counts.items():
                print(f"  {table}: {n}")
            return 0

        collection_id, per_artifact, inserted, deduped = seed(conn, host)
        print(f"seeded a Velociraptor sweep for {host['hostname']} (id {host['id']})")
        print(f"  collection_id : {collection_id}")
        for artifact, n in sorted(per_artifact.items()):
            print(f"  {artifact:<46} {n} rows")
        print(f"  stored: {inserted} new, {deduped} deduped against earlier runs")

        print("\nrunning the real detection engine over it ...")
        result = run_engine(conn, host_ids=[host["id"]])
        print(f"  new detections : {result['total_new_detections']}")
        print(f"  enriched       : {result.get('enriched')}")

        hits = conn.execute(
            """SELECT rule_name, severity, technique_id, summary FROM detections
               WHERE host_id=? AND summary LIKE '%velociraptor%'
               ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                        WHEN 'medium' THEN 2 ELSE 3 END""",
            (host["id"],)).fetchall()
        if hits:
            print("\nfindings attributed to the sweep:")
            for h in hits:
                try:
                    ev = json.loads(h["summary"])
                except json.JSONDecodeError:
                    ev = {}
                print(f"  [{h['severity']:<8}] {h['rule_name']}")
                print(f"             artifact: {ev.get('velociraptor_artifact', '-')}"
                      f"  kind: {ev.get('kind', '-')}")
        else:
            print("\n(no detections - is the watchlist IOC present?)")

        print(f"\nView   : /velociraptor?host_id={host['id']}")
        print(f"Report : /api/v1/export/report/{host['id']}.pdf   (section 10)")
        print(f"Undo   : python scripts/demo_velociraptor.py --host-id {host['id']} --purge")
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
