"""Remove only data created by the Windows capability demo.

This intentionally does not use the general host purge utility. A real
endpoint may continue collecting telemetry while the demo is running, so the
scope is limited to the demo IOC, marker file, demo process IDs, loopback
port 4444, and collection batches containing those exact signals.
"""
import argparse
import json
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from server import db as database  # noqa: E402

RAW_TABLES = (
    "raw_processes",
    "raw_connections",
    "raw_persistence",
    "raw_logs",
    "raw_files",
    "raw_velociraptor",
)


def parse_args():
    parser = argparse.ArgumentParser(description="Purge Windows demo data only")
    parser.add_argument("--db", required=True)
    parser.add_argument("--hostname", required=True)
    parser.add_argument("--marker-name", required=True)
    parser.add_argument("--marker-sha", default="")
    parser.add_argument("--process-pid", action="append", type=int, default=[])
    parser.add_argument("--ioc-source", required=True)
    parser.add_argument("--port", type=int, default=4444)
    return parser.parse_args()


def main():
    args = parse_args()
    if not os.path.exists(args.db):
        print("database not found; nothing to purge")
        return 0

    conn = database.connect(args.db)
    try:
        database.ensure_schema(conn)
        host = conn.execute(
            "SELECT id FROM hosts WHERE hostname=?", (args.hostname,)
        ).fetchone()
        if not host:
            print(f"host {args.hostname!r} not found; IOC cleanup only")
            host_id = None
        else:
            host_id = host["id"]

        collection_ids = set()
        if host_id is not None:
            marks = ",".join("?" for _ in args.process_pid)
            if args.process_pid:
                rows = conn.execute(
                    f"""SELECT collection_id FROM raw_processes
                        WHERE host_id=? AND pid IN ({marks})
                          AND collection_id IS NOT NULL""",
                    (host_id, *args.process_pid),
                ).fetchall()
                collection_ids.update(row["collection_id"] for row in rows)

            rows = conn.execute(
                """SELECT collection_id FROM raw_connections
                   WHERE host_id=? AND remote_ip='127.0.0.1'
                     AND remote_port=? AND collection_id IS NOT NULL""",
                (host_id, args.port),
            ).fetchall()
            collection_ids.update(row["collection_id"] for row in rows)

            pattern = f"%{args.marker_name}%"
            rows = conn.execute(
                """SELECT collection_id FROM raw_files
                   WHERE host_id=? AND (path LIKE ? OR yara_matches LIKE ?)
                     AND collection_id IS NOT NULL""",
                (host_id, pattern, pattern),
            ).fetchall()
            collection_ids.update(row["collection_id"] for row in rows)

        deleted = {}
        ids = tuple(collection_ids)
        if host_id is not None:
            conditions = []
            params = [host_id]
            if ids:
                marks = ",".join("?" for _ in ids)
                conditions.append(f"collection_id IN ({marks})")
                params.extend(ids)
            conditions.append("evidence_json LIKE ?")
            params.append(f"%{args.marker_name}%")
            if args.marker_sha:
                conditions.append("evidence_json LIKE ?")
                params.append(f"%{args.marker_sha}%")
            detection_rows = conn.execute(
                f"""SELECT id FROM detections
                    WHERE host_id=? AND ({' OR '.join(conditions)})""",
                params,
            ).fetchall()
            detection_ids = tuple(row["id"] for row in detection_rows)
            if detection_ids:
                dmarks = ",".join("?" for _ in detection_ids)
                deleted["enriched_detections"] = conn.execute(
                    f"DELETE FROM enriched_detections WHERE detection_id IN ({dmarks})",
                    detection_ids,
                ).rowcount
                deleted["approvals_queue"] = conn.execute(
                    f"DELETE FROM approvals_queue WHERE detection_id IN ({dmarks})",
                    detection_ids,
                ).rowcount
                deleted["detections"] = conn.execute(
                    f"DELETE FROM detections WHERE id IN ({dmarks})",
                    detection_ids,
                ).rowcount

            if ids:
                marks = ",".join("?" for _ in ids)
                for table in RAW_TABLES:
                    deleted[table] = conn.execute(
                        f"DELETE FROM {table} WHERE host_id=? AND collection_id IN ({marks})",
                        (host_id, *ids),
                    ).rowcount
                deleted["evidence_manifests"] = conn.execute(
                    f"DELETE FROM evidence_manifests WHERE host_id=? AND collection_id IN ({marks})",
                    (host_id, *ids),
                ).rowcount

        if host_id is not None:
            if args.process_pid:
                marks = ",".join("?" for _ in args.process_pid)
                deleted["demo_process_rows"] = conn.execute(
                    f"DELETE FROM raw_processes WHERE host_id=? AND pid IN ({marks})",
                    (host_id, *args.process_pid),
                ).rowcount
            deleted["demo_connection_rows"] = conn.execute(
                """DELETE FROM raw_connections
                   WHERE host_id=? AND remote_ip='127.0.0.1' AND remote_port=?""",
                (host_id, args.port),
            ).rowcount
            marker_pattern = f"%{args.marker_name}%"
            deleted["demo_file_rows"] = conn.execute(
                """DELETE FROM raw_files
                   WHERE host_id=? AND (path LIKE ? OR yara_matches LIKE ?)""",
                (host_id, marker_pattern, marker_pattern),
            ).rowcount

        deleted["demo_iocs"] = conn.execute(
            "DELETE FROM ioc_store WHERE threat_source=?", (args.ioc_source,)
        ).rowcount
        if args.marker_sha:
            deleted["marker_iocs"] = conn.execute(
                "DELETE FROM ioc_store WHERE ioc_type='hash' AND value=?",
                (args.marker_sha,),
            ).rowcount

        conn.commit()
        print(json.dumps({
            "host": args.hostname,
            "collection_ids": sorted(collection_ids),
            "deleted": deleted,
        }, sort_keys=True))
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
