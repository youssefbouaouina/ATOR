"""Purge collected artifacts and demo data from the ATOR DFIR database.

Deletes host-scoped evidence (raw_* tables, detections, manifests, telemetry),
can remove orphaned rows whose host no longer exists, and can clear generated
reports and demo watchlist IOCs.

Dry-run by default: nothing is deleted until --apply is passed. VACUUM only runs
with --apply (it rewrites the whole file and needs exclusive access).

Examples:
    python scripts/purge_host_data.py --hostname tet            # dry run
    python scripts/purge_host_data.py --hostname tet --apply
    python scripts/purge_host_data.py --orphans --reports --iocs --apply
    python scripts/purge_host_data.py --host-id 2 --apply --vacuum
"""
import argparse
import glob
import os
import shutil
import sys
from datetime import datetime, timezone

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from server import db as database  # noqa: E402

# Tables keyed directly by host_id (ordering matters: children before detections).
HOST_SCOPED_TABLES = (
    "raw_connections",
    "raw_files",
    "raw_logs",
    "raw_persistence",
    "raw_processes",
    "raw_velociraptor",
    "containers",
    "resource_alerts",
    "resource_samples",
    "agent_self_samples",
    "detections",
    "evidence_manifests",
)

# Tables referencing detections (must be cleared before detections are removed).
DETECTION_CHILD_TABLES = ("enriched_detections", "approvals_queue")

REPORT_DIR = os.path.join(PROJECT_ROOT, "reports_out")
SAMPLE_DIR = os.path.join(PROJECT_ROOT, "samples")

DETECTION_CHILD_SCOPE = "detection_id IN (SELECT id FROM detections WHERE {where})"


def _count(conn, sql, params=()):
    return conn.execute(sql, params).fetchone()[0]


def _scopes(host_ids, include_orphans):
    """Yield (where_clause, params) selectors for detection-child deletions."""
    if host_ids:
        marks = ",".join("?" for _ in host_ids)
        yield f"host_id IN ({marks})", tuple(host_ids)
    if include_orphans:
        yield "host_id NOT IN (SELECT id FROM hosts)", ()


def describe(conn, host_ids, include_orphans):
    """Return [(table, rows_to_delete)] for the requested scope."""
    plan = []
    for table in DETECTION_CHILD_TABLES:
        total = 0
        for where, params in _scopes(host_ids, include_orphans):
            total += _count(conn, f"SELECT COUNT(*) FROM {table} WHERE "
                                  + DETECTION_CHILD_SCOPE.format(where=where), params)
        if total:
            plan.append((table, total))
    for table in HOST_SCOPED_TABLES:
        total = 0
        if host_ids:
            marks = ",".join("?" for _ in host_ids)
            total += _count(conn, f"SELECT COUNT(*) FROM {table} WHERE host_id IN ({marks})", tuple(host_ids))
        if include_orphans:
            total += _count(conn, f"SELECT COUNT(*) FROM {table} WHERE host_id NOT IN (SELECT id FROM hosts)")
        if total:
            plan.append((table, total))
    return plan


def purge(conn, host_ids, include_orphans, delete_hosts):
    """Delete in FK-safe order and return {table: rows_deleted}."""
    deleted = {}
    for table in DETECTION_CHILD_TABLES:
        n = 0
        for where, params in _scopes(host_ids, include_orphans):
            n += conn.execute(
                f"DELETE FROM {table} WHERE " + DETECTION_CHILD_SCOPE.format(where=where), params
            ).rowcount
        deleted[table] = n

    for table in HOST_SCOPED_TABLES:
        n = 0
        if host_ids:
            marks = ",".join("?" for _ in host_ids)
            n += conn.execute(f"DELETE FROM {table} WHERE host_id IN ({marks})", tuple(host_ids)).rowcount
        if include_orphans:
            n += conn.execute(
                f"DELETE FROM {table} WHERE host_id NOT IN (SELECT id FROM hosts)"
            ).rowcount
        deleted[table] = n

    if delete_hosts and host_ids:
        marks = ",".join("?" for _ in host_ids)
        deleted["hosts"] = conn.execute(f"DELETE FROM hosts WHERE id IN ({marks})", tuple(host_ids)).rowcount
    conn.commit()
    return deleted


def remove_paths(label, pattern):
    removed = 0
    for path in glob.glob(pattern):
        try:
            if os.path.isdir(path):
                shutil.rmtree(path)
            else:
                os.remove(path)
            removed += 1
        except OSError:
            continue
    if removed:
        print(f"  {label}: removed {removed} path(s)")
    return removed


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Purge ATOR DFIR collected data")
    parser.add_argument("--db", default=database.DB_PATH)
    parser.add_argument("--host-id", type=int, action="append", default=None,
                        help="host id to purge (repeatable)")
    parser.add_argument("--hostname", action="append", default=None,
                        help="hostname to purge (repeatable)")
    parser.add_argument("--orphans", action="store_true",
                        help="also delete rows whose host_id no longer exists")
    parser.add_argument("--delete-host", action="store_true",
                        help="also delete the hosts row (endpoint stays enrolled by default)")
    parser.add_argument("--reports", action="store_true", help="delete generated reports/samples")
    parser.add_argument("--iocs", action="store_true", help="delete demo watchlist IOCs")
    parser.add_argument("--apply", action="store_true", help="perform deletion (default: dry run)")
    parser.add_argument("--vacuum", action="store_true",
                        help="VACUUM after purge to reclaim disk space (slow)")
    return parser.parse_args(argv)


def resolve_host_ids(conn, args):
    host_ids = list(args.host_id or [])
    for name in args.hostname or []:
        rows = conn.execute("SELECT id FROM hosts WHERE hostname=?", (name,)).fetchall()
        if not rows:
            print(f"ERROR: no host named {name!r} in {args.db}", file=sys.stderr)
            return None
        host_ids += [r["id"] for r in rows]
    return host_ids


def print_scope(conn, host_ids, args):
    labels = []
    for hid in host_ids:
        row = conn.execute("SELECT hostname FROM hosts WHERE id=?", (hid,)).fetchone()
        labels.append(f"{hid} ({row['hostname']})" if row else f"{hid} (missing)")
    if labels:
        print(f"host scope : {', '.join(labels)}")
    if args.orphans:
        orphans = [r[0] for r in conn.execute(
            "SELECT DISTINCT host_id FROM raw_logs WHERE host_id NOT IN (SELECT id FROM hosts)")]
        print(f"orphans    : host_id(s) {orphans or 'none'}")


def main(argv=None):
    args = parse_args(argv)
    if not os.path.exists(args.db):
        print(f"ERROR: database not found: {args.db}", file=sys.stderr)
        return 1

    conn = database.connect(args.db)
    try:
        # Make sure the schema is current (tables/columns) before counting.
        database.ensure_schema(conn)
        host_ids = resolve_host_ids(conn, args)
        if host_ids is None:
            return 1
        if not (host_ids or args.orphans or args.reports or args.iocs):
            print("Nothing selected. Use --host-id/--hostname/--orphans/--reports/--iocs.")
            return 1

        print_scope(conn, host_ids, args)
        plan = describe(conn, host_ids, args.orphans)
        print("\nrows selected for deletion:")
        if plan:
            for table, n in plan:
                print(f"  {table:<24} {n:>10,}")
            print(f"  {'TOTAL':<24} {sum(n for _, n in plan):>10,}")
        else:
            print("  (none)")
        print(f"\nmode       : {'APPLY (destructive)' if args.apply else 'dry run (no changes)'}")

        if not args.apply:
            print("\nRe-run with --apply to delete. Back up first: python scripts/backup_db.py")
            return 0

        deleted = purge(conn, host_ids, args.orphans, args.delete_host)
        print("\ndeleted rows:")
        for table, n in deleted.items():
            if n:
                print(f"  {table:<24} {n:>10,}")

        if args.iocs:
            n = conn.execute("DELETE FROM ioc_store WHERE threat_source LIKE 'ator-demo%'").rowcount
            conn.commit()
            print(f"  {'ioc_store (ator-demo)':<24} {n:>10,}")

        database.audit(conn, "maintenance", "data_purged", {
            "host_ids": host_ids, "orphans": args.orphans, "reports": args.reports,
            "iocs": args.iocs, "deleted": deleted,
        })
        conn.commit()

        # Rebuilding the natural-key indexes now succeeds (the duplicates are
        # gone), which re-activates ingest dedupe for future collections.
        created, skipped = database.ensure_dedupe_indexes(conn)
        print("\ndedupe indexes:")
        print(f"  active : {', '.join(created) if created else 'none'}")
        if skipped:
            print(f"  skipped: {', '.join(skipped)} (duplicates remain elsewhere)")

        if args.reports:
            print("\nreport artifacts:")
            remove_paths("reports_out", os.path.join(REPORT_DIR, "*"))
            if os.path.isdir(SAMPLE_DIR):
                remove_paths("samples", os.path.join(SAMPLE_DIR, "*"))
            for leftover in glob.glob(os.path.join(PROJECT_ROOT, "*.db-journal")):
                try:
                    os.remove(leftover)
                except OSError:
                    pass

        if args.vacuum:
            print("\nVACUUM: reclaiming space (this can take several minutes)...")
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            conn.commit()
            conn.isolation_level = None
            conn.execute("VACUUM")
            print("VACUUM complete.")

        print(f"\ndatabase size now: {os.path.getsize(args.db) / (1024 * 1024):.1f} MB")
        print(f"finished {datetime.now(timezone.utc).isoformat(timespec='seconds')}")
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())