"""Consistent online backup of the ATOR DFIR SQLite database.

Uses the sqlite3 backup API so a running server/agent (WAL mode) cannot produce
a torn copy. Safe to run while the dashboard and agents are collecting.

Usage:
    python scripts/backup_db.py                  # -> backups/ator_dfir_<utc>.db
    python scripts/backup_db.py --out D:\\x.db
"""
import argparse
import os
import sqlite3
import sys
from datetime import datetime, timezone

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from server import db as database  # noqa: E402


def backup(src_path, dest_path):
    os.makedirs(os.path.dirname(os.path.abspath(dest_path)), exist_ok=True)
    src = sqlite3.connect(f"file:{src_path}?mode=ro", uri=True, timeout=30)
    try:
        dest = sqlite3.connect(dest_path)
        try:
            src.backup(dest)
        finally:
            dest.close()
    finally:
        src.close()
    return dest_path


def main():
    parser = argparse.ArgumentParser(description="Back up the ATOR DFIR database")
    parser.add_argument("--db", default=database.DB_PATH, help="source database path")
    parser.add_argument("--out", default=None, help="destination path")
    args = parser.parse_args()

    if not os.path.exists(args.db):
        print(f"ERROR: database not found: {args.db}", file=sys.stderr)
        return 1

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest = args.out or os.path.join(PROJECT_ROOT, "backups", f"ator_dfir_{stamp}.db")
    backup(args.db, dest)
    src_mb = os.path.getsize(args.db) / (1024 * 1024)
    dest_mb = os.path.getsize(dest) / (1024 * 1024)
    print(f"source : {args.db} ({src_mb:.1f} MB)")
    print(f"backup : {dest} ({dest_mb:.1f} MB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
