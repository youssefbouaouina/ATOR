"""Small database helpers used by the Windows demo launcher."""
import argparse
import json
import sqlite3


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="action", required=True)

    resolve = sub.add_parser("resolve")
    resolve.add_argument("--config", required=True)
    resolve.add_argument("--db", required=True)

    wait = sub.add_parser("collections")
    wait.add_argument("--db", required=True)
    wait.add_argument("--host-id", required=True, type=int)
    wait.add_argument("--since", required=True)
    args = parser.parse_args()

    if args.action == "resolve":
        with open(args.config, encoding="utf-8") as fh:
            config = json.load(fh)
        with sqlite3.connect(args.db) as conn:
            row = conn.execute(
                "SELECT id, hostname FROM hosts WHERE client_id=?",
                (config.get("client_id"),),
            ).fetchone()
        if not row:
            raise SystemExit("agent client_id is not enrolled in this database")
        print(json.dumps({"id": row[0], "hostname": row[1]}))
        return

    with sqlite3.connect(args.db) as conn:
        count = conn.execute(
            """SELECT COUNT(*) FROM evidence_manifests
               WHERE host_id=? AND received_at_utc > ?""",
            (args.host_id, args.since),
        ).fetchone()[0]
    print(count)


if __name__ == "__main__":
    main()
