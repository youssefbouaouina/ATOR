"""Recompute every host's risk score.

Patterned on scripts/update_mitre.py: a small, cron-friendly entry point that does one thing
and reports what it did. Risk is deterministic aggregation over existing detections, so this
is safe to run as often as you like.

    python scripts/update_risk_scores.py
    python scripts/update_risk_scores.py --json
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server import db as database          # noqa: E402
from server.engine import ml_risk          # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="Recompute host risk scores")
    ap.add_argument("--db", default=os.environ.get("ATOR_DFIR_DB"))
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    database.init_db(args.db)               # ensures the ML tables exist
    conn = database.connect(args.db)
    try:
        result = ml_risk.update_all(conn)
        database.audit(conn, "cron", "update_risk_scores",
                       {"hosts": result["hosts_scored"]})
        conn.commit()
    finally:
        conn.close()

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print(f"scored {result['hosts_scored']} host(s): {result['by_tier']}")
        for row in result["scores"][:10]:
            print(f"  host {row['host_id']:>3d}  {row['score']:>8.2f}  {row['tier']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
