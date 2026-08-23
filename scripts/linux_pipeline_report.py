import json
import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

db = os.environ.get("ATOR_DFIR_DB", "/root/ator_dfir_linux.db")

conn = sqlite3.connect(db)
conn.row_factory = sqlite3.Row

print("containers inventoried:")
for r in conn.execute("SELECT container_name, image_name, status, ip_address FROM containers"):
    print(f"  {r['container_name']:24s} {r['image_name'] or '-':20s} {r['status']} ip={r['ip_address']}")

mapped = 0
for r in conn.execute("SELECT summary FROM detections WHERE rule_type='sigma' LIMIT 0"):
    pass
raw = conn.execute(
    "SELECT payload_json FROM raw_logs WHERE source='cgroup' LIMIT 1"
).fetchone()

from server.engine import run_engine

result = run_engine(conn)
print("\nengine:", json.dumps({k: result[k] for k in ("sigma_hits", "total_new_detections", "approvals_created")}))

rows = conn.execute(
    """SELECT d.rule_name, d.severity, d.technique_id, e.technique_name, h.hostname
       FROM detections d JOIN hosts h ON h.id = d.host_id
       LEFT JOIN enriched_detections e ON e.detection_id = d.id
       ORDER BY d.id DESC LIMIT 15"""
).fetchall()
print(f"\nlatest detections ({len(rows)}):")
for r in rows:
    print(f"  [{r['severity']:8s}] {r['rule_name'][:44]:44s} {r['technique_id'] or '-':10s}"
          f" {r['technique_name'] or '-'} @{r['hostname']}")

nav_ok = True
try:
    from server.engine import reporter
    p = reporter.generate_navigator_layer(conn, out_path="/tmp/nav_check.json")
    data = json.load(open(p))
    print(f"\nnavigator layer: {len(data['techniques'])} technique entries")
except Exception as exc:
    nav_ok = False
    print("navigator FAILED:", exc)

soc_rows = conn.execute(
    """SELECT d.host_id, COUNT(DISTINCT e.tactic) AS stages
       FROM detections d LEFT JOIN enriched_detections e ON e.detection_id=d.id
       GROUP BY d.host_id"""
).fetchall()
for r in soc_rows:
    print(f"host {r['host_id']}: {r['stages']} tactic stages observed")
conn.close()
