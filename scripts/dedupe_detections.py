import sqlite3

conn = sqlite3.connect("ator_dfir.db")
before = conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
conn.execute(
    """DELETE FROM detections WHERE id NOT IN
       (SELECT MIN(id) FROM detections
        GROUP BY host_id, rule_type, rule_name, detected_at_utc)"""
)
conn.execute("DELETE FROM enriched_detections WHERE detection_id NOT IN (SELECT id FROM detections)")
conn.commit()
after = conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
wm = conn.execute("SELECT value FROM kv WHERE key='engine_last_run_utc'").fetchone()
per_host = conn.execute(
    "SELECT h.hostname, COUNT(*) AS n FROM detections d JOIN hosts h ON h.id=d.host_id GROUP BY h.hostname"
).fetchall()
print(f"detections: {before} -> {after}; watermark={wm[0] if wm else None}")
for row in per_host:
    print(f"  {row[0]}: {row[1]}")
conn.close()
