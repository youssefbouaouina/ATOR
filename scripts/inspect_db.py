import os
import sys

import sqlite3

db = os.environ.get("ATOR_DFIR_DB", "/root/ator_dfir_linux.db")
conn = sqlite3.connect(db)
conn.row_factory = sqlite3.Row

for table, label in [
    ("hosts", "hosts enrolled"),
    ("evidence_manifests", "collections received"),
    ("raw_processes", "live processes"),
    ("raw_connections", "live connections"),
    ("raw_persistence", "persistence entries"),
    ("raw_logs", "log events"),
    ("raw_files", "files hashed"),
    ("containers", "containers inventoried"),
]:
    n = conn.execute(f"SELECT COUNT(*) AS c FROM {table}").fetchone()["c"]
    print(f"  {label:24s}: {n}")

print("\n  sample persistence:")
for r in conn.execute("SELECT ptype, name FROM raw_persistence LIMIT 5"):
    print(f"    [{r['ptype']}] {r['name'][:70]}")
print("\n  sample logs sources:", dict(conn.execute(
    "SELECT source, COUNT(*) FROM raw_logs GROUP BY source").fetchall()))
print("  manifests integrity:",
      conn.execute("SELECT manifest_sha256 IS NOT NULL AND artifact_count > -1 AS ok"
                    " FROM evidence_manifests").fetchall()[0]["ok"] == 1)
conn.close()
