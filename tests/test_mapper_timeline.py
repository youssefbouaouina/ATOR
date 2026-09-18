import json

from server.engine import attack_mapper
from server.engine.soc_chain import build as soc_build, risk_assessment
from server.engine.timeline import build as timeline_build, process_tree


def _host(conn, name="map-host"):
    return conn.execute(
        "INSERT INTO hosts (client_id, hostname, os_type, api_key_hash, enrolled_at_utc) VALUES (?,?,?,?,?)",
        ("c-" + name, name, "windows", "x", "2026-01-01T00:00:00+00:00"),
    ).lastrowid


def _det(conn, host_id, ts, technique=None, severity="high", rule="r"):
    cur = conn.execute(
        """INSERT INTO detections (host_id, rule_type, rule_name, severity, technique_id,
           summary, detected_at_utc) VALUES (?,?,?,?,?,?,?)""",
        (host_id, "sigma", rule, severity, technique, "{}", ts),
    )
    conn.commit()
    return cur.lastrowid


def test_lookup_powershell_subtechnique():
    tech = attack_mapper.lookup("T1059.001")
    assert tech is not None
    assert tech["name"] == "PowerShell"
    shorts = [t["short"] for t in tech["tactics"]]
    assert "execution" in shorts
    assert any("Windows" in p for p in tech["platforms"])
    assert tech["is_subtechnique"]


def test_enrichment_written(tmp_db):
    from server import db as database
    conn = database.connect()
    hid = _host(conn)
    det_id = _det(conn, hid, "2026-08-20T00:00:00+00:00", "T1059.001")
    result = attack_mapper.enrich_detections(conn, detection_ids=[det_id])
    assert result["enriched"] == 1
    row = conn.execute(
        "SELECT * FROM enriched_detections WHERE detection_id=?", (det_id,)
    ).fetchone()
    assert row["technique_name"] == "PowerShell"
    tactics = json.loads(row["tactic"])
    assert any(t["short"] == "execution" for t in tactics)


def test_unknown_technique_reported_missing(tmp_db):
    from server import db as database
    conn = database.connect()
    hid = _host(conn)
    det_id = _det(conn, hid, "2026-08-20T00:00:00+00:00", "T9999.999")
    result = attack_mapper.enrich_detections(conn, detection_ids=[det_id])
    assert result["enriched"] == 0
    assert "T9999.999" in result["missing"]


def test_soc_chain_ordering(tmp_db):
    from server import db as database
    from server.engine import attack_mapper
    conn = database.connect()
    hid = _host(conn)
    _det(conn, hid, "2026-08-20T10:05:00+00:00", "T1547.001")
    _det(conn, hid, "2026-08-20T10:01:00+00:00", "T1059.001")
    _det(conn, hid, "2026-08-20T10:03:00+00:00", "T1087")
    attack_mapper.enrich_detections(conn)
    chain = soc_build(conn, hid)
    order = [s["tactic"] for s in chain["chain"]]
    assert order.index("execution") < order.index("persistence") if "persistence" in order else True
    assert "execution" in order and "discovery" in order
    risk = risk_assessment(conn, hid)
    assert risk["counts"]["high"] == 3
    assert risk["risk_level"] in ("HIGH", "MEDIUM")


def test_timeline_sorted_and_skew(tmp_db):
    from server import db as database
    from datetime import datetime, timezone, timedelta
    conn = database.connect()
    hid = _host(conn)
    now = datetime.now(timezone.utc)
    old = (now - timedelta(days=200)).isoformat(timespec="seconds")
    for minutes_ago in (30, 25, 20, 15, 10, 5, 2):
        ts = (now - timedelta(minutes=minutes_ago)).isoformat(timespec="seconds")
        _det(conn, hid, ts)
    conn.execute(
        """INSERT INTO raw_logs (host_id, collected_at_utc, source, event_time_utc, payload_json)
           VALUES (?,?,?,?,?)""",
        (hid, old, "system", old, "{}"),
    )
    conn.commit()
    tl = timeline_build(conn, hid)
    dts = [e["_dt"] for e in tl["events"] if e["_dt"]]
    assert dts == sorted(dts)
    assert len(tl["skew"]) >= 1


def test_process_tree(tmp_db):
    from server import db as database
    conn = database.connect()
    hid = _host(conn)
    base = "2026-08-20T09:00:00+00:00"
    for pid, ppid, name in [(1, None, "explorer.exe"), (100, 1, "cmd.exe"), (101, 100, "whoami.exe")]:
        conn.execute(
            """INSERT INTO raw_processes (host_id, collection_id, collected_at_utc, pid, ppid, name)
               VALUES (?,?,?,?,?,?)""",
            (hid, "colA", base, pid, ppid, name),
        )
    conn.commit()
    tree = process_tree(conn, hid)
    pids = {n["pid"] for n in tree["nodes"]}
    assert pids == {1, 100, 101}
    edges = {(e["from"], e["to"]) for e in tree["edges"]}
    assert (1, 100) in edges and (100, 101) in edges


def test_timeline_bounds_payloads_and_preserves_total(tmp_db, monkeypatch):
    from server import db as database
    from server.engine import timeline
    conn = database.connect()
    hid = _host(conn)
    other = _host(conn, "other")
    conn.executemany(
        "INSERT INTO raw_logs (host_id, collected_at_utc, source, event_time_utc, payload_json) VALUES (?,?,?,?,?)",
        [(hid, "2026-09-17T00:00:00+00:00", "system",
          f"2026-09-17T00:{i // 60:02d}:{i % 60:02d}+00:00", "{}")
         for i in range(600)],
    )
    _det(conn, other, "2026-09-18T00:00:00+00:00")
    _det(conn, hid, "2026-09-17T00:10:00+00:00")
    parsed = []
    original = timeline.json.loads

    def loads(value, *args, **kwargs):
        parsed.append(value)
        return original(value, *args, **kwargs)

    monkeypatch.setattr(timeline.json, "loads", loads)
    result = timeline_build(conn, hid, limit=10)
    assert result["total"] == 601
    assert len(result["events"]) == 10
    assert len(parsed) <= 11
    assert result["events"][-1]["kind"] == "detection"
    assert result["events"][0]["ts"] == "2026-09-17T00:09:51+00:00"
    assert result["skew_scope"] == "displayed_events"
    assert timeline_build(conn, hid, limit=0)["events"] == []
    conn.close()


def test_timeline_mixed_timestamp_formats(tmp_db):
    from server import db as database
    conn = database.connect()
    hid = _host(conn)
    for ts in ("2026-09-17T10:00:00", "2026-09-17T09:00:00Z", "invalid"):
        _det(conn, hid, ts)
    result = timeline_build(conn, hid)
    assert len(result["events"]) == 3
    assert result["events"][0]["ts"] == "2026-09-17T09:00:00Z"
    assert result["events"][-1]["_dt"] is None
    conn.close()
