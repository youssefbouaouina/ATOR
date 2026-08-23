import os

from server.engine.yara_scanner import compile_rules, scan_bytes, scan_file
from server.engine.ioc_correlator import correlate_batch


RULES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules", "malware"
)


def test_compile_all_yara_rules():
    compiled, errors = compile_rules(RULES_DIR)
    assert compiled is not None
    assert errors == [], errors


def test_marker_file_fires(tmp_path):
    compiled, _ = compile_rules(RULES_DIR)
    sample = tmp_path / "test.bin"
    sample.write_bytes(b"MZ" + b"\x00" * 64 + b"ATOR_DFIR_TEST_FILE_MARKER_X7Q9")
    matches = scan_file(str(sample), compiled=compiled)
    rules = [m["rule"] for m in matches if "rule" in m]
    assert any("Eicar_Style" in r for r in rules), matches


def test_credential_tool_pattern_fires(tmp_path):
    compiled, _ = compile_rules(RULES_DIR)
    data = b"MZ" + b"\x00" * 32 + b"x sekurlsa::logonpasswords x"
    matches = scan_bytes(data, compiled=compiled)
    assert any("Credential_Dump" in m.get("rule", "") for m in matches), matches


def test_clean_text_no_match(tmp_path):
    compiled, _ = compile_rules(RULES_DIR)
    clean = tmp_path / "clean.txt"
    clean.write_text("hello benign world of ordinary documents")
    matches = scan_file(str(clean), compiled=compiled)
    assert [m for m in matches if "rule" in m] == []


BAD_SHA = "a" * 64
C2_IP = "203.0.113.66"


def test_ioc_correlator_hash_and_ip(tmp_db, seeded_host):
    from server import db as database
    conn = database.connect()
    conn.execute("INSERT INTO ioc_store (ioc_type,value,threat_source,added_at_utc) VALUES ('hash',?, 'feed', 't')", (BAD_SHA,))
    conn.execute("INSERT INTO ioc_store (ioc_type,value,threat_source,added_at_utc) VALUES ('ip',?, 'feed', 't')", (C2_IP,))
    conn.commit()

    artifacts = {
        "processes": [{"pid": 10, "name": "evil.exe", "sha256": BAD_SHA}],
        "files_triage": [{"path": "/tmp/evil.bin", "sha256": BAD_SHA.upper()}],
        "network": [
            {"pid": 11, "process_name": "evil.exe", "remote": f"{C2_IP}:4444"},
            {"pid": 12, "process_name": "chrome.exe", "remote": "93.184.216.34:443"},
        ],
    }
    dets = correlate_batch(conn, seeded_host["host_id"], "col-1",
                           "2026-08-20T00:00:00+00:00", artifacts)
    kinds = sorted(d["evidence"]["kind"] for d in dets)
    assert kinds == ["c2_connection", "file_hash", "process_hash"]
    assert all(d["severity"] in ("critical", "high") for d in dets)
