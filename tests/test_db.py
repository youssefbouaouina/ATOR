from server import db as database
from server.security import generate_api_key, hash_secret, new_client_id, verify_secret


def test_wal_mode(tmp_db):
    conn = database.connect()
    mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
    assert mode.lower() == "wal"
    conn.close()


def test_host_unique_client_id(tmp_db):
    conn = database.connect()
    cid = new_client_id()
    key_hash = hash_secret(generate_api_key())
    conn.execute(
        "INSERT INTO hosts (client_id, hostname, os_type, api_key_hash, enrolled_at_utc) VALUES (?,?,?,?,?)",
        (cid, "h1", "linux", key_hash, "2026-01-01T00:00:00+00:00"),
    )
    try:
        conn.execute(
            "INSERT INTO hosts (client_id, hostname, os_type, api_key_hash, enrolled_at_utc) VALUES (?,?,?,?,?)",
            (cid, "h2", "linux", key_hash, "2026-01-01T00:00:00+00:00"),
        )
        assert False, "expected UNIQUE violation"
    except Exception as exc:
        assert "UNIQUE" in str(exc)
    finally:
        conn.close()


def test_kv_upsert(tmp_db):
    conn = database.connect()
    database.audit(conn, "t", "test")
    conn.execute("INSERT INTO kv (key,value) VALUES ('k','1')")
    conn.execute("INSERT INTO kv (key,value) VALUES ('k','2') ON CONFLICT(key) DO UPDATE SET value='2'")
    assert conn.execute("SELECT value FROM kv WHERE key='k'").fetchone()["value"] == "2"
    conn.close()


def test_secret_roundtrip():
    secret = generate_api_key()
    stored = hash_secret(secret)
    assert verify_secret(secret, stored)
    assert not verify_secret(secret + "x", stored)
