import os
import sys
import tempfile

import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)


@pytest.fixture()
def tmp_db(monkeypatch):
    from server import db as database
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.remove(path)
    monkeypatch.setattr(database, "DB_PATH", path, raising=True)
    mode = database.init_db(path)
    yield path
    for suffix in ("", "-wal", "-shm"):
        try:
            os.remove(path + suffix)
        except OSError:
            pass


@pytest.fixture()
def seeded_host(tmp_db):
    from datetime import datetime, timezone
    from server import db as database
    from server.security import generate_api_key, hash_secret, new_client_id
    conn = database.connect()
    key = generate_api_key()
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    cur = conn.execute(
        """INSERT INTO hosts (client_id, hostname, os_type, api_key_hash, enrolled_at_utc, last_seen_utc)
           VALUES (?,?,?,?,?,?)""",
        (new_client_id(), "test-win01", "windows", hash_secret(key), now, now),
    )
    conn.commit()
    yield {"host_id": cur.lastrowid, "api_key": key}
    conn.close()


@pytest.fixture()
def client(tmp_db, monkeypatch):
    monkeypatch.setenv("ATOR_DFIR_DB", tmp_db)
    from fastapi.testclient import TestClient
    from server.api import app
    with TestClient(app) as tc:
        yield tc
