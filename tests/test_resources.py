import json
import statistics
from datetime import datetime, timezone, timedelta

import pytest
from fastapi.testclient import TestClient

import agent.collectors.resources as resources_mod
import server.db as database
from server.api import app
from agent.agent import load_config, DEFAULT_CONFIG


# ---------------------------------------------------------------------------
# Collector unit tests (mocked psutil)
# ---------------------------------------------------------------------------

def test_delta_rates_first_sample_returns_none():
    """First call to _delta_rates should return None for all rates (no baseline)."""
    resources_mod._prev = {"ts": None, "disk_r": None, "disk_w": None, "net_s": None, "net_r": None}
    rates = resources_mod._delta_rates()
    assert rates["disk_read_kbps"] is None
    assert rates["disk_write_kbps"] is None
    assert rates["net_sent_kbps"] is None
    assert rates["net_recv_kbps"] is None


def test_delta_rates_computes_correct_kbps(monkeypatch):
    """_delta_rates returns correct KB/s when counters increase."""
    import psutil

    class MockDisk:
        read_bytes = 1024 * 1024  # 1 MB
        write_bytes = 512 * 1024  # 512 KB

    class MockNet:
        bytes_sent = 2048 * 1024  # 2 MB
        bytes_recv = 1024 * 1024  # 1 MB

    class MockPsutil:
        @staticmethod
        def disk_io_counters():
            return MockDisk()

        @staticmethod
        def net_io_counters():
            return MockNet()

    monkeypatch.setattr(resources_mod, "psutil", MockPsutil)

    # Seed previous values
    resources_mod._prev = {
        "ts": 1000.0,
        "disk_r": 0,
        "disk_w": 0,
        "net_s": 0,
        "net_r": 0,
    }

    # Advance time by 1 second
    def fake_time():
        return 1001.0

    monkeypatch.setattr(resources_mod.time, "time", fake_time)

    rates = resources_mod._delta_rates()
    # 1 MB / 1s = 1024 KB/s read
    assert rates["disk_read_kbps"] == pytest.approx(1024.0, rel=1e-3)
    assert rates["disk_write_kbps"] == pytest.approx(512.0, rel=1e-3)
    assert rates["net_sent_kbps"] == pytest.approx(2048.0, rel=1e-3)
    assert rates["net_recv_kbps"] == pytest.approx(1024.0, rel=1e-3)


def test_delta_rates_counter_reset_returns_none(monkeypatch):
    """If counters go backwards (reset), rates should be None."""
    import psutil

    class MockDisk:
        read_bytes = 100  # reset to small value

    class MockNet:
        bytes_sent = 50
        bytes_recv = 50

    class MockPsutil:
        @staticmethod
        def disk_io_counters():
            return MockDisk()

        @staticmethod
        def net_io_counters():
            return MockNet()

    monkeypatch.setattr(resources_mod, "psutil", MockPsutil)
    resources_mod._prev = {
        "ts": 1000.0,
        "disk_r": 10000,
        "disk_w": 10000,
        "net_s": 10000,
        "net_r": 10000,
    }

    def fake_time():
        return 1001.0

    monkeypatch.setattr(resources_mod.time, "time", fake_time)

    rates = resources_mod._delta_rates()
    assert rates["disk_read_kbps"] is None
    assert rates["disk_write_kbps"] is None
    assert rates["net_sent_kbps"] is None
    assert rates["net_recv_kbps"] is None


def test_hardware_tier_classification():
    assert resources_mod._hardware_tier(2, 2048) == "low"
    assert resources_mod._hardware_tier(4, 8192) == "mid"
    assert resources_mod._hardware_tier(8, 16384) == "high"
    assert resources_mod._hardware_tier(16, 32768) == "high"
    assert resources_mod._hardware_tier(None, 8192) == "unknown"
    assert resources_mod._hardware_tier(4, None) == "unknown"


def test_snapshot_contains_all_expected_keys(monkeypatch):
    """snapshot() returns dict with all expected keys."""
    # Mock psutil to return deterministic values
    class MockVM:
        total = 16 * 1024 * 1024 * 1024
        used = 8 * 1024 * 1024 * 1024
        percent = 50.0

    class MockSM:
        percent = 10.0

    class MockPsutil:
        @staticmethod
        def cpu_percent(interval=None):
            return 25.0

        @staticmethod
        def virtual_memory():
            return MockVM()

        @staticmethod
        def swap_memory():
            return MockSM()

        @staticmethod
        def sensors_battery():
            class Batt:
                percent = 75.0
                power_plugged = True
            return Batt()

        @staticmethod
        def disk_io_counters():
            return None

        @staticmethod
        def net_io_counters():
            return None

    monkeypatch.setattr(resources_mod, "psutil", MockPsutil)
    monkeypatch.setattr(resources_mod, "os", type("os", (), {"cpu_count": lambda: 8}))
    # Disable GPU probe
    monkeypatch.setattr(resources_mod, "_gpu", lambda _: (False, None, None))
    # Seed delta
    resources_mod._prev = {"ts": None, "disk_r": None, "disk_w": None, "net_s": None, "net_r": None}

    snap = resources_mod.snapshot()
    expected = {"sampled_at_utc", "cpu_pct", "mem_total_mb", "mem_used_mb",
                "mem_pct", "swap_pct", "hw_tier", "cpu_cores",
                "gpu_present", "gpu_util_pct", "gpu_mem_used_mb",
                "battery_pct", "battery_plugged",
                "disk_read_kbps", "disk_write_kbps", "net_sent_kbps", "net_recv_kbps"}
    assert set(snap.keys()) == expected
    assert snap["cpu_pct"] == 25.0
    assert snap["mem_pct"] == 50.0
    assert snap["swap_pct"] == 10.0
    assert snap["hw_tier"] == "high"
    assert snap["cpu_cores"] == 8
    assert snap["gpu_present"] == 0
    assert snap["battery_pct"] == 75.0
    assert snap["battery_plugged"] == 1
    assert snap["disk_read_kbps"] is None  # first sample


def test_load_config_env_precedence(monkeypatch, tmp_path):
    """ATOR_SERVER_URL env beats config.json beats DEFAULT_CONFIG."""
    cfg_path = tmp_path / "config.json"
    cfg_path.write_text(json.dumps({"server_url": "http://from-file:8000"}), encoding="utf-8")

    monkeypatch.delenv("ATOR_SERVER_URL", raising=False)
    cfg = load_config(str(cfg_path))
    assert cfg["server_url"] == "http://from-file:8000"

    monkeypatch.setenv("ATOR_SERVER_URL", "http://from-env:8000")
    cfg = load_config(str(cfg_path))
    assert cfg["server_url"] == "http://from-env:8000"

    monkeypatch.delenv("ATOR_SERVER_URL")
    default = load_config(tmp_path / "missing.json")
    assert default["server_url"] == DEFAULT_CONFIG["server_url"]


# ---------------------------------------------------------------------------
# Server API integration tests
# ---------------------------------------------------------------------------

def _enroll(client):
    resp = client.post("/api/v1/enroll", json={
        "hostname": "test-res", "os_type": "windows", "docker_engine_flag": 0,
    })
    assert resp.status_code == 200
    return resp.json()


def _auth_headers(enrolled):
    return {
        "Authorization": "Bearer " + enrolled["api_key"],
        "X-Client-ID": enrolled["client_id"],
    }


def test_ingest_resources_basic(client):
    enrolled = _enroll(client)
    sample = {
        "sampled_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "cpu_pct": 12.5, "mem_used_mb": 2048.0, "mem_pct": 25.0, "swap_pct": 5.0,
        "disk_read_kbps": 100.0, "disk_write_kbps": 50.0,
        "net_sent_kbps": 200.0, "net_recv_kbps": 300.0,
        "gpu_present": 0, "hw_tier": "mid", "cpu_cores": 4, "mem_total_mb": 8192.0,
    }
    headers = _auth_headers(enrolled)
    resp = client.post("/api/v1/ingest/resources",
                       json={"samples": [sample]}, headers=headers)
    assert resp.status_code == 202
    data = resp.json()
    assert data["count"] == 1
    assert data["status"] == "accepted"


def test_resources_latest_returns_enrolled_hosts(client):
    enrolled = _enroll(client)
    # post one sample
    sample = {"cpu_pct": 10.0, "mem_pct": 20.0, "mem_used_mb": 1024.0,
              "mem_total_mb": 8192.0, "swap_pct": 5.0,
              "disk_read_kbps": 0, "disk_write_kbps": 0,
              "net_sent_kbps": 0, "net_recv_kbps": 0,
              "gpu_present": 0, "hw_tier": "mid", "cpu_cores": 4, "mem_total_mb": 8192.0}
    headers = _auth_headers(enrolled)
    client.post("/api/v1/ingest/resources", json={"samples": [sample]}, headers=headers)

    resp = client.get("/api/v1/resources/latest")
    assert resp.status_code == 200
    data = resp.json()
    hosts = {h["id"]: h for h in data["hosts"]}
    assert enrolled["host_id"] in hosts
    h = hosts[enrolled["host_id"]]
    assert h["hostname"] == "test-res"
    assert h["cpu_pct"] == 10.0


def test_resources_history_returns_points(client):
    enrolled = _enroll(client)
    now = datetime.now(timezone.utc)
    base = now - timedelta(minutes=10)
    # post 5 samples
    headers = _auth_headers(enrolled)
    for i in range(5):
        s = {"cpu_pct": float(10 + i * 2), "mem_pct": 20.0,
             "sampled_at_utc": (base + timedelta(minutes=i * 2)).isoformat(timespec="seconds")}
        client.post("/api/v1/ingest/resources", json={"samples": [s]}, headers=headers)

    resp = client.get(f"/api/v1/resources/history?host_id={enrolled['host_id']}&minutes=30&metrics=cpu_pct,mem_pct&limit=100")
    assert resp.status_code == 200
    data = resp.json()
    pts = data["points"]
    assert len(pts) == 5
    assert all("cpu_pct" in p for p in pts)


def test_resource_anomaly_detection_and_cooldown(client):
    """CPU > 90% triggers anomaly; second high sample within cooldown should NOT create second alert."""
    enrolled = _enroll(client)
    headers = _auth_headers(enrolled)

    # Post normal samples to establish baseline
    for i in range(15):
        s = {"cpu_pct": 10.0 + (i % 3), "mem_pct": 30.0,
             "sampled_at_utc": (datetime.now(timezone.utc) - timedelta(minutes=15 - i)).isoformat(timespec="seconds")}
        client.post("/api/v1/ingest/resources", json={"samples": [s]}, headers=headers)

    # Spike above absolute threshold
    spike = {"cpu_pct": 95.0, "mem_pct": 30.0,
             "sampled_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    resp = client.post("/api/v1/ingest/resources", json={"samples": [spike]}, headers=headers)
    assert resp.status_code == 202
    data = resp.json()
    assert data["alerts"] == 1

    # Verify alert persisted
    resp = client.get(f"/api/v1/resources/alerts?host_id={enrolled['host_id']}")
    assert resp.status_code == 200
    alerts = resp.json()["alerts"]
    assert len(alerts) == 1
    assert alerts[0]["metric"] == "cpu_pct"
    assert alerts[0]["value"] == 95.0
    alert_id = alerts[0]["id"]

    # Second spike within cooldown should NOT create another alert (cooldown 120s)
    spike2 = {"cpu_pct": 98.0, "mem_pct": 30.0,
              "sampled_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    resp = client.post("/api/v1/ingest/resources", json={"samples": [spike2]}, headers=headers)
    assert resp.json()["alerts"] == 0

    # Verify no new alert
    resp = client.get(f"/api/v1/resources/alerts?host_id={enrolled['host_id']}")
    assert len(resp.json()["alerts"]) == 1
    assert resp.json()["alerts"][0]["id"] == alert_id


@pytest.mark.skip(reason="TestClient doesn't support SSE streaming; validated manually")
def test_resources_stream_sse_shape(client):
    pass


def test_battery_low_direction_no_false_alarm(client):
    """Healthy 99% battery must NOT trigger; 8% must (direction-aware thresholds)."""
    enrolled = _enroll(client)
    headers = _auth_headers(enrolled)
    base = {"mem_pct": 30.0, "mem_used_mb": 1024.0, "mem_total_mb": 8192.0,
            "swap_pct": 2.0, "gpu_present": 0, "hw_tier": "mid", "cpu_cores": 4}
    healthy = dict(base, cpu_pct=10.0, battery_pct=99.0, battery_plugged=1)
    resp = client.post("/api/v1/ingest/resources",
                       json={"samples": [healthy]}, headers=headers)
    assert resp.status_code == 202
    assert resp.json()["alerts"] == 0, "healthy battery fired a false alert"

    resp = client.get("/api/v1/resources/latest")
    me = [h for h in resp.json()["hosts"] if h["id"] == enrolled["host_id"]][0]
    assert me["anomaly"] in (0, None)

    low_batt = dict(base, cpu_pct=10.0, battery_pct=8.0, battery_plugged=0)
    resp = client.post("/api/v1/ingest/resources",
                       json={"samples": [low_batt]}, headers=headers)
    assert resp.json()["alerts"] == 1, "8% battery should alert"


def test_retention_prune_via_kv_counter(client):
    """Pruning deletes rows older than the retention window."""
    enrolled = _enroll(client)
    host_id = enrolled["host_id"]
    from server import db as database
    conn = database.connect()
    try:
        # Insert samples with timestamps 2 hours ago (old)
        old_ts = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(timespec="seconds")
        for i in range(5):
            conn.execute(
                """INSERT INTO resource_samples (host_id, sampled_at_utc, cpu_pct)
                   VALUES (?,?,?)""",
                (host_id, old_ts, 5.0)
            )
        conn.commit()
        # Prune anything older than 1 hour
        database.prune_old_resource_samples(conn, hours=1)
        cnt = conn.execute("SELECT COUNT(*) FROM resource_samples WHERE host_id=?", (host_id,)).fetchone()[0]
        assert cnt == 0, f"Expected 0 old rows, got {cnt}"
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Run all
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    pytest.main([__file__, "-v"])