"""Phase 10: the model store and the run lock - the two pieces an unattended job most
often breaks itself on (a half-swapped model, a lock nobody releases)."""
import json
import os

import pytest

from ml.mlops import store
from ml.mlops.lock import LockHeld, RunLock
from server.engine import ml_registry

NOW = "2026-09-27T03:00:00+00:00"


@pytest.fixture()
def models(tmp_path, monkeypatch):
    path = tmp_path / "models"
    path.mkdir()
    monkeypatch.setattr(ml_registry, "MODELS_DIR", str(path))
    ml_registry.clear_cache()
    yield path
    ml_registry.clear_cache()


def _artefact(path, marker, version_id=None):
    import joblib
    payload = {"kind": "test", "marker": marker, "trained_at_utc": f"t-{marker}"}
    if version_id:
        payload["version_id"] = version_id
    joblib.dump(payload, str(path))


def _version(models, version_id, marker, component="anomaly"):
    vdir = models / "registry" / version_id
    vdir.mkdir(parents=True, exist_ok=True)
    names = {"anomaly": ("anomaly_t1", "anomaly_t2"), "tactic": ("tactic_t1",)}[component]
    for name in names:
        _artefact(vdir / f"{name}.joblib", f"{marker}-{name}", version_id)
    return version_id


def _serving_marker(models, name="anomaly_t1"):
    import joblib
    return joblib.load(str(models / f"{name}.joblib"))["marker"]


class TestStore:
    def test_legacy_champion_is_adopted_so_rollback_can_reach_it(self, models):
        _artefact(models / "anomaly_t1.joblib", "legacy")
        _artefact(models / "anomaly_t2.joblib", "legacy2")
        result = store.reconcile("anomaly", NOW)
        assert result["action"] == "adopted_legacy"
        assert store.champion_entry("anomaly")["version_id"].startswith("legacy-")
        assert store.reconcile("anomaly", NOW)["action"] == "ok"

    def test_promote_and_rollback(self, models):
        _artefact(models / "anomaly_t1.joblib", "legacy")
        _artefact(models / "anomaly_t2.joblib", "legacy")
        _version(models, "v1", "new")
        store.promote("anomaly", "v1", "test", NOW)
        assert _serving_marker(models) == "new-anomaly_t1"
        assert _serving_marker(models, "anomaly_t2") == "new-anomaly_t2"
        assert store.previous_version("anomaly").startswith("legacy-")
        store.rollback("anomaly", NOW)
        assert _serving_marker(models) == "legacy"
        assert [e["reason"] for e in store.load_history()["champions"]["anomaly"]] == \
            ["legacy", "test", "rollback"]

    def test_promotion_is_picked_up_by_the_servers_cache(self, models):
        """No restart needed: a fresh file means a fresh (mtime, size) cache key."""
        import joblib
        from server.engine import ml_features as mlf
        for marker, version in (("a", "v1"), ("bb", "v2")):
            vdir = models / "registry" / version
            vdir.mkdir(parents=True)
            for name in ("anomaly_t1", "anomaly_t2"):
                joblib.dump({"marker": marker, "version_id": version,
                             "feature_spec_sha256": mlf.feature_spec_sha256()},
                            str(vdir / f"{name}.joblib"))
        store.promote("anomaly", "v1", "test", NOW)
        assert ml_registry.load_artefact("anomaly", "t1")["marker"] == "a"
        store.promote("anomaly", "v2", "test", NOW)
        assert ml_registry.load_artefact("anomaly", "t1")["marker"] == "bb"

    def test_interrupted_swap_is_repaired(self, models):
        """Crash after replacing t1 but before t2: the recorded champion is restored."""
        _version(models, "v1", "old")
        _version(models, "v2", "new")
        store.promote("anomaly", "v1", "test", NOW)
        store.atomic_copy(str(models / "registry" / "v2" / "anomaly_t1.joblib"),
                          str(models / "anomaly_t1.joblib"))
        result = store.reconcile("anomaly", NOW)
        assert result["action"] == "repaired_interrupted_swap"
        assert _serving_marker(models) == "old-anomaly_t1"
        assert _serving_marker(models, "anomaly_t2") == "old-anomaly_t2"

    def test_hand_placed_model_is_adopted_not_overwritten(self, models):
        _version(models, "v1", "old")
        store.promote("anomaly", "v1", "test", NOW)
        _artefact(models / "anomaly_t1.joblib", "hand-trained")
        result = store.reconcile("anomaly", NOW)
        assert result["action"] == "adopted_manual_change"
        assert _serving_marker(models) == "hand-trained"
        assert store.previous_version("anomaly") == "v1"

    def test_shadow_slot_is_separate_from_serving(self, models):
        _version(models, "v1", "challenger")
        store.install("anomaly", "v1", slot="shadow")
        assert not (models / "anomaly_t1.joblib").exists()
        assert (models / "shadow" / "anomaly_t1.joblib").exists()
        assert store.clear_shadow() == ["anomaly_t1.joblib", "anomaly_t2.joblib"]

    def test_prune_keeps_rollback_targets_and_protected(self, models):
        for i in range(1, 8):
            _version(models, f"v{i}", f"m{i}")
            store.promote("anomaly", f"v{i}", "test", NOW)
        _version(models, "trial", "t")
        removed = store.prune(keep_versions=3, protect={"trial"})
        assert sorted(removed) == ["v1", "v2", "v3", "v4"]
        assert store.previous_version("anomaly") == "v6"
        assert (models / "registry" / "trial").exists()

    def test_rollback_without_history_is_an_error(self, models):
        with pytest.raises(RuntimeError):
            store.rollback("anomaly", NOW)

    def test_history_write_is_atomic_json(self, models):
        _version(models, "v1", "x")
        store.promote("anomaly", "v1", "test", NOW)
        path = models / "registry" / "history.json"
        assert json.loads(path.read_text())["champions"]["anomaly"][0]["version_id"] == "v1"
        assert not (models / "registry" / "history.json.tmp").exists()


class TestLock:
    def test_second_holder_is_refused_while_owner_alive(self, tmp_path):
        path = str(tmp_path / "pipeline.lock")
        with RunLock(path):
            with pytest.raises(LockHeld):
                RunLock(path).acquire()
        assert not os.path.exists(path)

    def test_lock_of_a_dead_process_is_reclaimed(self, tmp_path):
        path = tmp_path / "pipeline.lock"
        path.write_text(json.dumps({"pid": 999_999_999, "process_created": 1.0,
                                    "acquired_at": 1.0}))
        lock = RunLock(str(path)).acquire()
        assert lock.reclaimed["pid"] == 999_999_999
        lock.release()

    def test_lock_from_a_reused_pid_is_reclaimed(self, tmp_path):
        """Our own pid, but a process start time that is not ours: the pid was reused."""
        import time
        path = tmp_path / "pipeline.lock"
        path.write_text(json.dumps({"pid": os.getpid(), "process_created": 12345.0,
                                    "acquired_at": time.time()}))
        lock = RunLock(str(path)).acquire()
        assert lock.reclaimed is not None
        lock.release()

    def test_ancient_lock_is_reclaimed(self, tmp_path):
        import psutil
        path = tmp_path / "pipeline.lock"
        path.write_text(json.dumps({"pid": os.getpid(),
                                    "process_created": psutil.Process().create_time(),
                                    "acquired_at": 0}))
        lock = RunLock(str(path), stale_after_hours=6).acquire()
        assert lock.reclaimed is not None
        lock.release()

    def test_unreadable_lock_is_reclaimed(self, tmp_path):
        path = tmp_path / "pipeline.lock"
        path.write_text("{not json")
        RunLock(str(path)).acquire().release()
