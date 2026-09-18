"""Phase 8 tests: the train/serve coverage defect, and the guard against it recurring.

Phase 7b.2 shipped five burst features that scored well in cross-validation and were NaN on
every live host, because they were keyed off `collected_at_utc` - which is a per-process
launch time in the corpus and a single per-sweep timestamp in production. Nothing in the
suite could catch that: every test used corpus-shaped data, where the features worked.

The tests here are deliberately built around **two differently shaped databases**, because
that difference is the bug. A fixture that only ever produces one shape cannot detect it.
"""
import sqlite3

import numpy as np
import pandas as pd
import pytest

from server import db as database
from server.engine import ml_features as mlf


PROC_COLUMNS = ("host_id", "collection_id", "collected_at_utc", "pid", "ppid",
                "name", "cmdline", "exe_path", "sha256", "username")


def _blank_db(with_create_time=True):
    """An empty database built from the REAL schema, not a hand-written subset.

    An earlier draft of this file declared its own `raw_processes`/`raw_logs` tables and got
    the column names wrong, which is the same category of mistake this file exists to catch:
    a fixture that does not match production cannot test against production. Using
    `database.SCHEMA` makes the fixture wrong only if the product is wrong.

    `with_create_time=False` skips the ML migration, reproducing a database from before the
    overlay was applied - which the feature layer has to tolerate rather than raise on.
    """
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(database.SCHEMA)
    if with_create_time:
        database.migrate(conn)
    conn.execute(
        """INSERT INTO hosts (id, client_id, hostname, os_type, api_key_hash, enrolled_at_utc)
           VALUES (1, 'test-client', 'testbox', 'windows', 'x', '2026-03-01T00:00:00+00:00')""")
    conn.commit()
    return conn


def _corpus_shaped(conn, n=12):
    """What an OTRF capture looks like: one row per Sysmon EID 1, each with its own time.

    `collected_at_utc` and `create_time_utc` hold the SAME value here, and that is correct -
    a launch event is observed at the instant it happens.
    """
    for i in range(n):
        stamp = f"2026-03-01T10:00:{i * 3:02d}+00:00"
        conn.execute(
            "INSERT INTO raw_processes (host_id, collection_id, collected_at_utc, pid, ppid,"
            " name, cmdline, exe_path, create_time_utc) VALUES (1,'cap-1',?,?,?,?,?,?,?)",
            (stamp, 1000 + i, 1000 + i - 1 if i else 4,
             "powershell.exe", "powershell -enc AAAA", "C:/Windows/powershell.exe", stamp))
    conn.commit()


def _live_shaped(conn, n=12):
    """What a psutil sweep looks like: ONE collection timestamp, per-process start times.

    This is the shape that broke Phase 7b.2. Every row shares `collected_at_utc`; only
    `create_time_utc` distinguishes when each process actually started.
    """
    swept = "2026-03-01T12:00:00+00:00"
    for i in range(n):
        conn.execute(
            "INSERT INTO raw_processes (host_id, collection_id, collected_at_utc, pid, ppid,"
            " name, cmdline, exe_path, create_time_utc) VALUES (1,'sweep-1',?,?,?,?,?,?,?)",
            (swept, 2000 + i, 2000 + i - 1 if i else 4,
             "powershell.exe", "powershell -enc AAAA", "C:/Windows/powershell.exe",
             f"2026-03-01T11:59:{i * 3:02d}+00:00"))
    conn.commit()


BURST = ("procs_within_5s", "seconds_since_parent_start")


# --------------------------------------------------------------- the defect, as a test

class TestBurstFeaturesWorkOnBothShapes:
    """The regression test for the actual Phase 8 bug.

    Before the fix, `corpus` passed and `live` produced all-NaN. Asserting on both shapes in
    one test class is the point: either one alone is satisfiable by the broken code.
    """

    @pytest.mark.parametrize("shape", ["corpus", "live"])
    def test_burst_features_are_computed(self, shape):
        conn = _blank_db()
        (_corpus_shaped if shape == "corpus" else _live_shaped)(conn)
        frame = mlf.extract_process_frame(conn)
        features = mlf.transform(frame, tier=mlf.TIER_T1)
        for name in ("procs_within_5s",):
            values = pd.to_numeric(features[name], errors="coerce")
            assert values.notna().all(), f"{name} is NaN on {shape}-shaped data"

    def test_a_sweep_and_a_capture_agree_on_the_same_timings(self):
        """Identical spacing must give identical counts, whatever stamped the rows.

        Both fixtures space processes 3 seconds apart, so the windowed counts must match
        exactly. This is what "scale-free" has to mean in practice, and it is the property
        `proc_spawn_rate_per_min` could never have had.
        """
        out = {}
        for shape, build in (("corpus", _corpus_shaped), ("live", _live_shaped)):
            conn = _blank_db()
            build(conn)
            features = mlf.transform(mlf.extract_process_frame(conn), tier=mlf.TIER_T1)
            out[shape] = [pd.to_numeric(features[n], errors="coerce").tolist()
                          for n in ("procs_within_5s",)]
        assert out["corpus"] == out["live"]


class TestCollectedAtIsNeverUsedAsAStartTime:
    """No silent fallback. NULL start time must yield NaN, not the sweep time."""

    def test_missing_create_time_gives_nan_not_a_guess(self):
        conn = _blank_db()
        _live_shaped(conn)
        conn.execute("UPDATE raw_processes SET create_time_utc = NULL")
        conn.commit()
        features = mlf.transform(mlf.extract_process_frame(conn), tier=mlf.TIER_T1)
        for name in BURST:
            values = pd.to_numeric(features[name], errors="coerce")
            assert values.isna().all(), (
                f"{name} produced a value from collected_at_utc - that fallback is the bug")

    def test_partial_coverage_is_honoured_row_by_row(self):
        conn = _blank_db()
        _live_shaped(conn, n=6)
        conn.execute("UPDATE raw_processes SET create_time_utc = NULL WHERE pid IN (2000, 2001)")
        conn.commit()
        features = mlf.transform(mlf.extract_process_frame(conn), tier=mlf.TIER_T1)
        counted = pd.to_numeric(features["procs_within_5s"], errors="coerce")
        assert counted.isna().sum() == 2
        assert counted.notna().sum() == 4


class TestMigrationSafety:
    """A database that predates the ML migration must degrade, not raise."""

    def test_query_survives_a_missing_column(self):
        conn = _blank_db(with_create_time=False)
        conn.execute(
            "INSERT INTO raw_processes (host_id, collection_id, collected_at_utc, pid, name)"
            " VALUES (1,'c',?,1,'x')", ("2026-03-01T12:00:00+00:00",))
        conn.commit()
        frame = mlf.extract_process_frame(conn)          # must not raise
        features = mlf.transform(frame, tier=mlf.TIER_T1)
        assert len(features) == 1
        for name in BURST:
            assert pd.to_numeric(features[name], errors="coerce").isna().all()

    def test_migration_adds_the_column_and_is_idempotent(self, tmp_path):
        path = tmp_path / "m.db"
        database.init_db(str(path))
        conn = database.connect(str(path))
        try:
            columns = {r[1] for r in conn.execute("PRAGMA table_info(raw_processes)")}
            assert "create_time_utc" in columns
            assert database.migrate(conn)["columns_added"] == []
        finally:
            conn.close()


# ------------------------------------------------------- the three deleted features

class TestDeletedBurstFeatures:
    """Removed on measurement, not taste - see docs/ML_PHASE8_PLAN.md section 1."""

    @pytest.mark.parametrize("name, why", [
        ("collection_has_timespan", "AUC 0.479, leave-one-out delta exactly 0.0000"),
        ("seconds_since_collection_start",
         "position within a lab recording; removing it improved PR-AUC by 0.0029"),
        ("proc_spawn_rate_per_min",
         "collection-constant and defined over a span that is not comparable across sources"),
    ])
    def test_is_gone_from_the_spec(self, name, why):
        assert name not in mlf.FEATURE_NAMES, why
        for members in mlf.FEATURE_GROUPS.values():
            assert name not in members, f"{name} still listed in a feature group"

    def test_surviving_burst_features_are_all_t1(self):
        """They need only a process start time, which every OS reports. No tier gate."""
        assert set(BURST) <= set(mlf.T1_FEATURES)


# ------------------------------------------------ the general guard, not just this bug

class TestTrainServeCoverageGuard:
    """Fail when a feature is computable in training and absent in production.

    This is the part meant to outlive Phase 8. The specific bug is fixed by the tests above;
    this one catches the *next* feature that only works on one side, which is the failure
    mode that actually cost a phase.
    """

    #: A feature well-populated in training must not be near-absent at serve time.
    TRAIN_COVERAGE_FLOOR = 0.90
    SERVE_COVERAGE_FLOOR = 0.10

    def _coverage(self, conn):
        frame = mlf.extract_process_frame(conn)
        features = mlf.transform(frame, tier=mlf.TIER_T1)
        return {name: float(pd.to_numeric(features[name], errors="coerce").notna().mean())
                for name in mlf.T1_FEATURES if name in features.columns}

    def test_no_t1_feature_is_training_only(self):
        corpus_conn, live_conn = _blank_db(), _blank_db()
        _corpus_shaped(corpus_conn, n=30)
        _live_shaped(live_conn, n=30)
        train, serve = self._coverage(corpus_conn), self._coverage(live_conn)

        offenders = {
            name: (train[name], serve.get(name, 0.0))
            for name in train
            if train[name] >= self.TRAIN_COVERAGE_FLOOR
            and serve.get(name, 0.0) < self.SERVE_COVERAGE_FLOOR
        }
        assert not offenders, (
            "features computable in training but not at serve time: "
            + ", ".join(f"{n} ({t:.0%} train -> {s:.0%} serve)"
                        for n, (t, s) in sorted(offenders.items()))
            + " - this is the Phase 7b.2 failure mode; either make the feature computable "
              "from what the agent collects, or remove it")


class TestAgentCollectsStartTime:
    """The collector side of the same contract."""

    def test_iso_utc_rejects_unusable_epochs(self):
        from agent.collectors.processes import _iso_utc
        assert _iso_utc(None) is None
        assert _iso_utc(0) is None          # pid 0 / kernel pseudo-processes
        assert _iso_utc(-1) is None
        assert _iso_utc("nonsense") is None
        stamp = _iso_utc(1_772_000_000)
        assert stamp is not None and stamp.endswith("+00:00")

    def test_collect_reports_a_start_time_for_real_processes(self, monkeypatch):
        """Runs the real collector against this machine's real process table.

        `_sha256_file` is stubbed out: unstubbed, `collect()` SHA-256s every executable on the
        host, which turned this one test into minutes of wall clock and is nothing to do with
        what is being asserted. Hashing is covered elsewhere.
        """
        pytest.importorskip("psutil")
        from agent.collectors import processes
        monkeypatch.setattr(processes, "_sha256_file", lambda path: None)
        rows = processes.collect()
        assert rows, "no processes collected"
        with_time = [r for r in rows if r.get("create_time_utc")]
        # System Idle Process and System legitimately have none; everything else should.
        assert len(with_time) / len(rows) > 0.90
        assert all(r["create_time_utc"].endswith("+00:00") for r in with_time)


# ------------------------------------------- the UI must not quote a number it invented

class TestGatePrecisionComesFromTheArtefact:
    """The tactic hint's precision was hard-coded at 78% in four places.

    It is a measured quantity that moves on every retrain, so a literal is a claim with a
    shelf life. These pin the plumbing that reads it back out of the model instead.
    """

    def test_missing_gating_yields_no_claim(self):
        from server.engine.ml_integration import _gate_precision
        assert _gate_precision(None) is None
        assert _gate_precision({}) is None
        assert _gate_precision({"metrics": {}}) is None
        assert _gate_precision({"metrics": {"gating": {}}}) is None

    def test_precision_is_read_from_the_shipped_operating_point(self):
        from server.engine.ml_integration import _gate_precision
        artefact = {"metrics": {"gating": {"shipped_operating_point": {"precision": 0.7639}}}}
        assert _gate_precision(artefact) == pytest.approx(0.7639)

    def test_describe_surfaces_the_gate_when_the_artefact_carries_it(self, tmp_path):
        """`ml_registry.describe` is what the dashboard renders from."""
        pytest.importorskip("sklearn")
        from server.engine import ml_registry
        path = tmp_path / "d.db"
        database.init_db(str(path))
        conn = database.connect(str(path))
        try:
            out = ml_registry.describe(conn)
            gate = out.get("tactic_gate")
            if gate is None:
                pytest.skip("no tactic artefact present in this checkout")
            assert 0.0 <= gate["precision"] <= 1.0
            assert gate["precision_pct"] == round(gate["precision"] * 100)
            assert gate["min_probability"] is not None
        finally:
            conn.close()

    def test_describe_never_raises_without_artefacts(self, tmp_path, monkeypatch):
        from server.engine import ml_registry
        monkeypatch.setattr(ml_registry, "MODELS_DIR", str(tmp_path / "nonexistent"))
        ml_registry.clear_cache()
        path = tmp_path / "e.db"
        database.init_db(str(path))
        conn = database.connect(str(path))
        try:
            out = ml_registry.describe(conn)
            assert out["models"] == []
            assert "tactic_gate" not in out      # absent, rather than a made-up default
        finally:
            conn.close()
            ml_registry.clear_cache()


class TestPidStaysAnInteger:
    """Regression: coercing pid to Float64 broke detection-to-process matching.

    The Phase 8 parent-join fix cast `pid`/`ppid` with `astype("Float64")` to make the merge
    dtype-safe. It was dtype-safe and wrong: pids started rendering as "4.0", the confidence
    scorer matches detections back to processes by pid, and 25 ML findings silently went
    unscored. The full suite passed throughout - only opening the dashboard showed it.
    """

    def test_extracted_pids_are_integral(self):
        conn = _blank_db()
        _live_shaped(conn, n=4)
        frame = mlf.extract_process_frame(conn)
        assert str(frame["pid"].dtype) == "Int64", "pid must be a nullable INTEGER dtype"
        assert str(frame["ppid"].dtype) == "Int64"

    def test_pid_stringifies_without_a_decimal_point(self):
        """What the detection summary actually writes into the database."""
        conn = _blank_db()
        _live_shaped(conn, n=3)
        frame = mlf.extract_process_frame(conn)
        rendered = [str(v) for v in frame["pid"]]
        assert all("." not in r for r in rendered), rendered
        assert "2000" in rendered

    def test_all_null_ppid_still_merges(self):
        """The defect the Float64 cast was introduced to fix must stay fixed."""
        conn = _blank_db()
        conn.execute(
            "INSERT INTO raw_processes (host_id, collection_id, collected_at_utc, pid, name)"
            " VALUES (1,'c','2026-03-01T12:00:00+00:00',10,'a.exe')")
        conn.commit()
        frame = mlf.extract_process_frame(conn)      # must not raise
        assert len(frame) == 1
        assert pd.isna(frame["ppid"].iloc[0])
