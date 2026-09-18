"""Phase 2 tests: the feature contract.

The invariants worth protecting here are not "does it compute a number" but:

* the feature set is identical on training and production data (the no-skew claim);
* missing is NaN, never 0 (collapsing them teaches corpus artefacts);
* no feature touches a column that exists only in the training database;
* learned statistics are injected, never computed inside the transform (fold safety).
"""
import math
import os
import sqlite3
import tempfile

import numpy as np
import pandas as pd
import pytest

from server import db as database
from server.engine import ml_features as mlf


# --------------------------------------------------------------------------- fixtures

@pytest.fixture()
def populated_db(tmp_db, seeded_host):
    """A small but realistic set of processes/connections/sysmon rows."""
    host_id = seeded_host["host_id"]
    conn = database.connect(tmp_db)
    ts = "2026-03-01T22:30:00+00:00"          # a Sunday, off-hours

    def add_proc(pid, ppid, name, cmdline, exe_path, sha=None, user=None):
        conn.execute(
            """INSERT INTO raw_processes (host_id, collection_id, collected_at_utc, pid, ppid,
                                          name, cmdline, exe_path, sha256, username)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (host_id, "col-1", ts, pid, ppid, name, cmdline, exe_path, sha, user))

    # parent: an Empire-style encoded PowerShell
    add_proc(1000, 4, "powershell.exe",
             'powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA',
             r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
             sha="a" * 64, user=r"LAB\alice")
    # child of it, from a temp path, masquerading as svchost
    add_proc(1001, 1000, "svchost.exe", "svchost.exe -k netsvcs",
             r"C:\Users\alice\AppData\Local\Temp\svchost.exe", user=r"NT AUTHORITY\SYSTEM")
    # grandchild
    add_proc(1002, 1001, "whoami.exe", "whoami.exe /priv",
             r"C:\Windows\System32\whoami.exe")
    # unrelated, orphan (parent pid not in the collection), no cmdline captured
    add_proc(2000, 9999, "System", None, None)

    conn.execute(
        """INSERT INTO raw_connections (host_id, collection_id, collected_at_utc, pid,
                                         process_name, local_ip, local_port, remote_ip,
                                         remote_port, proto, status)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (host_id, "col-1", ts, 1001, "svchost.exe", "10.0.0.5", 50000,
         "93.184.216.34", 4444, "tcp", "ESTABLISHED"))
    conn.execute(
        """INSERT INTO raw_connections (host_id, collection_id, collected_at_utc, pid,
                                         process_name, local_ip, local_port, remote_ip,
                                         remote_port, proto, status)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (host_id, "col-1", ts, 1001, "svchost.exe", "10.0.0.5", 50001,
         "10.0.0.9", 445, "tcp", "LISTEN"))
    conn.commit()
    conn.close()
    return {"db": tmp_db, "host_id": host_id}


def _matrix(db_path, tier=mlf.TIER_T3, with_stats=True):
    conn = database.connect(db_path)
    try:
        frame = mlf.extract_process_frame(conn)
        stats = mlf.fit_stats(frame) if with_stats else None
        return mlf.transform(frame, stats=stats, tier=tier), frame
    finally:
        conn.close()


# --------------------------------------------------------------------------- the contract

class TestFeatureSpec:
    def test_names_unique(self):
        assert len(mlf.FEATURE_NAMES) == len(set(mlf.FEATURE_NAMES))

    def test_every_feature_has_a_valid_tier_and_description(self):
        for fd in mlf.FEATURE_SPEC:
            assert fd.tier in (mlf.TIER_T1, mlf.TIER_T2, mlf.TIER_T3), fd.name
            assert fd.description.strip(), fd.name

    def test_tier_partition_is_complete(self):
        assert (set(mlf.T1_FEATURES) | set(mlf.T2_FEATURES) | set(mlf.T3_FEATURES)
                == set(mlf.FEATURE_NAMES))
        assert not set(mlf.T1_FEATURES) & set(mlf.T2_FEATURES)
        assert not set(mlf.T2_FEATURES) & set(mlf.T3_FEATURES)
        assert not set(mlf.T1_FEATURES) & set(mlf.T3_FEATURES)

    def test_tiers_are_cumulative(self):
        """t1 subset of t2 subset of t3 - a host can only use a tier it has data for."""
        t1 = set(mlf.features_for_tier(mlf.TIER_T1))
        t2 = set(mlf.features_for_tier(mlf.TIER_T2))
        t3 = set(mlf.features_for_tier(mlf.TIER_T3))
        assert t1 < t2 < t3
        assert t3 == set(mlf.FEATURE_NAMES)

    def test_unknown_tier_is_rejected(self):
        with pytest.raises(ValueError):
            mlf.tiers_up_to("t9")

    def test_every_t3_feature_is_named_psh(self):
        for name in mlf.T3_FEATURES:
            assert name.startswith("psh_"), name

    def test_spec_hash_is_stable_and_sensitive(self):
        first = mlf.feature_spec_sha256()
        assert first == mlf.feature_spec_sha256()
        assert len(first) == 64
        # The hash must change if the contract changes, or a stale model could silently be
        # fed a different vector.
        original = mlf.FEATURE_SPEC
        try:
            mlf.FEATURE_SPEC = original + (
                mlf.FeatureDef("synthetic_probe", mlf.TIER_T1, "probe"),)
            assert mlf.feature_spec_sha256() != first
        finally:
            mlf.FEATURE_SPEC = original
        assert mlf.feature_spec_sha256() == first

    def test_every_t2_feature_is_named_sysmon(self):
        """Keeps the Sysmon dependency obvious at a glance in any model dump."""
        for name in mlf.T2_FEATURES:
            assert name.startswith("sysmon_"), name


class TestProductionSchemaDiscipline:
    """Features must never depend on training-only data."""

    FORBIDDEN = ("corpus_lineage", "corpus_labels", "corpus_captures",
                 "process_guid", "ParentProcessGuid", "is_reconstructed",
                 "sysmon_extended")

    def test_module_source_references_no_training_only_artefact(self):
        source = open(mlf.__file__, encoding="utf-8").read()
        for token in self.FORBIDDEN:
            assert token not in source, f"ml_features references training-only {token!r}"

    def test_reads_only_production_tables(self):
        source = open(mlf.__file__, encoding="utf-8").read()
        # `_PROCESS_SQL` became `_process_sql(conn)` in Phase 8, so that the optional
        # `create_time_utc` column is named only when the database actually has it.
        for sql in ("_process_sql", "_CONN_SQL", "_SYSMON_SQL"):
            assert sql in source
        # The three FROM targets must all be production tables.
        assert "FROM raw_processes" in source
        assert "FROM raw_connections" in source
        assert "FROM raw_logs" in source

    def test_does_not_import_sklearn(self):
        """Feature extraction runs inside the API process; it must stay dependency-light."""
        source = open(mlf.__file__, encoding="utf-8").read()
        assert "import sklearn" not in source
        assert "from sklearn" not in source


# --------------------------------------------------------------------------- scalar helpers

class TestScalarHelpers:
    def test_entropy_ordering(self):
        assert mlf.shannon_entropy("aaaaaaaa") == 0.0
        assert mlf.shannon_entropy("") == 0.0
        assert mlf.shannon_entropy(None) == 0.0
        low = mlf.shannon_entropy("cmd.exe /c dir")
        high = mlf.shannon_entropy("SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA")
        assert high > low

    @pytest.mark.parametrize("path,expected", [
        (r"C:\Windows\System32\cmd.exe", "system32"),
        (r"C:\Windows\SysWOW64\cmd.exe", "system32"),
        (r"C:\Windows\Temp\x.exe", "temp"),
        (r"C:\Users\bob\AppData\Local\Temp\x.exe", "temp"),
        (r"C:\Users\bob\Downloads\x.exe", "downloads"),
        (r"C:\Users\bob\AppData\Roaming\x.exe", "appdata"),
        (r"C:\ProgramData\x.exe", "programdata"),
        (r"C:\Program Files\App\x.exe", "program_files"),
        (r"C:\Windows\explorer.exe", "windows_other"),
        (r"C:\Users\bob\Desktop\x.exe", "user_other"),
        (r"\\server\share\x.exe", "unc"),
        (r"C:\evil.exe", "root_drive"),
        (r"D:\stuff\x.exe", "other"),
        (None, "missing"),
    ])
    def test_path_category(self, path, expected):
        assert mlf.path_category(path) == expected

    def test_path_categories_are_exhaustive(self):
        """Every value path_category can return must have a one-hot column."""
        samples = [r"C:\Windows\System32\a.exe", r"C:\Windows\Temp\a.exe",
                   r"C:\Users\b\Downloads\a.exe", r"\\srv\s\a.exe", r"C:\a.exe",
                   r"D:\x\a.exe", None, "", r"C:\Program Files\a\b.exe"]
        for s in samples:
            assert mlf.path_category(s) in mlf.PATH_CATEGORIES

    def test_masquerade_detection(self):
        # system binary from a system dir -> fine
        assert mlf.is_masquerading("svchost.exe", r"C:\Windows\System32\svchost.exe") == 0.0
        # same name from a temp dir -> masquerading
        assert mlf.is_masquerading("svchost.exe", r"C:\Temp\svchost.exe") == 1.0
        # not a system binary name -> not applicable
        assert mlf.is_masquerading("myapp.exe", r"C:\Temp\myapp.exe") == 0.0
        # unknown path -> NaN, never a claim of innocence
        assert math.isnan(mlf.is_masquerading("svchost.exe", None))
        assert math.isnan(mlf.is_masquerading(None, r"C:\x.exe"))

    def test_longest_b64_run(self):
        assert mlf.longest_b64_run("cmd /c dir") == 0.0
        assert mlf.longest_b64_run("-enc " + "A" * 40) == 40.0
        assert mlf.longest_b64_run(None) == 0.0

    @pytest.mark.parametrize("addr,expected", [
        ("10.0.0.1", True), ("192.168.1.1", True), ("172.16.0.1", True),
        ("127.0.0.1", True), ("169.254.1.1", True),
        ("8.8.8.8", False), ("93.184.216.34", False),
        ("not-an-ip", None), (None, None), ("", None),
    ])
    def test_private_ip(self, addr, expected):
        assert mlf.is_private_ip(addr) is expected

    def test_classify_user(self):
        assert mlf.classify_user(r"NT AUTHORITY\SYSTEM")["user_is_system"] == 1.0
        assert mlf.classify_user(r"NT AUTHORITY\NETWORK SERVICE")["user_is_service_account"] == 1.0
        assert mlf.classify_user(r"CORP\administrator")["user_is_admin_like"] == 1.0
        assert mlf.classify_user(r"CORP\bob")["user_is_domain"] == 1.0
        # NT AUTHORITY is a pseudo-domain, not a real one
        assert mlf.classify_user(r"NT AUTHORITY\SYSTEM")["user_is_domain"] == 0.0
        unknown = mlf.classify_user(None)
        assert unknown["user_present"] == 0.0
        assert math.isnan(unknown["user_is_system"])

    def test_double_extension(self):
        assert mlf._RX_DOUBLE_EXT.search("invoice.pdf.exe")
        assert mlf._RX_DOUBLE_EXT.search("photo.jpg.scr")
        assert not mlf._RX_DOUBLE_EXT.search("setup.exe")
        assert not mlf._RX_DOUBLE_EXT.search("archive.tar.gz")


class TestNanTruthinessRegression:
    """float('nan') is truthy, which silently broke an earlier implementation.

    `_col` normalises every missing marker to None so downstream `if v` is safe.
    """

    def test_nan_is_truthy_in_python(self):
        assert bool(float("nan")) is True          # the trap itself

    def test_col_normalises_all_missing_markers(self):
        frame = pd.DataFrame({"x": [None, float("nan"), np.nan, "ok", pd.NA]})
        assert mlf._col(frame, "x") == [None, None, None, "ok", None]

    def test_col_handles_absent_column(self):
        frame = pd.DataFrame({"a": [1, 2, 3]})
        assert mlf._col(frame, "missing") == [None, None, None]

    def test_num_always_returns_aligned_series(self):
        frame = pd.DataFrame({"a": [1, 2, 3]})
        absent = mlf._num(frame, "nope")
        assert isinstance(absent, pd.Series)
        assert len(absent) == 3 and absent.isna().all()
        present = mlf._num(frame, "a")
        assert isinstance(present, pd.Series) and present.tolist() == [1.0, 2.0, 3.0]


# --------------------------------------------------------------------------- transform

class TestTransformOutput:
    def test_shape_and_order(self, populated_db):
        X, frame = _matrix(populated_db["db"])
        assert list(X.columns) == list(mlf.FEATURE_NAMES)
        assert len(X) == len(frame) == 4
        assert X.dtypes.eq("float64").all(), "every feature must be numeric"

    def test_t1_tier_omits_sysmon_entirely(self, populated_db):
        X, _ = _matrix(populated_db["db"], tier=mlf.TIER_T1)
        assert list(X.columns) == list(mlf.T1_FEATURES)
        assert not [c for c in X.columns if c.startswith("sysmon_")]

    def test_empty_input_still_yields_the_contract(self, tmp_db):
        X, frame = _matrix(tmp_db)
        assert frame.empty
        assert list(X.columns) == list(mlf.FEATURE_NAMES)
        assert len(X) == 0

    def test_encoded_powershell_is_flagged(self, populated_db):
        X, frame = _matrix(populated_db["db"])
        idx = frame.index[frame["pid"] == 1000][0]
        row = X.loc[idx]
        assert row["cmdline_has_encoded_flag"] == 1.0
        assert row["cmdline_has_hidden_window"] == 1.0
        assert row["cmdline_has_policy_bypass"] == 1.0
        assert row["cmdline_longest_b64_run"] >= 20
        assert row["exe_is_lolbin"] == 1.0
        assert row["exe_is_script_host"] == 1.0
        assert row["path_cat_system32"] == 1.0
        assert row["sha256_present"] == 1.0

    def test_masquerading_child_is_flagged(self, populated_db):
        X, frame = _matrix(populated_db["db"])
        idx = frame.index[frame["pid"] == 1001][0]
        row = X.loc[idx]
        assert row["exe_masquerades_system"] == 1.0, "svchost.exe from a Temp path"
        assert row["path_cat_temp"] == 1.0
        assert row["parent_is_shell"] == 1.0, "parent is powershell.exe"
        assert row["parent_cmdline_has_encoded_flag"] == 1.0
        assert row["user_is_system"] == 1.0
        assert row["sha256_present"] == 0.0

    def test_tree_shape(self, populated_db):
        X, frame = _matrix(populated_db["db"])
        by_pid = {int(p): X.loc[i] for i, p in zip(frame.index, frame["pid"])}
        assert by_pid[1000]["child_count"] == 1.0
        assert by_pid[1001]["child_count"] == 1.0
        assert by_pid[1002]["child_count"] == 0.0
        # 1002 -> 1001 -> 1000 -> (4, absent) : depth counts resolvable ancestors
        assert by_pid[1002]["tree_depth"] >= 2.0
        assert by_pid[2000]["is_orphan"] == 1.0, "ppid 9999 is not in the collection"
        assert by_pid[1001]["is_orphan"] == 0.0

    def test_temporal_features(self, populated_db):
        X, _ = _matrix(populated_db["db"])
        # hour_of_day was removed in Phase 7b.1: PSI 8.67 between corpus and live, because
        # it encoded when the 2020 lab captures ran rather than anything behavioural.
        assert "hour_of_day" not in X.columns
        assert (X["is_off_hours"] == 1.0).all()
        assert (X["is_weekend"] == 1.0).all()      # 2026-03-01 is a Sunday

    def test_burst_features_are_nan_without_a_process_start_time(self, populated_db):
        """No `create_time_utc`, no timing features - and specifically not 0.

        Rewritten in Phase 8. The original version asserted NaN when a collection had a
        single *collection* timestamp, which is how the features were defined then and is
        exactly why they were NaN on every live host: a psutil sweep always has one. The
        condition that matters is whether each process reported its own start time.
        """
        X, _ = _matrix(populated_db["db"])
        # the shared fixture inserts no create_time_utc
        for col in ("procs_within_5s", "seconds_since_parent_start"):
            assert X[col].isna().all(), col


class TestMissingIsNotZero:
    """The invariant that keeps corpus artefacts out of the model."""

    def test_absent_cmdline_yields_nan_not_zero(self, populated_db):
        X, frame = _matrix(populated_db["db"])
        idx = frame.index[frame["pid"] == 2000][0]     # the row with cmdline=None
        row = X.loc[idx]
        assert row["cmdline_present"] == 0.0           # the indicator IS zero
        for col in ("cmdline_len", "cmdline_entropy", "cmdline_digit_ratio",
                    "cmdline_has_encoded_flag", "cmdline_url_count"):
            assert math.isnan(row[col]), f"{col} must be NaN when there is no cmdline"

    def test_absent_path_yields_nan_depth(self, populated_db):
        X, frame = _matrix(populated_db["db"])
        idx = frame.index[frame["pid"] == 2000][0]
        assert math.isnan(X.loc[idx, "path_depth"])
        assert X.loc[idx, "path_cat_missing"] == 1.0

    def test_process_without_connections_is_nan_not_zero(self, populated_db):
        X, frame = _matrix(populated_db["db"])
        idx = frame.index[frame["pid"] == 1000][0]     # no connection rows for pid 1000
        row = X.loc[idx]
        assert row["conn_available"] == 0.0
        for col in ("conn_count", "conn_distinct_remote_ips", "conn_external_count",
                    "conn_external_ratio", "conn_suspicious_port_count"):
            assert math.isnan(row[col]), col

    def test_connection_aggregates_when_present(self, populated_db):
        X, frame = _matrix(populated_db["db"])
        idx = frame.index[frame["pid"] == 1001][0]
        row = X.loc[idx]
        assert row["conn_available"] == 1.0
        assert row["conn_count"] == 2.0
        assert row["conn_distinct_remote_ips"] == 2.0
        assert row["conn_external_count"] == 1.0       # only 93.184.216.34 is public
        assert row["conn_external_ratio"] == 0.5
        assert row["conn_suspicious_port_count"] == 1.0   # port 4444
        assert row["conn_status_available"] == 1.0
        assert row["conn_established_count"] == 1.0
        assert row["conn_listen_count"] == 1.0

    def test_sysmon_absent_gives_nan_for_every_t2_feature(self, populated_db):
        """No source='sysmon' rows here, so T2 must be unknown - not a row of zeros."""
        X, _ = _matrix(populated_db["db"])
        assert (X["sysmon_available"] == 0.0).all()
        for name in mlf.T2_FEATURES:
            if name == "sysmon_available":
                continue
            assert X[name].isna().all(), f"{name} must be NaN when Sysmon is absent"


class TestSysmonTierTwo:
    def _with_sysmon(self, db_path, host_id):
        import json
        conn = database.connect(db_path)
        ts = "2026-03-01T22:30:00+00:00"

        def add_log(eid, fields):
            conn.execute(
                """INSERT INTO raw_logs (host_id, collection_id, collected_at_utc, source,
                                          event_id, event_time_utc, payload_json)
                   VALUES (?,?,?,'sysmon',?,?,?)""",
                (host_id, "col-1", ts, eid, ts, json.dumps({"fields": fields})))

        add_log(1, {"ProcessId": "1001", "Image": r"C:\Temp\svchost.exe",
                    "OriginalFileName": "realname.exe", "IntegrityLevel": "High",
                    "Description": "", "Company": "", "TerminalSessionId": "1"})
        add_log(7, {"ProcessId": "1001", "ImageLoaded": r"C:\Temp\eviltool.dll",
                    "SignatureStatus": "Unavailable", "Signed": "false"})
        add_log(11, {"ProcessId": "1001", "TargetFilename": r"C:\Temp\dropped.exe"})
        add_log(13, {"ProcessId": "1001",
                     "TargetObject": r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\x"})
        add_log(22, {"ProcessId": "1001", "QueryName": "c2.example.com", "QueryStatus": "0"})
        add_log(22, {"ProcessId": "1001", "QueryName": "dead.example.com", "QueryStatus": "9003"})
        add_log(8, {"SourceProcessId": "1001", "TargetProcessId": "1002"})
        conn.commit()
        conn.close()

    def test_sysmon_features_populate(self, populated_db):
        self._with_sysmon(populated_db["db"], populated_db["host_id"])
        X, frame = _matrix(populated_db["db"])
        idx = frame.index[frame["pid"] == 1001][0]
        row = X.loc[idx]
        assert row["sysmon_available"] == 1.0
        assert row["sysmon_integrity_level"] == 3.0            # High
        assert row["sysmon_original_name_mismatch"] == 1.0     # renamed binary
        assert row["sysmon_has_description"] == 0.0
        assert row["sysmon_image_load_count"] == 1.0
        assert row["sysmon_image_load_unsigned"] == 1.0
        assert row["sysmon_image_load_from_temp"] == 1.0
        assert row["sysmon_file_create_count"] == 1.0
        assert row["sysmon_registry_persistence"] == 1.0
        assert row["sysmon_dns_query_count"] == 2.0
        assert row["sysmon_dns_distinct_domains"] == 2.0
        assert row["sysmon_dns_failure_ratio"] == 0.5
        assert row["sysmon_remote_thread_out"] == 1.0

    def test_remote_thread_target_side(self, populated_db):
        self._with_sysmon(populated_db["db"], populated_db["host_id"])
        X, frame = _matrix(populated_db["db"])
        idx = frame.index[frame["pid"] == 1002][0]
        assert X.loc[idx, "sysmon_remote_thread_in"] == 1.0

    def test_sysmon_present_but_process_idle_gives_zero_not_nan(self, populated_db):
        """Distinguishing 'no Sysmon' from 'Sysmon saw nothing' is the whole point."""
        self._with_sysmon(populated_db["db"], populated_db["host_id"])
        X, frame = _matrix(populated_db["db"])
        idx = frame.index[frame["pid"] == 2000][0]      # no sysmon events for this pid
        row = X.loc[idx]
        assert row["sysmon_available"] == 1.0
        assert row["sysmon_image_load_count"] == 0.0, "a true zero, because Sysmon was on"
        assert row["sysmon_dns_query_count"] == 0.0


# --------------------------------------------------------------------------- fitted stats

class TestFittedStatsFoldSafety:
    def test_no_stats_means_nan_not_a_guess(self, populated_db):
        X, _ = _matrix(populated_db["db"], with_stats=False)
        for col in mlf.FITTED_FEATURES:
            assert X[col].isna().all(), f"{col} must be NaN without fitted statistics"

    def test_stats_produce_finite_rarities(self, populated_db):
        X, _ = _matrix(populated_db["db"], with_stats=True)
        assert X["process_name_rarity"].notna().any()
        assert (X["process_name_rarity"].dropna() >= 0).all()

    def test_rarer_name_scores_higher(self):
        frame = pd.DataFrame({
            "name": ["svchost.exe"] * 50 + ["weird.exe"],
            "parent_name": ["services.exe"] * 51,
        })
        stats = mlf.fit_stats(frame)
        assert stats.name_rarity("weird.exe") > stats.name_rarity("svchost.exe")

    def test_unseen_name_is_finite_and_rarest(self):
        frame = pd.DataFrame({"name": ["a.exe"] * 10, "parent_name": ["b.exe"] * 10})
        stats = mlf.fit_stats(frame)
        unseen = stats.name_rarity("never-seen.exe")
        assert math.isfinite(unseen)
        assert unseen > stats.name_rarity("a.exe")

    def test_pair_rarity_captures_lineage(self):
        frame = pd.DataFrame({
            "name": ["cmd.exe"] * 30 + ["cmd.exe"],
            "parent_name": ["explorer.exe"] * 30 + ["winword.exe"],
        })
        stats = mlf.fit_stats(frame)
        common = stats.pair_rarity("explorer.exe", "cmd.exe")
        rare = stats.pair_rarity("winword.exe", "cmd.exe")
        assert rare > common, "Office spawning a shell must be rarer than Explorer doing so"

    def test_stats_round_trip_through_json(self):
        frame = pd.DataFrame({"name": ["a.exe", "b.exe"], "parent_name": ["p.exe", "p.exe"]})
        stats = mlf.fit_stats(frame)
        revived = mlf.FeatureStats.from_dict(stats.to_dict())
        assert revived.total == stats.total
        assert revived.name_rarity("a.exe") == stats.name_rarity("a.exe")
        assert revived.pair_rarity("p.exe", "a.exe") == stats.pair_rarity("p.exe", "a.exe")

    def test_empty_stats_are_inert(self):
        empty = mlf.FeatureStats()
        assert math.isnan(empty.name_rarity("x.exe"))
        assert math.isnan(empty.pair_rarity("a", "b"))


# --------------------------------------------------------------------------- skew audit

class TestMissingnessReport:
    def test_report_covers_every_feature(self, populated_db):
        X, _ = _matrix(populated_db["db"])
        report = mlf.missingness_report(X)
        assert set(report["feature"]) == set(mlf.FEATURE_NAMES)
        assert report["missing_pct"].between(0, 100).all()

    def test_report_on_empty_matrix(self):
        report = mlf.missingness_report(pd.DataFrame())
        assert report.empty
