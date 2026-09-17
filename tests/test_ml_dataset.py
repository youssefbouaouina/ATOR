"""Phase 2 tests: dataset assembly, label integrity, and leak-free splitting.

The failure modes worth guarding against here are the silent ones:

* labelling the demo attack fixtures as benign (poisons the negative class);
* losing labels in a join (silently shrinks the positive class);
* letting one capture straddle a train/test split (inflates every metric);
* fitting rarity statistics on all rows before cross-validating (leaks).
"""
import os
import tempfile

import numpy as np
import pandas as pd
import pytest

from ml.datasets import assemble as A
from ml.datasets import labels as labels_mod
from ml.datasets import otrf, otrf_etl
from server import db as database
from server.engine import ml_features as mlf

from tests.test_ml_etl import _make_capture, _sysmon_event


# --------------------------------------------------------------------------- fixtures

@pytest.fixture()
def tiny_corpus():
    """A two-capture corpus: one with an attack chain, one entirely benign."""
    corpus_dir = tempfile.mkdtemp()
    fd, train_db = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.remove(train_db)

    attack = _make_capture(corpus_dir, "credential_access__host__mimikatz_a.zip", [
        _sysmon_event(1, ProcessId="10", Image=r"C:\Temp\mimikatz.exe",
                      CommandLine="mimikatz.exe sekurlsa::logonpasswords",
                      ProcessGuid="{seed}", ParentProcessGuid="{root}",
                      ParentProcessId="4", ParentImage=r"C:\Windows\System32\services.exe",
                      ParentCommandLine="services.exe"),
        _sysmon_event(1, ProcessId="11", Image=r"C:\Windows\System32\cmd.exe",
                      CommandLine="cmd.exe /c dir", ProcessGuid="{kid}",
                      ParentProcessGuid="{seed}", ParentProcessId="10",
                      ParentImage=r"C:\Temp\mimikatz.exe",
                      ParentCommandLine="mimikatz.exe sekurlsa::logonpasswords"),
        _sysmon_event(1, ProcessId="12", Image=r"C:\Windows\System32\notepad.exe",
                      CommandLine="notepad.exe", ProcessGuid="{bg}",
                      ParentProcessGuid="{root}", ParentProcessId="4",
                      ParentImage=r"C:\Windows\System32\services.exe",
                      ParentCommandLine="services.exe"),
    ])
    benign = _make_capture(corpus_dir, "discovery__host__quiet_b.zip", [
        _sysmon_event(1, ProcessId=str(20 + i), Image=rf"C:\Windows\System32\svc{i}.exe",
                      CommandLine=f"svc{i}.exe", ProcessGuid=f"{{q{i}}}",
                      ParentProcessGuid="{root2}", ParentProcessId="4",
                      ParentImage=r"C:\Windows\System32\services.exe",
                      ParentCommandLine="services.exe")
        for i in range(5)
    ])
    otrf_etl.build(train_db, corpus_dir, [attack, benign], rebuild=True, verbose=False)
    labels_mod.label_all(train_db, verbose=False)
    yield train_db
    for suffix in ("", "-wal", "-shm"):
        try:
            os.remove(train_db + suffix)
        except OSError:
            pass


@pytest.fixture()
def live_with_demo(tmp_db):
    """A live DB holding one real host and one demo fixture host."""
    conn = database.connect(tmp_db)
    now = database.now_iso()

    def add_host(client_id, hostname):
        return conn.execute(
            """INSERT INTO hosts (client_id, hostname, os_type, api_key_hash,
                                  enrolled_at_utc, last_seen_utc)
               VALUES (?,?,'windows','x',?,?)""", (client_id, hostname, now, now)).lastrowid

    real = add_host("host-abc123", "DESKTOP-REAL")
    demo = add_host("demo-win-ator-lab", "WIN-ATOR-LAB")

    def add_proc(host_id, collection, pid, name, cmdline, exe):
        conn.execute(
            """INSERT INTO raw_processes (host_id, collection_id, collected_at_utc, pid, ppid,
                                          name, cmdline, exe_path)
               VALUES (?,?,?,?,4,?,?,?)""",
            (host_id, collection, now, pid, name, cmdline, exe))

    for i in range(6):
        add_proc(real, "col-real", 100 + i, f"app{i}.exe", f"app{i}.exe",
                 rf"C:\Program Files\App\app{i}.exe")
    # protected process: psutil could not read the command line
    add_proc(real, "col-real", 200, "svchost.exe", None,
             r"C:\Windows\System32\svchost.exe")
    # the demo fixture's planted attack rows - must never be treated as benign
    add_proc(demo, "col-demo", 4100, "mimikatz.exe", "mimikatz.exe sekurlsa::logonpasswords",
             r"C:\Temp\mimikatz.exe")
    add_proc(demo, "col-demo", 4101, "powershell.exe",
             "powershell.exe -nop -w hidden -enc SQBFAFgA",
             r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
    conn.commit()
    conn.close()
    return tmp_db


# --------------------------------------------------------------------------- assembly

class TestDemoFixtureExclusion:
    """The single most damaging possible mistake in this pipeline."""

    def test_demo_rows_are_not_loaded_as_benign(self, tiny_corpus, live_with_demo):
        ds = A.load(tiny_corpus, live_with_demo, include_local=True)
        names = set(ds.frame.loc[ds.sources == A.SOURCE_LOCAL, "name"].dropna())
        assert "mimikatz.exe" not in names
        assert not any(
            c and "-enc" in str(c)
            for c in ds.frame.loc[ds.sources == A.SOURCE_LOCAL, "cmdline"].dropna())
        assert ds.meta["local_demo_rows_excluded"] == 2

    def test_only_non_demo_hosts_are_selected(self, live_with_demo):
        conn = database.connect(live_with_demo)
        try:
            real = A._real_host_ids(conn)
            clients = {r[0] for r in conn.execute(
                "SELECT client_id FROM hosts WHERE id IN "
                f"({','.join('?' * len(real))})", real)}
        finally:
            conn.close()
        assert all(not c.startswith("demo-") for c in clients)


class TestLabelIntegrity:
    def test_every_corpus_row_receives_a_label(self, tiny_corpus):
        ds = A.load(tiny_corpus, live_db=None, include_local=False)
        conn = database.connect(tiny_corpus)
        try:
            n_proc = conn.execute("SELECT COUNT(*) FROM raw_processes").fetchone()[0]
        finally:
            conn.close()
        # An inner join that drops rows would silently shrink the dataset.
        assert len(ds) == n_proc, "label join must not lose process rows"
        assert set(np.unique(ds.y)) <= {A.LABEL_BENIGN, A.LABEL_MALICIOUS}

    def test_attack_chain_is_positive_and_background_negative(self, tiny_corpus):
        ds = A.load(tiny_corpus, live_db=None, include_local=False)
        by_name = {}
        for name, label in zip(ds.frame["name"], ds.y):
            by_name.setdefault(str(name).lower(), set()).add(int(label))
        assert by_name["mimikatz.exe"] == {A.LABEL_MALICIOUS}
        assert by_name["notepad.exe"] == {A.LABEL_BENIGN}

    def test_tactic_is_set_only_for_positives(self, tiny_corpus):
        ds = A.load(tiny_corpus, live_db=None, include_local=False)
        for tactic, label in zip(ds.tactics, ds.y):
            if label == A.LABEL_BENIGN:
                assert tactic is None or pd.isna(tactic)
            else:
                assert tactic, "a positive must carry its tactic for Component C"

    def test_local_rows_are_benign_and_tagged(self, tiny_corpus, live_with_demo):
        ds = A.load(tiny_corpus, live_with_demo, include_local=True)
        local = ds.sources == A.SOURCE_LOCAL
        assert local.sum() == 7
        assert (ds.y[local] == A.LABEL_BENIGN).all()
        assert ds.meta["local_benign_assumed"] is True


class TestGroupNamespacing:
    def test_local_groups_cannot_collide_with_captures(self, tiny_corpus, live_with_demo):
        ds = A.load(tiny_corpus, live_with_demo, include_local=True)
        local_groups = set(ds.groups[ds.sources == A.SOURCE_LOCAL])
        corpus_groups = set(ds.groups[ds.sources == A.SOURCE_CORPUS])
        assert all(g.startswith("local::") for g in local_groups)
        assert not (local_groups & corpus_groups)

    def test_corpus_group_is_the_capture(self, tiny_corpus):
        ds = A.load(tiny_corpus, live_db=None, include_local=False)
        assert set(ds.groups) == {"credential_access__host__mimikatz_a",
                                  "discovery__host__quiet_b"}


class TestAblationSwitch:
    def test_no_local_yields_corpus_only(self, tiny_corpus, live_with_demo):
        with_local = A.load(tiny_corpus, live_with_demo, include_local=True)
        without = A.load(tiny_corpus, live_with_demo, include_local=False)
        assert len(without) < len(with_local)
        assert set(without.sources) == {A.SOURCE_CORPUS}
        assert without.n_positive == with_local.n_positive, "ablation must not touch positives"

    def test_column_alignment_across_sources(self, tiny_corpus, live_with_demo):
        """The live DB has no T2 aggregate columns; concatenation must still line up."""
        ds = A.load(tiny_corpus, live_with_demo, include_local=True)
        assert not ds.frame.columns.duplicated().any()
        X, _ = A.materialise(ds)
        assert list(X.columns) == list(mlf.FEATURE_NAMES)
        assert len(X) == len(ds)


# --------------------------------------------------------------------------- splitting

class TestGroupHoldoutSplit:
    def test_no_group_straddles_the_split(self, tiny_corpus, live_with_demo):
        ds = A.load(tiny_corpus, live_with_demo, include_local=True)
        train, test = A.group_holdout_split(ds)
        assert not (set(ds.groups[train]) & set(ds.groups[test])), \
            "a capture on both sides leaks sibling processes of the same attack"

    def test_partition_is_exhaustive(self, tiny_corpus, live_with_demo):
        ds = A.load(tiny_corpus, live_with_demo, include_local=True)
        train, test = A.group_holdout_split(ds)
        assert (train | test).all()
        assert not (train & test).any()

    def test_positives_reach_the_test_side(self, tiny_corpus, live_with_demo):
        """With few groups, a naive random split can leave the test set attack-free."""
        ds = A.load(tiny_corpus, live_with_demo, include_local=True)
        _, test = A.group_holdout_split(ds)
        assert (ds.y[test] == A.LABEL_MALICIOUS).sum() >= 1

    def test_deterministic_for_a_given_seed(self, tiny_corpus):
        ds = A.load(tiny_corpus, live_db=None, include_local=False)
        a, _ = A.group_holdout_split(ds, seed=42)
        b, _ = A.group_holdout_split(ds, seed=42)
        assert (a == b).all()

    def test_seed_changes_the_split(self, tiny_corpus, live_with_demo):
        ds = A.load(tiny_corpus, live_with_demo, include_local=True)
        splits = {tuple(A.group_holdout_split(ds, seed=s)[1]) for s in range(6)}
        assert len(splits) > 1, "the split must actually depend on the seed"


class TestFoldSafeStatistics:
    """Rarity features must not see the test folds."""

    def test_stats_are_fitted_only_on_the_train_mask(self, tiny_corpus, live_with_demo):
        ds = A.load(tiny_corpus, live_with_demo, include_local=True)
        train, test = A.group_holdout_split(ds)
        _, stats = A.materialise(ds, train_mask=train)
        # total must equal the number of TRAINING rows, not all rows
        assert stats.total == int(train.sum())
        assert stats.total < len(ds)

    def test_names_unique_to_test_are_absent_from_stats(self, tiny_corpus, live_with_demo):
        ds = A.load(tiny_corpus, live_with_demo, include_local=True)
        train, test = A.group_holdout_split(ds)
        _, stats = A.materialise(ds, train_mask=train)
        train_names = {mlf.basename(n) for n in ds.frame.loc[train, "name"].dropna()}
        test_only = {mlf.basename(n) for n in ds.frame.loc[test, "name"].dropna()} - train_names
        for name in test_only:
            assert name not in stats.name_counts, \
                f"{name!r} appears only in the test split but leaked into the statistics"

    def test_materialise_without_mask_uses_everything(self, tiny_corpus):
        """Correct only for a final fit on the full training set."""
        ds = A.load(tiny_corpus, live_db=None, include_local=False)
        _, stats = A.materialise(ds, train_mask=None)
        assert stats.total == len(ds)

    def test_unseen_test_names_still_score_finite(self, tiny_corpus, live_with_demo):
        import math
        ds = A.load(tiny_corpus, live_with_demo, include_local=True)
        train, test = A.group_holdout_split(ds)
        X, _ = A.materialise(ds, train_mask=train)
        rarity = X.loc[test, "process_name_rarity"].dropna()
        assert rarity.map(math.isfinite).all(), "smoothing must keep unseen names finite"


class TestSummary:
    def test_summary_reports_what_the_report_needs(self, tiny_corpus, live_with_demo):
        ds = A.load(tiny_corpus, live_with_demo, include_local=True)
        s = ds.summary()
        assert s["rows"] == len(ds)
        assert s["malicious"] + s["benign"] == s["rows"]
        assert 0.0 <= s["positive_rate"] <= 1.0
        assert set(s["by_source"]) == {A.SOURCE_CORPUS, A.SOURCE_LOCAL}
        assert s["malicious_by_tactic"]

    def test_subset_keeps_arrays_aligned(self, tiny_corpus, live_with_demo):
        ds = A.load(tiny_corpus, live_with_demo, include_local=True)
        mask = ds.sources == A.SOURCE_CORPUS
        sub = ds.subset(mask)
        assert len(sub) == int(mask.sum())
        assert len(sub.y) == len(sub.groups) == len(sub.tactics) == len(sub)
        assert set(sub.sources) == {A.SOURCE_CORPUS}

    def test_empty_dataset_is_handled(self, tmp_db):
        ds = A.load(tmp_db, live_db=None, include_local=False)
        assert len(ds) == 0
        assert ds.n_positive == 0
