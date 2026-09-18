"""Phase 7 tests: recovered labels, the three-tier spec, burst features, gated tactic hints.

Two of these pin guards that exist because of an *observed* failure rather than a
precaution, and both are called out in place.
"""
import json

import numpy as np
import pandas as pd
import pytest

from server import db as database
from server.engine import ml_features as mlf, ml_integration, ml_tactic


# --------------------------------------------------------------------------- tier system

class TestThreeTierSpec:
    def test_tiers_are_cumulative(self):
        t1 = set(mlf.features_for_tier(mlf.TIER_T1))
        t2 = set(mlf.features_for_tier(mlf.TIER_T2))
        t3 = set(mlf.features_for_tier(mlf.TIER_T3))
        assert t1 < t2 < t3
        assert t3 == set(mlf.FEATURE_NAMES)

    def test_each_tier_is_named_consistently(self):
        for name in mlf.T2_FEATURES:
            assert name.startswith("sysmon_"), name
        for name in mlf.T3_FEATURES:
            assert name.startswith("psh_"), name

    def test_t1_never_leaks_a_higher_tier_feature(self):
        t1 = mlf.features_for_tier(mlf.TIER_T1)
        assert not [n for n in t1 if n.startswith(("sysmon_", "psh_"))]

    def test_unknown_tier_is_rejected(self):
        with pytest.raises(ValueError):
            mlf.tiers_up_to("t9")


class TestHourOfDayRemoved:
    """Removed in 7b.1: PSI 8.67 - it encoded when the 2020 lab captures ran, not behaviour."""

    def test_absent_from_the_spec(self):
        assert "hour_of_day" not in mlf.FEATURE_NAMES

    def test_absent_from_every_group(self):
        """A group naming a removed feature silently breaks features_excluding()."""
        for group, names in mlf.FEATURE_GROUPS.items():
            assert "hour_of_day" not in names, group


# --------------------------------------------------------------------------- burst features

class TestBurstFeatures:
    """Rewritten in Phase 8, and the rewrite is the record of what went wrong.

    Phase 7b.2 defined these over `collected_at_utc` and the tests below asserted that
    behaviour, which is why they passed while the features were NaN on every production host.
    They now insert `create_time_utc` - each process's own start time - because that is what
    the features read, and what makes them mean the same thing in a lab capture and in a live
    sweep. `tests/test_ml_phase8.py` covers the cross-shape equivalence directly.
    """

    def _insert(self, conn, host_id, collection, starts, swept="2026-03-01T09:00:00+00:00"):
        """Insert live-shaped rows: ONE collection timestamp, per-process start times.

        Deliberately live-shaped rather than corpus-shaped. Under the old definition every
        one of these rows would have produced NaN.
        """
        for i, start in enumerate(starts):
            conn.execute(
                """INSERT INTO raw_processes (host_id, collection_id, collected_at_utc,
                                              pid, ppid, name, cmdline, exe_path,
                                              create_time_utc)
                   VALUES (?,?,?,?,4,'a.exe','a.exe',?,?)""",
                (host_id, collection, swept, 100 + i, r"C:.exe", start))
        conn.commit()

    def _matrix(self, conn):
        frame = mlf.extract_process_frame(conn)
        return mlf.transform(frame, stats=mlf.fit_stats(frame), tier=mlf.TIER_T1)

    def test_missing_start_time_yields_nan_not_zero(self, tmp_db, seeded_host):
        """Unknown start time must stay unknown. 0 would say "nothing started near it"."""
        conn = database.connect(tmp_db)
        try:
            self._insert(conn, seeded_host["host_id"], "nostart", [None] * 5)
            X = self._matrix(conn)
            for col in ("procs_within_5s", "seconds_since_parent_start"):
                assert X[col].isna().all(), col
        finally:
            conn.close()

    def test_spaced_processes_fall_outside_the_window(self, tmp_db, seeded_host):
        """Six processes 10s apart: none is within 5s of another, so every count is 0.

        0 and NaN mean different things here and the distinction is load-bearing: 0 is
        "nothing started near this process", NaN is "this host did not say when it started".
        """
        conn = database.connect(tmp_db)
        try:
            self._insert(conn, seeded_host["host_id"], "spread",
                         [f"2026-03-01T10:00:{i * 10:02d}+00:00" for i in range(6)])
            X = self._matrix(conn)
            assert X["procs_within_5s"].notna().all()
            assert (X["procs_within_5s"] == 0.0).all()
        finally:
            conn.close()

    def test_burst_is_detected_when_processes_cluster(self, tmp_db, seeded_host):
        conn = database.connect(tmp_db)
        try:
            starts = [f"2026-03-01T10:00:00.{i}00000+00:00" for i in range(5)]
            starts.append("2026-03-01T10:05:00+00:00")     # one far away
            self._insert(conn, seeded_host["host_id"], "burst", starts)
            X = self._matrix(conn)
            assert X["procs_within_5s"].max() >= 4
            # the outlier is alone in both windows
            assert X["procs_within_5s"].min() == 0.0
        finally:
            conn.close()

    def test_a_sweep_is_no_longer_a_dead_end(self, tmp_db, seeded_host):
        """The regression that Phase 8 exists for, stated at its smallest.

        Every row shares one `collected_at_utc`, as a psutil sweep always does. Under the
        Phase 7b.2 definition this produced NaN for every feature and for every host in
        production.
        """
        conn = database.connect(tmp_db)
        try:
            self._insert(conn, seeded_host["host_id"], "sweep",
                         [f"2026-03-01T10:00:{i:02d}+00:00" for i in range(4)])
            distinct = conn.execute(
                "SELECT COUNT(DISTINCT collected_at_utc) FROM raw_processes "
                "WHERE collection_id='sweep'").fetchone()[0]
            assert distinct == 1, "fixture must be sweep-shaped for this test to mean anything"
            X = self._matrix(conn)
            assert X["procs_within_5s"].notna().all()
        finally:
            conn.close()


# --------------------------------------------------------------------------- tactic gating

def _fit_tactic(seed: int = 0):
    """Fit Component C on synthetic support levels that straddle both gates.

    Class sizes are chosen against the two thresholds, not arbitrarily:

      * three classes at 40 examples  -> above MIN_SUPPORT_TO_SUGGEST (30), so suggestable
      * `persistence` at 15           -> above MIN_EXAMPLES_PER_CLASS (10) so it is LEARNED,
                                          below 30 so it must never be offered
      * `discovery` at 4              -> below 10, folded into OTHER_CLASS

    The middle case is the one worth having: a class that is learnable but not reportable is
    exactly what the support gate exists for, and a fixture without one cannot test it.
    """
    rng = np.random.default_rng(seed)
    names = list(mlf.features_for_tier(mlf.TIER_T1))
    labels, rows = [], []
    signature = {"defense_evasion": 0.0, "lateral_movement": 1.0,
                 "credential_access": 2.0, "persistence": 3.0, "discovery": 4.0}
    for tactic, n in (("defense_evasion", 40), ("lateral_movement", 40),
                      ("credential_access", 40), ("persistence", 15), ("discovery", 4)):
        for _ in range(n):
            # A learnable but separable pattern: one offset column plus noise, so the model
            # has something real to fit and the gates are what decide the output.
            row = rng.normal(0.0, 0.25, len(names))
            row[0] = signature[tactic] + rng.normal(0.0, 0.1)
            rows.append(row)
            labels.append(tactic)
    X = pd.DataFrame(rows, columns=names)
    return ml_tactic.TacticModel().fit(X, labels), X


class TestTacticSupportGate:
    """Component C ships in Phase 7, but only behind guards.

    At Phase 5 it was not deployed at all (50.8% accuracy against a 40.5% majority baseline).
    Phase 7a's label recovery took it to 77.6% precision at p>=0.80 on well-supported classes.
    """

    def test_thinly_supported_class_is_learned_but_not_suggested(self):
        model, X = _fit_tactic()
        assert "persistence" in model.classes_, "it is still learned"
        assert "persistence" not in model.suggestable_, "but never offered to an analyst"
        for row in model.suggest(X, min_probability=0.0):
            assert all(s["tactic"] != "persistence" for s in row)

    def test_well_supported_classes_are_suggestable(self):
        model, _ = _fit_tactic()
        assert set(model.suggestable_) == {"defense_evasion", "lateral_movement",
                                           "credential_access"}

    def test_other_is_never_suggested(self):
        model, X = _fit_tactic()
        for row in model.suggest(X, min_probability=0.0):
            assert all(s["tactic"] != ml_tactic.OTHER_CLASS for s in row)

    def test_gates_round_trip_through_serialisation(self):
        model, _ = _fit_tactic()
        revived = ml_tactic.TacticModel.from_payload(model.to_payload())
        assert revived.suggestable_ == model.suggestable_
        assert revived.class_support_ == model.class_support_

    def test_thresholds_match_the_measured_operating_point(self):
        assert ml_tactic.MIN_SUGGESTION_PROBABILITY == pytest.approx(0.80)
        assert ml_tactic.MIN_SUPPORT_TO_SUGGEST == 30
        assert ml_tactic.MIN_CONFIDENCE_TO_SUGGEST >= 0.5


class TestTacticOutOfDistributionGuard:
    """Regression, from an observed failure.

    Without a confidence gate the tactic model labelled `chrome.exe` and `System Idle Process`
    as `lateral_movement` with probability **1.00** - it is trained on malicious processes
    only, so a benign one is out of distribution and it has no "none of the above" class.
    Component B's answer to "is this an attack?" now gates Component C's "which kind?".
    """

    def _detection(self, conn, host_id, confidence, name="chrome.exe"):
        conn.execute(
            """INSERT INTO detections (host_id, collection_id, rule_type, rule_name, severity,
                                       technique_id, summary, detected_at_utc,
                                       anomaly_score, confidence_score)
               VALUES (?,?,'ml_anomaly',?,'low',NULL,?,?,0.999,?)""",
            (host_id, "col-1", f"ML Anomaly: {name}",
             json.dumps({"pid": "4242", "name": name}), database.now_iso(), confidence))
        conn.commit()

    def test_low_confidence_detection_gets_no_tactic(self, tmp_db, seeded_host):
        conn = database.connect(tmp_db)
        try:
            self._detection(conn, seeded_host["host_id"], confidence=0.05)
            assert ml_integration.suggest_tactics(conn)["suggested"] == 0
            assert conn.execute(
                "SELECT COUNT(*) FROM detections WHERE suggested_tactics IS NOT NULL"
            ).fetchone()[0] == 0
        finally:
            conn.close()

    def test_unscored_detection_is_skipped_not_guessed(self, tmp_db, seeded_host):
        conn = database.connect(tmp_db)
        try:
            conn.execute(
                """INSERT INTO detections (host_id, rule_type, rule_name, severity,
                                           summary, detected_at_utc)
                   VALUES (?,'ml_anomaly','ML Anomaly: x','low',?,?)""",
                (seeded_host["host_id"], json.dumps({"pid": "1"}), database.now_iso()))
            conn.commit()
            assert ml_integration.suggest_tactics(conn)["suggested"] == 0
        finally:
            conn.close()

    def test_rule_detections_are_never_given_a_hint(self, tmp_db, seeded_host):
        """Sigma hits already carry a real technique_id; a hint would only muddy it."""
        conn = database.connect(tmp_db)
        try:
            conn.execute(
                """INSERT INTO detections (host_id, rule_type, rule_name, severity,
                                           technique_id, summary, detected_at_utc,
                                           confidence_score)
                   VALUES (?,'sigma','Encoded PowerShell','high','T1059.001',?,?,0.95)""",
                (seeded_host["host_id"], json.dumps({"pid": "4242"}), database.now_iso()))
            conn.commit()
            ml_integration.suggest_tactics(conn)
            assert conn.execute(
                "SELECT suggested_tactics FROM detections").fetchone()[0] is None
        finally:
            conn.close()

    def test_suggestion_never_raises(self, tmp_db, monkeypatch):
        def explode(*a, **kw):
            raise RuntimeError("simulated failure")
        monkeypatch.setattr(ml_integration, "_suggest_tactics", explode)
        conn = database.connect(tmp_db)
        try:
            assert ml_integration.suggest_tactics(conn)["suggested"] == 0
        finally:
            conn.close()


# --------------------------------------------------------------------------- PowerShell T3

class TestPowerShellTier:
    """T3 is a measured null result for detection, but the plumbing must still be correct."""

    def _insert(self, conn, host_id, pid, payload, context=""):
        conn.execute(
            """INSERT INTO raw_logs (host_id, collection_id, collected_at_utc, source,
                                      event_id, event_time_utc, payload_json)
               VALUES (?,?,?,'powershell',4103,?,?)""",
            (host_id, "col-1", database.now_iso(), database.now_iso(),
             json.dumps({"fields": {"ExecutionProcessID": str(pid),
                                    "Payload": payload, "ContextInfo": context}})))

    def _process(self, conn, host_id, pid, cmdline="powershell.exe -enc AAAA"):
        conn.execute(
            """INSERT INTO raw_processes (host_id, collection_id, collected_at_utc, pid, ppid,
                                          name, cmdline, exe_path)
               VALUES (?,?,?,?,4,'powershell.exe',?,?)""",
            (host_id, "col-1", database.now_iso(), pid, cmdline,
             r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"))

    def test_events_attribute_to_a_process_via_execution_process_id(self, tmp_db, seeded_host):
        """ExecutionProcessID is the SUBJECT process on the PowerShell channel - unlike
        Sysmon, where it is Sysmon's own service pid."""
        host = seeded_host["host_id"]
        conn = database.connect(tmp_db)
        try:
            self._process(conn, host, 1648)
            self._insert(conn, host, 1648,
                         'CommandInvocation(Get-Random): value="/admin/get.php"',
                         'Host Application = powershell.exe -noP -sta -enc ' + "A" * 40)
            conn.commit()
            frame = mlf.extract_process_frame(conn)
            X = mlf.transform(frame, stats=mlf.fit_stats(frame), tier=mlf.TIER_T3)
            row = X.loc[frame.index[frame["pid"] == 1648][0]]
            assert row["psh_available"] == 1.0
            assert row["psh_event_count"] == 1.0
            assert row["psh_has_url"] == 1.0          # the C2 URI in the payload
            assert row["psh_host_app_encoded"] == 1.0
            assert row["psh_distinct_commands"] == 1.0
        finally:
            conn.close()

    def test_unattributable_events_are_dropped(self, tmp_db, seeded_host):
        """ExecutionProcessID 0 (every EID 400/600/800) cannot be attributed."""
        host = seeded_host["host_id"]
        conn = database.connect(tmp_db)
        try:
            self._process(conn, host, 500)
            self._insert(conn, host, 0, "something")
            conn.commit()
            frame = mlf.extract_process_frame(conn)
            X = mlf.transform(frame, stats=mlf.fit_stats(frame), tier=mlf.TIER_T3)
            assert (X["psh_available"] == 0.0).all()
        finally:
            conn.close()

    def test_absent_powershell_logging_yields_nan_not_zero(self, tmp_db, seeded_host):
        conn = database.connect(tmp_db)
        try:
            self._process(conn, seeded_host["host_id"], 700)
            conn.commit()
            frame = mlf.extract_process_frame(conn)
            X = mlf.transform(frame, stats=mlf.fit_stats(frame), tier=mlf.TIER_T3)
            assert (X["psh_available"] == 0.0).all()
            for name in mlf.T3_FEATURES:
                if name == "psh_available":
                    continue
                assert X[name].isna().all(), name
        finally:
            conn.close()

    def test_t1_tier_omits_powershell_entirely(self, tmp_db, seeded_host):
        conn = database.connect(tmp_db)
        try:
            self._process(conn, seeded_host["host_id"], 800)
            conn.commit()
            frame = mlf.extract_process_frame(conn)
            X = mlf.transform(frame, stats=mlf.fit_stats(frame), tier=mlf.TIER_T1)
            assert not [c for c in X.columns if c.startswith("psh_")]
        finally:
            conn.close()

    def test_seed_echoing_psh_features_are_in_the_leak_audit(self):
        """psh_host_app_encoded literally reads the Empire `-enc` seed off the host command
        line, so it must be auditable; psh_has_url and psh_has_crypto_loop are new evidence
        and must not be."""
        echo = set(mlf.SEED_ECHO_FEATURES)
        assert "psh_host_app_encoded" in echo
        assert "psh_has_download_cradle" in echo
        assert "psh_has_iex" in echo
        assert "psh_has_url" not in echo
        assert "psh_has_crypto_loop" not in echo
        assert "psh_payload_to_cmdline_ratio" not in echo
