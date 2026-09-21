"""The plain-language layer between the models and the Threat Hunting page.

The page is read by security analysts. These tests keep it that way as the ML layer
changes: a new feature cannot ship without a label an analyst understands, and no
performance sentence can appear that the model artefact does not back with a number.
"""
import pytest

from server.engine import ml_features as mlf
from server.engine import ml_vocabulary as vocab


# --------------------------------------------------------------------------- coverage

class TestEveryFeatureSpeaksSecurity:
    def test_every_model_feature_has_a_label(self):
        """The guard: adding a feature without a translation fails the build.

        Without it the page would silently fall back to a prettified column name such
        as "Conn max remote port", which is exactly the jargon this layer removes.
        """
        missing = [f for f in mlf.FEATURE_NAMES if f not in vocab.INDICATORS]
        assert not missing, f"features without an analyst-facing label: {missing}"

    def test_no_label_for_a_feature_that_does_not_exist(self):
        stale = [f for f in vocab.INDICATORS if f not in mlf.FEATURE_NAMES]
        assert not stale, f"labels for features no longer in the spec: {stale}"

    def test_labels_are_words_not_column_names(self):
        for feature, (neutral, higher, lower) in vocab.INDICATORS.items():
            for text in (neutral, higher, lower):
                if text is None:
                    continue
                assert "_" not in text, f"{feature}: {text!r} reads like a column name"
                assert text[0].isupper(), f"{feature}: {text!r} should be a sentence fragment"

    def test_every_feature_has_a_category(self):
        for feature in mlf.FEATURE_NAMES:
            assert vocab.indicator({"feature": feature})["category"] != "Behaviour", feature


# --------------------------------------------------------------------------- indicators

class TestIndicators:
    def test_direction_picks_the_specific_wording(self):
        assert vocab.indicator({"feature": "child_count", "direction": "higher",
                                "deviation": 12})["text"] == "Spawns many child processes"
        assert vocab.indicator({"feature": "child_count", "direction": "lower",
                                "deviation": 4})["text"] == "Spawns fewer children than normal"

    def test_old_findings_without_direction_get_neutral_wording(self):
        assert vocab.indicator({"feature": "child_count", "deviation": 4})["text"] == \
            "Unusual child count"

    def test_direction_without_a_meaningful_reading_falls_back_to_neutral(self):
        out = vocab.indicator({"feature": "cmdline_digit_ratio", "direction": "lower",
                               "deviation": 5})
        assert out["text"] == "Unusual command-line characters"

    def test_yes_no_indicators_show_presence_not_a_weak_bar(self):
        """A 0/1 column always deviates by exactly 1.0 - as a bar that would read 'mild'."""
        out = vocab.indicator({"feature": "cmdline_has_encoded_flag", "direction": "higher",
                               "deviation": 1.0})
        assert out["bars"] is None and out["strength"] == "present"
        assert out["text"].startswith("Encoded command")

    @pytest.mark.parametrize("deviation, bars", [(1.5, 1), (4, 2), (51665.0, 3), ("x", 1)])
    def test_strength_bars(self, deviation, bars):
        out = vocab.indicator({"feature": "conn_max_remote_port", "direction": "higher",
                               "deviation": deviation})
        assert out["bars"] == bars

    def test_unknown_feature_still_renders_readably(self):
        out = vocab.indicator({"feature": "hour_of_day", "deviation": 9})
        assert out["text"] == "Hour of day"
        assert out["feature"] == "hour_of_day"

    def test_duplicate_wordings_are_merged(self):
        explanation = {"top_features": [
            {"feature": "cmdline_digit_ratio", "deviation": 5},
            {"feature": "cmdline_upper_ratio", "deviation": 4}]}   # same neutral text
        assert len(vocab.indicators(explanation)) == 1

    def test_malformed_explanations_do_not_raise(self):
        assert vocab.indicators(None) == []
        assert vocab.indicators({"top_features": ["junk", None, {}]})[0]["text"]


# --------------------------------------------------------------------------- scores

class TestScores:
    @pytest.mark.parametrize("confidence, level", [
        (0.95, "High"), (0.8, "High"), (0.6, "Elevated"), (0.3, "Low"), (0.05, "Minimal")])
    def test_likelihood_levels(self, confidence, level):
        assert vocab.likelihood(confidence)["level"] == level

    def test_unscored_is_none_not_zero(self):
        """'Not scored' must never read as 'confidently benign'."""
        assert vocab.likelihood(None) is None
        assert vocab.likelihood(float("nan")) is None

    @pytest.mark.parametrize("score, text", [
        (0.9999, "Top 0.1%"), (0.9987, "Top 0.1%"), (0.995, "Top 0.5%"), (0.9, "Top 10%")])
    def test_rarity(self, score, text):
        assert vocab.rarity(score)["text"] == text


# --------------------------------------------------------------------------- ATT&CK

class TestTactics:
    def test_known_tactics_carry_their_mitre_id(self):
        t = vocab.tactic("lateral_movement")
        assert t == {"name": "Lateral Movement", "id": "TA0008",
                     "url": "https://attack.mitre.org/tactics/TA0008/"}

    def test_every_tactic_the_model_can_emit_is_mapped(self):
        from server.engine import ml_tactic
        for name in ("credential_access", "defense_evasion", "lateral_movement",
                     "persistence", "privilege_escalation", "discovery", "execution"):
            assert vocab.tactic(name)["id"], name
        assert vocab.tactic(ml_tactic.OTHER_CLASS)["id"] is None


# --------------------------------------------------------------------------- engines

class TestLabResults:
    def test_sentences_come_from_the_artefact_numbers(self):
        out = vocab.lab_results("triage", {"precision_at_25": 0.96, "recall_at_fpr_0.01": 0.8244})
        assert out == ["24 of its 25 highest-ranked leads were real attacks.",
                       "Catches 82% of attacks while mis-flagging 1 in 100 benign processes."]

    def test_no_numbers_no_claims(self):
        """A missing metric must produce no sentence, never an invented one."""
        assert vocab.lab_results("anomaly", {}) == []
        assert vocab.lab_results("tactic", {}, None) == []

    def test_tactic_sentence_uses_the_measured_gate(self):
        out = vocab.lab_results("tactic", {}, {"precision_pct": 80, "coverage_pct": 34})
        assert "80%" in out[0] and "34%" in out[1]


class TestEngineCards:
    def _ml(self, **entries):
        return {"models": list(entries.values())}

    def test_statuses(self):
        ml = self._ml(
            a={"model_type": "anomaly", "tier": "t1", "loadable": True, "metrics": {}},
            b={"model_type": "triage", "tier": "t1", "loadable": False},
            c={"model_type": "tactic", "tier": "t1", "loadable": True})
        cards = {c["type"]: c for c in vocab.engine_cards(ml)}
        assert cards["anomaly"]["status"] == "Online"
        assert cards["triage"]["status"].startswith("Offline")
        assert cards["tactic"]["status"] == "Online - advisory"

    def test_missing_engine_is_reported_not_hidden(self):
        cards = vocab.engine_cards({"models": []})
        assert [c["status"] for c in cards] == ["Not installed"] * 3

    def test_t1_is_the_served_tier_shown(self):
        ml = self._ml(
            b={"model_type": "anomaly", "tier": "t2", "loadable": True, "metrics": {}},
            a={"model_type": "anomaly", "tier": "t1", "loadable": True, "metrics": {}})
        card = vocab.engine_cards(ml)[0]
        assert card["telemetry"] == "Standard (process data)"


class TestDataHealth:
    @pytest.mark.parametrize("verdict, label", [
        ("stable", "Healthy"), ("moderate", "Watch"), ("shifted", "Degraded"), ("?", "Unknown")])
    def test_health_labels(self, verdict, label):
        assert vocab.health(verdict)["label"] == label


class TestExplanationsCarryDirection:
    """ml_anomaly.explain now records which way a feature deviated."""

    def test_explain_reports_direction(self):
        pytest.importorskip("sklearn")
        import numpy as np
        import pandas as pd
        from server.engine import ml_anomaly
        rng = np.random.default_rng(0)
        names = ["a", "b"]
        X = pd.DataFrame(rng.normal(10, 1, (200, 2)), columns=names)
        model = ml_anomaly.AnomalyModel(n_estimators=20).fit(X)
        out = model.explain(pd.DataFrame([[40.0, -20.0]], columns=names), top_k=2)[0]
        directions = {e["feature"]: e["direction"] for e in out}
        assert directions == {"a": "higher", "b": "lower"}


class TestPriority:
    """Priority follows threat likelihood - the signal the queue is sorted by."""

    @pytest.mark.parametrize("confidence, anomaly, label", [
        (0.86, 0.3, "P1"),        # a developer tool: rarity LOW, likelihood high -> P1
        (0.6, 0.999, "P2"),
        (0.3, 0.1, "P3"),
        (0.0, 0.9999, "P4"),      # System Idle Process: rare, nothing like an attack
        (None, 0.9995, "P3"),     # unscored but extremely rare
        (None, 0.5, "P4"),
    ])
    def test_levels(self, confidence, anomaly, label):
        assert vocab.priority(confidence, anomaly)["label"] == label

    def test_priority_is_monotonic_in_likelihood(self):
        order = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}
        ranks = [order[vocab.priority(c, 0.5)["label"]] for c in (0.99, 0.8, 0.5, 0.2, 0.0)]
        assert ranks == sorted(ranks)
