"""Phase 3 tests: the anomaly model and the evaluation protocol.

An evaluation harness is a measuring instrument, and a broken one produces confident wrong
numbers. These tests check the instrument: that thresholds mean what they claim, that
degenerate scorers cannot produce flattering numbers, that confidence intervals account for
within-capture correlation, and that no fold ever sees its own test data.
"""
import math

import numpy as np
import pandas as pd
import pytest

from ml.datasets import assemble as A
from ml.evaluation import harness as H
from server.engine import ml_anomaly, ml_features as mlf


# --------------------------------------------------------------------------- helpers

_BENIGN_NAMES = ("svchost.exe", "services.exe", "explorer.exe", "RuntimeBroker.exe",
                 "dwm.exe", "taskhostw.exe", "conhost.exe", "SearchIndexer.exe",
                 "spoolsv.exe", "dllhost.exe", "chrome.exe", "msedge.exe")
_BENIGN_DIRS = (r"C:\Windows\System32", r"C:\Windows",
                r"C:\Program Files\Common Files", r"C:\Program Files (x86)\Vendor\App")


def _dataset(n_groups=12, per_group=20, positive_groups=6, seed=0) -> A.Dataset:
    """A synthetic dataset with a learnable signal, grouped like real captures.

    Per-row variation matters here. An earlier version emitted only a handful of distinct
    feature vectors, and the percentile score mapping then collapsed into a few large ties -
    which made the model look as if it ranked benign above malicious when in fact there was
    almost nothing to rank. Realistic jitter keeps the fixture from testing an artefact.
    """
    rng = np.random.default_rng(seed)
    rows, y, groups, tactics, sources = [], [], [], [], []
    for g in range(n_groups):
        malicious_group = g < positive_groups
        for i in range(per_group):
            is_mal = malicious_group and i < 3
            if is_mal:
                blob = "".join(rng.choice(list(
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"),
                    size=int(rng.integers(50, 140))))
                name = rng.choice(["evil.exe", "svchost.exe", "update.exe", "a1b2c3.exe"])
                row = {
                    "name": str(name),
                    "cmdline": f"powershell.exe -nop -w hidden -enc {blob}",
                    "exe_path": rf"C:\Users\u{g}\AppData\Local\Temp\{name}",
                    "sha256": None,
                    "username": rf"LAB\user{g}",
                    "parent_name": str(rng.choice(["winword.exe", "explorer.exe",
                                                   "mshta.exe", "wscript.exe"])),
                    "parent_cmdline": "winword.exe /n",
                    "sibling_count": float(rng.integers(0, 3)),
                    "child_count": float(rng.integers(0, 2)),
                }
            else:
                name = str(rng.choice(_BENIGN_NAMES))
                directory = str(rng.choice(_BENIGN_DIRS))
                row = {
                    "name": name,
                    "cmdline": (f"{name} -k {rng.choice(['netsvcs', 'LocalService', 'DcomLaunch'])} "
                                f"-p -s Svc{rng.integers(1, 40)}"),
                    "exe_path": rf"{directory}\{name}",
                    "sha256": "b" * 64,
                    "username": str(rng.choice([r"NT AUTHORITY\SYSTEM",
                                                r"NT AUTHORITY\NETWORK SERVICE",
                                                rf"LAB\user{g}"])),
                    "parent_name": str(rng.choice(["services.exe", "svchost.exe",
                                                   "explorer.exe"])),
                    "parent_cmdline": "services.exe",
                    "sibling_count": float(rng.integers(5, 40)),
                    "child_count": float(rng.integers(0, 12)),
                }
            row.update({
                "id": len(rows) + 1,
                "host_id": 1 + (g % 3),
                "collection_id": f"cap-{g}",
                "collected_at_utc": f"2026-03-02T{8 + (i % 12):02d}:00:00+00:00",
                "pid": int(rng.integers(500, 9000)),
                "ppid": 4,
                "parent_exe_path": r"C:\Windows\explorer.exe",
                "sysmon_available": 0.0,
                "tree_depth": float(rng.integers(1, 4)),
                "is_orphan": 0.0,
            })
            rows.append(row)
            y.append(A.LABEL_MALICIOUS if is_mal else A.LABEL_BENIGN)
            groups.append(f"cap-{g}")
            tactics.append("execution" if is_mal else None)
            sources.append(A.SOURCE_CORPUS)
    return A.Dataset(pd.DataFrame(rows), np.array(y), np.array(groups),
                     np.array(tactics, dtype=object), np.array(sources))


def _mixed_dataset() -> A.Dataset:
    """Corpus rows (with positives) plus local rows (all benign), like the real one."""
    ds = _dataset()
    local = ds.frame.head(30).copy()
    local["collection_id"] = "col-live"
    local["sysmon_available"] = 0.0
    frame = pd.concat([ds.frame, local], ignore_index=True)
    return A.Dataset(
        frame=frame,
        y=np.concatenate([ds.y, np.zeros(len(local), dtype=int)]),
        groups=np.concatenate([ds.groups, np.full(len(local), "local::col-live")]),
        tactics=np.concatenate([ds.tactics, np.full(len(local), None, dtype=object)]),
        sources=np.concatenate([ds.sources, np.full(len(local), A.SOURCE_LOCAL)]),
    )


# --------------------------------------------------------------------------- metrics

class TestThresholdMetrics:
    def test_recall_at_fpr_holds_the_fpr(self):
        rng = np.random.default_rng(1)
        y = np.array([0] * 1000 + [1] * 100)
        scores = np.concatenate([rng.normal(0, 1, 1000), rng.normal(3, 1, 100)])
        res = H.recall_at_fpr(y, scores, 0.01)
        assert abs(res["actual_fpr"] - 0.01) < 0.005, "the delivered FPR must match the target"
        assert 0.0 <= res["recall"] <= 1.0

    def test_perfect_separation_gives_full_recall(self):
        y = np.array([0] * 50 + [1] * 50)
        scores = np.concatenate([np.zeros(50), np.ones(50)])
        assert H.recall_at_fpr(y, scores, 0.01)["recall"] == 1.0

    def test_inverted_scores_give_no_recall(self):
        y = np.array([0] * 50 + [1] * 50)
        scores = np.concatenate([np.ones(50), np.zeros(50)])
        assert H.recall_at_fpr(y, scores, 0.01)["recall"] == 0.0

    def test_fp_cost_at_recall_is_consistent(self):
        rng = np.random.default_rng(2)
        y = np.array([0] * 1000 + [1] * 100)
        scores = np.concatenate([rng.normal(0, 1, 1000), rng.normal(2, 1, 100)])
        res = H.fp_cost_at_recall(y, scores, 0.7)
        assert res["actual_recall"] >= 0.65
        assert 0 <= res["fp_per_1000_benign"] <= 1000

    def test_precision_at_k(self):
        y = np.array([1, 1, 0, 0, 0])
        scores = np.array([0.9, 0.8, 0.7, 0.6, 0.5])
        assert H.precision_at_k(y, scores, 2) == 1.0
        assert H.precision_at_k(y, scores, 4) == 0.5
        assert H.precision_at_k(y, scores, 99) == pytest.approx(0.4)

    def test_single_class_returns_nan_not_a_number(self):
        y = np.zeros(10, dtype=int)
        out = H.core_metrics(y, np.random.default_rng(0).random(10))
        assert math.isnan(out["pr_auc"])
        assert math.isnan(out["roc_auc"])


class TestBinaryScorerIsNotFlattered:
    """A rule set must not be able to report 100% recall at 1% FPR."""

    def test_binary_scorer_is_detected(self):
        y = np.array([0] * 90 + [1] * 10)
        scores = np.zeros(100)
        scores[90:95] = 1.0                      # fires on 5 of 10 positives, no FPs
        out = H.core_metrics(y, scores)
        assert out["binary_scorer"] is True
        assert out["distinct_scores"] == 2

    def test_threshold_metrics_are_nan_for_binary_scores(self):
        y = np.array([0] * 90 + [1] * 10)
        scores = np.zeros(100)
        scores[90:95] = 1.0
        out = H.core_metrics(y, scores)
        # Without the guard these come back as recall=1.0 at an actual FPR of 100%.
        assert math.isnan(out["recall_at_fpr_0.01"])
        assert math.isnan(out["precision_at_25"])
        assert math.isnan(out["fp_per_1000_at_recall_0.7"])

    def test_continuous_scorer_keeps_its_metrics(self):
        rng = np.random.default_rng(3)
        y = np.array([0] * 200 + [1] * 40)
        scores = np.concatenate([rng.normal(0, 1, 200), rng.normal(2, 1, 40)])
        out = H.core_metrics(y, scores)
        assert out["binary_scorer"] is False
        assert not math.isnan(out["recall_at_fpr_0.01"])

    def test_actual_fpr_is_always_reported(self):
        y = np.array([0] * 90 + [1] * 10)
        scores = np.zeros(100)
        scores[90:95] = 1.0
        out = H.core_metrics(y, scores)
        # Visible even for a binary scorer, so a reader can see the request was not honoured.
        assert out["actual_fpr_at_0.01"] == 1.0


class TestGroupBootstrap:
    def test_interval_brackets_the_point_estimate(self):
        rng = np.random.default_rng(4)
        ds = _dataset()
        scores = rng.random(len(ds))
        point = H.core_metrics(ds.y, scores)["pr_auc"]
        ci = H.group_bootstrap_ci(ds.y, scores, ds.groups, "pr_auc", n_boot=200)
        assert ci["lo"] <= point <= ci["hi"] or abs(ci["median"] - point) < 0.3

    def test_group_bootstrap_is_wider_when_rows_are_perfectly_correlated(self):
        """The case group bootstrapping exists for.

        Here every row inside a group is identical, so a group of 40 rows carries exactly one
        group's worth of information. A row bootstrap treats it as 40 independent
        observations and reports a falsely narrow interval; resampling groups does not.

        (This is not universally true for any dataset - with very few positives a row
        bootstrap can be *wider*, because the number of positives it draws varies wildly.
        The claim being tested is the specific one that motivates the design.)
        """
        n_groups, per_group = 10, 40
        y, groups, scores = [], [], []
        for g in range(n_groups):
            label = A.LABEL_MALICIOUS if g < 4 else A.LABEL_BENIGN
            # Score fixed per group, mildly overlapping between classes.
            value = 0.6 + 0.1 * g if label == A.LABEL_MALICIOUS else 0.4 + 0.1 * g
            y += [label] * per_group
            groups += [f"g{g}"] * per_group
            scores += [value] * per_group
        y, groups, scores = np.array(y), np.array(groups), np.array(scores)

        group_ci = H.group_bootstrap_ci(y, scores, groups, "pr_auc", n_boot=400)
        row_ci = H.group_bootstrap_ci(
            y, scores, np.arange(len(y)).astype(str), "pr_auc", n_boot=400)
        assert (group_ci["hi"] - group_ci["lo"]) > (row_ci["hi"] - row_ci["lo"]), (
            f"group CI {group_ci} should be wider than row CI {row_ci}")

    def test_degenerate_resamples_are_skipped(self):
        y = np.array([0] * 20 + [1] * 2)
        groups = np.array(["g0"] * 20 + ["g1"] * 2)
        ci = H.group_bootstrap_ci(y, np.random.default_rng(0).random(22), groups,
                                  "pr_auc", n_boot=50)
        assert ci["n_boot"] <= 50           # single-class resamples dropped, no crash


# --------------------------------------------------------------------------- CV integrity

class TestGroupedCv:
    def test_no_fold_scores_its_own_training_rows(self):
        ds = _dataset()
        seen = []

        def fit_score(X_train, y_train, X_test):
            seen.append((len(X_train), len(X_test)))
            return np.zeros(len(X_test))

        H.grouped_cv(ds, fit_score, tier=mlf.TIER_T1, n_splits=4, name="probe")
        assert len(seen) == 4
        assert all(tr > 0 and te > 0 for tr, te in seen)

    def test_every_row_receives_exactly_one_out_of_fold_score(self):
        ds = _dataset()
        res = H.grouped_cv(ds, lambda a, b, c: np.arange(len(c), dtype="float64"),
                           tier=mlf.TIER_T1, n_splits=4, name="probe")
        assert np.isfinite(res.scores).all(), "every row must be scored out-of-fold"

    def test_benign_only_fit_hides_positives_from_the_model(self):
        ds = _dataset()
        labels_seen = []

        def fit_score(X_train, y_train, X_test):
            labels_seen.append(set(np.unique(y_train)))
            return np.zeros(len(X_test))

        H.grouped_cv(ds, fit_score, tier=mlf.TIER_T1, n_splits=3,
                     name="probe", benign_only_fit=True)
        assert all(s == {A.LABEL_BENIGN} for s in labels_seen)

    def test_supervised_mode_passes_both_classes(self):
        ds = _dataset()
        labels_seen = []

        def fit_score(X_train, y_train, X_test):
            labels_seen.append(set(np.unique(y_train)))
            return np.zeros(len(X_test))

        H.grouped_cv(ds, fit_score, tier=mlf.TIER_T1, n_splits=3,
                     name="probe", benign_only_fit=False)
        assert all(len(s) == 2 for s in labels_seen)

    def test_feature_subset_is_honoured(self):
        ds = _dataset()
        widths = []

        def fit_score(X_train, y_train, X_test):
            widths.append(X_train.shape[1])
            return np.zeros(len(X_test))

        subset = mlf.features_excluding("tree", tier=mlf.TIER_T1)
        H.grouped_cv(ds, fit_score, tier=mlf.TIER_T1, n_splits=3, name="probe",
                     feature_subset=subset)
        assert widths and all(w == len(subset) for w in widths)
        assert "sibling_count" not in subset


class TestEvalMask:
    def test_corpus_mask_excludes_local_rows(self):
        ds = _mixed_dataset()
        mask = H.corpus_eval_mask(ds)
        assert mask.sum() == int((ds.sources == A.SOURCE_CORPUS).sum())
        assert (ds.y[~mask] == A.LABEL_BENIGN).all()

    def test_metrics_computed_only_on_masked_rows(self):
        ds = _mixed_dataset()
        mask = H.corpus_eval_mask(ds)
        res = H.grouped_cv(ds, lambda a, b, c: np.random.default_rng(0).random(len(c)),
                           tier=mlf.TIER_T1, n_splits=3, name="probe", eval_mask=mask)
        assert res.metrics["n"] == int(mask.sum())
        assert res.extra["eval_rows"] == int(mask.sum())

    def test_local_fp_report_uses_corpus_thresholds(self):
        ds = _mixed_dataset()
        rng = np.random.default_rng(6)
        scores = rng.random(len(ds))
        report = H.local_fp_report(ds, scores)
        assert report["n_local"] == int((ds.sources == A.SOURCE_LOCAL).sum())
        for fpr in H.FPR_TARGETS:
            entry = report[f"at_corpus_fpr_{fpr}"]
            assert 0.0 <= entry["local_fp_rate"] <= 1.0
            assert entry["local_flagged"] <= report["n_local"]


class TestComplementarity:
    def test_overlap_partitions_the_positives(self):
        ds = _dataset()
        sigma = np.zeros(len(ds))
        positives = np.flatnonzero(ds.y == A.LABEL_MALICIOUS)
        sigma[positives[:5]] = 1.0                       # rules catch 5
        model = np.where(ds.y == A.LABEL_MALICIOUS, 0.9, 0.1)
        out = H.sigma_complementarity(ds, sigma, model, target_fpr=0.01)
        o = out["overlap"]
        assert o["both"] + o["sigma_only"] + o["model_only"] + o["neither"] == out["positives"]

    def test_union_recall_is_at_least_sigma_recall(self):
        ds = _dataset()
        sigma = np.zeros(len(ds))
        sigma[np.flatnonzero(ds.y == A.LABEL_MALICIOUS)[:5]] = 1.0
        model = np.random.default_rng(7).random(len(ds))
        out = H.sigma_complementarity(ds, sigma, model)
        assert out["union_recall"] >= out["sigma_recall"]

    def test_missed_population_is_what_the_rules_did_not_catch(self):
        ds = _dataset()
        sigma = np.zeros(len(ds))
        caught = np.flatnonzero(ds.y == A.LABEL_MALICIOUS)[:4]
        sigma[caught] = 1.0
        out = H.sigma_complementarity(ds, sigma, np.zeros(len(ds)))
        assert out["rule_missed_positives"] == out["positives"] - len(caught)


# --------------------------------------------------------------------------- the model

class TestAnomalyModel:
    def _fitted(self):
        ds = _dataset()
        X, _ = A.materialise(ds, train_mask=None, tier=mlf.TIER_T1)
        benign = ds.y == A.LABEL_BENIGN
        return ml_anomaly.AnomalyModel(n_estimators=60).fit(X[benign]), X, ds

    def test_score_is_a_bounded_percentile(self):
        model, X, _ = self._fitted()
        scores = model.score(X)
        assert scores.min() >= 0.0 and scores.max() <= 1.0

    def test_score_is_monotonic_in_the_raw_score(self):
        model, X, _ = self._fitted()
        raw, pct = model.raw_scores(X), model.score(X)
        # Percentile mapping must preserve ranking, or every metric changes meaning.
        assert np.corrcoef(np.argsort(np.argsort(raw)), np.argsort(np.argsort(pct)))[0, 1] > 0.999

    def test_attacks_score_higher_than_baseline(self):
        model, X, ds = self._fitted()
        scores = model.score(X)
        assert scores[ds.y == A.LABEL_MALICIOUS].mean() > scores[ds.y == A.LABEL_BENIGN].mean()

    def test_baseline_percentiles_are_roughly_uniform(self):
        """Scoring the training baseline should spread across [0,1] by construction."""
        model, X, ds = self._fitted()
        benign_scores = model.score(X[ds.y == A.LABEL_BENIGN])
        assert 0.3 < np.median(benign_scores) < 0.7

    def test_predict_respects_the_threshold(self):
        model, X, _ = self._fitted()
        assert model.predict(X, threshold=0.0).all()
        assert model.predict(X, threshold=1.01).sum() == 0

    def test_feature_mismatch_is_refused_not_guessed(self):
        model, X, _ = self._fitted()
        with pytest.raises(ValueError, match="feature mismatch"):
            model.score(X.drop(columns=[X.columns[0]]))

    def test_scoring_before_fitting_is_an_error(self):
        model = ml_anomaly.AnomalyModel()
        with pytest.raises(RuntimeError, match="fit must be called"):
            model.score(pd.DataFrame({"a": [1.0]}))

    def test_fitting_on_nothing_is_refused(self):
        with pytest.raises(ValueError, match="zero rows"):
            ml_anomaly.AnomalyModel().fit(pd.DataFrame(columns=["a"]))

    def test_nan_features_are_tolerated(self):
        """IsolationForest cannot take NaN; the pipeline must impute."""
        ds = _dataset()
        X, _ = A.materialise(ds, train_mask=None, tier=mlf.TIER_T1)
        assert X.isna().any().any(), "fixture should contain missing values"
        model = ml_anomaly.AnomalyModel(n_estimators=40).fit(X[ds.y == A.LABEL_BENIGN])
        assert np.isfinite(model.score(X)).all()

    def test_explanation_names_real_features(self):
        model, X, _ = self._fitted()
        explanations = model.explain(X.head(5), top_k=3)
        assert len(explanations) == 5
        for row in explanations:
            assert len(row) <= 3
            for item in row:
                assert item["feature"] in model.feature_names
                assert item["deviation"] >= 0

    def test_round_trip_preserves_scores(self):
        model, X, _ = self._fitted()
        before = model.score(X)
        revived = ml_anomaly.AnomalyModel.from_payload(model.to_payload())
        assert np.allclose(before, revived.score(X))
        assert revived.feature_names == model.feature_names

    def test_deterministic_for_a_fixed_seed(self):
        ds = _dataset()
        X, _ = A.materialise(ds, train_mask=None, tier=mlf.TIER_T1)
        benign = X[ds.y == A.LABEL_BENIGN]
        a = ml_anomaly.AnomalyModel(n_estimators=50, seed=7).fit(benign).score(X)
        b = ml_anomaly.AnomalyModel(n_estimators=50, seed=7).fit(benign).score(X)
        assert np.allclose(a, b)


class TestFeatureGroups:
    def test_groups_cover_the_spec_without_overlap_surprises(self):
        covered = set()
        for names in mlf.FEATURE_GROUPS.values():
            covered.update(names)
        # Every grouped name must be a real feature.
        assert covered <= set(mlf.FEATURE_NAMES)

    def test_excluding_a_group_removes_exactly_it(self):
        # Compare against the tier's own feature count, not the global one: tiers are
        # cumulative, so T2 is a strict subset of the full spec.
        for tier in (mlf.TIER_T1, mlf.TIER_T2, mlf.TIER_T3):
            available = set(mlf.features_for_tier(tier))
            removed = available & set(mlf.FEATURE_GROUPS["tree"])
            subset = mlf.features_excluding("tree", tier=tier)
            assert set(mlf.FEATURE_GROUPS["tree"]).isdisjoint(subset), tier
            assert len(subset) == len(available) - len(removed), tier

    def test_every_grouped_name_is_a_real_feature(self):
        """A group naming a removed feature silently breaks features_excluding()."""
        for group, names in mlf.FEATURE_GROUPS.items():
            unknown = set(names) - set(mlf.FEATURE_NAMES)
            assert not unknown, f"group {group!r} names non-existent feature(s): {unknown}"

    def test_excluding_several_groups(self):
        subset = mlf.features_excluding("tree", "conn", tier=mlf.TIER_T2)
        assert set(mlf.FEATURE_GROUPS["conn"]).isdisjoint(subset)
        assert set(mlf.FEATURE_GROUPS["tree"]).isdisjoint(subset)

    def test_unknown_group_is_rejected(self):
        with pytest.raises(KeyError):
            mlf.features_excluding("not-a-group")

    def test_t1_exclusion_never_returns_sysmon(self):
        subset = mlf.features_excluding("tree", tier=mlf.TIER_T1)
        assert not [c for c in subset if c.startswith("sysmon_")]


class TestBaselines:
    def test_chance_lands_near_the_positive_rate(self):
        ds = _dataset()
        res = H.chance_baseline(ds)
        assert abs(res.metrics["pr_auc"] - res.metrics["positive_rate"]) < 0.12

    def test_best_single_feature_selects_inside_the_fold(self):
        ds = _dataset()
        res = H.best_single_feature_baseline(ds, tier=mlf.TIER_T1, n_splits=3)
        assert len(res.extra["selected_per_fold"]) == 3
        assert np.isfinite(res.scores).all()
