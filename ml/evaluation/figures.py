"""Evaluation figures for the ML report.

matplotlib only, no seaborn, no network. Written to `reports_ml/figures/` as PNG so they can
be embedded in the technical report and the defence slides.

Every figure is generated from `reports_ml/anomaly_eval.json`, so what the report shows and
what the harness measured cannot drift apart.
"""
from __future__ import annotations

import json
import os

import matplotlib
matplotlib.use("Agg")                 # headless: no display on a server or in CI
import matplotlib.pyplot as plt       # noqa: E402
import numpy as np                    # noqa: E402

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REPORTS_DIR = os.path.join(_PROJECT_ROOT, "reports_ml")
FIG_DIR = os.path.join(REPORTS_DIR, "figures")

# Colour-blind-safe (Okabe-Ito). Baselines grey, models coloured.
C_MODEL = "#0072B2"
C_MODEL_ALT = "#56B4E9"
C_BASELINE = "#999999"
C_WARN = "#D55E00"
C_OK = "#009E73"


def _load(path: str | None = None) -> dict:
    path = path or os.path.join(REPORTS_DIR, "anomaly_eval.json")
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _save(fig, name: str) -> str:
    os.makedirs(FIG_DIR, exist_ok=True)
    path = os.path.join(FIG_DIR, name)
    fig.savefig(path, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    return path


def fig_model_vs_baselines(report: dict) -> str:
    """PR-AUC with 95% group-bootstrap intervals, models against baselines."""
    order = ["baseline:chance", "baseline:sigma_rules",
             "baseline:best_single_feature", "baseline:best_single_feature_no_tree",
             "anomaly_iforest_t2_no_tree", "anomaly_iforest_t2", "anomaly_iforest_t1"]
    labels, values, los, his, colours = [], [], [], [], []
    chance = report["results"]["baseline:chance"]["metrics"]["pr_auc"]
    for name in order:
        entry = report["results"].get(name)
        if not entry:
            continue
        pr = entry["metrics"].get("pr_auc")
        if pr is None:
            continue
        ci = (entry.get("ci") or {}).get("pr_auc") or {}
        labels.append(name.replace("baseline:", "").replace("anomaly_iforest_", "IF "))
        values.append(pr)
        # NaN rather than 0 where no interval was computed (the Sigma rules are a single
        # deterministic operating point): a zero-width bar would read as a precise estimate.
        los.append(pr - ci["lo"] if ci.get("lo") is not None else np.nan)
        his.append(ci["hi"] - pr if ci.get("hi") is not None else np.nan)
        colours.append(C_BASELINE if name.startswith("baseline") else
                       (C_MODEL if name == "anomaly_iforest_t1" else C_MODEL_ALT))

    fig, ax = plt.subplots(figsize=(9, 4.6))
    ypos = np.arange(len(labels))
    ax.barh(ypos, values, color=colours, height=0.62)
    ax.errorbar(values, ypos, xerr=[los, his], fmt="none", ecolor="#333333",
                capsize=4, lw=1.2)
    ax.axvline(chance, color=C_WARN, ls="--", lw=1.2,
               label=f"chance = positive rate ({chance:.3f})")
    ax.set_yticks(ypos, labels, fontsize=9)
    ax.set_xlabel("PR-AUC (average precision) - higher is better")
    ax.set_title("Component A vs mandatory baselines\n"
                 "corpus rows only (1,716 rows / 185 positives), grouped 5-fold CV,\n"
                 "error bars = 95% bootstrap CI over captures", fontsize=10)
    ax.legend(fontsize=8, loc="lower right")
    ax.grid(axis="x", alpha=0.25)
    ax.set_axisbelow(True)
    for y, v in zip(ypos, values):
        ax.text(v + 0.012, y, f"{v:.3f}", va="center", fontsize=8.5)
    upper = np.nanmax(np.array(values) + np.nan_to_num(np.array(his), nan=0.0))
    ax.set_xlim(0, float(upper) * 1.18)
    return _save(fig, "01_model_vs_baselines.png")


def fig_feature_group_ablation(report: dict) -> str:
    """Leave-one-feature-group-out: which evidence actually carries the result."""
    full = report["results"].get("ablation:all_features(98)")
    if not full:
        return ""
    base = full["metrics"]["pr_auc"]
    rows = []
    for name, entry in report["results"].items():
        if not name.startswith("ablation:no_"):
            continue
        group = name.split("ablation:no_")[1].split("(")[0]
        rows.append((group, entry["metrics"]["pr_auc"] - base))
    rows.sort(key=lambda r: r[1])

    fig, ax = plt.subplots(figsize=(8, 4.2))
    labels = [r[0] for r in rows]
    deltas = [r[1] for r in rows]
    colours = [C_WARN if d < 0 else C_OK for d in deltas]
    ax.barh(np.arange(len(labels)), deltas, color=colours, height=0.6)
    ax.axvline(0, color="#333333", lw=1)
    ax.set_yticks(np.arange(len(labels)), labels, fontsize=9)
    ax.set_xlabel("change in PR-AUC when the group is removed")
    ax.set_title("Which feature families carry the result\n"
                 f"(baseline: all 98 features, PR-AUC {base:.3f})", fontsize=10)
    ax.grid(axis="x", alpha=0.25)
    ax.set_axisbelow(True)
    for i, d in enumerate(deltas):
        ax.text(d + (0.004 if d >= 0 else -0.004), i, f"{d:+.3f}",
                va="center", ha="left" if d >= 0 else "right", fontsize=8.5)
    pad = max(abs(min(deltas)), abs(max(deltas))) * 0.35
    ax.set_xlim(min(deltas) - pad, max(deltas) + pad)
    return _save(fig, "02_feature_group_ablation.png")


def fig_operating_points(report: dict) -> str:
    """False-positive burden on real benign endpoint data, at three thresholds."""
    local = report.get("local_false_positives") or {}
    models = [m for m in ("anomaly_iforest_t1", "anomaly_iforest_t2",
                          "anomaly_iforest_t2_no_tree") if m in local]
    if not models:
        return ""
    fprs = [0.01, 0.005, 0.001]
    width = 0.26
    fig, ax = plt.subplots(figsize=(8.4, 4.2))
    for i, model in enumerate(models):
        vals = [local[model].get(f"at_corpus_fpr_{f}", {}).get(
            "alerts_per_host_snapshot", np.nan) for f in fprs]
        xs = np.arange(len(fprs)) + (i - (len(models) - 1) / 2) * width
        colour = C_MODEL if model.endswith("t1") else (
            C_MODEL_ALT if model.endswith("t2") else C_BASELINE)
        ax.bar(xs, vals, width=width, label=model.replace("anomaly_iforest_", "IF "),
               color=colour)
        for x, v in zip(xs, vals):
            if np.isfinite(v):
                ax.text(x, v + 0.25, f"{v:.1f}", ha="center", fontsize=8)
    ax.set_xticks(np.arange(len(fprs)), [f"{f:.1%}" for f in fprs])
    ax.set_xlabel("threshold, set as a false-positive rate on corpus benign rows")
    ax.set_ylabel("false alerts per 270-process host sweep")
    ax.set_title("False-positive burden on genuine live benign telemetry\n"
                 "(538 real endpoint processes; these rows never influenced the threshold)",
                 fontsize=10)
    ax.legend(fontsize=8)
    ax.grid(axis="y", alpha=0.25)
    ax.set_axisbelow(True)
    return _save(fig, "03_operating_points.png")


def fig_sigma_complementarity(report: dict) -> str:
    """What the model adds over the rules already in production."""
    comp = (report.get("sigma_complementarity") or {}).get("with_tree_features")
    if not comp:
        return ""
    overlap = comp["overlap"]
    labels = ["rules only", "rules + model", "model only", "neither"]
    values = [overlap["sigma_only"], overlap["both"],
              overlap["model_only"], overlap["neither"]]
    colours = [C_BASELINE, C_OK, C_MODEL, C_WARN]

    fig, ax = plt.subplots(figsize=(8, 4.2))
    bars = ax.bar(labels, values, color=colours, width=0.6)
    total = comp["positives"]
    for bar, v in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, v + total * 0.012,
                f"{v}\n({v / total:.0%})", ha="center", fontsize=9)
    ax.set_ylabel(f"attacks (of {total} labelled positives)")
    ax.set_title("Detection overlap: Sigma rules vs the anomaly model\n"
                 f"model thresholded at {comp['target_fpr']:.0%} FPR - "
                 f"union recall {comp['union_recall']:.0%} vs rules alone "
                 f"{comp['sigma_recall']:.0%}", fontsize=10)
    ax.grid(axis="y", alpha=0.25)
    ax.set_axisbelow(True)
    ax.set_ylim(0, max(values) * 1.22)
    return _save(fig, "04_sigma_complementarity.png")


def fig_fold_stability(report: dict) -> str:
    """Per-fold PR-AUC: with 105 capture groups the spread is the honest headline."""
    series = {}
    for name in ("anomaly_iforest_t1", "anomaly_iforest_t2", "anomaly_iforest_t2_no_tree"):
        entry = report["results"].get(name)
        if not entry:
            continue
        vals = [f.get("pr_auc") for f in entry.get("per_fold", [])
                if f.get("pr_auc") is not None]
        if vals:
            series[name.replace("anomaly_iforest_", "IF ")] = vals
    if not series:
        return ""
    fig, ax = plt.subplots(figsize=(8, 4.2))
    for i, (label, vals) in enumerate(series.items()):
        ax.plot(range(1, len(vals) + 1), vals, marker="o",
                label=f"{label} (mean {np.mean(vals):.3f}, sd {np.std(vals):.3f})",
                color=[C_MODEL, C_MODEL_ALT, C_BASELINE][i % 3])
    chance = report["results"]["baseline:chance"]["metrics"]["pr_auc"]
    ax.axhline(chance, color=C_WARN, ls="--", lw=1.2, label=f"chance ({chance:.3f})")
    ax.set_xlabel("cross-validation fold (groups = captures)")
    ax.set_ylabel("PR-AUC")
    ax.set_title("Per-fold variability\n"
                 "wide spread is expected with 185 positives across 105 captures - "
                 "point estimates alone would mislead", fontsize=10)
    ax.set_xticks(range(1, max(len(v) for v in series.values()) + 1))
    ax.legend(fontsize=8)
    ax.grid(alpha=0.25)
    ax.set_axisbelow(True)
    return _save(fig, "05_fold_stability.png")


def generate_all(report_path: str | None = None) -> list[str]:
    report = _load(report_path)
    made = []
    for builder in (fig_model_vs_baselines, fig_feature_group_ablation,
                    fig_operating_points, fig_sigma_complementarity, fig_fold_stability):
        path = builder(report)
        if path:
            made.append(path)
    return made


if __name__ == "__main__":       # pragma: no cover - operator entry point
    for p in generate_all():
        print(f"wrote {p}")


# --------------------------------------------------------------------------- Phase 5

def _load_triage(path: str | None = None) -> dict | None:
    path = path or os.path.join(REPORTS_DIR, "triage_eval.json")
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def fig_component_comparison(anomaly_report: dict, triage_report: dict) -> str:
    """Component A vs Component B vs the deployed rules, on identical rows and folds."""
    wanted = [
        ("baseline:chance", "chance", C_BASELINE),
        ("baseline:sigma_rules", "Sigma rules", C_BASELINE),
        ("baseline:best_single_feature", "best single feature", C_BASELINE),
        ("anomaly_iforest_t1(for comparison)", "A: anomaly (unsupervised)", C_MODEL_ALT),
        ("triage_gbdt_t1", "B: triage (supervised)", C_MODEL),
    ]
    labels, values, los, his, colours = [], [], [], [], []
    for key, label, colour in wanted:
        entry = triage_report["results"].get(key)
        if not entry:
            continue
        pr = entry["metrics"].get("pr_auc")
        if pr is None:
            continue
        ci = (entry.get("ci") or {}).get("pr_auc") or {}
        labels.append(label)
        values.append(pr)
        los.append(pr - ci["lo"] if ci.get("lo") is not None else np.nan)
        his.append(ci["hi"] - pr if ci.get("hi") is not None else np.nan)
        colours.append(colour)

    fig, ax = plt.subplots(figsize=(9, 4.2))
    ypos = np.arange(len(labels))
    ax.barh(ypos, values, color=colours, height=0.6)
    ax.errorbar(values, ypos, xerr=[los, his], fmt="none", ecolor="#333333",
                capsize=4, lw=1.2)
    ax.set_yticks(ypos, labels, fontsize=9)
    ax.set_xlabel("PR-AUC (average precision)")
    ax.set_title("Supervised triage vs unsupervised anomaly detection\n"
                 "same 1,716 corpus rows, same grouped folds, 185 positives", fontsize=10)
    for y, v in zip(ypos, values):
        ax.text(v + 0.012, y, f"{v:.3f}", va="center", fontsize=8.5)
    ax.grid(axis="x", alpha=0.25)
    ax.set_axisbelow(True)
    ax.set_xlim(0, 1.08)
    return _save(fig, "06_component_a_vs_b.png")


def fig_reliability(triage_report: dict) -> str:
    """Reliability curve: does a stated confidence of 0.9 mean 90%?"""
    calibration = triage_report.get("calibration") or {}
    if not calibration:
        return ""
    fig, ax = plt.subplots(figsize=(6.4, 6))
    ax.plot([0, 1], [0, 1], ls="--", color="#333333", lw=1.2, label="perfect calibration")
    for i, (name, metrics) in enumerate(calibration.items()):
        bins = metrics.get("bins") or []
        if not bins:
            continue
        xs = [b["mean_predicted"] for b in bins]
        ys = [b["observed_frequency"] for b in bins]
        ax.plot(xs, ys, marker="o", color=[C_MODEL, C_MODEL_ALT, C_OK][i % 3],
                label=f"{name} (ECE {metrics['expected_calibration_error']:.4f}, "
                      f"Brier {metrics['brier_score']:.4f})")
    ax.set_xlabel("predicted probability")
    ax.set_ylabel("observed frequency of actual attacks")
    ax.set_title("Component B reliability\n"
                 "a point below the diagonal means the model is over-confident", fontsize=10)
    ax.legend(fontsize=8, loc="upper left")
    ax.grid(alpha=0.25)
    ax.set_axisbelow(True)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.set_aspect("equal")
    return _save(fig, "07_reliability_curve.png")


def fig_leak_audit(triage_report: dict) -> str:
    """How much of Component B's result is the labelling rule rather than behaviour?"""
    audit = triage_report.get("leak_audit")
    if not audit:
        return ""
    labels = ["all features", "without seed-echo\nfeatures", "without any\ncommand-line features"]
    values = [audit.get("pr_auc_all_features"), audit.get("pr_auc_without_seed_echo"),
              audit.get("pr_auc_without_any_cmdline")]
    if any(v is None for v in values):
        return ""
    fig, ax = plt.subplots(figsize=(7.6, 4.2))
    bars = ax.bar(labels, values, color=[C_MODEL, C_MODEL_ALT, C_OK], width=0.55)
    for bar, v in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width() / 2, v + 0.012, f"{v:.3f}",
                ha="center", fontsize=10)
    chance = triage_report["results"]["baseline:chance"]["metrics"]["pr_auc"]
    ax.axhline(chance, color=C_WARN, ls="--", lw=1.2, label=f"chance ({chance:.3f})")
    ax.set_ylabel("PR-AUC")
    ax.set_ylim(0, 1.05)
    ax.set_title("Leak audit: labels were generated from command-line signatures,\n"
                 "so how much does the model lose when those features are removed?",
                 fontsize=10)
    ax.legend(fontsize=8)
    ax.grid(axis="y", alpha=0.25)
    ax.set_axisbelow(True)
    return _save(fig, "08_leak_audit.png")


def generate_phase5(anomaly_path: str | None = None,
                    triage_path: str | None = None) -> list[str]:
    triage = _load_triage(triage_path)
    if triage is None:
        return []
    anomaly = _load(anomaly_path)
    made = []
    for path in (fig_component_comparison(anomaly, triage),
                 fig_reliability(triage), fig_leak_audit(triage)):
        if path:
            made.append(path)
    return made
