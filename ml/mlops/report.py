"""Run report: `run.json` (everything) and `REPORT.md` (what a human reads on Monday)."""
from __future__ import annotations

import json
import os

from ml.mlops import store

_STATUS_WORDS = {"succeeded": "Succeeded", "attention": "Completed - needs a look",
                 "failed": "FAILED - production unchanged"}


def compact(summary: dict) -> dict:
    """The subset stored in ml_pipeline_runs.summary_json for the dashboard."""
    candidates = summary.get("candidates") or {}
    monitor = summary.get("monitor") or {}
    drift = monitor.get("drift") or {}
    return {
        "status": summary.get("status"),
        "attention": summary.get("attention", []),
        "stages": {k: v.get("status") for k, v in (summary.get("stages") or {}).items()},
        "failed_stage": next((k for k, v in (summary.get("stages") or {}).items()
                              if v.get("status") == "failed"), None),
        "version_id": candidates.get("version_id"),
        "plan": {c: p.get("action") for c, p in (candidates.get("plan") or {}).items()},
        "offline": {c: {"passed": g.get("passed"), "failed": g.get("failed")}
                    for c, g in (summary.get("offline_gates") or {}).items()
                    if not c.startswith("_")},
        "staged": summary.get("staged"),
        "trials": summary.get("trials"),
        "promotions": [{"component": p.get("component"), "version_id": p.get("version_id"),
                        "promoted": p.get("promoted"), "rolled_back": p.get("rolled_back")}
                       for p in summary.get("promotions", [])],
        "pending_captures": [p["capture"] for p in
                             (summary.get("retrieve") or {}).get("pending", [])],
        "exclusions": (summary.get("exclusions") or {}).get("by_reason"),
        "drift_counts": drift.get("counts"),
        "outcomes": monitor.get("outcomes"),
        "health": monitor.get("health"),
    }


def _gate_lines(gates: list[dict]) -> list[str]:
    lines = []
    for g in gates:
        mark = {True: "pass", False: "**FAIL**", None: "skip"}[g.get("passed")]
        value = "" if g.get("value") is None else f" {g['value']}"
        threshold = "" if g.get("threshold") is None else f" (threshold {g['threshold']})"
        lines.append(f"| {g['gate']} | {mark} |{value}{threshold} | {g.get('detail', '')} |")
    return lines


def to_markdown(summary: dict) -> str:
    out = [f"# MLOps run {summary['run_id']}", "",
           f"**{_STATUS_WORDS.get(summary.get('status'), summary.get('status'))}** · "
           f"trigger `{summary.get('trigger')}` · started {summary.get('started_at_utc')} · "
           f"finished {summary.get('finished_at_utc')}", ""]
    if summary.get("attention"):
        out += ["## Needs attention", ""] + [f"- {a}" for a in summary["attention"]] + [""]

    out += ["## Stages", "", "| Stage | Result | Seconds |", "|---|---|---|"]
    for name, stage in (summary.get("stages") or {}).items():
        result = stage.get("status", "")
        if stage.get("error"):
            result += f" - {stage['error']}"
        out.append(f"| {name} | {result} | {stage.get('seconds', '')} |")
    out.append("")

    if summary.get("trials"):
        out += ["## Trials concluded", ""]
        for t in summary["trials"]:
            out.append(f"- {t['component']} `{t['version_id']}` (trial {t['trial_id']}): "
                       f"verdict **{t['verdict']}** -> {t.get('decision')}"
                       + (f" - {t['reason']}" if t.get("reason") else ""))
        out.append("")
    if summary.get("promotions"):
        out += ["## Deployments", ""]
        for p in summary["promotions"]:
            smoke = (p.get("smoke_test") or {})
            out.append(f"- {p['component']} `{p['version_id']}`: "
                       + ("**deployed**, smoke test passed" if p.get("promoted")
                          else f"**rolled back** ({smoke.get('reason')}); restored "
                               f"`{p.get('restored')}`"))
        out.append("")

    candidates = summary.get("candidates") or {}
    if candidates.get("plan"):
        out += ["## Retraining", "", f"Version `{candidates.get('version_id')}`", ""]
        for component, item in candidates["plan"].items():
            training = item.get("training") or {}
            detail = {"unchanged": "inputs identical to the deployed model - not retrained",
                      "in_trial": f"identical to the model already on trial "
                                  f"(`{item.get('version_id')}`)",
                      "train": f"trained in {training.get('seconds')} s, "
                               f"ok={training.get('ok')}"}[item["action"]]
            out.append(f"- **{component}**: {detail}")
        out.append("")
    for component, result in (summary.get("offline_gates") or {}).items():
        if component.startswith("_"):
            continue
        out += [f"### Offline gates - {component}: "
                f"{'PASSED' if result['passed'] else 'REJECTED'}", "",
                "| Gate | Result | Value | Detail |", "|---|---|---|---|"]
        out += _gate_lines(result["gates"]) + [""]
    if summary.get("staged"):
        out += ["## Staged", ""] + [f"- {s['component']}: {s['action']}"
                                    + (f" (trial {s['trial_id']})" if s.get("trial_id") else "")
                                    for s in summary["staged"]] + [""]

    retrieve = summary.get("retrieve") or {}
    if retrieve:
        fetch = retrieve.get("fetch") or {}
        out += ["## Data", "",
                f"- upstream corpus fetch: {fetch.get('status')}"
                + (f" ({fetch.get('reason')})" if fetch.get("reason") else "")
                + (f", {fetch.get('downloaded')} new file(s)" if fetch.get("downloaded") else ""),
                f"- captures admitted to training: {retrieve.get('admitted')}; awaiting review: "
                f"{len(retrieve.get('pending') or [])}; changed since approval: "
                f"{len(retrieve.get('changed') or [])}; unreadable (antivirus): "
                f"{len(retrieve.get('av_blocked') or [])}"]
        etl = summary.get("etl") or {}
        if etl:
            stats = etl.get("stats") or {}
            out.append(f"- training database: {etl.get('mode')} build ({etl.get('reason')}); "
                       f"{stats.get('captures')} captures, {stats.get('processes')} processes, "
                       f"{stats.get('malicious')} attack labels")
        excl = summary.get("exclusions") or {}
        if excl:
            out.append(f"- live telemetry: {excl.get('admitted')} of {excl.get('local_rows')} "
                       f"processes admitted as benign baseline; excluded "
                       f"{json.dumps(excl.get('by_reason'))}")
            if excl.get("feedback_readmitted"):
                out.append(f"- re-admitted after analyst dismissal: "
                           f"{len(excl['feedback_readmitted'])} process row(s): "
                           f"{excl['feedback_readmitted'][:20]}")
        out.append("")

    monitor = summary.get("monitor") or {}
    if monitor:
        out += ["## Monitoring", ""]
        drift = monitor.get("drift") or {}
        if drift.get("counts"):
            against = ("this estate's earlier weeks" if drift.get("reference") == "local"
                       else "the training corpus (informational: too little local history)")
            out.append(f"- drift over the last 7 days ({drift.get('live_rows')} live processes) "
                       f"vs {against}: {drift['counts']}")
        elif drift.get("error"):
            out.append(f"- drift: {drift['error']}")
        outcomes = monitor.get("outcomes") or {}
        if outcomes:
            out.append(f"- ML leads in the window: {outcomes.get('ml_leads')} across "
                       f"{outcomes.get('active_hosts')} active host(s) "
                       f"({outcomes.get('leads_per_host_day')} per host-day); analysts "
                       f"confirmed {outcomes.get('analyst_confirmed')}, dismissed "
                       f"{outcomes.get('analyst_dismissed')}")
        health = monitor.get("health") or {}
        out.append(f"- pipeline: last success {health.get('last_success_utc')}, consecutive "
                   f"failures {health.get('consecutive_failures')}, running trials "
                   f"{[t['component'] + ' ' + t['version_id'] for t in health.get('running_trials', [])]}")
        out.append("")
    return "\n".join(out) + "\n"


def write(run_dir: str, summary: dict) -> dict:
    json_path = os.path.join(run_dir, "run.json")
    md_path = os.path.join(run_dir, "REPORT.md")
    store.atomic_write_json(json_path, summary)
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(to_markdown(summary))
    return {"json": json_path, "markdown": md_path}
