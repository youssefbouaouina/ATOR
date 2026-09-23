"""The weekly run: snapshot -> conclude trials -> retrieve -> ETL -> train -> evaluate ->
stage -> monitor -> report.  docs/ML_MLOPS_PLAN.md section 3.

Only two steps change what analysts see: promotion inside `_conclude_trials` and bootstrap
promotion inside `_stage`. Both go through `trial.promote_with_rollback`. Everything else
writes into the run directory, a staging file, the model store, or the pipeline's own
bookkeeping tables. A stage that fails therefore aborts the rest of the run with production
untouched. Monitoring and the report still run, so the failure is visible.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import time
import traceback
from datetime import datetime, timezone

from ml.mlops import config, data, evaluate, monitor, report, store, train, trial

EXIT_OK, EXIT_FAILED, EXIT_ATTENTION = 0, 1, 2


class StageFailed(RuntimeError):
    pass


class Run:
    """State and logging for one pipeline run."""

    def __init__(self, now: datetime, trigger: str, home: str, policy: config.Policy):
        self.now = now
        self.now_iso = now.isoformat(timespec="seconds")
        self.run_id = now.strftime("%Y%m%dT%H%M%SZ")
        self.version_id = f"v{self.run_id}"
        self.home = home
        self.policy = policy
        self.dir = os.path.join(home, "runs", self.run_id)
        os.makedirs(self.dir, exist_ok=True)
        self.summary: dict = {"run_id": self.run_id, "started_at_utc": self.now_iso,
                              "trigger": trigger, "stages": {}, "attention": [],
                              "promotions": [], "trials": [], "candidates": {}}
        self._log = open(os.path.join(self.dir, "pipeline.log"), "a", encoding="utf-8")

    def log(self, message: str) -> None:
        line = f"{datetime.now(timezone.utc).isoformat(timespec='seconds')} {message}"
        print(line, flush=True)
        self._log.write(line + "\n")
        self._log.flush()

    def attention(self, reason: str) -> None:
        if reason not in self.summary["attention"]:
            self.summary["attention"].append(reason)
            self.log(f"ATTENTION: {reason}")

    def stage(self, name: str, fn, *, critical: bool = True):
        self.log(f"--- {name}")
        started = time.time()
        try:
            result = fn()
            self.summary["stages"][name] = {"status": "ok",
                                            "seconds": round(time.time() - started, 1)}
            return result
        except Exception as exc:                 # noqa: BLE001 - recorded, then decided
            self.summary["stages"][name] = {
                "status": "failed", "seconds": round(time.time() - started, 1),
                "error": f"{type(exc).__name__}: {exc}"}
            self.log(f"stage {name} FAILED: {type(exc).__name__}: {exc}")
            self._log.write(traceback.format_exc() + "\n")
            if critical:
                raise StageFailed(name) from exc
            return None

    def close(self) -> None:
        self._log.close()


# --------------------------------------------------------------------------- helpers

def _flag(home: str, name: str) -> bool:
    return os.path.exists(os.path.join(home, name))


def _live_conn():
    from server import db as database
    database.init_db(config.live_db_path())     # additive; creates the Phase 10 tables
    return database.connect(config.live_db_path())


def _last_completed_start(conn) -> str | None:
    row = conn.execute(
        """SELECT started_at_utc FROM ml_pipeline_runs
           WHERE status IN ('succeeded','attention') ORDER BY started_at_utc DESC LIMIT 1"""
    ).fetchone()
    return row[0] if row else None


def _hours_between(later: datetime, earlier_iso: str) -> float:
    earlier = datetime.fromisoformat(earlier_iso)
    if earlier.tzinfo is None:
        earlier = earlier.replace(tzinfo=timezone.utc)
    return (later - earlier).total_seconds() / 3600.0


def _champion_fingerprint(component: str) -> str | None:
    champions = evaluate.load_champions(component)
    served = config.COMPONENT_FILES[component][0]
    return (champions or {}).get(served, {}).get("fingerprint") if champions else None


# --------------------------------------------------------------------------- stages

def _preflight(run: Run) -> dict:
    from server.engine import ml_registry

    status = ml_registry.dependencies_available()
    if not status.available:
        raise RuntimeError(status.reason)
    free = {}
    for label, path in (("models", config.models_dir()), ("mlops", run.home),
                        ("training_db", os.path.dirname(config.train_db_path()))):
        os.makedirs(path, exist_ok=True)
        free[label] = round(shutil.disk_usage(path).free / 1e9, 2)
    if min(free.values()) < run.policy.min_free_disk_gb:
        raise RuntimeError(f"less than {run.policy.min_free_disk_gb} GB free: {free}")
    reconciled = [store.reconcile(c, run.now_iso) for c in config.COMPONENTS]
    for item in reconciled:
        if item["action"] == "repaired_interrupted_swap":
            run.attention(f"{item['component']}: an interrupted model swap was repaired "
                          f"(restored {item['version_id']})")
        elif item["action"] == "adopted_manual_change":
            run.attention(f"{item['component']}: a hand-placed model was found in models/ "
                          f"and adopted as {item['version_id']}")
    return {"free_disk_gb": free, "reconcile": reconciled}


def _snapshot(run: Run) -> dict:
    return data.snapshot_live_db(config.live_db_path(), os.path.join(run.dir, "live_snapshot.db"))


def _conclude_trials(run: Run, conn, snapshot: str) -> list[dict]:
    frozen = _flag(run.home, "FROZEN")
    outcomes = []
    for t in trial.running_trials(conn):
        component, version = t["component"], t["version_id"]
        if component == "anomaly":
            ev = trial.evidence(conn, t["id"])
            verdict, gates = trial.online_gates(ev, run.policy)
            online = {"evidence": ev, "gates": gates, "verdict": verdict}
        else:
            check = trial.replay_check(component, version, snapshot, t["started_at_utc"])
            verdict = "pass" if check["passed"] else "fail"
            online = {"replay": check, "verdict": verdict}
        outcome = {"trial_id": t["id"], "component": component, "version_id": version,
                   "verdict": verdict}

        if verdict == "fail":
            failed = [g["gate"] for g in online.get("gates", []) if g["passed"] is False]
            trial.close_trial(conn, t["id"], "rejected", run.now_iso,
                              f"online gates failed: {failed or online.get('replay')}", online)
            outcome["decision"] = "rejected"
        elif verdict == "inconclusive" or frozen:
            reason = ("promotion frozen by operator" if frozen and verdict == "pass"
                      else "not enough live evidence yet; trial extended")
            trial.extend_trial(conn, t["id"], online, reason)
            extensions = int(t["online"].get("extensions", 0)) + 1
            outcome.update(decision="extended", reason=reason, extensions=extensions)
            if extensions >= run.policy.inconclusive_alert_after and not frozen:
                run.attention(f"{component} trial has lacked live evidence for {extensions} "
                              f"weeks - is the server running long enough to score traffic?")
        else:
            result = trial.promote_with_rollback(conn, component, version, run.now_iso,
                                                 f"trial {t['id']} passed")
            run.summary["promotions"].append(result)
            if result["promoted"]:
                trial.close_trial(conn, t["id"], "promoted", run.now_iso,
                                  "offline and online gates passed", online)
                outcome["decision"] = "promoted"
            else:
                trial.close_trial(conn, t["id"], "aborted", run.now_iso,
                                  f"smoke test failed after promotion, rolled back: "
                                  f"{result['smoke_test'].get('reason')}", online)
                outcome["decision"] = "rolled_back"
                run.attention(f"{component} {version} failed its post-deployment smoke test "
                              f"and was rolled back automatically")
        if component == "anomaly" and outcome.get("decision") != "extended":
            store.clear_shadow()
        run.log(f"trial {t['id']} {component} {version}: {outcome.get('decision')}")
        outcomes.append(outcome)
    return outcomes


def _retrieve(run: Run) -> dict:
    fetched = data.fetch_corpus(run.policy, run.log)
    admission = data.admit_captures(run.home)
    if admission["pending"]:
        run.attention(f"{len(admission['pending'])} new attack capture(s) await review before "
                      f"they can be used for training: "
                      + ", ".join(p["capture"] for p in admission["pending"][:5]))
    if admission["changed"]:
        run.attention(f"{len(admission['changed'])} approved capture(s) changed on disk and were "
                      f"excluded: " + ", ".join(c["capture"] for c in admission["changed"][:5]))
    return {"fetch": fetched, "admitted": admission["admitted"],
            "pending": admission["pending"], "changed": admission["changed"],
            "av_blocked": admission["blocked"]}


def _etl(run: Run, admitted) -> dict:
    staging = os.path.join(run.home, "work", "ml_train.staging.db")
    built = data.build_training_db(admitted, config.train_db_path(), staging, run.log)
    previous = data.load_data_state(run.home)
    checks = data.validate_training_db(built["stats"], previous, len(admitted), run.policy)
    built["validation"] = checks
    failed = [c for c in checks if not c["ok"] and c["severity"] == "error"]
    for c in checks:
        if not c["ok"] and c["severity"] == "warning":
            run.attention(f"training data: {c['check']} - {c['detail']}")
    if failed:
        raise RuntimeError("training data failed validation: "
                           + "; ".join(f"{c['check']} ({c['detail']})" for c in failed))
    data.swap_training_db(staging, config.train_db_path())
    data.save_data_state(run.home, built["stats"])
    return built


def _train(run: Run, conn, snapshot: str, exclusions: dict) -> dict:
    train_db = config.train_db_path()
    corpus_fp = data.corpus_hash(train_db)
    vdir = store.version_dir(run.version_id)
    plan = {}
    for component in config.COMPONENTS:
        fp = data.component_fingerprint(component, corpus=corpus_fp,
                                        local=exclusions["local_fingerprint"], policy=run.policy)
        running = trial.running_trial(conn, component)
        if fp == _champion_fingerprint(component):
            plan[component] = {"action": "unchanged", "fingerprint": fp}
        elif running and running["offline"].get("fingerprint") == fp:
            plan[component] = {"action": "in_trial", "fingerprint": fp,
                               "version_id": running["version_id"]}
        else:
            plan[component] = {"action": "train", "fingerprint": fp}
    run.log("plan: " + ", ".join(f"{c}={p['action']}" for c, p in plan.items()))

    trained = []
    for component, item in plan.items():
        if item["action"] != "train":
            continue
        result = train.run_trainer(
            component, train_db=train_db, live_db=snapshot, out_dir=vdir,
            report_path=os.path.join(run.dir, f"{component}_eval.json"),
            log_path=os.path.join(run.dir, f"train_{component}.log"),
            timeout=run.policy.train_timeout)
        item["training"] = result
        run.log(f"trained {component}: ok={result['ok']} in {result['seconds']}s")
        if not result["ok"]:
            run.attention(f"{component} training failed (see {result['log']})")
            continue
        for name, path in store.component_files(run.version_id, component).items():
            train.stamp(path, version_id=run.version_id, fingerprint=item["fingerprint"],
                        component=component, libraries=data.library_versions(),
                        lineage={"run_id": run.run_id, "corpus": corpus_fp,
                                 "local_rows": exclusions["admitted"],
                                 "local_excluded": exclusions["by_reason"]})
        trained.append(component)
    if trained:
        item_canary = train.build_canary(train_db, vdir, trained)
        run.log(f"canary: {item_canary}")
    return {"plan": plan, "trained": trained, "corpus_fingerprint": corpus_fp}


def _evaluate(run: Run, trained: list[str], snapshot: str, cooling_off_since: str,
              plan: dict) -> dict:
    ctx = evaluate.build_context(config.train_db_path(), snapshot, cooling_off_since)
    run.log(f"evaluation context: {ctx.notes}")
    results = {}
    for component in trained:
        report_path = plan[component]["training"]["report"]
        with open(report_path, encoding="utf-8") as fh:
            report_json = json.load(fh)
        challenger = {name: train_artefact
                      for name, path in store.component_files(run.version_id, component).items()
                      if (train_artefact := _load(path)) is not None}
        champion = evaluate.load_champions(component)
        results[component] = evaluate.evaluate_component(
            component, report_json, challenger, champion, ctx, run.policy)
        verdict = "PASSED" if results[component]["passed"] else \
            f"REJECTED ({', '.join(results[component]['failed'])})"
        run.log(f"offline gates {component}: {verdict}")
    results["_context"] = ctx.notes
    return results


def _load(path):
    from ml.mlops import scoring
    return scoring.load(path)



def _stage(run: Run, conn, trained: list[str], gates: dict, plan: dict) -> list[dict]:
    frozen = _flag(run.home, "FROZEN")
    staged = []
    for component in trained:
        result = gates.get(component) or {}
        if not result.get("passed"):
            staged.append({"component": component, "action": "rejected_offline",
                           "failed": result.get("failed")})
            continue
        offline = {"fingerprint": plan[component]["fingerprint"], "gates": result["gates"]}
        champion = evaluate.load_champions(component)
        challenger = {name: _load(path) for name, path in
                      store.component_files(run.version_id, component).items()}
        if champion is not None and evaluate.equivalent(challenger, champion):
            if frozen:
                staged.append({"component": component, "action": "equivalent_held_frozen"})
                continue
            # Same outputs on every evaluation row: record it as the champion's successor so
            # its fingerprint stops the weekly retrain, without a pointless week-long trial.
            outcome = trial.promote_with_rollback(conn, component, run.version_id, run.now_iso,
                                                  "equivalent to the champion (provenance only)")
            run.summary["promotions"].append(outcome)
            staged.append({"component": component, "action": "adopted_equivalent"
                           if outcome["promoted"] else "equivalent_rolled_back"})
            continue
        if (champion is None and run.policy.allow_bootstrap_promotion
                and not frozen):
            # No valid champion (first deployment, or the feature spec changed and the
            # server already refuses the old model). Serving nothing is worse than serving a
            # model that passed every offline gate.
            outcome = trial.promote_with_rollback(conn, component, run.version_id, run.now_iso,
                                                  "bootstrap: no valid champion")
            run.summary["promotions"].append(outcome)
            staged.append({"component": component, "action": "bootstrap_promoted"
                           if outcome["promoted"] else "bootstrap_rolled_back"})
            continue
        trial_id = trial.start_trial(conn, run.version_id, component, offline, run.now_iso)
        staged.append({"component": component, "action": "trial_started", "trial_id": trial_id})
        run.log(f"{component}: shadow trial {trial_id} started for {run.version_id}")
    return staged


def _monitor(run: Run, conn, snapshot: str | None) -> dict:
    out = {"health": monitor.pipeline_health(conn, run.policy, run.now)}
    if snapshot and os.path.exists(snapshot):
        since = data.since(run.now, 7)
        try:
            out["drift"] = monitor.drift(config.train_db_path(), snapshot, since, conn,
                                         run.policy.min_local_reference_rows)
            drift = out["drift"]
            shifted = [r["feature"] for r in drift.get("worst", []) if r["verdict"] == "shifted"]
            # Only this week vs the estate's own earlier weeks raises attention: the corpus is
            # lab captures, and its gap to any real estate is permanent (25 features on the
            # first real run) - alerting on it every week would teach operators to ignore
            # the exit code.
            if (drift.get("reference") == "local"
                    and drift.get("counts", {}).get("shifted", 0)
                    >= max(3, run.policy.drift_attention_share * drift["features_compared"])):
                run.attention(f"this week's telemetry differs from earlier weeks on "
                              f"{drift['counts']['shifted']} signal(s): {', '.join(shifted[:5])} "
                              f"- check the agents before trusting the models")
        except Exception as exc:                 # noqa: BLE001
            out["drift"] = {"error": f"{type(exc).__name__}: {exc}"}
        out["outcomes"] = monitor.live_outcomes(snapshot, since, 7)
        if not out["outcomes"].get("active_hosts"):
            # Nothing to score means nothing detected: agents stopped reporting, or the
            # server was down all week. Either way the models are not protecting anything.
            run.attention("no endpoint telemetry arrived in the last 7 days - check the "
                          "agents and that the server is running")
    # consecutive_failures counts the runs BEFORE this one. Reaching this point means this run
    # did not abort, so earlier failures are a recovery, not a new problem; a run that does
    # fail exits 1 on its own.
    return out


def _retention(run: Run, conn) -> dict:
    runs_dir = os.path.join(run.home, "runs")
    runs = sorted(d for d in os.listdir(runs_dir) if os.path.isdir(os.path.join(runs_dir, d)))
    removed_runs = []
    for old in runs[:-run.policy.keep_runs]:
        shutil.rmtree(os.path.join(runs_dir, old), ignore_errors=True)
        removed_runs.append(old)
    protect = {t["version_id"] for t in trial.running_trials(conn)} | {run.version_id}
    removed_versions = store.prune(run.policy.keep_champion_versions, protect)
    return {"removed_runs": removed_runs, "removed_versions": removed_versions}


# --------------------------------------------------------------------------- entry point

def run_pipeline(*, force: bool = False, now: datetime | None = None, trigger: str = "schedule",
                 fetch: bool | None = None) -> int:
    from ml.mlops.lock import LockHeld, RunLock

    home = config.mlops_home()
    os.makedirs(home, exist_ok=True)
    if os.environ.get("ATOR_MLOPS_DISABLED") == "1" or _flag(home, "PAUSED"):
        print("MLOps pipeline is paused (python -m ml.mlops resume); nothing done.")
        return EXIT_OK
    policy = config.load_policy(home)
    if fetch is not None:
        import dataclasses
        policy = dataclasses.replace(policy, fetch_upstream=fetch)
    now = now or datetime.now(timezone.utc)

    lock = RunLock(os.path.join(home, "pipeline.lock"), policy.stale_lock_hours)
    try:
        lock.acquire()
    except LockHeld as exc:
        print(f"not started: {exc}")
        return EXIT_OK

    conn = None
    try:
        conn = _live_conn()
        # We hold the lock, so any run still marked 'running' died without finishing (power
        # cut, time limit). Close it, or the dashboard would say "Updating now" forever.
        conn.execute("""UPDATE ml_pipeline_runs SET status='failed', finished_at_utc=?,
                            summary_json='{"failed_stage": "interrupted", "attention":
                            ["this run was interrupted before it finished"]}'
                        WHERE status='running'""", (now.isoformat(timespec="seconds"),))
        conn.commit()
        last = _last_completed_start(conn)
        if last and not force and _hours_between(now, last) < policy.min_hours_between_runs:
            print(f"last completed run started {last}; next one is due "
                  f"{policy.min_hours_between_runs:g} h after it. Use --force to run anyway.")
            return EXIT_OK
        return _execute(Run(now, trigger, home, policy), conn, lock)
    finally:
        if conn is not None:
            conn.close()
        lock.release()


def _execute(run: Run, conn, lock) -> int:
    conn.execute("INSERT OR REPLACE INTO ml_pipeline_runs (run_id, started_at_utc, status, trigger) "
                 "VALUES (?, ?, 'running', ?)", (run.run_id, run.now_iso, run.summary["trigger"]))
    conn.commit()
    if lock.reclaimed:
        run.attention(f"the previous run did not finish (stale lock from pid "
                      f"{lock.reclaimed.get('pid')}); its lock was reclaimed")
    run.log(f"MLOps run {run.run_id} ({run.summary['trigger']})"
            + (" - promotion FROZEN" if _flag(run.home, "FROZEN") else ""))
    snapshot = None
    failed = False
    try:
        run.summary["preflight"] = run.stage("preflight", lambda: _preflight(run))
        snap = run.stage("snapshot", lambda: _snapshot(run))
        snapshot = snap["path"]
        run.summary["snapshot"] = {k: v for k, v in snap.items() if k != "path"}
        run.summary["trials"] = run.stage("conclude_trials",
                                          lambda: _conclude_trials(run, conn, snapshot))
        retrieved = run.stage("retrieve", lambda: _retrieve(run))
        run.summary["retrieve"] = {
            "fetch": retrieved["fetch"], "admitted": len(retrieved["admitted"]),
            "pending": retrieved["pending"], "changed": retrieved["changed"],
            "av_blocked": retrieved["av_blocked"]}
        exclusions = run.stage("exclusions", lambda: data.write_training_exclusions(
            snapshot, run.policy, run.now))
        run.summary["exclusions"] = {k: v for k, v in exclusions.items()
                                     if k != "local_fingerprint"}
        run.summary["etl"] = run.stage("etl", lambda: _etl(run, retrieved["admitted"]))
        trained = run.stage("train", lambda: _train(run, conn, snapshot, exclusions))
        run.summary["candidates"] = {"version_id": run.version_id, **trained}
        if trained["trained"]:
            gates = run.stage("evaluate", lambda: _evaluate(
                run, trained["trained"], snapshot, exclusions["cooling_off_since"],
                trained["plan"]))
            run.summary["offline_gates"] = gates
            store.atomic_write_json(os.path.join(store.version_dir(run.version_id), "card.json"), {
                "version_id": run.version_id, "run_id": run.run_id,
                "created_at_utc": run.now_iso, "plan": trained["plan"], "offline_gates": gates})
            run.summary["staged"] = run.stage("stage", lambda: _stage(
                run, conn, trained["trained"], gates, trained["plan"]))
    except StageFailed:
        failed = True
    except Exception as exc:                     # noqa: BLE001 - a bug between stages
        failed = True
        run.log(f"run aborted outside a stage: {type(exc).__name__}: {exc}")
        run.summary["stages"]["orchestrator"] = {"status": "failed",
                                                 "error": f"{type(exc).__name__}: {exc}"}
    finally:
        run.summary["monitor"] = run.stage("monitor", lambda: _monitor(run, conn, snapshot),
                                           critical=False)
        run.summary["retention"] = run.stage("retention", lambda: _retention(run, conn),
                                             critical=False)
        if not failed and snapshot and os.path.exists(snapshot):
            os.remove(snapshot)                  # kept only when the run failed, for diagnosis

    status = "failed" if failed else ("attention" if run.summary["attention"] else "succeeded")
    code = {"failed": EXIT_FAILED, "attention": EXIT_ATTENTION, "succeeded": EXIT_OK}[status]
    run.summary.update(status=status, exit_code=code,
                       finished_at_utc=datetime.now(timezone.utc).isoformat(timespec="seconds"))
    paths = report.write(run.dir, run.summary)
    from server import db as database
    conn.execute("""UPDATE ml_pipeline_runs SET finished_at_utc=?, status=?, summary_json=?,
                        report_path=? WHERE run_id=?""",
                 (run.summary["finished_at_utc"], status,
                  json.dumps(report.compact(run.summary), default=str), paths["markdown"],
                  run.run_id))
    database.audit(conn, "mlops", "ml_pipeline_run",
                   {"run_id": run.run_id, "status": status,
                    "promotions": [p.get("component") for p in run.summary["promotions"]
                                   if p.get("promoted")]})
    conn.commit()
    run.log(f"run {run.run_id} finished: {status} (exit {code}); report {paths['markdown']}")
    run.close()
    return code


if __name__ == "__main__":                       # pragma: no cover
    sys.exit(run_pipeline(force="--force" in sys.argv))
