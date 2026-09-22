"""Retrieve and ETL stages: corpus fetch and admission, live snapshot, poisoning exclusions,
staged training-database build, validation, fingerprints.

Nothing in this module writes to the live DFIR database or to the served models. Everything it
produces lives in the run directory or in a staging file that replaces `ml_train.db` only
after validation passes.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from datetime import datetime, timedelta

from ml.mlops import config, store

KV_ETL_HASH = "mlops_etl_code_sha256"
APPROVED_BASELINE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 "approved_captures.json")
LOCAL_APPROVALS = "approved_captures.local.json"
DATA_STATE = "data_state.json"


# --------------------------------------------------------------------------- hashing

def code_hash(relative_paths) -> str:
    """Content hash of source files, line-ending agnostic (git autocrlf must not retrain)."""
    h = hashlib.sha256()
    for rel in sorted(relative_paths):
        h.update(rel.encode())
        path = os.path.join(config.PROJECT_ROOT, rel)
        if os.path.exists(path):
            with open(path, "rb") as fh:
                h.update(fh.read().replace(b"\r\n", b"\n"))
        else:
            h.update(b"<missing>")
    return h.hexdigest()


def library_versions() -> dict:
    import platform

    out = {"python": ".".join(platform.python_version_tuple()[:2])}
    for module in ("sklearn", "numpy", "pandas", "joblib"):
        try:
            out[module] = __import__(module).__version__
        except Exception:                        # noqa: BLE001
            out[module] = None
    return out


def corpus_hash(train_db: str) -> str:
    """Hash of what the corpus teaches: which captures, and every label in them."""
    h = hashlib.sha256()
    conn = sqlite3.connect(train_db)
    try:
        for row in conn.execute("SELECT capture_id, sha256 FROM corpus_captures ORDER BY capture_id"):
            h.update(f"{row[0]}|{row[1]}\n".encode())
        for row in conn.execute("""SELECT capture_id, process_guid, label, COALESCE(tactic,'')
                                   FROM corpus_labels ORDER BY capture_id, process_guid"""):
            h.update("|".join(str(v) for v in row).encode())
    finally:
        conn.close()
    return h.hexdigest()


def component_fingerprint(component: str, *, corpus: str, local: str | None,
                          policy: config.Policy) -> str:
    """Everything that decides what `component`'s trainer would produce."""
    payload = {
        "component": component,
        "corpus": corpus,
        "code": code_hash(config.COMPONENT_CODE[component]),
        "libraries": library_versions(),
    }
    if component == "anomaly":
        # Only Component A learns from live rows; B and C are corpus-only (assemble.py).
        payload["local"] = local
        payload["admission"] = [policy.cooling_off_days, policy.local_window_days,
                                policy.max_local_rows, policy.incident_window_hours]
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


# --------------------------------------------------------------------------- retrieve

def fetch_corpus(policy: config.Policy, log) -> dict:
    """Download new upstream captures. Network failure degrades to the cached corpus."""
    from ml.datasets import otrf

    if not policy.fetch_upstream:
        return {"status": "skipped", "reason": "fetch_upstream disabled"}
    try:
        stats = otrf.fetch(config.corpus_dir(), verbose=False)
    except Exception as exc:                     # noqa: BLE001 - offline is a normal state
        log(f"upstream fetch failed, using cached corpus: {type(exc).__name__}: {exc}")
        return {"status": "degraded", "reason": f"{type(exc).__name__}: {exc}"}
    return {"status": "ok", "remote_total": stats["total"], "downloaded": stats["downloaded"],
            "failed": stats["failed"]}


def approved_captures(home: str) -> dict[str, str | None]:
    """filename -> pinned sha256. Committed baseline plus operator approvals."""
    approved: dict[str, str | None] = {}
    for path in (APPROVED_BASELINE, os.path.join(home, LOCAL_APPROVALS)):
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                approved.update(json.load(fh).get("captures", {}))
    return approved


def approve(home: str, filenames: list[str]) -> dict:
    """Pin the CURRENT content of the named captures as approved (operator action)."""
    from ml.datasets import otrf

    path = os.path.join(home, LOCAL_APPROVALS)
    current = {"captures": {}}
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            current = json.load(fh)
    added, missing = [], []
    for name in filenames:
        full = os.path.join(config.corpus_dir(), name)
        digest = otrf.sha256_file(full) if os.path.exists(full) else None
        if digest is None:
            missing.append(name)
            continue
        current["captures"][name] = digest
        added.append(name)
    store.atomic_write_json(path, current)
    return {"approved": added, "not_found_or_unreadable": missing}


def admit_captures(home: str) -> dict:
    """Split local captures into admitted / pending review / changed-since-approval.

    Labels come from per-capture signatures (ml/datasets/labels.py). A capture nobody wrote
    signatures for would be labelled all-benign, attack included, and poison the negative
    class. So a new capture waits for a human; see docs/ML_MLOPS_PLAN.md 4.5.
    """
    from ml.datasets import otrf

    approved = approved_captures(home)
    admitted, pending, changed = [], [], []
    for capture in otrf.local_captures(config.corpus_dir(), scope="host"):
        digest = otrf.sha256_file(capture.local_path)
        if capture.filename not in approved:
            pending.append({"capture": capture.filename, "sha256": digest})
        elif approved[capture.filename] and approved[capture.filename] != digest:
            changed.append({"capture": capture.filename, "sha256": digest,
                            "approved_sha256": approved[capture.filename]})
        else:
            admitted.append(capture)
    return {"admitted": admitted, "pending": pending, "changed": changed,
            "blocked": otrf.blocked_captures(config.corpus_dir())}


# --------------------------------------------------------------------------- live snapshot

def snapshot_live_db(live_path: str, dest: str) -> dict:
    """Point-in-time copy through SQLite's online backup API.

    Consistent even while the server is ingesting, and the live file is only read. The copy
    is migrated so the pipeline can query ML tables a pre-Phase-10 live DB does not have yet.
    """
    from server import db as database

    if not os.path.exists(live_path):
        raise FileNotFoundError(f"live database not found: {live_path}")
    for suffix in ("", "-wal", "-shm"):
        if os.path.exists(dest + suffix):
            os.remove(dest + suffix)
    src = sqlite3.connect(live_path, timeout=30)
    dst = sqlite3.connect(dest)
    try:
        src.backup(dst)
    finally:
        src.close()
        dst.close()
    database.init_db(dest)
    conn = sqlite3.connect(dest)
    try:
        check = conn.execute("PRAGMA quick_check").fetchone()[0]
        processes = conn.execute("SELECT COUNT(*) FROM raw_processes").fetchone()[0]
    finally:
        conn.close()
    if check != "ok":
        raise RuntimeError(f"live snapshot failed integrity check: {check}")
    return {"path": dest, "bytes": os.path.getsize(dest), "quick_check": check,
            "raw_processes": processes}


# --------------------------------------------------------------------------- exclusions

_RULE_TYPES_ML = ("ml_anomaly", "ml_triage")
_SERIOUS = ("high", "critical")


def _detection_targets(conn) -> list[dict]:
    """Every detection, resolved to the process it is about (host, pid, name, raw id)."""
    from server.engine.ml_integration import _pid_from_summary

    has_feedback = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='ml_feedback'").fetchone()
    sql = ("SELECT d.id, d.host_id, d.rule_type, d.severity, d.summary, d.detected_at_utc, "
           "d.ml_explanation, " + ("f.verdict" if has_feedback else "NULL") + " AS verdict, "
           "d.confidence_score "
           "FROM detections d "
           + ("LEFT JOIN ml_feedback f ON f.detection_id = d.id" if has_feedback else ""))
    out = []
    for row in conn.execute(sql):
        name, raw_id = None, None
        try:
            name = (json.loads(row[4] or "{}") or {}).get("name")
        except (TypeError, ValueError, AttributeError):
            pass
        try:
            raw_id = (json.loads(row[6] or "{}") or {}).get("raw_process_id")
        except (TypeError, ValueError, AttributeError):
            pass
        out.append({"id": row[0], "host_id": row[1], "rule_type": row[2], "severity": row[3],
                    "pid": _pid_from_summary(row[4]), "name": (name or "").lower() or None,
                    "detected_at": row[5], "raw_process_id": raw_id, "verdict": row[7],
                    "confidence": row[8]})
    return out


def write_training_exclusions(snapshot: str, policy: config.Policy, now: datetime) -> dict:
    """Decide which live rows may be assumed benign, and record the rest in the snapshot.

    docs/ML_MLOPS_PLAN.md 4.4. The first matching reason wins, in this order:
    cooling_off, detected, descendant, incident_window, feedback_cap, outside_window, row_cap.
    """
    import pandas as pd

    conn = sqlite3.connect(snapshot)
    try:
        procs = pd.read_sql_query(
            """SELECT p.id, p.host_id, p.pid, p.ppid, LOWER(COALESCE(p.name,'')) AS name,
                      p.collected_at_utc, p.create_time_utc, h.client_id
               FROM raw_processes p JOIN hosts h ON h.id = p.host_id""", conn)
        targets = _detection_targets(conn)
    finally:
        conn.close()

    procs = procs[~procs["client_id"].fillna("").str.startswith("demo-")].copy()
    procs["seen"] = pd.to_datetime(procs["collected_at_utc"], utc=True, errors="coerce")
    now_ts = pd.Timestamp(now)
    reasons: dict[int, str] = {}

    def mark(ids, reason):
        for raw_id in ids:
            reasons.setdefault(int(raw_id), reason)

    # 1. cooling-off: too recent to have been reviewed. Also the temporal hold-out (4.6 A4).
    cutoff = now_ts - pd.Timedelta(days=policy.cooling_off_days)
    mark(procs.loc[procs["seen"].isna() | (procs["seen"] >= cutoff), "id"], "cooling_off")

    # 2. processes any detector flagged - except ML leads an analyst dismissed as benign,
    #    unless a deterministic rule also fired on the same process.
    rule_keys = {(t["host_id"], t["pid"]) for t in targets
                 if t["rule_type"] not in _RULE_TYPES_ML and t["pid"] is not None}
    flagged, readmit, cascade, low_likelihood = set(), set(), set(), set()
    by_host_pid = procs.groupby(["host_id", "pid"])["id"].apply(list).to_dict() \
        if not procs.empty else {}
    names = dict(zip(procs["id"], procs["name"]))
    for t in targets:
        ids = []
        if t["raw_process_id"] is not None:
            ids.append(int(t["raw_process_id"]))
        if t["pid"] is not None:
            for raw_id in by_host_pid.get((t["host_id"], t["pid"]), []):
                # name must agree when both sides have one: bounds pid-reuse over-matching
                if not t["name"] or not names.get(raw_id) or names[raw_id] == t["name"]:
                    ids.append(int(raw_id))
        is_ml = t["rule_type"] in _RULE_TYPES_ML
        no_rule = (t["host_id"], t["pid"]) not in rule_keys
        dismissed = is_ml and t["verdict"] == "benign" and no_rule
        # An unreviewed ML lead the calibrated triage model rates unlikely to be an attack stays
        # in the baseline. Excluding every ML lead was measured (docs/ML_PROGRESS.md, Phase 10)
        # to DOUBLE next week's alert rate on unseen traffic: removing the model's own false
        # positives from "normal" makes the next model find them rarer still - a self-
        # reinforcing loop. Leads it rates likely malicious, or could not score, stay out.
        unlikely = (is_ml and t["verdict"] is None and no_rule and t["confidence"] is not None
                    and float(t["confidence"]) < policy.ml_lead_readmit_below)
        if dismissed:
            readmit.update(ids)
        elif unlikely:
            low_likelihood.update(ids)
        else:
            flagged.update(ids)
        # Lineage is followed only from findings that are probably real: a deterministic rule
        # hit, or an ML lead an analyst confirmed. An unreviewed ML lead is a statistical
        # outlier - one on `System` (pid 4) would otherwise exclude most of the OS tree.
        if t["rule_type"] not in _RULE_TYPES_ML or t["verdict"] == "confirmed":
            cascade.update(ids)
    readmit -= flagged
    low_likelihood -= flagged
    mark(sorted(flagged), "detected")

    # 3. descendants of flagged processes (same host, ppid chain, start-time ordered).
    #    Start times are ISO strings or missing. pandas stores a missing one as NaN, which is
    #    truthy and not comparable to a string, so only two real strings are ever compared.
    def _start(value):
        return value if isinstance(value, str) and value else None

    children: dict[tuple, list] = {}
    for row in procs.itertuples(index=False):
        if pd.notna(row.ppid):
            children.setdefault((row.host_id, int(row.ppid)), []).append(row)
    from ml.datasets.labels import _SEED_DENYLIST       # OS roots never propagate (labels.py)
    frontier = [(r.host_id, int(r.pid), _start(r.create_time_utc))
                for r in procs[procs["id"].isin(cascade)].itertuples(index=False)
                if pd.notna(r.pid) and r.name not in _SEED_DENYLIST]
    for _ in range(policy.lineage_depth):
        nxt = []
        for host_id, pid, started in frontier:
            for child in children.get((host_id, pid), ()):
                child_start = _start(child.create_time_utc)
                if started and child_start and child_start < started:
                    continue                     # started before the parent: a reused pid
                if int(child.id) not in reasons:
                    reasons[int(child.id)] = "descendant"
                    if pd.notna(child.pid):
                        nxt.append((child.host_id, int(child.pid), child_start))
        frontier = nxt

    # 4. rows near a serious deterministic detection on the same host.
    window = pd.Timedelta(hours=policy.incident_window_hours)
    for t in targets:
        if t["rule_type"] in _RULE_TYPES_ML or (t["severity"] or "") not in _SERIOUS:
            continue
        at = pd.to_datetime(t["detected_at"], utc=True, errors="coerce")
        if pd.isna(at):
            continue
        near = procs[(procs["host_id"] == t["host_id"]) & (procs["seen"] >= at - window)
                     & (procs["seen"] <= at + window)]
        mark(near["id"], "incident_window")

    # 5. analyst re-admissions are capped (the dashboard has no auth; plan 4.4).
    readmitted = sorted(i for i in readmit if i not in reasons)
    if len(readmitted) > policy.max_feedback_readmissions:
        mark(readmitted[policy.max_feedback_readmissions:], "feedback_cap")
        readmitted = readmitted[:policy.max_feedback_readmissions]

    # 6. bounded training window, then a row cap keeping the newest.
    oldest = now_ts - pd.Timedelta(days=policy.local_window_days)
    mark(procs.loc[procs["seen"] < oldest, "id"], "outside_window")
    eligible = procs[~procs["id"].isin(list(reasons))].sort_values("seen", ascending=False)
    if len(eligible) > policy.max_local_rows:
        mark(eligible["id"].iloc[policy.max_local_rows:], "row_cap")

    admitted = procs[~procs["id"].isin(list(reasons))].sort_values("id")
    local_fp = hashlib.sha256("\n".join(
        f"{i}|{s}" for i, s in zip(admitted["id"], admitted["collected_at_utc"])).encode()
    ).hexdigest()

    conn = sqlite3.connect(snapshot)
    try:
        conn.execute("DROP TABLE IF EXISTS ml_training_exclusions")
        conn.execute("""CREATE TABLE ml_training_exclusions (
                            raw_process_id INTEGER PRIMARY KEY, reason TEXT NOT NULL)""")
        conn.executemany("INSERT INTO ml_training_exclusions VALUES (?, ?)",
                         sorted(reasons.items()))
        conn.commit()
    finally:
        conn.close()

    by_reason: dict[str, int] = {}
    for reason in reasons.values():
        by_reason[reason] = by_reason.get(reason, 0) + 1
    return {"local_rows": int(len(procs)), "admitted": int(len(admitted)),
            "excluded": int(len(reasons)), "by_reason": by_reason,
            "feedback_readmitted": readmitted,
            "low_likelihood_leads_kept": len(low_likelihood - set(reasons)),
            "local_fingerprint": local_fp,
            "cooling_off_since": cutoff.isoformat()}


# --------------------------------------------------------------------------- ETL

def _read_kv(path: str, key: str):
    try:
        conn = sqlite3.connect(path)
        try:
            row = conn.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
            return row[0] if row else None
        finally:
            conn.close()
    except sqlite3.Error:
        return None


def _imported_captures(path: str) -> set[str]:
    try:
        conn = sqlite3.connect(path)
        try:
            return {r[0] for r in conn.execute("SELECT capture_id FROM corpus_captures")}
        finally:
            conn.close()
    except sqlite3.Error:
        return set()


def training_db_stats(path: str) -> dict:
    conn = sqlite3.connect(path)
    try:
        labels = dict(conn.execute("SELECT label, COUNT(*) FROM corpus_labels GROUP BY label"))
        by_tactic = dict(conn.execute(
            """SELECT tactic, COUNT(*) FROM corpus_labels WHERE label='malicious'
               GROUP BY tactic"""))
        return {
            "captures": conn.execute("SELECT COUNT(*) FROM corpus_captures").fetchone()[0],
            "processes": conn.execute("SELECT COUNT(*) FROM raw_processes").fetchone()[0],
            "malicious": int(labels.get("malicious", 0)),
            "benign": int(labels.get("benign", 0)),
            "malicious_by_tactic": {str(k): int(v) for k, v in by_tactic.items()},
        }
    finally:
        conn.close()


def build_training_db(admitted, canonical: str, staging: str, log) -> dict:
    """ETL + labels into `staging`. Incremental when safe, full otherwise."""
    from ml.datasets import labels, otrf_etl

    etl_hash = code_hash(config.ETL_CODE)
    admitted_ids = {c.capture_id for c in admitted}
    mode, why = "full", "no existing training database"
    if os.path.exists(canonical):
        existing_hash = _read_kv(canonical, KV_ETL_HASH)
        existing = _imported_captures(canonical)
        if existing_hash != etl_hash:
            why = ("ETL code changed since the last build" if existing_hash
                   else "training database was not built by the pipeline")
        elif not existing <= admitted_ids:
            why = f"{len(existing - admitted_ids)} imported capture(s) no longer admitted"
        else:
            mode, why = "incremental", f"{len(admitted_ids - existing)} new capture(s)"

    for suffix in ("", "-wal", "-shm"):
        if os.path.exists(staging + suffix):
            os.remove(staging + suffix)
    os.makedirs(os.path.dirname(staging), exist_ok=True)
    if mode == "incremental":
        src, dst = sqlite3.connect(canonical), sqlite3.connect(staging)
        try:
            src.backup(dst)
        finally:
            src.close()
            dst.close()
    log(f"ETL {mode}: {why}")
    built = otrf_etl.build(staging, config.corpus_dir(), captures=list(admitted),
                           rebuild=(mode == "full"), verbose=False)
    labelled = labels.label_all(staging, verbose=False)

    conn = sqlite3.connect(staging)
    try:
        conn.execute("INSERT OR REPLACE INTO kv (key, value) VALUES (?, ?)", (KV_ETL_HASH, etl_hash))
        conn.commit()
        # A single self-contained file: the swap must not leave a -wal behind that belongs
        # to a different database.
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.execute("PRAGMA journal_mode=DELETE")
    finally:
        conn.close()
    return {"mode": mode, "reason": why, "captures_imported": built["captures_imported"],
            "captures_with_no_seed": labelled.get("captures_with_no_seed", []),
            "stats": training_db_stats(staging)}


def validate_training_db(stats: dict, previous: dict | None, expected_captures: int,
                         policy: config.Policy) -> list[dict]:
    """Data contract checks. Any failed 'error' check stops the run before training."""
    from server.engine import ml_tactic

    checks = []

    def check(name, ok, detail, severity="error"):
        checks.append({"check": name, "ok": bool(ok), "detail": detail, "severity": severity})

    check("has_processes", stats["processes"] > 0, f"{stats['processes']} processes")
    check("has_attacks", stats["malicious"] > 0, f"{stats['malicious']} malicious labels")
    check("all_admitted_imported", stats["captures"] >= expected_captures,
          f"{stats['captures']} imported of {expected_captures} admitted",
          severity="warning")
    if previous:
        floor = previous["malicious"] * (1 - policy.max_positive_drop)
        check("attacks_not_lost", stats["malicious"] >= floor,
              f"{stats['malicious']} malicious vs {previous['malicious']} last build")
        floor = previous["processes"] * (1 - policy.max_process_drop)
        check("processes_not_lost", stats["processes"] >= floor,
              f"{stats['processes']} processes vs {previous['processes']} last build")
        lost = [t for t, n in previous.get("malicious_by_tactic", {}).items()
                if n >= ml_tactic.MIN_EXAMPLES_PER_CLASS
                and stats["malicious_by_tactic"].get(t, 0) < ml_tactic.MIN_EXAMPLES_PER_CLASS]
        check("tactic_classes_kept", not lost,
              f"classes fell below {ml_tactic.MIN_EXAMPLES_PER_CLASS} examples: {lost}"
              if lost else "every learnable tactic class kept")
    return checks


def swap_training_db(staging: str, canonical: str) -> None:
    for suffix in ("-wal", "-shm"):
        if os.path.exists(canonical + suffix):
            os.remove(canonical + suffix)
    store._replace(staging, canonical)


def load_data_state(home: str) -> dict | None:
    path = os.path.join(home, DATA_STATE)
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def save_data_state(home: str, stats: dict) -> None:
    store.atomic_write_json(os.path.join(home, DATA_STATE), stats)


def since(now: datetime, days: float) -> str:
    return (now - timedelta(days=days)).isoformat(timespec="seconds")
