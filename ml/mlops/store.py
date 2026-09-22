"""Versioned model store: immutable versions, atomic promotion, rollback, reconciliation.

Layout (inside the served models directory, which is git-ignored):

    models/anomaly_t1.joblib ...            the champions - the ONLY files the server serves
    models/shadow/anomaly_t1.joblib         the challenger under a live trial
    models/registry/<version>/<name>.joblib immutable copy of every artefact ever produced
    models/registry/<version>/card.json     metrics, gate results, fingerprints
    models/registry/history.json            champion history per component

The serving paths are unchanged from before Phase 10, so the server needs no new code to pick
up a promotion: `ml_registry.load_artefact` re-reads a file whose (mtime, size) changed.

**history.json is the source of truth** for what the champion should be. `reconcile()` compares
it with what is actually on disk and repairs the two situations an unattended job produces:
a crash halfway through swapping a component's files (restore the recorded champion), and a
human dropping a hand-trained model into models/ (adopt it, so rollback can still reach it).
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import time

from ml.mlops import config

HISTORY_NAME = "history.json"


def sha256_file(path: str) -> str | None:
    if not os.path.exists(path):
        return None
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def version_dir(version_id: str) -> str:
    return os.path.join(config.registry_dir(), version_id)


def serving_path(name: str) -> str:
    return os.path.join(config.models_dir(), f"{name}.joblib")


def shadow_path(name: str) -> str:
    return os.path.join(config.models_dir(), "shadow", f"{name}.joblib")


def atomic_write_json(path: str, payload) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True, default=str)
        fh.flush()
        os.fsync(fh.fileno())
    _replace(tmp, path)


def _replace(src: str, dst: str, attempts: int = 8) -> None:
    """os.replace with retries.

    Windows refuses to replace a file another process has open. The server opens an artefact
    only for the instant `joblib.load` reads it, and antivirus scans new files briefly, so
    waiting a moment is always enough - failing the promotion would not be.
    """
    delay = 0.25
    for attempt in range(attempts):
        try:
            os.replace(src, dst)
            return
        except PermissionError:
            if attempt == attempts - 1:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 4.0)


def atomic_copy(src: str, dst: str) -> None:
    """Copy so that `dst` is either the old file or the complete new one, never half."""
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    tmp = os.path.join(os.path.dirname(dst), f".{os.path.basename(dst)}.incoming")
    shutil.copyfile(src, tmp)                    # copyfile, not copy2: a FRESH mtime is what
    with open(tmp, "rb+") as fh:                 # tells the server's cache to reload
        os.fsync(fh.fileno())
    _replace(tmp, dst)


# --------------------------------------------------------------------------- history

def load_history() -> dict:
    path = os.path.join(config.registry_dir(), HISTORY_NAME)
    if not os.path.exists(path):
        return {"champions": {}}
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    data.setdefault("champions", {})
    return data


def save_history(history: dict) -> None:
    atomic_write_json(os.path.join(config.registry_dir(), HISTORY_NAME), history)


def champion_entry(component: str, history: dict | None = None) -> dict | None:
    entries = (history or load_history())["champions"].get(component) or []
    return entries[-1] if entries else None


def _append(history: dict, component: str, entry: dict) -> None:
    history["champions"].setdefault(component, []).append(entry)


# --------------------------------------------------------------------------- versions

def component_files(version_id: str, component: str) -> dict[str, str]:
    """name -> path of a component's artefacts inside one stored version."""
    out = {}
    for name in config.COMPONENT_FILES[component]:
        path = os.path.join(version_dir(version_id), f"{name}.joblib")
        if os.path.exists(path):
            out[name] = path
    return out


def version_hashes(version_id: str, component: str) -> dict[str, str]:
    return {name: sha256_file(path) for name, path in component_files(version_id, component).items()}


def serving_hashes(component: str, slot: str = "champion") -> dict[str, str | None]:
    locate = serving_path if slot == "champion" else shadow_path
    return {name: sha256_file(locate(name)) for name in config.COMPONENT_FILES[component]}


def _known_versions() -> list[str]:
    root = config.registry_dir()
    if not os.path.isdir(root):
        return []
    return sorted(d for d in os.listdir(root) if os.path.isdir(os.path.join(root, d)))


def _read_artefact_meta(path: str) -> dict:
    try:
        import joblib
        artefact = joblib.load(path)
        return {k: artefact.get(k) for k in ("version_id", "trained_at_utc")}
    except Exception:                            # noqa: BLE001
        return {}


def adopt_serving(component: str, reason: str, now: str) -> dict | None:
    """Archive whatever currently serves `component` as a stored version.

    Used for the hand-trained champions that predate the pipeline, and for a model a human
    replaced by hand. Without this, the first rollback after such a change would have
    nowhere to go.
    """
    present = {n: serving_path(n) for n in config.COMPONENT_FILES[component]
               if os.path.exists(serving_path(n))}
    if not present:
        return None
    first = next(iter(present.values()))
    meta = _read_artefact_meta(first)
    digest = sha256_file(first)[:10]
    version_id = meta.get("version_id") or f"{reason}-{digest}"
    target = version_dir(version_id)
    os.makedirs(target, exist_ok=True)
    for name, path in present.items():
        dst = os.path.join(target, f"{name}.joblib")
        if not os.path.exists(dst):
            atomic_copy(path, dst)
    card_path = os.path.join(target, "card.json")
    if not os.path.exists(card_path):
        atomic_write_json(card_path, {"version_id": version_id, "origin": reason,
                                      "trained_at_utc": meta.get("trained_at_utc"),
                                      "archived_at_utc": now})
    history = load_history()
    entry = {"version_id": version_id, "promoted_at_utc": now, "reason": reason,
             "files": version_hashes(version_id, component)}
    _append(history, component, entry)
    save_history(history)
    return entry


def reconcile(component: str, now: str) -> dict:
    """Make the served files agree with history.json. Returns what was done."""
    on_disk = {k: v for k, v in serving_hashes(component).items() if v}
    history = load_history()
    entry = champion_entry(component, history)

    if not on_disk:
        return {"component": component, "action": "none", "note": "no champion on disk"}
    if entry is None:
        adopted = adopt_serving(component, "legacy", now)
        return {"component": component, "action": "adopted_legacy",
                "version_id": adopted and adopted["version_id"]}
    expected = {k: v for k, v in (entry.get("files") or {}).items() if v}
    if on_disk == expected:
        return {"component": component, "action": "ok", "version_id": entry["version_id"]}

    known = {}
    for version in _known_versions():
        for name, digest in version_hashes(version, component).items():
            known[(name, digest)] = version
    if all((name, digest) in known for name, digest in on_disk.items()):
        # Every file belongs to a stored version but the set is mixed or stale: a promotion
        # or rollback was interrupted. Restore the last recorded champion.
        install(component, entry["version_id"], slot="champion")
        return {"component": component, "action": "repaired_interrupted_swap",
                "version_id": entry["version_id"]}
    adopted = adopt_serving(component, "manual", now)
    return {"component": component, "action": "adopted_manual_change",
            "version_id": adopted and adopted["version_id"]}


def install(component: str, version_id: str, slot: str = "champion") -> list[str]:
    files = component_files(version_id, component)
    if not files:
        raise FileNotFoundError(f"version {version_id} has no {component} artefacts")
    locate = serving_path if slot == "champion" else shadow_path
    written = []
    for name, src in files.items():
        dst = locate(name)
        atomic_copy(src, dst)
        written.append(dst)
    return written


def promote(component: str, version_id: str, reason: str, now: str) -> dict:
    reconcile(component, now)                    # archive the outgoing champion first
    install(component, version_id, slot="champion")
    history = load_history()
    entry = {"version_id": version_id, "promoted_at_utc": now, "reason": reason,
             "files": version_hashes(version_id, component)}
    _append(history, component, entry)
    save_history(history)
    return entry


def previous_version(component: str) -> str | None:
    entries = load_history()["champions"].get(component) or []
    if not entries:
        return None
    current = entries[-1]["version_id"]
    for entry in reversed(entries[:-1]):
        if entry["version_id"] != current and component_files(entry["version_id"], component):
            return entry["version_id"]
    return None


def rollback(component: str, now: str, reason: str = "rollback") -> dict:
    target = previous_version(component)
    if target is None:
        raise RuntimeError(f"no earlier {component} version to roll back to")
    install(component, target, slot="champion")
    history = load_history()
    entry = {"version_id": target, "promoted_at_utc": now, "reason": reason,
             "files": version_hashes(target, component)}
    _append(history, component, entry)
    save_history(history)
    return entry


def clear_shadow() -> list[str]:
    removed = []
    shadow_dir = os.path.join(config.models_dir(), "shadow")
    if os.path.isdir(shadow_dir):
        for filename in os.listdir(shadow_dir):
            if filename.endswith(".joblib"):
                os.remove(os.path.join(shadow_dir, filename))
                removed.append(filename)
    return removed


def prune(keep_versions: int, protect: set[str]) -> list[str]:
    """Delete stored versions nobody can roll back to any more."""
    history = load_history()
    keep = set(protect)
    for entries in history["champions"].values():
        distinct: list[str] = []
        for entry in reversed(entries):
            if entry["version_id"] not in distinct:
                distinct.append(entry["version_id"])
        keep.update(distinct[:keep_versions])
    removed = []
    for version in _known_versions():
        if version not in keep:
            shutil.rmtree(version_dir(version), ignore_errors=True)
            removed.append(version)
    return removed
