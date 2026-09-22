"""Train stage: run the existing trainers into an immutable version directory.

The trainers are the same entry points a developer runs by hand (`ml.training.train_*`), so
there is exactly one training implementation. The pipeline adds three things on top:

* output goes to `models/registry/<version>/`, never to the served `models/`;
* each artefact is stamped with its version, fingerprint and lineage, so any model found
  on disk can be traced back to the run, data and code that produced it;
* a canary frame and the scores each artefact gives it are stored next to the artefacts,
  and the post-promotion smoke test replays them.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time

from ml.mlops import config, scoring, store

CANARY_ROWS = 64
CANARY_NAME = "canary.joblib"


def run_trainer(component: str, *, train_db: str, live_db: str, out_dir: str,
                report_path: str, log_path: str, timeout: int) -> dict:
    """Subprocess, so a trainer's memory is returned to the OS and one failure is contained."""
    cmd = [sys.executable, "-m", f"ml.training.train_{component}",
           "--train-db", train_db, "--live-db", live_db, "--models-dir", out_dir,
           "--report", report_path, "--save"]
    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")
    started = time.time()
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    with open(log_path, "w", encoding="utf-8", errors="replace") as log:
        try:
            proc = subprocess.run(cmd, cwd=config.PROJECT_ROOT, stdout=log,
                                  stderr=subprocess.STDOUT, timeout=timeout, env=env)
            returncode = proc.returncode
        except subprocess.TimeoutExpired:
            returncode = None
    files = {name: os.path.join(out_dir, f"{name}.joblib")
             for name in config.COMPONENT_FILES[component]}
    missing = [n for n, p in files.items() if not os.path.exists(p)]
    return {"component": component, "ok": returncode == 0 and not missing,
            "returncode": returncode, "timed_out": returncode is None,
            "seconds": round(time.time() - started, 1), "missing_artefacts": missing,
            "log": log_path, "report": report_path}


def stamp(path: str, **meta) -> None:
    """Add provenance keys to an artefact, atomically. Unknown keys are ignored when served."""
    import joblib

    artefact = joblib.load(path)
    artefact.update(meta)
    tmp = f"{path}.stamping"
    joblib.dump(artefact, tmp)
    store._replace(tmp, path)


def build_canary(train_db: str, version_dir: str, components: list[str]) -> dict:
    """A fixed small corpus sample plus the scores every artefact gives it.

    Includes attacks, so the check exercises the high-score end too. Replayed after promotion
    against the file the server will actually load: identical scores prove the right model
    was deployed intact and loads in this interpreter.
    """
    import joblib
    import numpy as np

    from ml.datasets import assemble as A

    dataset = A.load(train_db, live_db=None, include_local=False)
    if len(dataset) == 0:
        return {"rows": 0}
    rng = np.random.default_rng(42)
    positives = np.flatnonzero(dataset.y == A.LABEL_MALICIOUS)
    negatives = np.flatnonzero(dataset.y != A.LABEL_MALICIOUS)
    take = min(len(positives), CANARY_ROWS // 4)
    picked = np.concatenate([
        rng.choice(positives, size=take, replace=False) if take else np.array([], dtype=int),
        rng.choice(negatives, size=min(len(negatives), CANARY_ROWS - take), replace=False),
    ])
    frame = dataset.frame.iloc[np.sort(picked)].reset_index(drop=True)
    expected = {}
    for component in components:
        for name, path in store.component_files(os.path.basename(version_dir), component).items():
            artefact = scoring.load(path)
            if artefact is not None:
                expected[name] = scoring.score(component, artefact, frame, scoring.tier_of(name))
    joblib.dump({"frame": frame, "expected": expected}, os.path.join(version_dir, CANARY_NAME))
    return {"rows": int(len(frame)), "artefacts": sorted(expected)}


def canary_check(version_id: str, component: str, slot_loader) -> dict:
    """Replay the stored canary through `slot_loader(model_type, tier)` - normally
    `ml_registry.load_artefact`, i.e. the server's own loader and spec guard."""
    import joblib
    import numpy as np

    path = os.path.join(store.version_dir(version_id), CANARY_NAME)
    if not os.path.exists(path):
        # A version archived from before the pipeline (legacy/manual) has no canary. The
        # weaker check still proves the server's loader accepts every file.
        loaded = {}
        for name in config.COMPONENT_FILES[component]:
            if name not in store.component_files(version_id, component):
                continue
            model_type, tier = name.rsplit("_", 1)
            loaded[name] = slot_loader(model_type, tier) is not None
        ok = bool(loaded) and all(loaded.values())
        return {"ok": ok, "checked": loaded,
                "reason": None if ok else "the server's loader refused an artefact",
                "note": "no canary stored for this version; load check only"}
    canary = joblib.load(path)
    results = {}
    for name in config.COMPONENT_FILES[component]:
        if name not in canary["expected"]:
            continue
        model_type, tier = name.rsplit("_", 1)
        artefact = slot_loader(model_type, tier)
        if artefact is None:
            return {"ok": False, "reason": f"{name}: the server's loader refused the artefact"}
        if artefact.get("version_id") != version_id:
            return {"ok": False, "reason": f"{name}: serving version "
                                           f"{artefact.get('version_id')!r}, expected {version_id!r}"}
        got = scoring.score(component, artefact, canary["frame"], tier)
        same = bool(np.allclose(got, canary["expected"][name], atol=1e-9, equal_nan=True))
        results[name] = same
        if not same:
            return {"ok": False, "reason": f"{name}: canary scores differ from training time",
                    "checked": results}
    return {"ok": bool(results), "checked": results,
            "reason": None if results else "nothing to check"}
