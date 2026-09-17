"""Assemble the modelling dataset from the corpus plus local benign telemetry.

Two sources, deliberately combined
----------------------------------
1. **Corpus** (`ml_train.db`) - 115 OTRF captures, lineage-labelled. Supplies every positive
   and most negatives.
2. **Local benign** (`ator_dfir.db`) - 538 process rows from real agent collections.

The local rows are not padding. The skew audit
(`python -m ml.evaluation.audit_baseline`) showed that **27% of live processes have no
command line at all** - psutil cannot read `cmdline` for protected processes when the agent
runs unelevated (svchost.exe, System, Registry, csrss.exe, LsaIso.exe...). In the corpus,
`cmdline` is present for 100% of rows, because Sysmon records it regardless of ACLs.

A model trained only on the corpus would therefore never once see `cmdline_present=0`, and
would meet that pattern for the first time in production - on precisely the process names
attackers like to masquerade as. Mixing the local rows in is what teaches it that pattern.

The benign assumption, stated plainly
-------------------------------------
Local rows are labelled benign **by assumption**: they come from the developers' own
workstation, which is not known to be compromised. This is the standard "clean baseline"
assumption and it is a real limitation - if that machine was infected, we are training on
mislabelled data. Two safeguards:

* the **demo fixture hosts are excluded**. `ator_dfir.db` hosts 2/3/4 (`client_id` prefixed
  `demo-`) hold 7 deliberately malicious rows - mimikatz, encoded PowerShell, `curl | sh` -
  planted by `scripts/make_demo_dataset.py`. Labelling those benign would poison the
  negative class outright. Only hosts whose `client_id` is not `demo-%` are used.
* local rows are tagged `source='local'` so their contribution can be ablated.

Grouping for cross-validation
-----------------------------
The CV group is the **capture** for corpus rows and the **collection** for local rows.
Splitting at row level would put sibling processes of one attack on both sides of the split;
the model would then recognise the capture rather than the behaviour, and every metric would
be inflated. Note the local rows come from one physical machine (hosts 5 and 7 are the same
box enrolled twice), so local benign diversity is low - stated in the evaluation report.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

import numpy as np
import pandas as pd

from ml.datasets.otrf_etl import DEFAULT_TRAIN_DB
from server import db as database
from server.engine import ml_features as mlf

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_LIVE_DB = os.path.join(_PROJECT_ROOT, "ator_dfir.db")

LABEL_MALICIOUS, LABEL_BENIGN = 1, 0
SOURCE_CORPUS, SOURCE_LOCAL = "corpus", "local"

# Hosts seeded by scripts/make_demo_dataset.py. Their rows are synthetic attack fixtures,
# not benign baseline, and must never be used as negatives.
DEMO_CLIENT_PREFIX = "demo-"


@dataclass
class Dataset:
    """Raw frame plus aligned targets. Features are NOT materialised here.

    `transform` is left to the caller because the rarity features need statistics fitted on
    training folds only; materialising X up front would leak the test folds' name
    distribution into every model. Use `materialise()` inside the CV loop.
    """
    frame: pd.DataFrame
    y: np.ndarray
    groups: np.ndarray
    tactics: np.ndarray
    sources: np.ndarray
    meta: dict = field(default_factory=dict)

    def __len__(self) -> int:
        return len(self.frame)

    @property
    def n_positive(self) -> int:
        return int((self.y == LABEL_MALICIOUS).sum())

    def subset(self, mask) -> "Dataset":
        mask = np.asarray(mask)
        return Dataset(
            frame=self.frame.loc[mask].reset_index(drop=True),
            y=self.y[mask], groups=self.groups[mask],
            tactics=self.tactics[mask], sources=self.sources[mask],
            meta=dict(self.meta),
        )

    def summary(self) -> dict:
        by_source = {}
        for src in (SOURCE_CORPUS, SOURCE_LOCAL):
            m = self.sources == src
            if m.sum():
                by_source[src] = {
                    "rows": int(m.sum()),
                    "malicious": int((self.y[m] == LABEL_MALICIOUS).sum()),
                    "groups": int(len(set(self.groups[m]))),
                }
        tactic_counts = pd.Series(
            self.tactics[self.y == LABEL_MALICIOUS]).value_counts().to_dict()
        return {
            "rows": len(self),
            "malicious": self.n_positive,
            "benign": len(self) - self.n_positive,
            "positive_rate": round(self.n_positive / max(len(self), 1), 4),
            "groups": int(len(set(self.groups))),
            "by_source": by_source,
            "malicious_by_tactic": {str(k): int(v) for k, v in tactic_counts.items()},
        }


def _corpus_labels(conn) -> pd.DataFrame:
    """raw_process_id -> (label, tactic), joined by primary key.

    The link is explicit (`corpus_lineage.raw_process_id`) rather than a (capture, pid)
    join, because 337 corpus processes have a NULL pid and pids recur within a capture.
    """
    # The corpus tables exist only in a training database. Pointing this at a plain
    # production DB is a reasonable thing to do by accident, so report "no labels" rather
    # than raising OperationalError.
    tables = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    if not {"corpus_labels", "corpus_lineage"} <= tables:
        return pd.DataFrame(columns=["raw_process_id", "label", "tactic"])

    rows = conn.execute(
        """SELECT g.raw_process_id AS raw_process_id, l.label AS label, l.tactic AS tactic
           FROM corpus_labels l
           JOIN corpus_lineage g
             ON g.capture_id = l.capture_id AND g.process_guid = l.process_guid
           WHERE g.raw_process_id IS NOT NULL"""
    ).fetchall()
    if not rows:
        return pd.DataFrame(columns=["raw_process_id", "label", "tactic"])
    return pd.DataFrame([dict(r) for r in rows])


def _real_host_ids(conn) -> list[int]:
    """Hosts that represent genuine collections, excluding the demo fixtures."""
    return [r[0] for r in conn.execute(
        "SELECT id FROM hosts WHERE client_id NOT LIKE ?", (DEMO_CLIENT_PREFIX + "%",))]


def load(train_db: str = DEFAULT_TRAIN_DB, live_db: str | None = DEFAULT_LIVE_DB,
         include_local: bool = True) -> Dataset:
    """Build the dataset. Features are materialised later, per CV fold."""
    frames, ys, groups, tactics, sources = [], [], [], [], []
    meta: dict = {"train_db": train_db, "live_db": live_db,
                  "include_local": include_local,
                  "feature_spec_sha256": mlf.feature_spec_sha256()}

    # ---- corpus
    conn = database.connect(train_db)
    try:
        corpus = mlf.extract_process_frame(conn)
        labels = _corpus_labels(conn)
    finally:
        conn.close()

    if not corpus.empty and not labels.empty:
        corpus = corpus.merge(labels, left_on="id", right_on="raw_process_id", how="inner")
        frames.append(corpus)
        ys.append(np.where(corpus["label"].to_numpy() == "malicious",
                           LABEL_MALICIOUS, LABEL_BENIGN))
        groups.append(corpus["collection_id"].to_numpy())
        tactics.append(corpus["tactic"].to_numpy())
        sources.append(np.full(len(corpus), SOURCE_CORPUS))
        meta["corpus_rows"] = int(len(corpus))
        meta["corpus_unlabelled_dropped"] = 0
    else:
        meta["corpus_rows"] = 0

    # ---- local benign
    if include_local and live_db and os.path.exists(live_db):
        conn = database.connect(live_db)
        try:
            real_hosts = _real_host_ids(conn)
            demo_excluded = conn.execute(
                "SELECT COUNT(*) FROM raw_processes p JOIN hosts h ON h.id = p.host_id "
                "WHERE h.client_id LIKE ?", (DEMO_CLIENT_PREFIX + "%",)).fetchone()[0]
            local = (mlf.extract_process_frame(conn, host_ids=real_hosts)
                     if real_hosts else pd.DataFrame())
        finally:
            conn.close()
        meta["local_demo_rows_excluded"] = int(demo_excluded)
        if not local.empty:
            frames.append(local)
            ys.append(np.full(len(local), LABEL_BENIGN))
            # Distinct group namespace so a local collection can never collide with a
            # corpus capture id.
            groups.append(np.array([f"local::{c}" for c in local["collection_id"]]))
            tactics.append(np.full(len(local), None, dtype=object))
            sources.append(np.full(len(local), SOURCE_LOCAL))
            meta["local_rows"] = int(len(local))
            meta["local_benign_assumed"] = True
        else:
            meta["local_rows"] = 0
    else:
        meta["local_rows"] = 0

    if not frames:
        empty = pd.DataFrame()
        return Dataset(empty, np.array([]), np.array([]), np.array([]), np.array([]), meta)

    # align columns across sources before concatenating - the live DB has no T2 aggregate
    # columns at all when Sysmon is absent
    all_cols: list[str] = []
    for f in frames:
        for c in f.columns:
            if c not in all_cols:
                all_cols.append(c)
    frames = [f.reindex(columns=all_cols) for f in frames]

    frame = pd.concat(frames, ignore_index=True)
    return Dataset(
        frame=frame,
        y=np.concatenate(ys),
        groups=np.concatenate(groups),
        tactics=np.concatenate(tactics),
        sources=np.concatenate(sources),
        meta=meta,
    )


def materialise(dataset: Dataset, train_mask=None, tier: str = mlf.TIER_T2):
    """Fit rarity statistics on `train_mask` rows only, then transform everything.

    Pass the training-fold mask, never None, inside a CV loop. `train_mask=None` fits on all
    rows, which is correct only for a final fit on the full training set.
    """
    if train_mask is None:
        fit_frame = dataset.frame
    else:
        fit_frame = dataset.frame.loc[np.asarray(train_mask)]
    stats = mlf.fit_stats(fit_frame)
    return mlf.transform(dataset.frame, stats=stats, tier=tier), stats


def group_holdout_split(dataset: Dataset, test_fraction: float = 0.25,
                        seed: int = 42) -> tuple[np.ndarray, np.ndarray]:
    """Split whole groups into (train_mask, test_mask), balancing positives.

    Groups - not rows - are assigned, so no capture straddles the split. Groups containing
    at least one positive are allocated separately from purely-benign groups, so the test
    side is guaranteed to contain attacks; with only 115 groups a naive random split can
    easily produce a test set with almost none.
    """
    rng = np.random.default_rng(seed)
    unique = np.array(sorted(set(dataset.groups)))
    has_positive = np.array([
        bool((dataset.y[dataset.groups == g] == LABEL_MALICIOUS).any()) for g in unique])

    test_groups: list = []
    for subset in (unique[has_positive], unique[~has_positive]):
        if len(subset) == 0:
            continue
        shuffled = subset.copy()
        rng.shuffle(shuffled)
        n_test = max(1, int(round(len(shuffled) * test_fraction)))
        test_groups.extend(shuffled[:n_test].tolist())

    test_set = set(test_groups)
    test_mask = np.array([g in test_set for g in dataset.groups])
    return ~test_mask, test_mask


if __name__ == "__main__":       # pragma: no cover - operator entry point
    import argparse
    import json
    ap = argparse.ArgumentParser(description="Assemble and describe the ML dataset")
    ap.add_argument("--train-db", default=DEFAULT_TRAIN_DB)
    ap.add_argument("--live-db", default=DEFAULT_LIVE_DB)
    ap.add_argument("--no-local", action="store_true",
                    help="corpus only - use to ablate the local benign contribution")
    ap.add_argument("--tier", choices=[mlf.TIER_T1, mlf.TIER_T2], default=mlf.TIER_T2)
    args = ap.parse_args()

    ds = load(args.train_db, args.live_db, include_local=not args.no_local)
    print(json.dumps({"summary": ds.summary(), "meta": ds.meta}, indent=2, default=str))

    if len(ds):
        train_mask, test_mask = group_holdout_split(ds)
        X, _ = materialise(ds, train_mask=train_mask, tier=args.tier)
        print(f"\nmatrix: {X.shape[0]} rows x {X.shape[1]} features ({args.tier})")
        print(f"held-out split: train={int(train_mask.sum())} "
              f"({int((ds.y[train_mask] == 1).sum())} positive)  "
              f"test={int(test_mask.sum())} ({int((ds.y[test_mask] == 1).sum())} positive)")
        overlap = set(ds.groups[train_mask]) & set(ds.groups[test_mask])
        print(f"group overlap between train and test: {len(overlap)}  (must be 0)")
        print("\ncmdline availability by source (the reason local rows are included):")
        for src in (SOURCE_CORPUS, SOURCE_LOCAL):
            m = ds.sources == src
            if m.sum():
                present = X.loc[m, "cmdline_present"].mean() * 100
                print(f"  {src:8s} {int(m.sum()):>5d} rows   cmdline present: {present:5.1f}%")
