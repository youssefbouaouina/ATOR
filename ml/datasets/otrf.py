"""OTRF Security-Datasets corpus: fetch, verify, enumerate.

Why this corpus
---------------
The live `ator_dfir.db` holds 545 process rows, 6 detections and zero analyst labels
(docs/ML_ARCHITECTURE.md section 1.3). Nothing can be trained or credibly evaluated on
that. The OTRF Security-Datasets project publishes real Sysmon / Security / PowerShell
telemetry captured while adversary-emulation tools (Empire, Covenant, Mimikatz, PurpleSharp,
Metasploit) were executed on instrumented Windows hosts, organised by MITRE ATT&CK tactic.

It is the right corpus for this project specifically because it is the *same kind of
telemetry this framework already collects* - `agent/collectors/logs.py` reads the
`Microsoft-Windows-Sysmon/Operational` channel - so it can be converted into ATOR's own
schema rather than modelled in a foreign feature space. See `otrf_etl`.

Chosen over Kaggle alternatives (CIC-IDS2017, UNSW-NB15, EMBER) because those are netflow
or PE-static feature spaces that do not map onto endpoint process artefacts, and because
Kaggle needs an API token this environment does not have. GitHub needs none.

Licence: OTRF Security-Datasets is MIT-licensed and intended for public research use.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.request
from dataclasses import dataclass

REPO = "OTRF/Security-Datasets"
TREE_URL = f"https://api.github.com/repos/{REPO}/git/trees/master?recursive=1"
RAW_BASE = f"https://raw.githubusercontent.com/{REPO}/master/"

# Only the Windows "atomic" captures: one capture per emulated technique, which is what
# makes per-capture grouping (and therefore leak-free cross-validation) possible.
CORPUS_PREFIX = "datasets/atomic/windows/"

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_DIR = os.path.join(_PROJECT_ROOT, "data", "external", "otrf")
MANIFEST_NAME = "manifest.json"

_UA = {"User-Agent": "ator-dfir-ml/1.0 (internship research)"}


@dataclass(frozen=True)
class Capture:
    """One downloaded capture archive."""
    local_path: str
    filename: str      # flattened: "{tactic}__{scope}__{name}.zip"
    tactic: str        # ATT&CK tactic from the corpus directory layout
    scope: str         # 'host' (endpoint telemetry) or 'network' (pcap-derived)
    name: str          # emulation name, e.g. 'empire_mimikatz_logonpasswords'

    @property
    def capture_id(self) -> str:
        """Stable identifier used as the cross-validation group key."""
        return self.filename[:-4] if self.filename.endswith(".zip") else self.filename


def _flatten(repo_path: str) -> str:
    """datasets/atomic/windows/<tactic>/<scope>/<name>.zip -> <tactic>__<scope>__<name>.zip"""
    return repo_path[len(CORPUS_PREFIX):].replace("/", "__")


def _parse_filename(filename: str) -> tuple[str, str, str]:
    stem = filename[:-4] if filename.endswith(".zip") else filename
    parts = stem.split("__")
    if len(parts) >= 3:
        return parts[0], parts[1], "__".join(parts[2:])
    if len(parts) == 2:
        return parts[0], "host", parts[1]
    return "other", "host", stem


def _get_json(url: str, timeout: int = 60):
    with urllib.request.urlopen(urllib.request.Request(url, headers=_UA), timeout=timeout) as r:
        return json.load(r)


def sha256_file(path: str) -> str | None:
    """SHA-256 of a file, or None if the OS refuses to open it.

    Returns None rather than raising because antivirus routinely blocks reads of this
    corpus - see `is_av_blocked`. A hard failure here would abort a 155-file manifest
    over one quarantined archive.
    """
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def is_av_blocked(path: str) -> bool:
    """True when a file exists on disk but the OS will not let us read it.

    This corpus is real adversary-emulation telemetry, so antivirus flags some archives.
    Observed on this machine: Windows Defender blocked
    `discovery__host__empire_shell_net_local_users.zip` and
    `discovery__host__empire_shell_net_localgroup_administrators.zip`; the files download
    and `os.path.getsize` reports the correct size, but `open()` raises
    `OSError(22, 'Invalid argument')` because a filter driver denies the read.

    Distinguishing this from a corrupt download matters: a corrupt file should be
    re-fetched, whereas re-fetching an AV-blocked file loops forever.

    Remediation (operator decision, needs administrator rights - deliberately NOT done
    automatically by this code, as it weakens the machine's protection):
        Add-MpPreference -ExclusionPath "<repo>\\data\\external\\otrf"
    """
    if not os.path.exists(path):
        return False
    try:
        with open(path, "rb") as fh:
            fh.read(1)
        return False
    except OSError:
        return True


def list_remote() -> list[str]:
    """Repository paths of every Windows atomic capture archive."""
    tree = _get_json(TREE_URL)
    return sorted(
        e["path"] for e in tree["tree"]
        if e["type"] == "blob"
        and e["path"].startswith(CORPUS_PREFIX)
        and e["path"].endswith(".zip")
    )


def fetch(dest_dir: str = DEFAULT_DIR, retries: int = 3, verbose: bool = True) -> dict:
    """Download every missing capture and write a checksummed manifest.

    Idempotent: files already present are skipped, so re-running costs one API call.
    Offline-only operation - nothing here is ever invoked by the server.
    """
    os.makedirs(dest_dir, exist_ok=True)
    remote = list_remote()
    stats = {"total": len(remote), "downloaded": 0, "skipped": 0, "failed": []}

    for i, repo_path in enumerate(remote, 1):
        dest = os.path.join(dest_dir, _flatten(repo_path))
        if os.path.exists(dest) and os.path.getsize(dest) > 0:
            stats["skipped"] += 1
            continue
        for attempt in range(retries):
            try:
                req = urllib.request.Request(RAW_BASE + repo_path, headers=_UA)
                with urllib.request.urlopen(req, timeout=180) as r:
                    payload = r.read()
                tmp = dest + ".part"
                with open(tmp, "wb") as fh:
                    fh.write(payload)
                os.replace(tmp, dest)
                stats["downloaded"] += 1
                break
            except Exception as exc:                      # noqa: BLE001 - report and continue
                if attempt == retries - 1:
                    stats["failed"].append({"path": repo_path, "error": f"{type(exc).__name__}: {exc}"})
                else:
                    time.sleep(2 * (attempt + 1))
        if verbose and i % 25 == 0:
            print(f"  {i}/{len(remote)} downloaded={stats['downloaded']} skipped={stats['skipped']}",
                  flush=True)

    write_manifest(dest_dir)
    return stats


def write_manifest(dest_dir: str = DEFAULT_DIR) -> str:
    """Record filename -> (size, sha256) so a corpus can be verified or reproduced."""
    entries, blocked = {}, []
    for filename in sorted(os.listdir(dest_dir)):
        if not filename.endswith(".zip"):
            continue
        path = os.path.join(dest_dir, filename)
        digest = sha256_file(path)
        if digest is None:
            blocked.append(filename)
            entries[filename] = {"bytes": os.path.getsize(path),
                                 "sha256": None, "av_blocked": True}
            continue
        entries[filename] = {"bytes": os.path.getsize(path), "sha256": digest}
    manifest = {
        "source_repo": REPO,
        "corpus_prefix": CORPUS_PREFIX,
        "captures": len(entries),
        "readable_captures": len(entries) - len(blocked),
        "av_blocked": sorted(blocked),
        "total_bytes": sum(e["bytes"] for e in entries.values()),
        "files": entries,
    }
    path = os.path.join(dest_dir, MANIFEST_NAME)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
    return path


def verify(dest_dir: str = DEFAULT_DIR) -> dict:
    """Check the local corpus against its manifest. Detects truncation or tampering."""
    path = os.path.join(dest_dir, MANIFEST_NAME)
    if not os.path.exists(path):
        return {"ok": False, "reason": "no manifest; run fetch() or write_manifest()"}
    with open(path, encoding="utf-8") as fh:
        manifest = json.load(fh)
    missing, corrupt, blocked = [], [], []
    for filename, meta in manifest["files"].items():
        full = os.path.join(dest_dir, filename)
        if not os.path.exists(full):
            missing.append(filename)
            continue
        digest = sha256_file(full)
        if digest is None:
            # Unreadable, not corrupt - re-fetching would not help.
            blocked.append(filename)
        elif meta.get("sha256") and digest != meta["sha256"]:
            corrupt.append(filename)
    return {
        "ok": not missing and not corrupt,      # AV-blocked files are tolerated
        "captures": manifest["captures"],
        "usable": manifest["captures"] - len(missing) - len(corrupt) - len(blocked),
        "missing": missing,
        "corrupt": corrupt,
        "av_blocked": blocked,
    }


def local_captures(dest_dir: str = DEFAULT_DIR, scope: str | None = "host",
                   skip_unreadable: bool = True) -> list[Capture]:
    """Enumerate downloaded captures.

    `scope='host'` (the default) keeps only endpoint telemetry. The 'network' captures are
    pcap-derived views of the same emulations; including both would put two views of one
    attack into different CV folds - a leak.

    `skip_unreadable` drops AV-blocked archives (see `is_av_blocked`) so callers never have
    to defend against them. Blocked files are reported by `blocked_captures()`.
    """
    if not os.path.isdir(dest_dir):
        return []
    out = []
    for filename in sorted(os.listdir(dest_dir)):
        if not filename.endswith(".zip"):
            continue
        tactic, cap_scope, name = _parse_filename(filename)
        if scope is not None and cap_scope != scope:
            continue
        path = os.path.join(dest_dir, filename)
        if skip_unreadable and is_av_blocked(path):
            continue
        out.append(Capture(
            local_path=path, filename=filename,
            tactic=tactic, scope=cap_scope, name=name,
        ))
    return out


def blocked_captures(dest_dir: str = DEFAULT_DIR) -> list[str]:
    """Filenames present on disk that the OS will not let us read (antivirus)."""
    if not os.path.isdir(dest_dir):
        return []
    return sorted(
        f for f in os.listdir(dest_dir)
        if f.endswith(".zip") and is_av_blocked(os.path.join(dest_dir, f))
    )


if __name__ == "__main__":       # pragma: no cover - operator entry point
    import argparse
    ap = argparse.ArgumentParser(description="OTRF Security-Datasets corpus manager")
    ap.add_argument("action", choices=["fetch", "verify", "list", "manifest"])
    ap.add_argument("--dir", default=DEFAULT_DIR)
    args = ap.parse_args()
    if args.action == "fetch":
        print(json.dumps(fetch(args.dir), indent=2))
    elif args.action == "verify":
        print(json.dumps(verify(args.dir), indent=2))
    elif args.action == "manifest":
        print(write_manifest(args.dir))
    else:
        caps = local_captures(args.dir)
        by_tactic: dict[str, int] = {}
        for c in caps:
            by_tactic[c.tactic] = by_tactic.get(c.tactic, 0) + 1
        print(f"{len(caps)} usable host captures")
        for tactic, n in sorted(by_tactic.items(), key=lambda kv: -kv[1]):
            print(f"  {tactic:24s} {n}")
        blocked = blocked_captures(args.dir)
        if blocked:
            print(f"\n{len(blocked)} archive(s) unreadable (antivirus), excluded:")
            for f in blocked:
                print(f"  {f}")
            print("  -> harmless; see is_av_blocked() for the optional exclusion command.")
