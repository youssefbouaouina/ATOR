"""Process-lineage labelling for the OTRF corpus.

The problem with the obvious approach
-------------------------------------
Each capture lives under a tactic directory, so it is tempting to label every event in
`credential_access/empire_mimikatz_logonpasswords.zip` as credential-access. That is wrong.
A capture holds thousands of background events from an instrumented lab host and only a
handful of attack events. Capture-level labels would be ~95% wrong, and worse, the model
would learn to separate *captures* (host names, lab quirks, time of day) rather than
*behaviour* - a leak that inflates every metric while producing a useless detector.

What this module does instead
-----------------------------
1. **Seed.** Match each capture's known attack signature against process
   `Image`/`CommandLine` to find the attacker's entry-point process(es). Signatures are
   curated per emulation tool and version-controlled below, so they are reviewable.
2. **Propagate.** Walk `ProcessGuid` -> `ParentProcessGuid` and label every descendant
   malicious. An attacker's `powershell.exe` spawning `whoami.exe` makes that `whoami.exe`
   part of the intrusion even though `whoami /user` is benign in isolation - which is exactly
   the context a rule-based detector lacks and a behavioural model should learn.
3. **Everything else in the same capture is benign.** This is the important half: the benign
   class comes from the *same hosts, same captures, same time windows* as the malicious
   class, so the model cannot separate the classes using host or capture artefacts.

Honest limitations
------------------
* Labels are **weak**: they rest on heuristic seed patterns, not ground truth from the
  emulation harness. A missed seed silently mislabels a whole subtree as benign; an
  over-broad seed poisons the benign class.
* Descendant propagation can over-label. An attacker process that spawns a genuinely
  routine child still marks that child malicious. This is a deliberate choice - in DFIR
  terms the child *is* part of the incident - but it is a modelling assumption, not a fact.
* `MAX_DEPTH` bounds propagation so a mislabelled seed near the root (e.g. `services.exe`)
  cannot cascade over an entire host.

Both limitations are reported with the results rather than buried.
"""
from __future__ import annotations

import re
import sqlite3
from collections import defaultdict, deque

LABEL_MALICIOUS = "malicious"
LABEL_BENIGN = "benign"

# Propagation depth cap. Deep enough for realistic tool chains
# (launcher -> powershell -> cmd -> utility), shallow enough that a bad seed on a service
# host cannot swallow the machine.
MAX_DEPTH = 6

# Processes that must never be accepted as a seed. If a signature matches one of these the
# match is rejected: labelling a system root process malicious would propagate to most of
# the host and destroy the benign class.
_SEED_DENYLIST = frozenset({
    "system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
    "lsass.exe", "svchost.exe", "explorer.exe", "dwm.exe", "spoolsv.exe", "taskhostw.exe",
    "sihost.exe", "runtimebroker.exe", "searchui.exe", "lsm.exe", "fontdrvhost.exe",
})


def _rx(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.IGNORECASE)


# ---------------------------------------------------------------------------
# Seed signatures.
#
# Keyed by a substring of the capture id (matched case-insensitively), so one entry covers
# every capture of the same emulation. `None` key is the fallback applied to any capture
# with no specific entry.
#
# Each signature is (field, regex) where field is 'image' or 'cmdline'. A process is a seed
# if ANY signature matches and its name is not in _SEED_DENYLIST.
# ---------------------------------------------------------------------------
_TOOL_SIGNATURES: dict[str, tuple[tuple[str, re.Pattern], ...]] = {
    # --- Empire: PowerShell agent; launchers are base64 blobs with -enc / -nop / -sta
    "empire": (
        ("cmdline", _rx(r"-(enc|encodedcommand)\s+[A-Za-z0-9+/=]{40,}")),
        ("cmdline", _rx(r"powershell.*-nop.*-sta")),
        ("cmdline", _rx(r"-w\s+hidden|-windowstyle\s+hidden")),
        ("cmdline", _rx(r"IEX|Invoke-Expression|DownloadString|FromBase64String")),
    ),
    # --- Covenant: .NET C2; Grunt implants, often via msbuild/installutil/regsvr32
    "covenant": (
        ("image", _rx(r"\\(GruntHTTP|GruntSMB|Grunt)[^\\]*\.exe$")),
        ("cmdline", _rx(r"grunt", )),
        ("cmdline", _rx(r"-(enc|encodedcommand)\s+[A-Za-z0-9+/=]{40,}")),
        ("image", _rx(r"\\(msbuild|installutil|regsvr32|wuauclt)\.exe$")),
    ),
    # --- Mimikatz and credential-dumping variants
    "mimikatz": (
        ("image", _rx(r"\\mimi(katz|explorer|dump)[^\\]*\.exe$")),
        ("cmdline", _rx(r"sekurlsa|lsadump|logonpasswords|privilege::debug|dcsync")),
    ),
    "ntds": (
        ("cmdline", _rx(r"ntdsutil|ntds\.dit|ifm\b|create\s+full")),
        ("cmdline", _rx(r"vssadmin\s+create|wmic\s+shadowcopy")),
    ),
    "sam": (
        ("cmdline", _rx(r"reg\s+save\s+hk(lm|cu)\\(sam|system|security)")),
        ("cmdline", _rx(r"esentutl.*\bsam\b|copy.*\\sam\b")),
    ),
    "lsass": (
        ("cmdline", _rx(r"comsvcs\.dll.*minidump|procdump.*lsass|dumpert")),
        ("image", _rx(r"\\(procdump|dumpert)[^\\]*\.exe$")),
    ),
    "rubeus": (("cmdline", _rx(r"rubeus|asktgt|kerberoast|ptt\b")),),
    "seatbelt": (("cmdline", _rx(r"seatbelt")),),
    "sharp": (("image", _rx(r"\\Sharp[A-Za-z]+\.exe$")), ("cmdline", _rx(r"sharp(view|sc|wmi)"))),
    # --- Metasploit / Meterpreter
    "msf": (("cmdline", _rx(r"meterpreter|msfvenom")),),
    "meterpreter": (("cmdline", _rx(r"meterpreter")),),
    # --- PurpleSharp adversary simulation
    "purplesharp": (("image", _rx(r"\\purplesharp[^\\]*\.exe$")), ("cmdline", _rx(r"purplesharp"))),
    # --- APT Simulator / Cobalt Strike emulation
    "aptsimulator": (("cmdline", _rx(r"apt-?simulator|aptsimulator")),),
    "cobaltstrike": (("cmdline", _rx(r"-(enc|encodedcommand)\s+[A-Za-z0-9+/=]{40,}")),),
    # --- Technique-specific captures named after the mechanism rather than a tool
    "schtask": (("cmdline", _rx(r"schtasks.*\/create|schtasks.*\/change")),),
    "wmi": (("cmdline", _rx(r"wmic.*(process\s+call\s+create|/node:)|Register-WmiEvent")),),
    "psexec": (("cmdline", _rx(r"psexec|paexec")), ("image", _rx(r"\\ps(exec|exesvc)[^\\]*\.exe$"))),
    "mshta": (("cmdline", _rx(r"mshta.*(javascript|vbscript|\.hta|\.sct)")),),
    "regsvr32": (("cmdline", _rx(r"regsvr32.*(scrobj|\.sct|/i:http)")),),
    "bitsadmin": (("cmdline", _rx(r"bitsadmin.*\/(transfer|addfile)")),),
    "certutil": (("cmdline", _rx(r"certutil.*(urlcache|decode|encode)")),),
    "installutil": (("cmdline", _rx(r"installutil")),),
    "cmstp": (("cmdline", _rx(r"cmstp.*\/s")),),
    "fodhelper": (("cmdline", _rx(r"fodhelper|ms-settings")),),
    "auditpol": (("cmdline", _rx(r"auditpol.*\/(set|clear)")),),
    "wevtutil": (("cmdline", _rx(r"wevtutil.*(cl|sl|/e:false)")),),
    "netsh": (("cmdline", _rx(r"netsh.*(firewall|portproxy)")),),
    "herpaderping": (("cmdline", _rx(r"herpaderp")),),
    "proxylogon": (("cmdline", _rx(r"-(enc|encodedcommand)\s+[A-Za-z0-9+/=]{40,}")),),
    "userinit": (("cmdline", _rx(r"userinitmprlogonscript")),),
    "control_panel": (("cmdline", _rx(r"control\.exe.*\.cpl|rundll32.*shell32.*Control_RunDLL")),),

    # --- Technique-mechanism signatures.
    #
    # These match the *specific registry key or utility invocation* the emulation performed,
    # which is deliberately NOT anything the feature set encodes. Seeding on a signal that a
    # feature also computes (e.g. "executable under \Downloads\", which is what
    # path_category does) would make the classifier merely relearn the labelling rule and
    # render its scores meaningless. See the leak audit in the evaluation report.
    "minint": (("cmdline", _rx(r"CurrentControlSet\d*\\Control\\MiniNt")),),
    "stop_event_logging": (
        ("cmdline", _rx(r"CurrentControlSet\d*\\Control\\MiniNt")),
        ("cmdline", _rx(r"Services\\EventLog\b.*(/t\s+REG_|Start)")),
    ),
    "eventlog": (
        ("cmdline", _rx(r"Services\\EventLog\b.*(/t\s+REG_|Start)")),
        ("cmdline", _rx(r"sc(\.exe)?\s+config\s+eventlog")),
        ("cmdline", _rx(r"Stop-Service.*eventlog|Set-Service.*eventlog")),
    ),
    "netprofm": (("cmdline", _rx(r"netprofm")),),
    "commandline_logging": (
        ("cmdline", _rx(r"ProcessCreationIncludeCmdLine")),
    ),
    "volume_shadow_copy": (
        ("cmdline", _rx(r"vssadmin.*create|wmic.*shadowcopy.*call\s+create")),
        ("cmdline", _rx(r"GLOBALROOT\\Device\\HarddiskVolumeShadowCopy")),
    ),
    "auditpolicy": (("cmdline", _rx(r"auditpol.*\/(set|clear|remove)")),),
    "cimprovider": (("cmdline", _rx(r"cimprovider.*-(r|remove)")),),
    "monologue": (("cmdline", _rx(r"monologue|netntlm")),),
    "powerview": (("cmdline", _rx(r"powerview|Get-Domain|Get-NetLocalGroup|Invoke-ACLScanner")),),
    "dllinjection": (("cmdline", _rx(r"LoadLibrary|CreateRemoteThread|Invoke-DllInjection")),),
    "mavinject": (("cmdline", _rx(r"mavinject.*\/injectrunning")),),
    "xsl": (("cmdline", _rx(r"wmic.*\/format:.*\.xsl|wmic.*os\s+get\s+\/format")),),
    "hh_local": (("cmdline", _rx(r"\bhh(\.exe)?\s+.*\.(htm|html|chm)")),),

}

# Signatures applied to EVERY capture, in addition to any tool-specific ones.
#
# Deliberately narrow - a broad universal signature is how the benign class gets poisoned.
_UNIVERSAL_SIGNATURES: tuple[tuple[str, re.Pattern], ...] = (
    # The emulation harness drops its implant under this literal filename, in captures whose
    # id gives no tool away. Matching the harness's own artefact name is closer to ground
    # truth than to a behavioural feature - no feature tests for a specific filename.
    #
    # Contrast with what would be WRONG here: seeding on "executable under \Downloads\".
    # path_category already encodes that, so the classifier would simply relearn the
    # labelling rule and its scores would mean nothing. Seeds and features must not overlap;
    # the residual overlap that remains is measured by the leak audit in the eval report.
    ("image", _rx(r"\\payload\.exe$")),
)

# Applied when no tool-specific entry matches the capture id. Deliberately narrow: broad
# fallbacks are how the benign class gets poisoned.
_FALLBACK_SIGNATURES: tuple[tuple[str, re.Pattern], ...] = (
    ("cmdline", _rx(r"-(enc|encodedcommand)\s+[A-Za-z0-9+/=]{40,}")),
    ("cmdline", _rx(r"FromBase64String|DownloadString|DownloadFile|IEX\s*\(")),
    ("cmdline", _rx(r"\|\s*(iex|sh|bash)\b")),
)


def signatures_for(capture_id: str) -> tuple[tuple[str, re.Pattern], ...]:
    """Seed signatures applicable to a capture, matched on its id."""
    lowered = capture_id.lower()
    collected: list[tuple[str, re.Pattern]] = []
    for token, sigs in _TOOL_SIGNATURES.items():
        if token in lowered:
            collected.extend(sigs)
    base = tuple(collected) if collected else _FALLBACK_SIGNATURES
    return base + _UNIVERSAL_SIGNATURES


def _is_seed(image: str | None, cmdline: str | None,
             sigs: tuple[tuple[str, re.Pattern], ...]) -> str | None:
    """Return the matching signature's pattern string, or None."""
    name = (image or "").replace("/", "\\").rsplit("\\", 1)[-1].lower()
    if name in _SEED_DENYLIST:
        return None
    for field, pattern in sigs:
        haystack = image if field == "image" else cmdline
        if haystack and pattern.search(str(haystack)):
            return pattern.pattern
    return None


def _is_child_of_seed(parent_image: str | None, parent_cmdline: str | None,
                      sigs: tuple[tuple[str, re.Pattern], ...]) -> str | None:
    """Seed a process because its *parent* matches an attack signature.

    Needed because a parent whose own ProcessCreate fell outside the capture window is only
    visible through the child's ParentImage/ParentCommandLine. The ETL reconstructs such
    parents as lineage nodes, but this covers the case where reconstruction could not run
    (e.g. no ParentProcessGuid), so a child of a known-malicious parent is still caught.
    """
    return _is_seed(parent_image, parent_cmdline, sigs)


CORPUS_LABEL_SCHEMA = """
CREATE TABLE IF NOT EXISTS corpus_labels (
    capture_id TEXT NOT NULL,
    host_id INTEGER NOT NULL,
    process_guid TEXT NOT NULL,
    pid INTEGER,
    label TEXT NOT NULL CHECK (label IN ('malicious','benign')),
    tactic TEXT,
    seed_rule TEXT,
    depth INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (capture_id, process_guid)
);
CREATE INDEX IF NOT EXISTS ix_corpus_labels_label ON corpus_labels(label);
CREATE INDEX IF NOT EXISTS ix_corpus_labels_capture ON corpus_labels(capture_id);
"""


def label_capture(conn: sqlite3.Connection, capture_id: str, tactic: str) -> dict:
    """Label every process in one capture. Returns per-capture counts."""
    rows = conn.execute(
        """SELECT host_id, pid, process_guid, parent_process_guid, image, cmdline,
                  parent_image, parent_cmdline, is_reconstructed
           FROM corpus_lineage WHERE capture_id = ?""",
        (capture_id,),
    ).fetchall()
    if not rows:
        return {"capture_id": capture_id, "processes": 0, "malicious": 0, "benign": 0, "seeds": 0}

    sigs = signatures_for(capture_id)
    children: dict[str, list[sqlite3.Row]] = defaultdict(list)
    for row in rows:
        children[row["parent_process_guid"]].append(row)

    # ---- 1. seeds: the process itself matches, or its parent does
    seeds: dict[str, str] = {}
    for row in rows:
        rule = _is_seed(row["image"], row["cmdline"], sigs)
        if not rule:
            rule = _is_child_of_seed(row["parent_image"], row["parent_cmdline"], sigs)
            if rule:
                rule = f"parent:{rule}"
        if rule:
            seeds[row["process_guid"]] = rule

    # ---- 2. breadth-first propagation to descendants, depth-capped
    labelled: dict[str, tuple[str, int]] = {}      # guid -> (seed_rule, depth)
    queue = deque((guid, rule, 0) for guid, rule in seeds.items())
    while queue:
        guid, rule, depth = queue.popleft()
        if guid in labelled and labelled[guid][1] <= depth:
            continue
        labelled[guid] = (rule, depth)
        if depth >= MAX_DEPTH:
            continue
        for child in children.get(guid, ()):
            child_guid = child["process_guid"]
            if child_guid and child_guid not in labelled:
                queue.append((child_guid, rule, depth + 1))

    # ---- 3. write labels; everything not reached is benign background
    payload = []
    for row in rows:
        guid = row["process_guid"]
        if guid in labelled:
            rule, depth = labelled[guid]
            payload.append((capture_id, row["host_id"], guid, row["pid"],
                            LABEL_MALICIOUS, tactic, rule, depth))
        else:
            payload.append((capture_id, row["host_id"], guid, row["pid"],
                            LABEL_BENIGN, None, None, 0))

    conn.execute("DELETE FROM corpus_labels WHERE capture_id = ?", (capture_id,))
    conn.executemany(
        """INSERT OR REPLACE INTO corpus_labels
               (capture_id, host_id, process_guid, pid, label, tactic, seed_rule, depth)
           VALUES (?,?,?,?,?,?,?,?)""", payload)
    conn.commit()

    n_mal = sum(1 for p in payload if p[4] == LABEL_MALICIOUS)
    return {"capture_id": capture_id, "processes": len(rows), "malicious": n_mal,
            "benign": len(rows) - n_mal, "seeds": len(seeds)}


def label_all(train_db: str, verbose: bool = True) -> dict:
    """Label every imported capture. Idempotent."""
    from server import db as database
    conn = database.connect(train_db)
    try:
        conn.executescript(CORPUS_LABEL_SCHEMA)
        conn.commit()
        captures = conn.execute(
            "SELECT capture_id, tactic FROM corpus_captures ORDER BY capture_id").fetchall()
        per_capture = [label_capture(conn, r["capture_id"], r["tactic"]) for r in captures]

        totals = conn.execute(
            "SELECT label, COUNT(*) n FROM corpus_labels GROUP BY label").fetchall()
        by_tactic = conn.execute(
            """SELECT tactic, COUNT(*) n FROM corpus_labels
               WHERE label='malicious' GROUP BY tactic ORDER BY n DESC""").fetchall()
        no_seed = [c["capture_id"] for c in per_capture
                   if c["processes"] > 0 and c["seeds"] == 0]
        # Only meaningful for captures big enough that "all malicious" is implausible. A
        # 2-process capture (reconstructed agent + its one child) being fully malicious is
        # correct, not a bug, so flagging it would be noise.
        all_mal = [c["capture_id"] for c in per_capture
                   if c["processes"] >= 10 and c["benign"] == 0]

        # Which seed rule produced which labels. This is the audit trail that makes weak
        # labels reviewable: a rule firing suspiciously often is how over-labelling shows up.
        by_rule = conn.execute(
            """SELECT seed_rule, COUNT(*) n, COUNT(DISTINCT capture_id) captures
               FROM corpus_labels WHERE label='malicious' AND seed_rule IS NOT NULL
               GROUP BY seed_rule ORDER BY n DESC""").fetchall()
        by_depth = conn.execute(
            """SELECT depth, COUNT(*) n FROM corpus_labels
               WHERE label='malicious' GROUP BY depth ORDER BY depth""").fetchall()
        reconstructed = conn.execute(
            """SELECT COUNT(*) FROM corpus_labels l
               JOIN corpus_lineage g
                 ON g.capture_id=l.capture_id AND g.process_guid=l.process_guid
               WHERE l.label='malicious' AND g.is_reconstructed=1""").fetchone()[0]

        totals_map = {r["label"]: r["n"] for r in totals}
        n_mal = totals_map.get(LABEL_MALICIOUS, 0)
        n_all = sum(totals_map.values()) or 1
        return {
            "captures_labelled": len(per_capture),
            "totals": totals_map,
            "positive_rate": round(n_mal / n_all, 4),
            "malicious_by_tactic": {r["tactic"]: r["n"] for r in by_tactic},
            # Diagnostics that decide whether the labels can be trusted:
            "malicious_by_seed_rule": [
                {"rule": r["seed_rule"], "processes": r["n"], "captures": r["captures"]}
                for r in by_rule
            ],
            # depth 0 = matched a signature directly; >0 = inherited via lineage
            "malicious_by_propagation_depth": {str(r["depth"]): r["n"] for r in by_depth},
            "malicious_that_are_reconstructed_parents": reconstructed,
            "captures_with_no_seed": no_seed,
            "captures_large_and_entirely_malicious": all_mal,
            "per_capture": per_capture,
        }
    finally:
        conn.close()


if __name__ == "__main__":       # pragma: no cover - operator entry point
    import argparse
    import json
    from ml.datasets.otrf_etl import DEFAULT_TRAIN_DB
    ap = argparse.ArgumentParser(description="Process-lineage labelling for the OTRF corpus")
    ap.add_argument("--train-db", default=DEFAULT_TRAIN_DB)
    ap.add_argument("--full", action="store_true", help="include the per-capture breakdown")
    args = ap.parse_args()
    result = label_all(args.train_db)
    if not args.full:
        result.pop("per_capture", None)
    print(json.dumps(result, indent=2))
