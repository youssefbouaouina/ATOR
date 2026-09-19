"""Layer 4.5 ML - feature extraction.

This module is the **single** implementation of the feature contract. It is used at training
time (against `ml_train.db`, built from the OTRF corpus) and at inference time (against the
live `ator_dfir.db`), which is what makes the no-train/serve-skew claim structural rather
than aspirational. It therefore reads **only** columns that exist in the production schema.

Hard rules
----------
1. **Production schema only.** No `ProcessGuid`, no `corpus_*` table, nothing that exists
   only in the training database. `tests/test_ml_features.py` enforces this.
2. **Missing is not zero.** A feature that cannot be computed is `NaN`, never 0. "This host
   has no Sysmon" and "this process loaded no DLLs" are different facts, and collapsing them
   teaches the model a corpus artefact. Every optional source has an explicit
   `*_available` indicator.
3. **No learned statistic is computed here.** Rarity features need corpus frequencies, which
   must be fitted on training folds only - fitting them on all data then cross-validating
   leaks. Hence the split: `extract_process_frame` (pure read) -> `fit_stats` (train folds
   only) -> `transform`.

Feature tiers (cumulative: t1 < t2 < t3)
----------------------------------------
* **T1** - computable from `raw_processes` + `raw_connections`, i.e. from a psutil sweep.
  Available on every enrolled host today.
* **T2** - adds features derived from Sysmon events in `raw_logs` (`source='sysmon'`).
  Available only where `scripts/install_sysmon.ps1` has been run. `sysmon_available` gates
  the whole block; when it is 0 every T2 feature is NaN.
* **T3** - adds PowerShell module logging (EID 4103), which is GPO-controlled and off by
  default. `psh_available` gates it. Worth the trouble because EID 4103's payload contains
  the *deobfuscated* pipeline: for an Empire agent whose command line is pure base64, the
  payload spells out the RC4 key schedule and the literal C2 URIs. No command-line feature
  can see any of that.

Each tier is an ablation that answers a deployment question with a number rather than an
opinion: "what does installing Sysmon buy?", "what does enabling script-block logging buy?"
See docs/ML_ARCHITECTURE.md sections 5.4 and 7.4, and docs/ML_PHASE7_PLAN.md.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime

import numpy as np
import pandas as pd

TIER_T1 = "t1"
TIER_T2 = "t2"
TIER_T3 = "t3"

# Tiers are cumulative: t1 < t2 < t3. Each step needs strictly more telemetry than the last,
# so a host can only use a tier it actually has the data for.
#   t1  psutil alone            - every enrolled host today
#   t2  + Sysmon                - hosts where scripts/install_sysmon.ps1 has run
#   t3  + PowerShell module logging - needs GPO, off by default
_TIER_ORDER = (TIER_T1, TIER_T2, TIER_T3)


def tiers_up_to(tier: str) -> tuple[str, ...]:
    """Every tier included at `tier`, since tiers are cumulative."""
    if tier not in _TIER_ORDER:
        raise ValueError(f"unknown tier {tier!r}; known: {_TIER_ORDER}")
    return _TIER_ORDER[:_TIER_ORDER.index(tier) + 1]

# --------------------------------------------------------------------------- domain sets

# Living-off-the-land binaries. Signed, Microsoft-shipped executables that attackers abuse
# precisely because blocking them is impractical. Drawn from the LOLBAS project, restricted
# to entries that plausibly appear in endpoint process telemetry.
LOLBINS = frozenset({
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
    "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msbuild.exe",
    "installutil.exe", "regasm.exe", "regsvcs.exe", "wmic.exe", "schtasks.exe", "at.exe",
    "reg.exe", "sc.exe", "net.exe", "net1.exe", "netsh.exe", "forfiles.exe", "pcalua.exe",
    "msiexec.exe", "cmstp.exe", "odbcconf.exe", "control.exe", "hh.exe", "ieexec.exe",
    "presentationhost.exe", "msdt.exe", "mavinject.exe", "xwizard.exe", "dnscmd.exe",
    "esentutl.exe", "extrac32.exe", "findstr.exe", "makecab.exe", "expand.exe",
    "replace.exe", "wuauclt.exe", "dfsvc.exe", "te.exe", "wab.exe", "cdb.exe",
    "vsjitdebugger.exe", "dnx.exe", "rcsi.exe", "csi.exe", "ntdsutil.exe", "vssadmin.exe",
    "wbadmin.exe", "bcdedit.exe", "cipher.exe", "fsutil.exe", "wevtutil.exe",
    "auditpol.exe", "cmdkey.exe", "diskshadow.exe", "psr.exe", "scriptrunner.exe",
    "syncappvpublishingserver.exe", "verclsid.exe", "winrs.exe", "wsreset.exe",
})

# Interpreters / script hosts: execution primitives independent of the LOLBIN notion.
SCRIPT_HOSTS = frozenset({
    "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
    "python.exe", "pythonw.exe", "perl.exe", "ruby.exe", "node.exe", "php.exe",
    "java.exe", "javaw.exe", "bash.exe", "sh.exe", "wsl.exe",
})

# Core Windows binaries. A process bearing one of these names from outside a system
# directory is masquerading - a classic, cheap, high-signal detection.
SYSTEM_BINARIES = frozenset({
    "svchost.exe", "lsass.exe", "services.exe", "csrss.exe", "winlogon.exe", "wininit.exe",
    "smss.exe", "explorer.exe", "spoolsv.exe", "taskhostw.exe", "dwm.exe", "conhost.exe",
    "lsm.exe", "sihost.exe", "fontdrvhost.exe", "audiodg.exe", "dllhost.exe",
    "searchindexer.exe", "runtimebroker.exe", "wmiprvse.exe", "taskeng.exe",
})

SHELL_NAMES = frozenset({"cmd.exe", "powershell.exe", "pwsh.exe", "bash.exe", "sh.exe",
                         "wsl.exe", "zsh.exe"})
OFFICE_NAMES = frozenset({"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
                          "msaccess.exe", "mspub.exe", "onenote.exe", "visio.exe"})
BROWSER_NAMES = frozenset({"chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe",
                           "opera.exe", "brave.exe", "safari.exe"})
SERVICE_HOST_NAMES = frozenset({"services.exe", "svchost.exe", "taskeng.exe",
                                "taskhostw.exe", "wmiprvse.exe"})

# Ports commonly used by reverse shells, C2 defaults and staging listeners. Not proof of
# anything - a feature, not a rule.
SUSPICIOUS_PORTS = frozenset({
    1337, 1080, 3333, 4444, 4445, 4446, 5555, 6666, 6667, 6697, 7777, 8081, 8443, 8888,
    9001, 9002, 9050, 9051, 31337, 12345, 54321, 1234, 2222,
})

# Path buckets, one-hot encoded. Ordered; first match wins. A single ordinal code would
# imply an ordering between, say, "temp" and "program_files" that does not exist.
PATH_CATEGORIES = (
    "system32",       # C:/Windows/System32 or SysWOW64 - the normal case
    "windows_other",  # elsewhere under C:/Windows
    "program_files",
    "programdata",
    "appdata",        # per-user Local/Roaming - very common malware staging area
    "temp",
    "downloads",
    "user_other",     # elsewhere under C:/Users
    "unc",            # \\server\share - remote execution
    "root_drive",     # C:/evil.exe - almost never legitimate
    "other",
    "missing",
)

_RX_B64_RUN = re.compile(r"[A-Za-z0-9+/=]{16,}")
_RX_URL = re.compile(r"https?://|ftp://|\\\\[a-z0-9._-]+\\", re.I)
_RX_IP_LITERAL = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RX_ENV_VAR = re.compile(r"%[A-Za-z_][A-Za-z0-9_]*%|\$env:[A-Za-z_]", re.I)
_RX_ENCODED_FLAG = re.compile(r"-e(nc|ncodedcommand|c)?\s+[A-Za-z0-9+/=]{20,}|"
                              r"-encodedcommand\s|frombase64string", re.I)
_RX_HIDDEN = re.compile(r"-w(indowstyle)?\s+hidden|-noni|-noninteractive", re.I)
_RX_BYPASS = re.compile(r"-ep\s+bypass|-executionpolicy\s+bypass|-nop(rofile)?\b|"
                        r"-nologo|unrestricted", re.I)
_RX_DOWNLOAD = re.compile(r"downloadstring|downloadfile|downloaddata|invoke-webrequest|"
                          r"\biwr\b|\bcurl\b|\bwget\b|urlcache|bitstransfer|"
                          r"start-bitstransfer|net\.webclient|invoke-restmethod", re.I)
_RX_PIPE_SHELL = re.compile(r"\|\s*(iex|invoke-expression|sh\b|bash\b|cmd\b|powershell)", re.I)
_RX_ADS = re.compile(r"::\$data|:[A-Za-z0-9_]+:\$DATA", re.I)
_RX_TOKEN = re.compile(r"\S+")
_RX_DOUBLE_EXT = re.compile(r"\.(txt|pdf|doc|docx|xls|xlsx|jpg|jpeg|png|gif|zip|rtf)"
                            r"\.(exe|scr|com|pif|bat|cmd|js|vbs|ps1|hta|lnk)$", re.I)

# Hours treated as "business hours" in UTC. Crude but honest: the corpus spans several
# labs and we have no per-host timezone, so this is a weak feature and is reported as such.
BUSINESS_HOUR_START, BUSINESS_HOUR_END = 7, 19


# --------------------------------------------------------------------------- scalar helpers

def shannon_entropy(text: str | None) -> float:
    """Character-level Shannon entropy in bits. 0.0 for empty/None.

    High entropy in a command line usually means encoded or packed content (base64 blobs,
    random names). It is the single most reliable cheap obfuscation signal.
    """
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def normalise_path(path: str | None) -> str:
    """Lowercase, forward-slash form used by every path comparison here."""
    return str(path or "").replace("\\", "/").lower()


def basename(path: str | None) -> str:
    return normalise_path(path).rsplit("/", 1)[-1]


def path_category(exe_path: str | None) -> str:
    """Bucket an image path. Returns one of PATH_CATEGORIES."""
    if not exe_path:
        return "missing"
    p = normalise_path(exe_path)
    if p.startswith("//") or p.startswith("\\\\"):
        return "unc"
    if "/windows/system32/" in p or "/windows/syswow64/" in p:
        return "system32"
    if "/appdata/local/temp/" in p or "/windows/temp/" in p or re.search(r"^[a-z]:/temp/", p):
        return "temp"
    if "/downloads/" in p:
        return "downloads"
    if "/appdata/" in p:
        return "appdata"
    if "/programdata/" in p:
        return "programdata"
    if "/program files" in p:
        return "program_files"
    if p.startswith("c:/windows/") or "/windows/" in p:
        return "windows_other"
    if "/users/" in p:
        return "user_other"
    # C:/evil.exe - directly on a drive root
    if re.match(r"^[a-z]:/[^/]+$", p):
        return "root_drive"
    return "other"


def path_depth(exe_path: str | None) -> float:
    if not exe_path:
        return np.nan
    return float(normalise_path(exe_path).strip("/").count("/"))


def longest_b64_run(text: str | None) -> float:
    if not text:
        return 0.0
    runs = _RX_B64_RUN.findall(text)
    return float(max((len(r) for r in runs), default=0))


def token_stats(text: str | None) -> tuple[float, float]:
    """(token_count, longest_token_length)."""
    if not text:
        return 0.0, 0.0
    tokens = _RX_TOKEN.findall(text)
    return float(len(tokens)), float(max((len(t) for t in tokens), default=0))


def char_class_ratios(text: str | None) -> tuple[float, float, float]:
    """(digit_ratio, uppercase_ratio, non-alphanumeric_ratio)."""
    if not text:
        return np.nan, np.nan, np.nan
    n = len(text)
    digits = sum(c.isdigit() for c in text)
    upper = sum(c.isupper() for c in text)
    other = sum((not c.isalnum()) and not c.isspace() for c in text)
    return digits / n, upper / n, other / n


def is_masquerading(name: str | None, exe_path: str | None) -> float:
    """A core Windows binary name running from outside a system directory.

    NaN when the path is unknown - we cannot tell, and guessing 0 would assert innocence.
    """
    if not name:
        return np.nan
    if basename(name) not in SYSTEM_BINARIES:
        return 0.0
    if not exe_path:
        return np.nan
    return float(path_category(exe_path) != "system32")


def name_path_mismatch(name: str | None, exe_path: str | None) -> float:
    """Process name disagreeing with its image's filename."""
    if not name or not exe_path:
        return np.nan
    return float(basename(name) != basename(exe_path))


def is_private_ip(addr: str | None) -> bool | None:
    """True/False, or None when the value is not an address at all."""
    if not addr:
        return None
    try:
        ip = ipaddress.ip_address(str(addr).strip())
    except ValueError:
        return None
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified


def classify_user(username: str | None) -> dict:
    """Account-type flags. All NaN when the username is unknown."""
    if not username:
        return {"user_present": 0.0, "user_is_system": np.nan,
                "user_is_service_account": np.nan, "user_is_admin_like": np.nan,
                "user_is_domain": np.nan}
    u = str(username).strip().lower()
    return {
        "user_present": 1.0,
        "user_is_system": float(u.endswith("\\system") or u == "system"),
        "user_is_service_account": float("network service" in u or "local service" in u),
        "user_is_admin_like": float("admin" in u),
        # DOMAIN\user, excluding the NT AUTHORITY pseudo-domain
        "user_is_domain": float("\\" in u and not u.startswith("nt authority")),
    }


def parse_iso(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None


# --------------------------------------------------------------------------- feature spec

@dataclass(frozen=True)
class FeatureDef:
    name: str
    tier: str
    description: str


def _spec() -> tuple[FeatureDef, ...]:
    f = []
    a = lambda n, t, d: f.append(FeatureDef(n, t, d))   # noqa: E731 - local brevity

    # ---- command line
    a("cmdline_present", TIER_T1, "1 if a command line was captured")
    a("cmdline_len", TIER_T1, "character length")
    a("cmdline_entropy", TIER_T1, "Shannon entropy - encoded/packed content")
    a("cmdline_token_count", TIER_T1, "whitespace-delimited token count")
    a("cmdline_max_token_len", TIER_T1, "longest token - long blobs are encoded payloads")
    a("cmdline_longest_b64_run", TIER_T1, "longest base64-charset run")
    a("cmdline_digit_ratio", TIER_T1, "fraction of digits")
    a("cmdline_upper_ratio", TIER_T1, "fraction of uppercase - base64 skews this")
    a("cmdline_special_ratio", TIER_T1, "fraction of non-alphanumeric non-space")
    a("cmdline_has_encoded_flag", TIER_T1, "-enc / -EncodedCommand / FromBase64String")
    a("cmdline_has_hidden_window", TIER_T1, "-w hidden / -NonInteractive")
    a("cmdline_has_policy_bypass", TIER_T1, "-ExecutionPolicy Bypass / -nop")
    a("cmdline_has_download_verb", TIER_T1, "DownloadString / IWR / curl / certutil urlcache")
    a("cmdline_has_pipe_to_shell", TIER_T1, "output piped into a shell or IEX")
    a("cmdline_url_count", TIER_T1, "URL-like substrings")
    a("cmdline_ip_literal_count", TIER_T1, "dotted-quad literals - C2 without DNS")
    a("cmdline_env_var_count", TIER_T1, "%VAR% / $env: - path obfuscation")
    a("cmdline_has_ads", TIER_T1, "NTFS alternate data stream reference")
    a("cmdline_escape_char_count", TIER_T1, "cmd ^ and PowerShell ` escapes - obfuscation")

    # ---- image path
    a("path_depth", TIER_T1, "directory depth of the image path")
    a("exe_name_len", TIER_T1, "image filename length")
    a("exe_name_entropy", TIER_T1, "image filename entropy - randomised droppers")
    a("exe_name_has_space", TIER_T1, "space in the filename")
    a("exe_name_double_ext", TIER_T1, "document-then-executable double extension")
    a("exe_is_lolbin", TIER_T1, "signed Microsoft binary known to be abusable (LOLBAS)")
    a("exe_is_script_host", TIER_T1, "interpreter / script host")
    a("exe_masquerades_system", TIER_T1, "system binary name outside a system directory")
    a("name_path_mismatch", TIER_T1, "process name differs from the image filename")
    a("sha256_present", TIER_T1, "hash captured - evidence completeness")
    for cat in PATH_CATEGORIES:
        a(f"path_cat_{cat}", TIER_T1, f"image path bucket == {cat}")

    # ---- parent
    a("parent_known", TIER_T1, "the parent process was present in the same collection")
    a("parent_is_lolbin", TIER_T1, "parent is a LOLBIN")
    a("parent_is_shell", TIER_T1, "parent is cmd/powershell/bash")
    a("parent_is_office", TIER_T1, "parent is an Office application - macro chain")
    a("parent_is_browser", TIER_T1, "parent is a browser - drive-by chain")
    a("parent_is_service_host", TIER_T1, "parent is services.exe/svchost.exe")
    a("parent_is_explorer", TIER_T1, "parent is explorer.exe - interactive launch")
    a("parent_cmdline_len", TIER_T1, "parent command-line length")
    a("parent_cmdline_entropy", TIER_T1, "parent command-line entropy")
    a("parent_cmdline_has_encoded_flag", TIER_T1, "parent ran encoded content")
    a("parent_name_rarity", TIER_T1, "-log10 corpus frequency of the parent name (fitted)")
    a("process_name_rarity", TIER_T1, "-log10 corpus frequency of this name (fitted)")
    a("parent_child_pair_rarity", TIER_T1,
      "-log10 corpus frequency of the (parent,child) pair (fitted) - rare lineage")

    # ---- process tree shape within the collection
    a("sibling_count", TIER_T1, "processes sharing this parent")
    a("child_count", TIER_T1, "processes spawned by this one")
    a("tree_depth", TIER_T1, "ancestor chain length within the collection")
    a("is_orphan", TIER_T1, "parent pid absent from the collection")

    # ---- user
    a("user_present", TIER_T1, "username captured")
    a("user_is_system", TIER_T1, "runs as NT AUTHORITY\\SYSTEM")
    a("user_is_service_account", TIER_T1, "NETWORK/LOCAL SERVICE")
    a("user_is_admin_like", TIER_T1, "account name contains 'admin'")
    a("user_is_domain", TIER_T1, "domain account rather than local/pseudo")

    # ---- network (joined by pid within the collection)
    a("conn_available", TIER_T1, "1 if any connection row joined to this process")
    a("conn_count", TIER_T1, "connection rows")
    a("conn_distinct_remote_ips", TIER_T1, "distinct remote addresses")
    a("conn_distinct_remote_ports", TIER_T1, "distinct remote ports")
    a("conn_external_count", TIER_T1, "connections to non-private addresses")
    a("conn_external_ratio", TIER_T1, "fraction of connections leaving the network")
    a("conn_max_remote_port", TIER_T1, "highest remote port")
    a("conn_min_remote_port", TIER_T1, "lowest remote port")
    a("conn_suspicious_port_count", TIER_T1, "connections on known C2/reverse-shell ports")
    a("conn_udp_ratio", TIER_T1, "fraction of UDP")
    a("conn_status_available", TIER_T1,
      "1 if TCP state was captured - psutil supplies it, Sysmon does not")
    a("conn_listen_count", TIER_T1, "listening sockets (NaN when state unavailable)")
    a("conn_established_count", TIER_T1, "established sockets (NaN when state unavailable)")

    # ---- temporal
    #
    # `hour_of_day` was REMOVED in Phase 7b.1. Its PSI between the training corpus and live
    # data was 8.67 - by far the worst of any feature - because it encodes *when the 2020 lab
    # captures were recorded*, not behaviour. A feature that cannot generalise across estates
    # is worse than no feature: it looks predictive in cross-validation and transfers nothing.
    # `is_off_hours` and `is_weekend` are kept because they are estate-relative rather than
    # absolute, but they remain weak (no per-host timezone) and are reported as such.
    a("is_off_hours", TIER_T1, "outside 07:00-19:00 UTC - weak, no per-host timezone")
    a("is_weekend", TIER_T1, "Saturday or Sunday UTC")
    # Burst features, computed from `raw_processes.create_time_utc` - each process's own
    # start time, never the time the agent swept.
    #
    # Phase 7b.2 shipped five of these keyed off `collected_at_utc` and reported +0.0134
    # PR-AUC. Phase 8 found all five were NaN on every live row, because a psutil sweep
    # stamps one collection time across every process it sees. Three were then removed on
    # measurement rather than repaired (docs/ML_PHASE8_PLAN.md section 1):
    #
    #   collection_has_timespan          AUC 0.479, delta exactly 0.0000 - a gate always open
    #   seconds_since_collection_start   malicious median 0.5s vs benign 26.9s: it measured
    #                                    position within a lab recording, the same artefact
    #                                    `hour_of_day` was removed for, and removing it
    #                                    IMPROVED PR-AUC by 0.0029
    #   proc_spawn_rate_per_min          identical for every row in a collection, and defined
    #                                    over the collection's whole span - which is ~3 min
    #                                    for a capture and can be weeks for a live sweep, so
    #                                    the number is not comparable across sources at all
    #
    # What survives is only what is *per-process* and *scale-free*: a count inside a fixed
    # time window, and a parent-to-child gap. Both mean the same thing on a 3-minute capture
    # and on a live host, which is the property the deleted three lacked.
    # `procs_within_60s` was added here in Phase 8 as the replacement for the deleted
    # collection-wide spawn rate, and then removed in the same phase after measurement:
    # dropping it IMPROVED PR-AUC by 0.0154 while costing 2.4pp of recall @1% FPR, and it
    # carried the worst residual train/serve shift of the three (PSI 3.94 against 0.97 for
    # the 5s window). Adding a feature because it seemed reasonable, and keeping it because
    # it was already written, is exactly the mistake that produced this phase. The 5s window
    # survives on evidence: removing it costs 7.8pp of recall at the operating point.
    a("procs_within_5s", TIER_T1, "processes starting within 5s of this one - tight burst")
    # Retained despite measuring neutral (+0.0005 PR-AUC, -0.0049 recall - both inside the
    # noise floor), for the same reason the T3 PowerShell tier is retained: it is evidence an
    # analyst reads during an investigation even when it does not move a detection metric.
    # That is a stated null result, not a quiet keep.
    a("seconds_since_parent_start", TIER_T1,
      "gap between parent and child start - implants spawn children promptly")

    # ---- T2: Sysmon
    a("sysmon_available", TIER_T2,
      "1 if the collection contains source='sysmon' rows; gates every feature below")
    a("sysmon_integrity_level", TIER_T2, "ordinal 0..4 Untrusted..System (EID 1)")
    a("sysmon_original_name_mismatch", TIER_T2,
      "OriginalFileName differs from the image filename - renamed binary")
    a("sysmon_has_description", TIER_T2, "PE Description present - unsigned tools often lack it")
    a("sysmon_has_company", TIER_T2, "PE Company present")
    a("sysmon_terminal_session_id", TIER_T2, "0 = service session, >0 = interactive")
    a("sysmon_image_load_count", TIER_T2, "EID 7 non-system DLL loads")
    a("sysmon_image_load_unsigned", TIER_T2, "EID 7 loads whose signature is absent/invalid")
    a("sysmon_image_load_from_temp", TIER_T2, "EID 7 loads from a temp/appdata path")
    a("sysmon_remote_thread_out", TIER_T2, "EID 8 injections performed by this process")
    a("sysmon_remote_thread_in", TIER_T2, "EID 8 injections targeting this process")
    a("sysmon_file_create_count", TIER_T2, "EID 11 file creations")
    a("sysmon_file_create_in_temp", TIER_T2, "EID 11 creations under temp/appdata")
    a("sysmon_file_create_executable", TIER_T2, "EID 11 creations of executable/script files")
    a("sysmon_registry_set_count", TIER_T2, "EID 13 registry value writes")
    a("sysmon_registry_persistence", TIER_T2, "EID 13 writes to Run/Services/Winlogon keys")
    a("sysmon_dns_query_count", TIER_T2, "EID 22 DNS queries")
    a("sysmon_dns_distinct_domains", TIER_T2, "distinct queried names")
    a("sysmon_dns_failure_ratio", TIER_T2, "fraction of non-zero QueryStatus - DGA/dead C2")

    # ---- T3: PowerShell module logging (EID 4103)
    #
    # Needs PowerShell module/pipeline logging, which is GPO-controlled and off by default -
    # hence a tier of its own, measured like the T1-vs-T2 Sysmon ablation.
    #
    # Why it is worth the trouble: EID 4103's Payload contains the *deobfuscated* pipeline.
    # For an Empire agent whose command line is nothing but base64, the payload spells out the
    # RC4 key schedule and the literal C2 URIs (/admin/get.php, /news.php, /login/process.php).
    # None of that is visible to any command-line feature.
    a("psh_available", TIER_T3,
      "1 if this collection has attributable PowerShell module logging; gates the rest")
    a("psh_event_count", TIER_T3, "EID 4103 events attributed to this process")
    a("psh_payload_total_len", TIER_T3, "total deobfuscated payload length (saturating)")
    a("psh_payload_max_entropy", TIER_T3, "highest payload entropy - packed/encoded content")
    a("psh_distinct_commands", TIER_T3, "distinct CommandInvocation() names invoked")
    a("psh_has_download_cradle", TIER_T3, "payload contains a download cradle")
    a("psh_has_iex", TIER_T3, "payload contains Invoke-Expression / IEX")
    a("psh_has_url", TIER_T3, "URL or URI path in the payload - C2 endpoints surface here")
    a("psh_has_crypto_loop", TIER_T3, "byte-array/modulo arithmetic - custom crypto or packing")
    a("psh_host_app_encoded", TIER_T3, "the PowerShell host was launched with -EncodedCommand")
    a("psh_payload_to_cmdline_ratio", TIER_T3,
      "deobfuscated payload length / command-line length - how much the command line hides")

    return tuple(f)


FEATURE_SPEC: tuple[FeatureDef, ...] = _spec()
FEATURE_NAMES: tuple[str, ...] = tuple(fd.name for fd in FEATURE_SPEC)
T1_FEATURES: tuple[str, ...] = tuple(fd.name for fd in FEATURE_SPEC if fd.tier == TIER_T1)
T2_FEATURES: tuple[str, ...] = tuple(fd.name for fd in FEATURE_SPEC if fd.tier == TIER_T2)
T3_FEATURES: tuple[str, ...] = tuple(fd.name for fd in FEATURE_SPEC if fd.tier == TIER_T3)


def features_for_tier(tier: str) -> tuple[str, ...]:
    """Feature names available at `tier`, cumulatively."""
    included = set(tiers_up_to(tier))
    return tuple(fd.name for fd in FEATURE_SPEC if fd.tier in included)

# Features that need fitted corpus statistics; NaN when no stats are supplied.
FITTED_FEATURES: tuple[str, ...] = (
    "parent_name_rarity", "process_name_rarity", "parent_child_pair_rarity",
)

# Families used for leave-one-group-out ablation, so a result can be attributed to a kind of
# evidence rather than to 98 anonymous columns.
#
# `tree` is called out for a specific reason. Measured on the corpus, malicious processes have
# a median `sibling_count` of 0 against 4 (corpus benign) and 26 (local benign), and that one
# feature alone reaches ROC-AUC 0.866. That is largely an artefact of lineage labelling:
# labelling an attacker's subtree produces small families by construction, while benign
# background is dominated by services.exe/svchost.exe sibling sets. A real deployment would
# not enjoy that separation, so the headline result is reported with `tree` ABLATED and the
# gap between the two is stated. See reports_ml/ML_EVALUATION.md.
FEATURE_GROUPS: dict[str, tuple[str, ...]] = {
    "cmdline": tuple(n for n in FEATURE_NAMES if n.startswith("cmdline_")),
    "path": tuple(n for n in FEATURE_NAMES
                  if n.startswith(("path_", "exe_")) or n in ("name_path_mismatch",
                                                              "sha256_present")),
    "parent": tuple(n for n in FEATURE_NAMES if n.startswith("parent_")),
    "tree": ("sibling_count", "child_count", "tree_depth", "is_orphan"),
    "user": tuple(n for n in FEATURE_NAMES if n.startswith("user_")),
    "conn": tuple(n for n in FEATURE_NAMES if n.startswith("conn_")),
    # hour_of_day was removed in Phase 7b.1 (PSI 8.67) and must not be listed here either -
    # a stale group name silently breaks features_excluding().
    "temporal": ("is_off_hours", "is_weekend"),
    "sysmon": T2_FEATURES,
    "powershell": T3_FEATURES,
    "temporal_burst": ("procs_within_5s", "seconds_since_parent_start"),
    "rarity": FITTED_FEATURES,
    # See SEED_ECHO_FEATURES.
    "seed_echo": (
        "cmdline_has_encoded_flag", "cmdline_longest_b64_run", "cmdline_max_token_len",
        "cmdline_has_hidden_window", "cmdline_has_policy_bypass",
        "cmdline_has_download_verb", "cmdline_has_pipe_to_shell",
        "parent_cmdline_has_encoded_flag", "exe_is_lolbin", "exe_is_script_host",
        # T3 additions. These restate seed signatures just as the command-line flags do -
        # psh_host_app_encoded is literally the Empire `-enc <base64>` seed read off the
        # PowerShell host's command line - so they belong in the audit. psh_has_url,
        # psh_has_crypto_loop and psh_payload_to_cmdline_ratio are NOT listed: nothing in
        # ml/datasets/labels.py keys on payload URIs or key-schedule arithmetic, so those
        # are genuinely new evidence.
        "psh_host_app_encoded", "psh_has_download_cradle", "psh_has_iex",
    ),
}

# Features that restate the patterns the *labels* were generated from.
#
# THE LEAK AUDIT DEPENDS ON THIS LIST.
#
# Labels are weak: `ml/datasets/labels.py` seeds on signatures such as
# `-enc <base64>`, `-nop -sta`, `-w hidden`, `IEX`/`DownloadString`, and propagates to
# descendants (which is what `parent_cmdline_has_encoded_flag` restates). Several features
# encode the same patterns almost exactly. A classifier can therefore score very well by
# rediscovering the labelling rule rather than learning anything about attacker behaviour -
# and the resulting number would be meaningless.
#
# The defence is measurement, not assertion: every supervised result is reported twice, with
# these features and without. The gap between the two is the honest size of the circularity.
# Reported in reports_ml/ML_EVALUATION_TRIAGE.md.
SEED_ECHO_FEATURES: tuple[str, ...] = FEATURE_GROUPS["seed_echo"]


def features_excluding(*group_names: str, tier: str = TIER_T3) -> list[str]:
    """Feature names for `tier`, minus every feature in the named groups."""
    drop: set[str] = set()
    for group in group_names:
        if group not in FEATURE_GROUPS:
            raise KeyError(f"unknown feature group {group!r}; "
                           f"known: {sorted(FEATURE_GROUPS)}")
        drop.update(FEATURE_GROUPS[group])
    return [n for n in features_for_tier(tier) if n not in drop]


def feature_spec_sha256() -> str:
    """Stable hash of the feature contract.

    Recorded on every `ml_models` row. If the spec changes, the hash changes, and the
    registry refuses to feed a new vector to an old model instead of silently producing
    garbage scores.
    """
    blob = "\n".join(f"{fd.name}|{fd.tier}" for fd in FEATURE_SPEC)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- extraction

_PROCESS_COLUMNS = ("id", "host_id", "collection_id", "collected_at_utc", "pid", "ppid",
                    "name", "cmdline", "exe_path", "sha256", "username")


def _process_sql(conn) -> str:
    """Process query, selecting `create_time_utc` only when the database actually has it.

    The column arrives with the ML migration. Naming it unconditionally would turn a
    pre-migration database into an OperationalError inside the feature layer, and the
    contract for this whole layer is that missing telemetry degrades to NaN rather than
    raising - detection has to keep working on a host the ML overlay never reached.
    """
    selected = list(_PROCESS_COLUMNS)
    try:
        present = {r[1] for r in conn.execute("PRAGMA table_info(raw_processes)")}
    except Exception:                            # noqa: BLE001 - treat as "cannot tell"
        present = set()
    selected.append("create_time_utc" if "create_time_utc" in present
                    else "NULL AS create_time_utc")
    return "SELECT " + ", ".join(f"p.{c}" if " " not in c else c
                                 for c in selected) + " FROM raw_processes p"

_CONN_SQL = """
SELECT c.host_id, c.collection_id, c.pid, c.remote_ip, c.remote_port, c.proto, c.status
FROM raw_connections c
WHERE c.pid IS NOT NULL
"""

# Sysmon rows, with the fields we need lifted out of payload_json by SQLite's JSON1. Doing
# the extraction in SQL keeps ~75k rows from being parsed in Python.
_SYSMON_SQL = """
SELECT l.host_id, l.collection_id, l.event_id,
       json_extract(l.payload_json, '$.fields.ProcessId')        AS f_pid,
       json_extract(l.payload_json, '$.fields.SourceProcessId')  AS f_src_pid,
       json_extract(l.payload_json, '$.fields.TargetProcessId')  AS f_tgt_pid,
       json_extract(l.payload_json, '$.fields.IntegrityLevel')   AS f_integrity,
       json_extract(l.payload_json, '$.fields.OriginalFileName') AS f_origname,
       json_extract(l.payload_json, '$.fields.Image')            AS f_image,
       json_extract(l.payload_json, '$.fields.Description')      AS f_desc,
       json_extract(l.payload_json, '$.fields.Company')          AS f_company,
       json_extract(l.payload_json, '$.fields.TerminalSessionId') AS f_session,
       json_extract(l.payload_json, '$.fields.ImageLoaded')      AS f_imageloaded,
       json_extract(l.payload_json, '$.fields.SignatureStatus')  AS f_sigstatus,
       json_extract(l.payload_json, '$.fields.Signed')           AS f_signed,
       json_extract(l.payload_json, '$.fields.TargetFilename')   AS f_targetfile,
       json_extract(l.payload_json, '$.fields.TargetObject')     AS f_targetobject,
       json_extract(l.payload_json, '$.fields.QueryName')        AS f_queryname,
       json_extract(l.payload_json, '$.fields.QueryStatus')      AS f_querystatus
FROM raw_logs l
WHERE l.source = 'sysmon'
"""

# PowerShell module logging (EID 4103).
#
# ExecutionProcessID is the SUBJECT process here - the powershell.exe host writes its own
# events. On Sysmon events the same field is Sysmon's service pid and must never be used this
# way; see ml/datasets/otrf_etl.py. Rows with ExecutionProcessID 0 are unattributable (that is
# every EID 400/600/800) and are filtered out rather than guessed at.
_POWERSHELL_SQL = """
SELECT l.host_id, l.collection_id,
       CAST(json_extract(l.payload_json, '$.fields.ExecutionProcessID') AS INTEGER) AS pid,
       json_extract(l.payload_json, '$.fields.Payload')     AS f_payload,
       json_extract(l.payload_json, '$.fields.ContextInfo') AS f_context
FROM raw_logs l
WHERE l.source = 'powershell' AND l.event_id = 4103
  AND json_extract(l.payload_json, '$.fields.ExecutionProcessID') IS NOT NULL
  AND CAST(json_extract(l.payload_json, '$.fields.ExecutionProcessID') AS INTEGER) > 0
"""

# Payload markers. Deliberately distinct from the command-line regexes: the point of this tier
# is to catch what the command line hides.
_RX_PS_COMMAND = re.compile(r"CommandInvocation\(([^)]+)\)")
_RX_PS_IEX = re.compile(r"invoke-expression|\biex\b", re.I)
_RX_PS_URL = re.compile(r"https?://|/[a-z0-9_-]+\.(php|asp|aspx|jsp|cgi)\b", re.I)
# Byte-array arithmetic with a modulo - the shape of an RC4/XOR key schedule, which appears
# verbatim in the deobfuscated payload of Empire-style stagers.
_RX_PS_CRYPTO = re.compile(r"%\s*256|\[byte\[\]\]|-bxor|frombase64string|"
                           r"\$[A-Za-z_]\w*\[\$[A-Za-z_]\w*\s*%", re.I)
# Saturation point shared with the ETL's PS_PAYLOAD_CAP so a truncated corpus and an
# untruncated production log yield the same number.
PS_PAYLOAD_SATURATION = 1500

_INTEGRITY_ORDINAL = {"untrusted": 0, "low": 1, "medium": 2, "high": 3, "system": 4}

_RX_EXECUTABLE_FILE = re.compile(
    r"\.(exe|dll|scr|com|pif|bat|cmd|js|jse|vbs|vbe|ps1|psm1|hta|lnk|sys|jar|msi)$", re.I)
_RX_PERSISTENCE_KEY = re.compile(
    r"\\currentversion\\run|\\currentversion\\runonce|\\services\\|\\winlogon\\|"
    r"\\schedule\\taskcache\\", re.I)


def _scope_clause(host_ids, collection_ids, alias):
    where, params = [], []
    if host_ids:
        where.append(f"{alias}.host_id IN ({','.join('?' * len(host_ids))})")
        params += list(host_ids)
    if collection_ids:
        where.append(f"{alias}.collection_id IN ({','.join('?' * len(collection_ids))})")
        params += list(collection_ids)
    return where, params


def _read(conn, sql, host_ids, collection_ids, alias, has_where=False):
    where, params = _scope_clause(host_ids, collection_ids, alias)
    if where:
        sql = sql + (" AND " if has_where else " WHERE ") + " AND ".join(where)
    rows = conn.execute(sql, params).fetchall()
    if not rows:
        return pd.DataFrame(columns=[d[0] for d in conn.execute(sql + " LIMIT 0", params).description])
    return pd.DataFrame([dict(r) for r in rows])


def _aggregate_connections(conn_df: pd.DataFrame) -> pd.DataFrame:
    """Per-(host, collection, pid) network aggregates."""
    cols = ["host_id", "collection_id", "pid", "conn_count", "conn_distinct_remote_ips",
            "conn_distinct_remote_ports", "conn_external_count", "conn_max_remote_port",
            "conn_min_remote_port", "conn_suspicious_port_count", "conn_udp_count",
            "conn_status_known", "conn_listen_count", "conn_established_count"]
    if conn_df.empty:
        return pd.DataFrame(columns=cols)

    df = conn_df.copy()
    df["pid"] = pd.to_numeric(df["pid"], errors="coerce")
    df = df.dropna(subset=["pid"])
    df["pid"] = df["pid"].astype("int64")
    df["remote_port"] = pd.to_numeric(df["remote_port"], errors="coerce")
    df["_is_external"] = df["remote_ip"].map(lambda v: is_private_ip(v) is False)
    df["_is_suspicious"] = df["remote_port"].map(
        lambda v: bool(pd.notna(v) and int(v) in SUSPICIOUS_PORTS))
    df["_is_udp"] = df["proto"].fillna("").str.lower().eq("udp")
    status = df["status"].fillna("").str.upper()
    df["_status_known"] = status.ne("")
    df["_listen"] = status.str.contains("LISTEN")
    df["_established"] = status.eq("ESTABLISHED")

    grouped = df.groupby(["host_id", "collection_id", "pid"], dropna=False)
    out = pd.DataFrame({
        "conn_count": grouped.size(),
        "conn_distinct_remote_ips": grouped["remote_ip"].nunique(),
        "conn_distinct_remote_ports": grouped["remote_port"].nunique(),
        "conn_external_count": grouped["_is_external"].sum(),
        "conn_max_remote_port": grouped["remote_port"].max(),
        "conn_min_remote_port": grouped["remote_port"].min(),
        "conn_suspicious_port_count": grouped["_is_suspicious"].sum(),
        "conn_udp_count": grouped["_is_udp"].sum(),
        "conn_status_known": grouped["_status_known"].sum(),
        "conn_listen_count": grouped["_listen"].sum(),
        "conn_established_count": grouped["_established"].sum(),
    }).reset_index()
    return out


def _aggregate_sysmon(sys_df: pd.DataFrame) -> tuple[pd.DataFrame, set]:
    """Per-(host, collection, pid) Sysmon aggregates, plus the set of
    (host_id, collection_id) pairs that have any Sysmon data at all.

    The second return value is what distinguishes "no Sysmon on this host" (all T2
    features NaN) from "Sysmon present, this process did nothing" (zeros).
    """
    empty_cols = ["host_id", "collection_id", "pid", "sysmon_integrity_level",
                  "sysmon_original_name_mismatch", "sysmon_has_description",
                  "sysmon_has_company", "sysmon_terminal_session_id",
                  "sysmon_image_load_count", "sysmon_image_load_unsigned",
                  "sysmon_image_load_from_temp", "sysmon_remote_thread_out",
                  "sysmon_remote_thread_in", "sysmon_file_create_count",
                  "sysmon_file_create_in_temp", "sysmon_file_create_executable",
                  "sysmon_registry_set_count", "sysmon_registry_persistence",
                  "sysmon_dns_query_count", "sysmon_dns_distinct_domains",
                  "sysmon_dns_failure_ratio"]
    if sys_df.empty:
        return pd.DataFrame(columns=empty_cols), set()

    df = sys_df.copy()
    covered = set(zip(df["host_id"], df["collection_id"]))

    def _pid_for(row):
        # EID 8 is a source->target relation; every other type keys on ProcessId.
        return row["f_pid"] if row["f_pid"] is not None else row["f_src_pid"]

    df["pid"] = pd.to_numeric(df.apply(_pid_for, axis=1), errors="coerce")

    frames = []

    # --- EID 1: per-process metadata (one row per process)
    e1 = df[df["event_id"] == 1].dropna(subset=["pid"]).copy()
    if not e1.empty:
        e1["sysmon_integrity_level"] = e1["f_integrity"].map(
            lambda v: _INTEGRITY_ORDINAL.get(str(v).strip().lower(), np.nan)
            if v is not None else np.nan)
        e1["sysmon_original_name_mismatch"] = [
            np.nan if not o or not i else float(basename(o) != basename(i))
            for o, i in zip(e1["f_origname"], e1["f_image"])
        ]
        e1["sysmon_has_description"] = e1["f_desc"].map(
            lambda v: float(bool(v and str(v).strip())))
        e1["sysmon_has_company"] = e1["f_company"].map(
            lambda v: float(bool(v and str(v).strip())))
        e1["sysmon_terminal_session_id"] = pd.to_numeric(e1["f_session"], errors="coerce")
        frames.append(e1.groupby(["host_id", "collection_id", "pid"], dropna=False)[[
            "sysmon_integrity_level", "sysmon_original_name_mismatch",
            "sysmon_has_description", "sysmon_has_company", "sysmon_terminal_session_id",
        ]].first().reset_index())

    # --- EID 7: image loads
    e7 = df[df["event_id"] == 7].dropna(subset=["pid"]).copy()
    if not e7.empty:
        sig_bad = e7["f_sigstatus"].fillna("").str.lower().ne("valid")
        unsigned = e7["f_signed"].astype(str).str.lower().isin(["false", "0"])
        e7["_unsigned"] = (sig_bad | unsigned)
        e7["_temp"] = e7["f_imageloaded"].map(
            lambda v: path_category(v) in {"temp", "appdata", "downloads"})
        g = e7.groupby(["host_id", "collection_id", "pid"], dropna=False)
        frames.append(pd.DataFrame({
            "sysmon_image_load_count": g.size(),
            "sysmon_image_load_unsigned": g["_unsigned"].sum(),
            "sysmon_image_load_from_temp": g["_temp"].sum(),
        }).reset_index())

    # --- EID 8: CreateRemoteThread, counted from both ends
    e8 = df[df["event_id"] == 8].copy()
    if not e8.empty:
        src = e8.dropna(subset=["f_src_pid"]).copy()
        src["pid"] = pd.to_numeric(src["f_src_pid"], errors="coerce")
        out_g = src.dropna(subset=["pid"]).groupby(
            ["host_id", "collection_id", "pid"], dropna=False).size()
        frames.append(out_g.rename("sysmon_remote_thread_out").reset_index())

        tgt = e8.dropna(subset=["f_tgt_pid"]).copy()
        tgt["pid"] = pd.to_numeric(tgt["f_tgt_pid"], errors="coerce")
        in_g = tgt.dropna(subset=["pid"]).groupby(
            ["host_id", "collection_id", "pid"], dropna=False).size()
        frames.append(in_g.rename("sysmon_remote_thread_in").reset_index())

    # --- EID 11: file creation
    e11 = df[df["event_id"] == 11].dropna(subset=["pid"]).copy()
    if not e11.empty:
        e11["_temp"] = e11["f_targetfile"].map(
            lambda v: path_category(v) in {"temp", "appdata", "downloads"})
        e11["_exec"] = e11["f_targetfile"].map(
            lambda v: bool(v and _RX_EXECUTABLE_FILE.search(str(v))))
        g = e11.groupby(["host_id", "collection_id", "pid"], dropna=False)
        frames.append(pd.DataFrame({
            "sysmon_file_create_count": g.size(),
            "sysmon_file_create_in_temp": g["_temp"].sum(),
            "sysmon_file_create_executable": g["_exec"].sum(),
        }).reset_index())

    # --- EID 13: registry value writes
    e13 = df[df["event_id"] == 13].dropna(subset=["pid"]).copy()
    if not e13.empty:
        e13["_persist"] = e13["f_targetobject"].map(
            lambda v: bool(v and _RX_PERSISTENCE_KEY.search(str(v))))
        g = e13.groupby(["host_id", "collection_id", "pid"], dropna=False)
        frames.append(pd.DataFrame({
            "sysmon_registry_set_count": g.size(),
            "sysmon_registry_persistence": g["_persist"].sum(),
        }).reset_index())

    # --- EID 22: DNS
    e22 = df[df["event_id"] == 22].dropna(subset=["pid"]).copy()
    if not e22.empty:
        e22["_failed"] = pd.to_numeric(e22["f_querystatus"], errors="coerce").fillna(0).ne(0)
        g = e22.groupby(["host_id", "collection_id", "pid"], dropna=False)
        frames.append(pd.DataFrame({
            "sysmon_dns_query_count": g.size(),
            "sysmon_dns_distinct_domains": g["f_queryname"].nunique(),
            "sysmon_dns_failure_ratio": g["_failed"].mean(),
        }).reset_index())

    if not frames:
        return pd.DataFrame(columns=empty_cols), covered

    merged = frames[0]
    for nxt in frames[1:]:
        merged = merged.merge(nxt, on=["host_id", "collection_id", "pid"], how="outer")
    merged["pid"] = pd.to_numeric(merged["pid"], errors="coerce")
    return merged, covered


def _aggregate_powershell(ps_df: pd.DataFrame) -> tuple[pd.DataFrame, set]:
    """Per-(host, collection, pid) PowerShell aggregates, plus the collections that have any.

    The second value distinguishes "PowerShell logging is off here" (all T3 features NaN)
    from "logging is on and this process ran no PowerShell" (true zeros) - the same
    availability contract used for Sysmon.
    """
    cols = ["host_id", "collection_id", "pid", "psh_event_count", "psh_payload_total_len",
            "psh_payload_max_entropy", "psh_distinct_commands", "psh_has_download_cradle",
            "psh_has_iex", "psh_has_url", "psh_has_crypto_loop", "psh_host_app_encoded"]
    if ps_df.empty:
        return pd.DataFrame(columns=cols), set()

    df = ps_df.copy()
    df["pid"] = pd.to_numeric(df["pid"], errors="coerce")
    df = df.dropna(subset=["pid"])
    if df.empty:
        return pd.DataFrame(columns=cols), set()
    df["pid"] = df["pid"].astype("int64")
    covered = set(zip(df["host_id"], df["collection_id"]))

    payload = [("" if pd.isna(v) else str(v)) for v in df["f_payload"]]
    context = [("" if pd.isna(v) else str(v)) for v in df["f_context"]]
    df["_len"] = [min(len(v), PS_PAYLOAD_SATURATION) for v in payload]
    df["_entropy"] = [shannon_entropy(v) if v else 0.0 for v in payload]
    df["_commands"] = [",".join(sorted(set(_RX_PS_COMMAND.findall(v)))) for v in payload]
    df["_download"] = [bool(_RX_DOWNLOAD.search(v)) for v in payload]
    df["_iex"] = [bool(_RX_PS_IEX.search(v)) for v in payload]
    df["_url"] = [bool(_RX_PS_URL.search(v)) for v in payload]
    df["_crypto"] = [bool(_RX_PS_CRYPTO.search(v)) for v in payload]
    df["_host_enc"] = [bool(_RX_ENCODED_FLAG.search(v)) for v in context]

    grouped = df.groupby(["host_id", "collection_id", "pid"], dropna=False)
    out = pd.DataFrame({
        "psh_event_count": grouped.size(),
        "psh_payload_total_len": grouped["_len"].sum(),
        "psh_payload_max_entropy": grouped["_entropy"].max(),
        "psh_has_download_cradle": grouped["_download"].max().astype(float),
        "psh_has_iex": grouped["_iex"].max().astype(float),
        "psh_has_url": grouped["_url"].max().astype(float),
        "psh_has_crypto_loop": grouped["_crypto"].max().astype(float),
        "psh_host_app_encoded": grouped["_host_enc"].max().astype(float),
    }).reset_index()
    # Distinct command names across all of a process's events.
    distinct = grouped["_commands"].apply(
        lambda series: len({c for joined in series for c in joined.split(",") if c}))
    out = out.merge(distinct.rename("psh_distinct_commands").reset_index(),
                    on=["host_id", "collection_id", "pid"], how="left")
    return out, covered


def _tree_features(proc_df: pd.DataFrame) -> pd.DataFrame:
    """Sibling/child counts, ancestor depth and orphan status within each collection.

    A "collection" is one agent sweep (or one corpus capture), which is the only scope in
    which pids are unambiguous - pids are recycled across time.
    """
    out = []
    for (host_id, collection_id), grp in proc_df.groupby(
            ["host_id", "collection_id"], dropna=False):
        pid_to_ppid, child_counts = {}, Counter()
        for pid, ppid in zip(grp["pid"], grp["ppid"]):
            if pd.notna(pid):
                pid_to_ppid[int(pid)] = int(ppid) if pd.notna(ppid) else None
            if pd.notna(ppid):
                child_counts[int(ppid)] += 1
        sibling_counts = Counter(
            int(p) for p in grp["ppid"] if pd.notna(p))

        for row_id, pid, ppid in zip(grp["id"], grp["pid"], grp["ppid"]):
            pid_i = int(pid) if pd.notna(pid) else None
            ppid_i = int(ppid) if pd.notna(ppid) else None
            known_parent = ppid_i is not None and ppid_i in pid_to_ppid

            depth, seen, cursor = 0, set(), ppid_i
            # Cycle guard: recycled pids can form loops in a snapshot.
            while cursor is not None and cursor in pid_to_ppid and cursor not in seen \
                    and depth < 32:
                seen.add(cursor)
                cursor = pid_to_ppid[cursor]
                depth += 1

            out.append({
                "id": row_id,
                "sibling_count": float(max(sibling_counts.get(ppid_i, 0) - 1, 0))
                if ppid_i is not None else np.nan,
                "child_count": float(child_counts.get(pid_i, 0)) if pid_i is not None else np.nan,
                "tree_depth": float(depth),
                "is_orphan": np.nan if ppid_i is None else float(not known_parent),
            })
    return pd.DataFrame(out, columns=["id", "sibling_count", "child_count",
                                      "tree_depth", "is_orphan"])


def extract_process_frame(conn, host_ids=None, collection_ids=None,
                          since_utc=None) -> pd.DataFrame:
    """Read the raw per-process frame: process row + parent + network + Sysmon aggregates.

    Contains no learned statistic, so it is safe to compute once and split for
    cross-validation afterwards.
    """
    sql = _process_sql(conn)
    params: list = []
    where, scope_params = _scope_clause(host_ids, collection_ids, "p")
    if since_utc:
        where.append("p.collected_at_utc >= ?")
    if where:
        sql += " WHERE " + " AND ".join(where)
        params = scope_params + ([since_utc] if since_utc else [])
    rows = conn.execute(sql, params).fetchall()
    if not rows:
        return pd.DataFrame(columns=list(_PROCESS_COLUMNS) + ["create_time_utc"])
    proc = pd.DataFrame([dict(r) for r in rows])

    # pid/ppid are the join keys for the parent self-join below, and pandas refuses to merge
    # an object column against an int64 one. A column of all-NULL ppid - a collection made
    # only of container process mappings, which carry no ppid - infers as `object` and made
    # the merge raise ValueError instead of yielding no parents. Coercing both keys first
    # means a process with no recorded parent gets NaN parent attributes, which is what the
    # rest of the pipeline already expects.
    #
    # `Int64`, not `Float64`: a pid is an integer, and the nullable *integer* dtype is what
    # keeps it printing as "4" rather than "4.0". Float64 here silently broke the confidence
    # scorer, which matches detections back to processes by pid and found nothing to match
    # "4.0" against - 25 ML findings went unscored and the UI showed them all as "unscored"
    # before this was caught.
    for key in ("pid", "ppid"):
        if key in proc.columns:
            proc[key] = pd.to_numeric(proc[key], errors="coerce").astype("Int64")

    # ---- parent attributes, by self-join on (host, collection, ppid -> pid)
    parent_src = proc[["host_id", "collection_id", "pid", "name", "cmdline", "exe_path"]].rename(
        columns={"pid": "ppid", "name": "parent_name",
                 "cmdline": "parent_cmdline", "exe_path": "parent_exe_path"})
    # Several rows can share a pid inside one collection (pid reuse across a long capture);
    # keep the first so the merge cannot fan out.
    parent_src = parent_src.drop_duplicates(subset=["host_id", "collection_id", "ppid"])
    proc = proc.merge(parent_src, on=["host_id", "collection_id", "ppid"], how="left")

    # ---- network
    conn_df = _read(conn, _CONN_SQL, host_ids, collection_ids, "c", has_where=True)
    proc = proc.merge(_aggregate_connections(conn_df),
                      on=["host_id", "collection_id", "pid"], how="left")

    # ---- Sysmon (T2)
    sys_df = _read(conn, _SYSMON_SQL, host_ids, collection_ids, "l", has_where=True)
    sys_agg, sysmon_covered = _aggregate_sysmon(sys_df)
    if not sys_agg.empty:
        proc = proc.merge(sys_agg, on=["host_id", "collection_id", "pid"], how="left")
    proc["sysmon_available"] = [
        float((h, c) in sysmon_covered) for h, c in zip(proc["host_id"], proc["collection_id"])
    ]

    # ---- PowerShell module logging (T3)
    ps_df = _read(conn, _POWERSHELL_SQL, host_ids, collection_ids, "l", has_where=True)
    ps_agg, ps_covered = _aggregate_powershell(ps_df)
    if not ps_agg.empty:
        proc = proc.merge(ps_agg, on=["host_id", "collection_id", "pid"], how="left")
    proc["psh_available"] = [
        float((h, c) in ps_covered) for h, c in zip(proc["host_id"], proc["collection_id"])
    ]

    # ---- tree shape
    proc = proc.merge(_tree_features(proc), on="id", how="left")
    # ---- burst / rate (needs the timestamps, so it runs after everything is joined)
    proc = proc.merge(_temporal_features(proc), on="id", how="left")
    return proc


def _temporal_features(proc_df: pd.DataFrame) -> pd.DataFrame:
    """Burst features, computed within each collection from each process's own start time.

    **Reads `create_time_utc`, never `collected_at_utc`, and does not fall back to it.**
    That is the entire point of this function's Phase 8 rewrite. In the corpus the two
    columns hold the same value, because a corpus row is a Sysmon EID 1 record and its
    UtcTime *is* the launch time. On a live host they differ completely: `collected_at_utc`
    is when the agent swept, identical across every process in that sweep. Keying off it made
    every one of these features NaN in production while looking healthy in training.

    Falling back to `collected_at_utc` when `create_time_utc` is NULL would reintroduce the
    bug quietly - one column would mean "started at" for some rows and "observed at" for
    others, and the model would learn across both. NaN is the honest value for "this host did
    not tell us when the process started", and NaN is what the imputer is for.

    The count is **windowed**, not collection-wide, so it is scale-free: "how many processes
    started within 5 seconds of this one" means the same thing in a 3-minute lab capture and
    on a host that has been up for a month. A collection-wide rate does not, which is why
    `proc_spawn_rate_per_min` was removed rather than repaired.
    """
    columns = ["id", "procs_within_5s", "seconds_since_parent_start"]
    if proc_df.empty or "create_time_utc" not in proc_df.columns:
        return pd.DataFrame(columns=columns)

    out = []
    for _, group in proc_df.groupby(["host_id", "collection_id"], dropna=False):
        starts = {}
        for row_id, raw in zip(group["id"], group["create_time_utc"]):
            parsed = parse_iso(raw) if raw is not None and pd.notna(raw) else None
            starts[row_id] = parsed.timestamp() if parsed else None
        known = sorted(v for v in starts.values() if v is not None)

        # pid -> start time, for the parent-gap feature
        start_by_pid = {}
        for pid, row_id in zip(group["pid"], group["id"]):
            if pd.notna(pid) and starts.get(row_id) is not None:
                start_by_pid.setdefault(int(pid), starts[row_id])

        for row_id, ppid in zip(group["id"], group["ppid"]):
            t = starts.get(row_id)
            if t is None:
                out.append({"id": row_id, "procs_within_5s": np.nan,
                            "seconds_since_parent_start": np.nan})
                continue
            # Self is excluded from both counts, so a lone process scores 0 rather than 1.
            near_5 = sum(1 for other in known if abs(other - t) <= 5.0) - 1
            parent_start = (start_by_pid.get(int(ppid))
                            if pd.notna(ppid) and int(ppid) in start_by_pid else None)
            out.append({
                "id": row_id,
                "procs_within_5s": float(max(near_5, 0)),
                # Negative would mean the child predates its parent - a pid-reuse artefact,
                # so it is dropped rather than fed in as a nonsense value.
                "seconds_since_parent_start": (float(t - parent_start)
                                               if parent_start is not None
                                               and t >= parent_start else np.nan),
            })
    return pd.DataFrame(out, columns=columns)


# --------------------------------------------------------------------------- fitted stats

@dataclass
class FeatureStats:
    """Corpus frequencies for the rarity features.

    MUST be fitted on training folds only. Fitting on the full dataset and then
    cross-validating leaks the test folds' name distribution into training and inflates
    every rarity-dependent result.
    """
    name_counts: dict = field(default_factory=dict)
    parent_counts: dict = field(default_factory=dict)
    pair_counts: dict = field(default_factory=dict)
    total: int = 0

    def _rarity(self, counts: dict, key) -> float:
        if not self.total:
            return np.nan
        # Add-half smoothing: an unseen key gets a finite, larger-than-any-seen rarity.
        return -math.log10((counts.get(key, 0) + 0.5) / (self.total + 1.0))

    def name_rarity(self, name) -> float:
        return self._rarity(self.name_counts, basename(name)) if name else np.nan

    def parent_rarity(self, name) -> float:
        return self._rarity(self.parent_counts, basename(name)) if name else np.nan

    def pair_rarity(self, parent_name, name) -> float:
        if not parent_name or not name:
            return np.nan
        return self._rarity(self.pair_counts, (basename(parent_name), basename(name)))

    def to_dict(self) -> dict:
        return {
            "name_counts": self.name_counts,
            "parent_counts": self.parent_counts,
            # JSON cannot key on tuples; join with a NUL that cannot occur in a filename.
            "pair_counts": {f"{p}\x00{c}": n for (p, c), n in self.pair_counts.items()},
            "total": self.total,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "FeatureStats":
        pairs = {tuple(k.split("\x00", 1)): n for k, n in (data.get("pair_counts") or {}).items()}
        return cls(name_counts=data.get("name_counts") or {},
                   parent_counts=data.get("parent_counts") or {},
                   pair_counts=pairs, total=int(data.get("total") or 0))


def fit_stats(frame: pd.DataFrame) -> FeatureStats:
    """Fit rarity vocabularies from a *training* frame."""
    names = Counter()
    parents = Counter()
    pairs = Counter()
    for name, parent in zip(frame.get("name", []), frame.get("parent_name", [])):
        if name:
            names[basename(name)] += 1
        if parent:
            parents[basename(parent)] += 1
        if name and parent:
            pairs[(basename(parent), basename(name))] += 1
    return FeatureStats(name_counts=dict(names), parent_counts=dict(parents),
                        pair_counts=dict(pairs), total=int(len(frame)))


# --------------------------------------------------------------------------- transform

def _count_escapes(text: str | None) -> float:
    if not text:
        return 0.0
    return float(text.count("^") + text.count("`"))


def _col(frame: pd.DataFrame, name: str) -> list:
    """A column as a plain list of ``str | None``.

    Every pandas/numpy missing marker becomes None. This matters more than it looks:
    ``float('nan')`` is **truthy** in Python, so the natural-looking
    ``v if v else default`` silently lets NaN through and then explodes on ``len(v)``.
    Normalising once here keeps every downstream comprehension honest.
    """
    if name not in frame.columns:
        return [None] * len(frame)
    return [None if pd.isna(v) else str(v) for v in frame[name]]


def _num(frame: pd.DataFrame, name: str) -> pd.Series:
    """A column as a float Series aligned to ``frame.index``, all-NaN when absent.

    An absent column is the normal case, not an error: a host without Sysmon produces no
    T2 aggregate columns at all. ``frame.get(name)`` would return None there, and
    ``pd.to_numeric(None)`` yields a bare scalar rather than a Series - which then fails on
    the next ``.where()``. This keeps the type stable regardless of what the database held.
    """
    if name not in frame.columns:
        return pd.Series(np.nan, index=frame.index, dtype="float64")
    return pd.to_numeric(frame[name], errors="coerce")


def transform(frame: pd.DataFrame, stats: FeatureStats | None = None,
              tier: str = TIER_T3) -> pd.DataFrame:
    """Turn a raw frame into the feature matrix, in FEATURE_SPEC order.

    `tier='t1'` zeroes nothing - it simply omits the T2 columns, so a T1 model can never
    accidentally see a Sysmon-derived value.
    """
    if frame.empty:
        return pd.DataFrame(columns=list(features_for_tier(tier)))

    n = len(frame)
    out: dict[str, object] = {}

    # Plain lists with None for missing - see _col() on why NaN must not survive here.
    cmd = _col(frame, "cmdline")
    pcmd = _col(frame, "parent_cmdline")
    exe = _col(frame, "exe_path")
    name = _col(frame, "name")
    pname = _col(frame, "parent_name")
    sha = _col(frame, "sha256")

    # ---- command line
    out["cmdline_present"] = [float(bool(v)) for v in cmd]
    out["cmdline_len"] = [float(len(v)) if v else np.nan for v in cmd]
    out["cmdline_entropy"] = [shannon_entropy(v) if v else np.nan for v in cmd]
    tok = [token_stats(v) for v in cmd]
    out["cmdline_token_count"] = [t[0] for t in tok]
    out["cmdline_max_token_len"] = [t[1] for t in tok]
    out["cmdline_longest_b64_run"] = [longest_b64_run(v) for v in cmd]
    ratios = [char_class_ratios(v) for v in cmd]
    out["cmdline_digit_ratio"] = [r[0] for r in ratios]
    out["cmdline_upper_ratio"] = [r[1] for r in ratios]
    out["cmdline_special_ratio"] = [r[2] for r in ratios]
    for col, rx in (("cmdline_has_encoded_flag", _RX_ENCODED_FLAG),
                    ("cmdline_has_hidden_window", _RX_HIDDEN),
                    ("cmdline_has_policy_bypass", _RX_BYPASS),
                    ("cmdline_has_download_verb", _RX_DOWNLOAD),
                    ("cmdline_has_pipe_to_shell", _RX_PIPE_SHELL),
                    ("cmdline_has_ads", _RX_ADS)):
        out[col] = [float(bool(rx.search(v))) if v else np.nan for v in cmd]
    out["cmdline_url_count"] = [float(len(_RX_URL.findall(v))) if v else np.nan for v in cmd]
    out["cmdline_ip_literal_count"] = [
        float(len(_RX_IP_LITERAL.findall(v))) if v else np.nan for v in cmd]
    out["cmdline_env_var_count"] = [
        float(len(_RX_ENV_VAR.findall(v))) if v else np.nan for v in cmd]
    out["cmdline_escape_char_count"] = [_count_escapes(v) if v else np.nan for v in cmd]

    # ---- image path
    out["path_depth"] = [path_depth(v) for v in exe]
    base = [basename(v) if v else None for v in name]
    out["exe_name_len"] = [float(len(v)) if v else np.nan for v in base]
    out["exe_name_entropy"] = [shannon_entropy(v) if v else np.nan for v in base]
    out["exe_name_has_space"] = [float(" " in v) if v else np.nan for v in base]
    out["exe_name_double_ext"] = [
        float(bool(_RX_DOUBLE_EXT.search(v))) if v else np.nan for v in base]
    out["exe_is_lolbin"] = [float(v in LOLBINS) if v else np.nan for v in base]
    out["exe_is_script_host"] = [float(v in SCRIPT_HOSTS) if v else np.nan for v in base]
    out["exe_masquerades_system"] = [is_masquerading(nm, px) for nm, px in zip(name, exe)]
    out["name_path_mismatch"] = [name_path_mismatch(nm, px) for nm, px in zip(name, exe)]
    out["sha256_present"] = [float(bool(v)) for v in sha]
    cats = [path_category(v) for v in exe]
    for cat in PATH_CATEGORIES:
        out[f"path_cat_{cat}"] = [float(v == cat) for v in cats]

    # ---- parent
    pbase = [basename(v) if v else None for v in pname]
    out["parent_known"] = [float(bool(v)) for v in pname]
    for col, members in (("parent_is_lolbin", LOLBINS),
                         ("parent_is_shell", SHELL_NAMES),
                         ("parent_is_office", OFFICE_NAMES),
                         ("parent_is_browser", BROWSER_NAMES),
                         ("parent_is_service_host", SERVICE_HOST_NAMES)):
        out[col] = [float(v in members) if v else np.nan for v in pbase]
    out["parent_is_explorer"] = [
        float(v == "explorer.exe") if v else np.nan for v in pbase]
    out["parent_cmdline_len"] = [float(len(v)) if v else np.nan for v in pcmd]
    out["parent_cmdline_entropy"] = [shannon_entropy(v) if v else np.nan for v in pcmd]
    out["parent_cmdline_has_encoded_flag"] = [
        float(bool(_RX_ENCODED_FLAG.search(v))) if v else np.nan for v in pcmd]

    if stats is not None and stats.total:
        out["parent_name_rarity"] = [stats.parent_rarity(v) for v in pname]
        out["process_name_rarity"] = [stats.name_rarity(v) for v in name]
        out["parent_child_pair_rarity"] = [
            stats.pair_rarity(p, c) for p, c in zip(pname, name)]
    else:
        for col in FITTED_FEATURES:
            out[col] = np.full(n, np.nan)

    # ---- tree
    for col in ("sibling_count", "child_count", "tree_depth", "is_orphan"):
        out[col] = _num(frame, col)

    # ---- user
    user_flags = [classify_user(v) for v in _col(frame, "username")]
    for key in ("user_present", "user_is_system", "user_is_service_account",
                "user_is_admin_like", "user_is_domain"):
        out[key] = [d[key] for d in user_flags]

    # ---- network. conn_available separates "no sockets" from "no data".
    conn_count = _num(frame, "conn_count")
    has_conn = conn_count.notna() & (conn_count > 0)
    out["conn_available"] = has_conn.map(float)
    for col in ("conn_count", "conn_distinct_remote_ips", "conn_distinct_remote_ports",
                "conn_external_count", "conn_max_remote_port", "conn_min_remote_port",
                "conn_suspicious_port_count"):
        values = _num(frame, col)
        out[col] = values.where(has_conn, np.nan)
    with np.errstate(invalid="ignore", divide="ignore"):
        ext = _num(frame, "conn_external_count")
        udp = _num(frame, "conn_udp_count")
        out["conn_external_ratio"] = (ext / conn_count).where(has_conn, np.nan)
        out["conn_udp_ratio"] = (udp / conn_count).where(has_conn, np.nan)

    # TCP state exists in psutil output but never in Sysmon EID 3, so it gets its own
    # availability flag and its dependants are NaN - not 0 - when it is absent.
    status_known = _num(frame, "conn_status_known").fillna(0)
    has_status = has_conn & (status_known > 0)
    out["conn_status_available"] = has_status.map(float)
    for col in ("conn_listen_count", "conn_established_count"):
        out[col] = _num(frame, col).where(has_status, np.nan)

    # ---- temporal
    #
    # hour_of_day is deliberately absent: PSI 8.67 between corpus and live, because it
    # encodes when the 2020 lab captures ran rather than anything behavioural. Removed in
    # Phase 7b.1.
    parsed = [parse_iso(v) for v in _col(frame, "collected_at_utc")]
    out["is_off_hours"] = [
        np.nan if not d else float(not (BUSINESS_HOUR_START <= d.hour < BUSINESS_HOUR_END))
        for d in parsed]
    out["is_weekend"] = [float(d.weekday() >= 5) if d else np.nan for d in parsed]
    for col in ("procs_within_5s", "seconds_since_parent_start"):
        out[col] = _num(frame, col)

    # ---- T2
    included = set(tiers_up_to(tier))
    if TIER_T2 in included:
        sysmon_on = _num(frame, "sysmon_available").fillna(0) > 0
        out["sysmon_available"] = sysmon_on.map(float)
        counting = {
            "sysmon_image_load_count", "sysmon_image_load_unsigned",
            "sysmon_image_load_from_temp", "sysmon_remote_thread_out",
            "sysmon_remote_thread_in", "sysmon_file_create_count",
            "sysmon_file_create_in_temp", "sysmon_file_create_executable",
            "sysmon_registry_set_count", "sysmon_registry_persistence",
            "sysmon_dns_query_count", "sysmon_dns_distinct_domains",
        }
        for fd in FEATURE_SPEC:
            if fd.tier != TIER_T2 or fd.name == "sysmon_available":
                continue
            values = _num(frame, fd.name)
            if fd.name in counting:
                # Sysmon present but no such event => a true zero. Sysmon absent => unknown.
                values = values.fillna(0.0)
            out[fd.name] = values.where(sysmon_on, np.nan)

    # ---- T3: PowerShell module logging
    if TIER_T3 in included:
        psh_on = _num(frame, "psh_available").fillna(0) > 0
        out["psh_available"] = psh_on.map(float)
        # With logging on, "this process ran no PowerShell" is a genuine zero; with logging
        # off, it is unknown. Same contract as the Sysmon block above.
        counting_t3 = {"psh_event_count", "psh_payload_total_len", "psh_distinct_commands",
                       "psh_has_download_cradle", "psh_has_iex", "psh_has_url",
                       "psh_has_crypto_loop", "psh_host_app_encoded"}
        for fd in FEATURE_SPEC:
            if fd.tier != TIER_T3 or fd.name == "psh_available":
                continue
            if fd.name == "psh_payload_to_cmdline_ratio":
                continue                         # derived below
            values = _num(frame, fd.name)
            if fd.name in counting_t3:
                values = values.fillna(0.0)
            out[fd.name] = values.where(psh_on, np.nan)
        # How much the command line hides: deobfuscated payload length over command-line
        # length. An Empire agent whose command line is pure base64 scores very high here.
        payload_len = _num(frame, "psh_payload_total_len").fillna(0.0)
        cmd_len = pd.Series(
            [float(len(v)) if v else np.nan for v in cmd], index=frame.index)
        with np.errstate(invalid="ignore", divide="ignore"):
            ratio = payload_len / cmd_len.replace(0.0, np.nan)
        out["psh_payload_to_cmdline_ratio"] = ratio.where(psh_on, np.nan)

    wanted = list(features_for_tier(tier))
    matrix = pd.DataFrame(out, index=frame.index)
    for col in wanted:                       # guarantee full, ordered coverage
        if col not in matrix.columns:
            matrix[col] = np.nan
    return matrix[wanted].astype("float64")


def build_matrix(conn, host_ids=None, collection_ids=None, since_utc=None,
                 stats: FeatureStats | None = None, tier: str = TIER_T3):
    """Convenience wrapper: read + transform. Returns (X, raw_frame)."""
    frame = extract_process_frame(conn, host_ids, collection_ids, since_utc)
    return transform(frame, stats=stats, tier=tier), frame


def missingness_report(matrix: pd.DataFrame) -> pd.DataFrame:
    """Per-feature NaN rate. The core skew diagnostic: run it on the corpus and on live
    data and compare - a feature that is 2% missing in training and 100% missing in
    production is a latent production failure, not a modelling detail.
    """
    if matrix.empty:
        return pd.DataFrame(columns=["feature", "tier", "missing", "missing_pct"])
    tiers = {fd.name: fd.tier for fd in FEATURE_SPEC}
    counts = matrix.isna().sum()
    return pd.DataFrame({
        "feature": counts.index,
        "tier": [tiers.get(c, "?") for c in counts.index],
        "missing": counts.to_numpy(),
        "missing_pct": (counts.to_numpy() / len(matrix) * 100).round(2),
    }).sort_values("missing_pct", ascending=False, ignore_index=True)


if __name__ == "__main__":       # pragma: no cover - operator entry point
    import argparse
    from server import db as database
    ap = argparse.ArgumentParser(description="Build and describe an ML feature matrix")
    ap.add_argument("--db", default=os.environ.get("ATOR_DFIR_DB"))
    ap.add_argument("--tier", choices=[TIER_T1, TIER_T2], default=TIER_T2)
    ap.add_argument("--limit-missing", type=int, default=25)
    args = ap.parse_args()
    connection = database.connect(args.db)
    try:
        frame = extract_process_frame(connection)
        st = fit_stats(frame)
        X = transform(frame, stats=st, tier=args.tier)
        print(f"spec sha256 : {feature_spec_sha256()}")
        print(f"rows        : {len(X)}")
        print(f"features    : {X.shape[1]} ({len(T1_FEATURES)} T1 / {len(T2_FEATURES)} T2)")
        print("\nhighest missingness:")
        print(missingness_report(X).head(args.limit_missing).to_string(index=False))
    finally:
        connection.close()
