"""Plain security language for the ML layer.

The ML Analytics page is read by security analysts, not data scientists. Every model
output passes through here before it reaches the page, so the page never shows a raw
feature name, a PR-AUC or a PSI value as its primary message.

The translation lives in one module rather than in the template for two reasons:

* it is testable - `tests/test_ml_vocabulary.py` fails the build if a feature is added
  to the model without a plain-language label here, the same way the train/serve
  coverage guard stops a feature that only works in training;
* the precision behind every sentence stays checkable. Performance sentences are
  generated from the metrics stored inside each model artefact, never written as
  literals, so a retrain cannot leave the page claiming numbers the model no longer has.

The technical names are not hidden: every translated indicator keeps its raw feature name
for a tooltip, and the page keeps a collapsed technical section for data scientists.
"""
from __future__ import annotations

import math
import re

# --------------------------------------------------------------------------- categories

#: feature group -> (label an analyst recognises, Bootstrap icon)
CATEGORIES = {
    "cmdline": ("Command line", "bi-terminal"),
    "path": ("File & location", "bi-folder2-open"),
    "parent": ("Process lineage", "bi-diagram-3"),
    "tree": ("Process tree", "bi-diagram-2"),
    "rarity": ("Rarity on this estate", "bi-stars"),
    "user": ("Account", "bi-person-badge"),
    "conn": ("Network", "bi-globe2"),
    "temporal": ("Timing", "bi-clock-history"),
    "temporal_burst": ("Timing", "bi-lightning-charge"),
    "sysmon": ("Sysmon telemetry", "bi-eye"),
    "powershell": ("PowerShell", "bi-code-slash"),
}
_FALLBACK_CATEGORY = ("Behaviour", "bi-activity")

# --------------------------------------------------------------------------- indicators
#
# name -> (neutral, when HIGHER than normal, when LOWER than normal)
#
# `neutral` is used when the direction is unknown (findings recorded before direction was
# stored) and for a direction with no meaningful reading. For yes/no indicators the
# "higher" text reads as the indicator being present.

INDICATORS: dict[str, tuple[str, str, str | None]] = {
    # -- command line
    "cmdline_present": ("Command-line visibility unusual", "Command line captured",
                        "Command line hidden from the agent"),
    "cmdline_len": ("Unusual command-line length", "Unusually long command line",
                    "Unusually short command line"),
    "cmdline_entropy": ("Unusual command-line content", "Command line looks encoded or packed",
                        "Unusually repetitive command line"),
    "cmdline_token_count": ("Unusual number of arguments", "Unusually many command-line arguments",
                            "Unusually few command-line arguments"),
    "cmdline_max_token_len": ("Unusual argument length",
                              "Very long single argument (possible embedded payload)", None),
    "cmdline_longest_b64_run": ("Encoded-looking content", "Base64-like blob in the command line",
                                None),
    "cmdline_digit_ratio": ("Unusual command-line characters", "Command line dense with digits",
                            None),
    "cmdline_upper_ratio": ("Unusual command-line characters",
                            "Mixed-case, encoded-looking command line", None),
    "cmdline_special_ratio": ("Unusual command-line characters",
                              "Symbol-heavy, obfuscated-looking command line", None),
    "cmdline_has_encoded_flag": ("Encoded command", "Encoded command (-enc / FromBase64String)",
                                 None),
    "cmdline_has_hidden_window": ("Hidden window", "Runs with a hidden window", None),
    "cmdline_has_policy_bypass": ("Policy bypass", "Bypasses the PowerShell execution policy",
                                  None),
    "cmdline_has_download_verb": ("Download behaviour", "Downloads content (download cradle)",
                                  None),
    "cmdline_has_pipe_to_shell": ("Pipe into a shell", "Pipes output into a shell or IEX", None),
    "cmdline_url_count": ("URLs in the command line", "URLs in the command line", None),
    "cmdline_ip_literal_count": ("Raw IP addresses", "Raw IP addresses in the command line", None),
    "cmdline_env_var_count": ("Environment-variable use",
                              "Environment-variable obfuscation in the command line", None),
    "cmdline_has_ads": ("Alternate data stream", "References an NTFS alternate data stream", None),
    "cmdline_escape_char_count": ("Escape characters", "Escape-character obfuscation (^ or `)",
                                  None),
    # -- file and location
    "path_depth": ("Unusual folder depth", "Runs from an unusually deep folder",
                   "Runs from an unusually shallow folder"),
    "exe_name_len": ("Unusual executable name", "Unusually long executable name",
                     "Unusually short executable name"),
    "exe_name_entropy": ("Unusual executable name", "Random-looking executable name", None),
    "exe_name_has_space": ("Space in the file name", "Space in the executable name", None),
    "exe_name_double_ext": ("Double extension", "Double extension (e.g. invoice.pdf.exe)", None),
    "exe_is_lolbin": ("Living-off-the-land binary", "Living-off-the-land binary (LOLBAS)", None),
    "exe_is_script_host": ("Script interpreter", "Script interpreter (PowerShell, wscript...)",
                           None),
    "exe_masquerades_system": ("Masquerading", "System binary name outside a system folder", None),
    "name_path_mismatch": ("Name mismatch", "Process name differs from its file on disk", None),
    "sha256_present": ("File hash availability", "File hash captured", "File hash unavailable"),
    "path_cat_system32": ("Unusual install location", "Runs from System32", None),
    "path_cat_windows_other": ("Unusual install location",
                               "Runs from a Windows folder outside System32", None),
    "path_cat_program_files": ("Unusual install location", "Runs from Program Files", None),
    "path_cat_programdata": ("Unusual install location", "Runs from ProgramData", None),
    "path_cat_appdata": ("Unusual install location", "Runs from a user AppData folder", None),
    "path_cat_temp": ("Unusual install location", "Runs from a Temp folder", None),
    "path_cat_downloads": ("Unusual install location", "Runs from the Downloads folder", None),
    "path_cat_user_other": ("Unusual install location", "Runs from a user profile folder", None),
    "path_cat_unc": ("Unusual install location", "Runs from a network share (UNC path)", None),
    "path_cat_root_drive": ("Unusual install location", "Runs from the root of a drive", None),
    "path_cat_other": ("Unusual install location", "Runs from an uncommon location", None),
    "path_cat_missing": ("Unknown location", "Executable path unknown", None),
    # -- lineage
    "parent_known": ("Parent visibility", "Parent process visible",
                     "Parent process gone (orphaned or short-lived parent)"),
    "parent_is_lolbin": ("LOLBAS parent", "Launched by a living-off-the-land binary", None),
    "parent_is_shell": ("Shell parent", "Launched from a command shell", None),
    "parent_is_office": ("Office parent", "Launched by an Office application (macro chain)", None),
    "parent_is_browser": ("Browser parent", "Launched by a web browser (drive-by chain)", None),
    "parent_is_service_host": ("Service parent", "Launched by a service host", None),
    "parent_is_explorer": ("Interactive launch", "Launched interactively from Explorer", None),
    "parent_cmdline_len": ("Unusual parent command line", "Parent has an unusually long command line",
                           None),
    "parent_cmdline_entropy": ("Unusual parent command line", "Parent command line looks encoded",
                               None),
    "parent_cmdline_has_encoded_flag": ("Encoded parent", "Parent ran an encoded command", None),
    "parent_name_rarity": ("Parent rarity", "Rarely seen parent process", "Very common parent process"),
    "process_name_rarity": ("Process rarity", "Rarely seen process name", "Very common process name"),
    "parent_child_pair_rarity": ("Rare lineage", "Rare parent-to-child combination", None),
    # -- process tree
    "sibling_count": ("Unusual sibling count", "Parent spawned many similar processes",
                      "Few sibling processes"),
    "child_count": ("Unusual child count", "Spawns many child processes",
                    "Spawns fewer children than normal"),
    "tree_depth": ("Unusual process chain", "Deep process chain", "Shallow process chain"),
    "is_orphan": ("Orphaned process", "Orphaned process (parent already gone)", None),
    # -- account
    "user_present": ("Account visibility", "Account captured", "Account unknown"),
    "user_is_system": ("SYSTEM account", "Runs as SYSTEM", "Not running as SYSTEM"),
    "user_is_service_account": ("Service account", "Runs as a service account", None),
    "user_is_admin_like": ("Admin account", "Runs under an admin-named account", None),
    "user_is_domain": ("Domain account", "Runs under a domain account", None),
    # -- network
    "conn_available": ("Network activity", "Has network activity", "No network activity"),
    "conn_count": ("Unusual connection count", "Unusually many network connections",
                   "Fewer connections than normal"),
    "conn_distinct_remote_ips": ("Many destinations", "Talks to many different hosts", None),
    "conn_distinct_remote_ports": ("Many destination ports", "Uses many different remote ports",
                                   None),
    "conn_external_count": ("External traffic", "Many connections leave the network", None),
    "conn_external_ratio": ("External traffic", "Traffic mostly leaves the network",
                            "Traffic stays inside the network"),
    "conn_max_remote_port": ("Unusual remote port", "Connects to an unusually high remote port",
                             "Connects only to low remote ports"),
    "conn_min_remote_port": ("Unusual remote port", "Connects to unusual remote ports",
                             "Connects to low / system ports"),
    "conn_suspicious_port_count": ("Suspicious ports", "Uses known C2 or reverse-shell ports", None),
    "conn_udp_ratio": ("UDP traffic", "Mostly UDP traffic", None),
    "conn_status_available": ("Connection state", "Connection state captured", None),
    "conn_listen_count": ("Listening ports", "Listening on network ports", None),
    "conn_established_count": ("Open connections", "Many established connections", None),
    # -- timing
    "is_off_hours": ("Off-hours activity", "Active outside business hours", None),
    "is_weekend": ("Weekend activity", "Active at the weekend", None),
    "procs_within_5s": ("Launch burst", "Part of a burst of process launches", "Started in isolation"),
    "seconds_since_parent_start": ("Unusual launch timing", "Started long after its parent",
                                   "Spawned immediately by its parent"),
    # -- Sysmon (enhanced telemetry)
    "sysmon_available": ("Sysmon telemetry", "Sysmon telemetry present", "No Sysmon telemetry"),
    "sysmon_integrity_level": ("Integrity level", "Elevated integrity level", "Low integrity level"),
    "sysmon_original_name_mismatch": ("Renamed binary", "Renamed binary (original name differs)",
                                      None),
    "sysmon_has_description": ("File metadata", "File has a description",
                               "No file description (common for attack tools)"),
    "sysmon_has_company": ("File metadata", "Company present in file metadata",
                           "No company in file metadata"),
    "sysmon_terminal_session_id": ("Session type", "Interactive session", "Service session"),
    "sysmon_image_load_count": ("DLL loading", "Loads many non-system DLLs", None),
    "sysmon_image_load_unsigned": ("Unsigned DLLs", "Loads unsigned DLLs", None),
    "sysmon_image_load_from_temp": ("DLLs from Temp", "Loads DLLs from Temp / AppData", None),
    "sysmon_remote_thread_out": ("Process injection", "Injects code into other processes", None),
    "sysmon_remote_thread_in": ("Process injection", "Targeted by process injection", None),
    "sysmon_file_create_count": ("File activity", "Creates many files", None),
    "sysmon_file_create_in_temp": ("Drops files", "Drops files into Temp / AppData", None),
    "sysmon_file_create_executable": ("Drops executables", "Drops executables or scripts", None),
    "sysmon_registry_set_count": ("Registry activity", "Writes many registry values", None),
    "sysmon_registry_persistence": ("Persistence", "Writes to autorun registry keys (persistence)",
                                    None),
    "sysmon_dns_query_count": ("DNS activity", "Makes many DNS lookups", None),
    "sysmon_dns_distinct_domains": ("DNS activity", "Looks up many different domains", None),
    "sysmon_dns_failure_ratio": ("Failed DNS", "Many failed DNS lookups (DGA or dead C2)", None),
    # -- PowerShell logging
    "psh_available": ("PowerShell logging", "PowerShell logging present", "No PowerShell logging"),
    "psh_event_count": ("PowerShell activity", "Heavy PowerShell activity", None),
    "psh_payload_total_len": ("PowerShell payload", "Large PowerShell payload", None),
    "psh_payload_max_entropy": ("Obfuscated PowerShell", "Obfuscated PowerShell payload", None),
    "psh_distinct_commands": ("PowerShell commands", "Runs many distinct PowerShell commands", None),
    "psh_has_download_cradle": ("Download cradle", "PowerShell download cradle", None),
    "psh_has_iex": ("Invoke-Expression", "PowerShell Invoke-Expression (IEX)", None),
    "psh_has_url": ("URL in PowerShell", "URL inside the PowerShell payload", None),
    "psh_has_crypto_loop": ("Crypto / packing", "Custom crypto or packing loop in PowerShell", None),
    "psh_host_app_encoded": ("Encoded PowerShell", "PowerShell launched with an encoded command",
                             None),
    "psh_payload_to_cmdline_ratio": ("Hidden PowerShell code",
                                     "Runs far more code than its command line shows", None),
}


def _group_of(feature: str) -> str | None:
    from server.engine import ml_features as mlf
    for group, members in mlf.FEATURE_GROUPS.items():
        if group != "seed_echo" and feature in members:
            return group
    return None


def _prettify(feature: str) -> str:
    """Readable fallback for a feature with no entry (e.g. one removed from the spec)."""
    words = re.sub(r"[_]+", " ", feature).strip()
    return words[:1].upper() + words[1:] if words else "Unusual behaviour"


#: Yes/no indicators. Their deviation is always exactly 1.0 (a 0/1 column has no spread
#: around its baseline), so a strength bar would call "Encoded command" merely "somewhat
#: unusual". They are shown as present/absent instead.
_FLAG = re.compile(r"(^|_)(has|is)_|^path_cat_|_mismatch$|masquerades|double_ext|"
                   r"_present$|_available$|_known$")


def is_flag(feature: str) -> bool:
    return bool(_FLAG.search(feature or ""))


def strength(deviation) -> tuple[int, str]:
    """How far from normal, as 1-3 bars an analyst can read at a glance."""
    try:
        d = float(deviation)
    except (TypeError, ValueError):
        return 1, "unusual"
    if not math.isfinite(d) or d < 3:
        return 1, "somewhat unusual"
    if d < 10:
        return 2, "unusual"
    return 3, "highly unusual"


def indicator(entry: dict) -> dict:
    """One explanation entry -> {text, category, icon, bars, strength, feature}."""
    feature = str((entry or {}).get("feature") or "")
    neutral, higher, lower = INDICATORS.get(feature, (None, None, None))
    direction = (entry or {}).get("direction")
    if direction == "higher" and higher:
        text = higher
    elif direction == "lower" and lower:
        text = lower
    else:
        text = neutral or _prettify(feature)
    label, icon = CATEGORIES.get(_group_of(feature) or "", _FALLBACK_CATEGORY)
    if is_flag(feature):
        bars, words = None, ("absent" if direction == "lower" else "present")
    else:
        bars, words = strength((entry or {}).get("deviation"))
    return {"text": text, "category": label, "icon": icon, "bars": bars,
            "strength": words, "feature": feature}


def indicators(explanation: dict, limit: int | None = None) -> list[dict]:
    items = [indicator(e) for e in ((explanation or {}).get("top_features") or [])
             if isinstance(e, dict)]
    seen, unique = set(), []
    for item in items:                           # two features can read the same
        if item["text"] not in seen:
            seen.add(item["text"])
            unique.append(item)
    return unique[:limit] if limit else unique


def feature_label(feature: str) -> str:
    """Neutral label for a feature where no single finding is involved (data health)."""
    neutral = INDICATORS.get(feature, (None,))[0]
    return neutral or _prettify(feature)


# --------------------------------------------------------------------------- scores

def likelihood(confidence) -> dict | None:
    """Component B output -> threat likelihood an analyst can act on. None when unscored."""
    try:
        c = float(confidence)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(c):
        return None
    if c >= 0.8:
        level, css = "High", "risk-critical"
    elif c >= 0.5:
        level, css = "Elevated", "risk-high"
    elif c >= 0.2:
        level, css = "Low", "risk-elevated"
    else:
        level, css = "Minimal", "risk-low"
    return {"level": level, "pct": round(c * 100), "css": css, "raw": c}


def priority(confidence, anomaly_score) -> dict:
    """Triage priority P1-P4, from the signal the queue is sorted by.

    Not the stored detection severity. That comes from the anomaly engine alone, i.e. from
    rarity, so a developer tool could read "LOW" beside "High - 86% threat likelihood" in
    the same row. Priority follows threat likelihood first, which is what the queue is
    ordered by, so the labels and the order never disagree. Rarity only decides for leads
    that have no likelihood score yet.
    """
    like = likelihood(confidence)
    rare = rarity(anomaly_score)
    if like is not None:
        c = like["raw"]
        if c >= 0.8:
            return {"label": "P1", "css": "badge-critical",
                    "title": "P1 - strongly resembles known attack activity; investigate first"}
        if c >= 0.5:
            return {"label": "P2", "css": "badge-high",
                    "title": "P2 - likely malicious; investigate soon"}
        if c >= 0.2:
            return {"label": "P3", "css": "badge-medium",
                    "title": "P3 - some resemblance to attack activity; review when time allows"}
        return {"label": "P4", "css": "badge-low",
                "title": "P4 - unusual but unlike known attacks; usually legitimate software"}
    if rare is not None and rare["raw"] >= 0.999:
        return {"label": "P3", "css": "badge-medium",
                "title": "P3 - extremely rare behaviour, not yet scored for threat likelihood"}
    return {"label": "P4", "css": "badge-low",
            "title": "P4 - not yet scored for threat likelihood"}


def rarity(anomaly_score) -> dict | None:
    """Component A percentile -> "rarer than N% of normal activity"."""
    try:
        a = float(anomaly_score)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(a):
        return None
    top = max(0.0, (1.0 - a) * 100)
    if top < 0.1:
        text = "Top 0.1%"
    elif top < 1:
        text = f"Top {top:.1f}%"
    else:
        text = f"Top {top:.0f}%"
    return {"text": text, "raw": a,
            "sentence": f"Rarer than {min(a * 100, 99.9):.1f}% of normal activity on this estate"}


# --------------------------------------------------------------------------- ATT&CK

TACTICS = {
    "reconnaissance": ("Reconnaissance", "TA0043"),
    "resource_development": ("Resource Development", "TA0042"),
    "initial_access": ("Initial Access", "TA0001"),
    "execution": ("Execution", "TA0002"),
    "persistence": ("Persistence", "TA0003"),
    "privilege_escalation": ("Privilege Escalation", "TA0004"),
    "defense_evasion": ("Defense Evasion", "TA0005"),
    "credential_access": ("Credential Access", "TA0006"),
    "discovery": ("Discovery", "TA0007"),
    "lateral_movement": ("Lateral Movement", "TA0008"),
    "collection": ("Collection", "TA0009"),
    "command_and_control": ("Command and Control", "TA0011"),
    "exfiltration": ("Exfiltration", "TA0010"),
    "impact": ("Impact", "TA0040"),
}


def tactic(name: str) -> dict:
    display, tid = TACTICS.get(str(name), (_prettify(str(name)), None))
    return {"name": display, "id": tid,
            "url": f"https://attack.mitre.org/tactics/{tid}/" if tid else None}


# --------------------------------------------------------------------------- engines

ENGINES = {
    "anomaly": {
        "title": "Anomaly hunter",
        "icon": "bi-binoculars",
        "what": "Flags processes that behave unlike anything normal on this estate - "
                "including behaviour no signature has been written for.",
    },
    "triage": {
        "title": "Threat-likelihood scorer",
        "icon": "bi-shield-exclamation",
        "what": "Rates every detection - rule-based and behavioural - by how closely the "
                "process resembles known attack activity, so one queue can be worked in order.",
    },
    "tactic": {
        "title": "ATT&CK tactic advisor",
        "icon": "bi-diagram-3",
        "what": "Suggests which MITRE ATT&CK tactic an unmapped behavioural lead most "
                "resembles. Advisory only; it stays silent when unsure.",
    },
}

TELEMETRY = {"t1": "Standard (process data)", "t2": "Enhanced (Sysmon)"}


def _pct(value) -> int | None:
    try:
        return round(float(value) * 100)
    except (TypeError, ValueError):
        return None


def lab_results(model_type: str, metrics: dict, gate: dict | None = None) -> list[str]:
    """What the model achieved in lab testing, in sentences an analyst can weigh.

    Built only from numbers stored in the model artefact. Returns [] rather than a
    guessed sentence when a number is missing.
    """
    m = metrics or {}
    out = []
    if model_type in ("anomaly", "triage"):
        p25 = m.get("precision_at_25")
        if p25 is not None:
            out.append(f"{round(float(p25) * 25)} of its 25 highest-ranked leads were real attacks.")
        caught = _pct(m.get("recall_at_fpr_0.01"))
        if caught is not None:
            out.append(f"Catches {caught}% of attacks while mis-flagging 1 in 100 benign processes.")
    elif model_type == "tactic" and gate:
        if gate.get("precision_pct") is not None:
            out.append(f"Right about {gate['precision_pct']}% of the time when it offers a tactic.")
        if gate.get("coverage_pct") is not None:
            out.append(f"Offers a tactic for about {gate['coverage_pct']}% of attacks; "
                       "silent on the rest.")
    return out


def engine_cards(ml: dict) -> list[dict]:
    """ml_registry.describe() -> one card per engine, T1 preferred as the served tier."""
    by_type: dict[str, list[dict]] = {}
    for entry in (ml or {}).get("models") or []:
        by_type.setdefault(entry.get("model_type"), []).append(entry)
    cards = []
    for model_type, spec in ENGINES.items():
        entries = sorted(by_type.get(model_type, []), key=lambda e: e.get("tier") != "t1")
        served = entries[0] if entries else None
        if served is None:
            status, css = "Not installed", "offline"
        elif not served.get("loadable"):
            status, css = "Offline - needs retraining", "offline"
        elif model_type == "tactic":
            status, css = "Online - advisory", "warn"
        else:
            status, css = "Online", "online"
        cards.append({
            **spec, "type": model_type, "status": status, "status_css": css,
            "telemetry": TELEMETRY.get((served or {}).get("tier"), "-"),
            "trained": ((served or {}).get("trained_at_utc") or "")[:10],
            "results": lab_results(model_type, (served or {}).get("metrics") or {},
                                   (ml or {}).get("tactic_gate")),
        })
    return cards


# --------------------------------------------------------------------------- data health

HEALTH = {
    "stable": ("Healthy", "online"),
    "moderate": ("Watch", "warn"),
    "shifted": ("Degraded", "offline"),
}


def health(verdict: str) -> dict:
    label, css = HEALTH.get(str(verdict), ("Unknown", "revoked"))
    return {"label": label, "css": css}
