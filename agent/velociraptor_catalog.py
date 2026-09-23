"""Curated allow-list of Velociraptor artifacts ATOR may collect.

This module is the contract shared by both personas and is deliberately the
ONLY place an artifact name can enter the system:

  * the server validates an analyst's request against it before queueing a
    command, and
  * the agent validates again before it execs anything.

That double check is the point. ``velociraptor_collect`` travels over the same
heartbeat command channel as ``collect_now``, so without an allow-list a server
(or anything that could forge a command) would be able to run arbitrary VQL on
every endpoint. Artifacts are data-gathering queries only; none of the entries
below modify the endpoint.

Entries are picked for triage value at low cost. ``requires_tool`` marks the
ones Velociraptor implements by downloading a third-party binary - they are
listed for completeness but are off by default, because an endpoint that
fetches tools mid-investigation is its own problem.
"""

# name -> metadata. technique_id feeds the normal ATT&CK enrichment path, so a
# finding from an artifact is mapped exactly like a Sigma or IOC hit.
CATALOG = {
    # -- Windows -------------------------------------------------------------
    "Windows.System.Pslist": {
        "platforms": ("windows",),
        "category": "process",
        "description": "Running processes with image path and authenticode/hash detail.",
        "technique_id": "T1057",
        "cost": "low",
        "timeout_seconds": 180,
    },
    "Windows.Network.Netstat": {
        "platforms": ("windows",),
        "category": "network",
        "description": "Active TCP/UDP endpoints with owning process.",
        "technique_id": "T1049",
        "cost": "low",
        "timeout_seconds": 120,
    },
    "Windows.System.Services": {
        "platforms": ("windows",),
        "category": "persistence",
        "description": "Installed services, their binaries and start mode.",
        "technique_id": "T1543.003",
        "cost": "low",
        "timeout_seconds": 180,
    },
    "Windows.System.TaskScheduler": {
        "platforms": ("windows",),
        "category": "persistence",
        "description": "Scheduled task definitions including the command executed.",
        "technique_id": "T1053.005",
        "cost": "medium",
        "timeout_seconds": 300,
    },
    "Windows.Persistence.PermanentWMIEvents": {
        "platforms": ("windows",),
        "category": "persistence",
        "description": "WMI event consumer/filter bindings - a classic fileless foothold.",
        "technique_id": "T1546.003",
        "cost": "medium",
        "timeout_seconds": 300,
    },
    "Windows.Forensics.Prefetch": {
        "platforms": ("windows",),
        "category": "execution",
        "description": "Prefetch execution evidence: what ran, when, and how often.",
        "technique_id": "T1204.002",
        "cost": "medium",
        "timeout_seconds": 300,
    },
    "Windows.Sysinternals.Autoruns": {
        "platforms": ("windows",),
        "category": "persistence",
        "description": "Full autostart extensibility point sweep (downloads Autoruns).",
        "technique_id": "T1547",
        "cost": "high",
        "timeout_seconds": 600,
        "requires_tool": True,
    },

    # -- Linux ---------------------------------------------------------------
    "Linux.Sys.Pslist": {
        "platforms": ("linux",),
        "category": "process",
        "description": "Running processes with exe path, cmdline and owning user.",
        "technique_id": "T1057",
        "cost": "low",
        "timeout_seconds": 180,
    },
    "Linux.Network.Netstat": {
        "platforms": ("linux",),
        "category": "network",
        "description": "Active sockets with owning process.",
        "technique_id": "T1049",
        "cost": "low",
        "timeout_seconds": 120,
    },
    "Linux.Sys.Crontab": {
        "platforms": ("linux",),
        "category": "persistence",
        "description": "System and per-user cron entries.",
        "technique_id": "T1053.003",
        "cost": "low",
        "timeout_seconds": 180,
    },
    "Linux.Sys.SUID": {
        "platforms": ("linux",),
        "category": "privilege",
        "description": "SUID/SGID binaries outside the expected package set.",
        "technique_id": "T1548.001",
        "cost": "medium",
        "timeout_seconds": 600,
    },
    "Linux.Ssh.AuthorizedKeys": {
        "platforms": ("linux",),
        "category": "persistence",
        "description": "authorized_keys entries for every user with a home directory.",
        "technique_id": "T1098.004",
        "cost": "low",
        "timeout_seconds": 180,
    },
}

# Artifacts a "run the standard triage set" request expands to. Deliberately the
# cheap ones: an analyst hitting one button should not stall an endpoint.
DEFAULT_TRIAGE = {
    "windows": ("Windows.System.Pslist", "Windows.Network.Netstat",
                "Windows.System.Services", "Windows.System.TaskScheduler"),
    "linux": ("Linux.Sys.Pslist", "Linux.Network.Netstat", "Linux.Sys.Crontab"),
}

MAX_ARTIFACTS_PER_REQUEST = 6


def is_allowed(name):
    return name in CATALOG


def for_platform(os_type):
    """Catalog entries runnable on ``os_type``, newest-analyst-friendly shape."""
    platform = "windows" if str(os_type).startswith("windows") else "linux"
    out = []
    for name, meta in sorted(CATALOG.items()):
        if platform in meta["platforms"]:
            out.append(dict(meta, name=name, platforms=list(meta["platforms"])))
    return out


def validate(names, os_type=None):
    """Return (accepted, rejected) for a requested artifact list.

    Rejections carry a reason so the analyst is told why rather than being left
    with a silently shorter list.
    """
    accepted, rejected = [], []
    seen = set()
    platform = None
    if os_type is not None:
        platform = "windows" if str(os_type).startswith("windows") else "linux"
    for raw in names or []:
        name = str(raw).strip()
        if name in seen:
            continue
        seen.add(name)
        meta = CATALOG.get(name)
        if meta is None:
            rejected.append({"artifact": name, "reason": "not in the ATOR artifact allow-list"})
        elif platform and platform not in meta["platforms"]:
            rejected.append({"artifact": name,
                             "reason": f"artifact does not run on {platform}"})
        elif len(accepted) >= MAX_ARTIFACTS_PER_REQUEST:
            rejected.append({"artifact": name,
                             "reason": f"more than {MAX_ARTIFACTS_PER_REQUEST} artifacts per request"})
        else:
            accepted.append(name)
    return accepted, rejected


def timeout_for(name):
    return int((CATALOG.get(name) or {}).get("timeout_seconds", 300))


def technique_for(name):
    return (CATALOG.get(name) or {}).get("technique_id")
