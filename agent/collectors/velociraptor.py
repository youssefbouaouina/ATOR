"""Run Velociraptor artifacts locally and normalise their rows.

Velociraptor is used here as a *tool*, not as a deployment: a single standalone
binary sits next to the agent and is invoked per collection. There is no
Velociraptor server, no second enrolment and no extra listening port on the
endpoint - the rows travel home over the ingest path the agent already uses.

This collector is on-demand only. It is NOT part of
COLLECTOR_ORDER_VOLATILITY_FIRST because an artifact sweep costs seconds to
minutes; it runs when the analyst queues a ``velociraptor_collect`` command.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid

from agent.agent import load_config
from agent import velociraptor_catalog as catalog

BINARY_NAMES = ("velociraptor.exe", "velociraptor") if sys.platform.startswith("win") \
    else ("velociraptor",)

# Rows can be large (prefetch, autoruns). Cap what one artifact may return so a
# single sweep cannot blow out the ingest payload or the endpoint's memory.
MAX_ROWS_PER_ARTIFACT = 500
MAX_ROW_BYTES = 8192


def find_binary(cfg=None):
    """Locate the Velociraptor binary, or None.

    Search order: explicit config, environment override, a ``tools/`` directory
    beside the agent install (where the deploy scripts put it), then PATH.
    """
    cfg = cfg if cfg is not None else load_config()
    explicit = cfg.get("velociraptor_path") or os.environ.get("ATOR_VELOCIRAPTOR")
    if explicit and os.path.isfile(explicit):
        return explicit
    agent_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    install_root = os.path.dirname(agent_root)
    for base in (os.path.join(install_root, "tools"), install_root, agent_root):
        for name in BINARY_NAMES:
            candidate = os.path.join(base, name)
            if os.path.isfile(candidate):
                return candidate
    for name in BINARY_NAMES:
        found = shutil.which(name)
        if found:
            return found
    return None


def probe(cfg=None):
    """Report whether this endpoint can run artifacts, and with what version."""
    binary = find_binary(cfg)
    if not binary:
        return {"present": False, "reason": "velociraptor binary not found"}
    try:
        proc = subprocess.run(
            [binary, "version"], capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=30,
        )
        # `velociraptor version` prints a YAML block whose first line is
        # "name: velociraptor" - the useful line is the version one, so prefer
        # that and fall back to the first line only if it is absent.
        lines = [ln.strip() for ln in (proc.stdout or proc.stderr or "").splitlines()
                 if ln.strip()]
        version = next((ln.split(":", 1)[1].strip() for ln in lines
                        if ln.lower().startswith("version:")), None)
        if not version:
            version = lines[0][:120] if lines else None
        return {"present": True, "path": binary, "version": version}
    except Exception as exc:
        return {"present": False, "path": binary, "reason": f"{type(exc).__name__}: {exc}"}


def _first(row, *keys):
    """Case-insensitive lookup of the first present key, including one nesting level.

    Artifact authors are not consistent about column naming (OSPath vs FullPath
    vs Path; Hash.SHA256 vs SHA256), so promoting a value into our own columns
    means checking several spellings rather than assuming one.
    """
    lowered = {str(k).lower(): v for k, v in row.items()}
    for key in keys:
        parts = str(key).lower().split(".")
        value = lowered.get(parts[0])
        for part in parts[1:]:
            if isinstance(value, dict):
                value = {str(k).lower(): v for k, v in value.items()}.get(part)
            else:
                value = None
        if value not in (None, ""):
            return value
    return None


def normalise_row(artifact, row):
    """Promote the fields ATOR correlates on out of a free-form VQL row.

    The whole row is kept verbatim in ``row_json``; the promoted keys exist so
    the IOC correlator and the UI have something indexable to work with. A row
    that promotes nothing is still stored - it is evidence either way.
    """
    if not isinstance(row, dict):
        row = {"value": row}
    sha = _first(row, "sha256", "hash.sha256")
    path = _first(row, "ospath", "fullpath", "path", "exe", "imagepath",
                  "filename", "binary", "command")
    # Real column names observed live: TaskScheduler says TaskName, Prefetch
    # says Executable. Neither is "Name", so both are looked up explicitly.
    name = _first(row, "name", "processname", "taskname", "executable",
                  "servicename", "exe")
    remote = _first(row, "raddr.ip", "remoteaddr", "raddr", "remote_ip", "foreignaddress")
    if isinstance(remote, str) and remote.count(":") == 1:
        remote = remote.rsplit(":", 1)[0]
    pid = _first(row, "pid", "process_id")
    try:
        pid = int(pid) if pid is not None else None
    except (TypeError, ValueError):
        pid = None
    blob = json.dumps(row, default=str)
    if len(blob) > MAX_ROW_BYTES:
        blob = json.dumps({"_truncated": True, "_bytes": len(blob),
                           "preview": blob[:MAX_ROW_BYTES]})
    return {
        "artifact": artifact,
        "row_json": blob,
        "path": str(path)[:512] if path is not None else None,
        "sha256": str(sha).lower()[:64] if sha else None,
        "process_name": str(name)[:256] if name is not None else None,
        "remote_ip": str(remote)[:64] if remote else None,
        "pid": pid,
    }


def _parse_output(artifact, stdout):
    """Decode Velociraptor's --format json output.

    Real output is not one tidy JSON document. An artifact with several sources
    emits several PRETTY-PRINTED arrays concatenated on stdout, so neither
    ``json.loads`` over the whole text nor a line-by-line pass works:

      * whole-text parsing fails on the second document, and
      * line-by-line parsing succeeds only on the lines that happen to be a
        lone scalar, which silently yields a pile of leaf values (a path here,
        a timestamp there) instead of rows.

    So the text is scanned with ``raw_decode``, which consumes one complete JSON
    value at a time regardless of indentation, and only objects are accepted as
    rows. A scalar reaching this point means the parse went wrong, and a wrong
    parse must not masquerade as evidence.
    """
    text = (stdout or "").strip()
    if not text:
        return []
    decoder = json.JSONDecoder()
    documents, idx, length = [], 0, len(text)
    while idx < length:
        while idx < length and text[idx] in " \t\r\n,":
            idx += 1
        if idx >= length:
            break
        try:
            value, end = decoder.raw_decode(text, idx)
        except ValueError:
            # Not the start of a JSON value (a banner or log line): skip to the
            # next line and keep going rather than abandoning the whole sweep.
            nxt = text.find("\n", idx)
            if nxt == -1:
                break
            idx = nxt + 1
            continue
        documents.append(value)
        idx = end

    rows = []
    for doc in documents:
        if isinstance(doc, list):
            rows.extend(doc)
        else:
            rows.append(doc)
    rows = [r for r in rows if isinstance(r, dict)]
    out = [normalise_row(artifact, row) for row in rows[:MAX_ROWS_PER_ARTIFACT]]
    if len(rows) > MAX_ROWS_PER_ARTIFACT:
        out.append(normalise_row(artifact, {
            "_note": "row cap reached",
            "_returned": MAX_ROWS_PER_ARTIFACT,
            "_total": len(rows),
        }))
    return out


def output_dir(cfg=None):
    """Directory raw artifact output is written to before parsing."""
    cfg = cfg if cfg is not None else {}
    base = cfg.get("velociraptor_output_dir") or os.path.join(
        tempfile.gettempdir(), "ator-velociraptor")
    os.makedirs(base, exist_ok=True)
    return base


def run_artifact(name, cfg=None, binary=None):
    """Collect one allow-listed artifact. Returns normalised rows.

    Results are written to a FILE and read back, rather than captured from a
    pipe. Velociraptor's own logging goes to stderr, which is captured
    separately, so the results file holds nothing but artifact output - no
    banner, no progress line, nothing to confuse the parser.

    The file is deleted once it parses. It is deliberately KEPT when parsing
    produces nothing from non-empty output, and its path is returned in the
    error: that is the signature of the parser meeting a shape it does not
    understand, and the raw evidence of it must survive to be looked at. The
    first version of this collector silently stored 285 unusable rows because
    a bad parse had no way to announce itself.

    An artifact that fails produces a single ``_error`` row rather than an
    exception: one unavailable artifact must not lose the others in the sweep.
    """
    if not catalog.is_allowed(name):
        return [{"artifact": name, "_error": "artifact not in allow-list"}]
    cfg = cfg if cfg is not None else load_config()
    binary = binary or find_binary(cfg)
    if not binary:
        return [{"artifact": name, "_error": "velociraptor binary not found"}]

    timeout = catalog.timeout_for(name)
    path = os.path.join(output_dir(cfg), f"{name}-{uuid.uuid4().hex}.json")
    cmd = [binary, "--nobanner", "artifacts", "collect", name, "--format", "json"]
    try:
        with open(path, "wb") as sink:
            proc = subprocess.run(cmd, stdout=sink, stderr=subprocess.PIPE,
                                  timeout=timeout)
    except subprocess.TimeoutExpired:
        _discard(path)
        return [{"artifact": name, "_error": "timed out after %ds" % timeout}]
    except Exception as exc:
        _discard(path)
        return [{"artifact": name, "_error": f"{type(exc).__name__}: {exc}"}]

    stderr = (proc.stderr or b"").decode("utf-8", "replace").strip()
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
    except OSError as exc:
        _discard(path)
        return [{"artifact": name, "_error": f"could not read results file: {exc}"}]

    rows = _parse_output(name, raw)
    if rows:
        _discard(path)
        return rows

    if proc.returncode != 0:
        _discard(path)
        tail = stderr.splitlines()[-1][:300] if stderr else "no output"
        return [{"artifact": name, "_error": f"exit {proc.returncode}: {tail}"}]
    if raw.strip():
        # Output arrived but nothing could be read from it. Keep the file.
        return [{"artifact": name,
                 "_error": f"produced {len(raw)} bytes but no rows could be parsed; "
                           f"raw output kept at {path}"}]
    _discard(path)
    return []                      # ran cleanly, genuinely found nothing


def _discard(path):
    try:
        os.remove(path)
    except OSError:
        pass


def collect(artifacts=None, cfg=None):
    """Run a set of artifacts. Called by the ``velociraptor_collect`` command.

    With no explicit list this returns nothing rather than guessing: a sweep is
    expensive and is only ever run because an analyst asked for it.
    """
    cfg = cfg if cfg is not None else load_config()
    names, rejected = catalog.validate(artifacts or [], os_type=os_type())
    out = [{"artifact": r["artifact"], "_error": r["reason"]} for r in rejected]
    if not names:
        return out
    binary = find_binary(cfg)
    for name in names:
        out += run_artifact(name, cfg=cfg, binary=binary)
    return out


def os_type():
    return "windows" if sys.platform.startswith("win") else "linux"
