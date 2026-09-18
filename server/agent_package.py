"""Builds the endpoint agent package served to bootstrap scripts.

The package is generated from the live ``agent/`` source tree (plus the YARA
rules used by the local file-triage scan) so endpoints never receive a stale
agent. Windows bootstraps fetch the .zip, Linux bootstraps the .tar.gz; both
share the same layout:

    agent/__init__.py, agent/agent.py, agent/collectors/*, agent/requirements.txt
    rules/malware/*.yar
"""
import io
import os
import tarfile
import threading
import time
import zipfile

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS_DIR = os.path.join(PROJECT_ROOT, "scripts")

# (source dir, archive prefix)
_SOURCES = [
    (os.path.join(PROJECT_ROOT, "agent"), "agent"),
    (os.path.join(PROJECT_ROOT, "rules", "malware"), "rules/malware"),
]
# Never ship per-host state: config.json holds this machine's credentials.
_EXCLUDED_NAMES = {"__pycache__", "config.json", "spool"}
_EXCLUDED_SUFFIXES = (".pyc", ".pyo")

BOOTSTRAP_SCRIPTS = {
    "bootstrap_endpoint.ps1": "text/plain; charset=utf-8",
    "bootstrap_endpoint.sh": "text/x-shellscript; charset=utf-8",
}

_cache = {}
_lock = threading.Lock()


def _package_files():
    files = []
    for src_dir, prefix in _SOURCES:
        if not os.path.isdir(src_dir):
            continue
        for root, dirs, names in os.walk(src_dir):
            dirs[:] = sorted(d for d in dirs if d not in _EXCLUDED_NAMES)
            for name in sorted(names):
                if name in _EXCLUDED_NAMES or name.endswith(_EXCLUDED_SUFFIXES):
                    continue
                path = os.path.join(root, name)
                rel = os.path.relpath(path, src_dir).replace(os.sep, "/")
                files.append((path, f"{prefix}/{rel}"))
    return files


def _signature(files):
    return tuple((arc, os.path.getmtime(path), os.path.getsize(path)) for path, arc in files)


def _read_source(path, arcname):
    with open(path, "rb") as fh:
        data = fh.read()
    if arcname.endswith((".py", ".txt", ".yar", ".yml")):
        # Normalise line endings so the Linux package never carries CRLF.
        data = data.replace(b"\r\n", b"\n")
    return data


def _build_zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, arc in files:
            info = zipfile.ZipInfo(arc, date_time=time.localtime(os.path.getmtime(path))[:6])
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, _read_source(path, arc))
    return buf.getvalue()


def _build_targz(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        seen_dirs = set()
        for path, arc in files:
            parts = arc.split("/")[:-1]
            for i in range(1, len(parts) + 1):
                d = "/".join(parts[:i])
                if d not in seen_dirs:
                    seen_dirs.add(d)
                    dinfo = tarfile.TarInfo(d)
                    dinfo.type = tarfile.DIRTYPE
                    dinfo.mode = 0o755
                    dinfo.mtime = int(os.path.getmtime(path))
                    tf.addfile(dinfo)
            data = _read_source(path, arc)
            info = tarfile.TarInfo(arc)
            info.size = len(data)
            info.mode = 0o644
            info.mtime = int(os.path.getmtime(path))
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def build(fmt):
    """Return the package bytes for ``fmt`` ('zip' or 'tar.gz'), rebuilding
    only when an agent source file changed."""
    builders = {"zip": _build_zip, "tar.gz": _build_targz}
    if fmt not in builders:
        raise ValueError(f"unsupported package format: {fmt}")
    files = _package_files()
    sig = _signature(files)
    with _lock:
        cached = _cache.get(fmt)
        if cached and cached[0] == sig:
            return cached[1]
        data = builders[fmt](files)
        _cache[fmt] = (sig, data)
        return data


def bootstrap_script(name):
    """Return the bootstrap script body (LF line endings for the shell script)."""
    if name not in BOOTSTRAP_SCRIPTS:
        raise KeyError(name)
    with open(os.path.join(SCRIPTS_DIR, name), "rb") as fh:
        data = fh.read()
    if name.endswith(".sh"):
        data = data.replace(b"\r\n", b"\n")
    return data
