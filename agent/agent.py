import hashlib
import json
import os
import sys
import uuid

AGENT_VERSION = "1.0.0"

DEFAULT_CONFIG = {
    "server_url": "http://127.0.0.1:8000",
    "api_key": "",
    "client_id": "",
    "spool_dir": "spool",
    "max_events_per_source": 300,
    "max_files": 200,
    "max_file_bytes": 5242880,
    "enable_local_yara": True,
    "collection_interval_seconds": 60,
    "resource_interval_seconds": 15,
    "enable_gpu_probe": True,
    "telemetry_mode": "full",          # "full" | "lightweight"
    "lightweight_interval_seconds": 30,
    # Absolute path to a standalone velociraptor binary. Empty means "look in
    # the install's tools/ directory and then PATH" (see collectors.velociraptor).
    "velociraptor_path": "",
}


_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.environ.get("ATOR_AGENT_CONFIG", os.path.join(_BASE_DIR, "config.json"))


def load_config(config_path=None):
    path = config_path or CONFIG_PATH
    cfg = dict(DEFAULT_CONFIG)
    if os.path.exists(path):
        # utf-8-sig: config files written by Windows PowerShell carry a BOM.
        with open(path, "r", encoding="utf-8-sig") as fh:
            cfg.update(json.load(fh))
    env_url = os.environ.get("ATOR_SERVER_URL")
    if env_url:
        cfg["server_url"] = env_url
    return cfg


def save_config(cfg, config_path=None):
    path = config_path or CONFIG_PATH
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=2)
    if not sys.platform.startswith("win"):
        # the config holds the host API key - keep it readable by root only
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


# -- Server auto-discovery ----------------------------------------------------
# If the configured server_url becomes unreachable (e.g. the server's LAN IP
# changed via DHCP), the agent scans the local subnet for the ATOR DFIR server
# on port 8000 and updates its config so telemetry keeps flowing.

DISCOVERY_PORT = 8000
_last_discover_success = 0.0
_last_discover_attempt = 0.0
_DISCOVERY_RETRY_SECONDS = 120


def _probe_health(url, timeout=2.0):
    """Return True if <url>/health answers 200 with a JSON status payload."""
    try:
        import requests
        resp = requests.get(url.rstrip("/") + "/health", timeout=timeout)
        if resp.status_code != 200:
            return False
        try:
            body = resp.json()
            return body.get("status") == "ok"
        except Exception:
            return False
    except Exception:
        return False


def _local_subnets():
    """Derive candidate /24 scan ranges from this machine's IPv4 addresses."""
    import socket
    subnets = set()
    candidates = []
    # default route interface
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("10.255.255.255", 1))  # no packets actually sent
            candidates.append(s.getsockname()[0])
        finally:
            s.close()
    except Exception:
        pass
    # all non-loopback, non-link-local IPv4 addresses
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith("127.") and not ip.startswith("169.254."):
                candidates.append(ip)
    except Exception:
        pass
    for ip in candidates:
        parts = ip.split(".")
        if len(parts) == 4:
            subnets.add(".".join(parts[:3]))
    return sorted(subnets)


def discover_server_url(cfg, timeout_per_ip=0.5, max_workers=48):
    """Scan the local subnets for the ATOR DFIR server. Returns a URL string
    (e.g. 'http://192.168.1.12:8000') or None if nothing responds with a
    valid /health payload."""
    import socket
    from concurrent.futures import ThreadPoolExecutor

    subnets = _local_subnets()
    if not subnets:
        return None
    host_ips = set()
    for sub in subnets:
        for i in range(1, 255):
            host_ips.add(f"{sub}.{i}")

    open_ports = set()

    def scan(ip):
        try:
            with socket.create_connection((ip, DISCOVERY_PORT), timeout=timeout_per_ip):
                open_ports.add(ip)
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        list(ex.map(scan, sorted(host_ips)))

    for ip in sorted(open_ports):
        url = f"http://{ip}:{DISCOVERY_PORT}"
        if _probe_health(url):
            return url
    return None


def ensure_server_url(cfg, force=False):
    """Return a working server_url. Respects an explicit ATOR_SERVER_URL env
    override. If the configured URL is unreachable, attempts subnet discovery
    (throttled) and persists the discovered URL into the config file."""
    global _last_discover_success, _last_discover_attempt
    import time

    if os.environ.get("ATOR_SERVER_URL"):
        return cfg["server_url"]
    if _probe_health(cfg.get("server_url", ""), timeout=2.0):
        _last_discover_success = time.time()
        return cfg["server_url"]

    now = time.time()
    if not force and now - _last_discover_attempt < _DISCOVERY_RETRY_SECONDS:
        return cfg["server_url"]
    _last_discover_attempt = now

    try:
        found = discover_server_url(cfg)
    except Exception:
        found = None
    if found and found != cfg.get("server_url"):
        cfg["server_url"] = found
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8-sig") as fh:
                data = json.load(fh)
            data["server_url"] = found
            save_config(data)
        except Exception:
            pass
        _last_discover_success = time.time()
        print(f"[auto-detect] server URL updated to {found}", flush=True)
    elif found:
        _last_discover_success = time.time()
    return cfg.get("server_url")


def _send_try(cfg, sender, *args):
    """Run a send; on failure trigger (throttled) server auto-discovery so the
    next attempt uses a fresh URL. Returns the sender result or re-raises."""
    try:
        result = sender(*args)
    except Exception:
        ensure_server_url(cfg)
        raise
    return result


def get_hostname():
    import socket
    return socket.gethostname()


def get_os_type():
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform.startswith("linux"):
        return "linux"
    return sys.platform


COLLECTOR_ORDER_VOLATILITY_FIRST = [
    "network",
    "processes",
    "persistence",
    "logs",
    "files_triage",
    "containers",
    "resources",
]


try:
    from server.security import sha256_bytes
except ImportError:
    def sha256_bytes(data):
        return hashlib.sha256(data).hexdigest()


def build_manifest(collection_id, started_at, finished_at, artifacts, extra=None):
    entries = []
    order = []
    # The routine collectors first, in volatility order; then any on-demand
    # collector present in this payload (velociraptor) so its rows are covered
    # by the same per-set hash and manifest hash as everything else.
    names = list(COLLECTOR_ORDER_VOLATILITY_FIRST)
    names += [n for n in sorted(artifacts) if n not in names]
    for name in names:
        items = artifacts.get(name) or []
        blob = json.dumps(items, sort_keys=True, default=str).encode()
        entries.append({
            "collector": name,
            "count": len(items),
            "sha256": sha256_bytes(blob),
        })
        order.append(name)
    manifest = {
        "collection_id": collection_id,
        "hostname": get_hostname(),
        "os_type": get_os_type(),
        "agent_version": AGENT_VERSION,
        "started_at_utc": started_at,
        "finished_at_utc": finished_at,
        "collector_order": order,
        "artifacts": entries,
    }
    # Merged BEFORE hashing: anything a caller adds afterwards would sit outside
    # manifest_sha256 and break verification at the server.
    if extra:
        manifest.update(extra)
    manifest["manifest_sha256"] = sha256_bytes(
        json.dumps({k: v for k, v in manifest.items()}, sort_keys=True, default=str).encode()
    )
    return manifest


def dispatch(name):
    from agent.collectors import registry
    func = registry.get(name)
    if func is None:
        return []
    return func() or []


def run_collection():
    from datetime import datetime, timezone
    import uuid
    started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    collection_id = str(uuid.uuid4())
    artifacts = {}
    for name in COLLECTOR_ORDER_VOLATILITY_FIRST:
        try:
            artifacts[name] = dispatch(name)
        except Exception as exc:
            artifacts[name] = [{"_error": f"{type(exc).__name__}: {exc}"}]
    finished = datetime.now(timezone.utc).isoformat(timespec="seconds")
    manifest = build_manifest(collection_id, started, finished, artifacts)
    return {"manifest": manifest, "artifacts": artifacts}


def run_velociraptor_collection(artifact_names):
    """Run an on-demand Velociraptor artifact sweep as its own collection.

    It gets a collection_id and manifest of its own rather than riding along
    with the routine collection: the rows are evidence, so they need the same
    integrity record, and an analyst-requested sweep should be attributable to
    the moment it was asked for.
    """
    from datetime import datetime, timezone

    from agent.collectors import velociraptor

    started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    collection_id = str(uuid.uuid4())
    try:
        rows = velociraptor.collect(artifact_names)
    except Exception as exc:
        rows = [{"_error": f"{type(exc).__name__}: {exc}"}]
    finished = datetime.now(timezone.utc).isoformat(timespec="seconds")
    artifacts = {"velociraptor": rows}
    manifest = build_manifest(
        collection_id, started, finished, artifacts,
        extra={"trigger": "velociraptor_collect",
               "requested_artifacts": list(artifact_names or [])},
    )
    return {"manifest": manifest, "artifacts": artifacts}


def send_payload(cfg, payload):
    import requests
    url = cfg["server_url"].rstrip("/") + "/api/v1/ingest"
    headers = {
        "Authorization": "Bearer " + cfg.get("api_key", ""),
        "X-Client-ID": cfg.get("client_id", ""),
        "Content-Type": "application/json",
    }
    resp = requests.post(url, json=payload, headers=headers, timeout=30)
    resp.raise_for_status()
    return resp


def _headers(cfg):
    return {
        "Authorization": "Bearer " + cfg.get("api_key", ""),
        "X-Client-ID": cfg.get("client_id", ""),
        "Content-Type": "application/json",
    }


def send_resources(cfg, samples):
    """Lightweight telemetry POST to the dedicated resources endpoint."""
    import requests
    url = cfg["server_url"].rstrip("/") + "/api/v1/ingest/resources"
    resp = requests.post(
        url, json={"samples": samples}, headers=_headers(cfg), timeout=15,
    )
    resp.raise_for_status()
    return resp


def send_agent_self(cfg, samples):
    """Lightweight self-monitoring telemetry POST to dedicated agent-self endpoint."""
    import requests
    url = cfg["server_url"].rstrip("/") + "/api/v1/agent-self/ingest"
    resp = requests.post(
        url, json={"samples": samples}, headers=_headers(cfg), timeout=15,
    )
    resp.raise_for_status()
    return resp


def spool_payload(cfg, payload, target="artifacts"):
    os.makedirs(cfg["spool_dir"], exist_ok=True)
    cid = (payload.get("manifest") or {}).get("collection_id") or str(uuid.uuid4())
    path = os.path.join(cfg["spool_dir"], f"{cid}.json")
    wrapper = {"target": target}
    if target in ("resources", "agent_self"):
        wrapper["payload"] = payload
    else:
        # legacy shape: bare ingest payload at top level
        wrapper.update(payload)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(wrapper, fh)
    return path


def flush_spool(cfg):
    sent = 0
    if not os.path.isdir(cfg["spool_dir"]):
        return sent
    # if the server stopped answering, try to rediscover its LAN IP once
    for fname in sorted(os.listdir(cfg["spool_dir"])):
        if not fname.endswith(".json"):
            continue
        path = os.path.join(cfg["spool_dir"], fname)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            target = data.get("target")
            if target == "resources":
                _send_try(cfg, send_resources, cfg, data["payload"]["samples"])
            elif target == "agent_self":
                _send_try(cfg, send_agent_self, cfg, data["payload"]["samples"])
            else:
                # legacy/unwrapped files go to the artifact ingest endpoint
                _send_try(cfg, send_payload, cfg, {k: v for k, v in data.items() if k != "target"})
            os.remove(path)
            sent += 1
        except Exception:
            continue
    return sent


class EnrollmentError(Exception):
    def __init__(self, message, status_code=None):
        super().__init__(message)
        self.status_code = status_code


def enroll_with_token(cfg, enrollment_token):
    """Enroll using an enrollment token issued after admin approval."""
    import requests
    url = cfg["server_url"].rstrip("/") + "/api/v1/enroll/enroll"
    body = {"enrollment_token": enrollment_token, "agent_version": AGENT_VERSION}
    resp = requests.post(url, json=body, timeout=30)
    if resp.status_code >= 400:
        try:
            detail = resp.json().get("detail")
        except ValueError:
            detail = resp.text[:200]
        raise EnrollmentError(f"enrollment rejected by server (HTTP {resp.status_code}): {detail}",
                              resp.status_code)
    data = resp.json()
    cfg["api_key"] = data["api_key"]
    cfg["client_id"] = data["client_id"]
    save_config(cfg)
    return data


def enroll(cfg):
    import requests
    url = cfg["server_url"].rstrip("/") + "/api/v1/enroll"
    body = {
        "hostname": get_hostname(),
        "os_type": get_os_type(),
        "docker_engine_flag": 1 if has_docker_engine() else 0,
        "agent_version": AGENT_VERSION,
    }
    resp = requests.post(url, json=body, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    cfg["api_key"] = data["api_key"]
    cfg["client_id"] = data["client_id"]
    save_config(cfg)
    return data


def has_docker_engine():
    import shutil
    import subprocess
    sock_paths = ["/var/run/docker.sock"]
    if any(os.path.exists(p) for p in sock_paths):
        return True
    if shutil.which("docker"):
        try:
            probe = subprocess.run(
                ["docker", "version", "--format", "{{.Server.Version}}"],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15,
            )
            return probe.returncode == 0
        except Exception:
            return False
    return False


def run_resource_sample(cfg, collector_name="resources"):
    """Collect a single resource sample and send it."""
    sample = dispatch(collector_name)
    if not sample:
        return False
    try:
        _send_try(cfg, send_resources, cfg, sample)
        return True
    except Exception:
        spool_payload(cfg, {"samples": sample}, target="resources")
        return False


def run_lightweight_sample(cfg):
    """Collect a lightweight agent self-monitoring sample."""
    sample = dispatch("agent_self")
    if not sample:
        return False
    try:
        _send_try(cfg, send_agent_self, cfg, sample)
        return True
    except Exception:
        spool_payload(cfg, {"samples": sample}, target="agent_self")
        return False


_velo_probe_cache = {"checked_at": 0.0, "value": None}
_VELO_PROBE_TTL_SECONDS = 900


def velociraptor_status(cfg=None, ttl=_VELO_PROBE_TTL_SECONDS):
    """Cached "can this endpoint run artifacts?" probe.

    Cached because the probe execs the binary and the heartbeat runs every ~20s;
    re-checking that often would cost more than the feature is worth. The TTL
    still lets an operator drop the binary in and have it noticed without
    restarting the agent.
    """
    import time
    now = time.time()
    if _velo_probe_cache["value"] is not None and now - _velo_probe_cache["checked_at"] < ttl:
        return _velo_probe_cache["value"]
    try:
        from agent.collectors import velociraptor
        value = velociraptor.probe(cfg)
    except Exception as exc:
        value = {"present": False, "reason": f"{type(exc).__name__}: {exc}"}
    _velo_probe_cache.update({"checked_at": now, "value": value})
    return value


def heartbeat(cfg, state=None):
    """Send a heartbeat and return the server's desired state + any queued commands."""
    import requests
    url = cfg["server_url"].rstrip("/") + "/api/v1/agent/heartbeat"
    body = {
        "state": state or "running",
        "agent_version": AGENT_VERSION,
        "telemetry_mode": cfg.get("telemetry_mode", "full"),
        "spool_count": _spool_count(cfg),
        "velociraptor": velociraptor_status(cfg),
    }
    resp = requests.post(
        url, json=body, timeout=15,
        headers={"Authorization": "Bearer " + cfg["api_key"],
                 "X-Client-ID": cfg["client_id"]},
    )
    resp.raise_for_status()
    return resp.json()


def _spool_count(cfg):
    spool = cfg.get("spool_dir", "spool")
    if not os.path.isdir(spool):
        return 0
    try:
        return len([f for f in os.listdir(spool) if f.endswith(".json")])
    except OSError:
        return 0


def _command_artifacts(cmd):
    """Artifact names carried by a queued command.

    The server sends them as a JSON object in ``args``. Anything malformed
    yields an empty list, which the collector then rejects - the agent never
    guesses what it was asked to run.
    """
    args = cmd.get("args")
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except (json.JSONDecodeError, TypeError):
            return []
    if not isinstance(args, dict):
        return []
    names = args.get("artifacts")
    return [str(n) for n in names] if isinstance(names, list) else []


def execute_commands(cfg, commands):
    """Run any commands the server queued for us (manual collect / scan kicks).

    The agent cannot be remotely controlled beyond this allow-list, and every
    outcome is reported back so the dashboard shows what happened.
    """
    import requests
    results = []
    for cmd in commands:
        cid = cmd.get("id")
        action = cmd.get("command")
        detail = {"action": action}
        status = "done"
        try:
            if action == "collect_now":
                payload = run_collection()
                try:
                    _send_try(cfg, send_payload, cfg, payload)
                    detail["delivery"] = "sent"
                except Exception as exc:
                    spool_payload(cfg, payload)
                    detail["delivery"] = "spooled"
                    detail["reason"] = str(exc)
            elif action == "velociraptor_collect":
                requested = _command_artifacts(cmd)
                payload = run_velociraptor_collection(requested)
                rows = payload["artifacts"]["velociraptor"]
                detail["artifacts"] = requested
                detail["rows"] = len([r for r in rows if "_error" not in r])
                failures = [r for r in rows if "_error" in r]
                if failures:
                    detail["failed"] = [{"artifact": r.get("artifact"), "error": r["_error"]}
                                        for r in failures][:10]
                try:
                    _send_try(cfg, send_payload, cfg, payload)
                    detail["delivery"] = "sent"
                except Exception as exc:
                    spool_payload(cfg, payload)
                    detail["delivery"] = "spooled"
                    detail["reason"] = str(exc)
                # Every requested artifact failing is a failed command, not a
                # quiet success with zero rows - the analyst needs to see that.
                if failures and not detail["rows"]:
                    status = "failed"
            elif action == "detect_now":
                # Detection runs server-side; the fresh collection above is what
                # the engine needs, so acknowledge and let the server scan.
                detail["note"] = "server-side scan - engine runs after collection"
            else:
                detail["error"] = "unknown command"
                status = "failed"
        except Exception as exc:
            status = "failed"
            detail["error"] = str(exc)
        try:
            requests.post(
                cfg["server_url"].rstrip("/") + f"/api/v1/agent/commands/{cid}/result",
                json={"status": status, "detail": detail}, timeout=15,
                headers={"Authorization": "Bearer " + cfg["api_key"],
                         "X-Client-ID": cfg["client_id"]},
            )
        except Exception:
            pass
        results.append((cid, status))
    return results


def main():
    import time
    cfg = load_config()

    # Handle --server argument if provided on command line
    for i, arg in enumerate(sys.argv):
        if arg.startswith("--server="):
            cfg["server_url"] = arg.split("=", 1)[1]
        elif arg == "--server" and i + 1 < len(sys.argv):
            cfg["server_url"] = sys.argv[i + 1]

    # Handle --token argument for enrollment (supports --token=<token> or --token <token>)
    token_arg = next((arg for arg in sys.argv if arg.startswith("--token")), None)
    if token_arg:
        if "=" in token_arg:
            enrollment_token = token_arg.split("=", 1)[1]
        else:
            try:
                token_idx = sys.argv.index(token_arg)
                enrollment_token = sys.argv[token_idx + 1]
            except IndexError:
                print("Error: --token requires a token value", file=sys.stderr)
                return 1
        try:
            data = enroll_with_token(cfg, enrollment_token)
        except EnrollmentError as exc:
            # Re-running a bootstrap reuses its (already consumed) token: that
            # is fine as long as the credentials saved last time still work.
            if exc.status_code == 409 and cfg.get("api_key") and cfg.get("client_id"):
                try:
                    heartbeat(cfg)
                    print(json.dumps({"status": "already_enrolled", "client_id": cfg["client_id"]}))
                    return 0
                except Exception:
                    pass
            print(f"Error: {exc}", file=sys.stderr)
            return 2
        except Exception as exc:
            print(f"Error: cannot reach server {cfg['server_url']}: {exc}", file=sys.stderr)
            return 3
        print(json.dumps({k: v for k, v in data.items() if k != "api_key"}, indent=2))
        print(f"Credentials saved to {CONFIG_PATH}")
        return 0

    if len(sys.argv) > 1 and sys.argv[1] == "enroll":
        print(json.dumps(enroll(cfg), indent=2))
        return 0
    if len(sys.argv) > 1 and sys.argv[1] == "once":
        flush_spool(cfg)
        payload = run_collection()
        try:
            send_payload(cfg, payload)
            print(json.dumps({"status": "sent", "collection_id": payload["manifest"]["collection_id"]}))
        except Exception as exc:
            spool_payload(cfg, payload)
            print(json.dumps({"status": "spooled", "reason": str(exc)}))
        return 0
    if len(sys.argv) > 1 and sys.argv[1] == "loop":
        # resolve a working server URL up front (auto-discovers after IP change)
        try:
            ensure_server_url(cfg, force=True)
        except Exception:
            pass
        telemetry_mode = cfg.get("telemetry_mode", "full")
        interval = max(5, int(cfg.get("collection_interval_seconds", 60)))
        r_interval = max(5, int(cfg.get("resource_interval_seconds", 15)))
        lw_interval = max(5, int(cfg.get("lightweight_interval_seconds", 30)))
        hb_interval = max(5, int(os.environ.get("ATOR_AGENT_HEARTBEAT_SECONDS", 20)))
        full_due = time.time()
        res_due = time.time()
        lw_due = time.time()
        hb_due = time.time()
        agent_state = "running"
        while True:
            now = time.time()
            # flush any spooled items first
            flush_spool(cfg)
            did_work = False
            # Heartbeat/control channel: report liveness, learn whether the
            # analyst paused us, and pick up queued commands.
            if hb_due <= now:
                try:
                    hb = heartbeat(cfg, state=agent_state)
                    desired = hb.get("desired_state") or "running"
                    if desired != agent_state:
                        print(f"[control] desired_state={desired}", flush=True)
                        agent_state = desired
                    queued = hb.get("commands") or []
                    if queued:
                        execute_commands(cfg, queued)
                except Exception:
                    ensure_server_url(cfg)
                hb_due = now + hb_interval
                did_work = True
            # Paused agents keep their control channel alive but stop collecting.
            if agent_state != "running":
                wait = max(0.5, min(hb_due - time.time(), 30))
                time.sleep(wait)
                continue
            # Agent-impact (self) samples run in BOTH modes: they are the
            # lightweight per-process snapshot (agent_cpu_pct, agent_mem_mb...)
            # that powers the "Agent Impact" telemetry view.
            if lw_due <= now:
                run_lightweight_sample(cfg)
                lw_due = now + lw_interval
                did_work = True
            # System-wide resource samples only in full mode.
            if telemetry_mode != "lightweight" and res_due <= now:
                run_resource_sample(cfg)
                res_due = now + r_interval
                did_work = True
            if full_due <= now:
                payload = run_collection()
                try:
                    _send_try(cfg, send_payload, cfg, payload)
                    status = "sent"
                except Exception:
                    spool_payload(cfg, payload)
                    status = "spooled"
                print(f"[{payload['manifest']['finished_at_utc']}] {status}", flush=True)
                full_due = now + interval
                did_work = True
            if not did_work:
                due_options = [full_due, lw_due, hb_due]
                if telemetry_mode != "lightweight":
                    due_options.append(res_due)
                next_due = min(due_options)
                wait = next_due - now
                time.sleep(max(0.5, min(wait, 30)))
        return 0
    print("usage: python -m agent.agent [enroll|once|loop] [--token=<token>] [--server=<url>]")
    return 1


if __name__ == "__main__":
    sys.exit(main())
