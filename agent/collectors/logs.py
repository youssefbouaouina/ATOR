import glob
import json
import os
import sys

from agent.agent import load_config


def collect():
    if sys.platform.startswith("win"):
        return _windows()
    return _linux()


def _windows():
    cfg = load_config()
    cap = int(cfg.get("max_events_per_source", 300))
    log_dir = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "winevt", "Logs")
    sources = [
        ("sysmon", "Microsoft-Windows-Sysmon%4Operational.evtx", "Microsoft-Windows-Sysmon/Operational"),
        ("security", "Security.evtx", "Security"),
        ("system", "System.evtx", "System"),
        ("application", "Application.evtx", "Application"),
    ]
    out = []
    for source_name, filename, logname in sources:
        path = os.path.join(log_dir, filename)
        if not os.path.exists(path):
            continue
        parsed = _parse_evtx(path, source_name, cap)
        denied = any(isinstance(e, dict) and str(e.get("_error", "")).startswith("access_denied")
                     for e in parsed)
        if not parsed or (denied and len(parsed) == 1):
            fallback = _powershell_events(logname, cap, source_name)
            if fallback:
                out += fallback
                continue
        out += parsed
    return out


def _powershell_events(logname, cap, source_name):
    import subprocess
    try:
        script = (
            f"Get-WinEvent -LogName '{logname}' -MaxEvents {cap} -ErrorAction Stop | "
            "Select-Object TimeCreated, Id, ProviderName, "
            "@{n='Msg';e={$_.Message -replace \"`r`n\",' ' }} | ConvertTo-Json -Compress"
        )
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", script],
            capture_output=True, text=True, timeout=60,
        )
        if proc.returncode != 0:
            return [{"_error": f"ps:{proc.stderr.strip()[:120]}"}]
        raw = proc.stdout.strip() or "[]"
        data = json.loads(raw) if raw.startswith("[") else [json.loads(raw)] if raw.startswith("{") else []
    except Exception as exc:
        return [{"_error": f"{type(exc).__name__}:{exc}"}]
    out = []
    for e in data[:cap]:
        time_utc = None
        try:
            from datetime import datetime, timezone
            dt = datetime.fromisoformat(str(e.get("TimeCreated", "")).replace("Z", "+00:00"))
            time_utc = dt.astimezone(timezone.utc).isoformat(timespec="seconds")
        except ValueError:
            pass
        out.append({
            "source": source_name,
            "event_id": e.get("Id"),
            "event_time_utc": time_utc,
            "provider": e.get("ProviderName"),
            "computer": get_hostname(),
            "payload_json": json.dumps({"message": str(e.get("Msg") or "")[:1500]}),
        })
    return out


def get_hostname():
    import socket
    return socket.gethostname()


def _parse_evtx(path, source_name, cap):
    out = []
    try:
        import Evtx.Evtx as evtx_mod
        with evtx_mod.Evtx(path) as log:
            records = []
            for record in log.records():
                try:
                    xml = record.xml()
                except Exception:
                    continue
                records.append(xml)
                if len(records) > cap * 3:
                    records = records[-cap:]
            for xml in records[-cap:]:
                parsed = _evtx_xml_to_dict(xml, source_name, os.path.basename(path))
                if parsed:
                    out.append(parsed)
    except (PermissionError, OSError):
        out.append({"_error": f"access_denied:{os.path.basename(path)}"})
    except Exception as exc:
        out.append({"_error": f"{type(exc).__name__}:{exc}"})
    return out


def _evtx_xml_to_dict(xml, source_name, filename):
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(xml)
        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
        sys_node = root.find("e:System", ns)
        event_id = None
        time_utc = None
        provider = None
        computer = None
        payload = {"xml": xml[:4000], "log": filename}
        if sys_node is not None:
            eid_node = sys_node.find("e:EventID", ns)
            if eid_node is not None:
                try:
                    event_id = int(eid_node.text)
                except (TypeError, ValueError):
                    event_id = None
            t_node = sys_node.find("e:TimeCreated", ns)
            if t_node is not None:
                time_utc = t_node.attrib.get("SystemTime")
            p_node = sys_node.find("e:Provider", ns)
            if p_node is not None:
                provider = p_node.attrib.get("Name")
            c_node = sys_node.find("e:Computer", ns)
            if c_node is not None:
                computer = c_node.text
        data_nodes = root.findall(".//e:Event_Data/e:Data", ns)
        fields = {}
        for d in data_nodes[:20]:
            fields[d.attrib.get("Name", "data")] = d.text
        payload["fields"] = fields
        return {
            "source": source_name,
            "event_id": event_id,
            "event_time_utc": time_utc,
            "provider": provider,
            "computer": computer,
            "payload_json": _dumps(payload),
        }
    except Exception:
        return None


def _dumps(obj):
    import json
    return json.dumps(obj, default=str)


def _linux():
    cfg = load_config()
    cap = int(cfg.get("max_events_per_source", 300))
    out = []
    for source_name, path in (("auth", "/var/log/auth.log"), ("syslog", "/var/log/syslog")):
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()[-cap:]
            for line in lines:
                ts, rest = _split_syslog_line(line)
                out.append({
                    "source": source_name,
                    "event_id": None,
                    "event_time_utc": ts,
                    "provider": None,
                    "computer": rest.split(" ", 1)[0] if rest else None,
                    "payload_json": _dumps({"message": line.strip()[:2000], "log": path}),
                })
        except OSError as exc:
            out.append({"_error": f"{type(exc).__name__}:{exc}"})
    if not out:
        out = _journalctl(cap)
    return out


def _split_syslog_line(line):
    parts = line.split(" ", 2)
    if len(parts) >= 3:
        from datetime import datetime, timezone
        raw_ts = parts[0]
        try:
            dt = datetime.strptime(f"{datetime.now(timezone.utc).year} {raw_ts}", "%Y %b %d %H:%M:%S")
            return dt.replace(tzinfo=timezone.utc).isoformat(timespec="seconds"), parts[2]
        except ValueError:
            pass
        return None, line
    return None, line


def _journalctl(cap):
    import subprocess
    out = []
    try:
        proc = subprocess.run(
            ["journalctl", "-n", str(cap), "--no-pager", "-o", "short-iso"],
            capture_output=True, text=True, timeout=30,
        )
        for line in proc.stdout.splitlines():
            ts = None
            msg = line
            if " " in line and line[:2].isdigit() or line[:4].isdigit():
                head = line.split(" ", 1)
                if len(head) == 2 and "T" in head[0]:
                    ts = head[0]
                    msg = head[1]
            out.append({
                "source": "journald",
                "event_id": None,
                "event_time_utc": ts,
                "provider": None,
                "computer": None,
                "payload_json": _dumps({"message": msg[:2000]}),
            })
    except Exception as exc:
        out.append({"_error": f"{type(exc).__name__}:{exc}"})
    return out
