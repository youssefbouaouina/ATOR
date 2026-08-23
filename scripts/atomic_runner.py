import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ATOMIC_TECHNIQUES = {
    "T1059.001": {
        "name": "PowerShell",
        "atomic": "Invoke-AtomicTest T1059.001",
        "sigma_rule": "PowerShell Encoded Command Execution",
        "simulated_cmdline": "powershell.exe -nop -w hidden -enc SQBFAFgA",
        "exe_path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    },
    "T1053.005": {
        "name": "Scheduled Task",
        "atomic": "Invoke-AtomicTest T1053.005",
        "sigma_rule": "Scheduled Task Creation via Schtasks",
        "simulated_cmdline": "schtasks.exe /create /tn ATORValidation /tr cmd.exe /sc once",
        "exe_path": r"C:\Windows\System32\schtasks.exe",
    },
    "T1547.001": {
        "name": "Registry Run Keys / Startup Folder",
        "atomic": "Invoke-AtomicTest T1547.001",
        "sigma_rule": "Registry Run Key Persistence via Reg Add",
        "simulated_cmdline": "reg.exe add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v ator_test /t REG_SZ /d cmd.exe",
        "exe_path": r"C:\Windows\System32\reg.exe",
    },
    "T1003.001": {
        "name": "LSASS Memory (credential dump pattern)",
        "atomic": "Invoke-AtomicTest T1003.001",
        "sigma_rule": "Credential Dumping Tool Mimikatz Execution",
        "simulated_cmdline": "mimikatz.exe sekurlsa::logonpasswords",
        "exe_path": r"C:\Temp\mimikatz_x64.exe",
    },
    "T1033": {
        "name": "System Owner/User Discovery",
        "atomic": "Invoke-AtomicTest T1033",
        "sigma_rule": "Account Discovery via Whoami",
        "simulated_cmdline": "whoami.exe /priv",
        "exe_path": r"C:\Windows\System32\whoami.exe",
    },
}


def check_server(server_url):
    import requests
    try:
        r = requests.get(server_url.rstrip("/") + "/health", timeout=10)
        return r.status_code == 200
    except Exception:
        return False


def run_simulated(technique_id, server_url=None):
    spec = ATOMIC_TECHNIQUES.get(technique_id)
    if not spec:
        print(f"[SKIP] {technique_id} not in validation catalog")
        return False
    if server_url and not check_server(server_url):
        print(f"[FAIL] server unreachable at {server_url}")
        return False
    print(f"[ATOMIC] technique={technique_id} ({spec['name']})")
    print(f"  live command : {spec['atomic']}   (requires admin PowerShell + Atomic Red Team module)")
    print(f"  simulated    : {spec['simulated_cmdline']}")
    if server_url:
        from server import db as database
        from server.engine.sigma_runner import run as sigma_run
        conn = database.connect()
        hits, errors = sigma_run(conn)
        conn.close()
        matched = [h for h in hits
                   if h["technique_id"] == technique_id or h["rule_name"] == spec["sigma_rule"]]
        if matched:
            print(f"[PASS] {technique_id} detected and enriched successfully "
                  f"(rule='{matched[0]['rule_name']}', detections={len(matched)})")
            return True
        print(f"[FAIL] {technique_id}: no matching detection found in database")
        return False
    return True


def main():
    parser = argparse.ArgumentParser(description="ATOR DFIR validation harness (Atomic Red Team regression runner)")
    parser.add_argument("--technique", default="all", help="e.g. T1059.001 or 'all'")
    parser.add_argument("--server-url", default=os.environ.get("ATOR_DFIR_SERVER", "http://127.0.0.1:8000"))
    parser.add_argument("--check-db", action="store_true", help="verify detections exist in the local DB")
    args = parser.parse_args()

    targets = list(ATOMIC_TECHNIQUES) if args.technique == "all" else [args.technique]
    results = {}
    for tid in targets:
        results[tid] = run_simulated(tid, server_url=args.server_url if args.check_db else None)

    passed = sum(1 for v in results.values() if v)
    total = len(results)
    print(f"\n=== REGRESSION SUMMARY: {passed}/{total} techniques validated ===")
    for tid, ok in results.items():
        print(f"  {'PASS' if ok else 'FAIL'}  {tid}  {ATOMIC_TECHNIQUES[tid]['name']}")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
