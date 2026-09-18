import psutil
import socket


def collect():
    results = []
    for conn in psutil.net_connections(kind="inet"):
        try:
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None
            proc_name = None
            rdomain = None
            if conn.raddr:
                try:
                    rdomain = socket.gethostbyaddr(conn.raddr.ip)[0]
                except Exception:
                    rdomain = None
            if conn.pid:
                try:
                    proc_name = psutil.Process(conn.pid).name()
                except Exception:
                    pass
            results.append({
                "pid": conn.pid,
                "process_name": proc_name,
                "local": laddr,
                "remote": raddr,
                "remote_domain": rdomain,
                "proto": "tcp" if conn.type == 1 else ("udp" if conn.type == 2 else str(conn.type)),
                "status": str(conn.status),
            })
        except Exception:
            continue
    return results
