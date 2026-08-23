import psutil
import os
import subprocess

def test_real_apps():
    active_apps = {}
    for conn in psutil.net_connections(kind='inet'):
        if conn.pid and conn.status in ['ESTABLISHED', 'LISTEN', 'SYN_SENT', 'CLOSE_WAIT']:
            try:
                p = psutil.Process(conn.pid)
                name = p.name()
                exe = p.exe()
                io = p.io_counters() if hasattr(p, 'io_counters') else None
                if name not in active_apps:
                    active_apps[name] = {
                        'pid': conn.pid,
                        'name': name,
                        'exe': exe,
                        'read_bytes': io.read_bytes if io else 0,
                        'write_bytes': io.write_bytes if io else 0,
                        'connections_count': 1,
                        'remote_ip': conn.raddr.ip if conn.raddr else 'Local'
                    }
                else:
                    active_apps[name]['connections_count'] += 1
            except Exception:
                pass

    print(f"Found {len(active_apps)} real active networked apps on this PC:")
    for name, data in list(active_apps.items())[:10]:
        print(f" - {name} (PID: {data['pid']}) -> Connections: {data['connections_count']} | Remote: {data['remote_ip']}")

if __name__ == "__main__":
    test_real_apps()
