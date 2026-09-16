"""
SwitchGate - Zero-Latency Blackhole Sinkhole Server v2.5
Handles HTTP/HTTPS proxy connection attempts for blocked domains and immediately responds with HTTP 403 Forbidden,
preventing browsers (Chrome, Edge, Firefox) from failing over to direct connections.
"""
import asyncio
import threading
from typing import Optional

BLOCKED_HTML_PAYLOAD = (
    "HTTP/1.1 403 Forbidden\r\n"
    "Content-Type: text/html; charset=utf-8\r\n"
    "Connection: close\r\n"
    "Cache-Control: no-cache, no-store, must-revalidate\r\n\r\n"
    "<!DOCTYPE html>"
    "<html lang='en'>"
    "<head><meta charset='UTF-8'><title>403 Forbidden - Blocked by SwitchGate</title>"
    "<style>body{background:#080b13;color:#f43f5e;font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;}"
    ".card{background:#111625;border:1px solid #f43f5e44;padding:40px;border-radius:18px;text-align:center;box-shadow:0 10px 40px rgba(0,0,0,0.6);max-width:500px;}"
    "h1{color:#f43f5e;margin:0 0 10px;font-size:24px;}p{color:#94a3b8;font-size:14px;line-height:1.5;}</style></head>"
    "<body><div class='card'><h1>[ACCESS BLOCKED]</h1><p>This website or application has been cut off by <strong>SwitchGate Network Gateway</strong>.</p></div></body></html>"
).encode("utf-8")


class BlackholeServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 18888):
        self.host = host
        self.port = port
        self.is_running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    def start(self):
        with self._lock:
            if self.is_running:
                return
            self.is_running = True
            self._thread = threading.Thread(target=self._run_server, daemon=True, name="SwitchGate-Blackhole")
            self._thread.start()
            print(f"[Blackhole Server] ✅ Active on {self.host}:{self.port} (HTTP 403 Hard Wall Proxy).")

    def stop(self):
        self.is_running = False
        if self._thread and self._thread.is_alive():
            try:
                self._thread.join(timeout=1.0)
            except Exception:
                pass

    def _run_server(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            try:
                # Read initial request header (up to 4KB)
                data = await asyncio.wait_for(reader.read(4096), timeout=3.0)
                if data:
                    # If it's an HTTP CONNECT tunnel (HTTPS proxy request)
                    if data.startswith(b"CONNECT"):
                        # Respond with HTTP 403 Forbidden to explicitly reject HTTPS tunnel
                        writer.write(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
                    else:
                        # Respond with full 403 HTML page for standard HTTP requests
                        writer.write(BLOCKED_HTML_PAYLOAD)
                    await writer.drain()
            except Exception:
                pass
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

        async def main():
            try:
                server = await asyncio.start_server(handle_client, self.host, self.port, reuse_address=True)
                async with server:
                    while self.is_running:
                        await asyncio.sleep(0.5)
            except Exception as e:
                print(f"[Blackhole Server Error] {e}")

        try:
            loop.run_until_complete(main())
        except Exception:
            pass
        finally:
            try:
                loop.close()
            except Exception:
                pass


blackhole_server = BlackholeServer()
