"""
SwitchGate - Zero-Latency Blackhole Sinkhole Server
Listens on 127.0.0.1:9999 and instantly rejects/closes connections for blocked apps and domains.
"""
import asyncio
import threading
from typing import Optional

class BlackholeServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 9999):
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
            print(f"[Blackhole Server] Active on {self.host}:{self.port} (Instant Connection Rejector).")

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
        
        async def handle_client(reader, writer):
            try:
                # Immediate clean close to reject traffic in 0ms
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

        async def main():
            try:
                server = await asyncio.start_server(handle_client, self.host, self.port)
                async with server:
                    while self.is_running:
                        await asyncio.sleep(0.5)
            except Exception:
                pass

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
