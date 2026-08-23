"""
SwitchGate - Ad-Purge & Security Shield (DNS Sinkhole Engine)
Intercepts DNS requests across the local network and vaporizes telemetry, tracking scripts, and advertisements.
"""
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, List, Dict, Any

from backend.config import AppConfig
from backend.database import db
from backend.adblock.adblock_engine import adblock_engine

# Try dnslib
DNSLIB_AVAILABLE = False
try:
    from dnslib import DNSRecord, DNSHeader, RR, A, QTYPE
    DNSLIB_AVAILABLE = True
except Exception:
    DNSLIB_AVAILABLE = False

class DnsSinkholeServer:
    def __init__(self, port: int = AppConfig.DNS_PORT):
        self.port = port
        self.upstream_dns = AppConfig.UPSTREAM_DNS[0] if AppConfig.UPSTREAM_DNS else "1.1.1.1"
        self.is_running = False
        self._server_sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._executor: Optional[ThreadPoolExecutor] = None
        self._lock = threading.Lock()
        self.total_queries = 0
        self.total_blocked = 0
        self.recent_blocked_logs: List[Dict[str, Any]] = []

    def start(self):
        """Launches the DNS Sinkhole Server."""
        if not DNSLIB_AVAILABLE:
            print("[DNS Sinkhole] dnslib not available, skipping DNS server.")
            return

        with self._lock:
            if self.is_running:
                return

        try:
            self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Try binding to configured port (e.g. 53 or 5353)
            try:
                self._server_sock.bind(("0.0.0.0", self.port))
            except Exception:
                # If 53 is busy or requires root, fallback to 5353
                self.port = 5353
                self._server_sock.bind(("0.0.0.0", self.port))

            self._executor = ThreadPoolExecutor(max_workers=32, thread_name_prefix="DNS-Forwarder")
            self.is_running = True
            self._thread = threading.Thread(target=self._listen_loop, daemon=True, name="SwitchGate-DNS")
            self._thread.start()
            print(f"[DNS Sinkhole] Ad-Purge Shield active on UDP port {self.port}")
        except Exception as e:
            print(f"[DNS Sinkhole Error] Failed to bind: {e}")

    def stop(self):
        self.is_running = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                pass
        if self._executor:
            try:
                self._executor.shutdown(wait=False, cancel_futures=True)
            except Exception:
                pass
        if self._thread and self._thread.is_alive():
            try:
                self._thread.join(timeout=1.0)
            except Exception:
                pass

    def _listen_loop(self):
        while self.is_running:
            try:
                if not self._server_sock:
                    break
                data, addr = self._server_sock.recvfrom(2048)
                if not data:
                    continue

                with self._lock:
                    self.total_queries += 1

                try:
                    request = DNSRecord.parse(data)
                    qname = str(request.q.qname).rstrip(".")
                    qtype = QTYPE.get(request.q.qtype, "A")
                except Exception:
                    continue

                # SafeSearch Enforcement
                safesearch_on = db.get_setting("dns_safesearch", "1") == "1"
                if safesearch_on:
                    q_lower = qname.lower()
                    if ("google." in q_lower and "forcesafesearch" not in q_lower) or q_lower == "google.com" or q_lower == "www.google.com":
                        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
                        reply.add_answer(RR(qname, QTYPE.A, rdata=A("216.239.38.120"), ttl=300))
                        try:
                            self._server_sock.sendto(reply.pack(), addr)
                        except Exception:
                            pass
                        continue
                    elif q_lower in ("youtube.com", "www.youtube.com", "m.youtube.com"):
                        # Keep main YouTube domain resolving, but block ad endpoints
                        pass
                    elif "bing.com" in q_lower and "strict" not in q_lower:
                        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
                        reply.add_answer(RR(qname, QTYPE.A, rdata=A("204.79.197.220"), ttl=300))
                        try:
                            self._server_sock.sendto(reply.pack(), addr)
                        except Exception:
                            pass
                        continue

                # Check if domain is blocked in DB or Brave Adblock-Rust Engine
                is_blocked = db.is_domain_blocked(qname) or adblock_engine.is_domain_blocked(qname)
                
                if is_blocked:
                    with self._lock:
                        self.total_blocked += 1
                    reply = DNSRecord(
                        DNSHeader(id=request.header.id, qr=1, aa=1, ra=1),
                        q=request.q
                    )
                    # Respond with 0.0.0.0 for A queries
                    if qtype == "A":
                        reply.add_answer(RR(qname, QTYPE.A, rdata=A("0.0.0.0"), ttl=300))
                    
                    try:
                        self._server_sock.sendto(reply.pack(), addr)
                    except Exception:
                        pass
                    
                    # Log blocked query
                    log_entry = {
                        "domain": qname,
                        "client_ip": addr[0],
                        "timestamp": time.strftime("%H:%M:%S"),
                        "action": "VAPORIZED"
                    }
                    with self._lock:
                        self.recent_blocked_logs.insert(0, log_entry)
                        if len(self.recent_blocked_logs) > 100:
                            self.recent_blocked_logs.pop()
                else:
                    # Forward upstream via worker pool
                    if self._executor and self.is_running:
                        self._executor.submit(self._forward_query, data, addr)

            except Exception:
                pass

    def _forward_query(self, data: bytes, client_addr):
        sock = None
        try:
            # Resolve dynamic upstream DNS based on DoH setting
            doh_setting = db.get_setting("secure_dns_doh", "Cloudflare (1.1.1.1)")
            upstream = "1.1.1.1"
            if "9.9.9.9" in doh_setting:
                upstream = "9.9.9.9"
            elif "8.8.8.8" in doh_setting:
                upstream = "8.8.8.8"
            elif self.upstream_dns:
                upstream = self.upstream_dns

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0)
            sock.sendto(data, (upstream, 53))
            reply_data, _ = sock.recvfrom(2048)
            if self._server_sock and self.is_running:
                self._server_sock.sendto(reply_data, client_addr)
        except Exception:
            pass
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "is_running": self.is_running,
                "port": self.port,
                "total_queries": self.total_queries,
                "total_blocked": self.total_blocked,
                "recent_blocked": list(self.recent_blocked_logs[:20])
            }

dns_sinkhole = DnsSinkholeServer()
