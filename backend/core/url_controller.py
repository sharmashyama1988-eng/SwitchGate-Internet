"""
SwitchGate - Real-Time Live Website / URL Domain Tracker & Circuit Breaker v2.5
Multi-Layered Enforcement:
  1. Windows Defender Firewall IP & Port 80/443 Blocking (TCP & UDP/QUIC Dropper)
  2. Active TCP Socket Circuit Breaking (kPerf)
  3. Windows PAC & WinINet Proxy Blackholing
  4. Sub-second DNS Cache Invalidation
"""
import os
import sys
import time
import socket
import psutil
import platform
import subprocess
import threading
from typing import Dict, List, Any, Optional, Set
from pathlib import Path
from backend.config import AppConfig
from backend.database import db
from backend.kperf.kperf_engine import kperf_engine
from backend.native.network_engine import native_engine
from backend.core.silent_process import silent_run

IS_WINDOWS = platform.system() == "Windows"
if IS_WINDOWS:
    import winreg
    import ctypes
    _wininet = ctypes.windll.wininet
    _REG_INTERNET_SETTINGS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

DOMAIN_MATRICES: Dict[str, List[str]] = {
    "youtube.com": [
        "youtube.com", "www.youtube.com", "m.youtube.com", "music.youtube.com",
        "gaming.youtube.com", "googlevideo.com", "ytimg.com", "i.ytimg.com",
        "s.ytimg.com", "yt3.ggpht.com", "youtubei.googleapis.com", "youtu.be",
        "yt.be", "youtube-nocookie.com", "youtube-ui.l.google.com"
    ],
    "instagram.com": [
        "instagram.com", "www.instagram.com", "cdninstagram.com", "z-p4-cdn.instagram.com",
        "scontent.cdninstagram.com", "threads.net"
    ],
    "facebook.com": [
        "facebook.com", "www.facebook.com", "fbcdn.net", "connect.facebook.net", "messenger.com"
    ],
    "netflix.com": [
        "netflix.com", "www.netflix.com", "nflxvideo.net", "nflximg.net", "nflxext.com", "nflxso.net"
    ],
    "tiktok.com": [
        "tiktok.com", "www.tiktok.com", "tiktokcdn.com", "byteoversea.com", "ibyteimg.com"
    ],
    "reddit.com": [
        "reddit.com", "www.reddit.com", "redd.it", "redditmedia.com", "redditstatic.com"
    ],
    "spotify.com": [
        "spotify.com", "www.spotify.com", "scdn.co", "spotifycdn.com", "audio-fa.spotify.com"
    ],
    "roblox.com": [
        "roblox.com", "www.roblox.com", "rbxcdn.com", "robloxlabs.com"
    ],
    "twitter.com": [
        "twitter.com", "www.twitter.com", "x.com", "twimg.com", "t.co"
    ],
    "openai.com": [
        "openai.com", "chatgpt.com", "cdn.oaistatic.com", "auth0.openai.com"
    ],
    "github.com": [
        "github.com", "www.github.com", "githubusercontent.com", "githubassets.com"
    ],
    "amazon.com": [
        "amazon.com", "www.amazon.com", "media-amazon.com", "ssl-images-amazon.com"
    ]
}


class WebsiteUrlController:
    def __init__(self):
        self.live_websites: Dict[str, Dict[str, Any]] = {}
        self.blocked_domains: Set[str] = set()
        self.browser_block_all: bool = False
        self._lock = threading.Lock()
        self.is_running = False
        self._stop_event = threading.Event()
        self._sync_thread: Optional[threading.Thread] = None
        self._init_tracked_sites()
        self._load_saved_rules()

    def _init_tracked_sites(self):
        for domain in DOMAIN_MATRICES.keys():
            self.live_websites[domain] = {
                "domain": domain,
                "friendly_name": domain.split(".")[0].title(),
                "category": "Popular Web Platform",
                "company": domain.split(".")[0].title(),
                "hits": 0,
                "last_seen": "Offline / Standby",
                "is_blocked": False
            }

    def _load_saved_rules(self):
        try:
            saved_rules = db.get_adblock_rules()
            for r in saved_rules:
                if r.get("category") == "website_block":
                    dom = r.get("domain", "").lower().strip()
                    if dom:
                        targets = DOMAIN_MATRICES.get(dom, [dom, f"www.{dom}"])
                        for d in targets:
                            self.blocked_domains.add(d)
                        if dom in self.live_websites:
                            self.live_websites[dom]["is_blocked"] = True
            if self.blocked_domains:
                self._apply_firewall_and_pac()
        except Exception as e:
            print(f"[URL Controller] Load saved rules notice: {e}")

    def start(self):
        with self._lock:
            if self.is_running:
                return
            self.is_running = True
            self._stop_event.clear()
        kperf_engine.start()
        self._sync_thread = threading.Thread(target=self._sync_kperf_domains, daemon=True, name="SwitchGate-URLSync")
        self._sync_thread.start()
        print("[URL Controller] ✅ Multi-Layered Website Firewall & Circuit Breaker active.")

    def stop(self):
        self._stop_event.set()
        self.is_running = False
        if self._sync_thread and self._sync_thread.is_alive():
            try:
                self._sync_thread.join(timeout=1.0)
            except Exception:
                pass
        self._clear_windows_pac()

    def _sync_kperf_domains(self):
        while not self._stop_event.is_set():
            try:
                active_domains = kperf_engine.get_active_domains()
                with self._lock:
                    for item in active_domains:
                        domain = item.get("domain", "").lower().strip()
                        if not domain or len(domain) < 3:
                            continue
                        if domain not in self.live_websites:
                            parts = domain.split(".")
                            friendly = parts[-2].title() if len(parts) >= 2 else domain.title()
                            self.live_websites[domain] = {
                                "domain": domain,
                                "friendly_name": friendly,
                                "category": "Dynamic Live Browsing",
                                "company": friendly,
                                "hits": item.get("hits", 1),
                                "last_seen": item.get("last_seen", time.strftime("%H:%M:%S")),
                                "is_blocked": domain in self.blocked_domains
                            }
                        else:
                            self.live_websites[domain]["hits"] = item.get("hits", self.live_websites[domain]["hits"] + 1)
                            self.live_websites[domain]["last_seen"] = item.get("last_seen", time.strftime("%H:%M:%S"))
                            self.live_websites[domain]["is_blocked"] = domain in self.blocked_domains
            except Exception:
                pass
            time.sleep(1.0)

    def get_live_websites(self) -> List[Dict[str, Any]]:
        with self._lock:
            sites = list(self.live_websites.values())
        sites.sort(key=lambda x: (not x["is_blocked"], x["hits"]), reverse=True)
        return sites

    def _resolve_domain_ips(self, domain: str) -> List[str]:
        """Resolves all IPv4 addresses associated with a domain and its common subdomains."""
        ips = set()
        subdomains = DOMAIN_MATRICES.get(domain, [domain, f"www.{domain}"])
        for sub in subdomains:
            try:
                infos = socket.getaddrinfo(sub, 443, socket.AF_INET, socket.SOCK_STREAM)
                for item in infos:
                    ips.add(item[4][0])
            except Exception:
                pass
            try:
                infos80 = socket.getaddrinfo(sub, 80, socket.AF_INET, socket.SOCK_STREAM)
                for item in infos80:
                    ips.add(item[4][0])
            except Exception:
                pass
        return list(ips)

    def toggle_website(self, domain: str, action: str) -> bool:
        domain = domain.lower().strip().replace("http://", "").replace("https://", "").rstrip("/")
        action_upper = action.upper()
        is_blocked = action_upper == "OFF"

        target_domains = DOMAIN_MATRICES.get(domain, [domain, f"www.{domain}"])
        clean_name = domain.replace(".", "_").replace("-", "_")

        with self._lock:
            if is_blocked:
                for d in target_domains:
                    self.blocked_domains.add(d)
                db.add_adblock_rule(domain, category="website_block")
                db.add_log("SITE_BLOCK", "", "", f"Switched Website OFF: {domain} (Blocked in Windows Kernel & PAC)")
            else:
                for d in target_domains:
                    self.blocked_domains.discard(d)
                db.delete_adblock_rule(domain)
                db.add_log("SITE_UNBLOCK", "", "", f"Restored Website Access: {domain}")

            if domain in self.live_websites:
                self.live_websites[domain]["is_blocked"] = is_blocked
            else:
                self.live_websites[domain] = {
                    "domain": domain,
                    "friendly_name": domain.split(".")[0].title(),
                    "category": "Custom Blocked Site",
                    "company": "Web Domain",
                    "hits": 1,
                    "last_seen": time.strftime("%H:%M:%S"),
                    "is_blocked": is_blocked
                }

        # ── 1. Real Windows Firewall IP Rules (TCP & UDP QUIC) ────────────────
        if IS_WINDOWS:
            rule_tcp = f"SwitchGate_Web_{clean_name}_TCP"
            rule_udp = f"SwitchGate_Web_{clean_name}_UDP"
            rule_in  = f"SwitchGate_Web_{clean_name}_In"

            if is_blocked:
                resolved_ips = self._resolve_domain_ips(domain)
                if resolved_ips:
                    ip_str = ",".join(resolved_ips)
                    # Block TCP Outbound (Port 80, 443, 8080)
                    silent_run(
                        ["netsh", "advfirewall", "firewall", "add", "rule",
                         f"name={rule_tcp}", "dir=out", "action=block",
                         "protocol=TCP", "remoteport=80,443,8080,8443", f"remoteip={ip_str}",
                         "enable=yes", "profile=any"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                    )
                    # Block UDP Outbound (QUIC Protocol - Port 80, 443, 8080)
                    silent_run(
                        ["netsh", "advfirewall", "firewall", "add", "rule",
                         f"name={rule_udp}", "dir=out", "action=block",
                         "protocol=UDP", "remoteport=80,443,8080,8443", f"remoteip={ip_str}",
                         "enable=yes", "profile=any"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                    )
                    # Block Inbound from these IPs
                    silent_run(
                        ["netsh", "advfirewall", "firewall", "add", "rule",
                         f"name={rule_in}", "dir=in", "action=block",
                         f"remoteip={ip_str}", "enable=yes", "profile=any"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                    )
                    # Kill active browser sockets to these IPs
                    kperf_engine.kill_sockets_by_remote_ips(resolved_ips)
                    print(f"[URL Controller] ✅ Windows Firewall blocked {len(resolved_ips)} IPs for {domain} (TCP+UDP QUIC).")
            else:
                # Remove Firewall Rules on restore
                silent_run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_tcp}"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                silent_run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_udp}"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                silent_run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_in}"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                print(f"[URL Controller] ✅ Removed Windows Firewall block rules for {domain}.")

        # ── 2. PAC Proxy Circuit Breaker ──────────────────────────────────────
        self._apply_firewall_and_pac()

        # ── 3. Flush DNS Cache ────────────────────────────────────────────────
        native_engine.flush_dns()
        return True

    def _apply_firewall_and_pac(self):
        if self.browser_block_all or self.blocked_domains:
            self._apply_windows_pac()
        else:
            self._clear_windows_pac()

    def generate_pac_script(self) -> str:
        """Generates dynamic PAC script that routes blocked domains to 127.0.0.1:18888 blackhole."""
        with self._lock:
            all_blocked = set(self.blocked_domains)
            if self.browser_block_all:
                return "function FindProxyForURL(url, host) { return 'PROXY 127.0.0.1:18888'; }\n"

        if not all_blocked:
            return "function FindProxyForURL(url, host) { return 'DIRECT'; }\n"

        ad_dict_entries = ", ".join([f'"{d}":1' for d in all_blocked])
        pac_code = f"""// SwitchGate PAC Hard Circuit Breaker
var BLOCKED_DOMAINS = {{{ad_dict_entries}}};

function FindProxyForURL(url, host) {{
    if (!host || host === "localhost" || host === "127.0.0.1" || host === "::1") return "DIRECT";
    host = host.toLowerCase();

    if (BLOCKED_DOMAINS[host]) {{
        return "PROXY 127.0.0.1:18888";
    }}

    for (var d in BLOCKED_DOMAINS) {{
        if (host === d || (host.length > d.length && host.indexOf("." + d) === (host.length - d.length - 1))) {{
            return "PROXY 127.0.0.1:18888";
        }}
    }}

    return "DIRECT";
}}
"""
        return pac_code

    def _apply_windows_pac(self):
        if not IS_WINDOWS:
            return
        try:
            pac_url = f"http://127.0.0.1:{AppConfig.PORT}/api/websites/switchgate.pac"
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _REG_INTERNET_SETTINGS, 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "AutoConfigURL", 0, winreg.REG_SZ, pac_url)
            winreg.CloseKey(key)
            _wininet.InternetSetOptionW(0, 39, None, 0)
            _wininet.InternetSetOptionW(0, 37, None, 0)
        except Exception as e:
            print(f"[PAC Notice] Error setting Windows PAC: {e}")

    def _clear_windows_pac(self):
        if not IS_WINDOWS:
            return
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _REG_INTERNET_SETTINGS, 0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(key, "AutoConfigURL")
            winreg.CloseKey(key)
            _wininet.InternetSetOptionW(0, 39, None, 0)
            _wininet.InternetSetOptionW(0, 37, None, 0)
        except Exception:
            pass


url_controller = WebsiteUrlController()
