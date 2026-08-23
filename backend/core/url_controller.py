"""
SwitchGate - Real-Time Live Website / URL Domain Tracker & Circuit Breaker (PAC & WinINet Powered)
Detects live domains visited on the system and provides instant 1-Click ON/OFF Internet Control
per website and per browser with zero freezing and zero crashes.
"""
import os
import sys
import time
import socket
import psutil
import platform
import threading
from typing import Dict, List, Any, Optional, Set
from pathlib import Path
from backend.config import AppConfig
from backend.database import db
from backend.kperf.kperf_engine import kperf_engine
from backend.native.network_engine import native_engine

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

    def start(self):
        with self._lock:
            if self.is_running:
                return
            self.is_running = True
            self._stop_event.clear()
        kperf_engine.start()
        self._sync_thread = threading.Thread(target=self._sync_kperf_domains, daemon=True, name="SwitchGate-URLSync")
        self._sync_thread.start()
        print("[URL Controller] Windows PAC & WinINet Website Circuit Breaker active.")

    def stop(self):
        self._stop_event.set()
        self.is_running = False
        if self._sync_thread and self._sync_thread.is_alive():
            try:
                self._sync_thread.join(timeout=1.0)
            except Exception:
                pass
        self._clear_windows_pac()

    def _init_tracked_sites(self):
        default_sites = [
            ("youtube.com", "Video Streaming", "Google LLC"),
            ("instagram.com", "Social Media", "Meta Platforms"),
            ("facebook.com", "Social Media", "Meta Platforms"),
            ("netflix.com", "Video Streaming", "Netflix Inc."),
            ("tiktok.com", "Social Media", "ByteDance"),
            ("reddit.com", "Social Media", "Reddit Inc."),
            ("github.com", "Developer Tools", "Microsoft"),
            ("openai.com", "Artificial Intelligence", "OpenAI"),
            ("twitter.com", "Social Media", "X Corp"),
            ("spotify.com", "Music Streaming", "Spotify AB"),
            ("roblox.com", "Online Gaming", "Roblox Corp"),
            ("amazon.com", "E-Commerce", "Amazon Inc.")
        ]
        now = time.strftime("%H:%M:%S")

        for domain, category, company in default_sites:
            is_blocked = db.is_domain_blocked(domain)
            if is_blocked:
                self.blocked_domains.add(domain)
                for sub in DOMAIN_MATRICES.get(domain, []):
                    self.blocked_domains.add(sub)

            self.live_websites[domain] = {
                "domain": domain,
                "friendly_name": domain.split(".")[0].title(),
                "category": category,
                "company": company,
                "hits": 1 if not is_blocked else 0,
                "last_seen": now,
                "is_blocked": is_blocked
            }

        if self.blocked_domains:
            self._apply_windows_pac()

    def set_browser_block_all(self, enable: bool):
        """Toggles global browser block via PAC script."""
        with self._lock:
            self.browser_block_all = enable

        if enable or self.blocked_domains:
            self._apply_windows_pac()
        else:
            self._clear_windows_pac()

        native_engine.flush_dns()

    def get_live_websites(self) -> List[Dict[str, Any]]:
        with self._lock:
            sites = list(self.live_websites.values())
            sites.sort(key=lambda x: (x["is_blocked"], -x["hits"]))
            return sites

    def generate_pac_script(self) -> str:
        """Generates dynamic Proxy Auto-Configuration (PAC) script with instant ad-purge."""
        with self._lock:
            block_all = self.browser_block_all
            blocked_list = list(self.blocked_domains)

        if block_all:
            return """function FindProxyForURL(url, host) {
    if (host === "localhost" || host === "127.0.0.1" || host === "::1") return "DIRECT";
    return "PROXY 127.0.0.1:9999; DIRECT";
}
"""

        # Fetch active adblock domains from Adblock-Rust Engine
        ad_domains = []
        try:
            from backend.adblock.adblock_engine import adblock_engine
            if adblock_engine.enabled:
                ad_domains = list(adblock_engine.blocked_domain_set)
        except Exception:
            ad_domains = []

        all_blocked = sorted(list(set(blocked_list + ad_domains)))

        if not all_blocked:
            return "function FindProxyForURL(url, host) { return 'DIRECT'; }\n"

        # Build high-speed JS object lookup for sublinear performance in browser
        ad_dict_entries = ", ".join([f'"{d}":1' for d in all_blocked])

        pac_code = f"""// SwitchGate Superintelligent PAC & Ad-Purge Circuit Breaker
var BLOCKED_DOMAINS = {{{ad_dict_entries}}};

function FindProxyForURL(url, host) {{
    if (!host || host === "localhost" || host === "127.0.0.1" || host === "::1") return "DIRECT";
    host = host.toLowerCase();

    // 1. Direct O(1) Exact Match
    if (BLOCKED_DOMAINS[host]) {{
        return "PROXY 127.0.0.1:9999; DIRECT";
    }}

    // 2. Fast Subdomain Traversal
    var dotIdx = host.indexOf('.');
    while (dotIdx !== -1) {{
        var sub = host.substring(dotIdx + 1);
        if (BLOCKED_DOMAINS[sub]) {{
            return "PROXY 127.0.0.1:9999; DIRECT";
        }}
        dotIdx = host.indexOf('.', dotIdx + 1);
    }}

    // 3. YouTube Ad / Stats Endpoint Interception
    if (host.indexOf("video-ad-stats") !== -1 || host.indexOf("googleads") !== -1 || host.indexOf("pagead2") !== -1) {{
        return "PROXY 127.0.0.1:9999; DIRECT";
    }}

    return "DIRECT";
}}
"""
        return pac_code

    def toggle_website(self, domain: str, action: str) -> bool:
        domain = domain.lower().strip().replace("http://", "").replace("https://", "").rstrip("/")
        action_upper = action.upper()
        is_blocked = action_upper == "OFF"

        target_domains = DOMAIN_MATRICES.get(domain, [domain, f"www.{domain}"])

        with self._lock:
            if is_blocked:
                for d in target_domains:
                    self.blocked_domains.add(d)
                db.add_adblock_rule(domain, category="website_block")
                db.add_log("SITE_BLOCK", "", "", f"Switched Website OFF: {domain} (Routed to blackhole across all browsers)")
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

        if self.browser_block_all or self.blocked_domains:
            self._apply_windows_pac()
        else:
            self._clear_windows_pac()

        native_engine.flush_dns()
        return True

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
        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"[PAC Notice] Error clearing Windows PAC: {e}")

    def _sync_kperf_domains(self):
        while not self._stop_event.is_set():
            try:
                now = time.strftime("%H:%M:%S")

                with kperf_engine._state_lock:
                    kperf_hits = dict(kperf_engine.live_domain_hits)

                with self._lock:
                    for d_key, d_info in kperf_hits.items():
                        if d_key in self.live_websites:
                            self.live_websites[d_key]["hits"] += d_info["hits"]
                            self.live_websites[d_key]["last_seen"] = d_info["last_seen"]
                        else:
                            is_blocked = db.is_domain_blocked(d_key)
                            self.live_websites[d_key] = {
                                "domain": d_key,
                                "friendly_name": d_key.split(".")[0].title(),
                                "category": d_info.get("category", "Web Service"),
                                "company": "Online Service",
                                "hits": d_info.get("hits", 1),
                                "last_seen": d_info.get("last_seen", now),
                                "is_blocked": is_blocked
                            }

                    # Memory bounding: Keep top 500 websites
                    if len(self.live_websites) > 500:
                        sorted_items = sorted(
                            self.live_websites.items(),
                            key=lambda item: (item[1].get("is_blocked", False), item[1].get("hits", 0)),
                            reverse=True
                        )
                        self.live_websites = dict(sorted_items[:500])

            except Exception:
                pass

            if self._stop_event.wait(timeout=1.0):
                break

url_controller = WebsiteUrlController()
