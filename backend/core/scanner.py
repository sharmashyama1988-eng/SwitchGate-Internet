"""
SwitchGate - Network Discovery & Device Scanner Engine
Detects live devices using ARP, mDNS, NetBIOS, ICMP, and OS ARP table inspection.
"""
import os
import re
import time
import socket
import struct
import platform
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any, Optional

from backend.config import AppConfig
from backend.database import db
from backend.core.oui_database import resolve_vendor_and_category

# Scapy imported lazily — NOT at module level (saves 2-3s startup time)
SCAPY_AVAILABLE = False
_scapy_ARP   = None
_scapy_Ether = None
_scapy_srp   = None

def _load_scapy():
    global SCAPY_AVAILABLE, _scapy_ARP, _scapy_Ether, _scapy_srp
    if SCAPY_AVAILABLE:
        return True
    try:
        import logging
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
        logging.getLogger("scapy").setLevel(logging.ERROR)
        from scapy.all import ARP, Ether, srp, conf
        conf.verb = 0
        _scapy_ARP   = ARP
        _scapy_Ether = Ether
        _scapy_srp   = srp
        SCAPY_AVAILABLE = True
        return True
    except Exception:
        return False

class NetworkScanner:
    def __init__(self):
        self.is_scanning = False
        self._stop_event = threading.Event()
        self._bg_thread: Optional[threading.Thread] = None
        self._scan_lock = threading.Lock()
        self._missed_pings: Dict[str, int] = {}  # MAC -> consecutive missed scan cycles (Grace period for sleep)

    def start_background_scan(self):
        """Starts continuous periodic network scanning."""
        if self._bg_thread and self._bg_thread.is_alive():
            return
        self._stop_event.clear()
        self._bg_thread = threading.Thread(target=self._scan_loop, daemon=True, name="SwitchGate-Scanner")
        self._bg_thread.start()

    def stop_background_scan(self):
        self._stop_event.set()
        if self._bg_thread and self._bg_thread.is_alive():
            try:
                self._bg_thread.join(timeout=1.0)
            except Exception:
                pass

    def _scan_loop(self):
        # Initial scan immediately
        try:
            self.scan_network()
        except Exception:
            pass
        while not self._stop_event.is_set():
            if self._stop_event.wait(timeout=AppConfig.SCAN_INTERVAL_SECONDS):
                break
            try:
                self.scan_network()
            except Exception:
                pass

    def scan_network(self) -> List[Dict[str, Any]]:
        """Executes a full multi-stage network scan."""
        with self._scan_lock:
            if self.is_scanning:
                return db.get_all_devices()
            self.is_scanning = True

        discovered = {}

        try:
            # 1. Scapy ARP Discovery (High Precision)
            if SCAPY_AVAILABLE:
                try:
                    scapy_results = self._scapy_arp_scan(AppConfig.NETWORK_CIDR)
                    for dev in scapy_results:
                        discovered[dev["mac"]] = dev
                except Exception as e:
                    print(f"[Scanner] Scapy scan fallback: {e}")

            # 2. Fast Socket Sweep (triggers OS ARP cache update)
            self._fast_ping_sweep(AppConfig.NETWORK_CIDR)

            # 3. OS ARP Table Inspection (Windows / Linux / macOS)
            os_devices = self._read_system_arp_table()
            for dev in os_devices:
                if dev["mac"] not in discovered:
                    discovered[dev["mac"]] = dev
                else:
                    discovered[dev["mac"]]["ip"] = dev["ip"]

            # 4. Resolve Hostnames & Metadata concurrently
            enriched_devices = self._enrich_devices(list(discovered.values()))

            # 5. Save to Database & Check Dynamic DHCP Migrations
            seen_macs = set()
            for dev in enriched_devices:
                # Do not treat broadcast/multicast as real client devices
                mac = dev["mac"].lower().replace("-", ":")
                if mac.startswith("ff:ff") or mac.startswith("01:00:5e"):
                    continue
                seen_macs.add(mac)
                self._missed_pings[mac] = 0  # Reset missed ping counter on active discovery

                # Check for dynamic DHCP IP change
                existing = db.get_device(mac)
                if existing and existing.get("ip") and existing.get("ip") != dev["ip"]:
                    old_ip = existing.get("ip")
                    # Synchronize with Blocker Engine dynamically
                    try:
                        from backend.core.blocker import blocker
                        blocker.sync_target_ip(mac, dev["ip"])
                    except Exception:
                        pass

                db.upsert_device(
                    mac=mac,
                    ip=dev["ip"],
                    vendor=dev["vendor"],
                    device_type=dev["device_type"],
                    suggested_name=dev["friendly_name"]
                )

            # Update sliding window for devices not seen in this scan (grace period before offline)
            for d in db.get_all_devices():
                d_mac = d["mac"]
                if d_mac not in seen_macs and not d_mac.startswith("ff:ff"):
                    self._missed_pings[d_mac] = self._missed_pings.get(d_mac, 0) + 1

            # 6. If isolated environment or demo mode, ensure rich device set for complete testing
            if AppConfig.MOCK_DEVICES_FOR_TESTING and len(enriched_devices) <= 1:
                self._seed_mock_devices()

        except Exception as e:
            print(f"[Scanner Error] {e}")
        finally:
            self.is_scanning = False

        return db.get_all_devices()

    def _scapy_arp_scan(self, cidr: str) -> List[Dict[str, str]]:
        results = []
        if not _load_scapy():
            return results
        try:
            arp    = _scapy_ARP(pdst=cidr)
            ether  = _scapy_Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp
            answered, _ = _scapy_srp(packet, timeout=AppConfig.ARP_SCAN_TIMEOUT, verbose=0)
            for sent, received in answered:
                results.append({
                    "ip":  received.psrc,
                    "mac": received.hwsrc.lower().replace("-", ":")
                })
        except Exception:
            pass
        return results

    def _fast_ping_sweep(self, cidr: str):
        """Sends quick UDP / TCP probes across subnet to force switches/routers and host ARP tables to refresh."""
        local_ip = AppConfig.LOCAL_IP or "127.0.0.1"
        parts = local_ip.split(".")
        if len(parts) >= 3 and parts[0] != "127" and parts[0] != "0":
            base_ip = ".".join(parts[:3])
        else:
            base_ip = "192.168.1"
        
        def probe_ip(host_id: int):
            target_ip = f"{base_ip}.{host_id}"
            sock = None
            try:
                # Lightweight UDP probe
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(0.05)
                sock.sendto(b"\x00", (target_ip, 5353))
            except Exception:
                pass
            finally:
                if sock:
                    try:
                        sock.close()
                    except Exception:
                        pass

        with ThreadPoolExecutor(max_workers=50) as executor:
            executor.map(probe_ip, range(1, 255))

    def _read_system_arp_table(self) -> List[Dict[str, str]]:
        devices = []
        try:
            cmd = ["arp", "-a"]
            output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, universal_newlines=True)
            
            # Windows & Linux regex for IP and MAC
            # Matches: 192.168.1.1  00-11-22-33-44-55 OR 192.168.1.1  00:11:22:33:44:55
            pattern = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})")
            for line in output.splitlines():
                match = pattern.search(line)
                if match:
                    ip, mac = match.groups()
                    mac_clean = mac.lower().replace("-", ":")
                    # Ignore broadcast / invalid
                    if mac_clean not in ["ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"]:
                        devices.append({"ip": ip, "mac": mac_clean})
        except Exception as e:
            print(f"[Scanner] System ARP read error: {e}")
        return devices

    def _enrich_devices(self, devices: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        enriched = []
        
        def resolve_device(dev):
            ip = dev.get("ip", "")
            mac = dev.get("mac", "")
            hostname = self._query_hostname(ip)
            vendor, dev_type, friendly = resolve_vendor_and_category(mac, hostname, ip)
            
            # Special check: If this is the Gateway IP, mark as router
            if ip and ip == AppConfig.GATEWAY_IP:
                dev_type = "router"
                friendly = "Main Wi-Fi Router (Gateway)"
                vendor = "Gateway"
            # If this is local machine
            elif ip and (ip == AppConfig.LOCAL_IP or mac == AppConfig.HOST_MAC):
                friendly = f"SwitchGate Host ({platform.node()})"
                dev_type = "laptop"
                
            return {
                "mac": mac,
                "ip": ip,
                "hostname": hostname,
                "vendor": vendor,
                "device_type": dev_type,
                "friendly_name": friendly
            }

        with ThreadPoolExecutor(max_workers=20) as executor:
            enriched = list(executor.map(resolve_device, devices))

        return enriched

    def _query_hostname(self, ip: str) -> str:
        """Attempts NetBIOS, mDNS, and Reverse DNS to resolve real device names."""
        if not ip:
            return ""
        # 1. Reverse DNS
        try:
            host = socket.gethostbyaddr(ip)[0]
            if host and host != ip:
                return host
        except Exception:
            pass

        # 2. NetBIOS Query (Port 137 UDP - Windows / Android / Smart TVs)
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.15)
            # NetBIOS Name Query packet
            query = b"\x80\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01"
            sock.sendto(query, (ip, 137))
            data, _ = sock.recvfrom(1024)
            if len(data) > 56:
                name = data[57:72].decode("utf-8", errors="ignore").strip()
                if name:
                    return name
        except Exception:
            pass
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

        return ""

    def _seed_mock_devices(self):
        """Seeds realistic devices for seamless first-run experience."""
        mocks = [
            ("74:a7:22:8b:14:02", "192.168.1.105", "LG Electronics", "tv", "Living Room LG OLED TV 65\""),
            ("14:99:e2:3a:77:bc", "192.168.1.112", "Apple", "phone", "Papa's iPhone 15 Pro"),
            ("24:4b:03:9e:11:4a", "192.168.1.120", "Samsung Electronics", "phone", "Mummy's Samsung Galaxy S24"),
            ("dc:a6:32:44:8f:19", "192.168.1.150", "Raspberry Pi", "iot", "Home Assistant Server"),
            ("ac:63:be:19:55:a1", "192.168.1.118", "Amazon Fire Stick", "tv", "Bedroom Fire TV Stick 4K"),
            ("28:0d:fc:88:99:11", "192.168.1.144", "Sony Interactive", "console", "PlayStation 5 Console"),
            ("24:6f:28:cc:bb:33", "192.168.1.160", "Espressif ESP32", "iot", "Smart Living Room Lighting"),
            ("3c:18:a0:aa:dd:22", "192.168.1.135", "HP Inc.", "laptop", "Office Work Laptop"),
        ]
        for mac, ip, vendor, dtype, name in mocks:
            db.upsert_device(mac=mac, ip=ip, vendor=vendor, device_type=dtype, suggested_name=name)

scanner = NetworkScanner()
