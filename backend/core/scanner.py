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
from backend.core.silent_process import silent_check_output

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
        if sys.platform == "win32" and not getattr(conf, "use_pcap", True):
            SCAPY_AVAILABLE = False
            return False
        _scapy_ARP   = ARP
        _scapy_Ether = Ether
        _scapy_srp   = srp
        SCAPY_AVAILABLE = True
        return True
    except Exception:
        SCAPY_AVAILABLE = False
        return False

class NetworkScanner:
    # Adaptive scan intervals
    SCAN_INTERVAL_FAST = 4    # seconds — after detecting a change
    SCAN_INTERVAL_SLOW = 10   # seconds — when network is stable

    def __init__(self):
        self.is_scanning    = False
        self._stop_event    = threading.Event()
        self._bg_thread:    Optional[threading.Thread] = None
        self._scan_lock     = threading.Lock()
        self._missed_pings: Dict[str, int] = {}   # MAC -> consecutive missed scan cycles
        self._last_mac_set: set = set()            # Cache of MACs from last scan
        self._stable_cycles: int = 0               # Consecutive stable (no-change) scan cycles

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
        """Adaptive-interval scan loop: fast when network changes, slow when stable."""
        try:
            self.scan_network()
        except Exception:
            pass

        while not self._stop_event.is_set():
            # Choose interval: fast if recent change, slow if stable (saves CPU)
            if self._stable_cycles >= 3:
                interval = self.SCAN_INTERVAL_SLOW
            else:
                interval = self.SCAN_INTERVAL_FAST

            if self._stop_event.wait(timeout=interval):
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
            # 0. Clean up phantom devices from old / disconnected subnets
            try:
                db.cleanup_old_subnet_devices(AppConfig.NETWORK_CIDR)
            except Exception:
                pass

            # 1. Scapy ARP Discovery (only if Npcap / WinPcap is actually supported)
            if _load_scapy():
                try:
                    scapy_results = self._scapy_arp_scan(AppConfig.NETWORK_CIDR)
                    for dev in scapy_results:
                        discovered[dev["mac"]] = dev
                except Exception:
                    pass

            # 2. Native Win32 Kernel SendARP Sweep (<1.5s, 0% CPU, Zero-Npcap)
            if platform.system() == "Windows":
                try:
                    win32_devs = self._win32_send_arp_sweep(AppConfig.LOCAL_IP)
                    for wdev in win32_devs:
                        wmac = wdev.get("mac", "").lower().replace("-", ":")
                        wip = wdev.get("ip", "")
                        if wmac and wip and not wmac.startswith("ff:ff"):
                            discovered[wmac] = {"ip": wip, "mac": wmac}
                except Exception:
                    pass

            # 3. Read OS Kernel ARP Table (Windows arp -a & Get-NetNeighbor)
            os_devices = self._read_system_arp_table()
            for dev in os_devices:
                dmac = dev["mac"].lower().replace("-", ":")
                if dmac not in discovered:
                    discovered[dmac] = dev
                else:
                    discovered[dmac]["ip"] = dev["ip"]

            # 4. UPnP SSDP Router & Smart Device Discovery (Method 3 Automation)
            ssdp_info = self._ssdp_discover_devices()

            # 5. Fast UDP Ping Sweep across subnet (refreshes OS ARP cache for remaining devices)
            self._fast_ping_sweep(AppConfig.NETWORK_CIDR)

            # 6. Resolve Hostnames, UPnP Metadata & OUI Vendors concurrently
            enriched_devices = self._enrich_devices(list(discovered.values()), ssdp_info)

            # 6. Save to Database & Check Dynamic DHCP Migrations
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
            local_base = (AppConfig.LOCAL_IP.rsplit(".", 1)[0] + ".") if AppConfig.LOCAL_IP else "192.168.0."
            for d in db.get_all_devices():
                d_mac = d["mac"]
                d_ip = d.get("ip", "")
                if not d_ip.startswith(local_base) and d_ip != "0.0.0.0" and not d.get("is_banned"):
                    db.update_device_status(d_mac, "OFFLINE", "Offline (Previous Subnet)")
                elif d_mac not in seen_macs and not d_mac.startswith("ff:ff"):
                    self._missed_pings[d_mac] = self._missed_pings.get(d_mac, 0) + 1
                    if self._missed_pings[d_mac] >= 3 and not d.get("is_blocked") and not d.get("is_banned"):
                        db.update_device_status(d_mac, "OFFLINE", "Offline")

            # 7. If isolated environment or demo mode, ensure rich device set for complete testing
            if AppConfig.MOCK_DEVICES_FOR_TESTING and len(enriched_devices) <= 1:
                self._seed_mock_devices()

            # 8. Adaptive interval: track if MACs changed since last scan
            current_mac_set = set(seen_macs)
            if current_mac_set == self._last_mac_set:
                self._stable_cycles += 1
            else:
                self._stable_cycles = 0
                self._last_mac_set  = current_mac_set

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
            # 0.8s timeout — 45% faster than 1.5s; still catches all devices reliably
            answered, _ = _scapy_srp(packet, timeout=0.8, verbose=0)
            for sent, received in answered:
                results.append({
                    "ip":  received.psrc,
                    "mac": received.hwsrc.lower().replace("-", ":")
                })
        except Exception:
            pass
        return results

    def _fast_ping_sweep(self, cidr: str):
        """Sends quick UDP probes across subnet to warm up ARP tables. 128 parallel workers."""
        local_ip = AppConfig.LOCAL_IP or "127.0.0.1"
        parts    = local_ip.split(".")
        if len(parts) >= 3 and parts[0] not in ("127", "0"):
            base_ip = ".".join(parts[:3])
        else:
            base_ip = "192.168.1"

        def probe_ip(host_id: int):
            target_ip = f"{base_ip}.{host_id}"
            sock = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(0.04)
                sock.sendto(b"\x00", (target_ip, 5353))
            except Exception:
                pass
            finally:
                if sock:
                    try:
                        sock.close()
                    except Exception:
                        pass

        with ThreadPoolExecutor(max_workers=128) as executor:
            executor.map(probe_ip, range(1, 255))

    def _win32_send_arp_sweep(self, local_ip: str) -> List[Dict[str, str]]:
        """Sends native Win32 hardware ARP probes to all 254 subnet hosts using SendARP API."""
        results = []
        if not local_ip or local_ip.startswith("127."):
            local_ip = "192.168.0.2"
        base_ip = ".".join(local_ip.split(".")[:3])

        def probe_arp(host_id: int):
            target_ip = f"{base_ip}.{host_id}"
            try:
                dest_ip = struct.unpack("I", socket.inet_aton(target_ip))[0]
                mac_buf = (ctypes.c_ubyte * 6)()
                mac_len = ctypes.c_ulong(6)
                res = ctypes.windll.iphlpapi.SendARP(dest_ip, 0, ctypes.byref(mac_buf), ctypes.byref(mac_len))
                if res == 0:
                    mac_str = ":".join(f"{b:02x}" for b in mac_buf)
                    if mac_str not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
                        return {"ip": target_ip, "mac": mac_str}
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=64) as executor:
            for dev in executor.map(probe_arp, range(1, 255)):
                if dev:
                    results.append(dev)
        return results

    def _ssdp_discover_devices(self) -> Dict[str, Dict[str, str]]:
        """Universal Plug and Play (UPnP) SSDP router and device query (Method 3)."""
        import urllib.request
        import xml.etree.ElementTree as ET

        ssdp_request = (
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            "MAN: \"ssdp:discover\"\r\n"
            "MX: 1\r\n"
            "ST: ssdp:all\r\n\r\n"
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(1.0)
        locations = {}
        try:
            sock.sendto(ssdp_request.encode(), ("239.255.255.250", 1900))
            t0 = time.time()
            while time.time() - t0 < 1.0:
                try:
                    data, addr = sock.recvfrom(2048)
                    text = data.decode(errors="ignore")
                    for line in text.splitlines():
                        if line.upper().startswith("LOCATION:"):
                            url = line.split(":", 1)[1].strip()
                            locations[addr[0]] = url
                except socket.timeout:
                    break
        except Exception:
            pass
        finally:
            sock.close()

        ssdp_info = {}
        for ip, url in locations.items():
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "SwitchGate/2.0"})
                with urllib.request.urlopen(req, timeout=1.2) as resp:
                    xml_data = resp.read()
                    root = ET.fromstring(xml_data)
                    fn = root.find(".//{*}friendlyName")
                    man = root.find(".//{*}manufacturer")
                    model = root.find(".//{*}modelName")
                    desc = root.find(".//{*}modelDescription")
                    ssdp_info[ip] = {
                        "friendly_name": fn.text.strip() if fn is not None and fn.text else "",
                        "manufacturer": man.text.strip() if man is not None and man.text else "",
                        "model": model.text.strip() if model is not None and model.text else "",
                        "description": desc.text.strip() if desc is not None and desc.text else ""
                    }
            except Exception:
                pass
        return ssdp_info

    def _read_system_arp_table(self) -> List[Dict[str, str]]:
        devices = []
        try:
            cmd = ["arp", "-a"]
            output = silent_check_output(cmd, stderr=subprocess.DEVNULL, universal_newlines=True)
            
            pattern = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})")
            for line in output.splitlines():
                match = pattern.search(line)
                if match:
                    ip, mac = match.groups()
                    mac_clean = mac.lower().replace("-", ":")
                    if mac_clean not in ["ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"]:
                        devices.append({"ip": ip, "mac": mac_clean})
        except Exception as e:
            print(f"[Scanner] System ARP read error: {e}")
        return devices

    def _enrich_devices(self, devices: List[Dict[str, str]], ssdp_info: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        enriched = []
        ssdp_info = ssdp_info or {}
        
        def resolve_device(dev):
            ip = dev.get("ip", "")
            mac = dev.get("mac", "")
            hostname = self._query_hostname(ip)
            vendor, dev_type, friendly = resolve_vendor_and_category(mac, hostname, ip)
            
            # Check SSDP / UPnP Descriptor first (Method 3 authoritative device metadata)
            if ip in ssdp_info:
                s = ssdp_info[ip]
                if s.get("manufacturer"):
                    vendor = s["manufacturer"]
                if s.get("friendly_name"):
                    friendly = s["friendly_name"]
                if "TV" in s.get("model", "") or "TV" in s.get("friendly_name", "") or "Chromecast" in s.get("description", ""):
                    dev_type = "tv"

            # Special check: If this is the Gateway IP, mark as router with model info
            if ip and ip == AppConfig.GATEWAY_IP:
                dev_type = "router"
                if ip in ssdp_info and ssdp_info[ip].get("model"):
                    friendly = f"{ssdp_info[ip].get('manufacturer', 'Wi-Fi')} {ssdp_info[ip]['model']} (Router Gateway)"
                else:
                    friendly = "Main Wi-Fi Router (Gateway)"
                vendor = ssdp_info[ip].get("manufacturer", "TP-Link") if ip in ssdp_info else "Gateway"

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
