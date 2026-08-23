"""
SwitchGate kPerf - Python Interface Bridge for Rust Kernel Hypervisor & Ring Buffer
Provides high-level APIs for zero-copy metadata streaming, instant socket termination,
and fast reverse-DNS domain matching.
"""
import os
import sys
import time
import socket
import struct
import platform
import ctypes
from ctypes import wintypes, Structure, c_uint32, c_uint64, c_uint16, c_uint8, c_int32, POINTER, byref
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

IS_WINDOWS = platform.system() == "Windows"

# Structures matching Rust C-ABI
class HypervisorStats(Structure):
    _fields_ = [
        ("is_running", c_uint32),
        ("ring_buffer_available", c_uint64),
        ("total_pushed", c_uint64),
        ("total_popped", c_uint64),
        ("total_dropped", c_uint64),
        ("total_shadows_captured", c_uint64),
        ("total_rst_injected", c_uint64),
    ]

class PacketShadow(Structure):
    _fields_ = [
        ("pid", c_uint32),
        ("local_ip", c_uint32),
        ("local_port", c_uint16),
        ("remote_ip", c_uint32),
        ("remote_port", c_uint16),
        ("protocol", c_uint8),
        ("tcp_state", c_uint8),
        ("flags", c_uint8),
        ("reserved", c_uint8),
        ("payload_bytes", c_uint32),
        ("timestamp_ms", c_uint64),
    ]

class KPerfBridge:
    def __init__(self):
        self.dll = None
        self.is_loaded = False
        self._init_dll()

    def _init_dll(self):
        if not IS_WINDOWS:
            return

        # Target locations for kperf_core.dll
        possible_paths = [
            Path(__file__).resolve().parent / "target" / "release" / "kperf_core.dll",
            Path(__file__).resolve().parent / "kperf_core.dll",
            Path(__file__).resolve().parent.parent / "native" / "kperf_core.dll"
        ]

        for p in possible_paths:
            if p.exists():
                try:
                    self.dll = ctypes.cdll.LoadLibrary(str(p))
                    self._setup_function_signatures()
                    self.is_loaded = True
                    print(f"[kPerf Core] Rust Kernel Hypervisor loaded from {p.name}")
                    break
                except Exception as e:
                    print(f"[kPerf Core Error] Failed to load DLL from {p}: {e}")

    def _setup_function_signatures(self):
        if not self.dll:
            return
        
        # kperf_init() -> i32
        self.dll.kperf_init.restype = c_int32
        self.dll.kperf_init.argtypes = []

        # kperf_start() -> i32
        self.dll.kperf_start.restype = c_int32
        self.dll.kperf_start.argtypes = []

        # kperf_stop() -> i32
        self.dll.kperf_stop.restype = c_int32
        self.dll.kperf_stop.argtypes = []

        # kperf_get_stats(*mut HypervisorStats) -> i32
        self.dll.kperf_get_stats.restype = c_int32
        self.dll.kperf_get_stats.argtypes = [POINTER(HypervisorStats)]

        # kperf_pop_shadow(*mut PacketShadow) -> i32
        self.dll.kperf_pop_shadow.restype = c_int32
        self.dll.kperf_pop_shadow.argtypes = [POINTER(PacketShadow)]

        # kperf_kill_socket(local_ip, local_port, remote_ip, remote_port) -> i32
        self.dll.kperf_kill_socket.restype = c_int32
        self.dll.kperf_kill_socket.argtypes = [c_uint32, c_uint16, c_uint32, c_uint16]

        # kperf_kill_pid(pid) -> u32
        self.dll.kperf_kill_pid.restype = c_uint32
        self.dll.kperf_kill_pid.argtypes = [c_uint32]

        # kperf_kill_remote_ip(remote_ip) -> u32
        self.dll.kperf_kill_remote_ip.restype = c_uint32
        self.dll.kperf_kill_remote_ip.argtypes = [c_uint32]

        # kperf_panic_kill_all() -> u32
        self.dll.kperf_panic_kill_all.restype = c_uint32
        self.dll.kperf_panic_kill_all.argtypes = []

        # kperf_flush_dns() -> i32
        self.dll.kperf_flush_dns.restype = c_int32
        self.dll.kperf_flush_dns.argtypes = []

        # kperf_send_arp(target_ip, *mut u8) -> i32
        self.dll.kperf_send_arp.restype = c_int32
        self.dll.kperf_send_arp.argtypes = [c_uint32, POINTER(c_uint8 * 6)]

        # kperf_get_gateway_info(*mut u32, *mut u8, *mut u32) -> i32
        self.dll.kperf_get_gateway_info.restype = c_int32
        self.dll.kperf_get_gateway_info.argtypes = [POINTER(c_uint32), POINTER(c_uint8 * 6), POINTER(c_uint32)]

    def start(self) -> bool:
        if self.is_loaded and self.dll:
            return self.dll.kperf_start() == 1
        return False

    def stop(self) -> bool:
        if self.is_loaded and self.dll:
            return self.dll.kperf_stop() == 1
        return False

    def get_stats(self) -> Dict[str, Any]:
        if not self.is_loaded or not self.dll:
            return {
                "is_running": False,
                "ring_buffer_available": 0,
                "total_pushed": 0,
                "total_popped": 0,
                "total_dropped": 0,
                "total_shadows_captured": 0,
                "total_rst_injected": 0,
                "engine": "Win32 Native Direct"
            }

        stats = HypervisorStats()
        if self.dll.kperf_get_stats(byref(stats)) == 0:
            return {
                "is_running": bool(stats.is_running),
                "ring_buffer_available": stats.ring_buffer_available,
                "total_pushed": stats.total_pushed,
                "total_popped": stats.total_popped,
                "total_dropped": stats.total_dropped,
                "total_shadows_captured": stats.total_shadows_captured,
                "total_rst_injected": stats.total_rst_injected,
                "engine": "Rust kPerf Kernel Hypervisor"
            }
        return {"is_running": False}

    def pop_shadows(self, max_count: int = 100) -> List[Dict[str, Any]]:
        results = []
        if not self.is_loaded or not self.dll:
            return results

        shadow = PacketShadow()
        for _ in range(max_count):
            if self.dll.kperf_pop_shadow(byref(shadow)) == 1:
                loc_ip = socket.inet_ntoa(struct.pack("I", shadow.local_ip))
                rem_ip = socket.inet_ntoa(struct.pack("I", shadow.remote_ip))
                results.append({
                    "pid": shadow.pid,
                    "local_ip": loc_ip,
                    "local_port": shadow.local_port,
                    "remote_ip": rem_ip,
                    "remote_port": shadow.remote_port,
                    "protocol": "TCP" if shadow.protocol == 6 else "UDP",
                    "tcp_state": shadow.tcp_state,
                    "timestamp_ms": shadow.timestamp_ms
                })
            else:
                break
        return results

    def kill_pid(self, pid: int) -> int:
        if self.is_loaded and self.dll:
            return int(self.dll.kperf_kill_pid(c_uint32(pid)))
        return 0

    def kill_remote_ip(self, ip_str: str) -> int:
        if self.is_loaded and self.dll:
            try:
                ip_val = struct.unpack("I", socket.inet_aton(ip_str))[0]
                return int(self.dll.kperf_kill_remote_ip(c_uint32(ip_val)))
            except Exception:
                pass
        return 0

    def panic_kill_all(self) -> int:
        if self.is_loaded and self.dll:
            return int(self.dll.kperf_panic_kill_all())
        return 0

    def flush_dns(self) -> bool:
        if self.is_loaded and self.dll:
            return self.dll.kperf_flush_dns() == 1
        return False

kperf = KPerfBridge()
