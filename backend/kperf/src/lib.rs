// SwitchGate kPerf - Kernel Hypervisor & Ring Buffer Tracker (Rust Core)
// Exposes high-performance C-ABI FFI functions for Python and Native callers.

pub mod ring_buffer;
pub mod kernel_hooks;
pub mod socket_killer;
pub mod resolver;
pub mod state;

use std::ffi::c_char;
use std::sync::atomic::Ordering;

use crate::kernel_hooks::{DnsFlushResolverCache, GetBestRoute, MibIpForwardRow, SendARP, DWORD, ULONG};
use crate::ring_buffer::PacketShadow;
use crate::socket_killer::{kill_all_external_sockets, kill_sockets_by_pid, kill_sockets_by_remote_ip, kill_tcp_connection};
use crate::state::GLOBAL_HYPERVISOR;

#[repr(C)]
pub struct HypervisorStats {
    pub is_running: u32,
    pub ring_buffer_available: u64,
    pub total_pushed: u64,
    pub total_popped: u64,
    pub total_dropped: u64,
    pub total_shadows_captured: u64,
    pub total_rst_injected: u64,
}

#[no_mangle]
pub extern "C" fn kperf_init() -> i32 {
    0
}

#[no_mangle]
pub extern "C" fn kperf_start() -> i32 {
    GLOBAL_HYPERVISOR.start();
    1
}

#[no_mangle]
pub extern "C" fn kperf_stop() -> i32 {
    GLOBAL_HYPERVISOR.stop();
    1
}

#[no_mangle]
pub extern "C" fn kperf_get_stats(out_stats: *mut HypervisorStats) -> i32 {
    if out_stats.is_null() {
        return -1;
    }

    let is_running = if GLOBAL_HYPERVISOR.is_running.load(Ordering::Relaxed) { 1 } else { 0 };
    let total_shadows = GLOBAL_HYPERVISOR.total_shadows_captured.load(Ordering::Relaxed);
    let total_rst = GLOBAL_HYPERVISOR.total_rst_injected.load(Ordering::Relaxed);

    let (avail, pushed, popped, dropped) = if let Ok(rb) = GLOBAL_HYPERVISOR.ring_buffer.lock() {
        (
            rb.available() as u64,
            rb.total_pushed.load(Ordering::Relaxed),
            rb.total_popped.load(Ordering::Relaxed),
            rb.total_dropped.load(Ordering::Relaxed),
        )
    } else {
        (0, 0, 0, 0)
    };

    unsafe {
        *out_stats = HypervisorStats {
            is_running,
            ring_buffer_available: avail,
            total_pushed: pushed,
            total_popped: popped,
            total_dropped: dropped,
            total_shadows_captured: total_shadows,
            total_rst_injected: total_rst,
        };
    }

    0
}

#[no_mangle]
pub extern "C" fn kperf_pop_shadow(out_shadow: *mut PacketShadow) -> i32 {
    if out_shadow.is_null() {
        return -1;
    }

    if let Ok(mut rb) = GLOBAL_HYPERVISOR.ring_buffer.lock() {
        if let Some(shadow) = rb.pop() {
            unsafe {
                *out_shadow = shadow;
            }
            return 1; // Popped successfully
        }
    }

    0 // Empty
}

#[no_mangle]
pub extern "C" fn kperf_kill_socket(local_ip: u32, local_port: u16, remote_ip: u32, remote_port: u16) -> i32 {
    let success = kill_tcp_connection(local_ip, local_port, remote_ip, remote_port);
    if success {
        GLOBAL_HYPERVISOR.total_rst_injected.fetch_add(1, Ordering::Relaxed);
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn kperf_kill_pid(pid: u32) -> u32 {
    let killed = kill_sockets_by_pid(pid);
    GLOBAL_HYPERVISOR.total_rst_injected.fetch_add(killed as u64, Ordering::Relaxed);
    killed
}

#[no_mangle]
pub extern "C" fn kperf_kill_remote_ip(remote_ip: u32) -> u32 {
    let killed = kill_sockets_by_remote_ip(remote_ip);
    GLOBAL_HYPERVISOR.total_rst_injected.fetch_add(killed as u64, Ordering::Relaxed);
    killed
}

#[no_mangle]
pub extern "C" fn kperf_panic_kill_all() -> u32 {
    let killed = kill_all_external_sockets();
    GLOBAL_HYPERVISOR.total_rst_injected.fetch_add(killed as u64, Ordering::Relaxed);
    killed
}

#[no_mangle]
pub extern "C" fn kperf_flush_dns() -> i32 {
    unsafe {
        let ret = DnsFlushResolverCache();
        if ret != 0 { 1 } else { 0 }
    }
}

#[no_mangle]
pub extern "C" fn kperf_send_arp(target_ip: u32, mac_out: *mut u8) -> i32 {
    if mac_out.is_null() {
        return -1;
    }
    let mut mac_len: ULONG = 6;
    unsafe {
        let ret = SendARP(target_ip, 0, mac_out, &mut mac_len);
        if ret == 0 && mac_len == 6 { 0 } else { -1 }
    }
}

#[no_mangle]
pub extern "C" fn kperf_get_gateway_info(gw_ip_out: *mut u32, gw_mac_out: *mut u8, if_index_out: *mut u32) -> i32 {
    let mut route = MibIpForwardRow {
        dw_forward_dest: 0,
        dw_forward_mask: 0,
        dw_forward_policy: 0,
        dw_forward_next_hop: 0,
        dw_forward_if_index: 0,
        dw_forward_type: 0,
        dw_forward_proto: 0,
        dw_forward_age: 0,
        dw_forward_next_hop_as: 0,
        dw_forward_metric1: 0,
        dw_forward_metric2: 0,
        dw_forward_metric3: 0,
        dw_forward_metric4: 0,
        dw_forward_metric5: 0,
    };

    // 8.8.8.8 in network byte order: 0x08080808
    let dest: DWORD = 0x08080808;
    unsafe {
        if GetBestRoute(dest, 0, &mut route) != 0 {
            return -1;
        }

        if !gw_ip_out.is_null() {
            *gw_ip_out = route.dw_forward_next_hop;
        }
        if !if_index_out.is_null() {
            *if_index_out = route.dw_forward_if_index;
        }
        if !gw_mac_out.is_null() {
            let mut mac_len: ULONG = 6;
            if SendARP(route.dw_forward_next_hop, 0, gw_mac_out, &mut mac_len) != 0 {
                std::ptr::write_bytes(gw_mac_out, 0, 6);
            }
        }
    }

    0
}
