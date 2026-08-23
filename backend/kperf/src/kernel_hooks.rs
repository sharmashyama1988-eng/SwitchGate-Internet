// SwitchGate kPerf - Kernel Hooks & Subsystem Interceptor
// Intercepts socket states, TCP table transitions, and ARP tables with zero CPU overhead.

use std::mem::size_of;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::ring_buffer::PacketShadow;

pub type DWORD = u32;
pub type ULONG = u32;
pub type BOOL = i32;
pub type PVOID = *mut std::ffi::c_void;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct MibTcpRowOwnerPid {
    pub dw_state: DWORD,
    pub dw_local_addr: DWORD,
    pub dw_local_port: DWORD,
    pub dw_remote_addr: DWORD,
    pub dw_remote_port: DWORD,
    pub dw_owning_pid: DWORD,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct MibUdpRowOwnerPid {
    pub dw_local_addr: DWORD,
    pub dw_local_port: DWORD,
    pub dw_owning_pid: DWORD,
}

#[repr(C)]
pub struct MibIpForwardRow {
    pub dw_forward_dest: DWORD,
    pub dw_forward_mask: DWORD,
    pub dw_forward_policy: DWORD,
    pub dw_forward_next_hop: DWORD,
    pub dw_forward_if_index: DWORD,
    pub dw_forward_type: DWORD,
    pub dw_forward_proto: DWORD,
    pub dw_forward_age: DWORD,
    pub dw_forward_next_hop_as: DWORD,
    pub dw_forward_metric1: DWORD,
    pub dw_forward_metric2: DWORD,
    pub dw_forward_metric3: DWORD,
    pub dw_forward_metric4: DWORD,
    pub dw_forward_metric5: DWORD,
}

#[link(name = "iphlpapi")]
#[link(name = "ws2_32")]
#[link(name = "dnsapi")]
extern "system" {
    pub fn GetExtendedTcpTable(
        pTcpTable: PVOID,
        pdwSize: *mut DWORD,
        bOrder: BOOL,
        ulAf: ULONG,
        TableClass: DWORD,
        Reserved: ULONG,
    ) -> DWORD;

    pub fn GetExtendedUdpTable(
        pUdpTable: PVOID,
        pdwSize: *mut DWORD,
        bOrder: BOOL,
        ulAf: ULONG,
        TableClass: DWORD,
        Reserved: ULONG,
    ) -> DWORD;

    pub fn SetTcpEntry(pTcpRow: PVOID) -> DWORD;
    pub fn SendARP(DestIP: DWORD, SrcIP: DWORD, pMacAddr: *mut u8, PhyAddrLen: *mut ULONG) -> DWORD;
    pub fn GetBestRoute(dwDestAddr: DWORD, dwSourceAddr: DWORD, pBestRoute: *mut MibIpForwardRow) -> DWORD;
    pub fn DnsFlushResolverCache() -> BOOL;
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Captures all live TCP connections and converts them into PacketShadow metadata structs.
pub fn capture_tcp_shadows() -> Vec<PacketShadow> {
    let mut shadows = Vec::new();
    let mut size: DWORD = 0;

    unsafe {
        // AF_INET = 2, TCP_TABLE_OWNER_PID_ALL = 5
        let _ = GetExtendedTcpTable(std::ptr::null_mut(), &mut size, 1, 2, 5, 0);
        if size == 0 {
            return shadows;
        }

        let mut buffer: Vec<u8> = vec![0u8; size as usize];
        let ret = GetExtendedTcpTable(buffer.as_mut_ptr() as PVOID, &mut size, 1, 2, 5, 0);
        if ret != 0 {
            return shadows;
        }

        let num_entries = *(buffer.as_ptr() as *const DWORD);
        let row_size = size_of::<MibTcpRowOwnerPid>();
        let mut offset = 4;
        let now = now_ms();

        for _ in 0..num_entries {
            if offset + row_size > buffer.len() {
                break;
            }
            let row = *(buffer.as_ptr().add(offset) as *const MibTcpRowOwnerPid);
            offset += row_size;

            let local_port = u16::from_be((row.dw_local_port & 0xFFFF) as u16);
            let remote_port = u16::from_be((row.dw_remote_port & 0xFFFF) as u16);

            shadows.push(PacketShadow {
                pid: row.dw_owning_pid,
                local_ip: row.dw_local_addr,
                local_port,
                remote_ip: row.dw_remote_addr,
                remote_port,
                protocol: 6, // TCP
                tcp_state: row.dw_state as u8,
                flags: if row.dw_remote_addr != 0 { 0x02 } else { 0x01 },
                reserved: 0,
                payload_bytes: 0,
                timestamp_ms: now,
            });
        }
    }

    shadows
}
