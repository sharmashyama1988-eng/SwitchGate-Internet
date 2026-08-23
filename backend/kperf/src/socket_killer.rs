// SwitchGate kPerf - Socket Circuit Breaker & Kernel Terminator
// Instantly terminates TCP streams using MIB_TCP_STATE_DELETE_TCB (State 12) via SetTcpEntry.

use crate::kernel_hooks::{GetExtendedTcpTable, SetTcpEntry, DWORD, MibTcpRowOwnerPid, PVOID};
use std::mem::size_of;

#[repr(C)]
#[derive(Copy, Clone)]
struct MibTcpRow {
    dw_state: DWORD, // 12 = MIB_TCP_STATE_DELETE_TCB
    dw_local_addr: DWORD,
    dw_local_port: DWORD,
    dw_remote_addr: DWORD,
    dw_remote_port: DWORD,
}

/// Kills a single TCP connection by sending kernel TCP RST and deleting the TCB block.
pub fn kill_tcp_connection(local_ip: u32, local_port: u16, remote_ip: u32, remote_port: u16) -> bool {
    let row = MibTcpRow {
        dw_state: 12, // MIB_TCP_STATE_DELETE_TCB
        dw_local_addr: local_ip,
        dw_local_port: (u16::to_be(local_port) as DWORD),
        dw_remote_addr: remote_ip,
        dw_remote_port: (u16::to_be(remote_port) as DWORD),
    };

    unsafe {
        let ret = SetTcpEntry(&row as *const _ as PVOID);
        ret == 0
    }
}

/// Terminates all active TCP connections owned by a target Process ID (PID).
pub fn kill_sockets_by_pid(target_pid: u32) -> u32 {
    let mut killed_count = 0;
    let mut size: DWORD = 0;

    unsafe {
        let _ = GetExtendedTcpTable(std::ptr::null_mut(), &mut size, 1, 2, 5, 0);
        if size == 0 {
            return 0;
        }

        let mut buffer: Vec<u8> = vec![0u8; size as usize];
        if GetExtendedTcpTable(buffer.as_mut_ptr() as PVOID, &mut size, 1, 2, 5, 0) != 0 {
            return 0;
        }

        let num_entries = *(buffer.as_ptr() as *const DWORD);
        let row_size = size_of::<MibTcpRowOwnerPid>();
        let mut offset = 4;

        for _ in 0..num_entries {
            if offset + row_size > buffer.len() {
                break;
            }
            let row = *(buffer.as_ptr().add(offset) as *const MibTcpRowOwnerPid);
            offset += row_size;

            if row.dw_owning_pid == target_pid {
                let rst_row = MibTcpRow {
                    dw_state: 12,
                    dw_local_addr: row.dw_local_addr,
                    dw_local_port: row.dw_local_port,
                    dw_remote_addr: row.dw_remote_addr,
                    dw_remote_port: row.dw_remote_port,
                };
                if SetTcpEntry(&rst_row as *const _ as PVOID) == 0 {
                    killed_count += 1;
                }
            }
        }
    }

    killed_count
}

/// Terminates all active TCP connections to a specific Remote IP.
pub fn kill_sockets_by_remote_ip(target_ip: u32) -> u32 {
    let mut killed_count = 0;
    let mut size: DWORD = 0;

    unsafe {
        let _ = GetExtendedTcpTable(std::ptr::null_mut(), &mut size, 1, 2, 5, 0);
        if size == 0 {
            return 0;
        }

        let mut buffer: Vec<u8> = vec![0u8; size as usize];
        if GetExtendedTcpTable(buffer.as_mut_ptr() as PVOID, &mut size, 1, 2, 5, 0) != 0 {
            return 0;
        }

        let num_entries = *(buffer.as_ptr() as *const DWORD);
        let row_size = size_of::<MibTcpRowOwnerPid>();
        let mut offset = 4;

        for _ in 0..num_entries {
            if offset + row_size > buffer.len() {
                break;
            }
            let row = *(buffer.as_ptr().add(offset) as *const MibTcpRowOwnerPid);
            offset += row_size;

            if row.dw_remote_addr == target_ip {
                let rst_row = MibTcpRow {
                    dw_state: 12,
                    dw_local_addr: row.dw_local_addr,
                    dw_local_port: row.dw_local_port,
                    dw_remote_addr: row.dw_remote_addr,
                    dw_remote_port: row.dw_remote_port,
                };
                if SetTcpEntry(&rst_row as *const _ as PVOID) == 0 {
                    killed_count += 1;
                }
            }
        }
    }

    killed_count
}

/// Master Panic: Instantly terminates all active outbound external TCP sockets on the system.
pub fn kill_all_external_sockets() -> u32 {
    let mut killed_count = 0;
    let mut size: DWORD = 0;

    unsafe {
        let _ = GetExtendedTcpTable(std::ptr::null_mut(), &mut size, 1, 2, 5, 0);
        if size == 0 {
            return 0;
        }

        let mut buffer: Vec<u8> = vec![0u8; size as usize];
        if GetExtendedTcpTable(buffer.as_mut_ptr() as PVOID, &mut size, 1, 2, 5, 0) != 0 {
            return 0;
        }

        let num_entries = *(buffer.as_ptr() as *const DWORD);
        let row_size = size_of::<MibTcpRowOwnerPid>();
        let mut offset = 4;

        for _ in 0..num_entries {
            if offset + row_size > buffer.len() {
                break;
            }
            let row = *(buffer.as_ptr().add(offset) as *const MibTcpRowOwnerPid);
            offset += row_size;

            let rem_ip = row.dw_remote_addr;
            // Skip 0.0.0.0 and 127.0.0.0/8
            if rem_ip == 0 || (rem_ip & 0xFF) == 127 {
                continue;
            }

            let rst_row = MibTcpRow {
                dw_state: 12,
                dw_local_addr: row.dw_local_addr,
                dw_local_port: row.dw_local_port,
                dw_remote_addr: row.dw_remote_addr,
                dw_remote_port: row.dw_remote_port,
            };
            if SetTcpEntry(&rst_row as *const _ as PVOID) == 0 {
                killed_count += 1;
            }
        }
    }

    killed_count
}
