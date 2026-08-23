// SwitchGate kPerf - Global Hypervisor State & Lock-Free Coordinator

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::kernel_hooks::capture_tcp_shadows;
use crate::ring_buffer::LockFreeRingBuffer;

pub struct HypervisorState {
    pub ring_buffer: Mutex<LockFreeRingBuffer>,
    pub is_running: AtomicBool,
    pub total_shadows_captured: AtomicU64,
    pub total_rst_injected: AtomicU64,
    worker_handle: Mutex<Option<JoinHandle<()>>>,
}

impl HypervisorState {
    pub fn new() -> Self {
        Self {
            ring_buffer: Mutex::new(LockFreeRingBuffer::new()),
            is_running: AtomicBool::new(false),
            total_shadows_captured: AtomicU64::new(0),
            total_rst_injected: AtomicU64::new(0),
            worker_handle: Mutex::new(None),
        }
    }

    pub fn start(&'static self) {
        if self.is_running.swap(true, Ordering::SeqCst) {
            return; // Already running
        }

        let handle = thread::spawn(move || {
            while self.is_running.load(Ordering::Relaxed) {
                let shadows = capture_tcp_shadows();
                let count = shadows.len() as u64;

                if let Ok(mut rb) = self.ring_buffer.lock() {
                    for s in shadows {
                        rb.push(s);
                    }
                }
                self.total_shadows_captured.fetch_add(count, Ordering::Relaxed);

                thread::sleep(Duration::from_millis(500)); // 2 Hz lightweight kernel sweep
            }
        });

        if let Ok(mut lock) = self.worker_handle.lock() {
            *lock = Some(handle);
        }
    }

    pub fn stop(&self) {
        self.is_running.store(false, Ordering::SeqCst);
    }
}

pub static GLOBAL_HYPERVISOR: std::sync::LazyLock<HypervisorState> =
    std::sync::LazyLock::new(|| HypervisorState::new());
