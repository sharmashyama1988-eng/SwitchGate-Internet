// SwitchGate kPerf - Lock-Free Asynchronous Ring Buffer Engine
// Implements zero-copy, atomic bounded SPSC/MPMC metadata shadow queue with zero CPU spikes.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

pub const RING_BUFFER_CAPACITY: usize = 65536; // 64K slots (Power of 2 for fast bitmask wrapping)
const RING_BUFFER_MASK: usize = RING_BUFFER_CAPACITY - 1;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PacketShadow {
    pub pid: u32,
    pub local_ip: u32,
    pub local_port: u16,
    pub remote_ip: u32,
    pub remote_port: u16,
    pub protocol: u8,   // 6 = TCP, 17 = UDP
    pub tcp_state: u8,  // 2 = LISTEN, 5 = ESTABLISHED, 12 = DELETE_TCB, etc.
    pub flags: u8,      // 0x01 = INBOUND, 0x02 = OUTBOUND, 0x04 = BLOCKED
    pub reserved: u8,
    pub payload_bytes: u32,
    pub timestamp_ms: u64,
}

impl Default for PacketShadow {
    fn default() -> Self {
        Self {
            pid: 0,
            local_ip: 0,
            local_port: 0,
            remote_ip: 0,
            remote_port: 0,
            protocol: 0,
            tcp_state: 0,
            flags: 0,
            reserved: 0,
            payload_bytes: 0,
            timestamp_ms: 0,
        }
    }
}

pub struct LockFreeRingBuffer {
    buffer: Box<[PacketShadow; RING_BUFFER_CAPACITY]>,
    head: AtomicUsize,
    tail: AtomicUsize,
    pub total_pushed: AtomicU64,
    pub total_popped: AtomicU64,
    pub total_dropped: AtomicU64,
}

impl LockFreeRingBuffer {
    pub fn new() -> Self {
        // Allocate zeroed on heap
        let boxed_buf = Box::new([PacketShadow::default(); RING_BUFFER_CAPACITY]);
        Self {
            buffer: boxed_buf,
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            total_pushed: AtomicU64::new(0),
            total_popped: AtomicU64::new(0),
            total_dropped: AtomicU64::new(0),
        }
    }

    /// Pushes a packet shadow metadata into the ring buffer without locking.
    #[inline(always)]
    pub fn push(&mut self, shadow: PacketShadow) -> bool {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);

        if head.wrapping_sub(tail) >= RING_BUFFER_CAPACITY {
            // Buffer full, increment dropped counter to preserve strict zero latency
            self.total_dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        let index = head & RING_BUFFER_MASK;
        self.buffer[index] = shadow;
        self.head.store(head.wrapping_add(1), Ordering::Release);
        self.total_pushed.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// Pops a packet shadow metadata from the ring buffer.
    #[inline(always)]
    pub fn pop(&mut self) -> Option<PacketShadow> {
        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Acquire);

        if tail == head {
            return None; // Buffer empty
        }

        let index = tail & RING_BUFFER_MASK;
        let item = self.buffer[index];
        self.tail.store(tail.wrapping_add(1), Ordering::Release);
        self.total_popped.fetch_add(1, Ordering::Relaxed);
        Some(item)
    }

    pub fn available(&self) -> usize {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Relaxed);
        head.wrapping_sub(tail)
    }
}
