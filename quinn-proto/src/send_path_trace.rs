//! Lightweight binary send-path trace for diagnosing throughput ceilings.
//!
//! When the `send-path-trace` feature is enabled, key decision points in the
//! send path append fixed-size records to a global lock-free ring buffer.
//! After the run, call [`dump_to_file`] to write the buffer to disk, then
//! decode offline with `quinn-trace-decode`.
//!
//! When the feature is disabled, only the enum definitions are compiled (so
//! instrumentation call sites can reference them without cfg guards). The
//! `send_path_trace!` macro compiles to nothing.
//!
//! Design:
//! - No heap allocation on the hot path
//! - No locks (atomic fetch_add for slot acquisition)
//! - Fixed 48-byte records, 1M slot ring (~48 MB)
//! - Records overwrite silently on wrap (ring, not growable)

/// Event types recorded in the send path
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendPathEvent {
    /// poll_transmit exited — datagrams_emitted, exit_reason
    PollTransmitExit = 1,
    /// Pacing blocked poll_transmit — delay_ns
    PacingBlocked = 2,
    /// Congestion control blocked poll_transmit
    CongestionBlocked = 3,
    /// Datagram cap reached (MAX_TRANSMIT_DATAGRAMS)
    DatagramCapReached = 4,
    /// No more data to send
    NoData = 5,
    /// write_source returned Blocked — limit was zero
    WriteBlocked = 6,
    /// MAX_DATA received from peer — new limit
    MaxDataReceived = 7,
    /// MAX_STREAM_DATA received from peer
    MaxStreamDataReceived = 8,
    /// Stream data written into send buffer
    StreamDataQueued = 9,
}

/// Exit reasons for poll_transmit
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PollTransmitExitReason {
    /// Normal completion (no more data or space)
    Complete = 0,
    /// Pacer blocked
    PacingBlocked = 1,
    /// Congestion window full
    CongestionBlocked = 2,
    /// MAX_TRANSMIT_DATAGRAMS cap
    DatagramCap = 3,
    /// Anti-amplification limit
    AntiAmplification = 4,
}

/// Fixed-size 48-byte trace record
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TraceRecord {
    /// Nanoseconds since trace start
    pub ts_ns: u64,
    /// Event type
    pub event: u8,
    /// Sub-reason / exit reason
    pub reason: u8,
    /// Padding for alignment
    pub _pad: [u8; 6],
    /// Primary value (meaning depends on event)
    pub val0: u64,
    /// Secondary value
    pub val1: u64,
    /// Tertiary value
    pub val2: u64,
    /// Quaternary value
    pub val3: u64,
}

/// Record size in bytes
pub const RECORD_SIZE: usize = std::mem::size_of::<TraceRecord>();
const _: () = assert!(RECORD_SIZE == 48);

// --- Runtime implementation (only compiled with send-path-trace feature) ---

#[cfg(feature = "send-path-trace")]
mod runtime {
    use super::*;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::time::Instant;

    /// Ring buffer capacity (1M records ≈ 48 MB)
    const RING_CAPACITY: usize = 1 << 20;
    const RING_MASK: usize = RING_CAPACITY - 1;

    struct TraceState {
        ring: Box<[TraceRecord]>,
        cursor: AtomicUsize,
        start: Instant,
        total_written: AtomicU64,
    }

    static mut TRACE: Option<TraceState> = None;
    static INITIALIZED: AtomicUsize = AtomicUsize::new(0);

    /// Initialize the global trace ring. Call once at startup.
    pub fn init() -> bool {
        if INITIALIZED
            .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return false;
        }
        let ring = vec![
            TraceRecord {
                ts_ns: 0,
                event: 0,
                reason: 0,
                _pad: [0; 6],
                val0: 0,
                val1: 0,
                val2: 0,
                val3: 0,
            };
            RING_CAPACITY
        ]
        .into_boxed_slice();
        // SAFETY: protected by atomic compare_exchange — only one thread can reach here
        unsafe {
            TRACE = Some(TraceState {
                ring,
                cursor: AtomicUsize::new(0),
                start: Instant::now(),
                total_written: AtomicU64::new(0),
            });
        }
        true
    }

    /// Record a trace event. Lock-free, no heap allocation.
    #[inline(always)]
    pub fn record(
        event: SendPathEvent,
        reason: u8,
        val0: u64,
        val1: u64,
        val2: u64,
        val3: u64,
    ) {
        if INITIALIZED.load(Ordering::Relaxed) != 1 {
            return;
        }
        // SAFETY: TRACE is Some when INITIALIZED == 1, never deallocated
        let state = unsafe { TRACE.as_ref().unwrap_unchecked() };
        let slot = state.cursor.fetch_add(1, Ordering::Relaxed) & RING_MASK;
        let ts_ns = state.start.elapsed().as_nanos() as u64;
        // SAFETY: slot is always in bounds due to RING_MASK
        unsafe {
            let ptr = state.ring.as_ptr().add(slot) as *mut TraceRecord;
            std::ptr::write(
                ptr,
                TraceRecord {
                    ts_ns,
                    event: event as u8,
                    reason,
                    _pad: [0; 6],
                    val0,
                    val1,
                    val2,
                    val3,
                },
            );
        }
        state.total_written.fetch_add(1, Ordering::Relaxed);
    }

    /// Dump the ring buffer contents to a binary file.
    pub fn dump_to_file(path: &std::path::Path) -> std::io::Result<DumpStats> {
        use std::io::Write;

        if INITIALIZED.load(Ordering::Relaxed) != 1 {
            return Ok(DumpStats {
                records_written: 0,
                total_events: 0,
                wrapped: false,
            });
        }

        let state = unsafe { TRACE.as_ref().unwrap_unchecked() };
        let total = state.total_written.load(Ordering::Relaxed);
        let wrapped = total as usize > RING_CAPACITY;
        let count = if wrapped { RING_CAPACITY } else { total as usize };
        let start_slot = if wrapped {
            state.cursor.load(Ordering::Relaxed) & RING_MASK
        } else {
            0
        };

        let mut file = std::fs::File::create(path)?;

        // Header: magic(4) + version(4) + count(8) + total(8) + start_slot(8)
        file.write_all(b"QSPT")?;
        file.write_all(&1u32.to_le_bytes())?;
        file.write_all(&(count as u64).to_le_bytes())?;
        file.write_all(&total.to_le_bytes())?;
        file.write_all(&(start_slot as u64).to_le_bytes())?;

        for i in 0..count {
            let slot = (start_slot + i) & RING_MASK;
            let record = unsafe { &*state.ring.as_ptr().add(slot) };
            let bytes: &[u8] = unsafe {
                std::slice::from_raw_parts(
                    record as *const TraceRecord as *const u8,
                    RECORD_SIZE,
                )
            };
            file.write_all(bytes)?;
        }

        Ok(DumpStats {
            records_written: count as u64,
            total_events: total,
            wrapped,
        })
    }

    /// Statistics returned by [`dump_to_file`]
    #[derive(Debug)]
    pub struct DumpStats {
        pub records_written: u64,
        pub total_events: u64,
        pub wrapped: bool,
    }
}

#[cfg(feature = "send-path-trace")]
pub use runtime::*;
