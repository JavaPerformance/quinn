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
pub const RECORD_SIZE: usize = size_of::<TraceRecord>();
const _: () = assert!(RECORD_SIZE == 48);

use std::mem::size_of;

// --- Runtime implementation (only compiled with send-path-trace feature) ---

#[cfg(feature = "send-path-trace")]
mod runtime {
    use super::*;
    use std::hint::spin_loop;
    use std::sync::{
        OnceLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    };
    use std::time::Instant;

    /// Ring buffer capacity (1M records ≈ 48 MB)
    const RING_CAPACITY: usize = 1 << 20;
    const RING_MASK: usize = RING_CAPACITY - 1;

    #[derive(Default)]
    struct TraceSlot {
        writing: AtomicBool,
        generation: AtomicU64,
        ts_ns: AtomicU64,
        metadata: AtomicU64,
        val0: AtomicU64,
        val1: AtomicU64,
        val2: AtomicU64,
        val3: AtomicU64,
    }

    impl TraceSlot {
        fn store(&self, generation: u64, record: TraceRecord) {
            while self
                .writing
                .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                spin_loop();
            }

            // Invalidate the previous record before replacing its fields.
            self.generation.store(0, Ordering::Release);
            self.ts_ns.store(record.ts_ns, Ordering::Relaxed);
            self.metadata.store(
                u64::from(record.event) | (u64::from(record.reason) << 8),
                Ordering::Relaxed,
            );
            self.val0.store(record.val0, Ordering::Relaxed);
            self.val1.store(record.val1, Ordering::Relaxed);
            self.val2.store(record.val2, Ordering::Relaxed);
            self.val3.store(record.val3, Ordering::Relaxed);
            self.generation.store(generation, Ordering::Release);
            self.writing.store(false, Ordering::Release);
        }

        fn load(&self, expected_generation: u64) -> Option<TraceRecord> {
            if self.generation.load(Ordering::Acquire) != expected_generation {
                return None;
            }

            let ts_ns = self.ts_ns.load(Ordering::Relaxed);
            let metadata = self.metadata.load(Ordering::Relaxed);
            let record = TraceRecord {
                ts_ns,
                event: metadata as u8,
                reason: (metadata >> 8) as u8,
                _pad: [0; 6],
                val0: self.val0.load(Ordering::Relaxed),
                val1: self.val1.load(Ordering::Relaxed),
                val2: self.val2.load(Ordering::Relaxed),
                val3: self.val3.load(Ordering::Relaxed),
            };

            (self.generation.load(Ordering::Acquire) == expected_generation).then_some(record)
        }
    }

    struct TraceState {
        ring: Box<[TraceSlot]>,
        cursor: AtomicUsize,
        start: Instant,
    }

    static TRACE: OnceLock<TraceState> = OnceLock::new();

    /// Initialize the global trace ring. Call once at startup.
    pub fn init() -> bool {
        let ring = (0..RING_CAPACITY)
            .map(|_| TraceSlot::default())
            .collect::<Vec<_>>()
            .into_boxed_slice();
        TRACE
            .set(TraceState {
                ring,
                cursor: AtomicUsize::new(0),
                start: Instant::now(),
            })
            .is_ok()
    }

    /// Record a trace event. Lock-free, no heap allocation.
    #[inline(always)]
    pub fn record(event: SendPathEvent, reason: u8, val0: u64, val1: u64, val2: u64, val3: u64) {
        let Some(state) = TRACE.get() else {
            return;
        };
        let ticket = state.cursor.fetch_add(1, Ordering::Relaxed);
        let slot = ticket & RING_MASK;
        let ts_ns = state.start.elapsed().as_nanos() as u64;
        state.ring[slot].store(
            ticket as u64 + 1,
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

    /// Dump the ring buffer contents to a binary file.
    pub fn dump_to_file(path: &std::path::Path) -> std::io::Result<DumpStats> {
        use std::io::Write;

        let Some(state) = TRACE.get() else {
            return Ok(DumpStats {
                records_written: 0,
                total_events: 0,
                wrapped: false,
            });
        };

        let total = state.cursor.load(Ordering::Acquire) as u64;
        let wrapped = total as usize > RING_CAPACITY;
        let first_ticket = total.saturating_sub(RING_CAPACITY as u64);
        let start_slot = first_ticket as usize & RING_MASK;
        let records = (first_ticket..total)
            .filter_map(|ticket| {
                state.ring[ticket as usize & RING_MASK].load(ticket.wrapping_add(1))
            })
            .collect::<Vec<_>>();

        let mut file = std::fs::File::create(path)?;

        // Header: magic(4) + version(4) + count(8) + total(8) + start_slot(8)
        file.write_all(b"QSPT")?;
        file.write_all(&1u32.to_le_bytes())?;
        file.write_all(&(records.len() as u64).to_le_bytes())?;
        file.write_all(&total.to_le_bytes())?;
        file.write_all(&(start_slot as u64).to_le_bytes())?;

        for record in &records {
            file.write_all(&record.ts_ns.to_le_bytes())?;
            file.write_all(&[record.event, record.reason])?;
            file.write_all(&record._pad)?;
            file.write_all(&record.val0.to_le_bytes())?;
            file.write_all(&record.val1.to_le_bytes())?;
            file.write_all(&record.val2.to_le_bytes())?;
            file.write_all(&record.val3.to_le_bytes())?;
        }

        Ok(DumpStats {
            records_written: records.len() as u64,
            total_events: total,
            wrapped,
        })
    }

    /// Statistics returned by [`dump_to_file`]
    #[derive(Debug)]
    pub struct DumpStats {
        /// Records written to the dump file
        pub records_written: u64,
        /// Events observed before the dump snapshot, including overwritten records
        pub total_events: u64,
        /// Whether the ring wrapped before the dump snapshot
        pub wrapped: bool,
    }
}

#[cfg(feature = "send-path-trace")]
pub use runtime::*;
