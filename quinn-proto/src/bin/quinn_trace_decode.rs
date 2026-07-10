//! Offline decoder for Quinn send-path trace files (QSPT format).
//!
//! Usage: quinn-trace-decode <trace_file> [--summary] [--csv]

use std::io::Read;
use std::path::PathBuf;

const RECORD_SIZE: usize = 48;

#[repr(C)]
#[derive(Clone, Copy)]
struct TraceRecord {
    ts_ns: u64,
    event: u8,
    reason: u8,
    _pad: [u8; 6],
    val0: u64,
    val1: u64,
    val2: u64,
    val3: u64,
}

fn event_name(e: u8) -> &'static str {
    match e {
        1 => "PollTransmitExit",
        2 => "PacingBlocked",
        3 => "CongestionBlocked",
        4 => "DatagramCapReached",
        5 => "NoData",
        6 => "WriteBlocked",
        7 => "MaxDataReceived",
        8 => "MaxStreamDataReceived",
        9 => "StreamDataQueued",
        _ => "Unknown",
    }
}

fn reason_name(event: u8, reason: u8) -> &'static str {
    match event {
        1 | 2 | 3 | 4 => match reason {
            0 => "Complete",
            1 => "PacingBlocked",
            2 => "CongestionBlocked",
            3 => "DatagramCap",
            4 => "AntiAmplification",
            _ => "Unknown",
        },
        _ => "-",
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: quinn-trace-decode <trace_file> [--summary] [--csv]");
        std::process::exit(1);
    }
    let path = PathBuf::from(&args[1]);
    let summary_only = args.iter().any(|a| a == "--summary");
    let csv = args.iter().any(|a| a == "--csv");

    let mut file = std::fs::File::open(&path).expect("failed to open trace file");
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)
        .expect("failed to read trace file");

    // Parse header
    if buf.len() < 32 {
        eprintln!("File too small for header");
        std::process::exit(1);
    }
    let magic = &buf[0..4];
    if magic != b"QSPT" {
        eprintln!("Invalid magic: {:?}", magic);
        std::process::exit(1);
    }
    let version = u32::from_le_bytes(buf[4..8].try_into().unwrap());
    let count = u64::from_le_bytes(buf[8..16].try_into().unwrap()) as usize;
    let total = u64::from_le_bytes(buf[16..24].try_into().unwrap());
    let _start_slot = u64::from_le_bytes(buf[24..32].try_into().unwrap());

    eprintln!(
        "QSPT v{version} — {count} records, {total} total events, wrapped={}",
        total as usize > count
    );

    let data = &buf[32..];
    if data.len() < count * RECORD_SIZE {
        eprintln!(
            "Data too small: expected {} bytes, got {}",
            count * RECORD_SIZE,
            data.len()
        );
        std::process::exit(1);
    }

    // Parse records
    let mut records: Vec<TraceRecord> = Vec::with_capacity(count);
    for i in 0..count {
        let offset = i * RECORD_SIZE;
        let rec: TraceRecord =
            unsafe { std::ptr::read(data[offset..].as_ptr() as *const TraceRecord) };
        records.push(rec);
    }

    // Summary counts
    let mut event_counts = [0u64; 16];
    let mut write_blocked_count = 0u64;
    let mut max_data_received_count = 0u64;
    let mut pacing_blocked_total_ns = 0u64;
    let mut max_peer_max_data = 0u64;

    for r in &records {
        if (r.event as usize) < event_counts.len() {
            event_counts[r.event as usize] += 1;
        }
        match r.event {
            6 => {
                write_blocked_count += 1;
            }
            7 => {
                max_data_received_count += 1;
                max_peer_max_data = max_peer_max_data.max(r.val0);
            }
            2 => {
                pacing_blocked_total_ns += r.val0;
            }
            _ => {}
        }
    }

    eprintln!("\n--- Event Counts ---");
    for (i, &c) in event_counts.iter().enumerate() {
        if c > 0 {
            eprintln!("  {:24} : {}", event_name(i as u8), c);
        }
    }
    eprintln!("\n--- Summary ---");
    eprintln!("  WriteBlocked events    : {write_blocked_count}");
    eprintln!("  MaxDataReceived events : {max_data_received_count}");
    eprintln!(
        "  Max peer_max_data      : {} bytes ({:.2} MiB)",
        max_peer_max_data,
        max_peer_max_data as f64 / (1024.0 * 1024.0)
    );
    eprintln!(
        "  PacingBlocked total    : {pacing_blocked_total_ns} ns ({:.3} ms)",
        pacing_blocked_total_ns as f64 / 1_000_000.0
    );

    if summary_only {
        return;
    }

    // Detail output
    if csv {
        println!("ts_ns,event,reason,val0,val1,val2,val3");
        for r in &records {
            println!(
                "{},{},{},{},{},{},{}",
                r.ts_ns,
                event_name(r.event),
                reason_name(r.event, r.reason),
                r.val0,
                r.val1,
                r.val2,
                r.val3
            );
        }
    } else {
        for (i, r) in records.iter().enumerate() {
            let ts_ms = r.ts_ns as f64 / 1_000_000.0;
            println!(
                "[{:8}] {:7.3}ms {:24} reason={:20} val0={:>14} val1={:>14} val2={:>14} val3={:>14}",
                i,
                ts_ms,
                event_name(r.event),
                reason_name(r.event, r.reason),
                r.val0,
                r.val1,
                r.val2,
                r.val3
            );
        }
    }
}
