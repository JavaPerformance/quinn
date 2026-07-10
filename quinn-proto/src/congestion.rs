//! Logic for controlling the rate at which data is sent

use crate::connection::RttEstimator;
use crate::{Duration, Instant};
use std::any::Any;
use std::sync::Arc;

mod bbr2;
mod bbr3;
mod cubic;
mod new_reno;

pub use bbr2::{Bbr, BbrConfig, BbrV2Config};
pub use bbr3::{Bbr3, Bbr3Config};
pub use cubic::{Cubic, CubicConfig};
pub use new_reno::{NewReno, NewRenoConfig};

/// Congestion signal reported by the QUIC recovery layer.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum CongestionEvent {
    /// One or more ack-eliciting packets were declared lost.
    Loss {
        /// Largest lost packet number in this loss batch, when known.
        largest_lost_packet_number: Option<u64>,
        /// Ack-eliciting bytes declared lost in this loss batch.
        lost_bytes: u64,
    },
    /// ECN congestion-experienced marks were reported by a peer.
    Ecn {
        /// Number of newly reported CE marks in the ACK's ECN counters.
        ce_count: u64,
        /// Largest packet number covered by the ACK carrying the counters.
        largest_acked_packet_number: Option<u64>,
    },
}

/// Common interface for different congestion controllers
pub trait Controller: Send + Sync {
    /// One or more packets were just sent
    #[allow(unused_variables)]
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {}

    /// One packet was just sent
    #[allow(unused_variables)]
    fn on_packet_sent(&mut self, now: Instant, bytes: u16, packet_number: u64) {}

    /// Packet deliveries were confirmed
    ///
    /// `app_limited` indicates whether the connection was blocked on outgoing
    /// application data prior to receiving these acknowledgements.
    #[allow(unused_variables)]
    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        pn: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
    }

    /// Packets are acked in batches, all with the same `now` argument. This indicates one of those batches has completed.
    #[allow(unused_variables)]
    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
    }

    /// Packets were deemed lost or marked congested.
    ///
    /// `in_persistent_congestion` indicates whether all packets sent within the persistent
    /// congestion threshold period ending when the most recent packet in this batch was sent were
    /// lost.
    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        event: CongestionEvent,
        is_persistent_congestion: bool,
    );

    /// One packet was just lost
    #[allow(unused_variables)]
    fn on_packet_lost(&mut self, lost_bytes: u16, packet_number: u64, now: Instant) {}

    /// Packets were incorrectly deemed lost
    ///
    /// This function is called when all packets that were deemed lost (for instance because
    /// of packet reordering) are acknowledged after the congestion event was raised.
    fn on_spurious_congestion_event(&mut self) {}

    /// The known MTU for the current network path has been updated
    fn on_mtu_update(&mut self, new_mtu: u16);

    /// The peer's ACK-frequency parameters have changed
    ///
    /// `ack_eliciting_threshold` is the number of ack-eliciting packets the peer may receive
    /// before being required to send an immediate ACK (per the QUIC ACK frequency extension).
    /// `requested_max_ack_delay` is the maximum delay we asked the peer to wait before sending
    /// an ACK when the threshold hasn't been reached.
    ///
    /// Controllers can use this to refine estimates that depend on peer ACK behavior (e.g.
    /// BBR's offload budget).
    #[allow(unused_variables)]
    fn on_ack_frequency_update(
        &mut self,
        ack_eliciting_threshold: u64,
        requested_max_ack_delay: Duration,
    ) {
    }

    /// Number of ack-eliciting bytes that may be in flight
    fn window(&self) -> u64;

    /// Retrieve implementation-specific metrics used to populate `qlog` traces when they are enabled
    /// This is also used to alter the pacing of the connection with
    /// `pacing_rate` and `send_quantum`
    fn metrics(&self) -> ControllerMetrics {
        ControllerMetrics {
            congestion_window: self.window(),
            ssthresh: None,
            pacing_rate: None,
            send_quantum: None,
        }
    }

    /// Duplicate the controller's state
    fn clone_box(&self) -> Box<dyn Controller>;

    /// Initial congestion window
    fn initial_window(&self) -> u64;

    /// Returns Self for use in down-casting to extract implementation details
    fn into_any(self: Box<Self>) -> Box<dyn Any>;
}

/// Common congestion controller metrics used both for logging purposes
/// but also to alter the pacing of the connection with
/// `pacing_rate` and `send_quantum`
#[derive(Default)]
#[non_exhaustive]
pub struct ControllerMetrics {
    /// Congestion window (bytes)
    pub congestion_window: u64,
    /// Slow start threshold (bytes)
    pub ssthresh: Option<u64>,
    /// Pacing rate (bytes/s)
    pub pacing_rate: Option<u64>,
    /// Send Quantum (bytes) used to control the size of packet bursts
    pub send_quantum: Option<u64>,
}

/// Constructs controllers on demand
pub trait ControllerFactory {
    /// Construct a fresh `Controller`
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller>;
}

const BASE_DATAGRAM_SIZE: u64 = 1200;
