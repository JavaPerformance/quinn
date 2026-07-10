//! BBR congestion control.
//!
//! This module contains Quinn's BBRv1 implementation and an experimental
//! BBRv2 mode based on the IETF BBR congestion-control draft.

use std::any::Any;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::sync::Arc;

use rand::{RngExt, SeedableRng};
use rand_pcg::Pcg32;

use crate::congestion::ControllerMetrics;
use crate::congestion::bbr2::bw_estimation::BandwidthEstimation;
use crate::congestion::bbr2::min_max::MinMax;
use crate::connection::RttEstimator;
use crate::{Duration, Instant};

use super::{BASE_DATAGRAM_SIZE, CongestionEvent, Controller, ControllerFactory};

mod bw_estimation;
mod min_max;

/// Experimental! Use at your own risk.
///
/// Aims for reduced buffer bloat and improved performance over high bandwidth-delay product networks.
/// Based on google's quiche implementation <https://source.chromium.org/chromium/chromium/src/+/master:net/third_party/quiche/src/quic/core/congestion_control/bbr_sender.cc>
/// of BBR <https://datatracker.ietf.org/doc/html/draft-cardwell-iccrg-bbr-congestion-control>.
/// More discussion and links at <https://groups.google.com/g/bbr-dev>.
#[derive(Debug, Clone)]
pub struct Bbr {
    config: Arc<BbrConfig>,
    version: BbrVersion,
    current_mtu: u64,
    max_bandwidth: BandwidthEstimation,
    acked_bytes: u64,
    mode: Mode,
    loss_state: LossState,
    recovery_state: RecoveryState,
    recovery_window: u64,
    is_at_full_bandwidth: bool,
    pacing_gain: f32,
    high_gain: f32,
    drain_gain: f32,
    cwnd_gain: f32,
    high_cwnd_gain: f32,
    last_cycle_start: Option<Instant>,
    current_cycle_offset: u8,
    init_cwnd: u64,
    min_cwnd: u64,
    prev_in_flight_count: u64,
    /// Locally tracked flight size between authoritative recovery-layer updates.
    tracked_in_flight: u64,
    exit_probe_rtt_at: Option<Instant>,
    probe_rtt_last_started_at: Option<Instant>,
    min_rtt: Duration,
    exiting_quiescence: bool,
    pacing_rate: u64,
    max_acked_packet_number: u64,
    max_sent_packet_number: u64,
    end_recovery_at_packet_number: u64,
    cwnd: u64,
    current_round_trip_end_packet_number: u64,
    round_count: u64,
    bw_at_last_round: u64,
    round_wo_bw_gain: u64,
    ack_aggregation: AckAggregationState,
    sent_packets: BTreeMap<u64, BbrSentPacket>,
    delivered_bytes: u64,
    delivered_time: Option<Instant>,
    /// BBRv2 slow-moving inflight upper bound. In V1 this is always `u64::MAX`
    /// so `window()` is unaffected. In V2 it is reduced only while probing for
    /// bandwidth and grown cautiously while later ProbeBW_UP rounds utilize it.
    inflight_hi: u64,
    /// BBRv2 short-term inflight upper bound. This absorbs loss outside
    /// bandwidth-probing phases so random loss does not permanently poison the
    /// long-term path model.
    inflight_lo: u64,
    /// BBRv2 short-term bandwidth upper bound, paired with `inflight_lo`.
    bw_lo: u64,
    /// Approximate inflight level for the most recent congestion signal.
    inflight_latest: u64,
    /// Approximate bandwidth estimate for the most recent congestion signal.
    bw_latest: u64,
    /// Bytes ACKed while probing upward since the last `inflight_hi` increment.
    probe_up_acked: u64,
    /// ProbeBW_UP rounds since the last long-term bound reduction.
    probe_up_rounds: u64,
    probe_bw_phase: ProbeBwPhase,
    bw_probe_samples: bool,
    random_number_generator: Pcg32,
}

impl Bbr {
    /// Construct a state using the given `config` and current time `now`
    pub fn new(config: Arc<BbrConfig>, current_mtu: u16) -> Self {
        Self::new_with_version(config, current_mtu, BbrVersion::V1)
    }

    fn new_with_version(config: Arc<BbrConfig>, current_mtu: u16, version: BbrVersion) -> Self {
        let initial_window = config.initial_window;
        Self {
            config,
            version,
            current_mtu: current_mtu as u64,
            max_bandwidth: BandwidthEstimation::default(),
            acked_bytes: 0,
            mode: Mode::Startup,
            loss_state: Default::default(),
            recovery_state: RecoveryState::NotInRecovery,
            recovery_window: 0,
            is_at_full_bandwidth: false,
            pacing_gain: DEFAULT_HIGH_GAIN,
            high_gain: DEFAULT_HIGH_GAIN,
            drain_gain: 1.0 / DEFAULT_HIGH_GAIN,
            cwnd_gain: DEFAULT_HIGH_GAIN,
            high_cwnd_gain: DEFAULT_HIGH_GAIN,
            last_cycle_start: None,
            current_cycle_offset: 0,
            init_cwnd: initial_window,
            min_cwnd: calculate_min_window(current_mtu as u64),
            prev_in_flight_count: 0,
            tracked_in_flight: 0,
            exit_probe_rtt_at: None,
            probe_rtt_last_started_at: None,
            min_rtt: Default::default(),
            exiting_quiescence: false,
            pacing_rate: 0,
            max_acked_packet_number: 0,
            max_sent_packet_number: 0,
            end_recovery_at_packet_number: 0,
            cwnd: initial_window,
            current_round_trip_end_packet_number: 0,
            round_count: 0,
            bw_at_last_round: 0,
            round_wo_bw_gain: 0,
            ack_aggregation: AckAggregationState::default(),
            sent_packets: BTreeMap::new(),
            delivered_bytes: 0,
            delivered_time: None,
            inflight_hi: u64::MAX,
            inflight_lo: u64::MAX,
            bw_lo: u64::MAX,
            inflight_latest: 0,
            bw_latest: 0,
            probe_up_acked: 0,
            probe_up_rounds: 0,
            probe_bw_phase: ProbeBwPhase::Cruise,
            bw_probe_samples: false,
            random_number_generator: Pcg32::from_rng(&mut rand::rng()),
        }
    }

    /// BBRv2 only: shrink `inflight_hi` in response to a round-level
    /// congestion signal. V1 never calls this (its V1 `has_congestion_losses`
    /// result already reduces `recovery_window` directly).
    ///
    /// `signal_inflight` should be the flight size recorded when the triggering
    /// packet was sent. Following BBRv2's upper-bound adaptation, preserve that
    /// observed flight and use 70% of the model target only as a lower bound.
    fn shrink_inflight_hi_on_signal(&mut self, signal_inflight: u64) {
        debug_assert!(matches!(self.version, BbrVersion::V2));
        let candidate = signal_inflight.max(self.bbrv2_inflight_hi_loss_floor());
        // Never grow the ceiling in the loss handler; ProbeBW_UP grows it back
        // only when the capped inflight level is later utilized without another
        // congestion signal.
        self.inflight_hi = self.inflight_hi.min(candidate);
        self.probe_up_acked = 0;
        self.probe_up_rounds = 0;
    }

    fn bbrv2_inflight_hi_floor(&self) -> u64 {
        // The draft's long-term inflight bound is model-based, not a starvation
        // lever. Do not let it fall below the current BDP estimate.
        self.get_target_cwnd(1.0).max(self.min_cwnd)
    }

    fn bbrv2_inflight_hi_loss_floor(&self) -> u64 {
        self.get_target_cwnd(1.0)
            .saturating_mul(BBR2_BETA_NUMERATOR)
            .saturating_div(BBR2_BETA_DENOMINATOR)
            .max(self.min_cwnd)
    }

    fn bbrv2_effective_bandwidth(&self) -> u64 {
        let mut bw = self.max_bandwidth.get_estimate();
        if matches!(self.version, BbrVersion::V2) {
            if self.bw_lo != u64::MAX && self.bbrv2_uses_short_term_model() {
                bw = bw.min(self.bw_lo);
            }
        }
        bw
    }

    fn bbrv2_is_probing_bandwidth(&self) -> bool {
        matches!(self.version, BbrVersion::V2)
            && (self.mode == Mode::Startup
                || (self.mode == Mode::ProbeBw
                    && matches!(self.probe_bw_phase, ProbeBwPhase::Refill | ProbeBwPhase::Up)))
    }

    fn bbrv2_uses_short_term_model(&self) -> bool {
        !matches!(
            (self.mode, self.probe_bw_phase),
            (Mode::ProbeBw, ProbeBwPhase::Refill | ProbeBwPhase::Up)
        )
    }

    fn bbrv2_bound_inflight_for_model(&self, base: u64) -> u64 {
        if !matches!(self.version, BbrVersion::V2) {
            return base;
        }

        let mut cap = self.inflight_hi;
        if matches!(self.mode, Mode::ProbeBw | Mode::ProbeRtt)
            && matches!(self.probe_bw_phase, ProbeBwPhase::Cruise)
            && cap != u64::MAX
        {
            cap = cap.saturating_mul(85) / 100;
        }
        if self.bbrv2_uses_short_term_model() {
            cap = cap.min(self.inflight_lo);
        }

        let capped = base.min(cap);
        if cap == u64::MAX {
            capped
        } else {
            capped.max(base.min(self.min_cwnd))
        }
    }

    fn bbrv2_reset_short_term_model(&mut self) {
        self.inflight_lo = u64::MAX;
        self.bw_lo = u64::MAX;
    }

    fn sent_packet_model_limit(&self) -> usize {
        let target_bytes = self
            .cwnd
            .max(self.prev_in_flight_count)
            .max(self.get_target_cwnd(BBR2_PROBE_UP_CWND_GAIN));
        let target_packets = target_bytes
            .saturating_div(self.current_mtu.max(1))
            .saturating_add(BBR_SENT_PACKET_MODEL_HEADROOM_PACKETS);

        target_packets.clamp(
            BBR_SENT_PACKET_MODEL_MIN_PACKETS,
            BBR_SENT_PACKET_MODEL_MAX_PACKETS,
        ) as usize
    }

    fn remember_sent_packet(&mut self, packet_number: u64, tx_in_flight: u64, now: Instant) {
        self.sent_packets.insert(
            packet_number,
            BbrSentPacket {
                round_count: self.round_count,
                tx_in_flight,
                sent_time: now,
                delivered_bytes_at_send: self.delivered_bytes,
                delivered_time_at_send: self.delivered_time.unwrap_or(now),
            },
        );

        while self.sent_packets.len() > self.sent_packet_model_limit() {
            self.sent_packets.pop_first();
        }
    }

    fn sent_packet_model(&self, packet_number: u64) -> Option<BbrSentPacket> {
        self.sent_packets.get(&packet_number).copied()
    }

    fn prune_sent_packet_model(&mut self, packet_number: u64) {
        self.sent_packets.remove(&packet_number);
    }

    fn bbrv2_delivery_rate_sample(
        &self,
        packet: BbrSentPacket,
        now: Instant,
        delivered_after_ack: u64,
    ) -> Option<u64> {
        let delivered = delivered_after_ack.saturating_sub(packet.delivered_bytes_at_send);
        let ack_elapsed = now.saturating_duration_since(packet.delivered_time_at_send);
        let send_elapsed = now.saturating_duration_since(packet.sent_time);
        let interval = ack_elapsed.max(send_elapsed);
        BandwidthEstimation::bw_from_delta(delivered, interval)
    }

    fn bbrv2_update_latest_delivery_signals(
        &mut self,
        now: Instant,
        packet_number: u64,
        delivered_after_ack: u64,
        app_limited: bool,
    ) {
        let packet_model = self.sent_packet_model(packet_number);
        self.inflight_latest = self.inflight_latest.max(
            packet_model
                .map(|packet| packet.tx_in_flight)
                .unwrap_or(delivered_after_ack),
        );
        let sample = packet_model
            .and_then(|packet| self.bbrv2_delivery_rate_sample(packet, now, delivered_after_ack))
            .unwrap_or_else(|| self.max_bandwidth.get_estimate());
        self.bw_latest = self.bw_latest.max(sample);
        self.max_bandwidth
            .update_max_bandwidth(self.round_count, sample, app_limited);
    }

    fn bbrv2_advance_latest_delivery_signals(&mut self, packet_number: u64, delivered: u64) {
        self.inflight_latest = self
            .sent_packet_model(packet_number)
            .map(|packet| packet.tx_in_flight)
            .unwrap_or(delivered);
        self.bw_latest = self.max_bandwidth.get_estimate();
    }

    fn bbrv2_reduce_short_term_bounds(&mut self, signal_inflight: u64, app_limited: bool) {
        let floor = self.bbrv2_inflight_hi_floor();
        if self.inflight_lo == u64::MAX {
            self.inflight_lo = self.cwnd;
        }
        let reduced_inflight = self.inflight_lo.saturating_mul(7) / 10;
        self.inflight_lo = self
            .inflight_latest
            .max(signal_inflight)
            .max(reduced_inflight)
            .max(floor);

        if !app_limited {
            if self.bw_lo == u64::MAX {
                self.bw_lo = self.max_bandwidth.get_estimate();
            }
            if self.bw_lo > 0 {
                let reduced_bw = self.bw_lo.saturating_mul(7) / 10;
                self.bw_lo = self.bw_latest.max(reduced_bw).max(1);
            }
        }
    }

    fn bbrv2_start_probe_bw_down(&mut self, now: Instant) {
        self.probe_bw_phase = ProbeBwPhase::Down;
        self.pacing_gain = BBR2_PROBE_DOWN_PACING_GAIN;
        self.cwnd_gain = DERIVED_HIGH_CWND_GAIN;
        self.last_cycle_start = Some(now);
        self.probe_up_acked = 0;
        self.bw_probe_samples = false;
    }

    fn bbrv2_start_probe_bw_cruise(&mut self, now: Instant) {
        self.probe_bw_phase = ProbeBwPhase::Cruise;
        self.pacing_gain = 1.0;
        self.cwnd_gain = DERIVED_HIGH_CWND_GAIN;
        self.last_cycle_start = Some(now);
    }

    fn bbrv2_start_probe_bw_refill(&mut self, now: Instant) {
        self.bbrv2_reset_short_term_model();
        self.probe_bw_phase = ProbeBwPhase::Refill;
        self.pacing_gain = 1.0;
        self.cwnd_gain = DERIVED_HIGH_CWND_GAIN;
        self.last_cycle_start = Some(now);
        self.probe_up_acked = 0;
        self.bw_probe_samples = true;
    }

    fn bbrv2_start_probe_bw_up(&mut self, now: Instant) {
        self.bbrv2_reset_short_term_model();
        self.probe_bw_phase = ProbeBwPhase::Up;
        self.pacing_gain = BBR2_PROBE_UP_PACING_GAIN;
        self.cwnd_gain = BBR2_PROBE_UP_CWND_GAIN;
        self.last_cycle_start = Some(now);
        self.probe_up_acked = 0;
        self.bw_probe_samples = true;
    }

    fn bbrv2_update_probe_bw_phase(&mut self, now: Instant, in_flight: u64, is_round_start: bool) {
        if !matches!(self.version, BbrVersion::V2)
            || !self.config.bbrv2_experimental_inflight_hi_shrink
        {
            self.update_gain_cycle_phase(now, in_flight);
            return;
        }

        match self.probe_bw_phase {
            ProbeBwPhase::Down => {
                let headroom = if self.inflight_hi == u64::MAX {
                    self.get_target_cwnd(1.0)
                } else {
                    self.inflight_hi.saturating_mul(85) / 100
                };
                if in_flight <= self.get_target_cwnd(1.0).min(headroom) {
                    self.bbrv2_start_probe_bw_cruise(now);
                }
            }
            ProbeBwPhase::Cruise => {
                if self
                    .last_cycle_start
                    .is_some_and(|start| now.duration_since(start) > self.min_rtt * 8)
                {
                    self.bbrv2_start_probe_bw_refill(now);
                }
            }
            ProbeBwPhase::Refill => {
                if is_round_start {
                    self.bbrv2_start_probe_bw_up(now);
                }
            }
            ProbeBwPhase::Up => {
                let target = self.get_target_cwnd(BBR2_PROBE_UP_PACING_GAIN);
                let min_rtt_elapsed = self
                    .last_cycle_start
                    .is_some_and(|start| now.duration_since(start) > self.min_rtt);
                if min_rtt_elapsed && in_flight > target {
                    self.bbrv2_start_probe_bw_down(now);
                }
            }
        }
    }

    fn bbrv2_handle_congestion_signal(&mut self, now: Instant, in_flight: u64, app_limited: bool) {
        self.inflight_latest = in_flight;
        self.bw_latest = self.max_bandwidth.get_estimate();

        if self.bbrv2_is_probing_bandwidth() && self.bw_probe_samples {
            self.shrink_inflight_hi_on_signal(in_flight);
            self.bw_probe_samples = false;
            if self.mode == Mode::ProbeBw && self.probe_bw_phase == ProbeBwPhase::Up {
                self.bbrv2_start_probe_bw_down(now);
            }
        } else {
            self.bbrv2_reduce_short_term_bounds(in_flight, app_limited);
        }
    }

    fn bbrv2_probe_up_inflight_hi(
        &mut self,
        bytes_acked: u64,
        is_round_start: bool,
        in_flight: u64,
    ) {
        if !matches!(self.version, BbrVersion::V2)
            || !self.config.bbrv2_experimental_inflight_hi_shrink
            || self.mode != Mode::ProbeBw
            || self.pacing_gain <= 1.0
            || self.inflight_hi == u64::MAX
            || self.loss_state.has_congestion_losses()
        {
            return;
        }

        if is_round_start {
            self.probe_up_rounds = self.probe_up_rounds.saturating_add(1);
        }

        let utilized = in_flight.saturating_add(bytes_acked) >= self.inflight_hi
            || self.cwnd >= self.inflight_hi;
        if !utilized {
            self.probe_up_acked = 0;
            return;
        }

        self.probe_up_acked = self.probe_up_acked.saturating_add(bytes_acked);
        let growth_packets = 1u64 << self.probe_up_rounds.saturating_sub(1).min(30);
        let probe_up_bytes = (self.cwnd / growth_packets).max(self.current_mtu);
        if self.probe_up_acked < probe_up_bytes {
            return;
        }

        let steps = (self.probe_up_acked / probe_up_bytes).max(1);
        self.probe_up_acked %= probe_up_bytes;
        self.inflight_hi = self
            .inflight_hi
            .saturating_add(steps.saturating_mul(self.current_mtu));
    }

    fn enter_startup_mode(&mut self) {
        self.mode = Mode::Startup;
        self.pacing_gain = self.high_gain;
        self.cwnd_gain = self.high_cwnd_gain;
    }

    fn enter_probe_bandwidth_mode(&mut self, now: Instant) {
        self.mode = Mode::ProbeBw;
        self.cwnd_gain = DERIVED_HIGH_CWND_GAIN;
        self.last_cycle_start = Some(now);
        if matches!(self.version, BbrVersion::V2)
            && self.config.bbrv2_experimental_inflight_hi_shrink
        {
            self.bbrv2_start_probe_bw_down(now);
            return;
        }
        // Pick a random offset for the gain cycle out of {0, 2..7} range. 1 is
        // excluded because in that case increased gain and decreased gain would not
        // follow each other.
        let mut rand_index = self
            .random_number_generator
            .random_range(0..PACING_GAIN.len() as u8 - 1);
        if rand_index >= 1 {
            rand_index += 1;
        }
        self.current_cycle_offset = rand_index;
        self.pacing_gain = PACING_GAIN[rand_index as usize];
        self.probe_bw_phase = ProbeBwPhase::Cruise;
    }

    fn update_recovery_state(&mut self, is_round_start: bool) {
        // Exit recovery when there are no losses for a round.
        if self.loss_state.has_congestion_losses() {
            self.end_recovery_at_packet_number = self.max_sent_packet_number;
        }
        match self.recovery_state {
            // Enter conservation on the first loss.
            RecoveryState::NotInRecovery if self.loss_state.has_congestion_losses() => {
                self.recovery_state = RecoveryState::Conservation;
                // This will cause the |recovery_window| to be set to the
                // correct value in CalculateRecoveryWindow().
                self.recovery_window = 0;
                // Since the conservation phase is meant to be lasting for a whole
                // round, extend the current round as if it were started right now.
                self.current_round_trip_end_packet_number = self.max_sent_packet_number;
            }
            RecoveryState::Growth | RecoveryState::Conservation => {
                if self.recovery_state == RecoveryState::Conservation && is_round_start {
                    self.recovery_state = RecoveryState::Growth;
                }
                // Exit recovery if appropriate.
                if !self.loss_state.has_congestion_losses()
                    && self.max_acked_packet_number > self.end_recovery_at_packet_number
                {
                    self.recovery_state = RecoveryState::NotInRecovery;
                }
            }
            _ => {}
        }
    }

    fn update_gain_cycle_phase(&mut self, now: Instant, in_flight: u64) {
        // In most cases, the cycle is advanced after an RTT passes.
        let mut should_advance_gain_cycling = self
            .last_cycle_start
            .map(|last_cycle_start| now.duration_since(last_cycle_start) > self.min_rtt)
            .unwrap_or(false);
        // If the pacing gain is above 1.0, the connection is trying to probe the
        // bandwidth by increasing the number of bytes in flight to at least
        // pacing_gain * BDP.  Make sure that it actually reaches the target, as
        // long as there are no losses suggesting that the buffers are not able to
        // hold that much.
        if self.pacing_gain > 1.0
            && !self.loss_state.has_congestion_losses()
            && self.prev_in_flight_count < self.get_target_cwnd(self.pacing_gain)
        {
            should_advance_gain_cycling = false;
        }

        // If pacing gain is below 1.0, the connection is trying to drain the extra
        // queue which could have been incurred by probing prior to it.  If the
        // number of bytes in flight falls down to the estimated BDP value earlier,
        // conclude that the queue has been successfully drained and exit this cycle
        // early.
        if self.pacing_gain < 1.0 && in_flight <= self.get_target_cwnd(1.0) {
            should_advance_gain_cycling = true;
        }

        if should_advance_gain_cycling {
            self.current_cycle_offset = (self.current_cycle_offset + 1) % PACING_GAIN.len() as u8;
            self.last_cycle_start = Some(now);
            // Stay in low gain mode until the target BDP is hit.  Low gain mode
            // will be exited immediately when the target BDP is achieved.
            if DRAIN_TO_TARGET
                && self.pacing_gain < 1.0
                && (PACING_GAIN[self.current_cycle_offset as usize] - 1.0).abs() < f32::EPSILON
                && in_flight > self.get_target_cwnd(1.0)
            {
                return;
            }
            self.pacing_gain = PACING_GAIN[self.current_cycle_offset as usize];
            if matches!(self.version, BbrVersion::V2)
                && self.config.bbrv2_experimental_inflight_hi_shrink
                && self.pacing_gain > 1.0
            {
                self.bbrv2_start_probe_bw_up(now);
            }
        }
    }

    fn maybe_exit_startup_or_drain(&mut self, now: Instant, in_flight: u64) {
        if self.mode == Mode::Startup && self.is_at_full_bandwidth {
            self.mode = Mode::Drain;
            self.pacing_gain = self.drain_gain;
            self.cwnd_gain = self.high_cwnd_gain;
        }
        if self.mode == Mode::Drain && in_flight <= self.get_target_cwnd(1.0) {
            self.enter_probe_bandwidth_mode(now);
        }
    }

    fn is_min_rtt_expired(&self, now: Instant, app_limited: bool) -> bool {
        !app_limited
            && self
                .probe_rtt_last_started_at
                .map(|last| now.saturating_duration_since(last) > Duration::from_secs(10))
                .unwrap_or(true)
    }

    fn maybe_enter_or_exit_probe_rtt(
        &mut self,
        now: Instant,
        is_round_start: bool,
        bytes_in_flight: u64,
        app_limited: bool,
    ) {
        let min_rtt_expired = self.is_min_rtt_expired(now, app_limited);
        if min_rtt_expired && !self.exiting_quiescence && self.mode != Mode::ProbeRtt {
            self.mode = Mode::ProbeRtt;
            self.pacing_gain = 1.0;
            // Do not decide on the time to exit ProbeRtt until the
            // |bytes_in_flight| is at the target small value.
            self.exit_probe_rtt_at = None;
            self.probe_rtt_last_started_at = Some(now);
        }

        if self.mode == Mode::ProbeRtt {
            if self.exit_probe_rtt_at.is_none() {
                // If the window has reached the appropriate size, schedule exiting
                // ProbeRtt.  The CWND during ProbeRtt is
                // kMinimumCongestionWindow, but we allow an extra packet since QUIC
                // checks CWND before sending a packet.
                if bytes_in_flight < self.get_probe_rtt_cwnd() + self.current_mtu {
                    const PROBE_RTT_TIME: Duration = Duration::from_millis(200);
                    self.exit_probe_rtt_at = Some(now + PROBE_RTT_TIME);
                }
            } else if is_round_start && now >= self.exit_probe_rtt_at.unwrap() {
                if !self.is_at_full_bandwidth {
                    self.enter_startup_mode();
                } else {
                    self.enter_probe_bandwidth_mode(now);
                }
            }
        }

        self.exiting_quiescence = false;
    }

    fn get_target_cwnd(&self, gain: f32) -> u64 {
        let bw = self.bbrv2_effective_bandwidth();
        let bdp = self.min_rtt.as_micros() as u64 * bw;
        let bdpf = bdp as f64;
        let cwnd = ((gain as f64 * bdpf) / 1_000_000f64) as u64;
        // BDP estimate will be zero if no bandwidth samples are available yet.
        if cwnd == 0 {
            return self.init_cwnd;
        }
        cwnd.max(self.min_cwnd)
    }

    fn get_probe_rtt_cwnd(&self) -> u64 {
        const MODERATE_PROBE_RTT_MULTIPLIER: f32 = 0.75;
        if PROBE_RTT_BASED_ON_BDP {
            return self.get_target_cwnd(MODERATE_PROBE_RTT_MULTIPLIER);
        }
        self.min_cwnd
    }

    fn calculate_pacing_rate(&mut self) {
        let bw = self.bbrv2_effective_bandwidth();
        if bw == 0 {
            return;
        }
        let target_rate = (bw as f64 * self.pacing_gain as f64) as u64;
        if self.is_at_full_bandwidth {
            self.pacing_rate = target_rate;
            return;
        }

        // Pace at the rate of initial_window / RTT as soon as RTT measurements are
        // available.
        if self.pacing_rate == 0 && self.min_rtt.as_nanos() != 0 {
            self.pacing_rate =
                BandwidthEstimation::bw_from_delta(self.init_cwnd, self.min_rtt).unwrap();
            return;
        }

        // Do not decrease the pacing rate during startup.
        if self.pacing_rate < target_rate {
            self.pacing_rate = target_rate;
        }
    }

    fn calculate_cwnd(&mut self, bytes_acked: u64, excess_acked: u64) {
        if self.mode == Mode::ProbeRtt {
            return;
        }
        let mut target_window = self.get_target_cwnd(self.cwnd_gain);
        if self.is_at_full_bandwidth {
            // Add the max recently measured ack aggregation to CWND.
            target_window += self.ack_aggregation.max_ack_height.get();
        } else {
            // Add the most recent excess acked.  Because CWND never decreases in
            // STARTUP, this will automatically create a very localized max filter.
            target_window += excess_acked;
        }
        // Instead of immediately setting the target CWND as the new one, BBR grows
        // the CWND towards |target_window| by only increasing it |bytes_acked| at a
        // time.
        if self.is_at_full_bandwidth {
            self.cwnd = target_window.min(self.cwnd + bytes_acked);
        } else if (self.cwnd_gain < target_window as f32) || (self.acked_bytes < self.init_cwnd) {
            // If the connection is not yet out of startup phase, do not decrease
            // the window.
            self.cwnd += bytes_acked;
        }

        // Enforce the limits on the congestion window.
        if self.cwnd < self.min_cwnd {
            self.cwnd = self.min_cwnd;
        }
    }

    fn calculate_recovery_window(&mut self, bytes_acked: u64, bytes_lost: u64, in_flight: u64) {
        if !self.recovery_state.in_recovery() {
            return;
        }
        // Set up the initial recovery window.
        if self.recovery_window == 0 {
            self.recovery_window = self.min_cwnd.max(in_flight + bytes_acked);
            return;
        }

        // Remove losses from the recovery window, while accounting for a potential
        // integer underflow.
        if self.recovery_window >= bytes_lost {
            self.recovery_window -= bytes_lost;
        } else {
            // k_max_segment_size = current_mtu
            self.recovery_window = self.current_mtu;
        }
        // In CONSERVATION mode, just subtracting losses is sufficient.  In GROWTH,
        // release additional |bytes_acked| to achieve a slow-start-like behavior.
        if self.recovery_state == RecoveryState::Growth {
            self.recovery_window += bytes_acked;
        }

        // Sanity checks.  Ensure that we always allow to send at least an MSS or
        // |bytes_acked| in response, whichever is larger.
        self.recovery_window = self
            .recovery_window
            .max(in_flight + bytes_acked)
            .max(self.min_cwnd);
    }

    /// <https://datatracker.ietf.org/doc/html/draft-cardwell-iccrg-bbr-congestion-control#section-4.3.2.2>
    fn check_if_full_bw_reached(&mut self, app_limited: bool) {
        if app_limited {
            return;
        }
        let target = (self.bw_at_last_round as f64 * STARTUP_GROWTH_TARGET as f64) as u64;
        let bw = self.max_bandwidth.get_estimate();
        if bw >= target {
            self.bw_at_last_round = bw;
            self.round_wo_bw_gain = 0;
            self.ack_aggregation.max_ack_height.reset();
            return;
        }

        self.round_wo_bw_gain += 1;
        if self.round_wo_bw_gain >= ROUND_TRIPS_WITHOUT_GROWTH_BEFORE_EXITING_STARTUP as u64
            || (self.recovery_state.in_recovery())
        {
            self.is_at_full_bandwidth = true;
        }
    }
}

impl Controller for Bbr {
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        self.max_sent_packet_number = last_packet_number;
        self.max_bandwidth.on_sent(now, bytes);
    }

    fn on_packet_sent(&mut self, now: Instant, bytes: u16, packet_number: u64) {
        self.tracked_in_flight = self.tracked_in_flight.saturating_add(bytes.into());
        self.max_sent_packet_number = self.max_sent_packet_number.max(packet_number);
        if matches!(self.version, BbrVersion::V2)
            && self.config.bbrv2_experimental_inflight_hi_shrink
        {
            self.remember_sent_packet(packet_number, self.tracked_in_flight, now);
        }
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        packet_number: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.tracked_in_flight = self.tracked_in_flight.saturating_sub(bytes);
        self.max_bandwidth
            .on_ack(now, sent, bytes, self.round_count, app_limited);
        let delivered_after_ack = self.delivered_bytes.saturating_add(bytes);
        self.acked_bytes += bytes;
        if self.is_min_rtt_expired(now, app_limited) || self.min_rtt > rtt.min() {
            self.min_rtt = rtt.min();
        }
        if matches!(self.version, BbrVersion::V2)
            && self.config.bbrv2_experimental_inflight_hi_shrink
        {
            self.bbrv2_update_latest_delivery_signals(
                now,
                packet_number,
                delivered_after_ack,
                app_limited,
            );
            self.prune_sent_packet_model(packet_number);
        }
        if bytes > 0 {
            self.delivered_bytes = delivered_after_ack;
            self.delivered_time = Some(now);
        }
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        // Recovery owns the canonical count. Resynchronizing here prevents
        // accounting drift across non-ack-eliciting packets and path events.
        self.tracked_in_flight = in_flight;
        let bytes_acked = self.max_bandwidth.bytes_acked_this_window();
        let excess_acked = self.ack_aggregation.update_ack_aggregation_bytes(
            bytes_acked,
            now,
            self.round_count,
            self.max_bandwidth.get_estimate(),
        );
        self.max_bandwidth.end_acks(self.round_count, app_limited);
        if let Some(largest_acked_packet) = largest_packet_num_acked {
            self.max_acked_packet_number = largest_acked_packet;
        }

        let mut is_round_start = false;
        if bytes_acked > 0 {
            is_round_start =
                self.max_acked_packet_number > self.current_round_trip_end_packet_number;
            if is_round_start {
                self.current_round_trip_end_packet_number = self.max_sent_packet_number;
                self.round_count += 1;
            }
        }
        self.loss_state.record_delivered(bytes_acked);
        self.loss_state.classify_congestion_signal(
            self.version,
            self.current_mtu,
            self.round_count,
        );

        // V2 experimental path: use separate long-term and short-term bounds.
        // Loss while probing bandwidth adapts `inflight_hi`; loss outside
        // probing only adapts the short-term bounds so random loss does not
        // permanently poison the path model.
        if matches!(self.version, BbrVersion::V2)
            && self.config.bbrv2_experimental_inflight_hi_shrink
            && self.loss_state.has_congestion_losses()
            && is_round_start
        {
            let signal_inflight = self
                .loss_state
                .latest_loss_tx_in_flight()
                .unwrap_or(in_flight);
            self.bbrv2_handle_congestion_signal(now, signal_inflight, app_limited);
        }

        self.update_recovery_state(is_round_start);

        if self.mode == Mode::ProbeBw {
            // BBRv2 raises long-term bounds from clean ProbeBW_UP samples before
            // phase transition checks can move the sender back to DOWN.
            self.bbrv2_probe_up_inflight_hi(bytes_acked, is_round_start, in_flight);
            self.bbrv2_update_probe_bw_phase(now, in_flight, is_round_start);
        }

        if is_round_start && !self.is_at_full_bandwidth {
            self.check_if_full_bw_reached(app_limited);
        }

        self.maybe_exit_startup_or_drain(now, in_flight);

        self.maybe_enter_or_exit_probe_rtt(now, is_round_start, in_flight, app_limited);

        // After the model is updated, recalculate the pacing rate and congestion window.
        self.calculate_pacing_rate();
        self.calculate_cwnd(bytes_acked, excess_acked);
        self.calculate_recovery_window(
            bytes_acked,
            self.loss_state.congestion_lost_bytes(),
            in_flight,
        );

        self.prev_in_flight_count = in_flight;
        self.loss_state.reset_batch();
        if is_round_start {
            self.loss_state.reset_round();
            if matches!(self.version, BbrVersion::V2)
                && self.config.bbrv2_experimental_inflight_hi_shrink
                && largest_packet_num_acked.is_some()
            {
                self.bbrv2_advance_latest_delivery_signals(
                    largest_packet_num_acked.unwrap(),
                    bytes_acked,
                );
            }
        }
    }

    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        event: CongestionEvent,
        is_persistent_congestion: bool,
    ) {
        match event {
            CongestionEvent::Ecn { ce_count, .. } => {
                self.loss_state
                    .record_ecn(ce_count, is_persistent_congestion);
            }
            CongestionEvent::Loss {
                largest_lost_packet_number,
                lost_bytes,
            } => {
                let lost_model = largest_lost_packet_number
                    .and_then(|packet_number| self.sent_packet_model(packet_number));
                self.loss_state.record_loss(
                    lost_bytes,
                    is_persistent_congestion,
                    lost_model.map(|packet| packet.round_count),
                    lost_model.map(|packet| packet.tx_in_flight),
                );
                if let Some(packet_number) = largest_lost_packet_number {
                    self.prune_sent_packet_model(packet_number);
                }
            }
        }
    }

    fn on_packet_lost(&mut self, lost_bytes: u16, _packet_number: u64, _now: Instant) {
        self.tracked_in_flight = self.tracked_in_flight.saturating_sub(lost_bytes.into());
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.current_mtu = new_mtu as u64;
        self.min_cwnd = calculate_min_window(self.current_mtu);
        self.init_cwnd = self.config.initial_window.max(self.min_cwnd);
        self.cwnd = self.cwnd.max(self.min_cwnd);
        if matches!(self.version, BbrVersion::V2) {
            self.inflight_hi = self.inflight_hi.max(self.bbrv2_inflight_hi_floor());
            self.inflight_lo = self.inflight_lo.max(self.min_cwnd);
        }
    }

    fn window(&self) -> u64 {
        let base = if self.mode == Mode::ProbeRtt {
            self.get_probe_rtt_cwnd()
        } else if self.recovery_state.in_recovery() && self.mode != Mode::Startup {
            self.cwnd.min(self.recovery_window)
        } else {
            self.cwnd
        };
        // V1 keeps `inflight_hi == u64::MAX` permanently, so the cap is a
        // no-op there. V2 may have reduced `inflight_hi` in response to a
        // round-level congestion signal; apply it as a ceiling after the
        // mode-specific base is chosen.
        match self.version {
            BbrVersion::V1 => base,
            BbrVersion::V2 => self.bbrv2_bound_inflight_for_model(base),
        }
    }

    fn metrics(&self) -> ControllerMetrics {
        ControllerMetrics {
            congestion_window: self.window(),
            ssthresh: None,
            pacing_rate: Some(self.pacing_rate),
            send_quantum: None,
        }
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        self.config.initial_window
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

/// Configuration for the [`Bbr`] congestion controller
#[derive(Debug, Clone)]
pub struct BbrConfig {
    initial_window: u64,
    bbrv2_experimental_inflight_hi_shrink: bool,
}

impl BbrConfig {
    /// Default limit on the amount of outstanding data in bytes.
    ///
    /// Recommended value: `min(10 * max_datagram_size, max(2 * max_datagram_size, 14720))`
    pub fn initial_window(&mut self, value: u64) -> &mut Self {
        self.initial_window = value;
        self
    }
}

impl Default for BbrConfig {
    fn default() -> Self {
        Self {
            initial_window: MAX_INITIAL_CONGESTION_WINDOW * BASE_DATAGRAM_SIZE,
            bbrv2_experimental_inflight_hi_shrink: false,
        }
    }
}

impl ControllerFactory for BbrConfig {
    fn build(self: Arc<Self>, _now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(Bbr::new(self, current_mtu))
    }
}

/// Configuration for the BBRv2 congestion controller.
///
/// This intentionally uses a distinct factory so deployments can A/B test
/// `bbr` and `bbrv2` without changing the legacy controller behaviour.
#[derive(Debug, Clone)]
pub struct BbrV2Config {
    inner: BbrConfig,
}

impl BbrV2Config {
    /// Default limit on the amount of outstanding data in bytes.
    ///
    /// Recommended value: `min(10 * max_datagram_size, max(2 * max_datagram_size, 14720))`
    pub fn initial_window(&mut self, value: u64) -> &mut Self {
        self.inner.initial_window(value);
        self
    }

    /// Enable the experimental full BBRv2 model.
    ///
    /// This activates long- and short-term inflight bounds, the short-term
    /// bandwidth bound, and the ProbeBW DOWN/CRUISE/REFILL/UP cycle. It remains
    /// disabled by default while the full model is benchmarked against the
    /// conservative BBRv2 signal classifier.
    pub fn full_model(&mut self, enabled: bool) -> &mut Self {
        self.inner.bbrv2_experimental_inflight_hi_shrink = enabled;
        self
    }

    /// Backwards-compatible alias for [`Self::full_model`].
    pub fn experimental_inflight_hi_shrink(&mut self, enabled: bool) -> &mut Self {
        self.full_model(enabled)
    }
}

impl Default for BbrV2Config {
    fn default() -> Self {
        Self {
            inner: BbrConfig::default(),
        }
    }
}

impl ControllerFactory for BbrV2Config {
    fn build(self: Arc<Self>, _now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(Bbr::new_with_version(
            Arc::new(self.inner.clone()),
            current_mtu,
            BbrVersion::V2,
        ))
    }
}

#[derive(Debug, Default, Copy, Clone)]
pub(super) struct AckAggregationState {
    max_ack_height: MinMax,
    aggregation_epoch_start_time: Option<Instant>,
    aggregation_epoch_bytes: u64,
}

impl AckAggregationState {
    fn update_ack_aggregation_bytes(
        &mut self,
        newly_acked_bytes: u64,
        now: Instant,
        round: u64,
        max_bandwidth: u64,
    ) -> u64 {
        // Compute how many bytes are expected to be delivered, assuming max
        // bandwidth is correct.
        let expected_bytes_acked = max_bandwidth
            * now
                .saturating_duration_since(self.aggregation_epoch_start_time.unwrap_or(now))
                .as_micros() as u64
            / 1_000_000;

        // Reset the current aggregation epoch as soon as the ack arrival rate is
        // less than or equal to the max bandwidth.
        if self.aggregation_epoch_bytes <= expected_bytes_acked {
            // Reset to start measuring a new aggregation epoch.
            self.aggregation_epoch_bytes = newly_acked_bytes;
            self.aggregation_epoch_start_time = Some(now);
            return 0;
        }

        // Compute how many extra bytes were delivered vs max bandwidth.
        // Include the bytes most recently acknowledged to account for stretch acks.
        self.aggregation_epoch_bytes += newly_acked_bytes;
        let diff = self.aggregation_epoch_bytes - expected_bytes_acked;
        self.max_ack_height.update_max(round, diff);
        diff
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) enum Mode {
    // Startup phase of the connection.
    Startup,
    // After achieving the highest possible bandwidth during the startup, lower
    // the pacing rate in order to drain the queue.
    Drain,
    // Cruising mode.
    ProbeBw,
    // Temporarily slow down sending in order to empty the buffer and measure
    // the real minimum RTT.
    ProbeRtt,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) enum ProbeBwPhase {
    Down,
    Cruise,
    Refill,
    Up,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct BbrSentPacket {
    round_count: u64,
    tx_in_flight: u64,
    sent_time: Instant,
    delivered_bytes_at_send: u64,
    delivered_time_at_send: Instant,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) enum BbrVersion {
    V1,
    V2,
}

// Indicates how the congestion control limits the amount of bytes in flight.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) enum RecoveryState {
    // Do not limit.
    NotInRecovery,
    // Allow an extra outstanding byte for each byte acknowledged.
    Conservation,
    // Allow two extra outstanding bytes for each byte acknowledged (slow
    // start).
    Growth,
}

impl RecoveryState {
    pub(super) fn in_recovery(&self) -> bool {
        !matches!(self, Self::NotInRecovery)
    }
}

#[derive(Debug, Clone, Default)]
pub(super) struct LossState {
    lost_bytes: u64,
    ecn_ce_count: u64,
    congestion_lost_bytes: u64,
    round_lost_bytes: u64,
    round_ecn_ce_count: u64,
    round_delivered_bytes: u64,
    latest_lost_round: Option<u64>,
    latest_loss_tx_in_flight: Option<u64>,
    persistent_congestion: bool,
}

impl LossState {
    pub(super) fn record_loss(
        &mut self,
        lost_bytes: u64,
        is_persistent_congestion: bool,
        sent_round: Option<u64>,
        tx_in_flight: Option<u64>,
    ) {
        self.lost_bytes = self.lost_bytes.saturating_add(lost_bytes);
        self.round_lost_bytes = self.round_lost_bytes.saturating_add(lost_bytes);
        self.latest_lost_round = sent_round.or(self.latest_lost_round);
        self.latest_loss_tx_in_flight = tx_in_flight.or(self.latest_loss_tx_in_flight);
        self.persistent_congestion |= is_persistent_congestion;
    }

    pub(super) fn record_ecn(&mut self, ce_count: u64, is_persistent_congestion: bool) {
        self.ecn_ce_count = self.ecn_ce_count.saturating_add(ce_count);
        self.round_ecn_ce_count = self.round_ecn_ce_count.saturating_add(ce_count);
        self.persistent_congestion |= is_persistent_congestion;
    }

    pub(super) fn record_delivered(&mut self, bytes: u64) {
        self.round_delivered_bytes = self.round_delivered_bytes.saturating_add(bytes);
    }

    pub(super) fn classify_congestion_signal(
        &mut self,
        version: BbrVersion,
        current_mtu: u64,
        current_round: u64,
    ) {
        let ecn_congestion_bytes = self.ecn_congestion_bytes(current_mtu);
        self.congestion_lost_bytes = match version {
            BbrVersion::V1 => self.lost_bytes.saturating_add(ecn_congestion_bytes),
            BbrVersion::V2 => {
                let attributed_round_complete = self
                    .latest_lost_round
                    .map(|round| round < current_round)
                    .unwrap_or(true);
                if self.persistent_congestion
                    || (attributed_round_complete
                        && self.round_loss_exceeds_bbr2_threshold(current_mtu))
                    || self.round_ecn_exceeds_bbr2_threshold(current_mtu)
                {
                    self.lost_bytes.saturating_add(ecn_congestion_bytes)
                } else {
                    0
                }
            }
        };
    }

    pub(super) fn latest_loss_tx_in_flight(&self) -> Option<u64> {
        self.latest_loss_tx_in_flight
    }

    fn round_loss_exceeds_bbr2_threshold(&self, current_mtu: u64) -> bool {
        let round_total = self
            .round_delivered_bytes
            .saturating_add(self.round_lost_bytes);
        if round_total == 0 || self.round_lost_bytes < BBR2_MIN_LOSS_SIGNAL_PACKETS * current_mtu {
            return false;
        }

        self.round_lost_bytes.saturating_mul(100) >= round_total * BBR2_LOSS_THRESHOLD_PERCENT
    }

    fn round_ecn_exceeds_bbr2_threshold(&self, current_mtu: u64) -> bool {
        let round_ecn_bytes = self.round_ecn_ce_count.saturating_mul(current_mtu);
        if self.round_delivered_bytes == 0
            || round_ecn_bytes < BBR2_MIN_LOSS_SIGNAL_PACKETS * current_mtu
        {
            return false;
        }

        round_ecn_bytes.saturating_mul(100)
            >= self.round_delivered_bytes * BBR2_LOSS_THRESHOLD_PERCENT
    }

    fn ecn_congestion_bytes(&self, current_mtu: u64) -> u64 {
        self.ecn_ce_count
            .saturating_mul(current_mtu)
            .min(self.round_delivered_bytes)
    }

    pub(super) fn reset_batch(&mut self) {
        self.lost_bytes = 0;
        self.ecn_ce_count = 0;
        self.congestion_lost_bytes = 0;
    }

    pub(super) fn reset_round(&mut self) {
        self.round_lost_bytes = 0;
        self.round_ecn_ce_count = 0;
        self.round_delivered_bytes = 0;
        self.latest_lost_round = None;
        self.latest_loss_tx_in_flight = None;
        self.persistent_congestion = false;
    }

    pub(super) fn has_congestion_losses(&self) -> bool {
        self.congestion_lost_bytes != 0
    }

    pub(super) fn congestion_lost_bytes(&self) -> u64 {
        self.congestion_lost_bytes
    }
}

fn calculate_min_window(current_mtu: u64) -> u64 {
    4 * current_mtu
}

// The gain used for the STARTUP, equal to 2/ln(2).
const DEFAULT_HIGH_GAIN: f32 = 2.885;
// The newly derived CWND gain for STARTUP, 2.
const DERIVED_HIGH_CWND_GAIN: f32 = 2.0;
// The cycle of gains used during the ProbeBw stage.
const PACING_GAIN: [f32; 8] = [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];
const BBR2_PROBE_DOWN_PACING_GAIN: f32 = 0.90;
const BBR2_PROBE_UP_PACING_GAIN: f32 = 1.25;
const BBR2_PROBE_UP_CWND_GAIN: f32 = 2.25;
const BBR2_BETA_NUMERATOR: u64 = 7;
const BBR2_BETA_DENOMINATOR: u64 = 10;

const STARTUP_GROWTH_TARGET: f32 = 1.25;
const ROUND_TRIPS_WITHOUT_GROWTH_BEFORE_EXITING_STARTUP: u8 = 3;
const BBR2_LOSS_THRESHOLD_PERCENT: u64 = 2;
const BBR2_MIN_LOSS_SIGNAL_PACKETS: u64 = 4;
const BBR_SENT_PACKET_MODEL_MIN_PACKETS: u64 = 4096;
const BBR_SENT_PACKET_MODEL_HEADROOM_PACKETS: u64 = 4096;
const BBR_SENT_PACKET_MODEL_MAX_PACKETS: u64 = 262_144;

// Do not allow initial congestion window to be greater than 200 packets.
const MAX_INITIAL_CONGESTION_WINDOW: u64 = 200;

const PROBE_RTT_BASED_ON_BDP: bool = true;
const DRAIN_TO_TARGET: bool = true;

#[cfg(test)]
mod tests {
    use super::*;

    fn ack_round_bytes(bbr: &mut Bbr, now: Instant, bytes: u64) {
        bbr.max_bandwidth
            .on_ack(now, now, bytes, bbr.round_count, false);
    }

    #[test]
    fn bbrv1_treats_any_batch_loss_as_congestion() {
        let mut loss = LossState::default();
        loss.record_loss(BASE_DATAGRAM_SIZE, false, None, None);
        loss.record_delivered(10 * 1024 * 1024);
        loss.classify_congestion_signal(BbrVersion::V1, BASE_DATAGRAM_SIZE, 1);

        assert!(loss.has_congestion_losses());
        assert_eq!(loss.congestion_lost_bytes(), BASE_DATAGRAM_SIZE);
    }

    #[test]
    fn bbrv2_ignores_tiny_random_loss_below_threshold() {
        let mut loss = LossState::default();
        loss.record_loss(3 * BASE_DATAGRAM_SIZE, false, None, None);
        loss.record_delivered(10 * 1024 * 1024);
        loss.classify_congestion_signal(BbrVersion::V2, BASE_DATAGRAM_SIZE, 1);

        assert!(!loss.has_congestion_losses());
        assert_eq!(loss.congestion_lost_bytes(), 0);
    }

    #[test]
    fn bbrv2_treats_loss_above_round_threshold_as_congestion() {
        let mut loss = LossState::default();
        loss.record_loss(4 * BASE_DATAGRAM_SIZE, false, None, None);
        loss.record_delivered(100 * BASE_DATAGRAM_SIZE);
        loss.classify_congestion_signal(BbrVersion::V2, BASE_DATAGRAM_SIZE, 1);

        assert!(loss.has_congestion_losses());
        assert_eq!(loss.congestion_lost_bytes(), 4 * BASE_DATAGRAM_SIZE);
    }

    #[test]
    fn bbrv2_defers_attributed_loss_until_sent_round_completes() {
        let mut loss = LossState::default();
        loss.record_loss(4 * BASE_DATAGRAM_SIZE, false, Some(7), Some(800_000));
        loss.record_delivered(100 * BASE_DATAGRAM_SIZE);

        loss.classify_congestion_signal(BbrVersion::V2, BASE_DATAGRAM_SIZE, 7);
        assert!(
            !loss.has_congestion_losses(),
            "loss attributed to the current packet-timed round should wait for the round boundary"
        );

        loss.classify_congestion_signal(BbrVersion::V2, BASE_DATAGRAM_SIZE, 8);
        assert!(loss.has_congestion_losses());
    }

    #[test]
    fn bbrv2_keeps_persistent_congestion_signal() {
        let mut loss = LossState::default();
        loss.record_loss(BASE_DATAGRAM_SIZE, true, None, None);
        loss.record_delivered(10 * 1024 * 1024);
        loss.classify_congestion_signal(BbrVersion::V2, BASE_DATAGRAM_SIZE, 1);

        assert!(loss.has_congestion_losses());
        assert_eq!(loss.congestion_lost_bytes(), BASE_DATAGRAM_SIZE);
    }

    #[test]
    fn bbrv1_treats_any_ecn_ce_signal_as_congestion() {
        let mut loss = LossState::default();
        loss.record_ecn(1, false);
        loss.record_delivered(100 * BASE_DATAGRAM_SIZE);
        loss.classify_congestion_signal(BbrVersion::V1, BASE_DATAGRAM_SIZE, 1);

        assert!(loss.has_congestion_losses());
        assert_eq!(loss.congestion_lost_bytes(), BASE_DATAGRAM_SIZE);
    }

    #[test]
    fn bbrv2_ignores_tiny_ecn_ce_signal_below_threshold() {
        let mut loss = LossState::default();
        loss.record_ecn(3, false);
        loss.record_delivered(10 * 1024 * 1024);
        loss.classify_congestion_signal(BbrVersion::V2, BASE_DATAGRAM_SIZE, 1);

        assert!(!loss.has_congestion_losses());
        assert_eq!(loss.congestion_lost_bytes(), 0);
    }

    #[test]
    fn bbrv2_treats_ecn_ce_above_round_threshold_as_congestion() {
        let mut loss = LossState::default();
        loss.record_ecn(4, false);
        loss.record_delivered(100 * BASE_DATAGRAM_SIZE);
        loss.classify_congestion_signal(BbrVersion::V2, BASE_DATAGRAM_SIZE, 1);

        assert!(loss.has_congestion_losses());
        assert_eq!(loss.congestion_lost_bytes(), 4 * BASE_DATAGRAM_SIZE);
    }

    #[test]
    fn bbrv2_config_builds_v2_controller() {
        let controller =
            Arc::new(BbrV2Config::default()).build(Instant::now(), BASE_DATAGRAM_SIZE as u16);
        let bbr = controller
            .into_any()
            .downcast::<Bbr>()
            .expect("BbrV2Config should build a Bbr controller");

        assert_eq!(bbr.version, BbrVersion::V2);
        assert!(!bbr.config.bbrv2_experimental_inflight_hi_shrink);
    }

    #[test]
    fn bbrv2_config_can_enable_full_model() {
        let mut cfg = BbrV2Config::default();
        cfg.full_model(true);
        let controller = Arc::new(cfg).build(Instant::now(), BASE_DATAGRAM_SIZE as u16);
        let bbr = controller
            .into_any()
            .downcast::<Bbr>()
            .expect("BbrV2Config should build a Bbr controller");

        assert_eq!(bbr.version, BbrVersion::V2);
        assert!(bbr.config.bbrv2_experimental_inflight_hi_shrink);
    }

    #[test]
    fn bbrv2_default_does_not_shrink_inflight_hi_on_congestion_signal() {
        let mut bbr = Bbr::new_with_version(
            Arc::new(BbrConfig::default()),
            BASE_DATAGRAM_SIZE as u16,
            BbrVersion::V2,
        );

        bbr.loss_state
            .record_loss(4 * BASE_DATAGRAM_SIZE, false, None, None);
        ack_round_bytes(&mut bbr, Instant::now(), 100 * BASE_DATAGRAM_SIZE);
        bbr.on_end_acks(Instant::now(), 1_000_000, false, Some(1));

        assert_eq!(
            bbr.inflight_hi,
            u64::MAX,
            "default bbrv2 keeps inflight_hi unconstrained until the experimental shrink flag is enabled"
        );
    }

    #[test]
    fn bbrv2_full_model_adapts_inflight_hi_on_congestion_signal() {
        let mut cfg = BbrConfig::default();
        cfg.bbrv2_experimental_inflight_hi_shrink = true;
        let mut bbr =
            Bbr::new_with_version(Arc::new(cfg), BASE_DATAGRAM_SIZE as u16, BbrVersion::V2);
        bbr.mode = Mode::ProbeBw;
        bbr.probe_bw_phase = ProbeBwPhase::Up;
        bbr.pacing_gain = BBR2_PROBE_UP_PACING_GAIN;
        bbr.bw_probe_samples = true;

        bbr.loss_state
            .record_loss(4 * BASE_DATAGRAM_SIZE, false, None, None);
        ack_round_bytes(&mut bbr, Instant::now(), 100 * BASE_DATAGRAM_SIZE);
        bbr.on_end_acks(Instant::now(), 1_000_000, false, Some(1));

        assert_eq!(
            bbr.inflight_hi, 1_000_000,
            "upper-bound adaptation must preserve the flight observed at send time"
        );
    }

    #[test]
    fn bbrv2_non_probing_loss_sets_short_term_bounds_only() {
        let mut cfg = BbrConfig::default();
        cfg.bbrv2_experimental_inflight_hi_shrink = true;
        let mut bbr =
            Bbr::new_with_version(Arc::new(cfg), BASE_DATAGRAM_SIZE as u16, BbrVersion::V2);
        bbr.mode = Mode::ProbeBw;
        bbr.pacing_gain = 1.0;
        bbr.inflight_hi = 1_000_000;

        bbr.loss_state
            .record_loss(4 * BASE_DATAGRAM_SIZE, false, None, None);
        ack_round_bytes(&mut bbr, Instant::now(), 100 * BASE_DATAGRAM_SIZE);
        bbr.on_end_acks(Instant::now(), 500_000, false, Some(1));

        assert_eq!(
            bbr.inflight_hi, 1_000_000,
            "non-probing loss must not reduce the long-term inflight bound"
        );
        assert!(
            bbr.inflight_lo < u64::MAX,
            "non-probing loss should reduce the short-term inflight bound"
        );
    }

    #[test]
    fn bbrv2_probing_loss_shrinks_long_term_and_enters_down() {
        let mut cfg = BbrConfig::default();
        cfg.bbrv2_experimental_inflight_hi_shrink = true;
        let mut bbr =
            Bbr::new_with_version(Arc::new(cfg), BASE_DATAGRAM_SIZE as u16, BbrVersion::V2);
        bbr.mode = Mode::ProbeBw;
        bbr.probe_bw_phase = ProbeBwPhase::Up;
        bbr.pacing_gain = BBR2_PROBE_UP_PACING_GAIN;
        bbr.bw_probe_samples = true;
        let now = Instant::now();
        bbr.min_rtt = Duration::from_millis(100);
        bbr.probe_rtt_last_started_at = Some(now);

        bbr.loss_state
            .record_loss(4 * BASE_DATAGRAM_SIZE, false, None, None);
        ack_round_bytes(&mut bbr, now, 100 * BASE_DATAGRAM_SIZE);
        bbr.on_end_acks(now, 1_000_000, false, Some(1));

        assert_eq!(bbr.inflight_hi, 1_000_000);
        assert!(
            bbr.pacing_gain < 1.0,
            "a probing loss should immediately move ProbeBW back to DOWN"
        );
    }

    #[test]
    fn bbrv2_loss_uses_tx_in_flight_from_lost_packet_model() {
        let mut cfg = BbrConfig::default();
        cfg.bbrv2_experimental_inflight_hi_shrink = true;
        let mut bbr =
            Bbr::new_with_version(Arc::new(cfg), BASE_DATAGRAM_SIZE as u16, BbrVersion::V2);
        bbr.mode = Mode::ProbeBw;
        bbr.probe_bw_phase = ProbeBwPhase::Up;
        bbr.pacing_gain = BBR2_PROBE_UP_PACING_GAIN;
        bbr.bw_probe_samples = true;
        let now = Instant::now();
        bbr.min_rtt = Duration::from_millis(100);
        bbr.probe_rtt_last_started_at = Some(now);
        bbr.remember_sent_packet(10, 900_000, now);

        bbr.on_congestion_event(
            now,
            now,
            CongestionEvent::Loss {
                largest_lost_packet_number: Some(10),
                lost_bytes: 4 * BASE_DATAGRAM_SIZE,
            },
            false,
        );
        ack_round_bytes(&mut bbr, now, 100 * BASE_DATAGRAM_SIZE);
        bbr.on_end_acks(now, 100_000, false, Some(11));

        assert_eq!(
            bbr.inflight_hi, 900_000,
            "BBRv2 should preserve tx_in_flight at send time, not use lower inflight at loss detection"
        );
    }

    #[test]
    fn bbrv2_packet_callbacks_track_flight_and_packet_metadata() {
        let mut cfg = BbrConfig::default();
        cfg.bbrv2_experimental_inflight_hi_shrink = true;
        let mut bbr =
            Bbr::new_with_version(Arc::new(cfg), BASE_DATAGRAM_SIZE as u16, BbrVersion::V2);
        let now = Instant::now();

        bbr.on_packet_sent(now, 1200, 10);
        bbr.on_packet_sent(now, 800, 11);

        assert_eq!(bbr.tracked_in_flight, 2000);
        assert_eq!(bbr.sent_packet_model(10).unwrap().tx_in_flight, 1200);
        assert_eq!(bbr.sent_packet_model(11).unwrap().tx_in_flight, 2000);

        bbr.on_packet_lost(1200, 10, now);
        assert_eq!(bbr.tracked_in_flight, 800);

        bbr.on_end_acks(now, 725, false, None);
        assert_eq!(bbr.tracked_in_flight, 725);
    }

    #[test]
    fn bbrv2_reports_pacing_rate_in_bytes_per_second() {
        let mut bbr = Bbr::new_with_version(
            Arc::new(BbrConfig::default()),
            BASE_DATAGRAM_SIZE as u16,
            BbrVersion::V2,
        );
        bbr.pacing_rate = 12_345;

        let metrics = bbr.metrics();
        assert_eq!(metrics.pacing_rate, Some(12_345));
        assert_eq!(metrics.send_quantum, None);
    }

    #[test]
    fn bbrv2_congestion_event_preserves_exact_ce_count() {
        let mut bbr = Bbr::new_with_version(
            Arc::new(BbrConfig::default()),
            BASE_DATAGRAM_SIZE as u16,
            BbrVersion::V2,
        );
        let now = Instant::now();

        bbr.on_congestion_event(
            now,
            now,
            CongestionEvent::Ecn {
                ce_count: 7,
                largest_acked_packet_number: Some(42),
            },
            false,
        );

        assert_eq!(bbr.loss_state.ecn_ce_count, 7);
        assert_eq!(bbr.loss_state.round_ecn_ce_count, 7);
    }

    #[test]
    fn bbrv2_packet_model_retains_large_flight_metadata() {
        let mut bbr = Bbr::new_with_version(
            Arc::new(BbrConfig::default()),
            BASE_DATAGRAM_SIZE as u16,
            BbrVersion::V2,
        );
        bbr.cwnd = 20_000 * BASE_DATAGRAM_SIZE;
        let now = Instant::now();

        for packet_number in 1..=10_000 {
            bbr.remember_sent_packet(
                packet_number,
                packet_number * BASE_DATAGRAM_SIZE,
                now + Duration::from_micros(packet_number),
            );
        }

        assert!(
            bbr.sent_packet_model(1).is_some(),
            "BBRv2's sent-packet model should scale with flight size instead of evicting at 4096 packets"
        );
        assert!(bbr.sent_packets.len() <= bbr.sent_packet_model_limit());
    }

    #[test]
    fn bbrv2_latest_delivery_signals_use_packet_rate_sample() {
        let mut cfg = BbrConfig::default();
        cfg.bbrv2_experimental_inflight_hi_shrink = true;
        let mut bbr =
            Bbr::new_with_version(Arc::new(cfg), BASE_DATAGRAM_SIZE as u16, BbrVersion::V2);
        let now = Instant::now();
        bbr.delivered_bytes = 10_000;
        bbr.delivered_time = Some(now);
        bbr.remember_sent_packet(7, 500_000, now);

        bbr.bbrv2_update_latest_delivery_signals(
            now + Duration::from_millis(100),
            7,
            110_000,
            false,
        );

        assert_eq!(bbr.inflight_latest, 500_000);
        assert_eq!(bbr.bw_latest, 1_000_000);
        assert_eq!(
            bbr.max_bandwidth.get_estimate(),
            1_000_000,
            "non-app-limited BBRv2 packet samples should feed the max bandwidth model"
        );
    }

    #[test]
    fn bbrv2_probe_bw_phase_sequence_sets_expected_gains() {
        let mut cfg = BbrConfig::default();
        cfg.bbrv2_experimental_inflight_hi_shrink = true;
        let mut bbr =
            Bbr::new_with_version(Arc::new(cfg), BASE_DATAGRAM_SIZE as u16, BbrVersion::V2);
        let now = Instant::now();
        bbr.min_rtt = Duration::from_millis(10);
        bbr.probe_rtt_last_started_at = Some(now);

        bbr.enter_probe_bandwidth_mode(now);
        assert_eq!(bbr.probe_bw_phase, ProbeBwPhase::Down);
        assert_eq!(bbr.pacing_gain, BBR2_PROBE_DOWN_PACING_GAIN);

        bbr.bbrv2_update_probe_bw_phase(now + Duration::from_millis(1), 0, false);
        assert_eq!(bbr.probe_bw_phase, ProbeBwPhase::Cruise);
        assert_eq!(bbr.pacing_gain, 1.0);

        bbr.bbrv2_update_probe_bw_phase(now + Duration::from_millis(100), 0, false);
        assert_eq!(bbr.probe_bw_phase, ProbeBwPhase::Refill);
        assert!(bbr.bw_probe_samples);

        bbr.bbrv2_update_probe_bw_phase(now + Duration::from_millis(101), 0, true);
        assert_eq!(bbr.probe_bw_phase, ProbeBwPhase::Up);
        assert_eq!(bbr.cwnd_gain, BBR2_PROBE_UP_CWND_GAIN);
    }

    #[test]
    fn bbrv2_probe_bw_up_waits_for_min_rtt_before_down() {
        let mut cfg = BbrConfig::default();
        cfg.bbrv2_experimental_inflight_hi_shrink = true;
        let mut bbr =
            Bbr::new_with_version(Arc::new(cfg), BASE_DATAGRAM_SIZE as u16, BbrVersion::V2);
        let now = Instant::now();
        bbr.mode = Mode::ProbeBw;
        bbr.probe_bw_phase = ProbeBwPhase::Up;
        bbr.pacing_gain = BBR2_PROBE_UP_PACING_GAIN;
        bbr.min_rtt = Duration::from_millis(100);
        bbr.last_cycle_start = Some(now);
        let over_probe_target = bbr.get_target_cwnd(BBR2_PROBE_UP_PACING_GAIN) + BASE_DATAGRAM_SIZE;

        bbr.bbrv2_update_probe_bw_phase(now + Duration::from_millis(50), over_probe_target, false);
        assert_eq!(
            bbr.probe_bw_phase,
            ProbeBwPhase::Up,
            "ProbeBW_UP should not leave before one min_rtt has elapsed"
        );

        bbr.bbrv2_update_probe_bw_phase(now + Duration::from_millis(101), over_probe_target, false);
        assert_eq!(
            bbr.probe_bw_phase,
            ProbeBwPhase::Down,
            "ProbeBW_UP should leave after min_rtt once inflight is above the probe target"
        );
    }

    #[test]
    fn bbrv2_probing_loss_does_not_install_long_term_bandwidth_cap() {
        let mut cfg = BbrConfig::default();
        cfg.bbrv2_experimental_inflight_hi_shrink = true;
        let mut bbr =
            Bbr::new_with_version(Arc::new(cfg), BASE_DATAGRAM_SIZE as u16, BbrVersion::V2);
        bbr.mode = Mode::ProbeBw;
        bbr.probe_bw_phase = ProbeBwPhase::Up;
        bbr.pacing_gain = BBR2_PROBE_UP_PACING_GAIN;
        bbr.bw_probe_samples = true;
        bbr.max_bandwidth
            .update_max_bandwidth(1, 100_000_000, false);
        let bandwidth_before = bbr.bbrv2_effective_bandwidth();

        bbr.bbrv2_handle_congestion_signal(Instant::now(), 1_000_000, false);

        assert_eq!(bbr.bbrv2_effective_bandwidth(), bandwidth_before);
    }

    #[test]
    fn bbrv2_on_end_acks_grows_inflight_hi_before_probe_bw_transition() {
        let mut cfg = BbrConfig::default();
        cfg.bbrv2_experimental_inflight_hi_shrink = true;
        let mut bbr =
            Bbr::new_with_version(Arc::new(cfg), BASE_DATAGRAM_SIZE as u16, BbrVersion::V2);
        let now = Instant::now();
        bbr.mode = Mode::ProbeBw;
        bbr.probe_bw_phase = ProbeBwPhase::Up;
        bbr.pacing_gain = BBR2_PROBE_UP_PACING_GAIN;
        bbr.cwnd = 128 * BASE_DATAGRAM_SIZE;
        bbr.inflight_hi = bbr.cwnd;
        bbr.max_sent_packet_number = 10;
        bbr.current_round_trip_end_packet_number = 1;
        bbr.min_rtt = Duration::from_millis(10);
        bbr.probe_rtt_last_started_at = Some(now);

        let before = bbr.inflight_hi;
        let cwnd = bbr.cwnd;
        ack_round_bytes(&mut bbr, now, cwnd);
        bbr.on_end_acks(now, cwnd, false, Some(2));

        assert!(
            bbr.inflight_hi > before,
            "clean ProbeBW_UP ACKs should grow inflight_hi before phase transition checks"
        );
    }

    #[test]
    fn bbrv2_probe_up_grows_inflight_hi_when_limit_is_utilized() {
        let mut cfg = BbrConfig::default();
        cfg.bbrv2_experimental_inflight_hi_shrink = true;
        let mut bbr =
            Bbr::new_with_version(Arc::new(cfg), BASE_DATAGRAM_SIZE as u16, BbrVersion::V2);
        bbr.mode = Mode::ProbeBw;
        bbr.probe_bw_phase = ProbeBwPhase::Up;
        bbr.pacing_gain = BBR2_PROBE_UP_PACING_GAIN;
        bbr.cwnd = 128 * BASE_DATAGRAM_SIZE;
        bbr.inflight_hi = bbr.cwnd;

        let before = bbr.inflight_hi;
        bbr.bbrv2_probe_up_inflight_hi(bbr.cwnd, true, bbr.cwnd);

        assert!(
            bbr.inflight_hi > before,
            "ProbeBW_UP should cautiously grow a utilized long-term bound"
        );
    }

    #[test]
    fn bbrv2_probe_up_resets_short_term_bounds() {
        let mut cfg = BbrConfig::default();
        cfg.bbrv2_experimental_inflight_hi_shrink = true;
        let mut bbr =
            Bbr::new_with_version(Arc::new(cfg), BASE_DATAGRAM_SIZE as u16, BbrVersion::V2);
        bbr.inflight_lo = 64 * BASE_DATAGRAM_SIZE;
        bbr.bw_lo = 1234;

        bbr.bbrv2_start_probe_bw_up(Instant::now());

        assert_eq!(bbr.inflight_lo, u64::MAX);
        assert_eq!(bbr.bw_lo, u64::MAX);
        assert!(bbr.pacing_gain > 1.0);
    }

    /// Fresh controllers of either version should have no `inflight_hi`
    /// ceiling applied. V1 never sets one; V2 starts with no congestion
    /// history, so both must report `u64::MAX`.
    #[test]
    fn inflight_hi_starts_unconstrained_for_both_versions() {
        let cfg = Arc::new(BbrConfig::default());
        let v1 = Bbr::new(cfg.clone(), BASE_DATAGRAM_SIZE as u16);
        let v2 = Bbr::new_with_version(cfg, BASE_DATAGRAM_SIZE as u16, BbrVersion::V2);
        assert_eq!(v1.inflight_hi, u64::MAX);
        assert_eq!(v2.inflight_hi, u64::MAX);
    }

    /// V2 preserves the observed inflight-at-send and uses 70% of the modeled
    /// target only as a floor, matching BBRv2 upper-bound adaptation.
    #[test]
    fn bbrv2_inflight_hi_preserves_signal_and_uses_model_floor() {
        let cfg = Arc::new(BbrConfig::default());
        let mut bbr = Bbr::new_with_version(cfg, BASE_DATAGRAM_SIZE as u16, BbrVersion::V2);

        // Large observed flight is retained rather than multiplied by beta.
        let signal_inflight = 1_000_000u64;
        bbr.shrink_inflight_hi_on_signal(signal_inflight);
        assert_eq!(
            bbr.inflight_hi, signal_inflight,
            "the triggering flight must not be reduced a second time"
        );

        // A later lower observation can reduce the bound, but never below the
        // model-derived safety floor.
        let smaller_signal = 300_000u64;
        bbr.shrink_inflight_hi_on_signal(smaller_signal);
        assert_eq!(bbr.inflight_hi, smaller_signal);

        // Tiny signal: floor at 70% of the target or min_cwnd, whichever is
        // larger.
        let mut bbr = Bbr::new_with_version(
            Arc::new(BbrConfig::default()),
            BASE_DATAGRAM_SIZE as u16,
            BbrVersion::V2,
        );
        bbr.shrink_inflight_hi_on_signal(1);
        assert_eq!(
            bbr.inflight_hi,
            bbr.bbrv2_inflight_hi_loss_floor(),
            "loss adaptation must retain its model-derived floor"
        );
    }

    #[test]
    fn bbrv2_mtu_update_keeps_inflight_hi_above_floor() {
        let mut bbr = Bbr::new_with_version(
            Arc::new(BbrConfig::default()),
            BASE_DATAGRAM_SIZE as u16,
            BbrVersion::V2,
        );

        bbr.inflight_hi = bbr.bbrv2_inflight_hi_floor();
        bbr.on_mtu_update((BASE_DATAGRAM_SIZE * 2) as u16);

        assert!(
            bbr.inflight_hi >= bbr.bbrv2_inflight_hi_floor(),
            "MTU growth must not leave inflight_hi below the current floor"
        );
        assert!(
            bbr.window() >= bbr.min_cwnd,
            "V2 window should preserve the current min_cwnd floor"
        );
    }

    /// V2: `window()` must respect a reduced `inflight_hi` ceiling even when
    /// neither ProbeRtt nor recovery mode applies. This is the behavior that
    /// makes V2 respond to large congestion events with a persistent ceiling
    /// reduction rather than only a short-lived recovery dip.
    #[test]
    fn bbrv2_window_is_capped_by_inflight_hi() {
        let cfg = Arc::new(BbrConfig::default());
        let mut bbr = Bbr::new_with_version(cfg, BASE_DATAGRAM_SIZE as u16, BbrVersion::V2);

        // Baseline: no ceiling, window returns cwnd.
        let baseline = bbr.cwnd;
        assert_eq!(bbr.window(), baseline);

        // Set the ceiling below cwnd; window should now report the ceiling.
        let ceiling = baseline / 4;
        bbr.inflight_hi = ceiling;
        assert_eq!(
            bbr.window(),
            ceiling,
            "V2 window should honor the inflight_hi cap"
        );
    }

    /// V1 must remain unaffected by `inflight_hi` under any conditions —
    /// including pathologically low values that V2 would honor as a cap.
    /// This guarantees the A/B switch is a true behavioral toggle, not a
    /// stealth change to legacy `bbr`.
    #[test]
    fn bbrv1_window_ignores_inflight_hi_cap() {
        let cfg = Arc::new(BbrConfig::default());
        let mut bbr = Bbr::new(cfg, BASE_DATAGRAM_SIZE as u16);
        assert_eq!(bbr.version, BbrVersion::V1);

        // Even with an artificially-low ceiling, V1 must not consult it.
        bbr.inflight_hi = 1;
        assert_eq!(
            bbr.window(),
            bbr.cwnd,
            "V1 window must be unchanged regardless of inflight_hi"
        );
    }
}
