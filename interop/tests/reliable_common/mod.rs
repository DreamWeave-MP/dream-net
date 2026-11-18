//! One interface over the `reliable` 1.3.4 Rust port and the C binding, so a scenario can drive
//! either implementation, or one of each, and record everything observable.

#![allow(dead_code)] // each test binary uses a different part

use dream_net_native::reliable as new;
use reliable_old as old;

/// The 14 config values, built into either implementation's `Config`.
#[derive(Debug, Clone, PartialEq)]
pub struct Settings {
    pub name: &'static str,
    pub max_packet_size: usize,
    pub fragment_above: usize,
    pub max_fragments: usize,
    pub fragment_size: usize,
    pub ack_buffer_size: usize,
    pub sent_packets_buffer_size: usize,
    pub received_packets_buffer_size: usize,
    pub fragment_reassembly_buffer_size: usize,
    pub rtt_smoothing_factor: f32,
    pub rtt_history_size: usize,
    pub packet_loss_smoothing_factor: f32,
    pub bandwidth_smoothing_factor: f32,
    pub packet_header_size: usize,
}

impl Settings {
    /// dream-net's `reliable_config` (and the audit's Appendix B).
    pub fn dream_net() -> Self {
        Self {
            name: "dn",
            max_packet_size: 32768,
            fragment_above: 1191,
            max_fragments: 28,
            fragment_size: 1186,
            ack_buffer_size: 64,
            sent_packets_buffer_size: 256,
            received_packets_buffer_size: 256,
            fragment_reassembly_buffer_size: 16,
            rtt_smoothing_factor: 0.0025,
            rtt_history_size: 128,
            packet_loss_smoothing_factor: 0.1,
            bandwidth_smoothing_factor: 0.1,
            packet_header_size: 28,
        }
    }

    /// Both libraries' defaults.
    pub fn defaults() -> Self {
        let d = new::Config::default();
        Self {
            name: "endpoint",
            max_packet_size: d.max_packet_size,
            fragment_above: d.fragment_above,
            max_fragments: d.max_fragments,
            fragment_size: d.fragment_size,
            ack_buffer_size: d.ack_buffer_size,
            sent_packets_buffer_size: d.sent_packets_buffer_size,
            received_packets_buffer_size: d.received_packets_buffer_size,
            fragment_reassembly_buffer_size: d.fragment_reassembly_buffer_size,
            rtt_smoothing_factor: d.rtt_smoothing_factor,
            rtt_history_size: d.rtt_history_size,
            packet_loss_smoothing_factor: d.packet_loss_smoothing_factor,
            bandwidth_smoothing_factor: d.bandwidth_smoothing_factor,
            packet_header_size: d.packet_header_size,
        }
    }

    pub fn to_old(&self) -> old::Config {
        old::Config {
            name: self.name.to_owned(),
            max_packet_size: self.max_packet_size,
            fragment_above: self.fragment_above,
            max_fragments: self.max_fragments,
            fragment_size: self.fragment_size,
            ack_buffer_size: self.ack_buffer_size,
            sent_packets_buffer_size: self.sent_packets_buffer_size,
            received_packets_buffer_size: self.received_packets_buffer_size,
            fragment_reassembly_buffer_size: self.fragment_reassembly_buffer_size,
            rtt_smoothing_factor: self.rtt_smoothing_factor,
            rtt_history_size: self.rtt_history_size,
            packet_loss_smoothing_factor: self.packet_loss_smoothing_factor,
            bandwidth_smoothing_factor: self.bandwidth_smoothing_factor,
            packet_header_size: self.packet_header_size,
        }
    }

    pub fn to_new(&self) -> new::Config {
        new::Config {
            name: self.name.to_owned(),
            max_packet_size: self.max_packet_size,
            fragment_above: self.fragment_above,
            max_fragments: self.max_fragments,
            fragment_size: self.fragment_size,
            ack_buffer_size: self.ack_buffer_size,
            sent_packets_buffer_size: self.sent_packets_buffer_size,
            received_packets_buffer_size: self.received_packets_buffer_size,
            fragment_reassembly_buffer_size: self.fragment_reassembly_buffer_size,
            rtt_smoothing_factor: self.rtt_smoothing_factor,
            rtt_history_size: self.rtt_history_size,
            packet_loss_smoothing_factor: self.packet_loss_smoothing_factor,
            bandwidth_smoothing_factor: self.bandwidth_smoothing_factor,
            packet_header_size: self.packet_header_size,
        }
    }
}

/// Which implementation an endpoint is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Old,
    New,
}

/// Either implementation behind one interface.
pub enum Ep {
    Old(Box<old::Endpoint>),
    New(Box<new::Endpoint>),
}

/// The 11 counters, in C order.
pub type Counters = [u64; 11];

/// rtt, `rtt_min`, `rtt_max`, `rtt_avg`, three jitters, packet loss, three bandwidths.
pub type Stats = [f32; 11];

impl Ep {
    pub fn create(kind: Kind, settings: &Settings, time: f64) -> Self {
        match kind {
            Kind::Old => Self::Old(Box::new(old::Endpoint::new(settings.to_old(), time))),
            Kind::New => Self::New(Box::new(
                new::Endpoint::new(settings.to_new(), time).expect("valid config"),
            )),
        }
    }

    /// Sends, returning the datagrams handed to transmit with their sequence.
    pub fn send(&mut self, data: &[u8]) -> Vec<(u16, Vec<u8>)> {
        let mut out = Vec::new();
        match self {
            Self::Old(e) => e.send_packet(data, |s, d| out.push((s, d.to_vec()))),
            Self::New(e) => e.send_packet(data, |s, d| out.push((s, d.to_vec()))),
        }
        out
    }

    /// Receives, answering `process` with `accept(sequence, packet)`; returns the delivery.
    pub fn receive(
        &mut self,
        data: &[u8],
        mut accept: impl FnMut(u16, &[u8]) -> bool,
    ) -> Option<(u16, Vec<u8>, bool)> {
        let mut out = None;
        let mut process = |s: u16, p: &[u8]| {
            assert!(out.is_none(), "process called twice");
            let verdict = accept(s, p);
            out = Some((s, p.to_vec(), verdict));
            verdict
        };
        match self {
            Self::Old(e) => e.receive_packet(data, &mut process),
            Self::New(e) => e.receive_packet(data, &mut process),
        }
        out
    }

    pub fn update(&mut self, time: f64) {
        match self {
            Self::Old(e) => e.update(time),
            Self::New(e) => e.update(time),
        }
    }

    pub fn drain_acks(&mut self) -> Vec<u16> {
        match self {
            Self::Old(e) => e.drain_acks().collect(),
            Self::New(e) => e.drain_acks().collect(),
        }
    }

    pub fn reset(&mut self) {
        match self {
            Self::Old(e) => e.reset(),
            Self::New(e) => e.reset(),
        }
    }

    pub fn next_packet_sequence(&self) -> u16 {
        match self {
            Self::Old(e) => e.next_packet_sequence(),
            Self::New(e) => e.next_packet_sequence(),
        }
    }

    pub fn counters(&self) -> Counters {
        macro_rules! fields {
            ($c:expr) => {{
                let c = $c;
                [
                    c.num_packets_sent,
                    c.num_packets_received,
                    c.num_packets_acked,
                    c.num_packets_stale,
                    c.num_packets_invalid,
                    c.num_packets_too_large_to_send,
                    c.num_packets_too_large_to_receive,
                    c.num_fragments_sent,
                    c.num_fragments_received,
                    c.num_fragments_invalid,
                    c.num_packets_duplicate,
                ]
            }};
        }
        match self {
            Self::Old(e) => fields!(e.counters()),
            Self::New(e) => fields!(e.counters()),
        }
    }

    pub fn stats(&self) -> Stats {
        macro_rules! stats {
            ($e:expr) => {{
                let e = $e;
                let b = e.bandwidth();
                [
                    e.rtt(),
                    e.rtt_min(),
                    e.rtt_max(),
                    e.rtt_avg(),
                    e.jitter_avg_vs_min_rtt(),
                    e.jitter_max_vs_min_rtt(),
                    e.jitter_stddev_vs_avg_rtt(),
                    e.packet_loss(),
                    b.sent_kbps,
                    b.received_kbps,
                    b.acked_kbps,
                ]
            }};
        }
        match self {
            Self::Old(e) => stats!(e),
            Self::New(e) => stats!(e),
        }
    }
}

/// Floats agree to within `1e-4` relative (or `1e-4` absolute near zero). The two compute in
/// the same `f32`/`f64` steps, except C's `pow(x, 0.5f)` for the port's `sqrt` and C's
/// `fabs` in double against the port's `f32::abs`.
pub fn close(a: f32, b: f32) -> bool {
    (a - b).abs() <= 1e-4 * a.abs().max(b.abs()).max(1.0)
}

/// `SplitMix64`: small, seeded, reproducible.
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    pub fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }

    pub fn chance(&mut self, p: f64) -> bool {
        let unit = (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64;
        unit < p
    }
}

/// FNV-1a, as Appendix B prints deliveries.
pub fn fnv1a(data: &[u8]) -> u32 {
    let mut h = 2_166_136_261u32;
    for &b in data {
        h ^= u32::from(b);
        h = h.wrapping_mul(16_777_619);
    }
    h
}
