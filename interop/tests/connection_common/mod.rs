//! Shared by the `connection_*` interop tests: one [`End`] type over dream-net 1.1.1's
//! `Connection` (the Rust `reliable` port) and the current one, and a seeded datagram link with
//! loss, duplication, delay and reordering that both drive identically.

#![allow(dead_code)]

use std::sync::Arc;

use dream_net as new;
use dream_net_old as old;

/// The schema both sides build, by version: three channels (a reliable window of 64, an
/// unreliable queue of 64, a reliable "bulk" window of 16) and five events, the same as the
/// main crate's `tests/common` schema. Events are named, so their ids agree on both sides.
const CHANNELS: [(&str, bool, u16); 3] = [
    ("reliable", true, 64),
    ("state", false, 64),
    ("bulk", true, 16),
];
const EVENTS: [(&str, usize, u32); 5] = [
    ("Chat", 0, 256),
    ("Spawn", 0, 1024),
    ("Move", 1, 64),
    ("Ping", 1, 0),
    ("Blob", 2, 8000),
];

/// Which implementation an [`End`] runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// dream-net 1.1.1 from crates.io, over the `reliable` 1.3.4 Rust port.
    Old,
    /// This tree.
    New,
}

/// The transport limits both sides use, as plain values (the two crates' `TransportConfig`s are
/// different types).
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_pending_events: usize,
    pub max_pending_bytes: usize,
    pub max_parked_bytes: usize,
    pub malformed_limit: u32,
    pub max_packets_per_flush: usize,
}

impl Default for Limits {
    fn default() -> Self {
        let d = new::TransportConfig::default();
        Self {
            max_pending_events: d.max_pending_events,
            max_pending_bytes: d.max_pending_bytes,
            max_parked_bytes: d.max_parked_bytes,
            malformed_limit: d.malformed_limit,
            max_packets_per_flush: d.max_packets_per_flush,
        }
    }
}

macro_rules! build_schema {
    ($krate:ident, $version:expr) => {{
        let mut b = $krate::Schema::builder($version).max_messages_per_packet(32);
        let mut ids = Vec::new();
        for (name, reliable, capacity) in CHANNELS {
            let config = if reliable {
                $krate::ChannelConfig::reliable_ordered(name)
            } else {
                $krate::ChannelConfig::unreliable_unordered(name)
            };
            ids.push(b.channel(config.with_capacity(capacity)).unwrap());
        }
        for (name, channel, max) in EVENTS {
            b.event(name, ids[channel], max).unwrap();
        }
        b.build().unwrap()
    }};
}

macro_rules! shared {
    ($krate:ident, $version:expr, $limits:expr) => {{
        let limits: Limits = $limits;
        let config = $krate::TransportConfig {
            max_pending_events: limits.max_pending_events,
            max_pending_bytes: limits.max_pending_bytes,
            max_parked_bytes: limits.max_parked_bytes,
            malformed_limit: limits.malformed_limit,
            max_packets_per_flush: limits.max_packets_per_flush,
            ..$krate::TransportConfig::default()
        };
        $krate::Shared::new(build_schema!($krate, $version), config).unwrap()
    }};
}

/// One end of a connection, old or new.
#[derive(Debug)]
pub enum End {
    Old {
        conn: old::Connection,
        inbox: old::Inbox<()>,
        shared: Arc<old::Shared>,
    },
    New {
        conn: new::Connection,
        inbox: new::Inbox<()>,
        shared: Arc<new::Shared>,
    },
}

/// Runs `$body` with `$conn`, `$inbox` and `$shared` bound to whichever side `$end` is.
macro_rules! with {
    ($end:expr, |$conn:ident, $inbox:ident, $shared:ident| $body:expr) => {
        match $end {
            End::Old {
                conn: $conn,
                inbox: $inbox,
                shared: $shared,
            } => $body,
            End::New {
                conn: $conn,
                inbox: $inbox,
                shared: $shared,
            } => $body,
        }
    };
}

/// What `send` did, the same for both crates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sent {
    Queued,
    QueueFull,
    Refused,
}

/// A delivered event: event id, channel id, payload.
pub type Delivery = (u32, u8, Vec<u8>);

/// `Counters` as an array, in declaration order.
pub type Counters = [u64; 15];
/// reliable's `Counters` as an array, in declaration order.
pub type ReliableCounters = [u64; 11];
/// `ConnectionStats` as an array, in declaration order.
pub type Stats = [f32; 11];

impl End {
    pub fn new(kind: Kind, version: u32, limits: Limits, time: f64) -> Self {
        let peer = 1u64 << 16;
        match kind {
            Kind::Old => {
                let shared = shared!(old, version, limits);
                let mut inbox = old::Inbox::new(1);
                inbox.open_slot(old::PeerId(peer));
                let conn = old::Connection::new(shared.clone(), old::PeerId(peer), time);
                End::Old {
                    conn,
                    inbox,
                    shared,
                }
            }
            Kind::New => {
                let shared = shared!(new, version, limits);
                let mut inbox = new::Inbox::new(1);
                inbox.open_slot(new::PeerId(peer));
                let conn = new::Connection::new(shared.clone(), new::PeerId(peer), time);
                End::New {
                    conn,
                    inbox,
                    shared,
                }
            }
        }
    }

    pub fn kind(&self) -> Kind {
        match self {
            End::Old { .. } => Kind::Old,
            End::New { .. } => Kind::New,
        }
    }

    pub fn event_id(&self, name: &str) -> u32 {
        with!(self, |_c, _i, shared| shared
            .schema()
            .event_id(name)
            .unwrap()
            .0)
    }

    pub fn fingerprint(&self) -> u128 {
        with!(self, |_c, _i, shared| shared.schema().fingerprint().0)
    }

    pub fn send(&mut self, event: &str, payload: &[u8]) -> Sent {
        match self {
            End::Old { conn, shared, .. } => {
                let id = shared.schema().event_id(event).unwrap();
                match conn.send(id, payload) {
                    Ok(()) => Sent::Queued,
                    Err(old::SendError::QueueFull(_)) => Sent::QueueFull,
                    Err(_) => Sent::Refused,
                }
            }
            End::New { conn, shared, .. } => {
                let id = shared.schema().event_id(event).unwrap();
                match conn.send(id, payload) {
                    Ok(()) => Sent::Queued,
                    Err(new::SendError::QueueFull(_)) => Sent::QueueFull,
                    Err(_) => Sent::Refused,
                }
            }
        }
    }

    pub fn update(&mut self, time: f64) {
        with!(self, |conn, inbox, _s| {
            inbox.compact();
            conn.update(time);
        });
    }

    /// Receives one datagram; control packets it answers with go to `out`.
    pub fn receive(&mut self, datagram: &[u8], out: &mut Vec<Vec<u8>>) {
        with!(self, |conn, inbox, _s| conn
            .receive(datagram, inbox, |d| out.push(d.to_vec())));
    }

    pub fn write_packets(&mut self, out: &mut Vec<Vec<u8>>) {
        with!(self, |conn, _i, _s| conn
            .write_packets(|d| out.push(d.to_vec())));
    }

    /// Pops every delivered event.
    pub fn drain(&mut self) -> Vec<Delivery> {
        let mut got = Vec::new();
        match self {
            End::Old { inbox, .. } => {
                while let Some((record, payload)) = inbox.pop() {
                    if let old::Record::Message(info) = record {
                        got.push((info.event.0, info.channel.0, payload.to_vec()));
                    }
                }
            }
            End::New { inbox, .. } => {
                while let Some((record, payload)) = inbox.pop() {
                    if let new::Record::Message(info) = record {
                        got.push((info.event.0, info.channel.0, payload.to_vec()));
                    }
                }
            }
        }
        got
    }

    pub fn inbox_len(&self) -> usize {
        with!(self, |_c, inbox, _s| inbox.len())
    }

    /// The handshake state, as its `Debug` text (the same in both crates).
    pub fn state(&self) -> String {
        with!(self, |conn, _i, _s| format!("{:?}", conn.state()))
    }

    pub fn established(&self) -> bool {
        self.state() == "Established"
    }

    pub fn failed(&self) -> bool {
        self.state().starts_with("Failed")
    }

    /// The `Debug` text of the state this end must reach when its peer's schema fingerprint is
    /// `remote`: a schema mismatch naming both fingerprints.
    pub fn schema_mismatch(&self, remote: u128) -> String {
        match self {
            End::Old { shared, .. } => format!(
                "{:?}",
                old::ConnectionState::Failed(old::Failure::SchemaMismatch {
                    local: shared.schema().fingerprint(),
                    remote: old::Fingerprint(remote),
                })
            ),
            End::New { shared, .. } => format!(
                "{:?}",
                new::ConnectionState::Failed(new::Failure::SchemaMismatch {
                    local: shared.schema().fingerprint(),
                    remote: new::Fingerprint(remote),
                })
            ),
        }
    }

    pub fn take_event(&mut self) -> Option<String> {
        with!(self, |conn, _i, _s| conn
            .take_event()
            .map(|e| format!("{e:?}")))
    }

    pub fn queued(&self, channel: u8) -> usize {
        match self {
            End::Old { conn, .. } => conn.queued(old::ChannelId(channel)),
            End::New { conn, .. } => conn.queued(new::ChannelId(channel)),
        }
    }

    pub fn parked_bytes(&self) -> usize {
        with!(self, |conn, _i, _s| conn.parked_bytes())
    }

    pub fn last_malformed(&self) -> Option<String> {
        with!(self, |conn, _i, _s| conn
            .last_malformed()
            .map(|m| format!("{m:?}")))
    }

    pub fn counters(&self) -> Counters {
        with!(self, |conn, _i, _s| {
            let c = conn.counters();
            [
                c.packets_sent,
                c.datagrams_sent,
                c.bytes_sent,
                c.datagrams_received,
                c.bytes_received,
                c.packets_received,
                c.events_queued,
                c.events_sent,
                c.events_resent,
                c.events_received,
                c.events_dropped_on_send,
                c.events_dropped_on_receive,
                c.duplicate_events,
                c.malformed_packets,
                c.packets_refused,
            ]
        })
    }

    pub fn reliable_counters(&self) -> ReliableCounters {
        with!(self, |conn, _i, _s| {
            let c = conn.reliable_counters();
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
        })
    }

    pub fn stats(&self) -> Stats {
        with!(self, |conn, _i, _s| {
            let s = conn.stats();
            [
                s.rtt,
                s.rtt_min,
                s.rtt_max,
                s.rtt_avg,
                s.jitter,
                s.jitter_max,
                s.jitter_stddev,
                s.packet_loss,
                s.sent_kbps,
                s.received_kbps,
                s.acked_kbps,
            ]
        })
    }
}

/// Two float statistics agree: equal, or within a relative 1e-4 (they are computed by the same
/// formulas in f32 on both sides; only summation order could differ).
#[allow(clippy::float_cmp)] // exact equality first, then the tolerance
pub fn close(a: f32, b: f32) -> bool {
    a == b || (a - b).abs() <= 1e-4 * a.abs().max(b.abs()).max(1.0)
}

/// `SplitMix64`, as `dream_net::sim::Rng`.
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    pub fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 * (1.0 / (1u64 << 53) as f64)
    }

    pub fn chance(&mut self, p: f64) -> bool {
        p > 0.0 && self.unit() < p
    }

    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next_u64() % n }
    }
}

/// Impairments of a [`Link`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Faults {
    pub latency: f64,
    /// Extra uniform delay in `[0, jitter)`: reorders datagrams.
    pub jitter: f64,
    pub loss: f64,
    pub duplicate: f64,
}

impl Faults {
    pub const PERFECT: Self = Self {
        latency: 0.0,
        jitter: 0.0,
        loss: 0.0,
        duplicate: 0.0,
    };

    pub fn lossy() -> Self {
        Self {
            latency: 0.03,
            jitter: 0.05,
            loss: 0.15,
            duplicate: 0.1,
        }
    }
}

/// A seeded one-way datagram link. Delivery order is (arrival time, send order), so jitter
/// reorders and every run with the same seed and the same sends is identical.
#[derive(Debug)]
pub struct Link {
    pub faults: Faults,
    rng: Rng,
    in_flight: Vec<(f64, u64, Vec<u8>)>,
    order: u64,
    pub sent: u64,
    pub lost: u64,
    pub duplicated: u64,
}

impl Link {
    pub fn new(faults: Faults, seed: u64) -> Self {
        Self {
            faults,
            rng: Rng::new(seed),
            in_flight: Vec::new(),
            order: 0,
            sent: 0,
            lost: 0,
            duplicated: 0,
        }
    }

    fn enqueue(&mut self, time: f64, datagram: &[u8]) {
        let jitter = if self.faults.jitter > 0.0 {
            self.rng.unit() * self.faults.jitter
        } else {
            0.0
        };
        self.order += 1;
        self.in_flight.push((
            time + self.faults.latency + jitter,
            self.order,
            datagram.to_vec(),
        ));
    }

    pub fn send(&mut self, time: f64, datagram: &[u8]) {
        self.sent += 1;
        if self.rng.chance(self.faults.loss) {
            self.lost += 1;
            return;
        }
        self.enqueue(time, datagram);
        if self.rng.chance(self.faults.duplicate) {
            self.duplicated += 1;
            self.enqueue(time, datagram);
        }
    }

    /// Takes every datagram due by `time`, in arrival order.
    pub fn due(&mut self, time: f64) -> Vec<Vec<u8>> {
        self.in_flight
            .sort_by(|a, b| a.0.total_cmp(&b.0).then(a.1.cmp(&b.1)));
        let n = self.in_flight.partition_point(|d| d.0 <= time);
        self.in_flight.drain(..n).map(|d| d.2).collect()
    }

    pub fn in_flight(&self) -> usize {
        self.in_flight.len()
    }
}

/// Which way a datagram went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    AtoB,
    BtoA,
}

/// Two ends, a link each way, and a log of every datagram either end emitted.
#[derive(Debug)]
pub struct Duo {
    pub a: End,
    pub b: End,
    pub a_to_b: Link,
    pub b_to_a: Link,
    pub time: f64,
    /// Every datagram emitted, in order, when `record` is set.
    pub wire: Vec<(Dir, Vec<u8>)>,
    pub record: bool,
}

impl Duo {
    pub fn new(a: End, b: End, faults: Faults, seed: u64) -> Self {
        Self {
            a,
            b,
            a_to_b: Link::new(faults, seed),
            b_to_a: Link::new(faults, seed ^ 0x5eed_5eed_5eed_5eed),
            time: 0.0,
            wire: Vec::new(),
            record: false,
        }
    }

    pub fn set_faults(&mut self, faults: Faults) {
        self.a_to_b.faults = faults;
        self.b_to_a.faults = faults;
    }

    fn emit(&mut self, dir: Dir, datagrams: Vec<Vec<u8>>) {
        let time = self.time;
        for d in datagrams {
            match dir {
                Dir::AtoB => self.a_to_b.send(time, &d),
                Dir::BtoA => self.b_to_a.send(time, &d),
            }
            if self.record {
                self.wire.push((dir, d));
            }
        }
    }

    /// One host frame, as `dream_net::sim::Pair::step`: update both, deliver what is due (acks
    /// answered on the spot), flush both.
    pub fn step(&mut self, dt: f64) {
        self.time += dt;
        let time = self.time;
        self.a.update(time);
        self.b.update(time);
        for d in self.b_to_a.due(time) {
            let mut out = Vec::new();
            self.a.receive(&d, &mut out);
            self.emit(Dir::AtoB, out);
        }
        for d in self.a_to_b.due(time) {
            let mut out = Vec::new();
            self.b.receive(&d, &mut out);
            self.emit(Dir::BtoA, out);
        }
        let mut out = Vec::new();
        self.a.write_packets(&mut out);
        self.emit(Dir::AtoB, out);
        let mut out = Vec::new();
        self.b.write_packets(&mut out);
        self.emit(Dir::BtoA, out);
    }

    pub fn handshake(&mut self, dt: f64, max_steps: usize) -> bool {
        for _ in 0..max_steps {
            if self.a.established() && self.b.established() {
                return true;
            }
            self.step(dt);
        }
        self.a.established() && self.b.established()
    }
}

/// A payload that names message `n` of stream `stream` and checks its own integrity.
pub fn payload(stream: u8, n: u32, len: usize) -> Vec<u8> {
    let mut p = vec![0u8; len.max(5)];
    p[0] = stream;
    p[1..5].copy_from_slice(&n.to_le_bytes());
    for (i, b) in p.iter_mut().enumerate().skip(5) {
        *b = (n as usize)
            .wrapping_mul(31)
            .wrapping_add(i)
            .wrapping_add(usize::from(stream) * 7) as u8;
    }
    p
}

/// The (stream, number) a [`payload`] names, after checking it is intact.
pub fn check(p: &[u8]) -> (u8, u32) {
    assert!(p.len() >= 5, "payload too short: {p:?}");
    let n = u32::from_le_bytes(p[1..5].try_into().unwrap());
    assert_eq!(
        p,
        payload(p[0], n, p.len()),
        "payload {}/{n} corrupted",
        p[0]
    );
    (p[0], n)
}
