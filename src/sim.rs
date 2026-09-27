//! A deterministic network simulator for tests and benchmarks.
//!
//! [`Link`] is a one-way datagram pipe with seeded latency, jitter, loss, duplication, and
//! bit corruption. [`Pair`] joins two [`Connection`]s with a link each way and steps them the
//! way a host frame does: deliver, update, flush. Correctness never needs real sockets; the
//! netcode integration is tested separately on localhost.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::sync::Arc;

use crate::connection::{Connection, Shared};
use crate::id::PeerId;
use crate::inbox::Inbox;

/// `SplitMix64`: tiny, fast, and deterministic across platforms.
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    /// A generator from a seed.
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    /// The next 64 random bits.
    #[inline]
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A uniform float in `[0, 1)`.
    #[inline]
    pub fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 * (1.0 / (1u64 << 53) as f64)
    }

    /// Whether an event of probability `p` happens.
    #[inline]
    pub fn chance(&mut self, p: f64) -> bool {
        p > 0.0 && self.unit() < p
    }

    /// A uniform integer in `[0, n)`.
    #[inline]
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next_u64() % n }
    }
}

/// Link impairments.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LinkConfig {
    /// One-way latency, seconds.
    pub latency: f64,
    /// Extra uniform random delay in `[0, jitter)`, seconds. Reorders datagrams.
    pub jitter: f64,
    /// Probability a datagram is lost.
    pub loss: f64,
    /// Probability a datagram is delivered twice.
    pub duplicate: f64,
    /// Probability one random bit of a datagram is flipped.
    pub corrupt: f64,
}

impl LinkConfig {
    /// A perfect link: no delay, no loss.
    pub const PERFECT: Self = Self {
        latency: 0.0,
        jitter: 0.0,
        loss: 0.0,
        duplicate: 0.0,
        corrupt: 0.0,
    };

    /// A link with the given latency and nothing else.
    pub fn latency(latency: f64) -> Self {
        Self {
            latency,
            ..Self::PERFECT
        }
    }
}

impl Default for LinkConfig {
    fn default() -> Self {
        Self::PERFECT
    }
}

/// Totals a link has seen.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LinkCounters {
    /// Datagrams offered.
    pub sent: u64,
    /// Datagrams dropped.
    pub lost: u64,
    /// Extra copies delivered.
    pub duplicated: u64,
    /// Datagrams with a flipped bit.
    pub corrupted: u64,
    /// Datagrams delivered (copies included).
    pub delivered: u64,
    /// Bytes offered.
    pub bytes: u64,
}

/// A one-way simulated datagram link.
#[derive(Debug)]
pub struct Link {
    config: LinkConfig,
    rng: Rng,
    in_flight: BinaryHeap<Reverse<(u64, u64, usize)>>,
    buffers: Vec<Vec<u8>>,
    free: Vec<usize>,
    order: u64,
    counters: LinkCounters,
}

fn nanos(seconds: f64) -> u64 {
    (seconds.max(0.0) * 1e9) as u64
}

impl Link {
    /// A link with `config`, seeded for reproducibility.
    pub fn new(config: LinkConfig, seed: u64) -> Self {
        Self {
            config,
            rng: Rng::new(seed),
            in_flight: BinaryHeap::new(),
            buffers: Vec::new(),
            free: Vec::new(),
            order: 0,
            counters: LinkCounters::default(),
        }
    }

    /// Changes the impairments for datagrams sent from now on.
    pub fn set_config(&mut self, config: LinkConfig) {
        self.config = config;
    }

    /// The link's totals.
    pub fn counters(&self) -> LinkCounters {
        self.counters
    }

    /// Datagrams in flight.
    pub fn in_flight(&self) -> usize {
        self.in_flight.len()
    }

    fn enqueue(&mut self, at: f64, datagram: &[u8]) {
        let slot = if let Some(slot) = self.free.pop() {
            self.buffers[slot].clear();
            self.buffers[slot].extend_from_slice(datagram);
            slot
        } else {
            self.buffers.push(datagram.to_vec());
            self.buffers.len() - 1
        };
        if self.rng.chance(self.config.corrupt) && !datagram.is_empty() {
            let bit = self.rng.below(datagram.len() as u64 * 8) as usize;
            self.buffers[slot][bit / 8] ^= 1 << (bit % 8);
            self.counters.corrupted += 1;
        }
        let jitter = if self.config.jitter > 0.0 {
            self.rng.unit() * self.config.jitter
        } else {
            0.0
        };
        self.order += 1;
        self.in_flight.push(Reverse((
            nanos(at + self.config.latency + jitter),
            self.order,
            slot,
        )));
    }

    /// Offers a datagram at `time`.
    pub fn send(&mut self, time: f64, datagram: &[u8]) {
        self.counters.sent += 1;
        self.counters.bytes += datagram.len() as u64;
        if self.rng.chance(self.config.loss) {
            self.counters.lost += 1;
            return;
        }
        self.enqueue(time, datagram);
        if self.rng.chance(self.config.duplicate) {
            self.counters.duplicated += 1;
            self.enqueue(time, datagram);
        }
    }

    /// Delivers every datagram due by `time`, in arrival order.
    pub fn deliver(&mut self, time: f64, mut receive: impl FnMut(&[u8])) {
        let now = nanos(time);
        while let Some(&Reverse((at, _, slot))) = self.in_flight.peek() {
            if at > now {
                break;
            }
            self.in_flight.pop();
            self.counters.delivered += 1;
            receive(&self.buffers[slot]);
            self.free.push(slot);
        }
    }
}

/// Two connections joined by a link each way.
#[derive(Debug)]
pub struct Pair {
    /// The "server" end.
    pub a: Connection,
    /// The "client" end.
    pub b: Connection,
    /// Events `a` received.
    pub a_inbox: Inbox<()>,
    /// Events `b` received.
    pub b_inbox: Inbox<()>,
    /// `a` to `b`.
    pub a_to_b: Link,
    /// `b` to `a`.
    pub b_to_a: Link,
    /// Simulated time, seconds.
    pub time: f64,
}

impl Pair {
    /// The peer id each end delivers as.
    pub const PEER: PeerId = PeerId::new(0, 1);

    /// Joins a connection built from `a` with one built from `b`.
    pub fn new(
        a: Arc<Shared>,
        b: Arc<Shared>,
        a_to_b: LinkConfig,
        b_to_a: LinkConfig,
        seed: u64,
    ) -> Self {
        let mut a_inbox = Inbox::new(1);
        let mut b_inbox = Inbox::new(1);
        a_inbox.open_slot(Self::PEER);
        b_inbox.open_slot(Self::PEER);
        Self {
            a: Connection::new(a, Self::PEER, 0.0),
            b: Connection::new(b, Self::PEER, 0.0),
            a_inbox,
            b_inbox,
            a_to_b: Link::new(a_to_b, seed),
            b_to_a: Link::new(b_to_a, seed ^ 0x5eed_5eed_5eed_5eed),
            time: 0.0,
        }
    }

    /// Joins two connections of the same schema over the same link each way.
    pub fn symmetric(shared: &Arc<Shared>, link: LinkConfig, seed: u64) -> Self {
        Self::new(shared.clone(), shared.clone(), link, link, seed)
    }

    /// Advances one frame of `dt` seconds the way a host does: update (so received packets
    /// are timestamped with this frame's time), deliver due datagrams, flush.
    pub fn step(&mut self, dt: f64) {
        self.time += dt;
        let time = self.time;
        self.a_inbox.compact();
        self.b_inbox.compact();
        self.a.update(time, &mut self.a_inbox);
        self.b.update(time, &mut self.b_inbox);
        let (a, a_inbox, a_to_b) = (&mut self.a, &mut self.a_inbox, &mut self.a_to_b);
        self.b_to_a.deliver(time, |d| {
            a.receive(d, a_inbox, |ack| a_to_b.send(time, ack));
        });
        let (b, b_inbox, b_to_a) = (&mut self.b, &mut self.b_inbox, &mut self.b_to_a);
        self.a_to_b.deliver(time, |d| {
            b.receive(d, b_inbox, |ack| b_to_a.send(time, ack));
        });
        let a_to_b = &mut self.a_to_b;
        self.a.write_packets(|d| a_to_b.send(time, d));
        let b_to_a = &mut self.b_to_a;
        self.b.write_packets(|d| b_to_a.send(time, d));
    }

    /// Steps until both ends are established or `max_steps` frames pass. Returns whether
    /// both established.
    pub fn handshake(&mut self, dt: f64, max_steps: usize) -> bool {
        use crate::lifecycle::ConnectionState::Established;
        for _ in 0..max_steps {
            if self.a.state() == Established && self.b.state() == Established {
                return true;
            }
            self.step(dt);
        }
        self.a.state() == Established && self.b.state() == Established
    }
}
