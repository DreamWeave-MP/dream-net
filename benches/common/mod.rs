//! Shared benchmark fixtures.

#![allow(dead_code)]

use std::sync::Arc;

use dream_net::{
    ChannelConfig, Connection, EventTypeId, Inbox, OverflowPolicy, PeerId, Schema, Shared,
    TransportConfig,
};

/// Payload sizes every size sweep uses.
pub const SIZES: [usize; 4] = [16, 64, 256, 1024];

/// A reliable channel (window 1024), an unreliable one (4096, drop oldest), and a bulk
/// reliable one; one event per size per class, plus an 8 KiB blob.
///
/// The transport tracks 512 packets, so a benchmark frame of 256 one-kilobyte events (one
/// packet each) is never throttled by the in-flight cap, while sections of up to 64 events
/// keep `received_packets_buffer_size * max_messages_per_packet + 2 * window <= 65536`.
pub fn schema() -> Schema {
    let mut b = Schema::builder(1).max_messages_per_packet(64);
    let reliable = b
        .channel(ChannelConfig::reliable_ordered("reliable").with_capacity(1024))
        .unwrap();
    let state = b
        .channel(
            ChannelConfig::unreliable_unordered("state")
                .with_capacity(4096)
                .with_overflow(OverflowPolicy::DropOldest),
        )
        .unwrap();
    let bulk = b
        .channel(ChannelConfig::reliable_ordered("bulk").with_capacity(256))
        .unwrap();
    for size in SIZES {
        b.event(format!("R{size}"), reliable, size as u32).unwrap();
        b.event(format!("U{size}"), state, size as u32).unwrap();
    }
    b.event("Blob", bulk, 8192).unwrap();
    b.build().unwrap()
}

/// Transport limits raised so a benchmark frame is never capped by the per-flush packet
/// governor (which exists to bound bursts, not to limit throughput measurements).
pub fn transport() -> TransportConfig {
    TransportConfig {
        max_packets_per_flush: 1024,
        sent_packets_buffer_size: 512,
        received_packets_buffer_size: 512,
        max_pending_events: 1 << 16,
        max_pending_bytes: 64 << 20,
        ..TransportConfig::default()
    }
}

pub fn shared() -> Arc<Shared> {
    Shared::new(schema(), transport()).unwrap()
}

/// The schema, built once: building it hashes the catalogue, which must never land inside a
/// timed loop.
pub fn cached() -> &'static Schema {
    static SCHEMA: std::sync::OnceLock<Schema> = std::sync::OnceLock::new();
    SCHEMA.get_or_init(schema)
}

pub fn reliable(size: usize) -> EventTypeId {
    cached().event_id(&format!("R{size}")).unwrap()
}

pub fn unreliable(size: usize) -> EventTypeId {
    cached().event_id(&format!("U{size}")).unwrap()
}

pub fn blob() -> EventTypeId {
    cached().event_id("Blob").unwrap()
}

/// Two connections wired straight into each other: no link, no copies beyond dream-net's own.
/// Measures dream-net plus reliable and nothing else.
pub struct Direct {
    pub a: Connection,
    pub b: Connection,
    pub a_inbox: Inbox<()>,
    pub b_inbox: Inbox<()>,
    pub time: f64,
    acks: Vec<u8>,
    ack_lens: Vec<usize>,
}

impl Direct {
    pub const PEER: PeerId = PeerId::new(0, 1);

    pub fn new(shared: &Arc<Shared>) -> Self {
        let mut a_inbox = Inbox::new(1);
        let mut b_inbox = Inbox::new(1);
        a_inbox.open_slot(Self::PEER);
        b_inbox.open_slot(Self::PEER);
        let mut pair = Self {
            a: Connection::new(shared.clone(), Self::PEER, 0.0),
            b: Connection::new(shared.clone(), Self::PEER, 0.0),
            a_inbox,
            b_inbox,
            time: 0.0,
            acks: Vec::new(),
            ack_lens: Vec::new(),
        };
        for _ in 0..8 {
            pair.step();
        }
        pair
    }

    /// One host frame on both ends.
    #[inline]
    pub fn step(&mut self) {
        self.time += 1.0 / 60.0;
        self.a_inbox.compact();
        self.b_inbox.compact();
        self.a.update(self.time);
        self.b.update(self.time);
        let (a, a_inbox) = (&mut self.a, &mut self.a_inbox);
        let (acks, lens) = (&mut self.acks, &mut self.ack_lens);
        self.b.write_packets(|d| {
            a.receive(d, a_inbox, |ack| {
                acks.extend_from_slice(ack);
                lens.push(ack.len());
            });
        });
        let mut offset = 0;
        for &len in &self.ack_lens {
            self.b
                .receive(&self.acks[offset..offset + len], &mut self.b_inbox, |_| {});
            offset += len;
        }
        self.acks.clear();
        self.ack_lens.clear();
        let (b, b_inbox) = (&mut self.b, &mut self.b_inbox);
        self.a.write_packets(|d| b.receive(d, b_inbox, |_| {}));
    }
}
