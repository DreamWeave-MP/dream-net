//! Long randomized sessions (§107 of the design): many peers, mixed channels, loss, jitter,
//! reordering, duplication, fragmented payloads, reconnects, stalled polling, and message id
//! wrap, checking exactly-once ordered delivery, bounded memory, and no failures throughout.
//!
//! `cargo test` runs a short soak. The release gate runs a long one:
//! `DREAM_NET_SOAK_FRAMES=200000 cargo test --release --test soak -- --nocapture`.

mod common;

use std::sync::Arc;

use common::test_schema;
use dream_net::sim::{LinkConfig, Pair, Rng};
use dream_net::{ConnectionState, EventTypeId, Inbox, Record, SendError, Shared, TransportConfig};

const DT: f64 = 1.0 / 60.0;
const PAIRS: usize = 16;

fn frames() -> u64 {
    std::env::var("DREAM_NET_SOAK_FRAMES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1500)
}

/// One direction of one reliable event stream.
#[derive(Default)]
struct Stream {
    sent: u32,
    received: u32,
}

struct Session {
    pair: Pair,
    /// Reliable streams b→a: Chat, Blob; a→b: Spawn.
    chat: Stream,
    blob: Stream,
    spawn: Stream,
    stall_until: u64,
    born: u64,
}

struct Events {
    chat: EventTypeId,
    spawn: EventTypeId,
    mv: EventTypeId,
    ping: EventTypeId,
    blob: EventTypeId,
}

fn payload(n: u32, len: usize) -> Vec<u8> {
    let mut p = vec![(n % 251) as u8; len.max(4)];
    p[..4].copy_from_slice(&n.to_le_bytes());
    p
}

fn link(rng: &mut Rng) -> LinkConfig {
    LinkConfig {
        latency: 0.005 + rng.unit() * 0.1,
        jitter: rng.unit() * 0.05,
        loss: [0.0, 0.01, 0.05, 0.2][rng.below(4) as usize],
        duplicate: rng.unit() * 0.05,
        corrupt: 0.0,
    }
}

fn session(shared: &Arc<Shared>, rng: &mut Rng, frame: u64) -> Session {
    let mut pair = Pair::symmetric(shared, link(rng), rng.next_u64());
    assert!(pair.handshake(DT, 1200), "handshake failed");
    Session {
        pair,
        chat: Stream::default(),
        blob: Stream::default(),
        spawn: Stream::default(),
        stall_until: 0,
        born: frame,
    }
}

fn drain(
    inbox: &mut Inbox<()>,
    events: &Events,
    streams: [(&mut Stream, EventTypeId); 2],
) -> usize {
    let mut buffer = vec![0u8; 8192];
    let [(first, first_event), (second, second_event)] = streams;
    let mut n = 0;
    while let Some(record) = inbox.pop_into(&mut buffer).unwrap() {
        let Record::Message(info) = record else {
            continue;
        };
        n += 1;
        let value = u32::from_le_bytes(buffer[..4].try_into().unwrap());
        let stream = if info.event == first_event {
            &mut *first
        } else if info.event == second_event {
            &mut *second
        } else {
            assert!(info.event == events.mv || info.event == events.ping);
            continue;
        };
        assert_eq!(
            value, stream.received,
            "reliable stream out of order or duplicated"
        );
        assert_eq!(
            buffer[4..info.len],
            vec![(value % 251) as u8; info.len - 4][..]
        );
        stream.received += 1;
    }
    n
}

impl Session {
    /// One frame of mixed traffic both ways.
    fn traffic(&mut self, rng: &mut Rng, events: &Events) {
        let pair = &mut self.pair;
        // b → a: a burst of chat, sometimes a fragmented blob, a stream of state
        for _ in 0..rng.below(12) {
            let chat = payload(self.chat.sent, 4 + rng.below(250) as usize);
            match pair.b.send(events.chat, &chat) {
                Ok(()) => self.chat.sent += 1,
                Err(SendError::QueueFull(_)) => break,
                Err(e) => panic!("{e}"),
            }
        }
        if rng.chance(0.05) {
            let blob = payload(self.blob.sent, 1000 + rng.below(7000) as usize);
            if pair.b.send(events.blob, &blob).is_ok() {
                self.blob.sent += 1;
            }
        }
        for i in 0..rng.below(8) {
            let _ = pair.b.send(events.mv, &payload(i as u32, 12));
        }
        // a → b: spawns and pings
        for _ in 0..rng.below(4) {
            let spawn = payload(self.spawn.sent, 4 + rng.below(1000) as usize);
            if pair.a.send(events.spawn, &spawn).is_ok() {
                self.spawn.sent += 1;
            }
        }
        let _ = pair.a.send(events.ping, &[]);
    }

    /// Polls both ends (a only when not stalled), checking every reliable stream.
    fn poll(&mut self, events: &Events, poll_a: bool) -> usize {
        let mut delivered = 0;
        if poll_a {
            delivered += drain(
                &mut self.pair.a_inbox,
                events,
                [(&mut self.chat, events.chat), (&mut self.blob, events.blob)],
            );
        }
        delivered
            + drain(
                &mut self.pair.b_inbox,
                events,
                [
                    (&mut self.spawn, events.spawn),
                    (&mut Stream::default(), EventTypeId(u32::MAX)),
                ],
            )
    }

    fn caught_up(&self) -> bool {
        self.chat.received == self.chat.sent
            && self.blob.received == self.blob.sent
            && self.spawn.received == self.spawn.sent
    }

    /// Heals the links and steps until every reliable stream has fully arrived.
    fn catch_up(&mut self, events: &Events) {
        self.pair.set_perfect();
        for _ in 0..5000 {
            self.pair.step(DT);
            self.poll(events, true);
            if self.caught_up() {
                return;
            }
        }
        panic!(
            "session born at {} did not catch up: chat {}/{} blob {}/{} spawn {}/{}",
            self.born,
            self.chat.received,
            self.chat.sent,
            self.blob.received,
            self.blob.sent,
            self.spawn.received,
            self.spawn.sent
        );
    }

    /// Both ends are healthy and within their receive bounds; returns their peak memory.
    fn check(&self, parked_budget: usize) -> usize {
        let mut peak = 0;
        for end in [&self.pair.a, &self.pair.b] {
            assert!(
                matches!(end.state(), ConnectionState::Established),
                "{:?} {:?} {:?}",
                end.state(),
                end.last_malformed(),
                end.counters()
            );
            assert!(end.parked_bytes() <= parked_budget);
            let memory = end.memory_usage();
            assert!(
                memory.receive <= 2 * parked_budget + 64 * 1024,
                "{memory:?}"
            );
            peak = peak.max(memory.total());
        }
        peak
    }
}

#[test]
fn soak() {
    let schema = test_schema();
    let events = Events {
        chat: schema.event_id("Chat").unwrap(),
        spawn: schema.event_id("Spawn").unwrap(),
        mv: schema.event_id("Move").unwrap(),
        ping: schema.event_id("Ping").unwrap(),
        blob: schema.event_id("Blob").unwrap(),
    };
    let config = TransportConfig {
        max_pending_events: 64,
        max_parked_bytes: 64 * 1024,
        ..TransportConfig::default()
    };
    let parked_budget = config.max_parked_bytes;
    let shared = Shared::new(schema, config).unwrap();
    let mut rng = Rng::new(0x50A4);
    let mut sessions: Vec<Session> = (0..PAIRS).map(|_| session(&shared, &mut rng, 0)).collect();
    let frames = frames();
    let (mut delivered, mut reconnects, mut peak_memory) = (0usize, 0usize, 0usize);

    for frame in 0..frames {
        for s in &mut sessions {
            s.traffic(&mut rng, &events);
            s.pair.step(DT);
            // the host sometimes stops polling for a while
            if s.stall_until <= frame && rng.chance(0.01) {
                s.stall_until = frame + 5 + rng.below(60);
            }
            delivered += s.poll(&events, s.stall_until <= frame);
            peak_memory = peak_memory.max(s.check(parked_budget));
        }
        // churn: every so often a session is torn down, after checking it caught up, and a
        // fresh one takes its place
        if frame > 0 && frame % 500 == 0 {
            let index = rng.below(PAIRS as u64) as usize;
            let fresh = session(&shared, &mut rng, frame);
            std::mem::replace(&mut sessions[index], fresh).catch_up(&events);
            reconnects += 1;
        }
    }

    // finally every live session must catch up too
    let mut wrapped = 0;
    for s in &mut sessions {
        s.catch_up(&events);
        wrapped += usize::from(s.chat.sent > 65_536);
    }
    println!(
        "soak: {frames} frames, {PAIRS} pairs, {delivered} events delivered, {reconnects} reconnects, \
         {wrapped} sessions past message id wrap, peak connection memory {} KiB",
        peak_memory / 1024
    );
    // memory stays bounded: queues, pools, windows, and reliable's buffers only
    assert!(peak_memory < 2 * 1024 * 1024, "{peak_memory}");
}
