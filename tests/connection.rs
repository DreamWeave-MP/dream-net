//! Channel and connection behaviour over the deterministic simulator: the reliability golden
//! tests, unreliable semantics, the handshake, backpressure, and hostile input.

// CI passes -W clippy::pedantic on the command line, overriding the manifest's lint table;
// test code casts freely between widths it controls.
#![allow(
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]

mod common;

use std::sync::Arc;

use common::{PacketSpec, encode, test_schema, test_schema_versioned};
use dream_net::sim::{LinkConfig, Pair};
use dream_net::wire::{Hello, Layout, WIRE_VERSION};
use dream_net::{
    ChannelId, Connection, ConnectionEvent, ConnectionState, EventTypeId, Failure, Fingerprint,
    Inbox, Record, SendError, Shared, TransportConfig,
};
use dream_net_native::reliable::{Endpoint, MAX_PACKET_HEADER_BYTES};

const DT: f64 = 1.0 / 60.0;

fn shared(config: TransportConfig) -> Arc<Shared> {
    Shared::new(test_schema(), config).unwrap()
}

fn event(name: &str) -> EventTypeId {
    test_schema().event_id(name).unwrap()
}

/// A payload that identifies message `n` and checks its own integrity.
fn payload(n: u32, len: usize) -> Vec<u8> {
    let mut p = vec![0u8; len.max(4)];
    p[..4].copy_from_slice(&n.to_le_bytes());
    for (i, b) in p.iter_mut().enumerate().skip(4) {
        *b = (n as usize).wrapping_mul(31).wrapping_add(i) as u8;
    }
    p
}

fn check(p: &[u8]) -> u32 {
    let n = u32::from_le_bytes(p[..4].try_into().unwrap());
    assert_eq!(p, payload(n, p.len()), "payload {n} corrupted");
    n
}

fn drain(inbox: &mut Inbox<()>) -> Vec<(EventTypeId, ChannelId, Vec<u8>)> {
    let mut out = Vec::new();
    while let Some((record, payload)) = inbox.pop() {
        if let Record::Message(info) = record {
            out.push((info.event, info.channel, payload.to_vec()));
        }
    }
    out
}

/// Streams `count` events from `b` to `a`, sending as fast as the channel accepts, and returns
/// the message numbers in delivery order.
fn stream(
    pair: &mut Pair,
    event: EventTypeId,
    count: u32,
    len: usize,
    max_steps: usize,
) -> Vec<u32> {
    let mut next = 0;
    let mut received = Vec::new();
    for _ in 0..max_steps {
        while next < count {
            match pair.b.send(event, &payload(next, len)) {
                Ok(()) => next += 1,
                Err(SendError::QueueFull(_)) => break,
                Err(e) => panic!("{e}"),
            }
        }
        pair.step(DT);
        for (e, _, p) in drain(&mut pair.a_inbox) {
            assert_eq!(e, event);
            received.push(check(&p));
        }
        if received.len() as u32 == count && next == count {
            break;
        }
    }
    received
}

fn lossy() -> LinkConfig {
    LinkConfig {
        latency: 0.05,
        jitter: 0.04,
        loss: 0.2,
        duplicate: 0.1,
        corrupt: 0.0,
    }
}

#[test]
fn handshake_establishes_both_ends_and_stops_sending_hello() {
    let s = shared(TransportConfig::default());
    let mut pair = Pair::symmetric(&s, LinkConfig::latency(0.02), 1);
    assert_eq!(pair.a.state(), ConnectionState::Handshaking);
    assert!(pair.handshake(DT, 60));
    assert_eq!(pair.a.take_event(), Some(ConnectionEvent::Established));
    assert_eq!(pair.a.take_event(), None);
    assert_eq!(pair.b.take_event(), Some(ConnectionEvent::Established));
    // once each hello is acked, idle packets shrink to the reliable header plus one byte
    for _ in 0..30 {
        pair.step(DT);
    }
    let before = pair.a.counters();
    pair.step(0.2);
    let after = pair.a.counters();
    let datagrams = after.datagrams_sent - before.datagrams_sent;
    let bytes = after.bytes_sent - before.bytes_sent;
    assert_eq!(datagrams, 1);
    assert!(bytes <= 1 + MAX_PACKET_HEADER_BYTES as u64, "{bytes} bytes");
}

#[test]
fn one_reliable_message() {
    let s = shared(TransportConfig::default());
    let mut pair = Pair::symmetric(&s, LinkConfig::PERFECT, 2);
    assert!(pair.handshake(DT, 10));
    pair.b.send(event("Chat"), b"hello").unwrap();
    pair.step(DT);
    pair.step(DT);
    let got = drain(&mut pair.a_inbox);
    assert_eq!(got, vec![(event("Chat"), ChannelId(0), b"hello".to_vec())]);
}

#[test]
fn reliable_many_messages_perfect_link() {
    let s = shared(TransportConfig::default());
    let mut pair = Pair::symmetric(&s, LinkConfig::PERFECT, 3);
    assert!(pair.handshake(DT, 10));
    let got = stream(&mut pair, event("Chat"), 5000, 40, 10_000);
    assert_eq!(got, (0..5000).collect::<Vec<_>>());
    assert_eq!(pair.b.counters().events_resent, 0);
}

#[test]
fn reliable_exactly_once_in_order_under_loss_reorder_and_duplication() {
    for seed in 0..8 {
        let s = shared(TransportConfig::default());
        let mut pair = Pair::symmetric(&s, lossy(), 100 + seed);
        assert!(pair.handshake(DT, 600), "seed {seed}");
        let got = stream(&mut pair, event("Chat"), 2000, 24, 100_000);
        assert_eq!(got, (0..2000).collect::<Vec<_>>(), "seed {seed}");
        let counters = pair.b.counters();
        assert!(
            counters.events_resent > 0,
            "seed {seed}: loss must force resends"
        );
        assert!(pair.b_to_a.counters().duplicated > 0);
    }
}

#[test]
fn reliable_message_ids_wrap() {
    let s = shared(TransportConfig::default());
    let mut pair = Pair::symmetric(&s, LinkConfig::PERFECT, 4);
    assert!(pair.handshake(DT, 10));
    let count = 70_000;
    let got = stream(&mut pair, event("Chat"), count, 4, 100_000);
    assert_eq!(got.len(), count as usize);
    assert!(got.iter().copied().eq(0..count));
}

#[test]
fn reliable_message_ids_wrap_under_loss() {
    let s = shared(TransportConfig::default());
    let link = LinkConfig {
        loss: 0.1,
        jitter: 0.01,
        ..LinkConfig::latency(0.01)
    };
    let mut pair = Pair::symmetric(&s, link, 5);
    assert!(pair.handshake(DT, 600));
    let count = 66_000;
    let got = stream(&mut pair, event("Chat"), count, 4, 400_000);
    assert!(got.iter().copied().eq(0..count));
}

#[test]
fn fragmented_reliable_events_survive_loss() {
    let s = shared(TransportConfig::default());
    let link = LinkConfig {
        loss: 0.05,
        jitter: 0.02,
        duplicate: 0.05,
        ..LinkConfig::latency(0.03)
    };
    let mut pair = Pair::symmetric(&s, link, 6);
    assert!(pair.handshake(DT, 600));
    let got = stream(&mut pair, event("Blob"), 200, 8000, 100_000);
    assert_eq!(got, (0..200).collect::<Vec<_>>());
    assert!(pair.b.reliable_counters().num_fragments_sent > 0);
    assert!(pair.a.reliable_counters().num_fragments_received > 0);
}

#[test]
fn reliable_queue_refuses_when_the_window_is_full() {
    let s = shared(TransportConfig::default());
    let mut pair = Pair::symmetric(&s, LinkConfig::PERFECT, 7);
    assert!(pair.handshake(DT, 10));
    for n in 0..64 {
        pair.b.send(event("Chat"), &payload(n, 8)).unwrap();
    }
    assert_eq!(
        pair.b.send(event("Chat"), b"overflow"),
        Err(SendError::QueueFull(ChannelId(0)))
    );
    assert_eq!(pair.b.queued(ChannelId(0)), 64);
    // acks free the window
    for _ in 0..4 {
        pair.step(DT);
    }
    assert_eq!(pair.b.queued(ChannelId(0)), 0);
    pair.b.send(event("Chat"), b"room again").unwrap();
}

#[test]
fn send_rejects_misuse_without_queueing() {
    let s = shared(TransportConfig::default());
    let mut pair = Pair::symmetric(&s, LinkConfig::PERFECT, 8);
    assert_eq!(
        pair.b.send(EventTypeId(99), b""),
        Err(SendError::UnknownEvent(EventTypeId(99)))
    );
    assert_eq!(
        pair.b.send(event("Move"), &[0; 65]),
        Err(SendError::PayloadTooLarge {
            event: event("Move"),
            len: 65,
            max: 64
        })
    );
    assert_eq!(pair.b.counters().events_queued, 0);
}

#[test]
fn unreliable_delivers_each_event_at_most_once_and_never_resends() {
    let s = shared(TransportConfig::default());
    let mut pair = Pair::symmetric(&s, lossy(), 9);
    assert!(pair.handshake(DT, 600));
    let mut seen = std::collections::HashSet::new();
    let mut out_of_order = false;
    let mut last = None;
    let mut n = 0u32;
    for _ in 0..600 {
        for _ in 0..20 {
            pair.b.send(event("Move"), &payload(n, 12)).unwrap();
            n += 1;
        }
        pair.step(DT);
        for (_, channel, p) in drain(&mut pair.a_inbox) {
            assert_eq!(channel, ChannelId(1));
            let m = check(&p);
            assert!(seen.insert(m), "event {m} delivered twice");
            if last.is_some_and(|l| m < l) {
                out_of_order = true;
            }
            last = Some(m);
        }
    }
    let counters = pair.b.counters();
    assert_eq!(counters.events_resent, 0);
    assert!(seen.len() < n as usize, "20% loss must lose some events");
    assert!(seen.len() > n as usize / 2);
    assert!(out_of_order, "jitter must reorder some events");
}

#[test]
fn unreliable_overflow_policies() {
    use dream_net::{ChannelConfig, OverflowPolicy, Schema};
    for (policy, expect) in [
        (
            OverflowPolicy::Fail,
            Err(SendError::QueueFull(ChannelId(0))),
        ),
        (OverflowPolicy::DropNewest, Ok(())),
        (OverflowPolicy::DropOldest, Ok(())),
    ] {
        let mut b = Schema::builder(0);
        let c = b
            .channel(
                ChannelConfig::unreliable_unordered("u")
                    .with_capacity(4)
                    .with_overflow(policy),
            )
            .unwrap();
        b.event("E", c, 8).unwrap();
        let s = Shared::new(b.build().unwrap(), TransportConfig::default()).unwrap();
        let mut pair = Pair::symmetric(&s, LinkConfig::PERFECT, 10);
        assert!(pair.handshake(DT, 10));
        for n in 0..4 {
            pair.b.send(EventTypeId(0), &payload(n, 4)).unwrap();
        }
        assert_eq!(
            pair.b.send(EventTypeId(0), &payload(4, 4)),
            expect,
            "{policy:?}"
        );
        pair.step(DT);
        pair.step(DT);
        let got: Vec<u32> = drain(&mut pair.a_inbox)
            .iter()
            .map(|(_, _, p)| check(p))
            .collect();
        let want = match policy {
            OverflowPolicy::DropOldest => vec![1, 2, 3, 4],
            _ => vec![0, 1, 2, 3],
        };
        assert_eq!(got, want, "{policy:?}");
        let dropped = u64::from(policy != OverflowPolicy::Fail);
        assert_eq!(pair.b.counters().events_dropped_on_send, dropped);
    }
}

#[test]
fn schema_mismatch_fails_both_ends_with_both_fingerprints() {
    let ours = test_schema();
    let theirs = test_schema_versioned(2);
    let a = Shared::new(ours.clone(), TransportConfig::default()).unwrap();
    let b = Shared::new(theirs.clone(), TransportConfig::default()).unwrap();
    let mut pair = Pair::new(a, b, LinkConfig::PERFECT, LinkConfig::PERFECT, 11);
    for _ in 0..5 {
        pair.step(DT);
    }
    assert_eq!(
        pair.a.take_event(),
        Some(ConnectionEvent::Failed(Failure::SchemaMismatch {
            local: ours.fingerprint(),
            remote: theirs.fingerprint(),
        }))
    );
    assert_eq!(
        pair.b.state(),
        ConnectionState::Failed(Failure::SchemaMismatch {
            local: theirs.fingerprint(),
            remote: ours.fingerprint(),
        })
    );
    assert!(pair.a_inbox.is_empty() && pair.b_inbox.is_empty());
}

#[test]
fn every_schema_difference_is_detected_before_delivery() {
    use dream_net::{ChannelConfig, Schema};
    let variants: Vec<fn() -> Schema> = vec![
        // different event set
        || {
            let mut b = Schema::builder(1).max_messages_per_packet(32);
            let r = b
                .channel(ChannelConfig::reliable_ordered("reliable").with_capacity(64))
                .unwrap();
            b.channel(ChannelConfig::unreliable_unordered("state").with_capacity(64))
                .unwrap();
            b.channel(ChannelConfig::reliable_ordered("bulk").with_capacity(16))
                .unwrap();
            b.event("Chat", r, 256).unwrap();
            b.build().unwrap()
        },
        // same events, different channel config
        || {
            let mut b = Schema::builder(1).max_messages_per_packet(32);
            let r = b
                .channel(ChannelConfig::reliable_ordered("reliable").with_capacity(32))
                .unwrap();
            let s = b
                .channel(ChannelConfig::unreliable_unordered("state").with_capacity(64))
                .unwrap();
            let k = b
                .channel(ChannelConfig::reliable_ordered("bulk").with_capacity(16))
                .unwrap();
            b.event("Chat", r, 256).unwrap();
            b.event("Spawn", r, 1024).unwrap();
            b.event("Move", s, 64).unwrap();
            b.event("Ping", s, 0).unwrap();
            b.event("Blob", k, 8000).unwrap();
            b.build().unwrap()
        },
        // same everything, different codec version
        || {
            let mut b = Schema::builder(1).max_messages_per_packet(32);
            let r = b
                .channel(ChannelConfig::reliable_ordered("reliable").with_capacity(64))
                .unwrap();
            let s = b
                .channel(ChannelConfig::unreliable_unordered("state").with_capacity(64))
                .unwrap();
            let k = b
                .channel(ChannelConfig::reliable_ordered("bulk").with_capacity(16))
                .unwrap();
            b.event("Chat", r, 256).unwrap();
            b.event("Spawn", r, 1024).unwrap();
            b.event_with_codec("Move", s, 64, 2).unwrap();
            b.event("Ping", s, 0).unwrap();
            b.event("Blob", k, 8000).unwrap();
            b.build().unwrap()
        },
    ];
    for (index, variant) in variants.into_iter().enumerate() {
        let a = shared(TransportConfig::default());
        let b = Shared::new(variant(), TransportConfig::default()).unwrap();
        let mut pair = Pair::new(a, b, LinkConfig::PERFECT, LinkConfig::PERFECT, 12);
        // queue gameplay on both ends before the handshake: none of it may be delivered
        pair.a.send(event("Chat"), b"early").unwrap();
        let _ = pair.b.send(EventTypeId(0), b"");
        for _ in 0..5 {
            pair.step(DT);
        }
        assert!(
            matches!(
                pair.a.state(),
                ConnectionState::Failed(Failure::SchemaMismatch { .. })
            ),
            "variant {index}"
        );
        assert!(matches!(
            pair.b.state(),
            ConnectionState::Failed(Failure::SchemaMismatch { .. })
        ));
        assert!(
            pair.a_inbox.is_empty() && pair.b_inbox.is_empty(),
            "variant {index}"
        );
    }
}

/// Wraps a connection packet in reliable framing, as the remote endpoint would.
fn framed(endpoint: &mut Endpoint, packet: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    endpoint.send_packet(packet, |_, d| out.push(d.to_vec()));
    out
}

fn lone_connection(config: TransportConfig) -> (Connection, Inbox<()>, Endpoint) {
    let remote = Endpoint::new(config.reliable_config("remote"), 0.0).unwrap();
    let s = shared(config);
    let peer = Pair::PEER;
    let mut inbox = Inbox::new(1);
    inbox.open_slot(peer);
    (Connection::new(s, peer, 0.0), inbox, remote)
}

#[test]
fn protocol_mismatch_is_distinguished_from_schema_mismatch() {
    let (mut conn, mut inbox, mut remote) = lone_connection(TransportConfig::default());
    let layout = Layout::new(&test_schema());
    let hello = Hello {
        wire_version: WIRE_VERSION + 1,
        fingerprint: test_schema().fingerprint(),
    };
    let packet = encode(
        &layout,
        &PacketSpec {
            hello: Some(hello),
            sections: vec![],
        },
    );
    for d in framed(&mut remote, &packet) {
        conn.receive(&d, &mut inbox, |_| {});
    }
    assert_eq!(
        conn.take_event(),
        Some(ConnectionEvent::Failed(Failure::ProtocolMismatch {
            local: WIRE_VERSION,
            remote: WIRE_VERSION + 1
        }))
    );
}

#[test]
fn malformed_packets_disconnect_at_the_limit() {
    for limit in [1u32, 3] {
        let config = TransportConfig {
            malformed_limit: limit,
            ..TransportConfig::default()
        };
        let (mut conn, mut inbox, mut remote) = lone_connection(config);
        for strike in 1..=limit {
            assert_eq!(conn.state(), ConnectionState::Handshaking);
            for d in framed(&mut remote, &[0xFF, 0xFF, 0xFF]) {
                conn.receive(&d, &mut inbox, |_| {});
            }
            assert_eq!(conn.counters().malformed_packets, u64::from(strike));
        }
        assert_eq!(
            conn.state(),
            ConnectionState::Failed(Failure::MalformedData)
        );
        // a failed connection ignores everything and sends nothing
        let mut sent = 0;
        conn.write_packets(|_| sent += 1);
        assert_eq!(sent, 0);
    }
}

#[test]
fn data_before_hello_is_refused() {
    let (mut conn, mut inbox, mut remote) = lone_connection(TransportConfig::default());
    let layout = Layout::new(&test_schema());
    let packet = encode(
        &layout,
        &PacketSpec {
            hello: None,
            sections: vec![common::SectionSpec {
                channel: ChannelId(1),
                first_id: 0,
                deltas: vec![],
                messages: vec![(event("Move"), vec![1])],
            }],
        },
    );
    for d in framed(&mut remote, &packet) {
        conn.receive(&d, &mut inbox, |_| {});
    }
    assert!(inbox.is_empty());
    assert_eq!(
        conn.state(),
        ConnectionState::Failed(Failure::MalformedData)
    );
}

#[test]
fn empty_and_garbage_datagrams_never_panic() {
    let config = TransportConfig {
        malformed_limit: u32::MAX,
        ..TransportConfig::default()
    };
    let (mut conn, mut inbox, _) = lone_connection(config);
    conn.receive(&[], &mut inbox, |_| {});
    let mut rng = dream_net::sim::Rng::new(13);
    for _ in 0..20_000 {
        let len = rng.below(1300) as usize;
        let d: Vec<u8> = (0..len).map(|_| rng.next_u64() as u8).collect();
        conn.receive(&d, &mut inbox, |_| {});
    }
    assert!(inbox.is_empty());
}

#[test]
fn handshake_times_out() {
    let (mut conn, _inbox, _) = lone_connection(TransportConfig {
        handshake_timeout: 2.0,
        ..TransportConfig::default()
    });
    conn.update(1.9);
    assert_eq!(conn.take_event(), None);
    conn.update(2.0);
    assert_eq!(
        conn.take_event(),
        Some(ConnectionEvent::Failed(Failure::HandshakeTimeout))
    );
}

#[test]
fn inbox_backpressure_holds_reliable_and_drops_unreliable() {
    let config = TransportConfig {
        max_pending_events: 8,
        ..TransportConfig::default()
    };
    let s = shared(config);
    let mut pair = Pair::symmetric(&s, LinkConfig::PERFECT, 14);
    assert!(pair.handshake(DT, 10));
    for n in 0..40 {
        pair.b.send(event("Chat"), &payload(n, 8)).unwrap();
        pair.b.send(event("Move"), &payload(1000 + n, 8)).unwrap();
    }
    for _ in 0..10 {
        pair.step(DT);
    }
    // nothing polled yet: the inbox holds exactly the limit
    assert_eq!(pair.a_inbox.len(), 8);
    assert!(pair.a.counters().events_dropped_on_receive > 0);
    // the next reliable event was refused (unacked, so the sender keeps it); polling makes
    // room and the resends arrive in order
    let mut reliable = Vec::new();
    for _ in 0..40 {
        for (e, _, p) in drain(&mut pair.a_inbox) {
            if e == event("Chat") {
                reliable.push(check(&p));
            }
        }
        pair.step(DT);
    }
    assert_eq!(reliable, (0..40).collect::<Vec<_>>());
}

#[test]
fn large_events_are_not_starved_by_small_ones() {
    let s = shared(TransportConfig::default());
    let mut pair = Pair::symmetric(&s, LinkConfig::PERFECT, 15);
    assert!(pair.handshake(DT, 10));
    pair.b.send(event("Blob"), &payload(7, 8000)).unwrap();
    let mut arrived = None;
    for step in 0..20 {
        // keep every channel busy with small events
        for n in 0..60 {
            let _ = pair.b.send(event("Move"), &payload(n, 60));
            let _ = pair.b.send(event("Chat"), &payload(n, 200));
        }
        pair.step(DT);
        if drain(&mut pair.a_inbox)
            .iter()
            .any(|(e, _, p)| *e == event("Blob") && check(p) == 7)
        {
            arrived = Some(step);
            break;
        }
    }
    assert!(
        arrived.is_some_and(|s| s <= 3),
        "blob arrived at {arrived:?}"
    );
}

#[test]
fn many_small_events_share_packets() {
    let s = shared(TransportConfig::default());
    let mut pair = Pair::symmetric(&s, LinkConfig::PERFECT, 16);
    assert!(pair.handshake(DT, 10));
    let before = pair.b.counters();
    for n in 0..60 {
        pair.b.send(event("Move"), &payload(n, 8)).unwrap();
        pair.b.send(event("Chat"), &payload(n, 8)).unwrap();
    }
    pair.step(DT);
    let after = pair.b.counters();
    // 120 events of ~10 bytes fit two 1191-byte packets; sections cap at 32 messages per
    // channel, so it takes exactly two
    assert_eq!(after.packets_sent - before.packets_sent, 2);
    pair.step(DT);
    assert_eq!(drain(&mut pair.a_inbox).len(), 120);
}

#[test]
fn corruption_never_panics() {
    let config = TransportConfig {
        malformed_limit: u32::MAX,
        ..TransportConfig::default()
    };
    let s = shared(config);
    let link = LinkConfig {
        corrupt: 0.2,
        loss: 0.05,
        duplicate: 0.05,
        jitter: 0.02,
        latency: 0.01,
    };
    let mut pair = Pair::symmetric(&s, link, 17);
    for step in 0..3000u32 {
        let _ = pair.b.send(event("Chat"), &payload(step, 16));
        let _ = pair.b.send(event("Move"), &payload(step, 16));
        let _ = pair.a.send(event("Blob"), &payload(step, 3000));
        pair.step(DT);
        drain(&mut pair.a_inbox);
        drain(&mut pair.b_inbox);
    }
    assert!(pair.a_to_b.counters().corrupted > 0);
}

#[test]
fn stats_track_the_link() {
    let s = shared(TransportConfig::default());
    let link = LinkConfig {
        loss: 0.1,
        ..LinkConfig::latency(0.05)
    };
    let mut pair = Pair::symmetric(&s, link, 18);
    assert!(pair.handshake(DT, 600));
    for n in 0..1200 {
        let _ = pair.b.send(event("Move"), &payload(n, 32));
        pair.step(DT);
        drain(&mut pair.a_inbox);
    }
    let stats = pair.b.stats();
    // two 50 ms legs plus up to a frame of ack delay
    assert!(stats.rtt_avg > 90.0 && stats.rtt_avg < 150.0, "{stats:?}");
    assert!(
        stats.packet_loss > 3.0 && stats.packet_loss < 25.0,
        "{stats:?}"
    );
    assert!(stats.sent_kbps > 0.0);
    let _ = Fingerprint::default();
}

#[test]
fn bursts_larger_than_the_ack_window_are_fully_acknowledged() {
    // one flush of ~250 packets: far more than reliable's 33-packet ack window
    use dream_net::{ChannelConfig, Schema};
    let config = TransportConfig {
        max_packets_per_flush: 1024,
        ..TransportConfig::default()
    };
    let mut b = Schema::builder(0);
    let r = b
        .channel(ChannelConfig::reliable_ordered("r").with_capacity(1024))
        .unwrap();
    b.event("E", r, 1024).unwrap();
    let s = Shared::new(b.build().unwrap(), config).unwrap();
    let mut pair = Pair::symmetric(&s, LinkConfig::latency(0.03), 19);
    assert!(pair.handshake(DT, 60));
    for n in 0..1000 {
        pair.b.send(EventTypeId(0), &payload(n, 1000)).unwrap();
    }
    let mut got = Vec::new();
    let mut max_in_flight = 0;
    for _ in 0..120 {
        let before = pair.b.counters().packets_sent;
        pair.step(DT);
        max_in_flight = max_in_flight.max(pair.b.counters().packets_sent - before);
        got.extend(drain(&mut pair.a_inbox).iter().map(|(_, _, p)| check(p)));
    }
    assert_eq!(got, (0..1000).collect::<Vec<_>>());
    // never more than half of reliable's 256-packet window in one go
    assert!(max_in_flight <= 128, "{max_in_flight}");
    assert_eq!(
        pair.b.counters().events_resent,
        0,
        "a perfect link needs no resends"
    );
    assert_eq!(
        pair.b.queued(ChannelId(0)),
        0,
        "everything was acknowledged"
    );
}

fn budget_config(parked: usize) -> TransportConfig {
    TransportConfig {
        max_pending_events: 8,
        max_parked_bytes: parked,
        ..TransportConfig::default()
    }
}

#[test]
fn a_host_that_stops_polling_cannot_grow_parked_memory_past_the_budget() {
    let budget = 8192;
    let s = shared(budget_config(budget));
    let mut pair = Pair::symmetric(&s, LinkConfig::latency(0.01), 20);
    assert!(pair.handshake(DT, 60));
    let mut next = 0;
    for _ in 0..300 {
        while next < 2000 && pair.b.send(event("Chat"), &payload(next, 200)).is_ok() {
            next += 1;
        }
        pair.step(DT);
        assert!(pair.a.parked_bytes() <= budget, "{}", pair.a.parked_bytes());
        assert!(pair.a_inbox.len() <= 8);
    }
    assert!(
        pair.a.counters().packets_refused > 0,
        "the budget must have pushed back"
    );
    // polling resumes: everything arrives, once, in order
    let mut got = Vec::new();
    for _ in 0..3000 {
        while next < 2000 && pair.b.send(event("Chat"), &payload(next, 200)).is_ok() {
            next += 1;
        }
        pair.step(DT);
        got.extend(drain(&mut pair.a_inbox).iter().map(|(_, _, p)| check(p)));
        assert!(pair.a.parked_bytes() <= budget);
        if got.len() == 2000 {
            break;
        }
    }
    assert_eq!(got, (0..2000).collect::<Vec<_>>());
}

#[test]
fn a_tight_budget_under_heavy_loss_still_delivers_exactly_once_in_order() {
    for seed in 0..4 {
        let config = TransportConfig {
            max_parked_bytes: 8192,
            ..TransportConfig::default()
        };
        let s = shared(config);
        let mut pair = Pair::symmetric(&s, lossy(), 30 + seed);
        assert!(pair.handshake(DT, 600));
        let got = stream(&mut pair, event("Spawn"), 600, 900, 200_000);
        assert_eq!(got, (0..600).collect::<Vec<_>>(), "seed {seed}");
        // nothing is parked any more; what remains charged is reorder capacity kept for reuse,
        // exactly what the buffers hold
        assert_eq!(pair.a.parked_bytes(), pair.a.memory_usage().receive);
        assert!(pair.a.parked_bytes() <= 8192);
    }
}

#[test]
fn a_hostile_peer_cannot_park_past_the_budget() {
    let budget = 8192;
    let (mut conn, mut inbox, mut remote) = lone_connection(budget_config(budget));
    let layout = Layout::new(&test_schema());
    let spawn = event("Spawn");
    // a valid hello, then far-ahead events that can only be parked: never id 0
    let mut n = 0u16;
    for round in 0..200u16 {
        let messages = (0..4).map(|i| (spawn, vec![i as u8; 1024])).collect();
        let packet = encode(
            &layout,
            &PacketSpec {
                hello: Some(layout.hello()),
                sections: vec![common::SectionSpec {
                    channel: ChannelId(0),
                    first_id: 1 + (n % 60),
                    deltas: vec![1, 1, 1],
                    messages,
                }],
            },
        );
        n = n.wrapping_add(round % 7);
        for d in framed(&mut remote, &packet) {
            conn.receive(&d, &mut inbox, |_| {});
        }
        assert!(conn.parked_bytes() <= budget);
        assert_eq!(conn.state(), ConnectionState::Established);
    }
    assert!(inbox.is_empty());
    assert!(conn.counters().packets_refused > 0);
    assert!(conn.memory_usage().receive < budget + 64 * 1024);
}

#[test]
fn the_pool_does_not_keep_a_burst_of_large_buffers() {
    let config = TransportConfig {
        max_pooled_bytes: 16 * 1024,
        ..TransportConfig::default()
    };
    let s = shared(config);
    let mut pair = Pair::symmetric(&s, LinkConfig::PERFECT, 21);
    assert!(pair.handshake(DT, 10));
    let got = stream(&mut pair, event("Blob"), 64, 8000, 10_000);
    assert_eq!(got.len(), 64);
    for _ in 0..10 {
        pair.step(DT);
    }
    for end in [&pair.a, &pair.b] {
        let memory = end.memory_usage();
        assert!(
            memory.send + memory.receive < 3 * 16 * 1024 + 8 * 1024,
            "{memory:?}"
        );
    }
}

#[test]
fn a_late_duplicate_of_a_refused_packet_is_ignored() {
    // reliable never records a refused packet as received, so a delayed network duplicate of
    // it reaches dream-net again, carrying ids far behind the receiver by then
    let (mut conn, mut inbox, mut remote) = lone_connection(TransportConfig {
        max_pending_events: 1,
        ..TransportConfig::default()
    });
    let layout = Layout::new(&test_schema());
    let chat = event("Chat");
    let packet = |first: u16, count: u16, hello: bool| {
        encode(
            &layout,
            &PacketSpec {
                hello: hello.then(|| layout.hello()),
                sections: vec![common::SectionSpec {
                    channel: ChannelId(0),
                    first_id: first,
                    deltas: vec![1; usize::from(count) - 1],
                    messages: (first..first + count)
                        .map(|n| (chat, payload(u32::from(n), 8)))
                        .collect(),
                }],
            },
        )
    };
    // ids 0 and 1: 0 is delivered, 1 finds the inbox full, so the packet is refused
    let refused = framed(&mut remote, &packet(0, 2, true));
    for d in &refused {
        conn.receive(d, &mut inbox, |_| {});
    }
    assert_eq!(conn.counters().packets_refused, 1);
    // the stream moves on, two windows past it
    let mut buffer = [0u8; 64];
    for id in 1..130u16 {
        while inbox.pop_into(&mut buffer).unwrap().is_some() {}
        for d in framed(&mut remote, &packet(id, 1, false)) {
            conn.receive(&d, &mut inbox, |_| {});
        }
    }
    while inbox.pop_into(&mut buffer).unwrap().is_some() {}
    let before = conn.counters().events_received;
    for d in &refused {
        conn.receive(d, &mut inbox, |_| {});
    }
    assert_eq!(
        conn.state(),
        ConnectionState::Established,
        "{:?}",
        conn.last_malformed()
    );
    assert_eq!(conn.counters().events_received, before);
    assert!(inbox.is_empty());
}

#[test]
fn schemas_whose_stale_ids_could_wrap_into_the_window_are_rejected() {
    use dream_net::{ChannelConfig, ConfigError, Schema};
    let mut b = Schema::builder(0).max_messages_per_packet(256);
    let r = b
        .channel(ChannelConfig::reliable_ordered("r").with_capacity(1024))
        .unwrap();
    b.event("E", r, 8).unwrap();
    // 256 packets of 256 events is the whole id space
    assert!(matches!(
        Shared::new(b.build().unwrap(), TransportConfig::default()),
        Err(ConfigError::Transport(_))
    ));
}

/// Many reliable channels, each attacked with a single far-ahead id: the reorder buffers'
/// real storage, summed over every channel, must stay within the one connection budget, and
/// a drained buffer must not stay pinned.
#[test]
fn many_channels_of_far_ahead_ids_share_one_budget() {
    use dream_net::{ChannelConfig, Schema};
    const CHANNELS: u8 = 32;
    let budget = 64 * 1024;
    let mut b = Schema::builder(0).max_messages_per_packet(16);
    for c in 0..CHANNELS {
        let id = b
            .channel(ChannelConfig::reliable_ordered(format!("c{c}")).with_capacity(8192))
            .unwrap();
        b.event(format!("e{c:02}"), id, 16).unwrap();
    }
    let schema = b.build().unwrap();
    let config = TransportConfig {
        max_parked_bytes: budget,
        max_pending_events: 1 << 16,
        ..TransportConfig::default()
    };
    let shared = Shared::new(schema.clone(), config.clone()).unwrap();
    let layout = Layout::new(&schema);
    let peer = Pair::PEER;
    let mut inbox = Inbox::new(1);
    inbox.open_slot(peer);
    let mut conn = Connection::new(shared, peer, 0.0);
    let mut remote = Endpoint::new(config.reliable_config("remote"), 0.0).unwrap();
    let mut send = |conn: &mut Connection, inbox: &mut Inbox<()>, channel: u8, ids: &[u16]| {
        let event = schema.event_id(&format!("e{channel:02}")).unwrap();
        let packet = encode(
            &layout,
            &PacketSpec {
                hello: Some(layout.hello()),
                sections: vec![common::SectionSpec {
                    channel: ChannelId(channel),
                    first_id: ids[0],
                    deltas: ids.windows(2).map(|w| u32::from(w[1] - w[0])).collect(),
                    messages: ids.iter().map(|_| (event, vec![7; 16])).collect(),
                }],
            },
        );
        for d in framed(&mut remote, &packet) {
            conn.receive(&d, inbox, |_| {});
        }
    };
    let check = |conn: &Connection| {
        assert_eq!(conn.state(), ConnectionState::Established);
        assert!(conn.parked_bytes() <= budget, "{}", conn.parked_bytes());
        assert_eq!(conn.memory_usage().receive, conn.parked_bytes());
    };

    // every channel at once: one event 1500 ids ahead needs ~47 KiB of slots
    for c in 0..CHANNELS {
        send(&mut conn, &mut inbox, c, &[1500]);
        check(&conn);
    }
    assert!(conn.counters().packets_refused >= u64::from(CHANNELS) - 1);

    // one channel after another: grow the buffer, then fill the gap so it drains
    let mut buffer = [0u8; 64];
    for c in 0..CHANNELS {
        send(&mut conn, &mut inbox, c, &[1500]);
        check(&conn);
        for start in (0..1500u16).step_by(16) {
            let ids: Vec<u16> = (start..(start + 16).min(1501)).collect();
            send(&mut conn, &mut inbox, c, &ids);
            check(&conn);
            while inbox.pop_into(&mut buffer).unwrap().is_some() {}
        }
    }
    // drained buffers were freed: nothing is left pinned
    assert!(conn.memory_usage().receive <= usize::from(CHANNELS) * 128 * 32);
}

/// `Connection` keeps the auto traits it had over the Rust port (decision 16 of the native
/// transport campaign): the C endpoint inside it must not take any away.
const _: () = {
    const fn traits<T: Send + Sync + Unpin + std::panic::UnwindSafe + std::panic::RefUnwindSafe>() {
    }
    traits::<Connection>();
    traits::<Shared>();
    traits::<dream_net::ConnectionStats>();
    traits::<dream_net::MemoryUsage>();
    traits::<dream_net_native::reliable::Counters>();
    traits::<dream_net_native::reliable::Config>();
};

/// A packet dream-net refuses is left to reliable unacknowledged, and the acks it carries are
/// not applied: reliable only acts on a packet once `process` accepts it.
#[test]
fn a_refused_packet_is_not_acked_and_its_acks_are_not_applied() {
    let (mut conn, mut inbox, mut remote) = lone_connection(TransportConfig {
        max_pending_events: 1,
        ..TransportConfig::default()
    });
    let layout = Layout::new(&test_schema());
    let chat = event("Chat");
    let packet = |id: u16, hello: bool| {
        encode(
            &layout,
            &PacketSpec {
                hello: hello.then(|| layout.hello()),
                sections: vec![common::SectionSpec {
                    channel: ChannelId(0),
                    first_id: id,
                    deltas: vec![],
                    messages: vec![(chat, payload(u32::from(id), 8))],
                }],
            },
        )
    };
    // the remote's hello and event 0 establish the connection and fill its inbox
    for d in framed(&mut remote, &packet(0, true)) {
        conn.receive(&d, &mut inbox, |_| {});
    }
    assert_eq!(conn.state(), ConnectionState::Established);
    // the connection sends its hello, and the remote receives it
    let mut sent = Vec::new();
    conn.write_packets(|d| sent.push(d.to_vec()));
    assert_eq!(sent.len(), 1);
    remote.receive_packet(&sent[0], |_, _| true);
    let _ = remote.drain_acks().count();

    // event 1 rides in a packet whose header acks the connection's hello packet, but the
    // inbox is full, so it is refused
    let refused = remote.next_packet_sequence();
    for d in framed(&mut remote, &packet(1, false)) {
        conn.receive(&d, &mut inbox, |_| {});
    }
    assert_eq!(conn.counters().packets_refused, 1);
    assert_eq!(
        conn.reliable_counters().num_packets_acked,
        0,
        "a refused packet's acks were applied"
    );
    // the hello is still unacked as far as the connection knows: it keeps sending it, and its
    // header does not ack the refused packet
    let mut again = Vec::new();
    conn.write_packets(|d| again.push(d.to_vec()));
    assert_eq!(again.len(), 1);
    assert_eq!(again[0].len(), sent[0].len(), "the hello was dropped");
    remote.receive_packet(&again[0], |_, _| true);
    assert!(
        !remote.drain_acks().any(|s| s == refused),
        "the refused packet was acked"
    );

    // once polled, the resent event is accepted, and its packet's acks apply
    while inbox.pop().is_some() {}
    for d in framed(&mut remote, &packet(1, false)) {
        conn.receive(&d, &mut inbox, |_| {});
    }
    assert_eq!(conn.reliable_counters().num_packets_acked, 2);
    assert_eq!(conn.counters().packets_refused, 1);
    let got = drain(&mut inbox);
    assert_eq!(got.len(), 1);
    assert_eq!(check(&got[0].2), 1);
}

/// Drains `inbox`, checking each reliable stream (indexed by event in `streams`) arrives in
/// order and each unreliable `Move` at most once.
fn absorb(
    inbox: &mut Inbox<()>,
    streams: &[EventTypeId],
    got: &mut [u32],
    moves: &mut std::collections::HashSet<u32>,
) {
    for (e, _, p) in drain(inbox) {
        let n = check(&p);
        if e == event("Move") {
            assert!(moves.insert(n), "unreliable {n} delivered twice");
            continue;
        }
        let i = streams.iter().position(|&s| s == e).unwrap();
        assert_eq!(n, got[i], "stream {i} out of order or duplicated");
        got[i] += 1;
    }
}

/// Both directions at once, every channel kind, fragmented and plain events, over links that
/// lose, duplicate, delay and reorder: each reliable stream arrives exactly once and in order,
/// and unreliable events arrive intact and at most once.
#[test]
fn mixed_channels_both_ways_under_heavy_loss_jitter_and_duplication() {
    for seed in 0..6 {
        let s = shared(TransportConfig::default());
        let link = LinkConfig {
            latency: 0.04,
            jitter: 0.08,
            loss: 0.3,
            duplicate: 0.2,
            corrupt: 0.0,
        };
        let mut pair = Pair::symmetric(&s, link, 900 + seed);
        assert!(pair.handshake(DT, 1200), "seed {seed}");
        let mut rng = dream_net::sim::Rng::new(seed);
        // b -> a: Chat and fragmented Blob; a -> b: Spawn; Move is unreliable, b -> a
        let b_streams = [event("Chat"), event("Blob")];
        let a_streams = [event("Spawn")];
        let (mut b_next, mut b_got) = ([0u32; 2], [0u32; 2]);
        let (mut a_next, mut a_got) = ([0u32; 1], [0u32; 1]);
        let (mut moves_sent, mut moves) = (0u32, std::collections::HashSet::new());
        let mut no_moves = std::collections::HashSet::new();
        for frame in 0..900u32 {
            let len = 4 + rng.below(252) as usize;
            if pair.b.send(b_streams[0], &payload(b_next[0], len)).is_ok() {
                b_next[0] += 1;
            }
            if frame.is_multiple_of(6) {
                let len = 1200 + rng.below(6800) as usize;
                if pair.b.send(b_streams[1], &payload(b_next[1], len)).is_ok() {
                    b_next[1] += 1;
                }
            }
            let len = 4 + rng.below(1020) as usize;
            if pair.a.send(a_streams[0], &payload(a_next[0], len)).is_ok() {
                a_next[0] += 1;
            }
            if pair.b.send(event("Move"), &payload(moves_sent, 16)).is_ok() {
                moves_sent += 1;
            }
            pair.step(DT);
            absorb(&mut pair.a_inbox, &b_streams, &mut b_got, &mut moves);
            absorb(&mut pair.b_inbox, &a_streams, &mut a_got, &mut no_moves);
        }
        pair.set_perfect();
        for _ in 0..3000 {
            pair.step(DT);
            absorb(&mut pair.a_inbox, &b_streams, &mut b_got, &mut moves);
            absorb(&mut pair.b_inbox, &a_streams, &mut a_got, &mut no_moves);
            if b_got == b_next && a_got == a_next {
                break;
            }
        }
        assert_eq!(b_got, b_next, "seed {seed}");
        assert_eq!(a_got, a_next, "seed {seed}");
        assert!(b_next[1] > 20 && a_next[0] > 100, "seed {seed}: barely ran");
        assert!(moves.iter().all(|&n| n < moves_sent));
        assert!(
            moves.len() < moves_sent as usize,
            "seed {seed}: no unreliable loss"
        );
        assert!(pair.b.counters().events_resent > 0);
        assert_eq!(pair.b.counters().events_dropped_on_send, 0);
        assert!(pair.a.reliable_counters().num_fragments_received > 0);
    }
}

/// More than 65536 packets on one connection, one event each, over a lossy reordering link:
/// the u16 packet sequence and the reliable message id both wrap while events are being
/// resent, and every event still arrives once, in order.
#[test]
fn retransmission_across_the_packet_sequence_and_message_id_wraps() {
    let s = shared(TransportConfig {
        // one event per packet: the budget holds the 1-byte header and one 16-byte event, and
        // no second one (a budget below the header would trip a debug assertion in dream-net)
        packet_budget: 24,
        ..TransportConfig::default()
    });
    let link = LinkConfig {
        loss: 0.05,
        jitter: 0.02,
        duplicate: 0.02,
        ..LinkConfig::latency(0.01)
    };
    let mut pair = Pair::symmetric(&s, link, 77);
    assert!(pair.handshake(DT, 600));
    let count = 70_000u32;
    let (mut next, mut got) = (0u32, 0u32);
    let mut resent_at_wrap = None;
    for _ in 0..100_000 {
        while next < count && pair.b.send(event("Chat"), &payload(next, 16)).is_ok() {
            next += 1;
        }
        pair.step(DT);
        for (_, _, p) in drain(&mut pair.a_inbox) {
            assert_eq!(check(&p), got, "out of order or duplicated");
            got += 1;
        }
        if resent_at_wrap.is_none() && pair.b.reliable_counters().num_packets_sent > 65_536 {
            resent_at_wrap = Some(pair.b.counters().events_resent);
        }
        if got == count {
            break;
        }
    }
    assert_eq!(got, count);
    let sent = pair.b.reliable_counters().num_packets_sent;
    assert!(sent > 70_000, "{sent} packets");
    assert!(pair.a.reliable_counters().num_packets_received > 65_536);
    let resent_at_wrap = resent_at_wrap.expect("the packet sequence wrapped");
    assert!(
        pair.b.counters().events_resent > resent_at_wrap,
        "nothing was resent after the wrap"
    );
}

/// A reliable channel under sustained overload and loss refuses `send` with `QueueFull` while
/// its window is full and never drops a queued event: everything it accepted arrives.
#[test]
fn reliable_backpressure_refuses_and_never_drops_under_loss() {
    let s = shared(TransportConfig::default());
    let mut pair = Pair::symmetric(&s, lossy(), 31);
    assert!(pair.handshake(DT, 600));
    let (mut accepted, mut refused, mut got) = (0u32, 0u32, 0u32);
    let take = |inbox: &mut Inbox<()>, got: &mut u32| {
        for (_, _, p) in drain(inbox) {
            assert_eq!(check(&p), *got, "out of order or duplicated");
            *got += 1;
        }
    };
    for _ in 0..1500 {
        for _ in 0..40 {
            match pair.b.send(event("Chat"), &payload(accepted, 32)) {
                Ok(()) => accepted += 1,
                Err(SendError::QueueFull(channel)) => {
                    assert_eq!(channel, ChannelId(0));
                    assert_eq!(pair.b.queued(channel), 64, "refused below the window");
                    refused += 1;
                }
                Err(e) => panic!("{e}"),
            }
        }
        pair.step(DT);
        take(&mut pair.a_inbox, &mut got);
    }
    pair.set_perfect();
    for _ in 0..600 {
        pair.step(DT);
        take(&mut pair.a_inbox, &mut got);
    }
    assert!(refused > 10_000, "{refused}");
    assert_eq!(got, accepted, "an accepted reliable event was lost");
    assert_eq!(pair.b.counters().events_dropped_on_send, 0);
    assert_eq!(pair.b.counters().events_queued, u64::from(accepted));
}
