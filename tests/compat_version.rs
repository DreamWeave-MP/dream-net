//! Protocol version rejection golden tests at `Connection` level: the first datagram a peer of
//! wire version 1 or 3 sends (pinned byte for byte in `tests/compat_vectors`, and proven there
//! to be what dream-net 1.1.1 and the `reliable` 1.3.4 port frame too) fails a connection with
//! `Failure::ProtocolMismatch`, deterministically, and nothing behind the foreign hello is ever
//! decoded or delivered. A wire-version-2 hello with a foreign fingerprint fails it with
//! `Failure::SchemaMismatch`. Either way the failed side answers only with its own hello.
//!
//! The same refusals over real sockets, against dream-net 1.1.1 peers as well, are in
//! `interop/tests/version_rejection.rs`.

// CI passes -W clippy::pedantic on the command line, overriding the manifest's lint table;
// test code casts freely between widths it controls.
#![allow(clippy::cast_possible_truncation)]

mod common;
mod compat_vectors;

use std::sync::Arc;

use common::test_schema;
use dream_net::wire::{Hello, Layout, PacketWriter, WIRE_VERSION};
use dream_net::{
    Connection, ConnectionEvent, ConnectionState, Failure, Fingerprint, Inbox, PeerId, Shared,
    TransportConfig,
};
use dream_net_native::reliable::Endpoint;

fn shared() -> Arc<Shared> {
    Shared::new(test_schema(), TransportConfig::default()).unwrap()
}

/// The first datagram a fresh reliable endpoint with dream-net's configuration sends for
/// `packet`.
fn frame(packet: &[u8]) -> Vec<u8> {
    let config = TransportConfig::default().reliable_config("golden");
    let mut out = Vec::new();
    Endpoint::new(config, 0.0)
        .unwrap()
        .send_packet(packet, |_, d| out.push(d.to_vec()));
    assert_eq!(out.len(), 1);
    out.pop().unwrap()
}

struct Outcome {
    events: Vec<ConnectionEvent>,
    delivered: usize,
    received: u64,
    malformed: u64,
    replies: Vec<Vec<u8>>,
}

/// Feeds `datagrams` to a fresh connection, then lets it write.
fn feed(datagrams: &[Vec<u8>]) -> (Connection, Outcome) {
    let peer = PeerId::new(3, 7);
    let mut conn = Connection::new(shared(), peer, 0.0);
    let mut inbox: Inbox<()> = Inbox::new(4);
    inbox.open_slot(peer);
    conn.update(0.01);
    for d in datagrams {
        conn.receive(d, &mut inbox, |_| {
            panic!("no control packet before a hello")
        });
    }
    let mut events = Vec::new();
    while let Some(e) = conn.take_event() {
        events.push(e);
    }
    let mut replies = Vec::new();
    conn.write_packets(|d| replies.push(d.to_vec()));
    let outcome = Outcome {
        events,
        delivered: inbox.len(),
        received: conn.counters().events_received,
        malformed: conn.counters().malformed_packets,
        replies,
    };
    (conn, outcome)
}

/// Our own hello, as the wire packet a failed connection answers with.
fn own_hello() -> Vec<u8> {
    let schema = test_schema();
    let layout = Layout::new(&schema);
    let mut buffer = vec![0u8; 64];
    let mut w = PacketWriter::new(&mut buffer);
    w.header(&layout, Some(layout.hello()), 0);
    let len = w.finish();
    buffer.truncate(len);
    assert_eq!(
        compat_vectors::hex(&buffer),
        "14009802305e0b20c527d0595fdb37ba9b3403"
    );
    buffer
}

#[test]
fn rejection_datagrams_are_the_vectors_framed_by_reliable() {
    for (name, _, hex) in compat_vectors::REJECTION_DATAGRAMS {
        let packet = compat_vectors::unhex(compat_vectors::vector(name).hex);
        let datagram = compat_vectors::unhex(hex);
        assert_eq!(frame(&packet), datagram, "{name}");
        assert!(datagram.ends_with(&packet));
    }
}

#[test]
fn a_foreign_wire_version_fails_the_connection_and_delivers_nothing() {
    for (name, version, hex) in compat_vectors::REJECTION_DATAGRAMS {
        let datagram = compat_vectors::unhex(hex);
        // the datagram, then the same again and a well-formed version-2 packet: once failed,
        // the connection ignores everything
        let (conn, out) = feed(&[datagram.clone(), datagram, frame(&own_hello())]);
        let failure = Failure::ProtocolMismatch {
            local: WIRE_VERSION,
            remote: version,
        };
        assert_eq!(out.events, [ConnectionEvent::Failed(failure)], "{name}");
        assert_eq!(conn.state(), ConnectionState::Failed(failure));
        assert_eq!(
            (out.delivered, out.received),
            (0, 0),
            "{name}: nothing delivered"
        );
        assert_eq!(out.malformed, 0, "{name}: a mismatch, not garbage");
        assert_eq!(conn.last_malformed(), None);
        assert_eq!(out.replies.len(), 1, "{name}");
        assert!(
            out.replies[0].ends_with(&own_hello()),
            "{name}: answers with its hello"
        );
    }
}

#[test]
fn a_foreign_fingerprint_fails_the_connection_as_a_schema_mismatch() {
    for name in [
        "hello_foreign_fingerprint",
        "hello_foreign_fingerprint_then_a_section",
    ] {
        let packet = compat_vectors::unhex(compat_vectors::vector(name).hex);
        let (_, out) = feed(&[frame(&packet)]);
        assert_eq!(
            out.events,
            [ConnectionEvent::Failed(Failure::SchemaMismatch {
                local: Fingerprint(compat_vectors::TEST_FINGERPRINT),
                remote: Fingerprint(compat_vectors::TEST_V9_FINGERPRINT),
            })],
            "{name}"
        );
        assert_eq!((out.delivered, out.received, out.malformed), (0, 0, 0));
        assert!(out.replies[0].ends_with(&own_hello()));
    }
}

/// The control: the same section behind our own hello is accepted and delivered, so the
/// refusals above are the hello's doing.
#[test]
fn the_same_section_behind_a_matching_hello_is_delivered() {
    let v = compat_vectors::vector("hello_wire_version_3_then_a_section");
    let schema = test_schema();
    let layout = Layout::new(&schema);
    let mut buffer = vec![0u8; 64];
    let mut w = PacketWriter::new(&mut buffer);
    w.header(
        &layout,
        Some(Hello {
            wire_version: WIRE_VERSION,
            fingerprint: schema.fingerprint(),
        }),
        1,
    );
    w.section(&layout, dream_net::ChannelId(0), 1);
    w.first_id(dream_net::Seq16(0));
    let (name, len, byte) = v.sections[0].messages[0];
    w.message(&layout, schema.event_id(name).unwrap(), &vec![byte; len]);
    let n = w.finish();
    buffer.truncate(n);
    // only the version differs from the vector
    let foreign = compat_vectors::unhex(v.hex);
    assert_eq!(buffer.len(), foreign.len());
    assert_eq!(buffer[1..], foreign[1..]);
    let (conn, out) = feed(&[frame(&buffer)]);
    assert_eq!(out.events, [ConnectionEvent::Established]);
    assert_eq!(conn.state(), ConnectionState::Established);
    assert_eq!((out.delivered, out.received), (1, 1));
}
