//! Protocol version rejection, with fixed bytes. dream-net's hello carries `WIRE_VERSION` (2 in
//! 1.1.1 and in this tree) before anything whose width depends on the schema, so a peer of
//! another wire version is refused as `Failure::ProtocolMismatch`, deterministically, before a
//! single schema-dependent field is read: whatever follows the foreign hello is never decoded
//! as events.
//!
//! - At `Connection` level over a simulated link: a hello of wire version 1 or 3 (pinned
//!   byte for byte, as wire packets and as the reliable datagrams that carry them), alone or
//!   followed by a section that a version-2 decoder would read as a `Chat` event, fails both
//!   1.1.1's and this tree's `Connection` with the same failure and delivers nothing.
//! - Over real sockets: a hand-driven netcode client carrying the server's own schema
//!   fingerprint but wire version 1 or 3 is `Rejected` by both server versions, and a
//!   hand-driven netcode server doing the same makes both client versions report
//!   `ConnectFailed { reason: protocolMismatch }`. The same hand-driven peers with wire
//!   version 2 are accepted and their event is delivered, so the refusal is the version's.
//!
//! The same wire bytes are pinned in the main crate's `tests/wire_golden.rs`.

// CI passes -W clippy::pedantic on the command line, overriding the manifest's lint table;
// test code casts freely between widths it controls.
#![allow(clippy::cast_possible_truncation, clippy::too_many_lines)]

mod matrix_common;

use std::time::{Duration, Instant};

use dream_net_native::netcode as nc;
use dream_net_native::reliable as rl;
use matrix_common::{
    Family, Kind, PROTOCOL, Record, Session, Variant, client, event, server, token,
    wait_for_the_next_second,
};

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// The base schema's fingerprint, the same in both versions (`tests/wire_golden.rs` pins it).
const FINGERPRINT: u128 = 0x6693_7746_fb6b_eb3a_04f8_a401_6bc6_0053;

/// Wire packets for the base schema: a hello of wire version `v` and the schema's own
/// fingerprint, then either nothing or one reliable section holding a `Chat` event with id 0
/// and payload "garbage".
const HELLO_V1: &str = "0c009802305e0b20c527d0595fdb37ba9b3403";
const HELLO_V3: &str = "1c009802305e0b20c527d0595fdb37ba9b3403";
const HELLO_V2_CHAT: &str = "14009802305e0b20c527d0595fdb37ba9b340b000090030067617262616765";
const HELLO_V1_CHAT: &str = "0c009802305e0b20c527d0595fdb37ba9b340b000090030067617262616765";
const HELLO_V3_CHAT: &str = "1c009802305e0b20c527d0595fdb37ba9b340b000090030067617262616765";

/// The same packets as the first datagram of a fresh reliable endpoint: reliable's 8-byte
/// header for sequence 0 (prefix byte `3e`, sequence, ack, four ack-bit bytes, all as a fresh
/// endpoint writes them), then the packet unchanged.
const DATAGRAM_V1: &str = "3e000001000000000c009802305e0b20c527d0595fdb37ba9b3403";
const DATAGRAM_V3: &str = "3e000001000000001c009802305e0b20c527d0595fdb37ba9b3403";
const DATAGRAM_V3_CHAT: &str =
    "3e000001000000001c009802305e0b20c527d0595fdb37ba9b340b000090030067617262616765";

/// Writes a hello of wire version `version` (and optionally the Chat section) with either
/// version's own `PacketWriter`, so the bytes above are pinned against both.
macro_rules! write_packet {
    ($dn:ident, $side:ident, $version:expr, $chat:expr) => {{
        let schema = matrix_common::$side::schema(Variant::Base);
        let layout = $dn::wire::Layout::new(&schema);
        let hello = $dn::wire::Hello {
            wire_version: $version,
            fingerprint: schema.fingerprint(),
        };
        let mut buffer = vec![0u8; 256];
        let mut w = $dn::wire::PacketWriter::new(&mut buffer);
        if $chat {
            w.header(&layout, Some(hello), 1);
            w.section(&layout, $dn::ChannelId(0), 1);
            w.first_id($dn::Seq16(0));
            w.message(&layout, schema.event_id("Chat").unwrap(), b"garbage");
        } else {
            w.header(&layout, Some(hello), 0);
        }
        let len = w.finish();
        buffer.truncate(len);
        buffer
    }};
}

fn packet(version: u16, chat: bool) -> Vec<u8> {
    let new = write_packet!(dream_net, new, version, chat);
    let old = write_packet!(dream_net_old, old, version, chat);
    assert_eq!(new, old, "both writers, wire version {version}");
    new
}

fn endpoint(time: f64) -> rl::Endpoint {
    rl::Endpoint::new(
        dream_net::TransportConfig::default().reliable_config("fake"),
        time,
    )
    .unwrap()
}

/// Wraps `packet` as the first datagram of a fresh endpoint, with the C reliable and the Rust
/// port, and checks they agree.
fn datagram(packet: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    endpoint(0.0).send_packet(packet, |_, d| out.push(d.to_vec()));
    let config = dream_net::TransportConfig::default().reliable_config("fake");
    let mut port = reliable_old::Endpoint::new(
        reliable_old::Config {
            name: "fake".into(),
            max_packet_size: config.max_packet_size,
            fragment_above: config.fragment_above,
            max_fragments: config.max_fragments,
            fragment_size: config.fragment_size,
            ack_buffer_size: config.ack_buffer_size,
            sent_packets_buffer_size: config.sent_packets_buffer_size,
            received_packets_buffer_size: config.received_packets_buffer_size,
            fragment_reassembly_buffer_size: config.fragment_reassembly_buffer_size,
            rtt_smoothing_factor: config.rtt_smoothing_factor,
            rtt_history_size: config.rtt_history_size,
            packet_loss_smoothing_factor: config.packet_loss_smoothing_factor,
            bandwidth_smoothing_factor: config.bandwidth_smoothing_factor,
            packet_header_size: config.packet_header_size,
        },
        0.0,
    );
    let mut ported = Vec::new();
    port.send_packet(packet, |_, d| ported.push(d.to_vec()));
    assert_eq!(
        out, ported,
        "C reliable and the 1.3.4 port frame the packet the same"
    );
    assert_eq!(out.len(), 1);
    out.pop().unwrap()
}

#[test]
fn version_rejection_packets_are_pinned_for_both_versions() {
    assert_eq!(dream_net::wire::WIRE_VERSION, 2);
    assert_eq!(dream_net_old::wire::WIRE_VERSION, 2);
    assert_eq!(matrix_common::new::fingerprint(Variant::Base), FINGERPRINT);
    assert_eq!(hex(&packet(1, false)), HELLO_V1);
    assert_eq!(hex(&packet(3, false)), HELLO_V3);
    assert_eq!(hex(&packet(2, true)), HELLO_V2_CHAT);
    assert_eq!(hex(&packet(1, true)), HELLO_V1_CHAT);
    assert_eq!(hex(&packet(3, true)), HELLO_V3_CHAT);
    assert_eq!(hex(&datagram(&packet(1, false))), DATAGRAM_V1);
    assert_eq!(hex(&datagram(&packet(3, false))), DATAGRAM_V3);
    assert_eq!(hex(&datagram(&packet(3, true))), DATAGRAM_V3_CHAT);
}

/// Both versions' decoders stop at a foreign hello with `Mismatch`, before reading the
/// section behind it.
#[test]
fn both_decoders_stop_at_a_foreign_hello() {
    for (bytes, version) in [
        (HELLO_V1, 1),
        (HELLO_V3, 3),
        (HELLO_V1_CHAT, 1),
        (HELLO_V3_CHAT, 3),
    ] {
        let bytes = unhex(bytes);
        let schema = matrix_common::new::schema(Variant::Base);
        let mut decoded = dream_net::wire::Decoded::default();
        let verdict =
            dream_net::wire::decode(&dream_net::wire::Layout::new(&schema), &bytes, &mut decoded);
        assert_eq!(
            verdict,
            Err(dream_net::wire::DecodeError::Mismatch(
                dream_net::wire::Hello {
                    wire_version: version,
                    fingerprint: dream_net::Fingerprint(FINGERPRINT),
                }
            ))
        );
        assert!(decoded.messages.is_empty() && decoded.sections.is_empty());
        let schema = matrix_common::old::schema(Variant::Base);
        let mut decoded = dream_net_old::wire::Decoded::default();
        let verdict = dream_net_old::wire::decode(
            &dream_net_old::wire::Layout::new(&schema),
            &bytes,
            &mut decoded,
        );
        assert_eq!(
            verdict,
            Err(dream_net_old::wire::DecodeError::Mismatch(
                dream_net_old::wire::Hello {
                    wire_version: version,
                    fingerprint: dream_net_old::Fingerprint(FINGERPRINT),
                }
            ))
        );
        assert!(decoded.messages.is_empty() && decoded.sections.is_empty());
    }
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Feeds `datagram` to a fresh `Connection` of either version; returns the failure it reports
/// (by `Debug` text), whether it delivered anything, and its state.
macro_rules! feed {
    ($dn:ident, $side:ident, $datagram:expr) => {{
        let schema = matrix_common::$side::schema(Variant::Base);
        let shared = $dn::Shared::new(schema, $dn::TransportConfig::default()).unwrap();
        let peer = $dn::PeerId::new(0, 1);
        let mut conn = $dn::Connection::new(shared, peer, 0.0);
        let mut inbox: $dn::Inbox<()> = $dn::Inbox::new(1);
        inbox.open_slot(peer);
        conn.update(0.01);
        conn.receive($datagram, &mut inbox, |_| {});
        let event = conn.take_event().map(|e| format!("{e:?}"));
        let state = format!("{:?}", conn.state());
        let mut replies = Vec::new();
        conn.write_packets(|d| replies.push(d.to_vec()));
        (
            event,
            inbox.len(),
            state,
            conn.counters().events_received,
            replies,
        )
    }};
}

#[test]
fn both_connections_refuse_a_foreign_wire_version_and_deliver_nothing() {
    for (version, chat) in [(1u16, false), (3, false), (1, true), (3, true)] {
        let datagram = datagram(&packet(version, chat));
        let expected = format!("Failed(ProtocolMismatch {{ local: 2, remote: {version} }})");
        let old = feed!(dream_net_old, old, &datagram);
        let new = feed!(dream_net, new, &datagram);
        assert_eq!(old.0.as_deref(), Some(expected.as_str()), "old, v{version}");
        assert_eq!(new.0.as_deref(), Some(expected.as_str()), "new, v{version}");
        assert_eq!((old.1, new.1), (0, 0), "nothing delivered");
        assert_eq!((old.3, new.3), (0, 0), "nothing received");
        assert_eq!(old.2, new.2);
        // a failed side answers only with its own hello (wire version 2), so the peer can
        // diagnose the mismatch too; both versions send the same bytes
        assert_eq!(old.4, new.4, "v{version}");
        assert_eq!(new.4.len(), 1);
        assert!(hex(&new.4[0]).ends_with("14009802305e0b20c527d0595fdb37ba9b3403"));
    }
    // the control: the same packet with wire version 2 is accepted and its event delivered
    let datagram = datagram(&packet(2, true));
    let old = feed!(dream_net_old, old, &datagram);
    let new = feed!(dream_net, new, &datagram);
    assert_eq!(old.0.as_deref(), Some("Established"));
    assert_eq!(new.0.as_deref(), Some("Established"));
    assert_eq!((old.3, new.3), (1, 1));
}

/// A netcode client driven by hand, carrying dream-net packets it writes itself through a C
/// reliable endpoint.
struct FakeClient {
    netcode: nc::Client,
    endpoint: rl::Endpoint,
    packet: Vec<u8>,
    received: Vec<Vec<u8>>,
}

impl FakeClient {
    fn new(packet: Vec<u8>) -> Self {
        Self {
            netcode: nc::Client::new(Family::V4.loopback(), 0.0).unwrap(),
            endpoint: endpoint(0.0),
            packet,
            received: Vec::new(),
        }
    }

    fn step(&mut self, time: f64) {
        self.netcode.update(time);
        self.endpoint.update(time);
        while let Some((datagram, _)) = self.netcode.receive_packet() {
            let received = &mut self.received;
            self.endpoint.receive_packet(&datagram, |_, p| {
                received.push(p.to_vec());
                true
            });
        }
        if self.netcode.state() == nc::ClientState::Connected {
            let netcode = &mut self.netcode;
            self.endpoint
                .send_packet(&self.packet, |_, d| netcode.send_packet(d).unwrap());
        }
    }
}

/// Runs a hand-driven client sending `packet` against a server of `server_kind`; returns the
/// server's records and the packets the fake received.
fn against_server(
    server_kind: Kind,
    packet: Vec<u8>,
    until_message: bool,
) -> (Vec<Record>, Vec<Vec<u8>>) {
    let key = dream_net::generate_key();
    let mut s = Session::new(server(
        server_kind,
        &key,
        Variant::Base,
        Family::V4.loopback(),
        PROTOCOL,
        4,
    ));
    wait_for_the_next_second();
    let t = token(Kind::New, &[s.server.address()], &key, 33, 30, 5, PROTOCOL);
    let mut fake = FakeClient::new(packet);
    fake.netcode.connect(&t).unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        let time = s.time();
        s.server.update(time);
        fake.step(time);
        s.poll();
        s.server.flush();
        let done = if until_message {
            !Session::messages(&s.server_records).is_empty()
        } else {
            !s.server_records.is_empty() && !fake.received.is_empty()
        };
        if done {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    // a little longer, so anything decoded late would show
    s.run_for(0.3);
    (s.server_records, fake.received)
}

#[test]
fn both_servers_reject_a_client_of_another_wire_version() {
    for server_kind in [Kind::Old, Kind::New] {
        for version in [1u16, 3] {
            let what = format!("server {server_kind:?}, client wire version {version}");
            let (records, received) = against_server(server_kind, packet(version, true), false);
            assert_eq!(records.len(), 1, "{what}: {records:?}");
            match &records[0] {
                Record::Rejected {
                    client_id, failure, ..
                } => {
                    assert_eq!(*client_id, 33, "{what}");
                    assert_eq!(
                        failure,
                        &format!("ProtocolMismatch {{ local: 2, remote: {version} }}"),
                        "{what}"
                    );
                }
                other => panic!("{what}: {other:?}"),
            }
            // the server told the fake its own wire version and schema, and nothing else
            assert!(!received.is_empty(), "{what}");
            for p in &received {
                assert_eq!(hex(p), "14009802305e0b20c527d0595fdb37ba9b3403", "{what}");
            }
        }
        // the control: wire version 2 is admitted and the Chat behind the hello delivered
        let (records, _) = against_server(server_kind, packet(2, true), true);
        let Record::Connected { peer, client_id } = records[0] else {
            panic!("{records:?}")
        };
        assert_eq!(client_id, 33);
        assert_eq!(
            records[1],
            Record::Message {
                peer,
                event: event(Variant::Base, "Chat"),
                channel: 0,
                payload: b"garbage".to_vec(),
            }
        );
    }
}

/// A hand-driven netcode server that answers every client with `packet`.
fn against_client(client_kind: Kind, packet: &[u8]) -> Vec<Record> {
    let key = dream_net::generate_key();
    let mut netcode = nc::Server::new(Family::V4.loopback(), PROTOCOL, &key, 0.0).unwrap();
    netcode.start(4).unwrap();
    let mut endpoint = endpoint(0.0);
    let mut c = client(client_kind, Variant::Base, Family::V4.loopback());
    wait_for_the_next_second();
    let t = token(Kind::New, &[netcode.address()], &key, 44, 30, 5, PROTOCOL);
    c.connect(&t);
    let started = Instant::now();
    let mut slot = None;
    let mut records = Vec::new();
    let deadline = started + Duration::from_secs(20);
    let mut ended_at = None;
    while Instant::now() < deadline {
        let time = started.elapsed().as_secs_f64();
        netcode.update(time);
        endpoint.update(time);
        while let Some(event) = netcode.next_event() {
            if let nc::ServerEvent::ClientConnected { client_index } = event {
                slot = Some(client_index);
            }
        }
        c.update(time);
        while let Some(r) = c.poll() {
            records.push(r);
        }
        if let Some(index) = slot {
            while netcode.receive_packet(index).is_some() {}
            endpoint.send_packet(packet, |_, d| netcode.send_packet(index, d).unwrap());
        }
        c.flush();
        if records
            .iter()
            .any(|r| matches!(r, Record::ConnectFailed(..) | Record::ClientDisconnected(_)))
        {
            ended_at.get_or_insert(Instant::now());
        }
        if ended_at.is_some_and(|t| t.elapsed() > Duration::from_millis(300)) {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    records
}

#[test]
fn both_clients_reject_a_server_of_another_wire_version() {
    for client_kind in [Kind::Old, Kind::New] {
        for version in [1u16, 3] {
            let what = format!("client {client_kind:?}, server wire version {version}");
            let records = against_client(client_kind, &packet(version, true));
            assert_eq!(
                records,
                [Record::ConnectFailed(
                    "protocolMismatch",
                    Some(format!(
                        "ProtocolMismatch {{ local: 2, remote: {version} }}"
                    ))
                )],
                "{what}"
            );
        }
    }
}
