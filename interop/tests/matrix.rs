//! The supported compatibility matrix, over real loopback sockets: every (client, server)
//! pairing of dream-net 1.1.1 (`netcode-official` 1.0.0 and the `reliable` 1.3.4 Rust port) and
//! this tree (C netcode 1.4.10 and C reliable 1.4.6, both through `dream-net-native`), for every
//! cell of `docs/maintenance/NATIVE_TRANSPORT_COMPATIBILITY.md`'s table:
//!
//! - connect and handshake, with tokens from either version's `generate_connect_token`, on IPv4
//!   and IPv6; events both ways on the reliable and the unreliable channel, an event large
//!   enough to fragment at the reliable layer, and many small events aggregated in one packet;
//! - client-initiated and server-initiated disconnects, and timeouts of either end;
//! - schema mismatches (schema version, event set, channel configuration, payload limit) with
//!   what each side reports;
//! - a wrong protocol id;
//! - the deliberate incompatibilities of campaign decision 12 (token reuse, the start floor,
//!   a restarted server), asserted as the new side's refusals, next to the old side's
//!   acceptance;
//! - peer origin: the server attributes every event to the authenticated netcode slot that
//!   carried it, whatever the payload says.
//!
//! Wire-version mismatches over sockets are in `version_rejection.rs`.

// CI passes -W clippy::pedantic on the command line, overriding the manifest's lint table;
// test code casts freely between widths it controls.
#![allow(clippy::cast_possible_truncation, clippy::too_many_lines)]

mod matrix_common;

use matrix_common::{
    Family, Kind, OTHER_PROTOCOL, PAIRINGS, PROTOCOL, Record, Session, Variant, client, event, new,
    old, server, settled_second, token, unix_time, wait_for_the_next_second,
};

/// Every schema variant builds the same event ids and fingerprint in both versions, and every
/// variant's fingerprint differs from the base schema's.
#[test]
fn both_versions_agree_on_every_variant() {
    for variant in [
        Variant::Base,
        Variant::Version9,
        Variant::ExtraEvent,
        Variant::Capacity,
        Variant::PayloadLimit,
    ] {
        assert_eq!(
            old::fingerprint(variant),
            new::fingerprint(variant),
            "{variant:?}"
        );
        if variant != Variant::Base {
            assert_ne!(new::fingerprint(variant), new::fingerprint(Variant::Base));
        }
        let (o, n) = (old::schema(variant), new::schema(variant));
        assert_eq!(o.events().len(), n.events().len());
        for e in n.events() {
            assert_eq!(
                o.event_id(&e.name).unwrap().0,
                n.event_id(&e.name).unwrap().0
            );
        }
    }
}

/// A connected session's traffic, checked record by record: reliable and unreliable events
/// both ways, a fragmented 8000-byte event both ways, and 32 small reliable events that go out
/// in one packet, delivered in order; then the client disconnects.
fn full_session(client_kind: Kind, server_kind: Kind, minter: Kind, family: Family) {
    let what =
        format!("client {client_kind:?}, server {server_kind:?}, token {minter:?}, {family:?}");
    let key = dream_net::generate_key();
    let mut s = Session::new(server(
        server_kind,
        &key,
        Variant::Base,
        family.loopback(),
        PROTOCOL,
        4,
    ));
    let c = s.add(client(client_kind, Variant::Base, family.loopback()));
    wait_for_the_next_second();
    let address = s.server.address();
    assert_eq!(address.is_ipv6(), family == Family::V6);
    let t = token(minter, &[address], &key, 77, 30, 5, PROTOCOL);
    let peer = s.connect(c, &t, 77);
    assert_eq!(s.server.client_id(peer), Some(77), "{what}");
    // let the hellos' acks settle so the next flush carries nothing else
    s.run_for(0.3);

    // aggregation: 32 small reliable events, one flush, one packet, both ways
    let chat = event(Variant::Base, "Chat");
    let before = s.clients[c].counts().unwrap();
    for n in 0u32..32 {
        s.clients[c].send("Chat", &n.to_le_bytes());
    }
    s.clients[c].flush();
    let after = s.clients[c].counts().unwrap();
    assert_eq!(
        after.packets_sent - before.packets_sent,
        1,
        "{what}: client aggregation"
    );
    assert_eq!(after.events_sent - before.events_sent, 32, "{what}");
    let before = s.server.counts(peer).unwrap();
    for n in 100u32..132 {
        s.server.send(peer, "Chat", &n.to_le_bytes());
    }
    s.server.flush();
    let after = s.server.counts(peer).unwrap();
    assert_eq!(
        after.packets_sent - before.packets_sent,
        1,
        "{what}: server aggregation"
    );
    assert_eq!(after.events_sent - before.events_sent, 32, "{what}");

    // the other channels, and an event that must fragment (reliable fragments anything above
    // 1191 bytes)
    let blob_up: Vec<u8> = (0..8000u32).map(|i| (i * 7 + 1) as u8).collect();
    let blob_down: Vec<u8> = (0..8000u32).map(|i| (i * 13 + 5) as u8).collect();
    assert!(blob_up.len() > dream_net::config::MAX_UNFRAGMENTED_PACKET);
    s.clients[c].send("Move", &[1; 12]);
    s.clients[c].send("Ping", &[]);
    s.clients[c].send("Blob", &blob_up);
    s.server.send(peer, "Move", &[2; 12]);
    s.server.send(peer, "Ping", &[]);
    s.server.send(peer, "Blob", &blob_down);
    assert!(
        s.run_until(|s| Session::messages(&s.server_records).len() == 35
            && Session::messages(&s.client_records[c]).len() == 35),
        "{what}: {:?} {:?}",
        s.server_records,
        s.client_records[c]
    );

    let expect = |records: &[Record], peer: u64, base: u32, mv: u8, blob: &[u8]| {
        let messages = Session::messages(records);
        let chats: Vec<&Record> = messages
            .iter()
            .copied()
            .filter(|r| matches!(r, Record::Message { event, .. } if *event == chat))
            .collect();
        let expected: Vec<Record> = (base..base + 32)
            .map(|n| Record::Message {
                peer,
                event: chat,
                channel: 0,
                payload: n.to_le_bytes().to_vec(),
            })
            .collect();
        assert_eq!(
            chats,
            expected.iter().collect::<Vec<_>>(),
            "{what}: in order"
        );
        for wanted in [
            Record::Message {
                peer,
                event: event(Variant::Base, "Move"),
                channel: 1,
                payload: vec![mv; 12],
            },
            Record::Message {
                peer,
                event: event(Variant::Base, "Ping"),
                channel: 1,
                payload: vec![],
            },
            Record::Message {
                peer,
                event: event(Variant::Base, "Blob"),
                channel: 2,
                payload: blob.to_vec(),
            },
        ] {
            assert_eq!(
                messages.iter().filter(|r| ***r == wanted).count(),
                1,
                "{what}: {wanted:?}"
            );
        }
    };
    expect(&s.server_records, peer, 0, 1, &blob_up);
    expect(&s.client_records[c], 0, 100, 2, &blob_down);

    // the 8000-byte events arrived as several datagrams each: one packet, seven fragments
    let server_counts = s.server.counts(peer).unwrap();
    let client_counts = s.clients[c].counts().unwrap();
    assert!(
        server_counts.datagrams_received >= server_counts.packets_received + 6,
        "{what}: {server_counts:?}"
    );
    assert!(
        client_counts.datagrams_received >= client_counts.packets_received + 6,
        "{what}: {client_counts:?}"
    );

    // client-initiated disconnect
    s.clients[c].disconnect();
    assert!(s.run_until(|s| s.server.num_connected() == 0
        && s.server_records.contains(&Record::Disconnected {
            peer,
            reason: "remote"
        })));
    s.step();
    assert_eq!(
        s.server_records[0],
        Record::Connected {
            peer,
            client_id: 77
        },
        "{what}"
    );
    assert_eq!(
        s.server_records.last().unwrap(),
        &Record::Disconnected {
            peer,
            reason: "remote"
        },
        "{what}"
    );
    assert_eq!(s.client_records[c][0], Record::ClientConnected, "{what}");
    assert_eq!(
        s.client_records[c].last().unwrap(),
        &Record::ClientDisconnected("requested"),
        "{what}"
    );
    assert_eq!(s.clients[c].status(), "Disconnected");
}

#[test]
fn every_pairing_carries_every_kind_of_traffic_over_ipv4() {
    for (client_kind, server_kind) in PAIRINGS {
        for minter in [Kind::Old, Kind::New] {
            full_session(client_kind, server_kind, minter, Family::V4);
        }
    }
}

#[test]
fn every_pairing_carries_every_kind_of_traffic_over_ipv6() {
    for (client_kind, server_kind) in PAIRINGS {
        for minter in [Kind::Old, Kind::New] {
            full_session(client_kind, server_kind, minter, Family::V6);
        }
    }
}

/// A connected session for the lifecycle cells; returns (session, client index, peer).
fn connected(client_kind: Kind, server_kind: Kind, timeout: i32) -> (Session, usize, u64) {
    let key = dream_net::generate_key();
    let mut s = Session::new(server(
        server_kind,
        &key,
        Variant::Base,
        Family::V4.loopback(),
        PROTOCOL,
        4,
    ));
    let c = s.add(client(client_kind, Variant::Base, Family::V4.loopback()));
    wait_for_the_next_second();
    let t = token(
        Kind::New,
        &[s.server.address()],
        &key,
        5,
        30,
        timeout,
        PROTOCOL,
    );
    let peer = s.connect(c, &t, 5);
    (s, c, peer)
}

#[test]
fn every_pairing_reports_a_server_disconnect() {
    for (client_kind, server_kind) in PAIRINGS {
        let what = format!("client {client_kind:?}, server {server_kind:?}");
        let (mut s, c, peer) = connected(client_kind, server_kind, 5);
        s.server.disconnect(peer);
        assert!(s.run_until(|s| s.client_ended(c).is_some()), "{what}");
        s.run_for(0.2);
        assert_eq!(
            s.server_records,
            [
                Record::Connected { peer, client_id: 5 },
                Record::Disconnected {
                    peer,
                    reason: "requested"
                }
            ],
            "{what}"
        );
        assert_eq!(
            s.client_records[c],
            [
                Record::ClientConnected,
                Record::ClientDisconnected("remote")
            ],
            "{what}"
        );
        assert_eq!(s.server.num_connected(), 0, "{what}");
    }
}

/// A client that falls silent times out on the server, after the token's timeout.
#[test]
fn every_pairing_times_out_a_silent_client() {
    for (client_kind, server_kind) in PAIRINGS {
        let what = format!("client {client_kind:?}, server {server_kind:?}");
        let (mut s, c, peer) = connected(client_kind, server_kind, 1);
        s.client_paused[c] = true;
        assert!(
            s.run_until(|s| s.server.num_connected() == 0 && s.server_records.len() == 2),
            "{what}"
        );
        assert_eq!(
            s.server_records[1],
            Record::Disconnected {
                peer,
                reason: "timeout"
            },
            "{what}"
        );
    }
}

/// A server that falls silent times the client out, after the token's timeout.
#[test]
fn every_pairing_times_out_a_silent_server() {
    for (client_kind, server_kind) in PAIRINGS {
        let what = format!("client {client_kind:?}, server {server_kind:?}");
        let (mut s, c, _) = connected(client_kind, server_kind, 1);
        s.server_paused = true;
        assert!(s.run_until(|s| s.client_ended(c).is_some()), "{what}");
        assert_eq!(
            s.client_records[c],
            [
                Record::ClientConnected,
                Record::ClientDisconnected("timeout")
            ],
            "{what}"
        );
        assert_eq!(s.clients[c].status(), "Disconnected", "{what}");
    }
}

/// Every one-way schema difference is reported, by both versions in every pairing, as the
/// same `SchemaMismatch` with both fingerprints: `Rejected` on the server (the peer is never
/// announced) and `ConnectFailed` on the client. Nothing is delivered.
#[test]
fn every_pairing_reports_every_schema_mismatch() {
    for server_kind in [Kind::Old, Kind::New] {
        let key = dream_net::generate_key();
        let mut s = Session::new(server(
            server_kind,
            &key,
            Variant::Base,
            Family::V4.loopback(),
            PROTOCOL,
            16,
        ));
        wait_for_the_next_second();
        let mut client_id = 200;
        for variant in [
            Variant::Version9,
            Variant::ExtraEvent,
            Variant::Capacity,
            Variant::PayloadLimit,
        ] {
            for client_kind in [Kind::Old, Kind::New] {
                let what = format!("client {client_kind:?}, server {server_kind:?}, {variant:?}");
                client_id += 1;
                let c = s.add(client(client_kind, variant, Family::V4.loopback()));
                let t = token(
                    Kind::New,
                    &[s.server.address()],
                    &key,
                    client_id,
                    30,
                    5,
                    PROTOCOL,
                );
                s.clients[c].connect(&t);
                let id = client_id;
                assert!(
                    s.run_until(|s| s.client_ended(c).is_some()
                        && s.server_records.iter().any(
                            |r| matches!(r, Record::Rejected { client_id, .. } if *client_id == id)
                        )),
                    "{what}"
                );
                let (ours, theirs) = (new::fingerprint(Variant::Base), new::fingerprint(variant));
                let failure = |local: u128, remote: u128| {
                    format!(
                        "SchemaMismatch {{ local: Fingerprint({local:032x}), remote: \
                         Fingerprint({remote:032x}) }}"
                    )
                };
                let rejected = s
                    .server_records
                    .iter()
                    .find(|r| matches!(r, Record::Rejected { client_id, .. } if *client_id == id))
                    .unwrap();
                assert!(
                    matches!(rejected, Record::Rejected { failure: f, .. } if *f == failure(ours, theirs)),
                    "{what}: {rejected:?}"
                );
                assert_eq!(
                    s.client_records[c],
                    [Record::ConnectFailed(
                        "schemaMismatch",
                        Some(failure(theirs, ours))
                    )],
                    "{what}"
                );
                assert_eq!(s.clients[c].status(), "Disconnected", "{what}");
            }
        }
        // nothing was ever announced or delivered
        assert!(
            s.server_records
                .iter()
                .all(|r| matches!(r, Record::Rejected { .. })),
            "{:?}",
            s.server_records
        );
    }
}

/// A token for another protocol id is never answered, by either version: the client's attempt
/// times out and the server reports nothing.
#[test]
fn every_pairing_ignores_a_wrong_protocol_id() {
    for (client_kind, server_kind) in PAIRINGS {
        let what = format!("client {client_kind:?}, server {server_kind:?}");
        let key = dream_net::generate_key();
        let mut s = Session::new(server(
            server_kind,
            &key,
            Variant::Base,
            Family::V4.loopback(),
            PROTOCOL,
            4,
        ));
        let c = s.add(client(client_kind, Variant::Base, Family::V4.loopback()));
        wait_for_the_next_second();
        let t = token(
            Kind::New,
            &[s.server.address()],
            &key,
            9,
            30,
            1,
            OTHER_PROTOCOL,
        );
        s.clients[c].connect(&t);
        assert!(s.run_until(|s| s.client_ended(c).is_some()), "{what}");
        assert_eq!(
            s.client_records[c],
            [Record::ConnectFailed("timeout", None)],
            "{what}"
        );
        assert!(s.server_records.is_empty(), "{what}");
        assert_eq!(s.server.num_connected(), 0, "{what}");
    }
}

/// Decision 12, D1/S1: a token admits one session. A new server refuses a second session with
/// a used token from either client (the attempt times out); an old server still admits it.
#[test]
fn every_pairing_answers_a_reused_token_as_its_server_version_decides() {
    for (client_kind, server_kind) in PAIRINGS {
        let what = format!("client {client_kind:?}, server {server_kind:?}");
        let key = dream_net::generate_key();
        let mut s = Session::new(server(
            server_kind,
            &key,
            Variant::Base,
            Family::V4.loopback(),
            PROTOCOL,
            4,
        ));
        let c = s.add(client(client_kind, Variant::Base, Family::V4.loopback()));
        wait_for_the_next_second();
        let t = token(Kind::New, &[s.server.address()], &key, 6, 30, 1, PROTOCOL);
        s.connect(c, &t, 6);
        s.clients[c].disconnect();
        assert!(s.run_until(|s| s.server.num_connected() == 0), "{what}");
        s.client_records[c].clear();
        s.clients[c].connect(&t);
        assert!(s.run_until(|s| !s.client_records[c].is_empty()), "{what}");
        let expected = match server_kind {
            Kind::New => Record::ConnectFailed("timeout", None),
            Kind::Old => Record::ClientConnected,
        };
        assert_eq!(s.client_records[c][0], expected, "{what}");
    }
}

/// Decision 12, D2/S5: a token no longer-lived than the server's maximum (30 seconds) and
/// minted in a new server's start second is refused (the attempt times out); an old server
/// has no start floor.
#[test]
fn every_pairing_answers_a_token_from_the_start_second_as_its_server_version_decides() {
    for (client_kind, server_kind) in PAIRINGS {
        let what = format!("client {client_kind:?}, server {server_kind:?}");
        let mut done = false;
        for _ in 0..5 {
            let key = dream_net::generate_key();
            let start = settled_second();
            let mut s = Session::new(server(
                server_kind,
                &key,
                Variant::Base,
                Family::V4.loopback(),
                PROTOCOL,
                4,
            ));
            let t = token(client_kind, &[s.server.address()], &key, 7, 30, 1, PROTOCOL);
            if unix_time().as_secs() != start {
                continue;
            }
            let c = s.add(client(client_kind, Variant::Base, Family::V4.loopback()));
            s.clients[c].connect(&t);
            assert!(s.run_until(|s| !s.client_records[c].is_empty()), "{what}");
            let expected = match server_kind {
                Kind::New => Record::ConnectFailed("timeout", None),
                Kind::Old => Record::ClientConnected,
            };
            assert_eq!(s.client_records[c][0], expected, "{what}");
            done = true;
            break;
        }
        assert!(done, "{what}: could not mint inside the start second");
    }
}

/// Decision 12, S2: a server restarted on the same key and address. A new server refuses a
/// token that a session already used before the restart (its start floor); an old server
/// admits it again, which reopens the used token's keys.
#[test]
fn every_pairing_answers_a_token_replayed_to_a_restarted_server_as_its_server_version_decides() {
    for (client_kind, server_kind) in PAIRINGS {
        let what = format!("client {client_kind:?}, server {server_kind:?}");
        let key = dream_net::generate_key();
        let first = server(
            server_kind,
            &key,
            Variant::Base,
            Family::V4.loopback(),
            PROTOCOL,
            4,
        );
        let address = first.address();
        let mut s = Session::new(first);
        let c = s.add(client(client_kind, Variant::Base, Family::V4.loopback()));
        wait_for_the_next_second();
        let t = token(Kind::New, &[address], &key, 8, 30, 1, PROTOCOL);
        s.connect(c, &t, 8);
        s.clients[c].disconnect();
        s.run_for(0.1);
        // the restart: the first server stops (and frees its port), then a new one starts on
        // the same key and address
        s.server = Box::new(Stopped(address));
        s.server = server(server_kind, &key, Variant::Base, address, PROTOCOL, 4);
        s.server_records.clear();
        s.client_records[c].clear();
        s.clients[c].connect(&t);
        assert!(s.run_until(|s| !s.client_records[c].is_empty()), "{what}");
        let expected = match server_kind {
            Kind::New => Record::ConnectFailed("timeout", None),
            Kind::Old => Record::ClientConnected,
        };
        assert_eq!(s.client_records[c][0], expected, "{what}");
    }
}

/// A placeholder for a server that has stopped: it answers nothing.
struct Stopped(std::net::SocketAddr);

impl matrix_common::ServerSide for Stopped {
    fn kind(&self) -> Kind {
        Kind::New
    }
    fn address(&self) -> std::net::SocketAddr {
        self.0
    }
    fn update(&mut self, _: f64) {}
    fn poll(&mut self) -> Option<Record> {
        None
    }
    fn send(&mut self, _: u64, _: &str, _: &[u8]) {}
    fn flush(&mut self) {}
    fn disconnect(&mut self, _: u64) {}
    fn num_connected(&self) -> usize {
        0
    }
    fn client_id(&self, _: u64) -> Option<u64> {
        None
    }
    fn counts(&self, _: u64) -> Option<matrix_common::Counts> {
        None
    }
}

/// The wire carries no sender identity: a server attributes every event to the netcode slot
/// that carried it. Two clients (one of each version) send payloads that name the other's
/// handle and client id; every message is attributed to its sender's own handle, on both
/// server versions.
#[test]
fn every_server_attributes_events_to_the_authenticated_slot() {
    for server_kind in [Kind::Old, Kind::New] {
        let key = dream_net::generate_key();
        let mut s = Session::new(server(
            server_kind,
            &key,
            Variant::Base,
            Family::V4.loopback(),
            PROTOCOL,
            4,
        ));
        let a = s.add(client(Kind::Old, Variant::Base, Family::V4.loopback()));
        let b = s.add(client(Kind::New, Variant::Base, Family::V4.loopback()));
        wait_for_the_next_second();
        let ta = token(
            Kind::New,
            &[s.server.address()],
            &key,
            1001,
            30,
            5,
            PROTOCOL,
        );
        let tb = token(
            Kind::Old,
            &[s.server.address()],
            &key,
            1002,
            30,
            5,
            PROTOCOL,
        );
        let peer_a = s.connect(a, &ta, 1001);
        let peer_b = s.connect(b, &tb, 1002);
        assert_ne!(peer_a, peer_b);
        // each claims to be the other, in every way a payload could
        let claim = |me: u8, other_peer: u64, other_id: u64| {
            let mut p = vec![me];
            p.extend_from_slice(&other_peer.to_le_bytes());
            p.extend_from_slice(&other_id.to_le_bytes());
            p.extend_from_slice(&other_peer.to_be_bytes());
            p
        };
        let (pa, pb) = (claim(b'a', peer_b, 1002), claim(b'b', peer_a, 1001));
        for _ in 0..20 {
            s.clients[a].send("Chat", &pa);
            s.clients[a].send("Move", &pa);
            s.clients[b].send("Chat", &pb);
            s.clients[b].send("Move", &pb);
        }
        assert!(s.run_until(|s| Session::messages(&s.server_records).len() >= 80));
        s.run_for(0.2);
        let mut seen = 0;
        for r in &s.server_records {
            if let Record::Message { peer, payload, .. } = r {
                let sender = match payload[0] {
                    b'a' => peer_a,
                    b'b' => peer_b,
                    other => panic!("{other}"),
                };
                assert_eq!(*peer, sender, "server {server_kind:?}");
                seen += 1;
            }
        }
        assert_eq!(seen, 80, "server {server_kind:?}");
        assert_eq!(s.server.client_id(peer_a), Some(1001));
        assert_eq!(s.server.client_id(peer_b), Some(1002));
    }
}
