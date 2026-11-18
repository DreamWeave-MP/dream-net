//! dream-net 1.1.1 (`netcode-official` 1.0.0 underneath) against the current dream-net (C
//! netcode 1.4.10 underneath) over loopback, at dream-net's level: an old client with a new
//! server and a new client with an old server complete the schema handshake and carry events
//! both ways on a reliable and an unreliable channel, a schema mismatch is reported with the
//! same `Failure` on each side as between two peers of the same version, and the deliberate
//! differences (campaign decision 12) show up as the new side's refusals.
//!
//! These were written while both sides still ran the same Rust `reliable` above netcode. Since
//! #10 the new side runs C reliable 1.4.6 too, so they now exercise the whole old stack
//! (`netcode-official` 1.0.0, `reliable` 1.3.4) against the whole new one (C netcode, C
//! reliable). `matrix.rs` extends them to every pairing and cell.

// CI passes -W clippy::pedantic on the command line, overriding the manifest's lint table;
// test code casts freely between widths it controls.
#![allow(clippy::cast_possible_truncation, clippy::too_many_lines)]

use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const PROTOCOL: u64 = 0x0DDB_A11C_AFE0_0009;
const DEADLINE: Duration = Duration::from_secs(20);

fn localhost() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

/// A record either version produced, with nothing version-specific left in it: handles as their
/// raw `u64`, reasons by their stable names, failures by their `Debug` text (the same shape in
/// both versions).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Record {
    Connected {
        peer: u64,
        client_id: u64,
    },
    Disconnected {
        peer: u64,
        reason: &'static str,
    },
    Rejected {
        peer: u64,
        client_id: u64,
        failure: String,
    },
    Message {
        peer: u64,
        event: u32,
        channel: u8,
        payload: Vec<u8>,
    },
    ClientConnected,
    ClientDisconnected(&'static str),
    ConnectFailed(&'static str, Option<String>),
}

trait ServerSide {
    fn address(&self) -> SocketAddr;
    fn update(&mut self, time: f64);
    fn poll(&mut self) -> Option<Record>;
    fn send(&mut self, peer: u64, event: &str, payload: &[u8]);
    fn flush(&mut self);
    fn disconnect(&mut self, peer: u64);
    fn num_connected(&self) -> usize;
}

trait ClientSide {
    fn connect(&mut self, token: &[u8; 2048]);
    fn update(&mut self, time: f64);
    fn poll(&mut self) -> Option<Record>;
    fn send(&mut self, event: &str, payload: &[u8]);
    fn flush(&mut self);
    fn disconnect(&mut self);
    fn status(&self) -> String;
}

/// Everything a test needs from one version of dream-net, written once for both.
macro_rules! side {
    ($side:ident, $dn:ident) => {
        mod $side {
            use super::{ClientSide, PROTOCOL, Record, ServerSide, localhost};
            use std::net::SocketAddr;

            /// tests/common's schema: three channels (reliable, unreliable, reliable bulk) and
            /// five events, `version` as given.
            pub fn schema(version: u32) -> $dn::Schema {
                let mut b = $dn::Schema::builder(version).max_messages_per_packet(32);
                let reliable = b
                    .channel($dn::ChannelConfig::reliable_ordered("reliable").with_capacity(64))
                    .unwrap();
                let state = b
                    .channel($dn::ChannelConfig::unreliable_unordered("state").with_capacity(64))
                    .unwrap();
                let bulk = b
                    .channel($dn::ChannelConfig::reliable_ordered("bulk").with_capacity(16))
                    .unwrap();
                b.event("Chat", reliable, 256).unwrap();
                b.event("Spawn", reliable, 1024).unwrap();
                b.event("Move", state, 64).unwrap();
                b.event("Ping", state, 0).unwrap();
                b.event("Blob", bulk, 8000).unwrap();
                b.build().unwrap()
            }

            pub fn fingerprint(version: u32) -> u128 {
                schema(version).fingerprint().0
            }

            pub fn token(
                addresses: &[SocketAddr],
                key: &[u8; 32],
                client_id: u64,
                lifetime: i32,
                timeout: i32,
            ) -> [u8; 2048] {
                let mut user_data = [0u8; 256];
                user_data[..8].copy_from_slice(&client_id.to_le_bytes());
                $dn::generate_connect_token(
                    addresses, addresses, lifetime, timeout, client_id, PROTOCOL, key, &user_data,
                )
                .unwrap()
            }

            pub struct Server(pub $dn::Server, u32);

            pub fn server(key: &[u8; 32], version: u32) -> Server {
                let server = $dn::Server::new(
                    $dn::ServerConfig {
                        public_address: localhost(),
                        protocol_id: PROTOCOL,
                        max_clients: 4,
                        transport: $dn::TransportConfig::default(),
                    },
                    key,
                    schema(version),
                    0.0,
                )
                .unwrap();
                Server(server, version)
            }

            fn reason(reason: $dn::DisconnectReason) -> &'static str {
                reason.name()
            }

            impl ServerSide for Server {
                fn address(&self) -> SocketAddr {
                    self.0.address()
                }
                fn update(&mut self, time: f64) {
                    self.0.update(time);
                }
                fn poll(&mut self) -> Option<Record> {
                    Some(match self.0.poll()? {
                        $dn::ServerEvent::Connected { peer, client_id } => Record::Connected {
                            peer: peer.0,
                            client_id,
                        },
                        $dn::ServerEvent::Disconnected { peer, reason: r } => {
                            Record::Disconnected {
                                peer: peer.0,
                                reason: reason(r),
                            }
                        }
                        $dn::ServerEvent::Rejected {
                            peer,
                            client_id,
                            failure,
                        } => Record::Rejected {
                            peer: peer.0,
                            client_id,
                            failure: format!("{failure:?}"),
                        },
                        $dn::ServerEvent::Message {
                            peer,
                            event,
                            channel,
                            payload,
                        } => Record::Message {
                            peer: peer.0,
                            event: event.0,
                            channel: channel.0,
                            payload: payload.to_vec(),
                        },
                    })
                }
                fn send(&mut self, peer: u64, event: &str, payload: &[u8]) {
                    let id = schema(self.1).event_id(event).unwrap();
                    self.0.send($dn::PeerId(peer), id, payload).unwrap();
                }
                fn flush(&mut self) {
                    self.0.flush();
                }
                fn disconnect(&mut self, peer: u64) {
                    self.0.disconnect($dn::PeerId(peer));
                }
                fn num_connected(&self) -> usize {
                    self.0.num_connected()
                }
            }

            pub struct Client(pub $dn::Client, u32);

            pub fn client(version: u32) -> Client {
                let client = $dn::Client::new(
                    $dn::ClientConfig {
                        bind_address: localhost(),
                        transport: $dn::TransportConfig::default(),
                    },
                    schema(version),
                    0.0,
                )
                .unwrap();
                Client(client, version)
            }

            impl ClientSide for Client {
                fn connect(&mut self, token: &[u8; 2048]) {
                    self.0.connect(token).unwrap();
                }
                fn update(&mut self, time: f64) {
                    self.0.update(time);
                }
                fn poll(&mut self) -> Option<Record> {
                    Some(match self.0.poll()? {
                        $dn::ClientEvent::Connected => Record::ClientConnected,
                        $dn::ClientEvent::Disconnected { reason: r } => {
                            Record::ClientDisconnected(reason(r))
                        }
                        $dn::ClientEvent::ConnectFailed { reason: r, failure } => {
                            Record::ConnectFailed(reason(r), failure.map(|f| format!("{f:?}")))
                        }
                        $dn::ClientEvent::Message {
                            event,
                            channel,
                            payload,
                        } => Record::Message {
                            peer: 0,
                            event: event.0,
                            channel: channel.0,
                            payload: payload.to_vec(),
                        },
                    })
                }
                fn send(&mut self, event: &str, payload: &[u8]) {
                    let id = schema(self.1).event_id(event).unwrap();
                    self.0.send(id, payload).unwrap();
                }
                fn flush(&mut self) {
                    self.0.flush();
                }
                fn disconnect(&mut self) {
                    self.0.disconnect();
                }
                fn status(&self) -> String {
                    format!("{:?}", self.0.status())
                }
            }
        }
    };
}

side!(old, dream_net_old);
side!(new, dream_net);

/// A server, one client, and every record each produced, on the wall clock.
struct Pair<S, C> {
    server: S,
    client: C,
    started: Instant,
    server_records: Vec<Record>,
    client_records: Vec<Record>,
}

impl<S: ServerSide, C: ClientSide> Pair<S, C> {
    fn new(server: S, client: C) -> Self {
        Self {
            server,
            client,
            started: Instant::now(),
            server_records: Vec::new(),
            client_records: Vec::new(),
        }
    }

    fn step(&mut self) {
        let time = self.started.elapsed().as_secs_f64();
        self.server.update(time);
        self.client.update(time);
        while let Some(record) = self.server.poll() {
            self.server_records.push(record);
        }
        while let Some(record) = self.client.poll() {
            self.client_records.push(record);
        }
        self.server.flush();
        self.client.flush();
        std::thread::sleep(Duration::from_millis(1));
    }

    fn run_until(&mut self, mut done: impl FnMut(&Self) -> bool) -> bool {
        let deadline = Instant::now() + DEADLINE;
        while Instant::now() < deadline {
            if done(self) {
                return true;
            }
            self.step();
        }
        done(self)
    }

    fn run_for(&mut self, seconds: f64) {
        let until = Instant::now() + Duration::from_secs_f64(seconds);
        while Instant::now() < until {
            self.step();
        }
    }

    fn peer(&self) -> Option<u64> {
        self.server_records.iter().find_map(|r| match r {
            Record::Connected { peer, .. } => Some(*peer),
            _ => None,
        })
    }

    fn client_ended(&self) -> Option<&Record> {
        self.client_records
            .iter()
            .find(|r| matches!(r, Record::ClientDisconnected(_) | Record::ConnectFailed(..)))
    }
}

fn unix_time() -> Duration {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
}

/// Waits until the wall clock has left the current second by 60 ms (netcode's `time(NULL)` is a
/// coarse clock): a token minted after this clears a new server's start floor.
fn wait_for_the_next_second() {
    let second = unix_time().as_secs();
    while unix_time() < Duration::from_secs(second + 1) + Duration::from_millis(60) {
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Waits until the current second is at least 60 ms old with half a second left, and returns it.
fn settled_second() -> u64 {
    loop {
        let now = unix_time();
        if (60..=500).contains(&now.subsec_millis()) {
            return now.as_secs();
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[derive(Clone, Copy, Debug)]
enum Minter {
    Old,
    New,
}

fn mint(minter: Minter, addresses: &[SocketAddr], key: &[u8; 32], id: u64) -> [u8; 2048] {
    match minter {
        Minter::Old => old::token(addresses, key, id, 30, 5),
        Minter::New => new::token(addresses, key, id, 30, 5),
    }
}

/// Connects, carries events both ways on the reliable and the unreliable channel, and
/// disconnects from the client: every record on both sides, in a version-neutral form.
fn exchange<S: ServerSide, C: ClientSide>(
    server: S,
    client: C,
    minter: Minter,
    key: &[u8; 32],
) -> (Vec<Record>, Vec<Record>) {
    let mut pair = Pair::new(server, client);
    wait_for_the_next_second();
    let token = mint(minter, &[pair.server.address()], key, 77);
    pair.client.connect(&token);
    assert!(
        pair.run_until(
            |p| p.peer().is_some() && p.client_records.contains(&Record::ClientConnected)
        ),
        "{:?} {:?}",
        pair.server_records,
        pair.client_records
    );
    let peer = pair.peer().unwrap();
    pair.client.send("Chat", b"up, reliably");
    pair.client.send("Move", &[1; 12]);
    pair.server.send(peer, "Chat", b"down, reliably");
    pair.server.send(peer, "Move", &[2; 12]);
    let messages = |records: &[Record]| {
        records
            .iter()
            .filter(|r| matches!(r, Record::Message { .. }))
            .count()
    };
    assert!(
        pair.run_until(|p| messages(&p.server_records) == 2 && messages(&p.client_records) == 2),
        "{:?} {:?}",
        pair.server_records,
        pair.client_records
    );
    pair.client.disconnect();
    assert!(pair.run_until(|p| {
        p.server.num_connected() == 0
            && p.server_records
                .iter()
                .any(|r| matches!(r, Record::Disconnected { .. }))
    }));
    pair.step();
    (pair.server_records, pair.client_records)
}

/// The records `exchange` must produce, whichever versions are on either side.
fn expected_exchange(peer: u64) -> (Vec<Record>, Vec<Record>) {
    let chat = new::schema(1).event_id("Chat").unwrap().0;
    let moved = new::schema(1).event_id("Move").unwrap().0;
    (
        vec![
            Record::Connected {
                peer,
                client_id: 77,
            },
            Record::Message {
                peer,
                event: chat,
                channel: 0,
                payload: b"up, reliably".to_vec(),
            },
            Record::Message {
                peer,
                event: moved,
                channel: 1,
                payload: vec![1; 12],
            },
            Record::Disconnected {
                peer,
                reason: "remote",
            },
        ],
        vec![
            Record::ClientConnected,
            Record::Message {
                peer: 0,
                event: chat,
                channel: 0,
                payload: b"down, reliably".to_vec(),
            },
            Record::Message {
                peer: 0,
                event: moved,
                channel: 1,
                payload: vec![2; 12],
            },
            Record::ClientDisconnected("requested"),
        ],
    )
}

/// Messages may arrive in either order across channels; everything else is in order.
fn sorted(mut records: Vec<Record>) -> Vec<Record> {
    let first_message = records
        .iter()
        .position(|r| matches!(r, Record::Message { .. }))
        .unwrap();
    records[first_message..first_message + 2].sort_by_key(|r| format!("{r:?}"));
    records
}

#[test]
fn both_versions_build_the_same_schema() {
    assert_eq!(old::fingerprint(1), new::fingerprint(1));
    assert_eq!(old::fingerprint(9), new::fingerprint(9));
    assert_ne!(new::fingerprint(1), new::fingerprint(9));
    for name in ["Chat", "Spawn", "Move", "Ping", "Blob"] {
        assert_eq!(
            old::schema(1).event_id(name).unwrap().0,
            new::schema(1).event_id(name).unwrap().0
        );
    }
}

#[test]
fn an_old_client_and_a_new_server_exchange_events_both_ways() {
    for minter in [Minter::New, Minter::Old] {
        let key = dream_net::generate_key();
        let (server, client) = exchange(new::server(&key, 1), old::client(1), minter, &key);
        let peer = match server[0] {
            Record::Connected { peer, .. } => peer,
            ref other => panic!("{other:?}"),
        };
        assert_eq!(dream_net::PeerId(peer).generation(), 1);
        let (expected_server, expected_client) = expected_exchange(peer);
        assert_eq!(sorted(server), expected_server, "token from {minter:?}");
        assert_eq!(sorted(client), expected_client, "token from {minter:?}");
    }
}

#[test]
fn a_new_client_and_an_old_server_exchange_events_both_ways() {
    for minter in [Minter::Old, Minter::New] {
        let key = dream_net::generate_key();
        let (server, client) = exchange(old::server(&key, 1), new::client(1), minter, &key);
        let peer = match server[0] {
            Record::Connected { peer, .. } => peer,
            ref other => panic!("{other:?}"),
        };
        let (expected_server, expected_client) = expected_exchange(peer);
        assert_eq!(sorted(server), expected_server, "token from {minter:?}");
        assert_eq!(sorted(client), expected_client, "token from {minter:?}");
    }
}

/// The first records of a schema-mismatched connection, on each side.
fn mismatch<S: ServerSide, C: ClientSide>(
    server: S,
    client: C,
    key: &[u8; 32],
) -> (Record, Record) {
    let mut pair = Pair::new(server, client);
    wait_for_the_next_second();
    let token = mint(Minter::New, &[pair.server.address()], key, 9);
    pair.client.connect(&token);
    assert!(pair.run_until(|p| !p.server_records.is_empty() && p.client_ended().is_some()));
    assert_eq!(pair.server.num_connected(), 0);
    assert_eq!(pair.client.status(), "Disconnected");
    let server = match &pair.server_records[0] {
        Record::Rejected {
            client_id, failure, ..
        } => Record::Rejected {
            peer: 0,
            client_id: *client_id,
            failure: failure.clone(),
        },
        other => panic!("{other:?}"),
    };
    (server, pair.client_ended().unwrap().clone())
}

#[test]
fn a_schema_mismatch_fails_the_same_way_across_versions() {
    // fingerprints print as 32 hex digits in both versions
    let ours = new::fingerprint(1);
    let theirs = new::fingerprint(9);
    let expected = (
        Record::Rejected {
            peer: 0,
            client_id: 9,
            failure: format!(
                "SchemaMismatch {{ local: Fingerprint({ours:032x}), remote: \
                 Fingerprint({theirs:032x}) }}"
            ),
        },
        Record::ConnectFailed(
            "schemaMismatch",
            Some(format!(
                "SchemaMismatch {{ local: Fingerprint({theirs:032x}), remote: \
                 Fingerprint({ours:032x}) }}"
            )),
        ),
    );
    let key = dream_net::generate_key();
    // the reference: two peers of the same version
    assert_eq!(
        mismatch(old::server(&key, 1), old::client(9), &key),
        expected
    );
    assert_eq!(
        mismatch(new::server(&key, 1), new::client(9), &key),
        expected
    );
    // and across versions, in both directions
    assert_eq!(
        mismatch(new::server(&key, 1), old::client(9), &key),
        expected
    );
    assert_eq!(
        mismatch(old::server(&key, 1), new::client(9), &key),
        expected
    );
}

/// D1/S1: an old client that reconnects with a used token is refused by a new server (it
/// times out); an old server admits the same reconnect, which is the defect.
#[test]
fn a_new_server_refuses_an_old_client_reusing_its_token() {
    fn reconnect<S: ServerSide>(server: S, key: &[u8; 32]) -> Vec<Record> {
        let mut pair = Pair::new(server, old::client(1));
        wait_for_the_next_second();
        let token = old::token(&[pair.server.address()], key, 5, 30, 1);
        pair.client.connect(&token);
        assert!(pair.run_until(|p| p.client_records.contains(&Record::ClientConnected)));
        pair.client.disconnect();
        assert!(pair.run_until(|p| p.server.num_connected() == 0));
        pair.client_records.clear();
        pair.client.connect(&token);
        assert!(pair.run_until(|p| !p.client_records.is_empty()));
        pair.client_records
    }
    let key = dream_net::generate_key();
    assert_eq!(
        reconnect(new::server(&key, 1), &key),
        [Record::ConnectFailed("timeout", None)]
    );
    assert_eq!(
        reconnect(old::server(&key, 1), &key),
        [Record::ClientConnected]
    );
}

/// D2/S5: a 30-second token minted in a new server's start second is refused; the old server
/// had no start floor.
#[test]
fn a_new_server_refuses_an_old_clients_token_from_its_start_second() {
    for (new_server, expected) in [
        (true, Record::ConnectFailed("timeout", None)),
        (false, Record::ClientConnected),
    ] {
        let mut done = false;
        for _ in 0..5 {
            let key = dream_net::generate_key();
            let start = settled_second();
            let server: Box<dyn ServerSide> = if new_server {
                Box::new(new::server(&key, 1))
            } else {
                Box::new(old::server(&key, 1))
            };
            let token = old::token(&[server.address()], &key, 6, 30, 1);
            if unix_time().as_secs() != start {
                continue;
            }
            let mut pair = Pair::new(server, old::client(1));
            pair.client.connect(&token);
            assert!(pair.run_until(|p| !p.client_records.is_empty()));
            assert_eq!(pair.client_records[0], expected, "new server: {new_server}");
            done = true;
            break;
        }
        assert!(done, "could not mint inside the start second");
    }
}

impl ServerSide for Box<dyn ServerSide> {
    fn address(&self) -> SocketAddr {
        (**self).address()
    }
    fn update(&mut self, time: f64) {
        (**self).update(time);
    }
    fn poll(&mut self) -> Option<Record> {
        (**self).poll()
    }
    fn send(&mut self, peer: u64, event: &str, payload: &[u8]) {
        (**self).send(peer, event, payload);
    }
    fn flush(&mut self) {
        (**self).flush();
    }
    fn disconnect(&mut self, peer: u64) {
        (**self).disconnect(peer);
    }
    fn num_connected(&self) -> usize {
        (**self).num_connected()
    }
}

/// D8/S4: a server disconnect leaves a new client with a two-address token disconnected
/// (`remote`), whichever version the server is; the second address never hears from it.
#[test]
fn a_server_disconnect_leaves_a_new_client_disconnected() {
    for old_server in [true, false] {
        let key = dream_net::generate_key();
        let server: Box<dyn ServerSide> = if old_server {
            Box::new(old::server(&key, 1))
        } else {
            Box::new(new::server(&key, 1))
        };
        let spare = UdpSocket::bind(localhost()).unwrap();
        spare.set_nonblocking(true).unwrap();
        let mut pair = Pair::new(server, new::client(1));
        wait_for_the_next_second();
        let addresses = [pair.server.address(), spare.local_addr().unwrap()];
        pair.client.connect(&new::token(&addresses, &key, 8, 30, 5));
        assert!(pair.run_until(
            |p| p.peer().is_some() && p.client_records.contains(&Record::ClientConnected)
        ));
        let peer = pair.peer().unwrap();
        pair.server.disconnect(peer);
        assert!(pair.run_until(|p| p.client_ended().is_some()));
        pair.run_for(1.0);
        assert_eq!(
            pair.client_records,
            [
                Record::ClientConnected,
                Record::ClientDisconnected("remote")
            ],
            "old server: {old_server}"
        );
        assert_eq!(pair.client.status(), "Disconnected");
        let mut buffer = [0u8; 2048];
        assert!(
            spare.recv_from(&mut buffer).is_err(),
            "old server: {old_server}"
        );
    }
}
