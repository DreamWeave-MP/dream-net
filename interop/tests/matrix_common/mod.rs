//! Shared by the socket matrix tests: dream-net 1.1.1 (`netcode-official` 1.0.0 and the
//! `reliable` 1.3.4 Rust port underneath) and this tree (C netcode 1.4.10 and C reliable 1.4.6
//! underneath) behind one object-safe server and client interface, a session that drives one
//! server and any number of clients over real loopback sockets on the wall clock, and the
//! wall-clock helpers the start floor needs.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const PROTOCOL: u64 = 0x0DDB_A11C_AFE0_0011;
pub const OTHER_PROTOCOL: u64 = 0x0DDB_A11C_AFE0_0012;
pub const DEADLINE: Duration = Duration::from_secs(20);

/// Which implementation a side runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// dream-net 1.1.1 from crates.io.
    Old,
    /// This tree.
    New,
}

/// Every (client, server) pairing.
pub const PAIRINGS: [(Kind, Kind); 4] = [
    (Kind::Old, Kind::Old),
    (Kind::Old, Kind::New),
    (Kind::New, Kind::Old),
    (Kind::New, Kind::New),
];

/// The schema a side builds. Every variant but `Base` differs from it in exactly one way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variant {
    /// tests/common's schema: channels `reliable` (window 64), `state` (unreliable, 64) and
    /// `bulk` (window 16); events Blob, Chat, Move, Ping, Spawn. Schema version 1.
    Base,
    /// Schema version 9.
    Version9,
    /// One more event (`Emote` on `state`).
    ExtraEvent,
    /// The `reliable` channel's window is 128.
    Capacity,
    /// `Chat` allows 512-byte payloads.
    PayloadLimit,
}

/// The address family a session runs on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    /// The loopback address with port 0.
    pub fn loopback(self) -> SocketAddr {
        match self {
            Family::V4 => "127.0.0.1:0".parse().unwrap(),
            Family::V6 => "[::1]:0".parse().unwrap(),
        }
    }
}

/// A record either version produced, with nothing version-specific left in it: handles as their
/// raw `u64`, reasons by their stable names, failures by their `Debug` text (the same shape in
/// both versions).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
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

/// The counters a matrix cell checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Counts {
    pub packets_sent: u64,
    pub events_sent: u64,
    pub datagrams_received: u64,
    pub packets_received: u64,
    pub events_received: u64,
}

pub trait ServerSide {
    fn kind(&self) -> Kind;
    fn address(&self) -> SocketAddr;
    fn update(&mut self, time: f64);
    fn poll(&mut self) -> Option<Record>;
    fn send(&mut self, peer: u64, event: &str, payload: &[u8]);
    fn flush(&mut self);
    fn disconnect(&mut self, peer: u64);
    fn num_connected(&self) -> usize;
    fn client_id(&self, peer: u64) -> Option<u64>;
    fn counts(&self, peer: u64) -> Option<Counts>;
}

pub trait ClientSide {
    fn kind(&self) -> Kind;
    fn connect(&mut self, token: &[u8; 2048]);
    fn update(&mut self, time: f64);
    fn poll(&mut self) -> Option<Record>;
    fn send(&mut self, event: &str, payload: &[u8]);
    fn flush(&mut self);
    fn disconnect(&mut self);
    fn status(&self) -> String;
    fn counts(&self) -> Option<Counts>;
}

/// Everything a test needs from one version of dream-net, written once for both.
macro_rules! side {
    ($side:ident, $dn:ident, $kind:expr) => {
        pub mod $side {
            use super::{ClientSide, Counts, Kind, Record, ServerSide, Variant};
            use std::net::SocketAddr;

            pub fn schema(variant: Variant) -> $dn::Schema {
                let version = if variant == Variant::Version9 { 9 } else { 1 };
                let window = if variant == Variant::Capacity {
                    128
                } else {
                    64
                };
                let chat = if variant == Variant::PayloadLimit {
                    512
                } else {
                    256
                };
                let mut b = $dn::Schema::builder(version).max_messages_per_packet(32);
                let reliable = b
                    .channel($dn::ChannelConfig::reliable_ordered("reliable").with_capacity(window))
                    .unwrap();
                let state = b
                    .channel($dn::ChannelConfig::unreliable_unordered("state").with_capacity(64))
                    .unwrap();
                let bulk = b
                    .channel($dn::ChannelConfig::reliable_ordered("bulk").with_capacity(16))
                    .unwrap();
                b.event("Chat", reliable, chat).unwrap();
                b.event("Spawn", reliable, 1024).unwrap();
                b.event("Move", state, 64).unwrap();
                b.event("Ping", state, 0).unwrap();
                b.event("Blob", bulk, 8000).unwrap();
                if variant == Variant::ExtraEvent {
                    b.event("Emote", state, 16).unwrap();
                }
                b.build().unwrap()
            }

            pub fn fingerprint(variant: Variant) -> u128 {
                schema(variant).fingerprint().0
            }

            pub fn token(
                addresses: &[SocketAddr],
                key: &[u8; 32],
                client_id: u64,
                lifetime: i32,
                timeout: i32,
                protocol: u64,
            ) -> [u8; 2048] {
                let mut user_data = [0u8; 256];
                user_data[..8].copy_from_slice(&client_id.to_le_bytes());
                $dn::generate_connect_token(
                    addresses, addresses, lifetime, timeout, client_id, protocol, key, &user_data,
                )
                .unwrap()
            }

            pub struct Server {
                pub inner: $dn::Server,
                schema: $dn::Schema,
            }

            pub fn server(
                key: &[u8; 32],
                variant: Variant,
                address: SocketAddr,
                protocol: u64,
                max_clients: usize,
            ) -> Server {
                let inner = $dn::Server::new(
                    $dn::ServerConfig {
                        public_address: address,
                        protocol_id: protocol,
                        max_clients,
                        transport: $dn::TransportConfig::default(),
                    },
                    key,
                    schema(variant),
                    0.0,
                )
                .unwrap();
                Server {
                    inner,
                    schema: schema(variant),
                }
            }

            fn counts(c: $dn::Counters) -> Counts {
                Counts {
                    packets_sent: c.packets_sent,
                    events_sent: c.events_sent,
                    datagrams_received: c.datagrams_received,
                    packets_received: c.packets_received,
                    events_received: c.events_received,
                }
            }

            impl ServerSide for Server {
                fn kind(&self) -> Kind {
                    $kind
                }
                fn address(&self) -> SocketAddr {
                    self.inner.address()
                }
                fn update(&mut self, time: f64) {
                    self.inner.update(time);
                }
                fn poll(&mut self) -> Option<Record> {
                    Some(match self.inner.poll()? {
                        $dn::ServerEvent::Connected { peer, client_id } => Record::Connected {
                            peer: peer.0,
                            client_id,
                        },
                        $dn::ServerEvent::Disconnected { peer, reason } => Record::Disconnected {
                            peer: peer.0,
                            reason: reason.name(),
                        },
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
                    let id = self.schema.event_id(event).unwrap();
                    self.inner.send($dn::PeerId(peer), id, payload).unwrap();
                }
                fn flush(&mut self) {
                    self.inner.flush();
                }
                fn disconnect(&mut self, peer: u64) {
                    self.inner.disconnect($dn::PeerId(peer));
                }
                fn num_connected(&self) -> usize {
                    self.inner.num_connected()
                }
                fn client_id(&self, peer: u64) -> Option<u64> {
                    self.inner.client_id($dn::PeerId(peer))
                }
                fn counts(&self, peer: u64) -> Option<Counts> {
                    self.inner.counters($dn::PeerId(peer)).map(counts)
                }
            }

            pub struct Client {
                pub inner: $dn::Client,
                schema: $dn::Schema,
            }

            pub fn client(variant: Variant, bind: SocketAddr) -> Client {
                let inner = $dn::Client::new(
                    $dn::ClientConfig {
                        bind_address: bind,
                        transport: $dn::TransportConfig::default(),
                    },
                    schema(variant),
                    0.0,
                )
                .unwrap();
                Client {
                    inner,
                    schema: schema(variant),
                }
            }

            impl ClientSide for Client {
                fn kind(&self) -> Kind {
                    $kind
                }
                fn connect(&mut self, token: &[u8; 2048]) {
                    self.inner.connect(token).unwrap();
                }
                fn update(&mut self, time: f64) {
                    self.inner.update(time);
                }
                fn poll(&mut self) -> Option<Record> {
                    Some(match self.inner.poll()? {
                        $dn::ClientEvent::Connected => Record::ClientConnected,
                        $dn::ClientEvent::Disconnected { reason } => {
                            Record::ClientDisconnected(reason.name())
                        }
                        $dn::ClientEvent::ConnectFailed { reason, failure } => {
                            Record::ConnectFailed(reason.name(), failure.map(|f| format!("{f:?}")))
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
                    let id = self.schema.event_id(event).unwrap();
                    self.inner.send(id, payload).unwrap();
                }
                fn flush(&mut self) {
                    self.inner.flush();
                }
                fn disconnect(&mut self) {
                    self.inner.disconnect();
                }
                fn status(&self) -> String {
                    format!("{:?}", self.inner.status())
                }
                fn counts(&self) -> Option<Counts> {
                    self.inner.counters().map(counts)
                }
            }
        }
    };
}

side!(old, dream_net_old, Kind::Old);
side!(new, dream_net, Kind::New);

pub fn server(
    kind: Kind,
    key: &[u8; 32],
    variant: Variant,
    address: SocketAddr,
    protocol: u64,
    max_clients: usize,
) -> Box<dyn ServerSide> {
    match kind {
        Kind::Old => Box::new(old::server(key, variant, address, protocol, max_clients)),
        Kind::New => Box::new(new::server(key, variant, address, protocol, max_clients)),
    }
}

pub fn client(kind: Kind, variant: Variant, bind: SocketAddr) -> Box<dyn ClientSide> {
    match kind {
        Kind::Old => Box::new(old::client(variant, bind)),
        Kind::New => Box::new(new::client(variant, bind)),
    }
}

/// A connect token minted by `minter`'s `generate_connect_token`.
pub fn token(
    minter: Kind,
    addresses: &[SocketAddr],
    key: &[u8; 32],
    client_id: u64,
    lifetime: i32,
    timeout: i32,
    protocol: u64,
) -> [u8; 2048] {
    match minter {
        Kind::Old => old::token(addresses, key, client_id, lifetime, timeout, protocol),
        Kind::New => new::token(addresses, key, client_id, lifetime, timeout, protocol),
    }
}

/// An event id, the same in both versions (`both_versions_agree_on_every_variant` proves it).
pub fn event(variant: Variant, name: &str) -> u32 {
    new::schema(variant).event_id(name).unwrap().0
}

/// One server, any number of clients, and every record each produced, on the wall clock.
pub struct Session {
    pub server: Box<dyn ServerSide>,
    pub clients: Vec<Box<dyn ClientSide>>,
    pub server_records: Vec<Record>,
    pub client_records: Vec<Vec<Record>>,
    /// A paused side is neither updated nor flushed: it falls silent without saying goodbye.
    pub server_paused: bool,
    pub client_paused: Vec<bool>,
    started: Instant,
}

impl Session {
    pub fn new(server: Box<dyn ServerSide>) -> Self {
        Self {
            server,
            clients: Vec::new(),
            server_records: Vec::new(),
            client_records: Vec::new(),
            server_paused: false,
            client_paused: Vec::new(),
            started: Instant::now(),
        }
    }

    /// Adds a client; returns its index.
    pub fn add(&mut self, client: Box<dyn ClientSide>) -> usize {
        self.clients.push(client);
        self.client_records.push(Vec::new());
        self.client_paused.push(false);
        self.clients.len() - 1
    }

    pub fn time(&self) -> f64 {
        self.started.elapsed().as_secs_f64()
    }

    pub fn step(&mut self) {
        let time = self.time();
        if !self.server_paused {
            self.server.update(time);
        }
        for (client, paused) in self.clients.iter_mut().zip(&self.client_paused) {
            if !paused {
                client.update(time);
            }
        }
        self.poll();
        if !self.server_paused {
            self.server.flush();
        }
        for (client, paused) in self.clients.iter_mut().zip(&self.client_paused) {
            if !paused {
                client.flush();
            }
        }
        std::thread::sleep(Duration::from_millis(1));
    }

    /// Takes every pending record without updating or flushing anything.
    pub fn poll(&mut self) {
        while let Some(record) = self.server.poll() {
            self.server_records.push(record);
        }
        for (client, records) in self.clients.iter_mut().zip(&mut self.client_records) {
            while let Some(record) = client.poll() {
                records.push(record);
            }
        }
    }

    pub fn run_until(&mut self, mut done: impl FnMut(&Self) -> bool) -> bool {
        let deadline = Instant::now() + DEADLINE;
        while Instant::now() < deadline {
            if done(self) {
                return true;
            }
            self.step();
        }
        done(self)
    }

    pub fn run_for(&mut self, seconds: f64) {
        let until = Instant::now() + Duration::from_secs_f64(seconds);
        while Instant::now() < until {
            self.step();
        }
    }

    /// The handle the server announced for `client_id`.
    pub fn peer_of(&self, client_id: u64) -> Option<u64> {
        self.server_records.iter().find_map(|r| match r {
            Record::Connected {
                peer,
                client_id: id,
            } if *id == client_id => Some(*peer),
            _ => None,
        })
    }

    /// Connects client `index` with `token` and runs until both ends announced the session.
    /// Returns the server's handle for it.
    pub fn connect(&mut self, index: usize, token: &[u8; 2048], client_id: u64) -> u64 {
        self.clients[index].connect(token);
        assert!(
            self.run_until(|s| s.peer_of(client_id).is_some()
                && s.client_records[index].contains(&Record::ClientConnected)),
            "server {:?}, client {:?}",
            self.server_records,
            self.client_records[index]
        );
        self.peer_of(client_id).unwrap()
    }

    /// The first record that ended client `index`'s attempt or session.
    pub fn client_ended(&self, index: usize) -> Option<&Record> {
        self.client_records[index]
            .iter()
            .find(|r| matches!(r, Record::ClientDisconnected(_) | Record::ConnectFailed(..)))
    }

    pub fn messages(records: &[Record]) -> Vec<&Record> {
        records
            .iter()
            .filter(|r| matches!(r, Record::Message { .. }))
            .collect()
    }
}

pub fn unix_time() -> Duration {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
}

/// Waits until the wall clock has left the current second by 60 ms (netcode's `time(NULL)` is a
/// coarse clock): a token minted after this clears a server started before it.
pub fn wait_for_the_next_second() {
    let second = unix_time().as_secs();
    while unix_time() < Duration::from_secs(second + 1) + Duration::from_millis(60) {
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Waits until the current second is at least 60 ms old with half a second left, and returns it.
pub fn settled_second() -> u64 {
    loop {
        let now = unix_time();
        if (60..=500).contains(&now.subsec_millis()) {
            return now.as_secs();
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
