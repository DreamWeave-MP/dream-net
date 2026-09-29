//! Server and client over real netcode on localhost: encrypted UDP, connect tokens, and
//! dream-net's lifecycle on top.

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

use std::net::SocketAddr;
use std::time::Duration;

use common::{test_schema, test_schema_versioned};
use dream_net::{
    ChannelId, Client, ClientConfig, ClientEvent, ClientStatus, DisconnectReason, EventTypeId,
    Failure, Key, PeerId, Schema, SendError, Server, ServerConfig, ServerEvent, TransportConfig,
    USER_DATA_BYTES,
};

const PROTOCOL: u64 = 0xD4EA_4E70_0000_0001;
const DT: f64 = 1.0 / 60.0;

struct World {
    key: Key,
    server: Server,
    clients: Vec<Client>,
    time: f64,
    server_events: Vec<ServerEvent<Vec<u8>>>,
    client_events: Vec<Vec<ClientEvent<Vec<u8>>>>,
}

fn localhost() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

impl World {
    fn new(max_clients: usize, transport: TransportConfig) -> Self {
        let key = dream_net::generate_key();
        let server = Server::new(
            ServerConfig {
                public_address: localhost(),
                protocol_id: PROTOCOL,
                max_clients,
                transport,
            },
            &key,
            test_schema(),
            0.0,
        )
        .unwrap();
        Self {
            key,
            server,
            clients: Vec::new(),
            time: 0.0,
            server_events: Vec::new(),
            client_events: Vec::new(),
        }
    }

    fn token(&self, client_id: u64) -> [u8; dream_net::CONNECT_TOKEN_BYTES] {
        let address = self.server.address();
        let mut user_data = [0u8; USER_DATA_BYTES];
        user_data[..8].copy_from_slice(&client_id.to_le_bytes());
        dream_net::generate_connect_token(
            &[address],
            &[address],
            30,
            5,
            client_id,
            PROTOCOL,
            &self.key,
            &user_data,
        )
        .unwrap()
    }

    fn add_client(&mut self, schema: Schema, client_id: u64) -> usize {
        let mut client = Client::new(
            ClientConfig {
                bind_address: localhost(),
                transport: TransportConfig::default(),
            },
            schema,
            self.time,
        )
        .unwrap();
        client.connect(&self.token(client_id)).unwrap();
        self.clients.push(client);
        self.client_events.push(Vec::new());
        self.clients.len() - 1
    }

    fn step(&mut self) {
        self.time += DT;
        self.server.update(self.time);
        for client in &mut self.clients {
            client.update(self.time);
        }
        while let Some(event) = self.server.poll() {
            self.server_events.push(owned_server(event));
        }
        for (client, events) in self.clients.iter_mut().zip(&mut self.client_events) {
            while let Some(event) = client.poll() {
                events.push(owned_client(event));
            }
        }
        self.server.flush();
        for client in &mut self.clients {
            client.flush();
        }
        std::thread::sleep(Duration::from_millis(1));
    }

    fn run_until(&mut self, max_steps: usize, mut done: impl FnMut(&Self) -> bool) -> bool {
        for _ in 0..max_steps {
            if done(self) {
                return true;
            }
            self.step();
        }
        done(self)
    }

    fn connected_peer(&self) -> Option<PeerId> {
        self.server_events.iter().rev().find_map(|e| match e {
            ServerEvent::Connected { peer, .. } => Some(*peer),
            _ => None,
        })
    }
}

fn owned_server(event: ServerEvent<&[u8]>) -> ServerEvent<Vec<u8>> {
    match event {
        ServerEvent::Connected { peer, client_id } => ServerEvent::Connected { peer, client_id },
        ServerEvent::Disconnected { peer, reason } => ServerEvent::Disconnected { peer, reason },
        ServerEvent::Rejected {
            peer,
            client_id,
            failure,
        } => ServerEvent::Rejected {
            peer,
            client_id,
            failure,
        },
        ServerEvent::Message {
            peer,
            event,
            channel,
            payload,
        } => ServerEvent::Message {
            peer,
            event,
            channel,
            payload: payload.to_vec(),
        },
    }
}

fn owned_client(event: ClientEvent<&[u8]>) -> ClientEvent<Vec<u8>> {
    match event {
        ClientEvent::Connected => ClientEvent::Connected,
        ClientEvent::Disconnected { reason } => ClientEvent::Disconnected { reason },
        ClientEvent::ConnectFailed { reason, failure } => {
            ClientEvent::ConnectFailed { reason, failure }
        }
        ClientEvent::Message {
            event,
            channel,
            payload,
        } => ClientEvent::Message {
            event,
            channel,
            payload: payload.to_vec(),
        },
    }
}

fn event(name: &str) -> EventTypeId {
    test_schema().event_id(name).unwrap()
}

#[test]
fn connect_exchange_and_disconnect() {
    let mut world = World::new(4, TransportConfig::default());
    let c = world.add_client(test_schema(), 42);
    assert_eq!(world.clients[c].status(), ClientStatus::Connecting);
    assert_eq!(
        world.clients[c].send(event("Chat"), b"early"),
        Err(SendError::NotConnected)
    );
    assert!(world.run_until(300, |w| w.connected_peer().is_some()
        && w.clients[c].status() == ClientStatus::Connected));
    let peer = world.connected_peer().unwrap();
    assert_eq!(world.server.client_id(peer), Some(42));
    assert_eq!(
        world.server.client_user_data(peer).unwrap()[..8],
        42u64.to_le_bytes()
    );
    assert_eq!(world.client_events[c], vec![ClientEvent::Connected]);

    world.clients[c]
        .send(event("Chat"), b"hello server")
        .unwrap();
    world.clients[c].send(event("Move"), &[7; 12]).unwrap();
    world
        .server
        .send(peer, event("Spawn"), b"hello client")
        .unwrap();
    assert_eq!(world.server.broadcast(event("Ping"), b"").unwrap(), 0);
    assert!(world.run_until(300, |w| {
        w.server_events
            .iter()
            .filter(|e| matches!(e, ServerEvent::Message { .. }))
            .count()
            == 2
            && w.client_events[c].len() == 3
    }));
    let messages: Vec<_> = world
        .server_events
        .iter()
        .filter(|e| matches!(e, ServerEvent::Message { .. }))
        .cloned()
        .collect();
    assert!(messages.contains(&ServerEvent::Message {
        peer,
        event: event("Chat"),
        channel: ChannelId(0),
        payload: b"hello server".to_vec(),
    }));
    assert!(messages.contains(&ServerEvent::Message {
        peer,
        event: event("Move"),
        channel: ChannelId(1),
        payload: vec![7; 12],
    }));
    assert!(world.client_events[c].contains(&ClientEvent::Message {
        event: event("Spawn"),
        channel: ChannelId(0),
        payload: b"hello client".to_vec(),
    }));
    assert!(world.server.stats(peer).is_some());
    assert!(world.server.memory_usage().total() > 0);

    world.clients[c].disconnect();
    assert!(world.run_until(300, |w| w.server_events.contains(
        &ServerEvent::Disconnected {
            peer,
            reason: DisconnectReason::Remote
        }
    )));
    assert_eq!(
        world.server.send(peer, event("Chat"), b"gone"),
        Err(SendError::UnknownPeer(peer))
    );
    world.step();
    assert_eq!(
        world.client_events[c].last(),
        Some(&ClientEvent::Disconnected {
            reason: DisconnectReason::Requested
        })
    );
}

#[test]
fn schema_mismatch_is_rejected_on_both_ends() {
    let mut world = World::new(4, TransportConfig::default());
    let theirs = test_schema_versioned(9);
    let c = world.add_client(theirs.clone(), 7);
    assert!(world.run_until(300, |w| !w.server_events.is_empty()
        && !w.client_events[c].is_empty()));
    let ours = test_schema().fingerprint();
    assert!(matches!(
        world.server_events[0],
        ServerEvent::Rejected {
            client_id: 7,
            failure: Failure::SchemaMismatch { local, remote },
            ..
        } if local == ours && remote == theirs.fingerprint()
    ));
    assert_eq!(
        world.client_events[c][0],
        ClientEvent::ConnectFailed {
            reason: DisconnectReason::SchemaMismatch,
            failure: Some(Failure::SchemaMismatch {
                local: theirs.fingerprint(),
                remote: ours
            })
        }
    );
    assert_eq!(world.server.num_connected(), 0);
    assert_eq!(world.clients[c].status(), ClientStatus::Disconnected);
}

#[test]
fn server_disconnect_reaches_the_client() {
    let mut world = World::new(4, TransportConfig::default());
    let c = world.add_client(test_schema(), 1);
    assert!(world.run_until(300, |w| w.connected_peer().is_some()));
    let peer = world.connected_peer().unwrap();
    world.server.disconnect(peer);
    world.step();
    assert!(world.server_events.contains(&ServerEvent::Disconnected {
        peer,
        reason: DisconnectReason::Requested
    }));
    assert!(world.run_until(300, |w| w.client_events[c].contains(
        &ClientEvent::Disconnected {
            reason: DisconnectReason::Remote
        }
    )));
}

#[test]
fn a_reused_slot_never_answers_to_the_old_handle() {
    let mut world = World::new(1, TransportConfig::default());
    let first = world.add_client(test_schema(), 1);
    assert!(world.run_until(300, |w| w.connected_peer().is_some()));
    let old = world.connected_peer().unwrap();
    world.clients[first].disconnect();
    assert!(world.run_until(300, |w| w.server.num_connected() == 0));
    world.server_events.clear();
    world.add_client(test_schema(), 2);
    assert!(world.run_until(300, |w| w.connected_peer().is_some()));
    let new = world.connected_peer().unwrap();
    assert_eq!(old.slot(), new.slot());
    assert_ne!(old, new);
    assert_eq!(world.server.client_id(old), None);
    assert_eq!(
        world.server.send(old, event("Chat"), b"x"),
        Err(SendError::UnknownPeer(old))
    );
    world.server.send(new, event("Chat"), b"x").unwrap();
}

#[test]
fn a_full_server_denies() {
    let mut world = World::new(1, TransportConfig::default());
    world.add_client(test_schema(), 1);
    assert!(world.run_until(300, |w| w.connected_peer().is_some()));
    let second = world.add_client(test_schema(), 2);
    assert!(world.run_until(600, |w| !w.client_events[second].is_empty()));
    assert_eq!(
        world.client_events[second][0],
        ClientEvent::ConnectFailed {
            reason: DisconnectReason::Denied,
            failure: None
        }
    );
}

#[test]
fn an_invalid_token_fails_authentication() {
    let mut world = World::new(1, TransportConfig::default());
    let mut client = Client::new(
        ClientConfig {
            bind_address: localhost(),
            transport: TransportConfig::default(),
        },
        test_schema(),
        0.0,
    )
    .unwrap();
    assert!(
        client
            .connect(&[0u8; dream_net::CONNECT_TOKEN_BYTES])
            .is_err()
    );
    assert_eq!(
        client.poll(),
        Some(ClientEvent::ConnectFailed {
            reason: DisconnectReason::Authentication,
            failure: None
        })
    );
    world.step();
}

#[test]
fn a_peer_that_never_says_hello_is_rejected() {
    let mut world = World::new(
        2,
        TransportConfig {
            handshake_timeout: 0.5,
            ..TransportConfig::default()
        },
    );
    // a bare netcode client authenticates but never speaks dream-net
    let mut raw = netcode::Client::new(localhost(), 0.0).unwrap();
    raw.connect(&world.token(99)).unwrap();
    let mut rejected = false;
    for _ in 0..600 {
        raw.update(world.time);
        world.step();
        if world.server_events.iter().any(|e| {
            matches!(
                e,
                ServerEvent::Rejected {
                    client_id: 99,
                    failure: Failure::HandshakeTimeout,
                    ..
                }
            )
        }) {
            rejected = true;
            break;
        }
    }
    assert!(rejected, "{:?}", world.server_events);
    assert_eq!(world.server.num_connected(), 0);
}

#[test]
fn poll_into_reports_small_buffers_without_consuming() {
    let mut world = World::new(1, TransportConfig::default());
    let c = world.add_client(test_schema(), 1);
    assert!(world.run_until(300, |w| w.connected_peer().is_some()
        && w.clients[c].status() == ClientStatus::Connected));
    world.clients[c].send(event("Chat"), &[9; 100]).unwrap();
    // step without the harness draining the server
    let mut buffer = [0u8; 10];
    let mut big = [0u8; 256];
    for _ in 0..300 {
        world.time += DT;
        world.server.update(world.time);
        world.clients[c].update(world.time);
        world.clients[c].flush();
        world.server.flush();
        if let Err(dream_net::BufferTooSmall { needed }) = world.server.poll_into(&mut buffer) {
            assert_eq!(needed, 100);
            let got = world.server.poll_into(&mut big).unwrap().unwrap();
            assert!(matches!(got, ServerEvent::Message { payload: 100, .. }));
            assert_eq!(big[..100], [9; 100]);
            return;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    panic!("the event never arrived");
}

/// Where `Connected` sits among a host's records, and where the first message does.
fn connected_and_first_message<T>(
    records: &[T],
    is_connected: impl Fn(&T) -> bool,
    is_message: impl Fn(&T) -> bool,
) -> (usize, usize) {
    let connected = records.iter().position(is_connected).expect("no Connected");
    let message = records.iter().position(is_message).expect("no message");
    (connected, message)
}

#[test]
fn the_server_announces_a_peer_before_its_first_event() {
    // The client's first packet carries its hello and an event together, as it does when the
    // hello-only packet before it is lost.
    let mut world = World::new(1, TransportConfig::default());
    let c = world.add_client(test_schema(), 5);
    let mut sent = false;
    for _ in 0..300 {
        world.time += DT;
        world.server.update(world.time);
        world.clients[c].update(world.time);
        while let Some(event) = world.server.poll() {
            world.server_events.push(owned_server(event));
        }
        while let Some(event) = world.clients[c].poll() {
            world.client_events[c].push(owned_client(event));
        }
        if !sent && world.clients[c].status() == ClientStatus::Connected {
            world.clients[c].send(event("Chat"), b"first").unwrap();
            sent = true;
        }
        world.server.flush();
        if sent {
            world.clients[c].flush();
        }
        if world
            .server_events
            .iter()
            .any(|e| matches!(e, ServerEvent::Message { .. }))
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let (connected, message) = connected_and_first_message(
        &world.server_events,
        |e| matches!(e, ServerEvent::Connected { .. }),
        |e| matches!(e, ServerEvent::Message { .. }),
    );
    assert!(connected < message, "{:?}", world.server_events);
}

#[test]
fn the_client_reports_connected_before_the_servers_first_event() {
    // The server's first packet the client reads carries its hello and an event together, as
    // it does when the hello-only packet before it is lost.
    let mut world = World::new(1, TransportConfig::default());
    let c = world.add_client(test_schema(), 6);
    // netcode connects without the server flushing, so the client's connection starts
    // before any server hello exists
    for _ in 0..300 {
        world.time += DT;
        world.server.update(world.time);
        world.clients[c].update(world.time);
        world.clients[c].flush();
        if world.clients[c].status() == ClientStatus::Handshaking {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(world.clients[c].status(), ClientStatus::Handshaking);
    let mut peer = None;
    for _ in 0..300 {
        world.time += DT;
        world.server.update(world.time);
        while let Some(event) = world.server.poll() {
            if let ServerEvent::Connected { peer: p, .. } = event {
                peer = Some(p);
            }
        }
        if let Some(peer) = peer {
            world.server.send(peer, event("Spawn"), b"first").unwrap();
            world.server.flush();
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(peer.is_some(), "the server never connected the client");
    for _ in 0..300 {
        std::thread::sleep(Duration::from_millis(1));
        world.time += DT;
        world.clients[c].update(world.time);
        while let Some(event) = world.clients[c].poll() {
            world.client_events[c].push(owned_client(event));
        }
        if world.client_events[c]
            .iter()
            .any(|e| matches!(e, ClientEvent::Message { .. }))
        {
            break;
        }
    }
    let (connected, message) = connected_and_first_message(
        &world.client_events[c],
        |e| *e == ClientEvent::Connected,
        |e| matches!(e, ClientEvent::Message { .. }),
    );
    assert!(connected < message, "{:?}", world.client_events[c]);
}
