//! Security regressions against a live server on localhost, written only against dream-net's
//! public API and raw UDP sockets so they outlive any change of transport backend: hostile
//! datagrams before and after authentication, replayed traffic, connect tokens presented
//! twice or for the wrong protocol, and stale peer handles.
//!
//! Every test here passes on the current transport and must keep passing after it is
//! replaced. Connect tokens that are meant to succeed live for an hour, well above any
//! maximum token lifetime a server enforces at its start, so a server that refuses tokens
//! issued before it started still accepts them in the second it starts.

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

use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use common::{connection_request, test_schema, token_servers};
use dream_net::{
    CONNECT_TOKEN_BYTES, Client, ClientConfig, ClientEvent, ClientStatus, EventTypeId, Key, PeerId,
    SendError, Server, ServerConfig, ServerEvent, TransportConfig, USER_DATA_BYTES,
};

const PROTOCOL: u64 = 0xD4EA_4E70_0000_00AD;

/// How long a test waits for something over real sockets before failing.
const DEADLINE: Duration = Duration::from_secs(20);

/// The lifetime of tokens that are meant to be accepted.
const TOKEN_LIFETIME: i32 = 3600;

/// The largest datagram these tests send; above any datagram netcode reads.
const OVERSIZED: usize = 1500;

fn localhost() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn chat() -> EventTypeId {
    test_schema().event_id("Chat").unwrap()
}

/// A deterministic byte stream (xorshift64), so a failure reproduces.
struct Noise(u64);

impl Noise {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next() as u8).collect()
    }
}

/// Forwards datagrams between one client and the server, so the server sees every client
/// datagram (and every injected one) arrive from the proxy's address. It records what the
/// client sent.
struct Proxy {
    socket: UdpSocket,
    server: SocketAddr,
    client: Option<SocketAddr>,
    from_client: Vec<Vec<u8>>,
}

impl Proxy {
    fn new(server: SocketAddr) -> Self {
        let socket = UdpSocket::bind(localhost()).unwrap();
        socket.set_nonblocking(true).unwrap();
        Self {
            socket,
            server,
            client: None,
            from_client: Vec::new(),
        }
    }

    fn address(&self) -> SocketAddr {
        self.socket.local_addr().unwrap()
    }

    fn pump(&mut self) {
        let mut buffer = [0u8; 2048];
        while let Ok((len, from)) = self.socket.recv_from(&mut buffer) {
            if from == self.server {
                if let Some(client) = self.client {
                    let _ = self.socket.send_to(&buffer[..len], client);
                }
            } else {
                self.client = Some(from);
                self.from_client.push(buffer[..len].to_vec());
                let _ = self.socket.send_to(&buffer[..len], self.server);
            }
        }
    }

    /// Sends `datagrams` to the server from the proxy's own address: to the server, they come
    /// from the authenticated client.
    fn inject(&self, datagrams: &[Vec<u8>]) {
        for datagram in datagrams {
            let _ = self.socket.send_to(datagram, self.server);
        }
    }
}

/// A server, its clients and an optional proxy, driven on the wall clock.
struct Net {
    key: Key,
    server: Server,
    clients: Vec<Client>,
    proxy: Option<Proxy>,
    started: Instant,
    server_events: Vec<ServerEvent<Vec<u8>>>,
    client_events: Vec<Vec<ClientEvent<Vec<u8>>>>,
}

impl Net {
    fn new(max_clients: usize) -> Self {
        let key = dream_net::generate_key();
        let server = Server::new(
            ServerConfig {
                public_address: localhost(),
                protocol_id: PROTOCOL,
                max_clients,
                transport: TransportConfig::default(),
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
            proxy: None,
            started: Instant::now(),
            server_events: Vec::new(),
            client_events: Vec::new(),
        }
    }

    fn with_proxy(max_clients: usize) -> Self {
        let mut net = Self::new(max_clients);
        net.proxy = Some(Proxy::new(net.server.address()));
        net
    }

    fn time(&self) -> f64 {
        self.started.elapsed().as_secs_f64()
    }

    /// A token for this server, routed through the proxy when there is one: the client
    /// connects to the first address, and the server accepts because its own is listed too.
    fn token(&self, client_id: u64) -> [u8; CONNECT_TOKEN_BYTES] {
        self.token_with(client_id, PROTOCOL, &self.key, TOKEN_LIFETIME, 5)
    }

    fn token_with(
        &self,
        client_id: u64,
        protocol: u64,
        key: &Key,
        lifetime: i32,
        timeout: i32,
    ) -> [u8; CONNECT_TOKEN_BYTES] {
        let mut addresses = Vec::new();
        if let Some(proxy) = &self.proxy {
            addresses.push(proxy.address());
        }
        addresses.push(self.server.address());
        dream_net::generate_connect_token(
            &addresses,
            &addresses,
            lifetime,
            timeout,
            client_id,
            protocol,
            key,
            &[0u8; USER_DATA_BYTES],
        )
        .unwrap()
    }

    fn add_client(&mut self, token: &[u8; CONNECT_TOKEN_BYTES]) -> usize {
        let mut client = Client::new(
            ClientConfig {
                bind_address: localhost(),
                transport: TransportConfig::default(),
            },
            test_schema(),
            self.time(),
        )
        .unwrap();
        client.connect(token).unwrap();
        self.clients.push(client);
        self.client_events.push(Vec::new());
        self.clients.len() - 1
    }

    fn step(&mut self) {
        let time = self.time();
        self.server.update(time);
        if let Some(proxy) = &mut self.proxy {
            proxy.pump();
        }
        for client in &mut self.clients {
            client.update(time);
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
        if let Some(proxy) = &mut self.proxy {
            proxy.pump();
        }
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

    /// Steps for `seconds` of wall time.
    fn run_for(&mut self, seconds: f64) {
        let until = Instant::now() + Duration::from_secs_f64(seconds);
        while Instant::now() < until {
            self.step();
        }
    }

    fn connected_peers(&self) -> Vec<PeerId> {
        self.server_events
            .iter()
            .filter_map(|e| match e {
                ServerEvent::Connected { peer, .. } => Some(*peer),
                _ => None,
            })
            .collect()
    }

    fn messages(&self) -> Vec<Vec<u8>> {
        self.server_events
            .iter()
            .filter_map(|e| match e {
                ServerEvent::Message { payload, .. } => Some(payload.clone()),
                _ => None,
            })
            .collect()
    }

    fn connect_one(&mut self, client_id: u64) -> (usize, PeerId) {
        let token = self.token(client_id);
        let c = self.add_client(&token);
        let before = self.connected_peers().len();
        assert!(
            self.run_until(|n| n.connected_peers().len() > before
                && n.clients[c].status() == ClientStatus::Connected),
            "client {client_id} never connected: {:?}",
            self.server_events
        );
        (c, *self.connected_peers().last().unwrap())
    }

    fn failed(&self, c: usize) -> bool {
        self.client_events[c]
            .iter()
            .any(|e| matches!(e, ClientEvent::ConnectFailed { .. }))
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

/// Datagrams no honest peer sends: empty, every prefix byte alone, every packet type and
/// sequence length over short and full-sized bodies, connection-request shapes with bad
/// fields, and oversized noise.
fn hostile_datagrams(seed: u64) -> Vec<Vec<u8>> {
    let mut noise = Noise(seed);
    let mut out = vec![Vec::new()];
    for prefix in 0..=255u8 {
        out.push(vec![prefix]);
        for len in [
            2, 3, 9, 17, 18, 25, 26, 40, 330, 1078, 1199, 1200, 1201, 1300,
        ] {
            let mut datagram = noise.bytes(len);
            datagram[0] = prefix;
            out.push(datagram);
        }
    }
    // connection requests: right length, then each field wrong in turn
    let far_future = u64::MAX / 2;
    let request = |version: &[u8; 13], protocol: u64, expire: u64, noise: &mut Noise| {
        let mut datagram = vec![0u8];
        datagram.extend_from_slice(version);
        datagram.extend_from_slice(&protocol.to_le_bytes());
        datagram.extend_from_slice(&expire.to_le_bytes());
        datagram.extend(noise.bytes(24 + 1024));
        datagram
    };
    for _ in 0..16 {
        out.push(request(b"NETCODE 1.02\0", PROTOCOL, far_future, &mut noise));
        out.push(request(b"NETCODE 1.01\0", PROTOCOL, far_future, &mut noise));
        out.push(request(
            b"NETCODE 1.02\0",
            PROTOCOL ^ 1,
            far_future,
            &mut noise,
        ));
        out.push(request(b"NETCODE 1.02\0", PROTOCOL, 1, &mut noise));
        let mut short = request(b"NETCODE 1.02\0", PROTOCOL, far_future, &mut noise);
        short.pop();
        out.push(short);
        let mut long = request(b"NETCODE 1.02\0", PROTOCOL, far_future, &mut noise);
        long.push(0);
        out.push(long);
    }
    for _ in 0..64 {
        let len = (noise.next() % OVERSIZED as u64) as usize;
        out.push(noise.bytes(len));
    }
    out.push(noise.bytes(OVERSIZED));
    out
}

/// Encrypted-packet shapes for every packet type and sequence length, with sequence numbers
/// at the edges of the 64-bit space: none authenticates, and none may move replay protection.
fn forged_encrypted(seed: u64) -> Vec<Vec<u8>> {
    let mut noise = Noise(seed);
    let mut out = Vec::new();
    for kind in 0..16u8 {
        for sequence_bytes in 0..16u8 {
            for body in [0, 1, 16, 17, 30, 200, 1216, 1290] {
                let mut datagram = vec![kind | (sequence_bytes << 4)];
                let sequence = match noise.next() % 3 {
                    0 => u64::MAX,
                    1 => u64::MAX - 1,
                    _ => noise.next(),
                };
                let n = usize::from(sequence_bytes).min(8);
                datagram.extend_from_slice(&sequence.to_le_bytes()[..n]);
                datagram.extend(noise.bytes(body));
                out.push(datagram);
            }
        }
    }
    out
}

fn spray(target: SocketAddr, datagrams: &[Vec<u8>]) {
    let socket = UdpSocket::bind(localhost()).unwrap();
    for datagram in datagrams {
        let _ = socket.send_to(datagram, target);
    }
}

#[test]
fn hostile_datagrams_before_authentication_admit_nobody() {
    let mut net = Net::new(4);
    let target = net.server.address();
    for seed in 1..=4 {
        spray(target, &hostile_datagrams(seed));
        spray(target, &forged_encrypted(seed));
        net.run_for(0.05);
    }
    net.run_for(0.2);
    assert!(net.server_events.is_empty(), "{:?}", net.server_events);
    assert_eq!(net.server.num_connected(), 0);

    // the server is still serving
    let (c, peer) = net.connect_one(1);
    net.clients[c].send(chat(), b"after the storm").unwrap();
    assert!(net.run_until(|n| n.messages().contains(&b"after the storm".to_vec())));
    assert_eq!(net.server.client_id(peer), Some(1));
}

#[test]
fn hostile_datagrams_to_a_client_are_ignored() {
    let mut net = Net::new(1);
    let token = net.token(1);
    let c = net.add_client(&token);
    let target: SocketAddr = format!("127.0.0.1:{}", net.clients[c].port())
        .parse()
        .unwrap();
    // while it is connecting
    spray(target, &hostile_datagrams(11));
    spray(target, &forged_encrypted(11));
    assert!(net.run_until(
        |n| n.clients[c].status() == ClientStatus::Connected && !n.connected_peers().is_empty()
    ));
    let peer = net.connected_peers()[0];
    // and once it is connected
    spray(target, &hostile_datagrams(12));
    spray(target, &forged_encrypted(12));
    net.server.send(peer, chat(), b"still here").unwrap();
    assert!(
        net.run_until(|n| n.client_events[c].iter().any(|e| matches!(
            e,
            ClientEvent::Message { payload, .. } if payload == b"still here"
        )))
    );
    assert_eq!(net.clients[c].status(), ClientStatus::Connected);
}

#[test]
fn forged_packets_from_an_authenticated_address_do_not_disturb_the_session() {
    let mut net = Net::with_proxy(2);
    let (c, peer) = net.connect_one(7);
    // the server sees these come from the client's own address, under the client's keys
    for seed in 21..=24 {
        let proxy = net.proxy.as_ref().unwrap();
        proxy.inject(&forged_encrypted(seed));
        proxy.inject(&hostile_datagrams(seed));
        net.step();
    }
    for n in 0u32..40 {
        net.clients[c].send(chat(), &n.to_le_bytes()).unwrap();
    }
    assert!(
        net.run_until(|n| n.messages().len() >= 40),
        "{:?}",
        net.server_events
    );
    let expected: Vec<Vec<u8>> = (0u32..40).map(|n| n.to_le_bytes().to_vec()).collect();
    assert_eq!(net.messages(), expected);
    assert_eq!(net.connected_peers(), vec![peer]);
    assert!(
        !net.server_events.iter().any(|e| matches!(
            e,
            ServerEvent::Disconnected { .. } | ServerEvent::Rejected { .. }
        )),
        "{:?}",
        net.server_events
    );
    assert_eq!(net.server.client_id(peer), Some(7));
}

#[test]
fn replayed_traffic_delivers_nothing_twice_and_admits_nobody() {
    let mut net = Net::with_proxy(4);
    let (c, peer) = net.connect_one(3);
    for n in 0u32..20 {
        net.clients[c].send(chat(), &n.to_le_bytes()).unwrap();
    }
    assert!(net.run_until(|n| n.messages().len() >= 20));
    net.run_for(0.2);
    let recorded = net.proxy.as_ref().unwrap().from_client.clone();
    // the replay includes the connection request that admitted the client
    assert!(recorded.iter().any(|d| d.len() == 1078 && d[0] == 0));
    let delivered = net.messages();

    // everything the client ever sent, again, from its own address and from a stranger's
    net.proxy.as_ref().unwrap().inject(&recorded);
    spray(net.server.address(), &recorded);
    net.run_for(0.5);

    assert_eq!(net.messages(), delivered);
    assert_eq!(net.connected_peers(), vec![peer]);
    assert_eq!(net.server.num_connected(), 1);

    // the session itself is unharmed
    net.clients[c].send(chat(), b"fresh").unwrap();
    assert!(net.run_until(|n| n.messages().contains(&b"fresh".to_vec())));
}

/// Presents `token` again exactly as a second client would until a server answers it: its
/// connection request, from a new raw socket, ten times a second to each server the token
/// lists in turn for the token's timeout, while `net` runs. A process refuses to pass a used
/// token to `connect` again (asserted by the callers), so this is how the server's own refusal
/// is tested. Returns every datagram the socket received.
fn present_raw(net: &mut Net, token: &[u8; CONNECT_TOKEN_BYTES]) -> Vec<Vec<u8>> {
    let socket = UdpSocket::bind(localhost()).unwrap();
    socket.set_nonblocking(true).unwrap();
    let request = connection_request(token);
    let (timeout, servers) = token_servers(token);
    let mut answers = Vec::new();
    let mut buffer = [0u8; 2048];
    for server in servers {
        let until = Instant::now() + Duration::from_secs(u64::try_from(timeout).unwrap());
        let mut next_send = Instant::now();
        while Instant::now() < until {
            if Instant::now() >= next_send {
                socket.send_to(&request, server).unwrap();
                next_send += Duration::from_millis(100);
            }
            net.step();
            while let Ok((len, _)) = socket.recv_from(&mut buffer) {
                answers.push(buffer[..len].to_vec());
            }
        }
    }
    answers
}

/// The positive control for `present_raw`: a server answers it with a challenge (packet type
/// 2) for a token it has not seen, so the refusals asserted below cannot pass vacuously.
#[test]
fn the_raw_presenter_is_answered_for_a_fresh_token() {
    let mut net = Net::new(1);
    let token = net.token(55);
    let answers = present_raw(&mut net, &token);
    assert_ne!(answers.len(), 0, "the server never answered a fresh token");
    assert!(answers.iter().all(|d| d[0] & 0x0F == 2), "{answers:?}");
}

#[test]
fn a_connect_token_is_refused_from_a_second_address() {
    let mut net = Net::new(4);
    let token = net.token_with(5, PROTOCOL, &net.key, TOKEN_LIFETIME, 1);
    let first = net.add_client(&token);
    assert!(net.run_until(|n| n.clients[first].status() == ClientStatus::Connected));

    // the same token on another client of this process: refused here, before anything is sent
    let mut second = Client::new(
        ClientConfig {
            bind_address: localhost(),
            transport: TransportConfig::default(),
        },
        test_schema(),
        net.time(),
    )
    .unwrap();
    assert!(matches!(
        second.connect(&token),
        Err(dream_net::Error::Netcode(
            dream_net::NetcodeError::InvalidConnectToken
        ))
    ));
    // the same token from another socket, while the first holds it, presented as a second
    // client would: the server never answers
    assert_eq!(present_raw(&mut net, &token), Vec::<Vec<u8>>::new());
    assert_eq!(net.connected_peers().len(), 1);

    // and after the first has left
    net.clients[first].disconnect();
    assert!(net.run_until(|n| n.server.num_connected() == 0));
    assert_eq!(present_raw(&mut net, &token), Vec::<Vec<u8>>::new());
    assert_eq!(net.connected_peers().len(), 1);
    assert_eq!(net.server.num_connected(), 0);
}

#[test]
fn tokens_for_another_protocol_key_or_time_are_refused() {
    let mut net = Net::new(4);
    let stranger = dream_net::generate_key();
    let tokens = [
        net.token_with(1, PROTOCOL ^ 0xFF, &net.key, TOKEN_LIFETIME, 1),
        net.token_with(2, PROTOCOL, &stranger, TOKEN_LIFETIME, 1),
        net.token_with(3, PROTOCOL, &net.key, 0, 1),
    ];
    let clients: Vec<usize> = tokens.iter().map(|t| net.add_client(t)).collect();
    assert!(
        net.run_until(|n| clients.iter().all(|&c| n.failed(c))),
        "{:?}",
        net.client_events
    );
    assert!(net.server_events.is_empty(), "{:?}", net.server_events);
    assert_eq!(net.server.num_connected(), 0);
    for &c in &clients {
        assert!(
            !net.client_events[c].contains(&ClientEvent::Connected),
            "{:?}",
            net.client_events[c]
        );
    }
}

#[test]
fn a_stale_peer_handle_cannot_reach_the_slots_next_occupant() {
    let mut net = Net::new(1);
    let (first, old) = net.connect_one(1);
    net.clients[first].disconnect();
    assert!(net.run_until(|n| n.server.num_connected() == 0));
    let (second, new) = net.connect_one(2);
    assert_eq!(old.slot(), new.slot());
    assert_ne!(old, new);

    assert_eq!(
        net.server.send(old, chat(), b"x"),
        Err(SendError::UnknownPeer(old))
    );
    assert_eq!(net.server.client_id(old), None);
    assert_eq!(net.server.client_address(old), None);
    assert!(net.server.client_user_data(old).is_none());
    assert!(net.server.stats(old).is_none());
    assert!(net.server.counters(old).is_none());
    assert!(net.server.peer_connection(old).is_none());
    assert_eq!(
        net.server.broadcast_except(Some(old), chat(), b"all"),
        Ok(0)
    );

    // disconnecting the stale handle leaves the new occupant alone
    let before = net.server_events.len();
    net.server.disconnect(old);
    net.run_for(0.2);
    assert!(
        !net.server_events[before..]
            .iter()
            .any(|e| matches!(e, ServerEvent::Disconnected { .. })),
        "{:?}",
        net.server_events
    );
    assert_eq!(net.server.client_id(new), Some(2));
    assert_eq!(net.clients[second].status(), ClientStatus::Connected);
    net.server.send(new, chat(), b"yours").unwrap();
    assert!(
        net.run_until(|n| n.client_events[second].iter().any(|e| matches!(
            e,
            ClientEvent::Message { payload, .. } if payload == b"yours"
        )))
    );
}
