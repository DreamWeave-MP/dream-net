//! A live server, its clients and an optional recording relay on localhost, driven on the wall
//! clock, for the lifecycle and lifecycle-security tests. Only dream-net's public API and
//! `std::net::UdpSocket` are used.

#![allow(dead_code)]

use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::common::test_schema;
use dream_net::{
    CONNECT_TOKEN_BYTES, Client, ClientConfig, ClientEvent, ClientStatus, EventTypeId, Key, PeerId,
    Server, ServerConfig, ServerEvent, TransportConfig, USER_DATA_BYTES,
};

pub const PROTOCOL: u64 = 0xD4EA_4E70_0000_0009;

/// How long a test waits for something over real sockets before failing: a wall-clock bound,
/// because a loaded runner may take many times longer per step than a workstation.
pub const DEADLINE: Duration = Duration::from_secs(20);

pub type Token = [u8; CONNECT_TOKEN_BYTES];

pub fn localhost() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

pub fn chat() -> EventTypeId {
    test_schema().event_id("Chat").unwrap()
}

pub fn moved() -> EventTypeId {
    test_schema().event_id("Move").unwrap()
}

/// The wall clock in whole Unix seconds: what netcode stamps tokens and its start floor with.
pub fn unix_second() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Waits until the wall clock is past `second` by at least 60 ms. netcode reads `time(NULL)`, a
/// coarse clock that can lag `SystemTime` by a few milliseconds at a second boundary.
pub fn wait_past_second(second: u64) {
    loop {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        if now.as_secs() > second + 1 || (now.as_secs() == second + 1 && now.subsec_millis() >= 60)
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Waits until the current second is at least 60 ms old and has at least half a second left,
/// and returns it: work started now can finish inside this second, as netcode sees it.
pub fn settled_second() -> u64 {
    loop {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        if (60..=500).contains(&now.subsec_millis()) {
            return now.as_secs();
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

pub fn user_data(client_id: u64) -> [u8; USER_DATA_BYTES] {
    let mut data = [0u8; USER_DATA_BYTES];
    data[..8].copy_from_slice(&client_id.to_le_bytes());
    data[255] = 0xA5;
    data
}

/// The packet type netcode puts in the low nibble of a datagram's first byte (0: connection
/// request, 1: denied, 2: challenge, 3: response, 4: keep-alive, 5: payload, 6: disconnect).
pub fn packet_type(datagram: &[u8]) -> u8 {
    datagram.first().map_or(0xFF, |b| b & 0x0F)
}

/// Sits between one client and the server and records every datagram in both directions. The
/// client connects to the relay (the first address in its token); the server sees the relay's
/// address, and accepts because its own address is listed too.
pub struct Relay {
    socket: UdpSocket,
    server: SocketAddr,
    client: Option<SocketAddr>,
    /// Every datagram the client sent, in order.
    pub to_server: Vec<Vec<u8>>,
    /// Every datagram the server sent, in order.
    pub to_client: Vec<Vec<u8>>,
    /// Drop everything instead of forwarding it (still recorded).
    pub blocked: bool,
    /// Hold client datagrams of this packet type instead of forwarding them.
    pub hold: Option<u8>,
    pub held: Vec<Vec<u8>>,
}

impl Relay {
    pub fn new(server: SocketAddr) -> Self {
        let socket = UdpSocket::bind(localhost()).unwrap();
        socket.set_nonblocking(true).unwrap();
        Self {
            socket,
            server,
            client: None,
            to_server: Vec::new(),
            to_client: Vec::new(),
            blocked: false,
            hold: None,
            held: Vec::new(),
        }
    }

    pub fn address(&self) -> SocketAddr {
        self.socket.local_addr().unwrap()
    }

    pub fn pump(&mut self) {
        let mut buffer = [0u8; 2048];
        while let Ok((len, from)) = self.socket.recv_from(&mut buffer) {
            let datagram = buffer[..len].to_vec();
            if from == self.server {
                self.to_client.push(datagram.clone());
                if let (Some(client), false) = (self.client, self.blocked) {
                    let _ = self.socket.send_to(&datagram, client);
                }
            } else {
                self.client = Some(from);
                self.to_server.push(datagram.clone());
                if self.hold == Some(packet_type(&datagram)) {
                    self.held.push(datagram);
                } else if !self.blocked {
                    let _ = self.socket.send_to(&datagram, self.server);
                }
            }
        }
    }

    /// Sends the last held datagram on to the server, and forgets the rest.
    pub fn release_last_held(&mut self) {
        if let Some(datagram) = self.held.pop() {
            let _ = self.socket.send_to(&datagram, self.server);
        }
        self.held.clear();
        self.hold = None;
    }
}

/// A server, its clients and an optional relay, on the wall clock.
pub struct Net {
    pub key: Key,
    pub server: Server,
    pub max_clients: usize,
    /// The wall-clock second the server started in, or a later one.
    pub server_started: u64,
    pub relay: Option<Relay>,
    pub clients: Vec<Client>,
    pub started: Instant,
    pub server_events: Vec<ServerEvent<Vec<u8>>>,
    pub client_events: Vec<Vec<ClientEvent<Vec<u8>>>>,
}

pub fn server(key: &Key, address: SocketAddr, max_clients: usize, max_lifetime: u32) -> Server {
    Server::with_max_token_lifetime(
        ServerConfig {
            public_address: address,
            protocol_id: PROTOCOL,
            max_clients,
            transport: TransportConfig::default(),
        },
        key,
        test_schema(),
        0.0,
        max_lifetime,
    )
    .unwrap()
}

impl Net {
    pub fn new(max_clients: usize) -> Self {
        let key = dream_net::generate_key();
        Self::on(
            key,
            server(
                &key,
                localhost(),
                max_clients,
                dream_net::DEFAULT_MAX_CONNECT_TOKEN_LIFETIME,
            ),
            max_clients,
        )
    }

    pub fn on(key: Key, server: Server, max_clients: usize) -> Self {
        Self {
            key,
            server,
            max_clients,
            server_started: unix_second(),
            relay: None,
            clients: Vec::new(),
            started: Instant::now(),
            server_events: Vec::new(),
            client_events: Vec::new(),
        }
    }

    pub fn with_relay(mut self) -> Self {
        self.relay = Some(Relay::new(self.server.address()));
        self
    }

    pub fn time(&self) -> f64 {
        self.started.elapsed().as_secs_f64()
    }

    /// Replaces the server with a new one on the same key and address (a restart).
    pub fn restart(&mut self) {
        let address = self.server.address();
        // the old one goes first, so the new one can bind its port
        let placeholder = server(&self.key, localhost(), 1, 30);
        drop(std::mem::replace(&mut self.server, placeholder));
        self.server = server(
            &self.key,
            address,
            self.max_clients,
            dream_net::DEFAULT_MAX_CONNECT_TOKEN_LIFETIME,
        );
        self.server_started = unix_second();
    }

    /// A 30-second token (the server's default maximum), timeout 5 s, minted once the wall
    /// clock has left the server's start second, as a backend serving a running server mints
    /// it. Routed through the relay when there is one.
    pub fn token(&self, client_id: u64) -> Token {
        wait_past_second(self.server_started);
        self.token_with(client_id, 30, 5, self.relay.is_some())
    }

    /// A token minted now, without waiting for anything.
    pub fn token_with(
        &self,
        client_id: u64,
        lifetime: i32,
        timeout: i32,
        via_relay: bool,
    ) -> Token {
        let mut addresses = Vec::new();
        if via_relay {
            addresses.push(self.relay.as_ref().unwrap().address());
        }
        addresses.push(self.server.address());
        dream_net::generate_connect_token(
            &addresses,
            &addresses,
            lifetime,
            timeout,
            client_id,
            PROTOCOL,
            &self.key,
            &user_data(client_id),
        )
        .unwrap()
    }

    pub fn new_client(&mut self) -> usize {
        let client = Client::new(
            ClientConfig {
                bind_address: localhost(),
                transport: TransportConfig::default(),
            },
            test_schema(),
            self.time(),
        )
        .unwrap();
        self.clients.push(client);
        self.client_events.push(Vec::new());
        self.clients.len() - 1
    }

    pub fn add_client(&mut self, token: &Token) -> usize {
        let c = self.new_client();
        self.clients[c].connect(token).unwrap();
        c
    }

    pub fn pump_relay(&mut self) {
        if let Some(relay) = &mut self.relay {
            relay.pump();
        }
    }

    pub fn update_server(&mut self) {
        let time = self.time();
        self.server.update(time);
        while let Some(event) = self.server.poll() {
            self.server_events.push(owned_server(event));
        }
    }

    pub fn update_clients(&mut self) {
        let time = self.time();
        for (client, events) in self.clients.iter_mut().zip(&mut self.client_events) {
            client.update(time);
            while let Some(event) = client.poll() {
                events.push(owned_client(event));
            }
        }
    }

    pub fn flush(&mut self) {
        self.server.flush();
        for client in &mut self.clients {
            client.flush();
        }
    }

    pub fn step(&mut self) {
        self.update_server();
        self.pump_relay();
        self.update_clients();
        self.flush();
        self.pump_relay();
        std::thread::sleep(Duration::from_millis(1));
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

    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.server_events
            .iter()
            .filter_map(|e| match e {
                ServerEvent::Connected { peer, .. } => Some(*peer),
                _ => None,
            })
            .collect()
    }

    pub fn messages_from(&self, peer: PeerId) -> Vec<Vec<u8>> {
        self.server_events
            .iter()
            .filter_map(|e| match e {
                ServerEvent::Message {
                    peer: p, payload, ..
                } if *p == peer => Some(payload.clone()),
                _ => None,
            })
            .collect()
    }

    pub fn client_got(&self, c: usize, payload: &[u8]) -> bool {
        self.client_events[c].iter().any(
            |e| matches!(e, ClientEvent::Message { payload: p, .. } if p.as_slice() == payload),
        )
    }

    /// Connects a client with a fresh token and returns it with its peer handle.
    pub fn connect_one(&mut self, client_id: u64) -> (usize, PeerId) {
        let token = self.token(client_id);
        let c = self.add_client(&token);
        let before = self.connected_peers().len();
        assert!(
            self.run_until(|n| n.connected_peers().len() > before
                && n.clients[c].status() == ClientStatus::Connected),
            "client {client_id} never connected: {:?} {:?}",
            self.server_events,
            self.client_events[c]
        );
        (c, *self.connected_peers().last().unwrap())
    }

    pub fn ended(&self, c: usize) -> Option<ClientEvent<Vec<u8>>> {
        self.client_events[c]
            .iter()
            .find(|e| {
                matches!(
                    e,
                    ClientEvent::ConnectFailed { .. } | ClientEvent::Disconnected { .. }
                )
            })
            .cloned()
    }
}

pub fn owned_server(event: ServerEvent<&[u8]>) -> ServerEvent<Vec<u8>> {
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

pub fn owned_client(event: ClientEvent<&[u8]>) -> ClientEvent<Vec<u8>> {
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
