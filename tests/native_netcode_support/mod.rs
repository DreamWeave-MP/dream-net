//! Shared helpers for the netcode binding's loopback tests.
//!
//! Time is simulated: every step advances the caller's clock by [`DT`] and updates the peers.
//! Only the wall clock (token timestamps and the server's start floor) is real.
//!
//! Linux delivers loopback UDP into the receiving socket's queue during `sendto`; macOS and
//! Windows deliver it a moment later. So every step ends with [`pace`], a short real pause that
//! lets what it sent land before the next step reads, and a test that needs every datagram
//! already sent to be waiting in its socket calls [`await_loopback`] or [`wait_until`] first.
//! Without the pause a pump could spend its 30 simulated seconds before the first datagram of a
//! handshake arrived. The suite is checked with loopback delayed by 200 µs (`tc netem`).

#![allow(dead_code)] // each test root uses part of this module

use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dream_net::native::netcode::{
    CONNECT_TOKEN_BYTES, Client, ClientState, Key, Server, ServerEvent, USER_DATA_BYTES, UserData,
    generate_connect_token,
};

pub const PROTOCOL: u64 = 0x1122_3344_5566_7788;
/// Simulated seconds per step.
pub const DT: f64 = 0.01;
/// Steps after which a pump gives up: 30 simulated seconds.
pub const MAX_STEPS: usize = 3000;
/// A token lifetime far above any test server's maximum, so tokens minted right after a
/// server's start pass its start floor.
pub const LONG_LIFETIME: i32 = 3600;

/// The real pause at the end of every simulated step: well above loopback's delivery delay on
/// any platform, and short enough that a full [`MAX_STEPS`] pump takes under two seconds.
pub fn pace() {
    std::thread::sleep(Duration::from_micros(500));
}

pub fn localhost() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

pub fn localhost_v6() -> SocketAddr {
    "[::1]:0".parse().unwrap()
}

/// Whether this host can bind `::1`; prints why not when it cannot.
pub fn ipv6_available() -> bool {
    match UdpSocket::bind("[::1]:0") {
        Ok(_) => true,
        Err(e) => {
            println!("SKIPPED: this host cannot bind [::1] ({e})");
            false
        }
    }
}

#[allow(clippy::cast_possible_truncation)] // deliberate byte truncation
pub fn user_data_for(client_id: u64) -> UserData {
    let mut data = [0u8; USER_DATA_BYTES];
    data[..8].copy_from_slice(&client_id.to_le_bytes());
    for (i, b) in data.iter_mut().enumerate().skip(8) {
        *b = (i as u8) ^ (client_id as u8);
    }
    data
}

pub fn token_with(
    address: SocketAddr,
    key: &Key,
    client_id: u64,
    expire_seconds: i32,
    timeout_seconds: i32,
) -> [u8; CONNECT_TOKEN_BYTES] {
    generate_connect_token(
        &[address],
        &[address],
        expire_seconds,
        timeout_seconds,
        client_id,
        PROTOCOL,
        key,
        &user_data_for(client_id),
    )
    .unwrap()
}

/// A token for `server` with a long lifetime and a 5 s timeout.
pub fn token(server: &Server, key: &Key, client_id: u64) -> [u8; CONNECT_TOKEN_BYTES] {
    token_with(server.address(), key, client_id, LONG_LIFETIME, 5)
}

/// The connection request a netcode client sends for `token`, byte for byte: everything the
/// server sees of an attempt until it answers. The token's public layout is the version (13
/// bytes), protocol id, create and expire timestamps, the nonce (24 bytes) and the encrypted
/// private part (1024 bytes); the request is a zero prefix byte and all of them but the create
/// timestamp. (`tests/lifecycle/mod.rs` has the same for dream-net's own tests.)
pub fn connection_request(token: &[u8; CONNECT_TOKEN_BYTES]) -> Vec<u8> {
    let mut request = vec![0u8];
    request.extend_from_slice(&token[0..21]);
    request.extend_from_slice(&token[29..1085]);
    assert_eq!(request.len(), 1078);
    request
}

/// Presents `token` again exactly as a second client would until a server answers it: its
/// connection request, from a raw socket bound to `bind`, ten times a second for the token's
/// timeout (`timeout_seconds`) to `server`, which is updated meanwhile, its clock advancing
/// with the wall clock from `time`.
/// A process refuses to pass a used token to `Client::connect` again, so this is how the
/// server's own refusal is tested; `bind` can be the released address of a client of this
/// process, to present it from the same socket address. Returns every datagram the socket
/// received: what the server answered.
pub fn present_raw(
    server: &mut Server,
    time: &mut f64,
    token: &[u8; CONNECT_TOKEN_BYTES],
    timeout_seconds: u64,
    bind: SocketAddr,
) -> Vec<Vec<u8>> {
    let socket = UdpSocket::bind(bind).unwrap();
    socket.set_nonblocking(true).unwrap();
    let request = connection_request(token);
    let to = server.address();
    let started = std::time::Instant::now();
    let base = *time;
    let until = started + Duration::from_secs(timeout_seconds);
    let mut next_send = std::time::Instant::now();
    let mut answers = Vec::new();
    let mut buffer = [0u8; 2048];
    while std::time::Instant::now() < until {
        if std::time::Instant::now() >= next_send {
            socket.send_to(&request, to).unwrap();
            next_send += Duration::from_millis(100);
        }
        *time = base + started.elapsed().as_secs_f64();
        server.update(*time);
        while let Ok((len, _)) = socket.recv_from(&mut buffer) {
            answers.push(buffer[..len].to_vec());
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    answers
}

/// Waits long enough for every datagram already sent over loopback to reach its socket. A no-op
/// in effect on Linux; macOS and Windows hand datagrams over shortly after `sendto` returns.
pub fn await_loopback() {
    std::thread::sleep(Duration::from_millis(50));
}

/// Calls `poll` until it returns true, without advancing anyone's simulated clock, for at most
/// five seconds of wall time: for a step that must see a datagram just sent over loopback.
pub fn wait_until(what: &str, mut poll: impl FnMut() -> bool) {
    let until = std::time::Instant::now() + Duration::from_secs(5);
    while !poll() {
        assert!(
            std::time::Instant::now() < until,
            "{what}: not reached within 5 s"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

pub fn wall_second() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// How far from a second boundary the wall-clock tests stay. C reads the wall clock with
/// `time(NULL)`, which glibc serves from the coarse realtime clock: near a boundary it can
/// still report the previous second for a few milliseconds after `SystemTime` has moved on.
pub const BOUNDARY_MARGIN: Duration = Duration::from_millis(60);

fn subsecond() -> Duration {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    Duration::from_nanos(u64::from(now.subsec_nanos()))
}

/// Sleeps until the wall clock's whole second changes, plus [`BOUNDARY_MARGIN`] (at most a
/// little over one second).
pub fn wait_for_next_second() {
    let start = wall_second();
    while wall_second() == start {
        std::thread::sleep(Duration::from_millis(5));
    }
    std::thread::sleep(BOUNDARY_MARGIN);
}

/// Sleeps, if needed, until the current second has at least half a second left and is at
/// least [`BOUNDARY_MARGIN`] old, and returns it.
pub fn settled_second() -> u64 {
    loop {
        let sub = subsecond();
        if sub >= BOUNDARY_MARGIN && sub <= Duration::from_millis(500) {
            return wall_second();
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// A server and its clients on one simulated clock.
pub struct World {
    pub key: Key,
    pub server: Server,
    pub clients: Vec<Client>,
    pub time: f64,
    pub events: Vec<ServerEvent>,
}

impl World {
    pub fn new(max_clients: usize) -> Self {
        Self::on(localhost(), max_clients)
    }

    pub fn on(address: SocketAddr, max_clients: usize) -> Self {
        let key = dream_net::native::netcode::generate_key();
        let mut server = Server::new(address, PROTOCOL, &key, 0.0).unwrap();
        server.start(max_clients).unwrap();
        Self {
            key,
            server,
            clients: Vec::new(),
            time: 0.0,
            events: Vec::new(),
        }
    }

    /// Adds a client bound like the server's address family, connecting with a fresh token.
    pub fn add_client(&mut self, client_id: u64) -> usize {
        let bind = if self.server.address().is_ipv4() {
            localhost()
        } else {
            localhost_v6()
        };
        let mut client = Client::new(bind, self.time).unwrap();
        let token = token(&self.server, &self.key, client_id);
        client.connect(&token).unwrap();
        self.clients.push(client);
        self.clients.len() - 1
    }

    /// One step: every client, then the server, then drain the server's events.
    pub fn step(&mut self) {
        self.time += DT;
        for client in &mut self.clients {
            client.update(self.time);
        }
        self.server.update(self.time);
        self.drain();
        pace();
    }

    pub fn drain(&mut self) {
        while let Some(event) = self.server.next_event() {
            self.events.push(event);
        }
    }

    /// Steps until `done` holds; panics after [`MAX_STEPS`].
    pub fn pump_until(&mut self, what: &str, mut done: impl FnMut(&World) -> bool) {
        for _ in 0..MAX_STEPS {
            if done(self) {
                return;
            }
            self.step();
        }
        panic!(
            "{what}: not reached after {MAX_STEPS} steps; client states {:?}, events {:?}",
            self.clients.iter().map(Client::state).collect::<Vec<_>>(),
            self.events
        );
    }

    /// Steps until client `index` leaves the connecting states, and returns its state.
    pub fn settle(&mut self, index: usize) -> ClientState {
        self.pump_until("client settles", |w| {
            !w.clients[index].state().is_connecting()
        });
        self.clients[index].state()
    }

    pub fn connect_all(&mut self) {
        self.pump_until("all clients connected", |w| {
            w.clients
                .iter()
                .all(|c| c.state() == ClientState::Connected)
                && w.server.num_connected_clients() == w.clients.len()
        });
        self.drain();
    }

    /// The events since the last call.
    pub fn take_events(&mut self) -> Vec<ServerEvent> {
        self.drain();
        std::mem::take(&mut self.events)
    }
}
