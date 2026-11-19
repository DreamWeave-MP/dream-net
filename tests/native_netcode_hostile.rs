//! Hostile datagrams against a live server and a live client: random, truncated, oversized,
//! zero-length and replayed captured packets must never crash anything, connect anybody,
//! deliver anything twice, or stall a legitimate handshake (audit S3).

// CI passes -W clippy::pedantic on the command line, overriding the manifest's lint table;
// test code casts freely between widths it controls.
#![allow(clippy::cast_possible_truncation, clippy::too_many_lines)]

mod native_netcode_support;

use std::net::{SocketAddr, UdpSocket};

use dream_net::native::netcode::{
    Client, ClientState, Server, ServerEvent, generate_connect_token, generate_key,
};
use native_netcode_support::{
    DT, LONG_LIFETIME, PROTOCOL, World, await_loopback, localhost, pace, user_data_for, wait_until,
};

/// xorshift64*: deterministic noise.
struct Noise(u64);

impl Noise {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next() as u8).collect()
    }
}

fn socket() -> UdpSocket {
    let socket = UdpSocket::bind(localhost()).unwrap();
    socket.set_nonblocking(true).unwrap();
    socket
}

/// A UDP relay that records every datagram: the client talks to `front`, the server hears it
/// from `back`.
struct Relay {
    front: UdpSocket,
    back: UdpSocket,
    server: SocketAddr,
    client: Option<SocketAddr>,
    to_server: Vec<Vec<u8>>,
    to_client: Vec<Vec<u8>>,
}

impl Relay {
    fn new(server: SocketAddr) -> Self {
        Self {
            front: socket(),
            back: socket(),
            server,
            client: None,
            to_server: Vec::new(),
            to_client: Vec::new(),
        }
    }

    fn front_address(&self) -> SocketAddr {
        self.front.local_addr().unwrap()
    }

    fn pump(&mut self) {
        let mut buffer = [0u8; 2048];
        while let Ok((n, from)) = self.front.recv_from(&mut buffer) {
            self.client = Some(from);
            self.to_server.push(buffer[..n].to_vec());
            self.back.send_to(&buffer[..n], self.server).unwrap();
        }
        while let Ok((n, _)) = self.back.recv_from(&mut buffer) {
            self.to_client.push(buffer[..n].to_vec());
            if let Some(client) = self.client {
                self.front.send_to(&buffer[..n], client).unwrap();
            }
        }
    }
}

/// Everything hostile, generated from `noise` and the `captured` datagrams.
fn hostile_set(noise: &mut Noise, captured: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut set = Vec::new();
    for _ in 0..300 {
        set.push(Vec::new());
    }
    for len in [1usize, 2, 8, 17, 18, 64, 300, 1078, 1199, 1200, 1300, 1500] {
        for _ in 0..4 {
            set.push(noise.bytes(len));
        }
    }
    // every prefix byte at a few lengths
    for prefix in 0..=255u8 {
        for len in [1usize, 9, 30, 1078] {
            let mut d = noise.bytes(len);
            d[0] = prefix;
            set.push(d);
        }
    }
    for d in captured {
        // verbatim, every truncation, padded, and with one bit flipped
        set.push(d.clone());
        for cut in (1..d.len()).step_by(7) {
            set.push(d[..cut].to_vec());
        }
        let mut padded = d.clone();
        padded.extend(noise.bytes(64));
        set.push(padded);
        let mut flipped = d.clone();
        let at = (noise.next() as usize) % flipped.len();
        flipped[at] ^= 1 << (noise.next() % 8);
        set.push(flipped);
    }
    // oversized: larger than netcode's 1300-byte read buffer
    for _ in 0..8 {
        set.push(noise.bytes(4000));
    }
    set
}

/// Sends `set` from `from` to `to`, a little at a time so the kernel queue keeps most of it.
fn spray(from: &UdpSocket, to: SocketAddr, set: &[Vec<u8>], mut between: impl FnMut()) {
    for chunk in set.chunks(64) {
        for d in chunk {
            let _ = from.send_to(d, to);
        }
        between();
    }
}

fn step(
    client: &mut Client,
    server: &mut Server,
    relay: &mut Relay,
    time: &mut f64,
    events: &mut Vec<ServerEvent>,
) {
    *time += DT;
    client.update(*time);
    relay.pump();
    server.update(*time);
    relay.pump();
    while let Some(e) = server.next_event() {
        events.push(e);
    }
    pace();
}

#[test]
fn hostile_and_replayed_datagrams_admit_nobody_and_disturb_nothing() {
    let key = generate_key();
    let mut server = Server::new(localhost(), PROTOCOL, &key, 0.0).unwrap();
    server.start(4).unwrap();
    let mut relay = Relay::new(server.address());
    // the client reaches the relay (public address); the server checks its own (internal)
    let token = generate_connect_token(
        &[relay.front_address()],
        &[server.address()],
        LONG_LIFETIME,
        5,
        42,
        PROTOCOL,
        &key,
        &user_data_for(42),
    )
    .unwrap();
    let mut client = Client::new(localhost(), 0.0).unwrap();
    client.connect(&token).unwrap();
    let mut time = 0.0;
    let mut events = Vec::new();
    for _ in 0..200 {
        step(&mut client, &mut server, &mut relay, &mut time, &mut events);
        if client.state() == ClientState::Connected {
            break;
        }
    }
    assert_eq!(client.state(), ClientState::Connected);
    for i in 0..5u8 {
        client.send_packet(&[i; 40]).unwrap();
        server.send_packet(0, &[!i; 40]).unwrap();
        step(&mut client, &mut server, &mut relay, &mut time, &mut events);
    }
    // let the last payloads land, then take every legitimate one
    for _ in 0..3 {
        step(&mut client, &mut server, &mut relay, &mut time, &mut events);
    }
    let mut legit = 0;
    while server.receive_packet(0).is_some() {
        legit += 1;
    }
    while client.receive_packet().is_some() {
        legit += 1;
    }
    assert_eq!(legit, 10);
    let captured_to_server = relay.to_server.clone();
    let captured_to_client = relay.to_client.clone();
    assert!(captured_to_server.len() > 5 && captured_to_client.len() > 5);

    let mut noise = Noise(0x9E37_79B9_7F4A_7C15);
    let stranger = socket();
    // at the server, from a stranger and from the session's own (relay) address
    let at_server = hostile_set(&mut noise, &captured_to_server);
    let server_address = server.address();
    spray(&stranger, server_address, &at_server, || {
        step(&mut client, &mut server, &mut relay, &mut time, &mut events);
    });
    let relay_back = relay.back.try_clone().unwrap();
    let relay_front = relay.front.try_clone().unwrap();
    spray(&relay_back, server_address, &at_server, || {
        step(&mut client, &mut server, &mut relay, &mut time, &mut events);
    });
    // at the client, from a stranger and from the address it expects the server at
    let at_client = hostile_set(&mut noise, &captured_to_client);
    let client_address: SocketAddr = format!("127.0.0.1:{}", client.port()).parse().unwrap();
    spray(&stranger, client_address, &at_client, || {
        step(&mut client, &mut server, &mut relay, &mut time, &mut events);
    });
    spray(&relay_front, client_address, &at_client, || {
        step(&mut client, &mut server, &mut relay, &mut time, &mut events);
    });

    // let the last of the spray land (macOS and Windows deliver loopback a moment after sendto),
    // so the checks below see all of it
    await_loopback();
    step(&mut client, &mut server, &mut relay, &mut time, &mut events);
    await_loopback();
    step(&mut client, &mut server, &mut relay, &mut time, &mut events);

    // nothing replayed or forged was delivered, nobody else connected, the session survived
    assert_eq!(client.state(), ClientState::Connected);
    assert_eq!(server.num_connected_clients(), 1);
    assert_eq!(
        events,
        vec![ServerEvent::ClientConnected { client_index: 0 }]
    );
    let mut stray = 0;
    while server.receive_packet(0).is_some() {
        stray += 1;
    }
    while client.receive_packet().is_some() {
        stray += 1;
    }
    assert_eq!(stray, 0, "a replayed or forged payload was delivered");
    client.send_packet(b"still here").unwrap();
    server.send_packet(0, b"and here").unwrap();
    let (mut at_server, mut at_client) = (None, None);
    wait_until("the session's own payloads cross the relay", || {
        step(&mut client, &mut server, &mut relay, &mut time, &mut events);
        at_server = at_server
            .take()
            .or_else(|| server.receive_packet(0).map(|p| p.0));
        at_client = at_client
            .take()
            .or_else(|| client.receive_packet().map(|p| p.0));
        at_server.is_some() && at_client.is_some()
    });
    assert_eq!(at_server.unwrap(), b"still here");
    assert_eq!(at_client.unwrap(), b"and here");

    // after the session ends, replaying its whole capture from its own address and from a
    // stranger reconnects nobody: the token was consumed
    client.disconnect();
    drop(client);
    for _ in 0..3 {
        await_loopback();
        relay.pump();
        await_loopback();
        time += DT;
        server.update(time);
    }
    assert_eq!(server.num_connected_clients(), 0);
    for from in [&relay_back, &stranger] {
        for _ in 0..3 {
            for d in &captured_to_server {
                let _ = from.send_to(d, server.address());
            }
            time += DT;
            server.update(time);
        }
    }
    await_loopback();
    time += DT;
    server.update(time);
    while let Some(e) = server.next_event() {
        events.push(e);
    }
    assert_eq!(
        events,
        vec![
            ServerEvent::ClientConnected { client_index: 0 },
            ServerEvent::ClientDisconnected {
                client_index: 0,
                reason: dream_net::native::netcode::DisconnectReason::ClientDisconnect
            }
        ]
    );
    assert_eq!(server.num_connected_clients(), 0);
}

#[test]
fn a_flood_of_empty_datagrams_does_not_stall_a_handshake() {
    let mut world = World::new(2);
    let flooder = socket();
    let server = world.server.address();
    let c = world.add_client(1);
    let client = SocketAddr::new(server.ip(), world.clients[c].port());
    let mut steps = 0;
    // 200 empty datagrams at each side before every step. netcode-official 1.0.0 ended its
    // receive loop at each one, so it needed one update per empty datagram; C 1.4.10 skips them.
    while world.clients[c].state() != ClientState::Connected {
        for _ in 0..200 {
            let _ = flooder.send_to(&[], server);
            let _ = flooder.send_to(&[], client);
        }
        world.step();
        steps += 1;
        assert!(steps < 30, "the handshake stalled: {steps} steps");
    }
    world.clients[c].send_packet(b"through").unwrap();
    for _ in 0..200 {
        let _ = flooder.send_to(&[], server);
    }
    world.step();
    assert_eq!(world.server.receive_packet(0).unwrap().0, b"through");
}
