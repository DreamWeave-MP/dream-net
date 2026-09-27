//! Real loopback UDP with netcode's encryption: dream-net against the naive alternative.
//!
//! Each frame every client sends `EVENTS` 64-byte events to the server, and the server sends
//! `EVENTS` 64-byte events back to every client. `dream-net` aggregates them into a few
//! reliable-framed datagrams per peer; `netcode_per_event` is the baseline that sends one
//! encrypted datagram per event with netcode alone (no acks, no ordering, no schema). The
//! difference is what aggregation buys: one AEAD seal and one syscall per packet instead of
//! per event.

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

use common::{transport, unreliable};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use dream_net::{Client, ClientConfig, ClientStatus, Server, ServerConfig, ServerEvent};

const EVENTS: usize = 32;
const PROTOCOL: u64 = 0xBE7C_4000;

fn localhost() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn token(
    address: SocketAddr,
    key: &dream_net::Key,
    id: u64,
) -> [u8; dream_net::CONNECT_TOKEN_BYTES] {
    dream_net::generate_connect_token(
        &[address],
        &[address],
        300,
        30,
        id,
        PROTOCOL,
        key,
        &[0; dream_net::USER_DATA_BYTES],
    )
    .unwrap()
}

struct DreamWorld {
    event: dream_net::EventTypeId,
    server: Server,
    clients: Vec<Client>,
    time: f64,
}

impl DreamWorld {
    fn new(n: usize) -> Self {
        let key = dream_net::generate_key();
        let server = Server::new(
            ServerConfig {
                public_address: localhost(),
                protocol_id: PROTOCOL,
                max_clients: n,
                transport: transport(),
            },
            &key,
            common::schema(),
            0.0,
        )
        .unwrap();
        let clients = (0..n)
            .map(|i| {
                let mut client = Client::new(
                    ClientConfig {
                        bind_address: localhost(),
                        transport: transport(),
                    },
                    common::schema(),
                    0.0,
                )
                .unwrap();
                client
                    .connect(&token(server.address(), &key, i as u64 + 1))
                    .unwrap();
                client
            })
            .collect();
        let mut world = Self {
            event: unreliable(64),
            server,
            clients,
            time: 0.0,
        };
        for _ in 0..2000 {
            world.frame(0);
            if world.server.num_connected() == n
                && world
                    .clients
                    .iter()
                    .all(|c| c.status() == ClientStatus::Connected)
            {
                return world;
            }
            std::thread::sleep(std::time::Duration::from_micros(200));
        }
        panic!("clients did not connect");
    }

    fn frame(&mut self, events: usize) -> usize {
        self.time += 1.0 / 60.0;
        let event = self.event;
        let payload = [3u8; 64];
        let mut buffer = [0u8; 2048];
        let mut received = 0;
        for client in &mut self.clients {
            client.update(self.time);
            while let Some(e) = client.poll_into(&mut buffer).unwrap() {
                received += usize::from(matches!(e, dream_net::ClientEvent::Message { .. }));
            }
            if client.status() == ClientStatus::Connected {
                for _ in 0..events {
                    client.send(event, &payload).unwrap();
                }
            }
            client.flush();
        }
        self.server.update(self.time);
        while let Some(e) = self.server.poll_into(&mut buffer).unwrap() {
            received += usize::from(matches!(e, ServerEvent::Message { .. }));
        }
        let peers: Vec<_> = self.server.peers().collect();
        for peer in peers {
            for _ in 0..events {
                self.server.send(peer, event, &payload).unwrap();
            }
        }
        self.server.flush();
        received
    }
}

struct RawWorld {
    server: netcode::Server,
    clients: Vec<netcode::Client>,
    time: f64,
}

impl RawWorld {
    fn new(n: usize) -> Self {
        let key = netcode::generate_key();
        let mut server = netcode::Server::new(localhost(), PROTOCOL, &key, 0.0).unwrap();
        server.start(n).unwrap();
        let clients = (0..n)
            .map(|i| {
                let mut client = netcode::Client::new(localhost(), 0.0).unwrap();
                client
                    .connect(&token(server.address(), &key, i as u64 + 1))
                    .unwrap();
                client
            })
            .collect();
        let mut world = Self {
            server,
            clients,
            time: 0.0,
        };
        for _ in 0..2000 {
            world.frame(0);
            if world.server.num_connected_clients() == n
                && world
                    .clients
                    .iter()
                    .all(|c| c.state() == netcode::ClientState::Connected)
            {
                return world;
            }
            std::thread::sleep(std::time::Duration::from_micros(200));
        }
        panic!("clients did not connect");
    }

    fn frame(&mut self, events: usize) -> usize {
        self.time += 1.0 / 60.0;
        let payload = [3u8; 66]; // dream-net's 64 bytes plus its ~2 bytes of framing
        let mut received = 0;
        for client in &mut self.clients {
            client.update(self.time);
            while client.receive_packet().is_some() {
                received += 1;
            }
            for _ in 0..events {
                client.send_packet(&payload).unwrap();
            }
        }
        self.server.update(self.time);
        while self.server.next_event().is_some() {}
        for slot in 0..self.server.max_clients() {
            while self.server.receive_packet(slot).is_some() {
                received += 1;
            }
            for _ in 0..events {
                self.server.send_packet(slot, &payload).unwrap();
            }
        }
        received
    }
}

fn loopback(c: &mut Criterion) {
    let mut group = c.benchmark_group("netcode/frame");
    for clients in [1, 8, 32] {
        // events per frame: EVENTS up and EVENTS down per client
        group.throughput(Throughput::Elements((clients * EVENTS * 2) as u64));
        group.bench_with_input(BenchmarkId::new("dream-net", clients), &clients, |b, &n| {
            let mut world = DreamWorld::new(n);
            b.iter(|| world.frame(EVENTS));
        });
        group.bench_with_input(
            BenchmarkId::new("netcode_per_event", clients),
            &clients,
            |b, &n| {
                let mut world = RawWorld::new(n);
                b.iter(|| world.frame(EVENTS));
            },
        );
    }
    group.finish();
}

criterion_group!(benches, loopback);
criterion_main!(benches);
