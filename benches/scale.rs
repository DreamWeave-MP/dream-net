//! One host driving many peers: the server-side frame cost as the peer count grows.
//!
//! Every frame each client sends a 16-byte reliable event and a 64-byte unreliable one, and
//! the server sends each client the same plus a 64-byte broadcast-style state event per
//! frame. Datagrams move directly between connections (no sockets), so this is the cost of
//! dream-net's own per-peer work: update, decode, deliver, poll, queue, pack, and reliable.

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

use std::hint::black_box;

use common::{reliable, shared, unreliable};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use dream_net::{Connection, Inbox, PeerId};

struct Host {
    r16: dream_net::EventTypeId,
    u64: dream_net::EventTypeId,
    server: Vec<Connection>,
    server_inbox: Inbox<()>,
    clients: Vec<(Connection, Inbox<()>)>,
    time: f64,
}

impl Host {
    fn new(peers: usize) -> Self {
        let shared = shared();
        let mut server_inbox = Inbox::new(peers);
        let mut server = Vec::new();
        let mut clients = Vec::new();
        for slot in 0..peers {
            let peer = PeerId::new(slot as u16, 1);
            server_inbox.open_slot(peer);
            server.push(Connection::new(shared.clone(), peer, 0.0));
            let mut inbox = Inbox::new(1);
            let client_peer = PeerId::new(0, 1);
            inbox.open_slot(client_peer);
            clients.push((Connection::new(shared.clone(), client_peer, 0.0), inbox));
        }
        let mut host = Self {
            r16: reliable(16),
            u64: unreliable(64),
            server,
            server_inbox,
            clients,
            time: 0.0,
        };
        for _ in 0..8 {
            host.frame(false);
        }
        host
    }

    fn frame(&mut self, traffic: bool) -> usize {
        self.time += 1.0 / 60.0;
        let time = self.time;
        let (r16, u64_) = (self.r16, self.u64);
        let small = [1u8; 16];
        let state = [2u8; 64];
        let mut buffer = [0u8; 2048];
        let mut delivered = 0;

        // clients: send, then flush into their server-side connection
        for ((client, inbox), server) in self.clients.iter_mut().zip(&mut self.server) {
            inbox.compact();
            client.update(time);
            if traffic {
                client.send(r16, &small).unwrap();
                client.send(u64_, &state).unwrap();
            }
            let server_inbox = &mut self.server_inbox;
            client.write_packets(|d| server.receive(d, server_inbox, |_| {}));
            while inbox.pop_into(&mut buffer).unwrap().is_some() {
                delivered += 1;
            }
        }

        // server: update, poll everything, send to everyone, flush
        self.server_inbox.compact();
        for connection in &mut self.server {
            connection.update(time);
        }
        while self.server_inbox.pop_into(&mut buffer).unwrap().is_some() {
            delivered += 1;
        }
        for (connection, (client, inbox)) in self.server.iter_mut().zip(&mut self.clients) {
            if traffic {
                connection.send(r16, &small).unwrap();
                connection.send(u64_, &state).unwrap();
                connection.send(u64_, &state).unwrap();
            }
            connection.write_packets(|d| client.receive(d, inbox, |_| {}));
        }
        delivered
    }
}

fn scale(c: &mut Criterion) {
    let mut group = c.benchmark_group("scale/frame");
    for peers in [1, 16, 64, 256] {
        // events per frame: 2 per client up, 3 per client down
        group.throughput(Throughput::Elements(peers as u64 * 5));
        group.bench_with_input(BenchmarkId::from_parameter(peers), &peers, |b, &peers| {
            let mut host = Host::new(peers);
            b.iter(|| black_box(host.frame(true)));
        });
    }
    group.finish();

    let mut group = c.benchmark_group("scale/idle_frame");
    for peers in [64, 256] {
        group.throughput(Throughput::Elements(peers as u64));
        group.bench_with_input(BenchmarkId::from_parameter(peers), &peers, |b, &peers| {
            let mut host = Host::new(peers);
            b.iter(|| black_box(host.frame(false)));
        });
    }
    group.finish();
}

/// The inbox when a host polls only part of it each frame: compaction then moves the
/// unpolled payload bytes down (a memmove proportional to what is still queued).
fn partial_poll(c: &mut Criterion) {
    use dream_net::EventTypeId;
    let mut group = c.benchmark_group("scale/inbox_partial_poll");
    let peers = 64;
    let payload = [5u8; 256];
    for keep in [0usize, 256, 4096] {
        group.throughput(Throughput::Elements(peers as u64 * 8));
        group.bench_with_input(BenchmarkId::new("left_queued", keep), &keep, |b, &keep| {
            let mut host = Host::new(peers);
            let event: EventTypeId = unreliable(256);
            let mut buffer = [0u8; 2048];
            b.iter(|| {
                host.time += 1.0 / 60.0;
                for ((client, _), server) in host.clients.iter_mut().zip(&mut host.server) {
                    for _ in 0..8 {
                        client.send(event, &payload).unwrap();
                    }
                    let inbox = &mut host.server_inbox;
                    client.write_packets(|d| server.receive(d, inbox, |_| {}));
                }
                host.server_inbox.compact();
                // poll all but `keep` events
                while host.server_inbox.len() > keep {
                    black_box(host.server_inbox.pop_into(&mut buffer).unwrap());
                }
            });
        });
    }
    group.finish();
}

criterion_group!(benches, scale, partial_poll);
criterion_main!(benches);
