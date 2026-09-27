//! One connection pair: per-call costs and end-to-end throughput.
//!
//! - `send`: queueing one event (the copy into a channel slot).
//! - `pack`: turning queued events into datagrams (selection, framing, reliable headers).
//! - `direct`: a full frame on both ends with datagrams handed straight across: dream-net
//!   plus reliable, nothing else.
//! - `poll_into`: moving one received event out of the inbox into caller storage.
//! - `lossy`: CPU per delivered reliable event through the simulator at 0-20% loss,
//!   resends included.
//! - `fragmented`: 8 KiB reliable events that reliable must split and reassemble.

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
use std::time::{Duration, Instant};

use common::{Direct, SIZES, blob, reliable, shared, unreliable};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use dream_net::SendError;
use dream_net::sim::{LinkConfig, Pair};

const BATCH: usize = 256;

fn send(c: &mut Criterion) {
    let shared = shared();
    let payload = [7u8; 1024];
    let mut group = c.benchmark_group("connection/send");
    group.throughput(Throughput::Elements(1));
    for size in SIZES {
        for (class, event) in [
            ("unreliable", unreliable(size)),
            ("reliable", reliable(size)),
        ] {
            group.bench_function(BenchmarkId::new(class, format!("{size}B")), |b| {
                let mut pair = Direct::new(&shared);
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    let mut left = iters;
                    while left > 0 {
                        let n = left.min(BATCH as u64);
                        let start = Instant::now();
                        for _ in 0..n {
                            black_box(pair.b.send(event, black_box(&payload[..size]))).unwrap();
                        }
                        total += start.elapsed();
                        // drain the queue outside the timed region
                        pair.step();
                        while pair.a_inbox.pop().is_some() {}
                        left -= n;
                    }
                    total
                });
            });
        }
    }
    group.finish();
}

fn pack(c: &mut Criterion) {
    let shared = shared();
    let payload = [7u8; 1024];
    let mut group = c.benchmark_group("connection/pack");
    group.throughput(Throughput::Elements(BATCH as u64));
    for size in SIZES {
        for (class, event) in [
            ("unreliable", unreliable(size)),
            ("reliable", reliable(size)),
        ] {
            group.bench_function(BenchmarkId::new(class, format!("{BATCH}x{size}B")), |b| {
                let mut pair = Direct::new(&shared);
                // the timed flush copies its datagrams here; they are delivered untimed, so
                // the other end acks them and reliable windows stay open
                let mut bytes: Vec<u8> = Vec::with_capacity(1 << 20);
                let mut lens: Vec<usize> = Vec::with_capacity(1024);
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        for _ in 0..BATCH {
                            pair.b.send(event, &payload[..size]).unwrap();
                        }
                        bytes.clear();
                        lens.clear();
                        let start = Instant::now();
                        pair.b.write_packets(|d| {
                            bytes.extend_from_slice(d);
                            lens.push(d.len());
                        });
                        total += start.elapsed();
                        // deliver, routing the receiver's immediate acks back to the sender
                        let mut acks: Vec<Vec<u8>> = Vec::new();
                        let mut offset = 0;
                        for &len in &lens {
                            let d = &bytes[offset..offset + len];
                            pair.a
                                .receive(d, &mut pair.a_inbox, |ack| acks.push(ack.to_vec()));
                            offset += len;
                        }
                        for ack in &acks {
                            pair.b.receive(ack, &mut pair.b_inbox, |_| {});
                        }
                        pair.step();
                        while pair.a_inbox.pop().is_some() {}
                    }
                    total
                });
            });
        }
    }
    group.finish();
}

fn direct(c: &mut Criterion) {
    let shared = shared();
    let payload = [7u8; 1024];
    let mut group = c.benchmark_group("connection/direct");
    for size in SIZES {
        group.throughput(Throughput::Bytes((BATCH * size) as u64));
        for (class, event) in [
            ("unreliable", unreliable(size)),
            ("reliable", reliable(size)),
        ] {
            group.bench_function(BenchmarkId::new(class, format!("{BATCH}x{size}B")), |b| {
                let mut pair = Direct::new(&shared);
                let mut buffer = [0u8; 2048];
                b.iter(|| {
                    for _ in 0..BATCH {
                        pair.b.send(event, &payload[..size]).unwrap();
                    }
                    pair.step();
                    let mut n = 0;
                    while pair.a_inbox.pop_into(&mut buffer).unwrap().is_some() {
                        n += 1;
                    }
                    assert_eq!(n, BATCH);
                });
            });
        }
    }
    group.finish();
}

fn poll_into(c: &mut Criterion) {
    let shared = shared();
    let payload = [7u8; 1024];
    let mut group = c.benchmark_group("connection/poll_into");
    group.throughput(Throughput::Elements(1));
    for size in [16, 256, 1024] {
        let event = unreliable(size);
        group.bench_function(format!("{size}B"), |b| {
            let mut pair = Direct::new(&shared);
            let mut buffer = [0u8; 2048];
            b.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                let mut left = iters;
                while left > 0 {
                    let n = left.min(BATCH as u64);
                    for _ in 0..n {
                        pair.b.send(event, &payload[..size]).unwrap();
                    }
                    pair.step();
                    let start = Instant::now();
                    for _ in 0..n {
                        black_box(pair.a_inbox.pop_into(&mut buffer).unwrap());
                    }
                    total += start.elapsed();
                    left -= n;
                }
                total
            });
        });
    }
    group.finish();
}

fn lossy(c: &mut Criterion) {
    const EVENTS: u32 = 20_000;
    let shared = shared();
    let event = reliable(64);
    let payload = [7u8; 64];
    let mut group = c.benchmark_group("connection/lossy");
    group.sample_size(10);
    group.throughput(Throughput::Elements(u64::from(EVENTS)));
    for loss in [0.0, 0.01, 0.05, 0.2] {
        let link = LinkConfig {
            latency: 0.05,
            jitter: 0.01,
            loss,
            duplicate: 0.0,
            corrupt: 0.0,
        };
        let mut resends = 0u64;
        group.bench_function(format!("{}pct", (loss * 100.0) as u32), |b| {
            b.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                for seed in 0..iters {
                    let mut pair = Pair::symmetric(&shared, link, seed);
                    assert!(pair.handshake(1.0 / 60.0, 600));
                    let mut buffer = [0u8; 256];
                    let start = Instant::now();
                    let (mut sent, mut received) = (0, 0);
                    while received < EVENTS {
                        while sent < EVENTS {
                            match pair.b.send(event, &payload) {
                                Ok(()) => sent += 1,
                                Err(SendError::QueueFull(_)) => break,
                                Err(e) => panic!("{e}"),
                            }
                        }
                        pair.step(1.0 / 60.0);
                        while pair.a_inbox.pop_into(&mut buffer).unwrap().is_some() {
                            received += 1;
                        }
                    }
                    total += start.elapsed();
                    resends = pair.b.counters().events_resent;
                }
                total
            });
        });
        eprintln!(
            "  lossy {:>2}%: {resends} resends for {EVENTS} events ({:.1}% overhead)",
            (loss * 100.0) as u32,
            resends as f64 / f64::from(EVENTS) * 100.0
        );
    }
    group.finish();
}

fn fragmented(c: &mut Criterion) {
    let shared = shared();
    let event = blob();
    let payload = vec![7u8; 8192];
    let mut group = c.benchmark_group("connection/fragmented");
    group.throughput(Throughput::Bytes(16 * 8192));
    group.bench_function("16x8KiB", |b| {
        let mut pair = Direct::new(&shared);
        let mut buffer = vec![0u8; 8192];
        b.iter(|| {
            for _ in 0..16 {
                pair.b.send(event, &payload).unwrap();
            }
            pair.step();
            let mut n = 0;
            while pair.a_inbox.pop_into(&mut buffer).unwrap().is_some() {
                n += 1;
            }
            assert_eq!(n, 16);
        });
    });
    group.finish();
}

fn idle(c: &mut Criterion) {
    let mut group = c.benchmark_group("connection/idle");
    // reliable's own per-frame statistics pass, which dream-net cannot skip: it is also what
    // advances the endpoint's clock
    for history in [512usize, 128, 32] {
        group.bench_function(format!("reliable_update/history{history}"), |b| {
            let mut config = common::transport().reliable_config("bench");
            config.rtt_history_size = history;
            let mut endpoint = reliable::Endpoint::new(config, 0.0);
            let mut time = 0.0;
            b.iter(|| {
                time += 1.0 / 60.0;
                endpoint.update(black_box(time));
            });
        });
    }
    let shared = shared();
    group.bench_function("update", |b| {
        let mut pair = Direct::new(&shared);
        b.iter(|| {
            pair.time += 1.0 / 60.0;
            pair.a.update(pair.time);
        });
    });
    group.bench_function("frame_both_ends", |b| {
        let mut pair = Direct::new(&shared);
        b.iter(|| pair.step());
    });
    group.finish();
}

criterion_group!(
    benches, send, pack, direct, poll_into, lossy, fragmented, idle
);
criterion_main!(benches);
