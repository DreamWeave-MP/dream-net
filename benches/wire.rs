//! The wire codec alone: encoding and zero-copy decoding of connection packets.

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

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use dream_net::wire::{Decoded, Layout, PacketWriter, decode};
use dream_net::{ChannelId, Seq16};

const SHAPES: [(usize, usize); 6] = [(1, 16), (8, 64), (64, 16), (64, 64), (16, 256), (4, 1024)];

fn event(size: usize, reliable: bool) -> dream_net::EventTypeId {
    if reliable {
        common::reliable(size)
    } else {
        common::unreliable(size)
    }
}

fn encode(
    layout: &Layout,
    buffer: &mut [u8],
    event: dream_net::EventTypeId,
    count: usize,
    size: usize,
    reliable: bool,
) -> usize {
    let payload = [0xA5u8; 1024];
    let channel = ChannelId(u8::from(!reliable));
    let mut w = PacketWriter::new(buffer);
    w.header(layout, None, 1);
    w.section(layout, channel, count as u32);
    for i in 0..count {
        if reliable {
            if i == 0 {
                w.first_id(Seq16(65000));
            } else {
                w.next_id(1 + (i as u32 % 3));
            }
        }
        w.message(layout, event, &payload[..size]);
    }
    w.finish()
}

fn wire(c: &mut Criterion) {
    let schema = common::schema();
    let layout = Layout::new(&schema);
    let mut buffer = vec![0u8; 80 * 1024];
    for reliable in [false, true] {
        let class = if reliable { "reliable" } else { "unreliable" };
        let mut group = c.benchmark_group(format!("wire/encode/{class}"));
        for (count, size) in SHAPES {
            group.throughput(Throughput::Elements(count as u64));
            group.bench_with_input(
                BenchmarkId::from_parameter(format!("{count}x{size}B")),
                &(count, size),
                |b, &(count, size)| {
                    let event = event(size, reliable);
                    b.iter(|| {
                        black_box(encode(&layout, &mut buffer, event, count, size, reliable))
                    });
                },
            );
        }
        group.finish();

        let mut group = c.benchmark_group(format!("wire/decode/{class}"));
        let mut decoded = Decoded::default();
        for (count, size) in SHAPES {
            let len = encode(
                &layout,
                &mut buffer,
                event(size, reliable),
                count,
                size,
                reliable,
            );
            let packet = buffer[..len].to_vec();
            group.throughput(Throughput::Elements(count as u64));
            group.bench_with_input(
                BenchmarkId::from_parameter(format!("{count}x{size}B")),
                &packet,
                |b, packet| {
                    b.iter(|| {
                        decode(&layout, black_box(packet), &mut decoded).unwrap();
                        black_box(decoded.messages.len())
                    });
                },
            );
        }
        group.finish();
    }
}

criterion_group!(benches, wire);
criterion_main!(benches);
