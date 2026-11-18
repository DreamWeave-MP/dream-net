//! The safe reliable binding end to end: acks, fragmentation at every boundary, a lossy,
//! reordering, duplicating link, the 16-bit sequence wrap on both sides, statistics, reset,
//! closure panics, empty and oversized input, `Debug`, drop and auto traits.

// CI passes -W clippy::pedantic on the command line, overriding the manifest's lint table;
// test code casts freely between widths it controls.
#![allow(
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::too_many_lines
)]

mod native_reliable_support;

use std::collections::{BTreeMap, BTreeSet};
use std::panic::{AssertUnwindSafe, RefUnwindSafe, UnwindSafe, catch_unwind};

use dream_net::native::reliable::{
    Bandwidth, Config, Counters, Endpoint, FRAGMENT_HEADER_BYTES, MAX_PACKET_HEADER_BYTES,
    sequence_greater_than, sequence_less_than,
};
use native_reliable_support::{Link, Rng, dream_net_config, payload};

const DT: f64 = 1.0 / 60.0;

fn endpoint(config: Config) -> Endpoint {
    Endpoint::new(config, 0.0).expect("valid config")
}

/// Checked when this compiles: dream-net's `Connection` keeps these traits (shared decision 16).
#[test]
fn auto_traits() {
    fn check<T: Send + Sync + Unpin + UnwindSafe + RefUnwindSafe>() {}
    fn send_sync<T: Send + Sync>() {}
    check::<Endpoint>();
    check::<Config>();
    check::<Counters>();
    check::<dream_net::native::reliable::ConfigError>();
    check::<dream_net::native::reliable::Bandwidth>();
    // like `vec::Drain`, which the port returned
    send_sync::<dream_net::native::reliable::DrainAcks<'static>>();
}

#[test]
fn constants_match_the_rust_port() {
    assert_eq!(MAX_PACKET_HEADER_BYTES, 9);
    assert_eq!(FRAGMENT_HEADER_BYTES, 5);
    let d = Config::default();
    assert_eq!(
        (
            d.name.as_str(),
            d.max_packet_size,
            d.fragment_above,
            d.max_fragments,
            d.fragment_size,
            d.ack_buffer_size,
            d.sent_packets_buffer_size,
            d.received_packets_buffer_size,
            d.fragment_reassembly_buffer_size,
            d.rtt_history_size,
            d.packet_header_size
        ),
        (
            "endpoint", 16384, 1024, 16, 1024, 256, 256, 256, 64, 512, 28
        )
    );
    assert_eq!(
        (
            d.rtt_smoothing_factor,
            d.packet_loss_smoothing_factor,
            d.bandwidth_smoothing_factor
        ),
        (0.0025, 0.1, 0.1)
    );
    assert_eq!(d.validate(), Ok(()));
}

/// Against an independent statement of the C's half-space rule: `s1` is ahead of `s2` by
/// 1..=32767 steps, or by exactly 32768 when `s1` is also numerically larger (the tie is broken
/// by value, so exactly one of a pair 32768 apart is "greater"). Every `s1` against a set of
/// steps that covers each edge, and a million random pairs.
#[test]
fn sequence_comparison_is_half_space_and_wrap_correct() {
    let definition = |s1: u16, s2: u16| {
        let step = s1.wrapping_sub(s2);
        (1..32768).contains(&step) || (step == 32768 && s1 > s2)
    };
    let check = |s1: u16, s2: u16| {
        assert_eq!(
            sequence_greater_than(s1, s2),
            definition(s1, s2),
            "{s1} {s2}"
        );
        assert_eq!(sequence_less_than(s1, s2), definition(s2, s1), "{s1} {s2}");
        assert!(!(sequence_greater_than(s1, s2) && sequence_less_than(s1, s2)));
        assert_eq!(
            sequence_greater_than(s1, s2) || sequence_less_than(s1, s2),
            s1 != s2,
            "{s1} {s2}"
        );
    };
    for s1 in 0..=u16::MAX {
        for step in [0u16, 1, 2, 100, 32767, 32768, 32769, 65534, 65535] {
            check(s1, s1.wrapping_sub(step));
        }
    }
    let mut rng = Rng::new(7);
    for _ in 0..1_000_000 {
        check(rng.next_u64() as u16, rng.next_u64() as u16);
    }
}

/// The upstream `test_acks` scenario: both directions ack every packet.
#[test]
fn acks_round_trip() {
    let mut time = 100.0;
    let mut sender = Endpoint::new(Config::default(), time).unwrap();
    let mut receiver = Endpoint::new(Config::default(), time).unwrap();
    let mut sender_acked = BTreeSet::new();
    let mut receiver_acked = BTreeSet::new();
    for _ in 0..256 {
        sender.send_packet(&[0u8; 8], |_, data| {
            receiver.receive_packet(data, |_, _| true);
        });
        receiver.send_packet(&[0u8; 8], |_, data| {
            sender.receive_packet(data, |_, _| true);
        });
        sender_acked.extend(sender.drain_acks());
        receiver_acked.extend(receiver.drain_acks());
        sender.update(time);
        receiver.update(time);
        time += 0.01;
    }
    // each of the sender's packets is acked by the reply to it; each of the receiver's by the
    // sender's next packet, so all but its last
    assert_eq!(sender_acked, (0..256).collect());
    assert_eq!(receiver_acked, (0..255).collect());
    assert_eq!(sender.acks(), [0u16; 0]);
    assert_eq!(sender.counters().num_packets_acked, 256);
    assert_eq!(sender.counters().num_packets_sent, 256);
    assert_eq!(receiver.counters().num_packets_received, 256);
}

#[test]
fn acks_and_clear_acks_without_drain() {
    let mut a = endpoint(Config::default());
    let mut b = endpoint(Config::default());
    for _ in 0..4 {
        a.send_packet(&[1, 2, 3], |_, d| b.receive_packet(d, |_, _| true));
    }
    b.send_packet(&[9], |_, d| a.receive_packet(d, |_, _| true));
    // C records the acks of one header newest first
    assert_eq!(a.acks(), &[3, 2, 1, 0]);
    // a partly consumed drain still clears everything
    let mut drain = a.drain_acks();
    assert_eq!(drain.len(), 4);
    assert_eq!(drain.next(), Some(3));
    assert_eq!(drain.len(), 3);
    drop(drain);
    assert_eq!(a.acks(), [0u16; 0]);
    a.send_packet(&[1], |_, d| b.receive_packet(d, |_, _| true));
    b.send_packet(&[9], |_, d| a.receive_packet(d, |_, _| true));
    assert_eq!(a.acks(), &[4]);
    a.clear_acks();
    assert_eq!(a.acks(), [0u16; 0]);
}

/// A full ack buffer drops new acks until it is cleared, as upstream documents.
#[test]
fn ack_buffer_is_bounded() {
    let config = Config {
        ack_buffer_size: 4,
        ..Config::default()
    };
    let mut a = endpoint(config);
    let mut b = endpoint(Config::default());
    for _ in 0..10 {
        a.send_packet(&[1], |_, d| b.receive_packet(d, |_, _| true));
    }
    b.send_packet(&[9], |_, d| a.receive_packet(d, |_, _| true));
    assert_eq!(a.acks().len(), 4);
    assert_eq!(a.counters().num_packets_acked, 4);
}

/// Every size around each boundary, for the default config and dream-net's.
#[test]
fn fragmentation_and_reassembly_at_every_boundary() {
    for config in [Config::default(), dream_net_config("dn")] {
        let (above, size, max) = (
            config.fragment_above,
            config.fragment_size,
            config.max_packet_size,
        );
        let mut sizes = vec![1, 2, above - 1, above, above + 1, max - 1, max];
        for k in 1..=config.max_fragments {
            for d in [-1i64, 0, 1] {
                let n = (k * size) as i64 + d;
                if n > above as i64 && n <= max as i64 {
                    sizes.push(n as usize);
                }
            }
        }
        let mut a = endpoint(config.clone());
        let mut b = endpoint(config.clone());
        let mut sent_fragments = 0u64;
        for (i, &len) in sizes.iter().enumerate() {
            let data = payload(i as u64, len);
            let mut datagrams = Vec::new();
            let sequence = a.next_packet_sequence();
            a.send_packet(&data, |s, d| {
                assert_eq!(s, sequence);
                datagrams.push(d.to_vec());
            });
            let expected = if len <= above { 1 } else { len.div_ceil(size) };
            assert_eq!(datagrams.len(), expected, "{len}");
            for d in &datagrams {
                assert!(d.len() <= (max + MAX_PACKET_HEADER_BYTES).max(size + 14));
                if len > above {
                    assert!(d.len() <= size + FRAGMENT_HEADER_BYTES + MAX_PACKET_HEADER_BYTES);
                }
            }
            if len > above {
                sent_fragments += expected as u64;
            }
            // deliver the fragments in reverse to exercise out-of-order reassembly
            let mut delivered = Vec::new();
            for d in datagrams.iter().rev() {
                b.receive_packet(d, |s, p| {
                    delivered.push((s, p.to_vec()));
                    true
                });
            }
            assert_eq!(delivered, vec![(sequence, data)], "{len}");
        }
        assert_eq!(a.counters().num_packets_sent, sizes.len() as u64);
        assert_eq!(a.counters().num_fragments_sent, sent_fragments);
        assert_eq!(b.counters().num_fragments_received, sent_fragments);
        assert_eq!(b.counters().num_fragments_invalid, 0);
        assert_eq!(a.counters().num_packets_too_large_to_send, 0);

        // one byte over the limit is refused and counted, and uses no sequence
        let sequence = a.next_packet_sequence();
        let mut called = false;
        a.send_packet(&vec![7u8; max + 1], |_, _| called = true);
        assert!(!called);
        assert_eq!(a.counters().num_packets_too_large_to_send, 1);
        assert_eq!(a.next_packet_sequence(), sequence);
        a.send_packet(&vec![7u8; 10 * max], |_, _| called = true);
        assert!(!called);
        assert_eq!(a.counters().num_packets_too_large_to_send, 2);
    }
}

struct Sim {
    a: Endpoint,
    b: Endpoint,
    ab: Link,
    ba: Link,
    time: f64,
    sent: BTreeMap<u16, Vec<u8>>,
    delivered: BTreeMap<u16, Vec<u8>>,
    acked: BTreeSet<u16>,
    sends: u64,
    fragments: u64,
}

impl Sim {
    fn new(config: &Config, ab: Link, ba: Link) -> Self {
        Self {
            a: endpoint(config.clone()),
            b: endpoint(config.clone()),
            ab,
            ba,
            time: 0.0,
            sent: BTreeMap::new(),
            delivered: BTreeMap::new(),
            acked: BTreeSet::new(),
            sends: 0,
            fragments: 0,
        }
    }

    /// One frame: A sends `size` bytes (if any), B answers with a small packet carrying acks.
    fn frame(&mut self, size: Option<usize>) {
        self.time += DT;
        self.a.update(self.time);
        self.b.update(self.time);
        if let Some(len) = size {
            let sequence = self.a.next_packet_sequence();
            let data = payload(u64::from(sequence) + self.sends * 65536, len);
            let (ab, time) = (&mut self.ab, self.time);
            let mut fragments = 0;
            self.a.send_packet(&data, |_, d| {
                fragments += 1;
                ab.send(time, d);
            });
            if len > self.a.config().fragment_above {
                self.fragments += fragments;
            }
            self.sends += 1;
            self.sent.insert(sequence, data);
        }
        for d in self.ab.due(self.time) {
            let delivered = &mut self.delivered;
            let sent = &self.sent;
            self.b.receive_packet(&d, |s, p| {
                assert_eq!(Some(&p.to_vec()), sent.get(&s), "delivered {s} not intact");
                assert!(delivered.insert(s, p.to_vec()).is_none(), "{s} twice");
                true
            });
        }
        let (ba, time) = (&mut self.ba, self.time);
        self.b.send_packet(&[0xAB; 4], |_, d| ba.send(time, d));
        for d in self.ba.due(self.time) {
            self.a.receive_packet(&d, |_, _| true);
        }
        for s in self.a.drain_acks() {
            assert!(self.acked.insert(s), "acked {s} twice");
        }
        let _ = self.b.drain_acks();
    }

    fn check_counters(&self) {
        let a = self.a.counters();
        let b = self.b.counters();
        assert_eq!(a.num_packets_sent, self.sends);
        assert_eq!(a.num_fragments_sent, self.fragments);
        assert_eq!(a.num_packets_acked, self.acked.len() as u64);
        assert_eq!(b.num_packets_invalid, 0);
        assert_eq!(b.num_fragments_invalid, 0);
        assert_eq!(b.num_packets_too_large_to_receive, 0);
        // every regular packet (incl. each completed reassembly) is stale, a duplicate, or
        // delivered
        assert_eq!(
            b.num_packets_received - b.num_packets_stale - b.num_packets_duplicate,
            self.delivered.len() as u64
        );
        assert!(
            self.acked
                .is_subset(&self.delivered.keys().copied().collect())
        );
    }
}

/// Seeded loss, duplication and reordering both ways, fragmented and not: deliveries are intact
/// and at most once, acks are a subset of deliveries, counters add up. With a perfect return
/// link the acks are exactly the delivered set.
#[test]
fn lossy_reordering_duplicating_link() {
    for seed in 0..8u64 {
        let config = dream_net_config("sim");
        let lossy_back = seed % 2 == 0;
        let ab = Link::new(seed, 0.15, 0.1, 0.03, 0.06);
        let ba = if lossy_back {
            Link::new(seed + 100, 0.15, 0.1, 0.03, 0.06)
        } else {
            Link::new(seed + 100, 0.0, 0.0, 0.03, 0.0)
        };
        let mut sim = Sim::new(&config, ab, ba);
        let mut rng = Rng::new(seed * 31 + 1);
        for _ in 0..3000 {
            let len = match rng.below(10) {
                0 => 1 + rng.below(32768) as usize,
                1 => 1192 + rng.below(4000) as usize,
                _ => 1 + rng.below(1191) as usize,
            };
            sim.frame(Some(len));
        }
        // drain the links: B keeps answering so every delivery is acked
        for _ in 0..30 {
            sim.frame(None);
        }
        assert!(sim.ab.is_empty());
        sim.check_counters();
        let delivered: BTreeSet<u16> = sim.delivered.keys().copied().collect();
        assert!(delivered.len() > 1500, "{seed}: {}", delivered.len());
        if !lossy_back {
            assert_eq!(sim.acked, delivered, "{seed}");
        }
    }
}

/// More than 65536 packets each way, unfragmented and fragmented across the wrap: no
/// packet is stale, duplicate or lost, and every one is acked.
#[test]
fn sequence_wrap_on_both_sides() {
    let config = Config::default();
    let mut a = endpoint(config.clone());
    let mut b = endpoint(config);
    let mut time = 0.0;
    let mut a_acked = 0u64;
    let mut b_acked = 0u64;
    let mut delivered_at_b = 0u64;
    let mut delivered_at_a = 0u64;
    let mut last_b_ack: Option<u16> = None;
    let total = 70_000u32;
    for i in 0..total {
        time += 0.001;
        a.update(time);
        b.update(time);
        // fragmented packets on both sides of the wrap
        let len = if (65_530..65_542).contains(&i) {
            3000
        } else {
            8
        };
        let expected = payload(u64::from(i), len);
        let mut ok = false;
        a.send_packet(&expected, |_, d| {
            b.receive_packet(d, |s, p| {
                assert_eq!(s, i as u16);
                ok = p == expected;
                true
            });
        });
        assert!(ok, "packet {i} lost");
        delivered_at_b += 1;
        b.send_packet(&expected[..4.min(len)], |_, d| {
            a.receive_packet(d, |s, _| {
                assert_eq!(s, i as u16);
                delivered_at_a += 1;
                true
            });
        });
        for s in a.drain_acks() {
            assert_eq!(s, i as u16);
            a_acked += 1;
        }
        for s in b.drain_acks() {
            if let Some(last) = last_b_ack {
                assert!(sequence_greater_than(s, last));
            }
            last_b_ack = Some(s);
            b_acked += 1;
        }
    }
    assert_eq!(a.next_packet_sequence(), (total % 65536) as u16);
    assert_eq!(b.next_packet_sequence(), (total % 65536) as u16);
    assert_eq!(delivered_at_b, u64::from(total));
    assert_eq!(delivered_at_a, u64::from(total));
    assert_eq!(a_acked, u64::from(total));
    assert_eq!(b_acked, u64::from(total) - 1);
    for c in [a.counters(), b.counters()] {
        assert_eq!(c.num_packets_stale, 0);
        assert_eq!(c.num_packets_duplicate, 0);
        assert_eq!(c.num_packets_invalid, 0);
        assert_eq!(c.num_fragments_invalid, 0);
    }
    assert_eq!(a.counters().num_packets_sent, u64::from(total));
}

/// Statistics converge to the simulated link: rtt to twice the one-way latency (plus up to a
/// frame of quantisation each way), packet loss to the drop rate, bandwidth to the send rate.
#[test]
fn statistics_converge_to_the_link() {
    let config = Config::default();
    let latency = 0.05;
    let mut sim = Sim::new(
        &config,
        Link::new(1, 0.1, 0.0, latency, 0.0),
        Link::new(2, 0.0, 0.0, latency, 0.0),
    );
    for _ in 0..3600 {
        sim.frame(Some(100));
    }
    let a = &sim.a;
    let rtt_ms = 2.0 * latency as f32 * 1000.0;
    let frame_ms = DT as f32 * 1000.0;
    for (name, value) in [
        ("rtt", a.rtt()),
        ("rtt_min", a.rtt_min()),
        ("rtt_max", a.rtt_max()),
        ("rtt_avg", a.rtt_avg()),
    ] {
        assert!(
            value >= rtt_ms - 1.0 && value <= rtt_ms + 2.0 * frame_ms + 1.0,
            "{name} = {value}"
        );
    }
    assert!(a.jitter_avg_vs_min_rtt() < 2.0 * frame_ms);
    assert!(a.jitter_max_vs_min_rtt() < 2.0 * frame_ms + 1.0);
    assert!(a.jitter_stddev_vs_avg_rtt() < 2.0 * frame_ms);
    let loss = a.packet_loss();
    assert!((5.0..=15.0).contains(&loss), "packet_loss = {loss}");
    // A sends (28 + 100) bytes 60 times a second
    let expected_kbps = 128.0 * 60.0 * 8.0 / 1000.0;
    let bandwidth = a.bandwidth();
    assert!(
        (bandwidth.sent_kbps - expected_kbps).abs() < expected_kbps * 0.05,
        "{bandwidth:?}"
    );
    assert!(bandwidth.acked_kbps < bandwidth.sent_kbps);
    assert!(bandwidth.acked_kbps > bandwidth.sent_kbps * 0.8);
    // B receives (28 + 100 + header) bytes about 54 times a second
    let received = sim.b.bandwidth().received_kbps;
    assert!(
        received > expected_kbps * 0.8 && received < expected_kbps * 1.1,
        "{received}"
    );
}

/// Reset clears acks, counters, sequence, statistics and reassembly memory, keeps the config,
/// and leaves the endpoint usable.
#[test]
fn reset_restores_the_initial_state() {
    let config = dream_net_config("reset");
    let mut sim = Sim::new(&config, Link::new(3, 0.1, 0.0, 0.02, 0.0), Link::perfect());
    for i in 0..300 {
        sim.frame(Some(if i % 7 == 0 { 5000 } else { 50 }));
    }
    let mut a = sim.a;
    let created = endpoint(config.clone()).allocated_bytes();
    // leave a reassembly half done
    let mut fragments = Vec::new();
    a.send_packet(&[5u8; 5000], |_, d| fragments.push(d.to_vec()));
    let mut b = sim.b;
    b.receive_packet(&fragments[0], |_, _| unreachable!());
    assert!(b.allocated_bytes() > created);
    assert!(a.rtt() > 0.0 && a.counters().num_packets_sent > 0);
    for e in [&mut a, &mut b] {
        e.reset();
        assert_eq!(e.next_packet_sequence(), 0);
        assert_eq!(e.acks(), [0u16; 0]);
        assert_eq!(*e.counters(), Counters::default());
        assert_eq!(
            (
                e.rtt(),
                e.rtt_min(),
                e.rtt_max(),
                e.rtt_avg(),
                e.packet_loss(),
                e.jitter_avg_vs_min_rtt(),
                e.jitter_max_vs_min_rtt(),
                e.jitter_stddev_vs_avg_rtt()
            ),
            (0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
        );
        assert_eq!(e.bandwidth(), Bandwidth::default());
        assert_eq!(e.allocated_bytes(), created);
        assert_eq!(e.config(), &config);
    }
    let mut delivered = Vec::new();
    a.send_packet(&[1, 2, 3], |_, d| {
        b.receive_packet(d, |s, p| {
            delivered.push((s, p.to_vec()));
            true
        });
    });
    assert_eq!(delivered, vec![(0, vec![1, 2, 3])]);
    b.send_packet(&[4], |_, d| a.receive_packet(d, |_, _| true));
    assert_eq!(a.acks(), &[0]);
}

fn panic_message(payload: &Box<dyn std::any::Any + Send>) -> &str {
    payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("")
}

/// A transmit closure that panics: the panic reaches the caller after C finished the send,
/// no later fragment reaches the closure, and the endpoint stays consistent and usable.
#[test]
fn transmit_panic_resumes_after_the_send_completes() {
    let config = Config::default();
    let mut a = endpoint(config.clone());
    let mut b = endpoint(config);
    let mut calls = 0;
    let result = catch_unwind(AssertUnwindSafe(|| {
        a.send_packet(&[3u8; 5000], |_, _| {
            calls += 1;
            assert!(calls != 2, "transmit failed");
        });
    }));
    let payload = result.expect_err("the panic resumes");
    assert_eq!(panic_message(&payload), "transmit failed");
    assert_eq!(calls, 2, "no transmit after the panic");
    // C finished the send: all five fragments were framed and counted, one packet sent
    assert_eq!(a.counters().num_packets_sent, 1);
    assert_eq!(a.counters().num_fragments_sent, 5);
    assert_eq!(a.next_packet_sequence(), 1);
    // and the endpoint works
    let mut delivered = Vec::new();
    a.send_packet(&[1u8; 3000], |_, d| {
        b.receive_packet(d, |s, p| {
            delivered.push((s, p.len()));
            true
        });
    });
    assert_eq!(delivered, vec![(1, 3000)]);
}

/// A process closure that panics: the packet is rejected (not acked, not recorded), the panic
/// resumes, and the same datagram is processed again later. Also for a completed reassembly.
#[test]
fn process_panic_rejects_the_packet_and_resumes() {
    let config = Config::default();
    let mut a = endpoint(config.clone());
    let mut b = endpoint(config);
    let mut datagrams = Vec::new();
    a.send_packet(&[1, 2, 3], |_, d| datagrams.push(d.to_vec()));
    a.send_packet(&[9u8; 4000], |_, d| datagrams.push(d.to_vec()));
    assert_eq!(datagrams.len(), 5);

    let result = catch_unwind(AssertUnwindSafe(|| {
        b.receive_packet(&datagrams[0], |_, _| panic!("process failed"));
    }));
    assert_eq!(panic_message(&result.unwrap_err()), "process failed");
    assert_eq!(b.counters().num_packets_received, 1);
    // not recorded: the next packet from B acks nothing, and the datagram is not a duplicate
    let mut accepted = Vec::new();
    b.receive_packet(&datagrams[0], |s, p| {
        accepted.push((s, p.to_vec()));
        true
    });
    assert_eq!(accepted, vec![(0, vec![1, 2, 3])]);
    assert_eq!(b.counters().num_packets_duplicate, 0);

    // the panic on the fragment that completes a reassembly
    for d in &datagrams[1..4] {
        b.receive_packet(d, |_, _| unreachable!("incomplete"));
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        b.receive_packet(&datagrams[4], |_, _| panic!("reassembled"));
    }));
    assert_eq!(panic_message(&result.unwrap_err()), "reassembled");
    let before = b.allocated_bytes();
    // the reassembly buffer was freed; the fragments can be delivered again
    let mut lengths = Vec::new();
    for d in &datagrams[1..] {
        b.receive_packet(d, |s, p| {
            lengths.push((s, p.len()));
            true
        });
    }
    assert_eq!(lengths, vec![(1, 4000)]);
    assert!(b.allocated_bytes() <= before);
    b.send_packet(&[7], |_, d| a.receive_packet(d, |_, _| true));
    assert_eq!(a.acks(), &[1, 0]);
}

/// A rejected packet is not acked, and its piggy-backed acks are discarded.
#[test]
fn rejected_packets_are_not_acked() {
    let mut a = endpoint(Config::default());
    let mut b = endpoint(Config::default());
    a.send_packet(&[1], |_, d| b.receive_packet(d, |_, _| false));
    b.send_packet(&[2], |_, d| a.receive_packet(d, |_, _| true));
    assert_eq!(a.acks(), [0u16; 0]);
    a.send_packet(&[1], |_, d| b.receive_packet(d, |_, _| true));
    b.send_packet(&[2], |_, d| a.receive_packet(d, |_, _| true));
    assert_eq!(a.acks(), &[1]);
}

#[test]
fn empty_and_oversized_input() {
    let config = Config::default();
    let mut a = endpoint(config.clone());
    let mut b = endpoint(config.clone());
    // empty send: a no-op
    a.send_packet(&[], |_, _| panic!("transmitted an empty packet"));
    assert_eq!(*a.counters(), Counters::default());
    assert_eq!(a.next_packet_sequence(), 0);
    // empty receive: counted invalid
    b.receive_packet(&[], |_, _| panic!("processed an empty datagram"));
    assert_eq!(b.counters().num_packets_invalid, 1);
    // one byte over max_packet_size plus both headers: too large before parsing
    let limit = config.max_packet_size + MAX_PACKET_HEADER_BYTES + FRAGMENT_HEADER_BYTES;
    for len in [limit + 1, limit + 1000, 4 * limit] {
        b.receive_packet(&vec![0u8; len], |_, _| panic!("processed {len}"));
    }
    assert_eq!(b.counters().num_packets_too_large_to_receive, 3);
    // a regular packet whose payload is over max_packet_size
    let mut big = vec![0u8; limit];
    big[..3].copy_from_slice(&[0b0011_1110, 0, 0]);
    b.receive_packet(&big, |_, _| panic!("processed an oversized payload"));
    assert_eq!(b.counters().num_packets_too_large_to_receive, 4);
    assert_eq!(b.counters().num_packets_received, 1);
    // short headers are invalid
    for d in [&[0u8][..], &[0, 0], &[0, 0, 0], &[0b0010_0000, 1, 0]] {
        b.receive_packet(d, |_, _| panic!("processed a short header"));
    }
    assert_eq!(b.counters().num_packets_invalid, 5);
    // a header-only packet is a valid, empty packet
    let mut got = None;
    b.receive_packet(&[0b0010_0000, 5, 0, 1], |s, p| {
        got = Some((s, p.len()));
        true
    });
    assert_eq!(got, Some((5, 0)));
}

/// `update` never moves time backwards and ignores non-finite times.
#[test]
fn time_is_clamped() {
    for start in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        let e = Endpoint::new(Config::default(), start).unwrap();
        assert!(format!("{e:?}").contains("time: 0.0"));
    }
    let mut a = endpoint(Config::default());
    let mut b = endpoint(Config::default());
    a.update(1.0);
    a.send_packet(&[1], |_, d| b.receive_packet(d, |_, _| true));
    for t in [0.5, f64::NAN, f64::NEG_INFINITY, f64::INFINITY, -1.0] {
        a.update(t);
    }
    a.update(1.1);
    b.send_packet(&[1], |_, d| a.receive_packet(d, |_, _| true));
    assert_eq!(a.acks(), &[0]);
    a.update(1.1);
    // the rtt is from the clamped times: 100 ms, finite
    assert!((a.rtt() - 100.0).abs() < 0.01, "{}", a.rtt());
}

#[test]
fn debug_shows_state_and_no_pointers() {
    let mut a = endpoint(Config {
        name: "debug-me".to_owned(),
        ..Config::default()
    });
    a.send_packet(&[1], |_, _| {});
    let text = format!("{a:?}");
    assert!(text.starts_with("Endpoint {"), "{text}");
    assert!(text.contains("\"debug-me\""));
    assert!(text.contains("next_packet_sequence: 1"));
    assert!(text.contains("num_packets_sent: 1"));
    assert!(!text.contains("0x"), "{text}");
    assert!(!text.to_lowercase().contains("ptr"), "{text}");
    let drain = format!("{:?}", a.drain_acks());
    assert!(drain.starts_with("DrainAcks"), "{drain}");
}

/// Endpoints move across threads and are shared by reference; drop frees everything (the
/// allocator test measures it).
#[test]
fn endpoints_cross_threads() {
    let mut a = endpoint(Config::default());
    let mut b = endpoint(Config::default());
    let (a, b) = std::thread::spawn(move || {
        a.send_packet(&[1, 2, 3], |_, d| b.receive_packet(d, |_, _| true));
        (a, b)
    })
    .join()
    .unwrap();
    std::thread::scope(|scope| {
        for _ in 0..4 {
            scope.spawn(|| {
                assert_eq!(a.counters().num_packets_sent, 1);
                assert_eq!(b.counters().num_packets_received, 1);
                let _ = (a.rtt(), b.bandwidth(), a.acks().len(), b.memory_usage());
            });
        }
    });
    drop(a);
    drop(b);
}

/// The closures may drive other endpoints (dream-net's harness does).
#[test]
fn closures_drive_other_endpoints() {
    let mut a = endpoint(Config::default());
    let mut b = endpoint(Config::default());
    let mut c = endpoint(Config::default());
    let mut at_c = 0;
    a.send_packet(&[1u8; 3000], |_, d| {
        b.receive_packet(d, |_, p| {
            b_forward(&mut c, p, &mut at_c);
            true
        });
    });
    assert_eq!(at_c, 1);
}

fn b_forward(c: &mut Endpoint, p: &[u8], at_c: &mut usize) {
    let mut fresh = endpoint(Config::default());
    fresh.send_packet(p, |_, d| {
        c.receive_packet(d, |_, q| {
            assert_eq!(q, p);
            *at_c += 1;
            true
        });
    });
}
