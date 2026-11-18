//! Remote input into `receive_packet`: every hostile case the C checks, one by one with its
//! counter, then a property test of arbitrary bytes and structured mutations of genuine packets
//! and fragments. Nothing panics, every delivered byte comes from the datagrams received for
//! that sequence (no invented or stale bytes), and memory stays within `memory_usage()`.

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

mod reliable_support;

use std::collections::{BTreeMap, BTreeSet};

use dream_net_native::reliable::{Config, Counters, Endpoint};
use proptest::prelude::*;
use reliable_support::{packet_header_len, parse_fragment, payload, sequence_of};

/// Small enough that windows, reassembly slots and fragment limits are all reachable.
fn small_config() -> Config {
    Config {
        name: "hostile".into(),
        max_packet_size: 2048,
        fragment_above: 256,
        max_fragments: 8,
        fragment_size: 256,
        ack_buffer_size: 16,
        sent_packets_buffer_size: 32,
        received_packets_buffer_size: 32,
        fragment_reassembly_buffer_size: 3, // C rounds it up to 4 slots
        rtt_history_size: 16,
        ..Config::default()
    }
}

/// reliable's canonical packet header, as `reliable_write_packet_header` writes it.
fn header(sequence: u16, ack: u16, ack_bits: u32) -> Vec<u8> {
    let mut prefix = 0u8;
    let mut tail = Vec::new();
    for i in 0..4 {
        let byte = (ack_bits >> (8 * i)) as u8;
        if byte != 0xFF {
            prefix |= 1 << (i + 1);
            tail.push(byte);
        }
    }
    let difference = sequence.wrapping_sub(ack);
    let mut out = vec![0, sequence as u8, (sequence >> 8) as u8];
    if difference <= 255 {
        prefix |= 1 << 5;
        out.push(difference as u8);
    } else {
        out.extend_from_slice(&ack.to_le_bytes());
    }
    out[0] = prefix;
    out.extend_from_slice(&tail);
    out
}

fn regular(sequence: u16, ack: u16, ack_bits: u32, body: &[u8]) -> Vec<u8> {
    let mut out = header(sequence, ack, ack_bits);
    out.extend_from_slice(body);
    out
}

fn fragment(sequence: u16, id: u8, count: usize, body: &[u8]) -> Vec<u8> {
    let mut out = vec![
        1,
        sequence as u8,
        (sequence >> 8) as u8,
        id,
        (count - 1) as u8,
    ];
    if id == 0 {
        out.extend_from_slice(&header(sequence, sequence.wrapping_sub(1), 0));
    }
    out.extend_from_slice(body);
    out
}

/// Feeds one datagram and returns what was delivered, checking the call delivered at most once.
fn feed(e: &mut Endpoint, d: &[u8]) -> Option<(u16, Vec<u8>)> {
    let mut out = None;
    e.receive_packet(d, |s, p| {
        assert!(out.is_none(), "process called twice in one receive");
        out = Some((s, p.to_vec()));
        true
    });
    out
}

fn delta(before: &Counters, after: &Counters) -> [u64; 11] {
    let f = |c: &Counters| {
        [
            c.num_packets_sent,
            c.num_packets_received,
            c.num_packets_acked,
            c.num_packets_stale,
            c.num_packets_invalid,
            c.num_packets_too_large_to_send,
            c.num_packets_too_large_to_receive,
            c.num_fragments_sent,
            c.num_fragments_received,
            c.num_fragments_invalid,
            c.num_packets_duplicate,
        ]
    };
    let (b, a) = (f(before), f(after));
    std::array::from_fn(|i| a[i] - b[i])
}

const RECEIVED: usize = 1;
const STALE: usize = 3;
const INVALID: usize = 4;
const TOO_LARGE_RX: usize = 6;
const FRAGMENTS_RECEIVED: usize = 8;
const FRAGMENTS_INVALID: usize = 9;
const DUPLICATE: usize = 10;

/// Feeds `d`, expects no delivery, and returns which counters moved.
fn refused(e: &mut Endpoint, d: &[u8]) -> [u64; 11] {
    let before = *e.counters();
    assert_eq!(feed(e, d), None, "delivered {d:02x?}");
    assert!(e.allocated_bytes() <= e.memory_usage());
    delta(&before, e.counters())
}

fn only(index: usize) -> [u64; 11] {
    let mut d = [0; 11];
    d[index] = 1;
    d
}

#[test]
fn each_hostile_case_is_refused_and_counted() {
    let config = small_config();
    let fs = config.fragment_size;
    let mut e = Endpoint::new(config.clone(), 0.0).unwrap();
    let full = vec![0x5A; fs];

    // num_fragments above max_fragments
    assert_eq!(
        refused(&mut e, &fragment(10, 1, 9, &full)),
        only(FRAGMENTS_INVALID)
    );
    // fragment id at or above num_fragments
    assert_eq!(
        refused(&mut e, &fragment(10, 4, 4, &full)),
        only(FRAGMENTS_INVALID)
    );
    assert_eq!(
        refused(&mut e, &fragment(10, 255, 1, &full)),
        only(FRAGMENTS_INVALID)
    );
    // a non-final fragment that is not exactly fragment_size, and one larger than it
    assert_eq!(
        refused(&mut e, &fragment(10, 1, 4, &full[1..])),
        only(FRAGMENTS_INVALID)
    );
    let mut big = full.clone();
    big.push(0);
    assert_eq!(
        refused(&mut e, &fragment(10, 3, 4, &big)),
        only(FRAGMENTS_INVALID)
    );
    // shorter than a fragment header
    assert_eq!(refused(&mut e, &[1, 10, 0, 1]), only(FRAGMENTS_INVALID));
    // fragment 0 whose packet header names another sequence, or is not canonical
    let mut wrong = vec![1, 10, 0, 0, 3];
    wrong.extend_from_slice(&header(11, 10, 0));
    wrong.extend_from_slice(&full[..fs - wrong.len() + 5]);
    assert_eq!(refused(&mut e, &wrong), only(FRAGMENTS_INVALID));
    let mut noncanonical = vec![1, 10, 0, 0, 3];
    // the ack written as two bytes although the difference fits one: same values, other bytes
    noncanonical.extend_from_slice(&[0b0001_1110, 10, 0, 9, 0, 0, 0, 0, 0]);
    noncanonical.extend_from_slice(&full[..fs - 9]);
    assert_eq!(refused(&mut e, &noncanonical), only(FRAGMENTS_INVALID));
    assert_eq!(e.counters().num_fragments_received, 0);

    // a valid fragment opens a reassembly; a duplicate of it changes nothing; a mismatched
    // count for the same sequence is invalid
    let created = Endpoint::new(config.clone(), 0.0)
        .unwrap()
        .allocated_bytes();
    assert_eq!(
        refused(&mut e, &fragment(20, 1, 4, &full)),
        only(FRAGMENTS_RECEIVED)
    );
    assert!(e.allocated_bytes() > created);
    assert_eq!(refused(&mut e, &fragment(20, 1, 4, &full)), [0; 11]);
    assert_eq!(
        refused(&mut e, &fragment(20, 2, 5, &full)),
        only(FRAGMENTS_INVALID)
    );

    // more interleaved reassemblies than slots: the oldest are evicted (and freed), memory
    // stays bounded, and a late fragment of an evicted, now stale, packet is refused
    for s in 21..40u16 {
        assert_eq!(
            refused(&mut e, &fragment(s, 1, 8, &full)),
            only(FRAGMENTS_RECEIVED)
        );
    }
    assert!(e.allocated_bytes() <= e.memory_usage());
    assert_eq!(
        refused(&mut e, &fragment(20, 2, 4, &full)),
        only(FRAGMENTS_INVALID)
    );

    // completing a reassembly delivers exactly the stored bytes
    let parts: Vec<Vec<u8>> = (0..3).map(|i| payload(i, fs)).collect();
    let last = payload(9, 17);
    assert_eq!(feed(&mut e, &fragment(41, 2, 4, &parts[2])), None);
    assert_eq!(feed(&mut e, &fragment(41, 3, 4, &last)), None);
    assert_eq!(feed(&mut e, &fragment(41, 1, 4, &parts[1])), None);
    let mut first = fragment(41, 0, 4, &[]);
    first.extend_from_slice(&parts[0]);
    let (s, p) = feed(&mut e, &first).expect("reassembled");
    assert_eq!(s, 41);
    assert_eq!(p, [&parts[0][..], &parts[1], &parts[2], &last].concat());
    // fragments of a packet already received are ignored, uncounted
    assert_eq!(refused(&mut e, &fragment(41, 2, 4, &parts[2])), [0; 11]);
    // and the regular duplicate of it is a duplicate
    assert_eq!(refused(&mut e, &regular(41, 0, 0, b"x")), {
        let mut d = only(RECEIVED);
        d[DUPLICATE] = 1;
        d
    });

    // stale: older than the received window
    assert_eq!(
        feed(&mut e, &regular(100, 0, 0, b"new")),
        Some((100, b"new".to_vec()))
    );
    assert_eq!(refused(&mut e, &regular(100 - 40, 0, 0, b"old")), {
        let mut d = only(RECEIVED);
        d[STALE] = 1;
        d
    });
    // a reassembly that is stale is refused as invalid
    assert_eq!(
        refused(&mut e, &fragment(100 - 40, 1, 2, &full)),
        only(FRAGMENTS_INVALID)
    );

    // invalid regular headers
    for d in [&[0u8, 1][..], &[0b0011_1110, 1, 0, 1, 0xFF, 0xFF]] {
        assert_eq!(refused(&mut e, d), {
            let mut x = only(RECEIVED);
            x[INVALID] = 1;
            x
        });
    }
    // too large before parsing
    assert_eq!(refused(&mut e, &vec![0; 2048 + 15]), only(TOO_LARGE_RX));

    // acks for sequences never sent, and ack-bits storms, ack nothing
    for s in 101..200u16 {
        let d = regular(s, s.wrapping_mul(7919), u32::MAX, b"a");
        assert!(feed(&mut e, &d).is_some());
    }
    assert_eq!(e.counters().num_packets_acked, 0);
    assert_eq!(e.acks(), [0u16; 0]);

    // with one packet sent, a storm acks it once, and the ack buffer stays bounded
    for _ in 0..40 {
        e.send_packet(b"ping", |_, _| {});
    }
    let mut s = 200u16;
    for _ in 0..10 {
        for ack in [0u16, 31, 39, 65535] {
            assert!(feed(&mut e, &regular(s, ack, u32::MAX, b"storm")).is_some());
            s += 1;
        }
    }
    assert_eq!(e.counters().num_packets_acked, 16);
    assert_eq!(e.acks().len(), 16);
    let acked: BTreeSet<u16> = e.drain_acks().collect();
    assert_eq!(acked.len(), 16);
    // only packets still in the 32-packet sent window can be acked
    assert!(acked.iter().all(|&s| (8..40).contains(&s)));
}

/// Reassembly and duplicate detection across the 16-bit wrap.
#[test]
fn fragments_around_the_wrap() {
    let config = small_config();
    let fs = config.fragment_size;
    let mut e = Endpoint::new(config, 0.0).unwrap();
    // walk the windows up to the wrap in steps the half-space comparison accepts
    for s in [20_000u16, 40_000, 60_000, 65_500] {
        assert!(feed(&mut e, &regular(s, 0, 0, b"step")).is_some());
    }
    for s in (65_520..=u16::MAX).chain(0..20) {
        let a = payload(u64::from(s), fs);
        let b = payload(u64::from(s) + 1, 3);
        assert_eq!(feed(&mut e, &fragment(s, 1, 2, &b)), None);
        let mut first = fragment(s, 0, 2, &[]);
        first.extend_from_slice(&a);
        assert_eq!(feed(&mut e, &first), Some((s, [a, b].concat())), "{s}");
        // a replay of either is ignored
        assert_eq!(feed(&mut e, &first), None);
    }
    let c = e.counters();
    assert_eq!(c.num_packets_stale, 0);
    assert_eq!(c.num_fragments_invalid, 0);
    assert_eq!(c.num_packets_received, 4 + 36);
}

/// What a test datagram (or burst of them) is made of.
#[derive(Debug, Clone)]
enum Op {
    /// One genuine datagram from the pool.
    Genuine(usize),
    /// Every datagram of one genuine packet, in order or reversed, optionally with one byte of
    /// one of them changed and one of them sent twice.
    Packet {
        index: usize,
        reverse: bool,
        flip: Option<(usize, usize, u8)>,
        repeat: Option<usize>,
    },
    /// A genuine datagram with bytes changed.
    Flip(usize, Vec<(usize, u8)>),
    /// A genuine datagram cut short.
    Truncate(usize, usize),
    /// A genuine datagram with bytes added.
    Extend(usize, Vec<u8>),
    /// Anything.
    Bytes(Vec<u8>),
    /// A crafted fragment near the genuine sequences or the wrap.
    Fragment {
        sequence: u16,
        id: u8,
        count: u8,
        len: usize,
        fill: u8,
    },
    /// A crafted regular packet with arbitrary acks.
    Regular {
        sequence: u16,
        ack: u16,
        ack_bits: u32,
        len: usize,
    },
    /// Time passes.
    Update(u8),
}

fn op() -> impl Strategy<Value = Op> {
    let near = prop_oneof![0u16..80, 65_500u16..=u16::MAX, any::<u16>()];
    let index = 0usize..1000;
    prop_oneof![
        4 => index.clone().prop_map(Op::Genuine),
        4 => (
            index.clone(),
            any::<bool>(),
            prop::option::of((0usize..64, 0usize..40_000, 1u8..=255)),
            prop::option::of(0usize..64),
        )
            .prop_map(|(index, reverse, flip, repeat)| Op::Packet { index, reverse, flip, repeat }),
        3 => (index.clone(), prop::collection::vec((0usize..40_000, any::<u8>()), 1..4))
            .prop_map(|(i, f)| Op::Flip(i, f)),
        1 => (index.clone(), 0usize..1400).prop_map(|(i, n)| Op::Truncate(i, n)),
        1 => (index, prop::collection::vec(any::<u8>(), 1..300))
            .prop_map(|(i, b)| Op::Extend(i, b)),
        2 => prop::collection::vec(any::<u8>(), 0..400).prop_map(Op::Bytes),
        3 => (near.clone(), any::<u8>(), any::<u8>(), 0usize..300, any::<u8>()).prop_map(
            |(sequence, id, count, len, fill)| Op::Fragment { sequence, id: id % 10, count: count % 10, len, fill }
        ),
        2 => (near, any::<u16>(), any::<u32>(), 0usize..300)
            .prop_map(|(sequence, ack, ack_bits, len)| Op::Regular { sequence, ack, ack_bits, len }),
        1 => any::<u8>().prop_map(Op::Update),
    ]
}

/// Genuine traffic: packets of every shape from a sender with the receiver's config.
struct Pool {
    /// The datagrams of each packet, in send order.
    packets: Vec<Vec<Vec<u8>>>,
    /// Every datagram, in send order.
    datagrams: Vec<Vec<u8>>,
    sent: BTreeMap<u16, Vec<u8>>,
}

fn pool(config: &Config) -> Pool {
    let mut sender = Endpoint::new(config.clone(), 0.0).unwrap();
    let mut packets = Vec::new();
    let mut sent = BTreeMap::new();
    for i in 0..60u64 {
        let len = match i % 6 {
            0 => 1,
            1 => config.fragment_above,
            2 => config.fragment_above + 1,
            3 => config.max_packet_size,
            _ => 1 + (i as usize * 997) % config.max_packet_size,
        };
        let data = payload(i, len);
        let sequence = sender.next_packet_sequence();
        let mut datagrams = Vec::new();
        sender.send_packet(&data, |_, d| datagrams.push(d.to_vec()));
        packets.push(datagrams);
        sent.insert(sequence, data);
    }
    let datagrams = packets.iter().flatten().cloned().collect();
    Pool {
        packets,
        datagrams,
        sent,
    }
}

fn build(op: &Op, pool: &Pool, fragment_size: usize) -> Vec<Vec<u8>> {
    let genuine = |i: usize| pool.datagrams[i % pool.datagrams.len()].clone();
    let one = match op {
        Op::Genuine(i) => genuine(*i),
        Op::Packet {
            index,
            reverse,
            flip,
            repeat,
        } => {
            let mut datagrams = pool.packets[index % pool.packets.len()].clone();
            if let Some((which, at, x)) = *flip {
                let n = datagrams.len();
                let d = &mut datagrams[which % n];
                let len = d.len();
                d[at % len] ^= x;
            }
            if let Some(which) = *repeat {
                let again = datagrams[which % datagrams.len()].clone();
                datagrams.push(again);
            }
            if *reverse {
                datagrams.reverse();
            }
            return datagrams;
        }
        Op::Flip(i, flips) => {
            let mut d = genuine(*i);
            for &(at, x) in flips {
                let n = d.len();
                d[at % n] ^= x.max(1);
            }
            d
        }
        Op::Truncate(i, n) => {
            let d = genuine(*i);
            d[..n % (d.len() + 1)].to_vec()
        }
        Op::Extend(i, extra) => [genuine(*i), extra.clone()].concat(),
        Op::Bytes(b) => b.clone(),
        Op::Fragment {
            sequence,
            id,
            count,
            len,
            fill,
        } => {
            let count = usize::from(*count).max(1);
            let len = if usize::from(*id) + 1 < count {
                fragment_size
            } else {
                *len
            };
            fragment(*sequence, *id, count, &vec![*fill; len])
        }
        Op::Regular {
            sequence,
            ack,
            ack_bits,
            len,
        } => regular(
            *sequence,
            *ack,
            *ack_bits,
            &payload(u64::from(*sequence), *len),
        ),
        Op::Update(_) => return Vec::new(),
    };
    vec![one]
}

/// How many packets a run delivered, by kind.
#[derive(Debug, Default, Clone, Copy)]
struct Delivered {
    regular: usize,
    reassembled: usize,
    genuine_reassembled: usize,
}

fn run(config: &Config, ops: &[Op]) -> Result<Delivered, TestCaseError> {
    let pool = pool(config);
    let fs = config.fragment_size;
    let mut e = Endpoint::new(config.clone(), 0.0).unwrap();
    let mut time = 0.0;
    let mut stats = Delivered::default();
    // every fragment payload seen per (sequence, fragment id)
    let mut seen: BTreeMap<(u16, usize), BTreeSet<Vec<u8>>> = BTreeMap::new();
    let mut last = *e.counters();
    for op in ops {
        if let Op::Update(dt) = op {
            time += f64::from(*dt) / 100.0;
            e.update(time);
            continue;
        }
        for d in build(op, &pool, fs) {
            if let Some((sequence, id, _, body)) = parse_fragment(&d) {
                seen.entry((sequence, id))
                    .or_default()
                    .insert(body.to_vec());
            }
            let delivered = feed(&mut e, &d);
            prop_assert!(e.allocated_bytes() <= e.memory_usage());
            let now = *e.counters();
            prop_assert!(now.num_packets_received >= last.num_packets_received);
            prop_assert!(now.num_fragments_received >= last.num_fragments_received);
            prop_assert!(now.num_fragments_invalid >= last.num_fragments_invalid);
            prop_assert!(now.num_packets_invalid >= last.num_packets_invalid);
            prop_assert_eq!(now.num_packets_sent, 0);
            last = now;
            let Some((sequence, p)) = delivered else {
                continue;
            };
            prop_assert!(p.len() <= config.max_packet_size);
            prop_assert_eq!(Some(sequence), sequence_of(&d));
            if d.first().is_some_and(|b| b & 1 == 0) {
                // a regular packet: exactly the bytes after its header
                stats.regular += 1;
                let header = packet_header_len(&d).expect("delivered with a header");
                prop_assert_eq!(&p[..], &d[header..]);
            } else {
                // a reassembly: every chunk is a payload received for that sequence and id
                stats.reassembled += 1;
                for (i, chunk) in p.chunks(fs).enumerate() {
                    let found = seen.get(&(sequence, i)).is_some_and(|s| s.contains(chunk));
                    prop_assert!(found, "chunk {} of {} was never received", i, sequence);
                }
                if p.is_empty() {
                    prop_assert!(seen.contains_key(&(sequence, 0)));
                }
                if pool.sent.get(&sequence) == Some(&p) {
                    stats.genuine_reassembled += 1;
                }
            }
            // an untouched genuine regular datagram delivers the genuine packet
            if let (Op::Genuine(_), Some(genuine)) = (op, pool.sent.get(&sequence))
                && d.first().is_some_and(|b| b & 1 == 0)
            {
                prop_assert_eq!(&p, genuine);
            }
        }
    }
    drop(e);
    Ok(stats)
}

/// The generator reaches every delivery path: a fixed sample of runs delivers regular packets,
/// reassemblies, and genuine multi-fragment reassemblies.
#[test]
fn the_property_reaches_reassembly() {
    use proptest::strategy::ValueTree;
    let mut runner = proptest::test_runner::TestRunner::deterministic();
    let ops = prop::collection::vec(op(), 100..200);
    let mut total = Delivered::default();
    for config in [
        small_config(),
        reliable_support::dream_net_config("hostile"),
    ] {
        for _ in 0..32 {
            let sample = ops.new_tree(&mut runner).unwrap().current();
            let stats = run(&config, &sample).unwrap();
            total.regular += stats.regular;
            total.reassembled += stats.reassembled;
            total.genuine_reassembled += stats.genuine_reassembled;
        }
    }
    println!("{total:?}");
    assert!(total.regular > 500, "{total:?}");
    assert!(total.reassembled > 100, "{total:?}");
    assert!(total.genuine_reassembled > 50, "{total:?}");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn hostile_datagrams_small_config(ops in prop::collection::vec(op(), 1..300)) {
        run(&small_config(), &ops)?;
    }

    #[test]
    fn hostile_datagrams_dream_net_config(ops in prop::collection::vec(op(), 1..200)) {
        run(&reliable_support::dream_net_config("hostile"), &ops)?;
    }
}
