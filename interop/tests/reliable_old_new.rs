//! A `reliable` 1.3.4 Rust endpoint and a C endpoint talking to each other, both ways round,
//! over seeded lossy links, with fragmented and unfragmented packets: every delivery is intact
//! and at most once, every ack names a packet the other side delivered, and with a lossless
//! return link the acks are exactly the delivered set.

// CI passes -W clippy::pedantic on the command line, overriding the manifest's lint table;
// test code casts freely between widths it controls.
#![allow(
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]

mod reliable_common;

use std::collections::{BTreeMap, BTreeSet};

use reliable_common::{Ep, Kind, Rng, Settings};

fn exchange(sender: Kind, receiver: Kind, seed: u64, back_loss: f64) {
    let settings = Settings::dream_net();
    let mut a = Ep::create(sender, &settings, 0.0);
    let mut b = Ep::create(receiver, &settings, 0.0);
    let mut rng = Rng::new(seed);
    let mut sent: BTreeMap<u16, Vec<u8>> = BTreeMap::new();
    let mut delivered: BTreeMap<u16, Vec<u8>> = BTreeMap::new();
    let mut acked = BTreeSet::new();
    let mut b_sent = 0u64;
    let mut b_delivered = 0u64;
    let mut in_flight: Vec<Vec<u8>> = Vec::new();
    let mut time = 0.0;
    for frame in 0..2000u32 {
        time += 1.0 / 60.0;
        a.update(time);
        b.update(time);
        // last frame's datagrams from A arrive, in a shuffled order
        while !in_flight.is_empty() {
            let d = in_flight.swap_remove(rng.below(in_flight.len() as u64) as usize);
            if let Some((s, p, _)) = b.receive(&d, |_, _| true) {
                assert_eq!(Some(&p), sent.get(&s), "{s} not intact");
                assert!(delivered.insert(s, p).is_none(), "{s} delivered twice");
            }
        }
        if frame < 1950 {
            let len = match rng.below(8) {
                0 => 1192 + rng.below(20_000) as usize,
                1 => 1191,
                _ => 1 + rng.below(1191) as usize,
            };
            let data: Vec<u8> = (0..len).map(|_| rng.next_u64() as u8).collect();
            let mut sequence = None;
            for (s, d) in a.send(&data) {
                sequence = Some(s);
                if !rng.chance(0.1) {
                    in_flight.push(d);
                }
            }
            sent.insert(sequence.expect("sent"), data);
        }
        // B answers every frame, carrying its acks and its own payload
        let reply = vec![frame as u8; 1 + (frame as usize % 3000)];
        b_sent += 1;
        for (_, d) in b.send(&reply) {
            if !rng.chance(back_loss)
                && let Some((_, p, _)) = a.receive(&d, |_, _| true)
            {
                assert_eq!(p.len(), reply.len());
                b_delivered += 1;
            }
        }
        for s in a.drain_acks() {
            assert!(acked.insert(s), "{s} acked twice");
        }
        let _ = b.drain_acks();
    }
    let delivered_set: BTreeSet<u16> = delivered.keys().copied().collect();
    assert!(acked.is_subset(&delivered_set));
    assert!(delivered.len() > 1300, "{}", delivered.len());
    if back_loss == 0.0 {
        assert_eq!(acked, delivered_set, "{sender:?} -> {receiver:?}");
        assert_eq!(b_delivered, b_sent);
    } else {
        assert!(b_delivered > b_sent / 2);
    }
    let counters = a.counters();
    assert_eq!(counters[0], sent.len() as u64);
    assert_eq!(counters[2], acked.len() as u64);
}

#[test]
fn old_to_new_and_new_to_old() {
    for (sender, receiver) in [(Kind::Old, Kind::New), (Kind::New, Kind::Old)] {
        for (seed, back_loss) in [(1, 0.0), (2, 0.15), (3, 0.0), (4, 0.3)] {
            exchange(sender, receiver, seed, back_loss);
        }
    }
}
