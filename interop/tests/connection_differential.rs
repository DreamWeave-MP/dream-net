//! A differential run of dream-net's `Connection`: the same seeded schedule of sends, link
//! faults, hostile datagrams and time steps is driven through two dream-net 1.1.1 ends (the
//! `reliable` 1.3.4 Rust port) and through two ends of this tree, and both must emit
//! byte-identical datagram streams and identical deliveries, states and counters, with link
//! statistics equal within float tolerance. The mixed pairings must match too.
//!
//! The scenarios cover the paths where the reliable backend decides something: loss,
//! duplication and reordering with fragmented events; a receiver that stops polling, so
//! packets are refused by dream-net and left unacked; a long run across the u16 packet
//! sequence wrap and the reliable message id wrap; garbage and mutated datagrams; and a schema
//! mismatch.

// CI passes -W clippy::pedantic on the command line, overriding the manifest's lint table;
// test code casts freely between widths it controls.
#![allow(
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::many_single_char_names,
    clippy::too_many_lines
)]

mod connection_common;

use connection_common::{
    Counters, Dir, Duo, End, Faults, Kind, Limits, ReliableCounters, Rng, Sent, Stats, close,
    payload,
};

const DT: f64 = 1.0 / 60.0;

/// Something observable.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Event {
    Wire(Dir, Vec<u8>),
    Deliver(char, u32, u8, Vec<u8>),
    Sent(char, &'static str, Sent),
    State(char, String),
    Counters(char, Counters, ReliableCounters),
}

#[derive(Debug, Default)]
struct Transcript {
    events: Vec<Event>,
    stats: Vec<(char, Stats)>,
    datagrams: usize,
}

impl Transcript {
    /// Records what happened since the last call: datagrams, deliveries, states.
    fn frame(&mut self, duo: &mut Duo) {
        for (dir, d) in duo.wire.drain(..) {
            self.datagrams += 1;
            self.events.push(Event::Wire(dir, d));
        }
        for (side, end) in [('a', &mut duo.a), ('b', &mut duo.b)] {
            for (event, channel, p) in end.drain() {
                self.events.push(Event::Deliver(side, event, channel, p));
            }
            if let Some(e) = end.take_event() {
                self.events.push(Event::State(side, e));
            }
        }
    }

    /// Records both ends' counters and statistics.
    fn snapshot(&mut self, duo: &Duo) {
        for (side, end) in [('a', &duo.a), ('b', &duo.b)] {
            self.events.push(Event::Counters(
                side,
                end.counters(),
                end.reliable_counters(),
            ));
            self.events.push(Event::State(side, end.state()));
            self.stats.push((side, end.stats()));
        }
    }

    fn send(&mut self, side: char, end: &mut End, event: &'static str, p: &[u8]) -> Sent {
        let sent = end.send(event, p);
        self.events.push(Event::Sent(side, event, sent));
        sent
    }
}

fn duo(a: Kind, b: Kind, limits: Limits, faults: Faults, seed: u64) -> Duo {
    let mut duo = Duo::new(
        End::new(a, 1, limits, 0.0),
        End::new(b, 1, limits, 0.0),
        faults,
        seed,
    );
    duo.record = true;
    duo
}

/// Requires `other` to match `reference` exactly, stats within tolerance.
fn same(name: &str, pairing: (Kind, Kind), reference: &Transcript, other: &Transcript) {
    if let Some(i) = reference
        .events
        .iter()
        .zip(&other.events)
        .position(|(x, y)| x != y)
    {
        panic!(
            "{name}: {pairing:?} diverges from Old/Old at event {i}:\n  old: {:?}\n  new: {:?}",
            reference.events[i], other.events[i]
        );
    }
    assert_eq!(
        reference.events.len(),
        other.events.len(),
        "{name}: {pairing:?} transcript length"
    );
    assert_eq!(reference.stats.len(), other.stats.len());
    for (k, ((sa, a), (sb, b))) in reference.stats.iter().zip(&other.stats).enumerate() {
        assert_eq!(sa, sb);
        for f in 0..a.len() {
            assert!(
                close(a[f], b[f]),
                "{name}: {pairing:?} snapshot {k} side {sa} stat {f}: {} vs {}",
                a[f],
                b[f]
            );
        }
    }
}

/// Runs `scenario` for Old/Old and every other pairing in `pairings`, requiring agreement.
/// Returns the reference transcript.
fn agree(
    name: &str,
    pairings: &[(Kind, Kind)],
    scenario: impl Fn(Kind, Kind) -> Transcript,
) -> Transcript {
    let reference = scenario(Kind::Old, Kind::Old);
    for &pairing in pairings {
        let other = scenario(pairing.0, pairing.1);
        same(name, pairing, &reference, &other);
    }
    println!(
        "{name}: {} events, {} datagrams, identical for {pairings:?}",
        reference.events.len(),
        reference.datagrams
    );
    reference
}

const ALL: [(Kind, Kind); 3] = [
    (Kind::New, Kind::New),
    (Kind::Old, Kind::New),
    (Kind::New, Kind::Old),
];

fn count_deliveries(t: &Transcript, side: char) -> usize {
    t.events
        .iter()
        .filter(|e| matches!(e, Event::Deliver(s, ..) if *s == side))
        .count()
}

fn lossy_mixed(a: Kind, b: Kind) -> Transcript {
    let mut t = Transcript::default();
    let mut duo = duo(a, b, Limits::default(), Faults::lossy(), 41);
    let mut rng = Rng::new(42);
    let (mut chat, mut blob, mut spawn, mut mv) = (0u32, 0u32, 0u32, 0u32);
    for frame in 0..1200u32 {
        for _ in 0..rng.below(8) {
            let len = 5 + rng.below(250) as usize;
            if t.send('b', &mut duo.b, "Chat", &payload(0, chat, len)) == Sent::Queued {
                chat += 1;
            }
        }
        if frame.is_multiple_of(5) {
            let len = 1192 + rng.below(6800) as usize;
            if t.send('b', &mut duo.b, "Blob", &payload(1, blob, len)) == Sent::Queued {
                blob += 1;
            }
        }
        for _ in 0..rng.below(4) {
            let len = 5 + rng.below(1000) as usize;
            if t.send('a', &mut duo.a, "Spawn", &payload(2, spawn, len)) == Sent::Queued {
                spawn += 1;
            }
        }
        let len = 5 + rng.below(60) as usize;
        if t.send('a', &mut duo.a, "Move", &payload(9, mv, len)) == Sent::Queued {
            mv += 1;
        }
        t.send('b', &mut duo.b, "Ping", &[]);
        // irregular frame times too
        let dt = if rng.chance(0.1) { DT * 3.5 } else { DT };
        duo.step(dt);
        t.frame(&mut duo);
        if frame.is_multiple_of(50) {
            t.snapshot(&duo);
        }
    }
    duo.set_faults(Faults::PERFECT);
    for _ in 0..1200 {
        duo.step(DT);
        t.frame(&mut duo);
    }
    t.snapshot(&duo);
    t
}

#[test]
fn lossy_reordered_duplicated_and_fragmented_traffic() {
    let t = agree("lossy", &ALL, lossy_mixed);
    assert!(count_deliveries(&t, 'a') > 1000);
    assert!(count_deliveries(&t, 'b') > 500);
}

fn stalled_receiver(a: Kind, b: Kind) -> Transcript {
    let mut t = Transcript::default();
    let limits = Limits {
        max_pending_events: 16,
        max_parked_bytes: 8 * 1024,
        ..Limits::default()
    };
    let faults = Faults {
        loss: 0.05,
        jitter: 0.03,
        duplicate: 0.05,
        latency: 0.02,
    };
    let mut duo = duo(a, b, limits, faults, 7);
    let mut rng = Rng::new(8);
    let (mut chat, mut blob) = (0u32, 0u32);
    for frame in 0..1500u32 {
        for _ in 0..rng.below(10) {
            let len = 5 + rng.below(250) as usize;
            if t.send('b', &mut duo.b, "Chat", &payload(0, chat, len)) == Sent::Queued {
                chat += 1;
            }
        }
        // fragmented events too, so whole reassembled packets are refused and resent
        if frame.is_multiple_of(10) {
            let len = 1192 + rng.below(6000) as usize;
            if t.send('b', &mut duo.b, "Blob", &payload(1, blob, len)) == Sent::Queued {
                blob += 1;
            }
        }
        duo.step(DT);
        // a polls only some of the time: its inbox fills and packets are refused
        if (frame / 100) % 3 == 2 {
            t.frame(&mut duo);
        } else {
            for (dir, d) in duo.wire.drain(..) {
                t.datagrams += 1;
                t.events.push(Event::Wire(dir, d));
            }
        }
        if frame.is_multiple_of(50) {
            t.snapshot(&duo);
        }
    }
    duo.set_faults(Faults::PERFECT);
    for _ in 0..1500 {
        duo.step(DT);
        t.frame(&mut duo);
    }
    t.snapshot(&duo);
    t
}

#[test]
fn a_stalled_receiver_refuses_packets_identically() {
    let t = agree("stalled", &ALL, stalled_receiver);
    let refused = t
        .events
        .iter()
        .rev()
        .find_map(|e| match e {
            Event::Counters('a', c, _) => Some(c[14]),
            _ => None,
        })
        .unwrap();
    assert!(refused > 0, "no packet was refused");
}

fn long_wrap(a: Kind, b: Kind) -> Transcript {
    let mut t = Transcript::default();
    let faults = Faults {
        loss: 0.03,
        jitter: 0.02,
        duplicate: 0.02,
        latency: 0.0,
    };
    let mut duo = duo(a, b, Limits::default(), faults, 99);
    duo.record = true;
    let mut rng = Rng::new(100);
    let mut chat = 0u32;
    let mut frames = 0u32;
    // past the u16 packet sequence wrap on b, and the message id wrap several times
    loop {
        for _ in 0..64 {
            let len = 150 + rng.below(100) as usize;
            if t.send('b', &mut duo.b, "Chat", &payload(0, chat, len)) == Sent::Queued {
                chat += 1;
            } else {
                break;
            }
        }
        duo.step(DT);
        t.frame(&mut duo);
        frames += 1;
        if frames.is_multiple_of(500) {
            t.snapshot(&duo);
        }
        if duo.b.reliable_counters()[0] > 70_000 && chat > 140_000 {
            break;
        }
        assert!(frames < 40_000, "the run did not reach the wraps");
    }
    duo.set_faults(Faults::PERFECT);
    for _ in 0..600 {
        duo.step(DT);
        t.frame(&mut duo);
    }
    t.snapshot(&duo);
    t
}

#[test]
fn a_long_run_across_the_packet_sequence_and_message_id_wraps() {
    let t = agree("wrap", &ALL, long_wrap);
    let delivered = count_deliveries(&t, 'a');
    assert!(delivered > 140_000, "{delivered}");
}

fn hostile(a: Kind, b: Kind) -> Transcript {
    let mut t = Transcript::default();
    let limits = Limits {
        malformed_limit: u32::MAX,
        ..Limits::default()
    };
    let mut duo = duo(a, b, limits, Faults::lossy(), 3);
    let mut rng = Rng::new(4);
    let mut chat = 0u32;
    let mut blob = 0u32;
    let mut seen: Vec<Vec<u8>> = Vec::new();
    for frame in 0..1500u32 {
        for _ in 0..rng.below(6) {
            let len = 5 + rng.below(250) as usize;
            if t.send('b', &mut duo.b, "Chat", &payload(0, chat, len)) == Sent::Queued {
                chat += 1;
            }
        }
        if frame.is_multiple_of(7) {
            let len = 1192 + rng.below(4000) as usize;
            if t.send('b', &mut duo.b, "Blob", &payload(1, blob, len)) == Sent::Queued {
                blob += 1;
            }
        }
        duo.step(DT);
        if !(duo.a.established() && duo.b.established()) {
            // a hostile datagram that decodes as a different hello fails the handshake: start
            // once both ends are up, with datagrams that no longer carry the hello
            t.frame(&mut duo);
            continue;
        }
        for (dir, d) in &duo.wire {
            if *dir == Dir::BtoA && seen.len() < 4096 {
                seen.push(d.clone());
            }
        }
        // garbage, mutated real datagrams, and replays straight into a
        for _ in 0..rng.below(4) {
            let datagram = match rng.below(4) {
                0 => (0..rng.below(1300)).map(|_| rng.next_u64() as u8).collect(),
                1 | 2 if !seen.is_empty() => {
                    let mut d = seen[rng.below(seen.len() as u64) as usize].clone();
                    for _ in 0..=rng.below(3) {
                        let i = rng.below(d.len() as u64) as usize;
                        d[i] ^= 1 << rng.below(8);
                    }
                    d
                }
                _ if !seen.is_empty() => seen[rng.below(seen.len() as u64) as usize].clone(),
                _ => vec![0],
            };
            let mut out = Vec::new();
            duo.a.receive(&datagram, &mut out);
            for d in out {
                duo.wire.push((Dir::AtoB, d));
            }
        }
        t.frame(&mut duo);
        if frame.is_multiple_of(50) {
            t.snapshot(&duo);
        }
    }
    t.snapshot(&duo);
    t
}

#[test]
fn garbage_mutated_and_replayed_datagrams_are_handled_identically() {
    let t = agree("hostile", &ALL, hostile);
    let last = t
        .events
        .iter()
        .rev()
        .find_map(|e| match e {
            Event::Counters('a', c, r) => Some((*c, *r)),
            _ => None,
        })
        .unwrap();
    // malformed framing and reliable's own refusals were both exercised
    assert!(last.0[13] > 0, "{last:?}");
    assert!(last.1[4] > 0 || last.1[9] > 0, "{last:?}");
}

fn mismatch(a: Kind, b: Kind) -> Transcript {
    let mut t = Transcript::default();
    let mut duo = Duo::new(
        End::new(a, 1, Limits::default(), 0.0),
        End::new(b, 2, Limits::default(), 0.0),
        Faults::lossy(),
        11,
    );
    duo.record = true;
    t.send('b', &mut duo.b, "Chat", &payload(0, 0, 8));
    for _ in 0..300 {
        duo.step(DT);
        t.frame(&mut duo);
    }
    t.snapshot(&duo);
    t
}

#[test]
fn schema_mismatch_is_handled_identically() {
    let t = agree("mismatch", &ALL, mismatch);
    assert!(
        t.events
            .iter()
            .any(|e| matches!(e, Event::State('a', s) if s.starts_with("Failed(SchemaMismatch")))
    );
}
