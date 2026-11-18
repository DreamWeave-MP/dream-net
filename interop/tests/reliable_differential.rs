//! The C reliable binding against the `reliable` 1.3.4 Rust port it replaces, driven with
//! identical inputs: the audit's Appendix B exchange, seeded lossy/reordering/duplicating
//! links with rejections and ack-buffer pressure, a run across the sequence wrap, and hostile
//! datagrams. Every emitted datagram, delivery, ack and counter must match exactly, and the
//! statistics within float tolerance, for old-old, new-new, and both mixed pairings. The
//! documented differences (audit D13, D16, D19) are pinned as differences.

// CI passes -W clippy::pedantic on the command line, overriding the manifest's lint table;
// test code casts freely between widths it controls.
#![allow(
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::needless_range_loop,
    clippy::too_many_lines
)]

mod reliable_common;

use reliable_common::{Counters, Ep, Kind, Rng, Settings, Stats, close, fnv1a};

/// Something observable, with packet bytes as (length, FNV-1a) to keep long runs small.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Event {
    Tx {
        side: usize,
        sequence: u16,
        len: usize,
        hash: u32,
    },
    Rx {
        side: usize,
        sequence: u16,
        len: usize,
        hash: u32,
        accepted: bool,
    },
    Acks {
        side: usize,
        acks: Vec<u16>,
    },
    Counters {
        side: usize,
        counters: Counters,
    },
}

#[derive(Debug, Default)]
struct Transcript {
    events: Vec<Event>,
    stats: Vec<(usize, Stats)>,
}

const PAIRINGS: [(Kind, Kind); 4] = [
    (Kind::Old, Kind::Old),
    (Kind::New, Kind::New),
    (Kind::Old, Kind::New),
    (Kind::New, Kind::Old),
];

/// Runs `scenario` for every pairing and requires the four transcripts to agree.
fn agree(name: &str, scenario: impl Fn(Kind, Kind) -> Transcript) -> Transcript {
    let reference = scenario(Kind::Old, Kind::Old);
    for (a, b) in PAIRINGS.into_iter().skip(1) {
        let other = scenario(a, b);
        let first = reference
            .events
            .iter()
            .zip(&other.events)
            .position(|(x, y)| x != y);
        if let Some(i) = first {
            panic!(
                "{name}: {a:?}/{b:?} diverges from Old/Old at event {i}: {:?} vs {:?}",
                reference.events[i], other.events[i]
            );
        }
        assert_eq!(
            reference.events.len(),
            other.events.len(),
            "{name}: {a:?}/{b:?} transcript length"
        );
        assert_eq!(reference.stats.len(), other.stats.len());
        for ((side, x), (_, y)) in reference.stats.iter().zip(&other.stats) {
            for k in 0..x.len() {
                assert!(
                    close(x[k], y[k]),
                    "{name}: {a:?}/{b:?} side {side} stat {k}: {} vs {}",
                    x[k],
                    y[k]
                );
            }
        }
    }
    reference
}

/// The audit's Appendix B, line for line: both sides send sizes cycling through
/// {1, 10, 1191, 1192, 5000, 32768, 77, 300} at 60 Hz for 120 frames, every third datagram of
/// each side is dropped, acks are drained every frame.
fn appendix_b(kind_a: Kind, kind_b: Kind) -> Transcript {
    let settings = [
        Settings {
            name: "a",
            ..Settings::dream_net()
        },
        Settings {
            name: "b",
            ..Settings::dream_net()
        },
    ];
    let mut e = [
        Ep::create(kind_a, &settings[0], 0.0),
        Ep::create(kind_b, &settings[1], 0.0),
    ];
    let mut t = Transcript::default();
    let sizes = [1usize, 10, 1191, 1192, 5000, 32768, 77, 300];
    let mut dgram_index = [0usize; 2];
    let mut time = 0.0;
    for frame in 0..120usize {
        time += 1.0 / 60.0;
        for x in &mut e {
            x.update(time);
        }
        let mut queues: [Vec<Vec<u8>>; 2] = [Vec::new(), Vec::new()];
        for s in 0..2 {
            let size = sizes[(frame * 3 + s) % 8];
            let payload: Vec<u8> = (0..size).map(|i| (i * 7 + frame + s) as u8).collect();
            for (sequence, d) in e[s].send(&payload) {
                t.events.push(Event::Tx {
                    side: s,
                    sequence,
                    len: d.len(),
                    hash: fnv1a(&d),
                });
                let k = dgram_index[s];
                dgram_index[s] += 1;
                if k % 3 != 2 {
                    queues[s].push(d);
                }
            }
        }
        for s in 0..2 {
            let other = 1 - s;
            for d in &queues[s] {
                if let Some((sequence, p, accepted)) = e[other].receive(d, |_, _| true) {
                    t.events.push(Event::Rx {
                        side: other,
                        sequence,
                        len: p.len(),
                        hash: fnv1a(&p),
                        accepted,
                    });
                }
            }
        }
        for (s, x) in e.iter_mut().enumerate() {
            t.events.push(Event::Acks {
                side: s,
                acks: x.drain_acks(),
            });
        }
    }
    for (s, x) in e.iter().enumerate() {
        t.events.push(Event::Counters {
            side: s,
            counters: x.counters(),
        });
        t.stats.push((s, x.stats()));
    }
    t
}

#[test]
fn appendix_b_transcript_is_identical() {
    let t = agree("appendix B", appendix_b);
    // the audit's figures: 1200 TX lines, 110 RX lines, and these counters on both sides
    let tx = t
        .events
        .iter()
        .filter(|e| matches!(e, Event::Tx { .. }))
        .count();
    let rx = t
        .events
        .iter()
        .filter(|e| matches!(e, Event::Rx { .. }))
        .count();
    assert_eq!((tx, rx), (1200, 110));
    for side in 0..2 {
        assert!(t.events.contains(&Event::Counters {
            side,
            counters: [120, 55, 54, 0, 0, 0, 0, 525, 350, 0, 0],
        }));
    }
}

/// A seeded link per direction: drop, duplicate, and delay by whole frames (reordering).
struct Link {
    rng: Rng,
    loss: f64,
    duplicate: f64,
    max_delay: u64,
    pending: Vec<(u64, u64, Vec<u8>)>,
    order: u64,
}

impl Link {
    fn new(seed: u64, loss: f64, duplicate: f64, max_delay: u64) -> Self {
        Self {
            rng: Rng::new(seed),
            loss,
            duplicate,
            max_delay,
            pending: Vec::new(),
            order: 0,
        }
    }

    fn send(&mut self, frame: u64, d: &[u8]) {
        if self.rng.chance(self.loss) {
            return;
        }
        let copies = if self.rng.chance(self.duplicate) {
            2
        } else {
            1
        };
        for _ in 0..copies {
            let at = frame + self.rng.below(self.max_delay + 1);
            self.pending.push((at, self.order, d.to_vec()));
            self.order += 1;
        }
    }

    fn due(&mut self, frame: u64) -> Vec<Vec<u8>> {
        self.pending.sort_by_key(|p| (p.0, p.1));
        let n = self.pending.iter().take_while(|p| p.0 <= frame).count();
        self.pending.drain(..n).map(|p| p.2).collect()
    }
}

struct Plan {
    settings: Settings,
    seed: u64,
    frames: u64,
    loss: f64,
    duplicate: f64,
    max_delay: u64,
    /// Side 1 drains its acks only every this many frames (ack buffer pressure).
    lazy_drain: u64,
}

fn random_exchange(plan: &Plan, kind_a: Kind, kind_b: Kind) -> Transcript {
    let mut e = [
        Ep::create(kind_a, &plan.settings, 0.0),
        Ep::create(kind_b, &plan.settings, 0.0),
    ];
    let mut links = [
        Link::new(plan.seed ^ 1, plan.loss, plan.duplicate, plan.max_delay),
        Link::new(plan.seed ^ 2, plan.loss, plan.duplicate, plan.max_delay),
    ];
    let mut rng = Rng::new(plan.seed);
    let mut t = Transcript::default();
    let mut time = 0.0;
    let max = plan.settings.max_packet_size;
    let above = plan.settings.fragment_above;
    for frame in 0..plan.frames {
        time += (1 + rng.below(4)) as f64 / 120.0;
        for x in &mut e {
            x.update(time);
        }
        for s in 0..2 {
            for _ in 0..rng.below(4) {
                let len = match rng.below(20) {
                    0 => max,
                    1 => max + 1 + rng.below(100) as usize, // too large to send
                    2..=4 => above + 1 + rng.below((max - above) as u64) as usize,
                    5 => above,
                    _ => 1 + rng.below(above as u64) as usize,
                };
                let fill = rng.next_u64() as u8;
                let payload: Vec<u8> = (0..len).map(|i| fill ^ (i as u8)).collect();
                for (sequence, d) in e[s].send(&payload) {
                    t.events.push(Event::Tx {
                        side: s,
                        sequence,
                        len: d.len(),
                        hash: fnv1a(&d),
                    });
                    links[s].send(frame, &d);
                }
            }
        }
        for s in 0..2 {
            let other = 1 - s;
            for d in links[s].due(frame) {
                // reject about one packet in thirteen, decided by its content
                let delivered = e[other].receive(&d, |_, p| !fnv1a(p).is_multiple_of(13));
                if let Some((sequence, p, accepted)) = delivered {
                    t.events.push(Event::Rx {
                        side: other,
                        sequence,
                        len: p.len(),
                        hash: fnv1a(&p),
                        accepted,
                    });
                }
            }
        }
        for (s, x) in e.iter_mut().enumerate() {
            if s == 0 || frame.is_multiple_of(plan.lazy_drain) {
                t.events.push(Event::Acks {
                    side: s,
                    acks: x.drain_acks(),
                });
            }
            t.events.push(Event::Counters {
                side: s,
                counters: x.counters(),
            });
            t.stats.push((s, x.stats()));
        }
    }
    t
}

#[test]
fn seeded_lossy_exchanges_are_identical() {
    let small = Settings {
        name: "small",
        max_packet_size: 4096,
        fragment_above: 300,
        max_fragments: 16,
        fragment_size: 256,
        ack_buffer_size: 8,
        sent_packets_buffer_size: 64,
        received_packets_buffer_size: 32,
        fragment_reassembly_buffer_size: 4,
        rtt_history_size: 32,
        ..Settings::defaults()
    };
    let mut total = (0usize, 0usize);
    for (i, settings) in [Settings::dream_net(), Settings::defaults(), small]
        .into_iter()
        .enumerate()
    {
        for seed in 0..6u64 {
            let plan = Plan {
                settings: settings.clone(),
                seed: seed * 1000 + i as u64,
                frames: 600,
                loss: [0.0, 0.05, 0.2][seed as usize % 3],
                duplicate: [0.0, 0.1][seed as usize % 2],
                max_delay: [0, 3][seed as usize % 2],
                lazy_drain: 1 + seed % 4,
            };
            let t = agree(&format!("{} seed {seed}", settings.name), |a, b| {
                random_exchange(&plan, a, b)
            });
            total.0 += t
                .events
                .iter()
                .filter(|e| matches!(e, Event::Tx { .. }))
                .count();
            total.1 += t
                .events
                .iter()
                .filter(|e| matches!(e, Event::Rx { .. }))
                .count();
        }
    }
    assert!(total.0 > 50_000 && total.1 > 20_000, "{total:?}");
}

/// 70 000 packets each way at 1 ms: both sides cross the 16-bit wrap, identically.
#[test]
fn the_sequence_wrap_is_identical() {
    let plan = Plan {
        settings: Settings::defaults(),
        seed: 77,
        frames: 0,
        loss: 0.02,
        duplicate: 0.02,
        max_delay: 2,
        lazy_drain: 1,
    };
    let scenario = |kind_a, kind_b| {
        let mut e = [
            Ep::create(kind_a, &plan.settings, 0.0),
            Ep::create(kind_b, &plan.settings, 0.0),
        ];
        let mut links = [
            Link::new(1, plan.loss, plan.duplicate, plan.max_delay),
            Link::new(2, plan.loss, plan.duplicate, plan.max_delay),
        ];
        let mut t = Transcript::default();
        let mut digest = [0u32; 2];
        for frame in 0..70_000u64 {
            let time = frame as f64 / 1000.0;
            for x in &mut e {
                x.update(time);
            }
            for (s, link) in links.iter_mut().enumerate() {
                let len = if (65_530..65_545).contains(&frame) {
                    2500
                } else {
                    20
                };
                let payload = vec![(frame as u8) ^ (s as u8); len];
                for (sequence, d) in e[s].send(&payload) {
                    digest[s] = digest[s].rotate_left(5) ^ fnv1a(&d) ^ u32::from(sequence);
                    link.send(frame, &d);
                }
            }
            for s in 0..2 {
                for d in links[s].due(frame) {
                    if let Some((sequence, p, _)) = e[1 - s].receive(&d, |_, _| true) {
                        digest[1 - s] =
                            digest[1 - s].rotate_left(7) ^ fnv1a(&p) ^ u32::from(sequence);
                    }
                }
            }
            for x in &mut e {
                for a in x.drain_acks() {
                    t.events.push(Event::Acks {
                        side: 0,
                        acks: vec![a],
                    });
                }
            }
            if frame % 1000 == 999 {
                for (s, x) in e.iter().enumerate() {
                    t.events.push(Event::Counters {
                        side: s,
                        counters: x.counters(),
                    });
                    t.events.push(Event::Tx {
                        side: s,
                        sequence: x.next_packet_sequence(),
                        len: 0,
                        hash: digest[s],
                    });
                    t.stats.push((s, x.stats()));
                }
            }
        }
        t
    };
    let t = agree("wrap", scenario);
    // both sides wrapped
    assert!(t.events.iter().any(|e| matches!(
        e,
        Event::Tx { sequence, len: 0, .. } if *sequence == (70_000u32 % 65_536) as u16
    )));
}

/// Hostile datagrams into one receiver of each implementation: arbitrary bytes, crafted
/// headers and fragments, and mutations of genuine traffic. Deliveries and counters agree at
/// every step. (Empty datagrams are left out: the port panics on them.)
#[test]
fn hostile_input_is_handled_identically() {
    for (settings, seed) in [
        (Settings::dream_net(), 1u64),
        (
            Settings {
                name: "small",
                max_packet_size: 2048,
                fragment_above: 256,
                max_fragments: 8,
                fragment_size: 256,
                received_packets_buffer_size: 32,
                fragment_reassembly_buffer_size: 4,
                ..Settings::defaults()
            },
            2,
        ),
    ] {
        let mut rng = Rng::new(seed);
        let mut sender = Ep::create(Kind::New, &settings, 0.0);
        let mut genuine = Vec::new();
        for i in 0..200usize {
            let len = 1 + (i * 331) % settings.max_packet_size;
            for (_, d) in sender.send(&vec![i as u8; len]) {
                genuine.push(d);
            }
        }
        let mut old = Ep::create(Kind::Old, &settings, 0.0);
        let mut new = Ep::create(Kind::New, &settings, 0.0);
        let mut deliveries = 0;
        for step in 0..60_000u32 {
            let d: Vec<u8> = match rng.below(8) {
                0 => (0..=rng.below(64)).map(|_| rng.next_u64() as u8).collect(),
                1 => {
                    // a fragment header with fields near the limits
                    let mut d = vec![
                        1,
                        rng.next_u64() as u8,
                        rng.below(3) as u8,
                        rng.below(12) as u8,
                        rng.below(12) as u8,
                    ];
                    let len = match rng.below(3) {
                        0 => settings.fragment_size,
                        1 => rng.below(settings.fragment_size as u64 + 20) as usize,
                        _ => settings.fragment_size + 9,
                    };
                    d.extend((0..len).map(|_| rng.next_u64() as u8));
                    d
                }
                2 => {
                    // a regular header with every prefix bit pattern
                    let mut d = vec![(rng.next_u64() as u8) & !1];
                    d.extend((0..rng.below(16)).map(|_| rng.next_u64() as u8));
                    d
                }
                3 | 4 => genuine[rng.below(genuine.len() as u64) as usize].clone(),
                _ => {
                    let mut d = genuine[rng.below(genuine.len() as u64) as usize].clone();
                    for _ in 0..=rng.below(3) {
                        let at = rng.below(d.len() as u64) as usize;
                        d[at] ^= 1 + rng.below(255) as u8;
                    }
                    if rng.chance(0.2) {
                        d.truncate(1 + rng.below(d.len() as u64) as usize);
                    }
                    d
                }
            };
            if step % 500 == 0 {
                old.update(f64::from(step) / 1000.0);
                new.update(f64::from(step) / 1000.0);
            }
            let a = old.receive(&d, |_, p| !fnv1a(p).is_multiple_of(5));
            let b = new.receive(&d, |_, p| !fnv1a(p).is_multiple_of(5));
            assert_eq!(a, b, "step {step}: {d:02x?}");
            deliveries += usize::from(a.is_some());
            assert_eq!(old.counters(), new.counters(), "step {step}");
            assert_eq!(old.drain_acks(), new.drain_acks(), "step {step}");
        }
        println!("{}: {deliveries} deliveries", settings.name);
        assert!(deliveries > 2_000, "{deliveries}");
    }
}

/// D16: with every rtt sample at or above 10 s, the port's `rtt_min` sentinel reports 0; C
/// reports the minimum. Everything else agrees.
#[test]
fn rtt_min_on_a_ten_second_link_differs_as_documented() {
    let settings = Settings::defaults();
    let mut rtt_min = Vec::new();
    for kind in [Kind::Old, Kind::New] {
        let mut a = Ep::create(kind, &settings, 0.0);
        let mut b = Ep::create(kind, &settings, 0.0);
        for (_, d) in a.send(&[1, 2, 3]) {
            b.receive(&d, |_, _| true);
        }
        a.update(11.0);
        b.update(11.0);
        for (_, d) in b.send(&[4]) {
            a.receive(&d, |_, _| true);
        }
        assert_eq!(a.drain_acks(), [0]);
        a.update(11.0);
        let s = a.stats();
        assert!(close(s[0], 11_000.0) && close(s[2], 11_000.0) && close(s[3], 11_000.0));
        rtt_min.push(s[1]);
    }
    assert_eq!(rtt_min[0], 0.0, "the port's sentinel");
    assert!(close(rtt_min[1], 11_000.0), "C's true minimum");
}

/// D19: `reset` clears the statistics in C, not in the port. Counters, acks and the sequence
/// are cleared by both.
#[test]
fn reset_differs_as_documented() {
    let settings = Settings::defaults();
    let mut after = Vec::new();
    for kind in [Kind::Old, Kind::New] {
        let mut a = Ep::create(kind, &settings, 0.0);
        let mut b = Ep::create(kind, &settings, 0.0);
        let mut time = 0.0;
        let mut replies: Vec<Vec<u8>> = Vec::new();
        for _ in 0..100 {
            time += 0.05;
            a.update(time);
            b.update(time);
            // last frame's replies arrive now: a 50 ms round trip
            for d in replies.drain(..) {
                a.receive(&d, |_, _| true);
            }
            for (_, d) in a.send(&[0; 100]) {
                b.receive(&d, |_, _| true);
            }
            replies.extend(b.send(&[0; 10]).into_iter().map(|(_, d)| d));
            a.drain_acks();
        }
        a.update(time);
        assert!(a.stats()[0] > 0.0);
        a.reset();
        assert_eq!(a.counters(), [0; 11]);
        assert_eq!(a.next_packet_sequence(), 0);
        assert_eq!(a.drain_acks(), Vec::<u16>::new());
        after.push(a.stats());
    }
    assert!(after[0][0] > 0.0, "the port keeps rtt");
    assert_eq!(after[1], [0.0; 11], "C clears every statistic");
}

/// D13: C rounds the windows up to a power of two; the port uses them as given. With powers of
/// two (dream-net requires them for the sent and received windows) the two agree; with others
/// they can diverge. This pins that the divergence is real, so nobody relies on it.
#[test]
fn non_power_of_two_windows_differ_as_documented() {
    let settings = Settings {
        sent_packets_buffer_size: 100,
        received_packets_buffer_size: 100,
        fragment_reassembly_buffer_size: 3,
        ..Settings::defaults()
    };
    let mut verdicts = Vec::new();
    for kind in [Kind::Old, Kind::New] {
        let mut e = Ep::create(kind, &settings, 0.0);
        let regular = |s: u16| {
            let mut d = vec![0b0010_0000, s as u8, (s >> 8) as u8, 1];
            d.push(0xAA);
            d
        };
        // a packet 110 behind the newest: outside a 100 window, inside C's 128
        e.receive(&regular(200), |_, _| true);
        verdicts.push(e.receive(&regular(90), |_, _| true).is_some());
    }
    assert_eq!(verdicts, [false, true]);
}
