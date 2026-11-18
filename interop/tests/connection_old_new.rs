//! dream-net 1.1.1's `Connection` (over the `reliable` 1.3.4 Rust port) and this tree's, in one
//! process, talking to each other both ways round over seeded links that lose, duplicate, delay
//! and reorder datagrams: the handshake, reliable-ordered streams both ways (fragmented and
//! not), unreliable traffic, queue refusals, and schema mismatch detection. Reliable events
//! arrive exactly once and in order across the old/new boundary; unreliable events arrive
//! intact and at most once.

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

mod connection_common;

use std::collections::BTreeSet;

use connection_common::{Duo, End, Faults, Kind, Limits, Rng, Sent, check, payload};

const DT: f64 = 1.0 / 60.0;

/// A reliable stream: which event carries it, its payload sizes, and how far it got.
struct Stream {
    id: u8,
    event: &'static str,
    min: usize,
    max: usize,
    sent: u32,
    received: u32,
    refused: u32,
}

impl Stream {
    fn new(id: u8, event: &'static str, min: usize, max: usize) -> Self {
        Self {
            id,
            event,
            min,
            max,
            sent: 0,
            received: 0,
            refused: 0,
        }
    }

    /// Queues up to `n` more events, stopping at the first refusal (retried next frame).
    fn feed(&mut self, end: &mut End, rng: &mut Rng, n: u32) {
        for _ in 0..n {
            let len = self.min + rng.below((self.max - self.min + 1) as u64) as usize;
            match end.send(self.event, &payload(self.id, self.sent, len)) {
                Sent::Queued => self.sent += 1,
                Sent::QueueFull => {
                    self.refused += 1;
                    break;
                }
                Sent::Refused => panic!("{} refused", self.event),
            }
        }
    }
}

/// Unreliable traffic one way: what was sent and what arrived.
#[derive(Default)]
struct Loose {
    sent: u32,
    got: BTreeSet<u32>,
}

/// Checks every delivery: reliable streams in exact order, unreliable ones intact and unique.
fn absorb(
    got: Vec<(u32, u8, Vec<u8>)>,
    streams: &mut [&mut Stream],
    loose: &mut Loose,
    side: &str,
) {
    for (_event, _channel, p) in got {
        if p.is_empty() {
            continue; // Ping
        }
        let (stream, n) = check(&p);
        if stream == 9 {
            assert!(n < loose.sent, "{side}: unreliable {n} was never sent");
            assert!(
                loose.got.insert(n),
                "{side}: unreliable {n} delivered twice"
            );
            continue;
        }
        let s = streams
            .iter_mut()
            .find(|s| s.id == stream)
            .unwrap_or_else(|| panic!("{side}: stream {stream} delivered here"));
        assert_eq!(
            n, s.received,
            "{side}: stream {stream} out of order or duplicated"
        );
        s.received += 1;
    }
}

/// Old and new ends exchange every kind of traffic over a hostile link, then heal it.
fn session(a_kind: Kind, b_kind: Kind, seed: u64) {
    let tag = format!("{a_kind:?}->{b_kind:?} seed {seed}");
    let a = End::new(a_kind, 1, Limits::default(), 0.0);
    let b = End::new(b_kind, 1, Limits::default(), 0.0);
    assert_eq!(a.fingerprint(), b.fingerprint(), "{tag}");
    let mut duo = Duo::new(a, b, Faults::lossy(), seed);
    assert!(duo.handshake(DT, 600), "{tag}: no handshake");
    assert_eq!(duo.a.take_event().as_deref(), Some("Established"), "{tag}");
    assert_eq!(duo.b.take_event().as_deref(), Some("Established"), "{tag}");

    let mut rng = Rng::new(seed ^ 0xabcd);
    // b -> a: small reliable, fragmented reliable; a -> b: reliable
    let mut chat = Stream::new(0, "Chat", 5, 256);
    let mut blob = Stream::new(1, "Blob", 1192, 8000);
    let mut spawn = Stream::new(2, "Spawn", 5, 1024);
    let (mut to_a, mut to_b) = (Loose::default(), Loose::default());
    for frame in 0..1500u32 {
        chat.feed(&mut duo.b, &mut rng, 6);
        if frame.is_multiple_of(4) {
            blob.feed(&mut duo.b, &mut rng, 1);
        }
        spawn.feed(&mut duo.a, &mut rng, 3);
        for (end, loose) in [(&mut duo.b, &mut to_a), (&mut duo.a, &mut to_b)] {
            let len = 5 + rng.below(60) as usize;
            if end.send("Move", &payload(9, loose.sent, len)) == Sent::Queued {
                loose.sent += 1;
            }
            let _ = end.send("Ping", &[]);
        }
        duo.step(DT);
        absorb(duo.a.drain(), &mut [&mut chat, &mut blob], &mut to_a, &tag);
        absorb(duo.b.drain(), &mut [&mut spawn], &mut to_b, &tag);
        assert!(
            !duo.a.failed() && !duo.b.failed(),
            "{tag}: {}",
            duo.a.state()
        );
    }
    // heal, and let every reliable event arrive
    duo.set_faults(Faults::PERFECT);
    for _ in 0..3000 {
        duo.step(DT);
        absorb(duo.a.drain(), &mut [&mut chat, &mut blob], &mut to_a, &tag);
        absorb(duo.b.drain(), &mut [&mut spawn], &mut to_b, &tag);
        if chat.received == chat.sent && blob.received == blob.sent && spawn.received == spawn.sent
        {
            break;
        }
    }
    for s in [&chat, &blob, &spawn] {
        assert_eq!(s.received, s.sent, "{tag}: stream {} incomplete", s.id);
        assert!(s.sent > 50, "{tag}: stream {} barely ran", s.id);
    }
    // the windows filled and refused, and nothing reliable was dropped for it
    assert!(chat.refused > 0, "{tag}: the chat window never filled");
    // a lossy link: reliable events were resent, fragments crossed, unreliable ones were lost
    assert!(duo.b.counters()[8] > 0, "{tag}: no resends");
    assert!(duo.b.reliable_counters()[7] > 0, "{tag}: no fragments sent");
    assert!(
        duo.a.reliable_counters()[8] > 0,
        "{tag}: no fragments received"
    );
    for loose in [&to_a, &to_b] {
        assert!(!loose.got.is_empty(), "{tag}: no unreliable delivery");
        assert!(
            (loose.got.len() as u32) < loose.sent,
            "{tag}: nothing unreliable lost"
        );
    }
    assert!(duo.a_to_b.duplicated > 0 && duo.b_to_a.lost > 0, "{tag}");
}

#[test]
fn old_and_new_exchange_every_kind_of_traffic() {
    for seed in 0..3 {
        session(Kind::Old, Kind::New, 100 + seed);
        session(Kind::New, Kind::Old, 200 + seed);
    }
}

/// The control: the same sessions between two old ends and two new ends.
#[test]
fn old_old_and_new_new_sessions_pass_the_same_checks() {
    session(Kind::Old, Kind::Old, 300);
    session(Kind::New, Kind::New, 300);
}

/// A schema difference is detected by both ends, old or new, with both fingerprints, and
/// nothing is delivered.
#[test]
fn schema_mismatch_is_detected_across_old_and_new() {
    for (a_kind, b_kind) in [(Kind::Old, Kind::New), (Kind::New, Kind::Old)] {
        let a = End::new(a_kind, 1, Limits::default(), 0.0);
        let b = End::new(b_kind, 2, Limits::default(), 0.0);
        let (fa, fb) = (a.fingerprint(), b.fingerprint());
        assert_ne!(fa, fb);
        let mut duo = Duo::new(a, b, Faults::lossy(), 9);
        let _ = duo.b.send("Chat", &payload(0, 0, 8));
        let _ = duo.a.send("Move", &payload(9, 0, 8));
        for _ in 0..240 {
            duo.step(DT);
        }
        assert_eq!(duo.a.state(), duo.a.schema_mismatch(fb), "{a_kind:?}");
        assert_eq!(duo.b.state(), duo.b.schema_mismatch(fa), "{b_kind:?}");
        assert!(duo.a.drain().is_empty() && duo.b.drain().is_empty());
        let a_event = duo.a.take_event().unwrap();
        assert!(a_event.starts_with("Failed(SchemaMismatch"), "{a_event}");
    }
}

/// A receiver that stops polling fills its inbox: reliable packets are refused (left unacked)
/// rather than dropped, and once it polls again everything arrives in order, across old and
/// new.
#[test]
fn backpressure_holds_reliable_events_across_old_and_new() {
    for (a_kind, b_kind) in [(Kind::Old, Kind::New), (Kind::New, Kind::Old)] {
        let limits = Limits {
            max_pending_events: 8,
            ..Limits::default()
        };
        let a = End::new(a_kind, 1, limits, 0.0);
        let b = End::new(b_kind, 1, limits, 0.0);
        let mut duo = Duo::new(a, b, Faults::PERFECT, 5);
        assert!(duo.handshake(DT, 60));
        let mut rng = Rng::new(17);
        let mut chat = Stream::new(0, "Chat", 5, 64);
        let mut to_a = Loose::default();
        for frame in 0..600 {
            chat.feed(&mut duo.b, &mut rng, 8);
            duo.step(DT);
            // a stalls for 200 frames at a time
            if (frame / 200) % 2 == 1 {
                absorb(duo.a.drain(), &mut [&mut chat], &mut to_a, "stall");
            } else {
                assert!(duo.a.inbox_len() <= 8 + 64);
            }
        }
        for _ in 0..600 {
            duo.step(DT);
            absorb(duo.a.drain(), &mut [&mut chat], &mut to_a, "stall");
        }
        assert_eq!(chat.received, chat.sent);
        assert!(duo.a.counters()[14] > 0, "no packet was refused");
        assert!(chat.refused > 0, "the sender was never refused");
    }
}
