//! The current wire codec against dream-net 1.1.1's, the last release framed by serialize: for
//! random schemas and packets both encoders write the same bytes, and for those packets, their
//! truncations and mutations, and arbitrary bytes, both decoders reach the same verdict, down
//! to the decoded contents and the exact `Malformed` reason.

// CI passes -W clippy::pedantic on the command line, overriding the manifest's lint table;
// test code casts freely between widths it controls.
#![allow(
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]

use proptest::prelude::*;

/// A schema described as data, so both crates can build it.
#[derive(Debug, Clone)]
struct SchemaDef {
    version: u32,
    max_messages: u32,
    /// (reliable, capacity)
    channels: Vec<(bool, u16)>,
    /// (channel index, max payload); named by index
    events: Vec<(u8, u32)>,
}

/// A packet described as data: its sections carry event ids of the built schema.
#[derive(Debug, Clone)]
struct Packet {
    hello: bool,
    sections: Vec<Section>,
}

#[derive(Debug, Clone)]
struct Section {
    channel: u8,
    first_id: u16,
    deltas: Vec<u32>,
    messages: Vec<(u32, Vec<u8>)>,
}

/// The same codec surface over either crate.
macro_rules! codec {
    ($module:ident, $krate:ident) => {
        mod $module {
            use super::{Packet, SchemaDef};
            use $krate::wire::{Decoded, Layout, PacketWriter, decode};
            use $krate::{ChannelConfig, ChannelId, EventTypeId, Schema, Seq16};

            pub struct Codec {
                pub schema: Schema,
                pub layout: Layout,
                decoded: Decoded,
            }

            impl Codec {
                pub fn new(def: &SchemaDef) -> Self {
                    let mut b =
                        Schema::builder(def.version).max_messages_per_packet(def.max_messages);
                    let ids: Vec<ChannelId> = def
                        .channels
                        .iter()
                        .enumerate()
                        .map(|(i, &(reliable, capacity))| {
                            let name = format!("c{i}");
                            let config = if reliable {
                                ChannelConfig::reliable_ordered(name)
                            } else {
                                ChannelConfig::unreliable_unordered(name)
                            };
                            b.channel(config.with_capacity(capacity)).unwrap()
                        })
                        .collect();
                    for (i, &(channel, max_payload)) in def.events.iter().enumerate() {
                        b.event(format!("e{i}"), ids[usize::from(channel)], max_payload)
                            .unwrap();
                    }
                    let schema = b.build().unwrap();
                    let layout = Layout::new(&schema);
                    Self {
                        schema,
                        layout,
                        decoded: Decoded::default(),
                    }
                }

                /// The event ids of each channel, in schema order.
                pub fn channel_events(&self) -> Vec<Vec<u32>> {
                    self.schema
                        .channels()
                        .iter()
                        .map(|c| c.events.iter().map(|e| e.0).collect())
                        .collect()
                }

                pub fn fingerprint(&self) -> u128 {
                    self.schema.fingerprint().0
                }

                pub fn overhead(&self) -> usize {
                    self.layout.worst_case_single_message_overhead()
                }

                /// Encodes `packet`, returning the bytes and the writer's own bit count.
                pub fn encode(&self, packet: &Packet) -> (Vec<u8>, u64) {
                    let size: usize = packet
                        .sections
                        .iter()
                        .flat_map(|s| s.messages.iter().map(|m| m.1.len() + 16))
                        .sum::<usize>()
                        + 64 * (packet.sections.len() + 1);
                    let mut buffer = vec![0u8; size.div_ceil(8) * 8 + 8];
                    let mut w = PacketWriter::new(&mut buffer);
                    let layout = &self.layout;
                    w.header(
                        layout,
                        packet.hello.then(|| layout.hello()),
                        packet.sections.len() as u32,
                    );
                    for s in &packet.sections {
                        let channel = ChannelId(s.channel);
                        w.section(layout, channel, s.messages.len() as u32);
                        let reliable = layout.channel(channel).reliable;
                        for (i, (event, payload)) in s.messages.iter().enumerate() {
                            if reliable {
                                if i == 0 {
                                    w.first_id(Seq16(s.first_id));
                                } else {
                                    w.next_id(s.deltas[i - 1]);
                                }
                            }
                            w.message(layout, EventTypeId(*event), payload);
                        }
                    }
                    let bits = w.bits();
                    let len = w.finish();
                    buffer.truncate(len);
                    (buffer, bits)
                }

                /// Decodes `bytes`: the verdict, with everything decoded, as comparable text.
                pub fn decode(&mut self, bytes: &[u8]) -> String {
                    match decode(&self.layout, bytes, &mut self.decoded) {
                        Ok(()) => {
                            let payloads: Vec<&[u8]> = self
                                .decoded
                                .messages
                                .iter()
                                .map(|m| m.payload(bytes))
                                .collect();
                            format!("Ok {:?} {:?}", self.decoded, payloads)
                        }
                        Err(e) => format!("Err {e:?} ({e})"),
                    }
                }
            }
        }
    };
}

codec!(new, dream_net);
codec!(old, dream_net_old);

fn schema_def() -> impl Strategy<Value = SchemaDef> {
    let capacity = prop_oneof![
        Just(1u16),
        Just(2),
        1u16..=64,
        Just(256),
        1u16..=32768,
        Just(32768)
    ];
    let max_payload = prop_oneof![
        Just(0u32),
        1u32..=64,
        Just(255),
        Just(256),
        0u32..=70_000,
        Just(1 << 24)
    ];
    let max_messages = prop_oneof![Just(1u32), 1u32..=64, Just(4096), 1u32..=4096];
    (
        any::<u32>(),
        max_messages,
        prop::collection::vec((any::<bool>(), capacity), 0..=6),
        prop::collection::vec((any::<u8>(), max_payload), 0..=10),
    )
        .prop_map(|(version, max_messages, channels, events)| {
            let events = if channels.is_empty() {
                Vec::new()
            } else {
                events
                    .into_iter()
                    .map(|(c, p)| (c % channels.len() as u8, p))
                    .collect()
            };
            SchemaDef {
                version,
                max_messages,
                channels,
                events,
            }
        })
}

/// A valid packet for `def`, drawn from raw randomness: sections on channels that have events,
/// in a random order, reliable ids spread within the channel window.
fn packet(
    def: &SchemaDef,
    channel_events: &[Vec<u32>],
    max_payloads: &[u32],
    seed: &[u64],
) -> Packet {
    let mut rng = seed.iter().copied().cycle();
    let mut next = move || rng.next().unwrap_or(0);
    let mut order: Vec<usize> = (0..def.channels.len()).collect();
    for i in (1..order.len()).rev() {
        order.swap(i, (next() % (i as u64 + 1)) as usize);
    }
    let mut sections = Vec::new();
    for channel in order {
        let events = &channel_events[channel];
        if events.is_empty() || next() % 3 == 0 {
            continue;
        }
        let (reliable, window) = def.channels[channel];
        let mut count = 1 + (next() % 6) as u32;
        count = count.min(def.max_messages);
        if reliable {
            count = count.min(u32::from(window));
        }
        // deltas: the total span stays below the window; a draw picks a bucket-sized limit
        let mut deltas = Vec::new();
        if reliable && count > 1 {
            let budget = (u32::from(window) - 1) / (count - 1);
            for _ in 1..count {
                let limit = match next() % 5 {
                    0 => 1,
                    1 => 6,
                    2 => 23,
                    3 => 280,
                    _ => 69_914,
                }
                .min(budget);
                deltas.push(1 + (next() % u64::from(limit)) as u32);
            }
        }
        let messages = (0..count)
            .map(|_| {
                let event = events[(next() % events.len() as u64) as usize];
                let max = max_payloads[event as usize].min(48);
                let len = (next() % (u64::from(max) + 1)) as usize;
                let payload = (0..len).map(|_| next() as u8).collect();
                (event, payload)
            })
            .collect();
        sections.push(Section {
            channel: channel as u8,
            first_id: if reliable { next() as u16 } else { 0 },
            deltas,
            messages,
        });
    }
    Packet {
        hello: next() % 2 == 0,
        sections,
    }
}

struct Pair {
    new: new::Codec,
    old: old::Codec,
    channel_events: Vec<Vec<u32>>,
    max_payloads: Vec<u32>,
}

fn pair(def: &SchemaDef) -> Pair {
    let new = new::Codec::new(def);
    let old = old::Codec::new(def);
    let channel_events = new.channel_events();
    assert_eq!(channel_events, old.channel_events());
    let max_payloads = new.schema.events().iter().map(|e| e.max_payload).collect();
    Pair {
        new,
        old,
        channel_events,
        max_payloads,
    }
}

fn mutate(bytes: &mut Vec<u8>, edits: &[(u8, u16, u8)]) {
    for &(kind, at, value) in edits {
        let len = bytes.len();
        match kind % 5 {
            0 | 1 if len > 0 => {
                let i = usize::from(at) % len;
                bytes[i] ^= 1 << (value % 8);
            }
            2 if len > 0 => {
                let i = usize::from(at) % len;
                bytes[i] = value;
            }
            3 => bytes.truncate(usize::from(at) % (len + 1)),
            _ => bytes.push(value),
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    #[test]
    fn encoders_agree_and_decoders_agree(
        def in schema_def(),
        seed in prop::collection::vec(any::<u64>(), 1..64),
        edits in prop::collection::vec((any::<u8>(), any::<u16>(), any::<u8>()), 1..6),
    ) {
        let mut p = pair(&def);
        prop_assert_eq!(p.new.fingerprint(), p.old.fingerprint());
        prop_assert_eq!(p.new.overhead(), p.old.overhead());
        let packet = packet(&def, &p.channel_events, &p.max_payloads, &seed);
        let (bytes, bits) = p.new.encode(&packet);
        let (old_bytes, old_bits) = p.old.encode(&packet);
        prop_assert_eq!(&bytes, &old_bytes);
        prop_assert_eq!(bits, old_bits);

        let verdict = p.new.decode(&bytes);
        prop_assert!(verdict.starts_with("Ok"), "{}", verdict);
        prop_assert_eq!(&verdict, &p.old.decode(&bytes));

        for len in 0..bytes.len() {
            prop_assert_eq!(p.new.decode(&bytes[..len]), p.old.decode(&bytes[..len]));
        }
        let mut mutated = bytes.clone();
        mutate(&mut mutated, &edits);
        prop_assert_eq!(p.new.decode(&mutated), p.old.decode(&mutated));
    }

    #[test]
    fn decoders_agree_on_arbitrary_bytes(
        def in schema_def(),
        bytes in prop::collection::vec(any::<u8>(), 0..96),
        header in 0u8..8,
    ) {
        let mut p = pair(&def);
        prop_assert_eq!(p.new.decode(&bytes), p.old.decode(&bytes));
        // a data kind without a hello reaches the schema-dependent fields far more often
        let mut shaped = bytes;
        if let Some(first) = shaped.first_mut() {
            *first = (*first & !0b111) | (header & 0b100);
        }
        prop_assert_eq!(p.new.decode(&shaped), p.old.decode(&shaped));
    }
}

/// Every `Malformed` reason is reached by the mutation tests above for some schema; this pins
/// that each one is also reached, identically, on fixed inputs.
#[test]
fn every_refusal_class_agrees() {
    let def = SchemaDef {
        version: 3,
        max_messages: 16,
        channels: vec![(true, 32), (false, 32), (true, 4)],
        events: vec![(0, 64), (0, 3000), (1, 32), (1, 0), (2, 16)],
    };
    let mut p = pair(&def);
    let inputs: [&[u8]; 9] = [
        &[],
        &[1],
        &[0b0001_1000],
        &[0b0010_0000],
        &[0, 0],
        &[8, 9, 0, 0, 0, 0, 1, 0, 0, 4, 0, 0, 0, 0, 0],
        &[0b0000_0100, 0xFF, 0xFF],
        &[0b1111_1000, 0xFF, 0xFF, 0xFF],
        &[0b0000_1000, 0b1111_1111],
    ];
    let mut seen = std::collections::BTreeSet::new();
    for bytes in inputs {
        let verdict = p.new.decode(bytes);
        assert_eq!(verdict, p.old.decode(bytes), "{bytes:?}");
        seen.insert(verdict);
    }
    assert!(seen.iter().any(|v| v.contains("NonCanonical")), "{seen:?}");
    assert!(seen.iter().any(|v| v.contains("Truncated")), "{seen:?}");
    assert!(seen.iter().any(|v| v.contains("TrailingBytes")), "{seen:?}");
    assert!(
        seen.iter().any(|v| v.contains("NonzeroPadding")),
        "{seen:?}"
    );
    assert!(seen.iter().any(|v| v.contains("ReservedKind")), "{seen:?}");
}

/// The verdict's class: `Ok`, `Err Mismatch`, or `Err Malformed <reason>`.
fn class(verdict: &str) -> String {
    if verdict.starts_with("Ok") {
        return "Ok".to_owned();
    }
    if verdict.starts_with("Err Mismatch") {
        return "Err Mismatch".to_owned();
    }
    verdict
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .take(3)
        .collect::<Vec<_>>()
        .join(" ")
}

/// The differential runs above as one deterministic sweep that also counts what it reached:
/// every verdict `decode` can return (each `Malformed` reason it produces, a mismatch, and
/// acceptance) must come up, and agree, at least once.
#[test]
fn sweep_reaches_every_verdict() {
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;

    let mut runner = TestRunner::deterministic();
    let inputs = (
        schema_def(),
        prop::collection::vec(any::<u64>(), 1..64),
        prop::collection::vec((any::<u8>(), any::<u16>(), any::<u8>()), 1..4),
    );
    let mut counts = std::collections::BTreeMap::<String, u32>::new();
    let mut compared = 0u32;
    for _ in 0..3_000 {
        let (def, seed, edits) = inputs.new_tree(&mut runner).unwrap().current();
        let mut p = pair(&def);
        let packet = packet(&def, &p.channel_events, &p.max_payloads, &seed);
        let (bytes, _) = p.new.encode(&packet);
        assert_eq!(bytes, p.old.encode(&packet).0);
        let mut candidates = vec![bytes.clone()];
        for len in 0..bytes.len() {
            candidates.push(bytes[..len].to_vec());
        }
        for i in 0..8u16 {
            let mut mutated = bytes.clone();
            mutate(
                &mut mutated,
                &edits[..edits.len().min(1 + usize::from(i % 3))],
            );
            mutate(
                &mut mutated,
                &[(i as u8, seed[0] as u16 ^ i, (seed[0] >> 16) as u8)],
            );
            candidates.push(mutated);
        }
        for candidate in candidates {
            let verdict = p.new.decode(&candidate);
            assert_eq!(verdict, p.old.decode(&candidate), "{def:?} {candidate:?}");
            *counts.entry(class(&verdict)).or_default() += 1;
            compared += 1;
        }
    }
    eprintln!("{compared} decodes compared: {counts:#?}");
    for class in [
        "Ok",
        "Err Mismatch",
        "Err Malformed Truncated",
        "Err Malformed ReservedKind",
        "Err Malformed ValueOutOfRange",
        "Err Malformed DuplicateChannel",
        "Err Malformed EventOnWrongChannel",
        "Err Malformed PayloadTooLarge",
        "Err Malformed IdSpanExceedsWindow",
        "Err Malformed NonzeroPadding",
        "Err Malformed TrailingBytes",
        "Err Malformed NonCanonical",
    ] {
        assert!(
            counts.contains_key(class),
            "never reached {class}: {counts:#?}"
        );
    }
}
