//! The wire format: round trips, conformance with serialize's own streams, and refusals.

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

use common::{PacketSpec, SectionSpec, encode, test_schema, test_schema_versioned};
use dream_net::wire::{DecodeError, Decoded, Hello, Layout, Malformed, WIRE_VERSION, decode};
use dream_net::{ChannelId, EventTypeId, Fingerprint, Schema, Seq16};
use proptest::prelude::*;
use serialize::{BitWriter, ReadStream, Stream, WriteStream};

fn decode_spec(layout: &Layout, schema: &Schema, packet: &[u8]) -> Result<PacketSpec, DecodeError> {
    let mut decoded = Decoded::default();
    decode(layout, packet, &mut decoded)?;
    Ok(PacketSpec {
        hello: decoded.hello,
        sections: decoded
            .sections
            .iter()
            .map(|s| {
                let messages = &decoded.messages[s.first as usize..(s.first + s.count) as usize];
                let reliable = layout.channel(s.channel).reliable;
                SectionSpec {
                    channel: s.channel,
                    first_id: if reliable { messages[0].id.0 } else { 0 },
                    deltas: if reliable {
                        messages
                            .windows(2)
                            .map(|w| u32::from(w[1].id.since(w[0].id)))
                            .collect()
                    } else {
                        Vec::new()
                    },
                    messages: messages
                        .iter()
                        .map(|m| {
                            assert_eq!(schema.event(m.event).unwrap().channel, s.channel);
                            (m.event, m.payload(packet).to_vec())
                        })
                        .collect(),
                }
            })
            .collect(),
    })
}

/// The same packet written with serialize's `Stream` idioms, to prove dream-net's writer
/// produces exactly what `serialize_int`/`serialize_int_relative`/`serialize_bytes` would.
fn encode_reference(schema: &Schema, spec: &PacketSpec) -> Vec<u8> {
    let channels = schema.channels().len() as i32;
    let events = schema.events().len() as i32;
    let mut buffer = vec![0u8; 64 * 1024];
    let mut s = WriteStream::new(&mut buffer);
    let mut kind = 0u32;
    let Ok(()) = s.serialize_bits(&mut kind, 2);
    let mut has_hello = spec.hello.is_some();
    let Ok(()) = s.serialize_bool(&mut has_hello);
    if let Some(hello) = spec.hello {
        let mut version = hello.wire_version;
        let Ok(()) = s.serialize_u16(&mut version);
        let mut fingerprint = hello.fingerprint.0;
        let Ok(()) = s.serialize_u128(&mut fingerprint);
    }
    let mut count = spec.sections.len() as i32;
    let Ok(()) = s.serialize_int(&mut count, 0, channels);
    for section in &spec.sections {
        let def = schema.channel(section.channel).unwrap();
        let mut channel = i32::from(section.channel.0);
        let Ok(()) = s.serialize_int(&mut channel, 0, channels - 1);
        let mut n = section.messages.len() as i32;
        let Ok(()) = s.serialize_int(&mut n, 1, schema.max_messages_per_packet() as i32);
        let reliable = def.delivery() == dream_net::Delivery::ReliableOrdered;
        let mut previous = i32::from(section.first_id);
        for (index, (event, payload)) in section.messages.iter().enumerate() {
            if reliable {
                if index == 0 {
                    let mut id = section.first_id;
                    let Ok(()) = s.serialize_u16(&mut id);
                } else {
                    let mut current = previous + section.deltas[index - 1] as i32;
                    let Ok(()) = s.serialize_int_relative(previous, &mut current);
                    previous = current;
                }
            }
            let mut e = event.0 as i32;
            let Ok(()) = s.serialize_int(&mut e, 0, events - 1);
            let mut len = payload.len() as i32;
            let Ok(()) = s.serialize_int(&mut len, 0, def.max_payload as i32);
            let mut bytes = payload.clone();
            let Ok(()) = s.serialize_bytes(&mut bytes);
        }
    }
    let Ok(()) = s.serialize_align();
    s.flush();
    let len = s.bytes_processed() as usize;
    buffer.truncate(len);
    buffer
}

/// Reads a packet back with serialize's checked `ReadStream`.
fn decode_reference(schema: &Schema, packet: &[u8]) -> serialize::Result<PacketSpec> {
    let channels = schema.channels().len() as i32;
    let events = schema.events().len() as i32;
    let mut s = ReadStream::new(packet, packet.len());
    let mut kind = 0u32;
    s.serialize_bits(&mut kind, 2)?;
    let mut has_hello = false;
    s.serialize_bool(&mut has_hello)?;
    let mut hello = None;
    if has_hello {
        let mut wire_version = 0u16;
        s.serialize_u16(&mut wire_version)?;
        let mut fingerprint = 0u128;
        s.serialize_u128(&mut fingerprint)?;
        hello = Some(Hello {
            wire_version,
            fingerprint: Fingerprint(fingerprint),
        });
    }
    let mut count = 0;
    s.serialize_int(&mut count, 0, channels)?;
    let mut sections = Vec::new();
    for _ in 0..count {
        let mut channel = 0;
        s.serialize_int(&mut channel, 0, channels - 1)?;
        let def = schema.channel(ChannelId(channel as u8)).unwrap();
        let reliable = def.delivery() == dream_net::Delivery::ReliableOrdered;
        let mut n = 0;
        s.serialize_int(&mut n, 1, schema.max_messages_per_packet() as i32)?;
        let mut section = SectionSpec {
            channel: ChannelId(channel as u8),
            first_id: 0,
            deltas: Vec::new(),
            messages: Vec::new(),
        };
        let mut previous = 0;
        for index in 0..n {
            if reliable {
                if index == 0 {
                    s.serialize_u16(&mut section.first_id)?;
                    previous = i32::from(section.first_id);
                } else {
                    let mut current = 0;
                    s.serialize_int_relative(previous, &mut current)?;
                    section.deltas.push((current - previous) as u32);
                    previous = current;
                }
            }
            let mut event = 0;
            s.serialize_int(&mut event, 0, events - 1)?;
            let mut len = 0;
            s.serialize_int(&mut len, 0, def.max_payload as i32)?;
            let mut payload = vec![0u8; len as usize];
            s.serialize_bytes(&mut payload)?;
            section.messages.push((EventTypeId(event as u32), payload));
        }
        sections.push(section);
    }
    s.serialize_align()?;
    Ok(PacketSpec { hello, sections })
}

fn spec_strategy() -> impl Strategy<Value = PacketSpec> {
    let schema = test_schema();
    let hello = Hello {
        wire_version: WIRE_VERSION,
        fingerprint: schema.fingerprint(),
    };
    let channel_sections = schema
        .channels()
        .iter()
        .map(|channel| {
            let events = channel.events.clone();
            let reliable = channel.delivery() == dream_net::Delivery::ReliableOrdered;
            let window = u32::from(channel.config.capacity);
            let max_payloads: Vec<u32> = events
                .iter()
                .map(|e| schema.event(*e).unwrap().max_payload.min(300))
                .collect();
            // seven deltas must fit one window
            let max_delta = ((window - 1) / 7).max(1);
            let id = channel.id;
            let message = (0..events.len()).prop_flat_map(move |i| {
                let event = events[i];
                prop::collection::vec(any::<u8>(), 0..=max_payloads[i] as usize)
                    .prop_map(move |payload| (event, payload))
            });
            (
                any::<bool>(),
                any::<u16>(),
                prop::collection::vec(message, 1..8),
                prop::collection::vec(1u32..=max_delta, 7),
            )
                .prop_map(move |(present, first_id, messages, raw_deltas)| {
                    if !present {
                        return None;
                    }
                    let mut deltas = Vec::new();
                    if reliable {
                        deltas.extend(raw_deltas.iter().take(messages.len() - 1));
                    }
                    Some(SectionSpec {
                        channel: id,
                        first_id: if reliable { first_id } else { 0 },
                        deltas,
                        messages,
                    })
                })
        })
        .collect::<Vec<_>>();
    (any::<bool>(), channel_sections, any::<u64>()).prop_map(move |(with_hello, sections, seed)| {
        let mut sections: Vec<SectionSpec> = sections.into_iter().flatten().collect();
        // section order on the wire is the sender's choice: rotate it
        if !sections.is_empty() {
            let len = sections.len();
            sections.rotate_left((seed as usize) % len);
        }
        PacketSpec {
            hello: with_hello.then_some(hello),
            sections,
        }
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn round_trips_and_matches_serialize_streams(spec in spec_strategy()) {
        let schema = test_schema();
        let layout = Layout::new(&schema);
        let packet = encode(&layout, &spec);
        prop_assert_eq!(&packet, &encode_reference(&schema, &spec));
        prop_assert_eq!(decode_spec(&layout, &schema, &packet).unwrap(), spec.clone());
        prop_assert_eq!(decode_reference(&schema, &packet).unwrap(), spec);
    }

    #[test]
    fn refuses_every_truncation(spec in spec_strategy()) {
        let schema = test_schema();
        let layout = Layout::new(&schema);
        let packet = encode(&layout, &spec);
        let mut decoded = Decoded::default();
        for len in 0..packet.len() {
            prop_assert!(decode(&layout, &packet[..len], &mut decoded).is_err());
        }
    }

    #[test]
    fn never_panics_on_random_bytes(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let schema = test_schema();
        let layout = Layout::new(&schema);
        let mut decoded = Decoded::default();
        let _ = decode(&layout, &bytes, &mut decoded);
    }

    #[test]
    fn accepted_packets_are_canonical(bytes in prop::collection::vec(any::<u8>(), 1..64)) {
        let schema = test_schema();
        let layout = Layout::new(&schema);
        if let Ok(spec) = decode_spec(&layout, &schema, &bytes) {
            prop_assert_eq!(encode(&layout, &spec), bytes);
        }
    }
}

fn malformed(layout: &Layout, packet: &[u8]) -> Malformed {
    let mut decoded = Decoded::default();
    match decode(layout, packet, &mut decoded) {
        Err(DecodeError::Malformed(m)) => m,
        other => panic!("expected a malformed refusal, got {other:?}"),
    }
}

/// Builds raw packets bit by bit: (value, bits) pairs, where `ALIGN` pads to a byte, then a
/// final align and the tail bytes.
fn raw(fields: &[(u32, u32)], tail: &[u8]) -> Vec<u8> {
    let mut buffer = vec![0u8; 1024];
    let mut w = BitWriter::new(&mut buffer);
    for &(value, bits) in fields {
        if bits == 0 {
            w.write_align();
        } else {
            w.write_bits(value, bits);
        }
    }
    w.write_align();
    if !tail.is_empty() {
        w.write_bytes(tail);
    }
    w.flush_bits();
    let len = w.bytes_written() as usize;
    buffer.truncate(len);
    buffer
}

// widths for the test schema: 3 channels -> channel 2 bits, section count 2 bits; 32 messages
// -> count 5 bits; 5 events -> 3 bits; lengths: reliable 1024 -> 11 bits, state 64 -> 7 bits,
// bulk 8000 -> 13 bits
const CHAT: u32 = 1;
const MOVE: u32 = 2;
const PING: u32 = 3;
const ALIGN: (u32, u32) = (0, 0);

#[test]
#[allow(clippy::too_many_lines)] // one assertion per refusal class, deliberately in one place
fn refuses_each_malformed_class() {
    let schema = test_schema();
    let layout = Layout::new(&schema);

    assert_eq!(malformed(&layout, &[]), Malformed::Truncated);
    assert_eq!(
        malformed(&layout, &raw(&[(1, 2)], &[])),
        Malformed::ReservedKind
    );
    // section count 1, channel 3 (out of range)
    assert_eq!(
        malformed(&layout, &raw(&[(0, 2), (0, 1), (1, 2), (3, 2)], &[])),
        Malformed::ValueOutOfRange
    );
    // two sections on channel 1 (state), one Ping each
    assert_eq!(
        malformed(
            &layout,
            &raw(
                &[
                    (0, 2),
                    (0, 1),
                    (2, 2),
                    (1, 2),
                    (0, 5),
                    (PING, 3),
                    (0, 7),
                    ALIGN,
                    (1, 2),
                    (0, 5),
                    (PING, 3),
                    (0, 7)
                ],
                &[]
            )
        ),
        Malformed::DuplicateChannel
    );
    // Chat on the state channel
    assert_eq!(
        malformed(
            &layout,
            &raw(
                &[(0, 2), (0, 1), (1, 2), (1, 2), (0, 5), (CHAT, 3), (0, 7)],
                &[]
            )
        ),
        Malformed::EventOnWrongChannel
    );
    // Move (max 64) is fine at 64 on state; Chat (max 256) at 300 on reliable (max 1024)
    assert_eq!(
        malformed(
            &layout,
            &raw(
                &[
                    (0, 2),
                    (0, 1),
                    (1, 2),
                    (0, 2),
                    (0, 5),
                    (0, 16),
                    (CHAT, 3),
                    (300, 11)
                ],
                &[0; 300]
            )
        ),
        Malformed::PayloadTooLarge
    );
    // length above the channel maximum: state max 64 in 7 bits, 100 fits the bits
    assert_eq!(
        malformed(
            &layout,
            &raw(
                &[(0, 2), (0, 1), (1, 2), (1, 2), (0, 5), (MOVE, 3), (100, 7)],
                &[]
            )
        ),
        Malformed::ValueOutOfRange
    );
    // two Chat ids 64 apart on a 64-message window: delta 64 is bucket [24,280]
    assert_eq!(
        malformed(
            &layout,
            &raw(
                &[
                    (0, 2),
                    (0, 1),
                    (1, 2),
                    (0, 2),
                    (1, 5),
                    (7, 16),
                    (CHAT, 3),
                    (0, 11),
                    ALIGN,
                    (0, 1),
                    (0, 1),
                    (0, 1),
                    (1, 1),
                    (64 - 24, 9),
                    (CHAT, 3),
                    (0, 11),
                ],
                &[]
            )
        ),
        Malformed::IdSpanExceedsWindow
    );
    // an ack-only packet with a padding bit set
    assert_eq!(
        malformed(&layout, &[0b0010_0000]),
        Malformed::NonzeroPadding
    );
    assert_eq!(malformed(&layout, &[0, 0]), Malformed::TrailingBytes);
    // message count field says 1-based 32 but only one message follows
    assert_eq!(
        malformed(
            &layout,
            &raw(
                &[(0, 2), (0, 1), (1, 2), (1, 2), (31, 5), (PING, 3), (0, 7)],
                &[]
            )
        ),
        Malformed::Truncated
    );
}

#[test]
fn foreign_hello_is_a_mismatch_not_garbage() {
    let ours = test_schema();
    let theirs = test_schema_versioned(2);
    let their_layout = Layout::new(&theirs);
    let spec = PacketSpec {
        hello: Some(their_layout.hello()),
        sections: Vec::new(),
    };
    let packet = encode(&their_layout, &spec);
    let mut decoded = Decoded::default();
    assert_eq!(
        decode(&Layout::new(&ours), &packet, &mut decoded),
        Err(DecodeError::Mismatch(Hello {
            wire_version: WIRE_VERSION,
            fingerprint: theirs.fingerprint(),
        }))
    );
    let old_version = Hello {
        wire_version: WIRE_VERSION + 1,
        fingerprint: ours.fingerprint(),
    };
    let packet = encode(
        &Layout::new(&ours),
        &PacketSpec {
            hello: Some(old_version),
            sections: Vec::new(),
        },
    );
    assert_eq!(
        decode(&Layout::new(&ours), &packet, &mut decoded),
        Err(DecodeError::Mismatch(old_version))
    );
}

#[test]
fn ack_only_packet_is_one_byte() {
    let layout = Layout::new(&test_schema());
    let packet = encode(
        &layout,
        &PacketSpec {
            hello: None,
            sections: Vec::new(),
        },
    );
    assert_eq!(packet, [0]);
}

#[test]
fn reliable_ids_wrap_inside_a_section() {
    let schema = test_schema();
    let layout = Layout::new(&schema);
    let chat = schema.event_id("Chat").unwrap();
    let spec = PacketSpec {
        hello: None,
        sections: vec![SectionSpec {
            channel: ChannelId(0),
            first_id: u16::MAX - 1,
            deltas: vec![1, 1, 5],
            messages: vec![
                (chat, b"a".to_vec()),
                (chat, b"b".to_vec()),
                (chat, b"c".to_vec()),
                (chat, b"d".to_vec()),
            ],
        }],
    };
    let packet = encode(&layout, &spec);
    let mut decoded = Decoded::default();
    decode(&layout, &packet, &mut decoded).unwrap();
    let ids: Vec<Seq16> = decoded.messages.iter().map(|m| m.id).collect();
    assert_eq!(ids, vec![Seq16(65534), Seq16(65535), Seq16(0), Seq16(5)]);
}

#[test]
fn every_relative_bucket_matches_serialize() {
    let mut b = Schema::builder(0).max_messages_per_packet(8);
    let wide = b
        .channel(dream_net::ChannelConfig::reliable_ordered("wide").with_capacity(32768))
        .unwrap();
    b.event("E", wide, 4).unwrap();
    let schema = b.build().unwrap();
    let layout = Layout::new(&schema);
    let e = schema.event_id("E").unwrap();
    // one delta per tier: 1, [2,6], [7,23], [24,280], [281,4377], [4378,...]
    let deltas = vec![1, 6, 23, 280, 4377, 20000];
    assert!(deltas.iter().sum::<u32>() < 32768);
    let spec = PacketSpec {
        hello: None,
        sections: vec![SectionSpec {
            channel: wide,
            first_id: 60000,
            deltas: deltas.clone(),
            messages: (0..7).map(|i| (e, vec![i; (i % 5) as usize])).collect(),
        }],
    };
    let packet = encode(&layout, &spec);
    assert_eq!(packet, encode_reference(&schema, &spec));
    assert_eq!(decode_spec(&layout, &schema, &packet).unwrap(), spec);
    assert_eq!(decode_reference(&schema, &packet).unwrap(), spec);
    for delta in deltas {
        let mut buffer = vec![0u8; 64];
        let mut s = WriteStream::new(&mut buffer);
        let mut current = 100 + delta as i32;
        let Ok(()) = s.serialize_int_relative(100, &mut current);
        assert_eq!(
            s.bits_processed(),
            dream_net::wire::relative_bits(delta),
            "delta {delta}"
        );
    }
}

#[test]
fn refuses_the_absolute_relative_tier() {
    // found by cargo fuzz: a fourth id encoded with serialize's 32-bit absolute tier for a
    // delta a bucket covers decoded fine but re-encoded differently
    let mut b = Schema::builder(3).max_messages_per_packet(16);
    let r = b
        .channel(dream_net::ChannelConfig::reliable_ordered("reliable").with_capacity(32))
        .unwrap();
    let s = b
        .channel(dream_net::ChannelConfig::unreliable_unordered("state").with_capacity(32))
        .unwrap();
    let t = b
        .channel(dream_net::ChannelConfig::reliable_ordered("tiny").with_capacity(4))
        .unwrap();
    b.event("A", r, 64).unwrap();
    b.event("B", r, 3000).unwrap();
    b.event("C", s, 32).unwrap();
    b.event("D", s, 0).unwrap();
    b.event("E", t, 16).unwrap();
    let schema = b.build().unwrap();
    let layout = Layout::new(&schema);
    let crash = [8, 9, 0, 0, 0, 0, 1, 0, 0, 4, 0, 0, 0, 0, 0];
    assert_eq!(malformed(&layout, &crash), Malformed::NonCanonical);
}
