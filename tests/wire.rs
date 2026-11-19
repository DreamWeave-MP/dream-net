//! The wire format: round trips, canonical encoding, and refusals. The bytes themselves are
//! pinned in `tests/wire_golden.rs`.

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

use common::{
    PacketSpec, SectionSpec, decode_spec, encode, spec_strategy, test_schema, test_schema_versioned,
};
use dream_net::wire::{
    DecodeError, Decoded, Hello, Layout, Malformed, PacketWriter, WIRE_VERSION, decode,
};
use dream_net::{ChannelConfig, ChannelId, Fingerprint, Schema, Seq16};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn round_trips(spec in spec_strategy()) {
        let schema = test_schema();
        let layout = Layout::new(&schema);
        let (packet, bits) = encode_with_bits(&layout, &spec);
        prop_assert_eq!(packet.len() as u64, bits.div_ceil(8));
        prop_assert_eq!(&packet, &raw_packet(&schema, &spec));
        prop_assert_eq!(decode_spec(&layout, &schema, &packet).unwrap(), spec);
    }

    #[test]
    fn refuses_every_truncation(spec in spec_strategy()) {
        let schema = test_schema();
        let layout = Layout::new(&schema);
        let packet = encode(&layout, &spec);
        let mut decoded = Decoded::default();
        for len in 0..packet.len() {
            prop_assert!(decode(&layout, &packet[..len], &mut decoded).is_err());
            // every read of a prefix returns what it returned on the whole packet until one
            // runs out, so a truncation is always reported as one
            prop_assert_eq!(
                decode(&layout, &packet[..len], &mut decoded),
                Err(DecodeError::Malformed(Malformed::Truncated))
            );
        }
    }

    #[test]
    fn refuses_trailing_bytes(
        spec in spec_strategy(),
        tail in prop::collection::vec(any::<u8>(), 1..16),
    ) {
        let layout = Layout::new(&test_schema());
        let mut packet = encode(&layout, &spec);
        packet.extend_from_slice(&tail);
        prop_assert_eq!(malformed(&layout, &packet), Malformed::TrailingBytes);
    }

    #[test]
    fn refuses_nonzero_trailer_padding(spec in spec_strategy(), bit in 0u64..7) {
        let layout = Layout::new(&test_schema());
        let (mut packet, bits) = encode_with_bits(&layout, &spec);
        let pad = (8 - bits % 8) % 8;
        if bit < pad {
            let at = bits + bit;
            packet[(at / 8) as usize] |= 1 << (at % 8);
            prop_assert_eq!(malformed(&layout, &packet), Malformed::NonzeroPadding);
        }
    }

    #[test]
    fn mutated_packets_never_panic_and_accepted_ones_are_canonical(
        spec in spec_strategy(),
        flips in prop::collection::vec(any::<u16>(), 1..8),
    ) {
        let schema = test_schema();
        let layout = Layout::new(&schema);
        let mut packet = encode(&layout, &spec);
        for flip in flips {
            let at = usize::from(flip >> 3) % packet.len();
            packet[at] ^= 1 << (flip & 7);
        }
        if let Ok(decoded) = decode_spec(&layout, &schema, &packet) {
            prop_assert_eq!(encode(&layout, &decoded), packet);
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
///
/// This writes the format from its definition, one bit at a time (least significant first,
/// stream bit `k` in bit `k % 8` of byte `k / 8`), independently of dream-net's writer.
fn raw(fields: &[(u32, u32)], tail: &[u8]) -> Vec<u8> {
    let mut stream: Vec<bool> = Vec::new();
    let align = |stream: &mut Vec<bool>| {
        while !stream.len().is_multiple_of(8) {
            stream.push(false);
        }
    };
    for &(value, bits) in fields {
        if bits == 0 {
            align(&mut stream);
        } else {
            stream.extend((0..bits).map(|i| value >> i & 1 == 1));
        }
    }
    align(&mut stream);
    let mut bytes: Vec<u8> = stream
        .chunks(8)
        .map(|byte| {
            byte.iter()
                .enumerate()
                .fold(0, |b, (i, &bit)| b | u8::from(bit) << i)
        })
        .collect();
    bytes.extend_from_slice(tail);
    bytes
}

fn bits_required(min: u32, max: u32) -> u32 {
    if min == max {
        0
    } else {
        32 - (max - min).leading_zeros()
    }
}

/// `spec` for `schema` written field by field with [`raw`], from the grammar in the wire
/// module's docs: what any encoder of wire format v2 must produce.
fn raw_packet(schema: &Schema, spec: &PacketSpec) -> Vec<u8> {
    let channels = schema.channels().len() as u32;
    let events = schema.events().len() as u32;
    let max_messages = schema.max_messages_per_packet();
    let mut fields = vec![(0, 2), (u32::from(spec.hello.is_some()), 1)];
    if let Some(hello) = spec.hello {
        fields.push((u32::from(hello.wire_version), 16));
        fields.extend((0..4).map(|i| ((hello.fingerprint.0 >> (32 * i)) as u32, 32)));
    }
    fields.push((spec.sections.len() as u32, bits_required(0, channels)));
    let mut tail = Vec::new();
    // a payload is aligned, so everything before it ends on a byte boundary: writing the
    // stream in pieces that end at each payload restarts the bit count where it already was
    let flush = |fields: &mut Vec<(u32, u32)>, tail: &mut Vec<u8>| {
        // zero-width fields occupy nothing (and would mean an align to `raw`)
        fields.retain(|&(_, bits)| bits > 0);
        let bytes = raw(fields, tail);
        fields.clear();
        tail.clear();
        bytes
    };
    let mut out = Vec::new();
    for section in &spec.sections {
        let def = schema.channel(section.channel).unwrap();
        fields.push((u32::from(section.channel.0), bits_required(0, channels - 1)));
        fields.push((
            section.messages.len() as u32 - 1,
            bits_required(1, max_messages),
        ));
        let reliable = def.delivery() == dream_net::Delivery::ReliableOrdered;
        for (index, (event, payload)) in section.messages.iter().enumerate() {
            if reliable {
                if index == 0 {
                    fields.push((u32::from(section.first_id), 16));
                } else {
                    fields.extend(relative_fields(section.deltas[index - 1]));
                }
            }
            fields.push((event.0, bits_required(0, events - 1)));
            fields.push((payload.len() as u32, bits_required(0, def.max_payload)));
            tail.extend_from_slice(payload);
            out.extend(flush(&mut fields, &mut tail));
        }
    }
    out.extend(flush(&mut fields, &mut tail));
    out
}

/// serialize's `int_relative` fields for a forward delta: a one-bit fast path, then a
/// unary bucket choice and the offset within the bucket.
fn relative_fields(delta: u32) -> Vec<(u32, u32)> {
    if delta == 1 {
        return vec![(1, 1)];
    }
    let mut fields = vec![(0, 1)];
    for (min, max) in [(2, 6), (7, 23), (24, 280), (281, 4377), (4378, 69914)] {
        if delta <= max {
            fields.push((1, 1));
            fields.push((delta - min, bits_required(min, max)));
            return fields;
        }
        fields.push((0, 1));
    }
    unreachable!("delta {delta} is past every bucket")
}

/// [`common::encode`], also returning the bits written before the trailer's padding.
fn encode_with_bits(layout: &Layout, spec: &PacketSpec) -> (Vec<u8>, u64) {
    let mut buffer = vec![0u8; 64 * 1024];
    let mut w = PacketWriter::new(&mut buffer);
    w.header(layout, spec.hello, spec.sections.len() as u32);
    for section in &spec.sections {
        w.section(layout, section.channel, section.messages.len() as u32);
        let reliable = layout.channel(section.channel).reliable;
        for (index, (event, payload)) in section.messages.iter().enumerate() {
            if reliable {
                if index == 0 {
                    w.first_id(Seq16(section.first_id));
                } else {
                    w.next_id(section.deltas[index - 1]);
                }
            }
            w.message(layout, *event, payload);
        }
    }
    let bits = w.bits();
    let len = w.finish();
    buffer.truncate(len);
    (buffer, bits)
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
fn decode_errors_are_std_errors() {
    use std::error::Error as _;

    let schema = test_schema();
    let layout = Layout::new(&schema);
    let mut decoded = Decoded::default();

    let truncated = decode(&layout, &[], &mut decoded).unwrap_err();
    assert_eq!(truncated.to_string(), "truncated packet");
    let why = truncated
        .source()
        .expect("a malformed packet's reason is its source");
    assert_eq!(why.downcast_ref(), Some(&Malformed::Truncated));
    assert!(why.source().is_none());

    let foreign = Hello {
        wire_version: WIRE_VERSION + 1,
        fingerprint: Fingerprint(0x0123_4567_89ab_cdef_0011_2233_4455_6677),
    };
    let packet = encode(
        &layout,
        &PacketSpec {
            hello: Some(foreign),
            sections: Vec::new(),
        },
    );
    let mismatch = decode(&layout, &packet, &mut decoded).unwrap_err();
    assert_eq!(
        mismatch.to_string(),
        format!(
            "mismatched hello: wire version {}, schema fingerprint 0123456789abcdef0011223344556677",
            WIRE_VERSION + 1
        )
    );
    assert!(mismatch.source().is_none());

    let boxed: Box<dyn std::error::Error + Send + Sync> = mismatch.into();
    assert_eq!(boxed.downcast_ref(), Some(&mismatch));
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
fn every_relative_bucket_round_trips() {
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
    assert_eq!(packet, raw_packet(&schema, &spec));
    assert_eq!(decode_spec(&layout, &schema, &packet).unwrap(), spec);
    // fast path, then 1 + bucket index flag bits and the bucket's width: 3, 5, 9, 13, 17
    let expected = [1, 2 + 3, 3 + 5, 4 + 9, 5 + 13, 6 + 17];
    for (delta, bits) in deltas.into_iter().zip(expected) {
        assert_eq!(dream_net::wire::relative_bits(delta), bits, "delta {delta}");
        let fields = relative_fields(delta);
        assert_eq!(
            fields.iter().map(|f| u64::from(f.1)).sum::<u64>(),
            bits,
            "delta {delta}"
        );
    }
    // the edges of every bucket
    for (min, max, width) in [(2, 6, 3), (7, 23, 5), (24, 280, 9), (281, 4377, 13)] {
        for delta in [min, max] {
            let flags = relative_fields(delta).len() as u64 - 1;
            assert_eq!(dream_net::wire::relative_bits(delta), flags + width);
        }
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

#[test]
fn refuses_every_other_decode_path() {
    let schema = test_schema();
    let layout = Layout::new(&schema);

    // an event index past the last event, within its 3 bits
    assert_eq!(
        malformed(
            &layout,
            &raw(
                &[(0, 2), (0, 1), (1, 2), (1, 2), (0, 5), (5, 3), (0, 7)],
                &[]
            )
        ),
        Malformed::ValueOutOfRange
    );
    // a message count past the schema's maximum: 20 of 32 in 5 bits is fine, so use a
    // schema whose maximum leaves headroom in the field
    let mut b = Schema::builder(0).max_messages_per_packet(20);
    let state = b
        .channel(ChannelConfig::unreliable_unordered("state"))
        .unwrap();
    b.event("Ping", state, 0).unwrap();
    let narrow = b.build().unwrap();
    // 2 channels would need the section count's spare value; one channel has none, so test
    // the message count: 21 (field 20) of at most 20
    assert_eq!(
        malformed(
            &Layout::new(&narrow),
            &raw(&[(0, 2), (0, 1), (1, 1), (20, 5)], &[])
        ),
        Malformed::ValueOutOfRange
    );
    // a section count past the channel count: 2 channels make the field 2 bits, and 3 is
    // out of range
    let mut b = Schema::builder(0);
    let a = b.channel(ChannelConfig::unreliable_unordered("a")).unwrap();
    b.channel(ChannelConfig::unreliable_unordered("b")).unwrap();
    b.event("E", a, 0).unwrap();
    let two = b.build().unwrap();
    assert_eq!(
        malformed(&Layout::new(&two), &raw(&[(0, 2), (0, 1), (3, 2)], &[])),
        Malformed::ValueOutOfRange
    );
    // nonzero padding before a payload, not just in the trailer: Move with one byte on
    // state is 22 bits of fields, then 2 bits of padding
    assert_eq!(
        malformed(
            &layout,
            &raw(
                &[
                    (0, 2),
                    (0, 1),
                    (1, 2),
                    (1, 2),
                    (0, 5),
                    (MOVE, 3),
                    (1, 7),
                    (0b10, 2)
                ],
                &[0x42]
            )
        ),
        Malformed::NonzeroPadding
    );
    // the same packet with clean padding is accepted
    let mut decoded = Decoded::default();
    decode(
        &layout,
        &raw(
            &[(0, 2), (0, 1), (1, 2), (1, 2), (0, 5), (MOVE, 3), (1, 7)],
            &[0x42],
        ),
        &mut decoded,
    )
    .unwrap();
    // a payload length larger than the bytes left
    assert_eq!(
        malformed(
            &layout,
            &raw(
                &[(0, 2), (0, 1), (1, 2), (1, 2), (0, 5), (MOVE, 3), (4, 7)],
                &[1, 2, 3]
            )
        ),
        Malformed::Truncated
    );
    // a hello cut short
    assert_eq!(
        malformed(
            &layout,
            &raw(&[(0, 2), (1, 1), (WIRE_VERSION.into(), 16)], &[])
        ),
        Malformed::Truncated
    );
}

#[test]
fn degenerate_schemas() {
    // no channels: every field after the hello flag is zero bits wide
    let empty = Schema::builder(0).build().unwrap();
    let layout = Layout::new(&empty);
    let mut decoded = Decoded::default();
    decode(&layout, &[0], &mut decoded).unwrap();
    assert_eq!(decoded.sections, Vec::new());
    assert_eq!(malformed(&layout, &[0, 0]), Malformed::TrailingBytes);
    assert_eq!(malformed(&layout, &[0b1000]), Malformed::NonzeroPadding);
    assert_eq!(malformed(&layout, &[]), Malformed::Truncated);

    // a channel without events: a section on it can carry nothing valid
    let mut b = Schema::builder(0).max_messages_per_packet(1);
    b.channel(ChannelConfig::unreliable_unordered("quiet"))
        .unwrap();
    let schema = b.build().unwrap();
    let layout = Layout::new(&schema);
    // section count 1 (1 bit); channel and count are zero bits wide
    assert_eq!(
        malformed(&layout, &raw(&[(0, 2), (0, 1), (1, 1)], &[])),
        Malformed::ValueOutOfRange
    );
    decode(&layout, &raw(&[(0, 2), (0, 1), (0, 1)], &[]), &mut decoded).unwrap();
}
