//! Golden vectors for wire format v2.
//!
//! v2 changed only the schema fingerprint derivation (SHA-256 instead of FNV-1a), so only
//! the vectors carrying a hello differ from v1.
//!
//! These bytes are the protocol. A refactor that changes them is a protocol change: bump
//! `WIRE_VERSION` in the same commit and say why.

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
mod compat_vectors;

use common::{PacketSpec, SectionSpec, encode, test_schema};
use compat_vectors::{HelloSpec, SchemaSpec, VECTORS, Vector, Verdict};
use dream_net::wire::{DecodeError, Decoded, Hello, Layout, PacketWriter, WIRE_VERSION, decode};
use dream_net::{ChannelConfig, ChannelId, Delivery, Fingerprint, Schema, Seq16};

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn vectors() -> Vec<(&'static str, PacketSpec)> {
    let schema = test_schema();
    let layout = Layout::new(&schema);
    let chat = schema.event_id("Chat").unwrap();
    let spawn = schema.event_id("Spawn").unwrap();
    let mv = schema.event_id("Move").unwrap();
    let ping = schema.event_id("Ping").unwrap();
    let blob = schema.event_id("Blob").unwrap();
    vec![
        (
            "ack_only",
            PacketSpec {
                hello: None,
                sections: vec![],
            },
        ),
        (
            "hello_only",
            PacketSpec {
                hello: Some(layout.hello()),
                sections: vec![],
            },
        ),
        (
            "unreliable_pair",
            PacketSpec {
                hello: None,
                sections: vec![SectionSpec {
                    channel: ChannelId(1),
                    first_id: 0,
                    deltas: vec![],
                    messages: vec![(mv, vec![1, 2, 3, 4]), (ping, vec![])],
                }],
            },
        ),
        (
            "reliable_wrap_and_gap",
            PacketSpec {
                hello: None,
                sections: vec![SectionSpec {
                    channel: ChannelId(0),
                    first_id: 65535,
                    deltas: vec![1, 9],
                    messages: vec![
                        (chat, b"hi".to_vec()),
                        (spawn, vec![0xAB; 3]),
                        (chat, vec![]),
                    ],
                }],
            },
        ),
        (
            "hello_and_three_sections",
            PacketSpec {
                hello: Some(layout.hello()),
                sections: vec![
                    SectionSpec {
                        channel: ChannelId(2),
                        first_id: 7,
                        deltas: vec![],
                        messages: vec![(blob, vec![0x5A; 9])],
                    },
                    SectionSpec {
                        channel: ChannelId(0),
                        first_id: 300,
                        deltas: vec![2],
                        messages: vec![(chat, b"x".to_vec()), (chat, b"yz".to_vec())],
                    },
                    SectionSpec {
                        channel: ChannelId(1),
                        first_id: 0,
                        deltas: vec![],
                        messages: vec![(mv, vec![0xFF])],
                    },
                ],
            },
        ),
    ]
}

const GOLDEN: [(&str, &str); 5] = [
    ("ack_only", "00"),
    ("hello_only", "14009802305e0b20c527d0595fdb37ba9b3403"),
    ("unreliable_pair", "a82002010203040300"),
    ("reliable_wrap_and_gap", "08f1ff1f010068693900ababab140100"),
    (
        "hello_and_three_sections",
        "14009802305e0b20c527d0595fdb37ba9b345b70008004005a5a5a5a5a5a5a5a5a049680040078220200797a010500ff",
    ),
];

#[test]
fn wire_version_is_two() {
    assert_eq!(
        WIRE_VERSION, 2,
        "golden vectors below are for wire format v2"
    );
}

#[test]
fn schema_fingerprint_is_pinned() {
    // the fingerprint derivation is protocol too: two builds that disagree on it can never
    // connect, so it changes only with a wire version bump
    assert_eq!(
        test_schema().fingerprint(),
        Fingerprint(0x6693_7746_fb6b_eb3a_04f8_a401_6bc6_0053)
    );
}

#[test]
fn encodes_golden_bytes() {
    let layout = Layout::new(&test_schema());
    for ((name, spec), (golden_name, golden)) in vectors().into_iter().zip(GOLDEN) {
        assert_eq!(name, golden_name);
        assert_eq!(hex(&encode(&layout, &spec)), golden, "{name}");
    }
}

#[test]
fn decodes_golden_bytes() {
    let layout = Layout::new(&test_schema());
    let mut decoded = Decoded::default();
    for (name, golden) in GOLDEN {
        let bytes: Vec<u8> = (0..golden.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&golden[i..i + 2], 16).unwrap())
            .collect();
        decode(&layout, &bytes, &mut decoded).unwrap_or_else(|e| panic!("{name}: {e:?}"));
    }
}

// ---------------------------------------------------------------------------------------------
// Compatibility vectors (`tests/compat_vectors`): the same table was proven equal to dream-net
// 1.1.1's own schema builder and writer when 2.0.0 replaced it, so these bytes are wire format
// 2 as every release has written it, not only what this tree writes.
// ---------------------------------------------------------------------------------------------

/// Builds a vector schema from its plain-data declaration.
fn build(spec: SchemaSpec, version: u32) -> Schema {
    let mut b = Schema::builder(version).max_messages_per_packet(32);
    let ids: Vec<ChannelId> = spec
        .channels()
        .iter()
        .map(|&(name, reliable, capacity)| {
            let config = if reliable {
                ChannelConfig::reliable_ordered(name)
            } else {
                ChannelConfig::unreliable_unordered(name)
            };
            b.channel(config.with_capacity(capacity)).unwrap()
        })
        .collect();
    for &(name, channel, max) in spec.events() {
        b.event(name, ids[channel], max).unwrap();
    }
    b.build().unwrap()
}

fn vector_hello(v: &Vector, schema: &Schema) -> Option<Hello> {
    match v.hello {
        HelloSpec::None => None,
        HelloSpec::Own => Some(Layout::new(schema).hello()),
        HelloSpec::WireVersion(wire_version) => Some(Hello {
            wire_version,
            fingerprint: schema.fingerprint(),
        }),
        HelloSpec::Fingerprint(f) => Some(Hello {
            wire_version: WIRE_VERSION,
            fingerprint: Fingerprint(f),
        }),
    }
}

fn encode_vector(v: &Vector) -> Vec<u8> {
    let schema = build(v.schema, 1);
    let layout = Layout::new(&schema);
    let mut buffer = vec![0u8; 64 * 1024];
    let mut w = PacketWriter::new(&mut buffer);
    w.header(&layout, vector_hello(v, &schema), v.sections.len() as u32);
    for section in v.sections {
        let channel = ChannelId(section.channel);
        w.section(&layout, channel, section.messages.len() as u32);
        let reliable = layout.channel(channel).reliable;
        for (index, &(name, len, byte)) in section.messages.iter().enumerate() {
            if reliable {
                if index == 0 {
                    w.first_id(Seq16(section.first_id));
                } else {
                    w.next_id(section.deltas[index - 1]);
                }
            }
            w.message(
                &layout,
                schema.event_id(name).unwrap(),
                &compat_vectors::payload(len, byte),
            );
        }
    }
    let len = w.finish();
    buffer.truncate(len);
    buffer
}

#[test]
fn compat_schemas_have_the_pinned_catalogue() {
    let schema = build(SchemaSpec::Test, 1);
    assert_eq!(schema.fingerprint(), test_schema().fingerprint());
    assert_eq!(
        schema.fingerprint(),
        Fingerprint(compat_vectors::TEST_FINGERPRINT)
    );
    assert_eq!(
        build(SchemaSpec::Test, 9).fingerprint(),
        Fingerprint(compat_vectors::TEST_V9_FINGERPRINT)
    );
    for (name, id) in compat_vectors::TEST_EVENT_IDS {
        assert_eq!(schema.event_id(name).unwrap().0, id, "{name}");
        assert_eq!(schema.events()[id as usize].name, name);
    }
    assert_eq!(schema.events().len(), compat_vectors::TEST_EVENT_IDS.len());
    for (id, name, reliable, capacity, max_payload) in compat_vectors::TEST_CHANNEL_CATALOGUE {
        let channel = schema.channel(ChannelId(id)).unwrap();
        assert_eq!(schema.channel_id(name), Some(ChannelId(id)));
        assert_eq!(channel.name(), name);
        assert_eq!(
            channel.delivery() == Delivery::ReliableOrdered,
            reliable,
            "{name}"
        );
        assert_eq!(channel.config.capacity, capacity, "{name}");
        assert_eq!(channel.max_payload, max_payload, "{name}");
    }
    let wide = build(SchemaSpec::Wide, 1);
    assert_eq!(
        wide.fingerprint(),
        Fingerprint(compat_vectors::WIDE_FINGERPRINT)
    );
    for (name, id) in compat_vectors::WIDE_EVENT_IDS {
        assert_eq!(wide.event_id(name).unwrap().0, id, "{name}");
    }
}

#[test]
fn encodes_compat_vectors() {
    for v in &VECTORS {
        assert_eq!(compat_vectors::hex(&encode_vector(v)), v.hex, "{}", v.name);
    }
}

#[test]
fn decodes_compat_vectors() {
    for v in &VECTORS {
        let schema = build(v.schema, 1);
        let layout = Layout::new(&schema);
        let bytes = compat_vectors::unhex(v.hex);
        let mut decoded = Decoded::default();
        let verdict = decode(&layout, &bytes, &mut decoded);
        match v.verdict {
            Verdict::Ok => {
                verdict.unwrap_or_else(|e| panic!("{}: {e:?}", v.name));
                assert_eq!(decoded.hello, vector_hello(v, &schema), "{}", v.name);
                assert_eq!(decoded.sections.len(), v.sections.len(), "{}", v.name);
                for (section, spec) in decoded.sections.iter().zip(v.sections) {
                    assert_eq!(section.channel, ChannelId(spec.channel));
                    let messages = &decoded.messages
                        [section.first as usize..(section.first + section.count) as usize];
                    assert_eq!(messages.len(), spec.messages.len(), "{}", v.name);
                    let reliable = layout.channel(section.channel).reliable;
                    let mut id = Seq16(spec.first_id);
                    for (index, (m, &(name, len, byte))) in
                        messages.iter().zip(spec.messages).enumerate()
                    {
                        if reliable && index > 0 {
                            id = id.add(spec.deltas[index - 1] as u16);
                        }
                        assert_eq!(m.event, schema.event_id(name).unwrap(), "{}", v.name);
                        assert_eq!(m.id, if reliable { id } else { Seq16::ZERO });
                        assert_eq!(m.payload(&bytes), compat_vectors::payload(len, byte));
                    }
                }
            }
            Verdict::Mismatch => {
                // stopped at the hello, before anything schema-dependent was read
                assert_eq!(
                    verdict,
                    Err(DecodeError::Mismatch(vector_hello(v, &schema).unwrap())),
                    "{}",
                    v.name
                );
                assert!(decoded.sections.is_empty() && decoded.messages.is_empty());
            }
        }
    }
}

#[test]
fn compat_vector_ids_wrap_through_zero() {
    let v = compat_vectors::vector("relative_tiers_across_the_wrap");
    let mut id = Seq16(v.sections[0].first_id);
    let mut ids = vec![id.0];
    for &delta in v.sections[0].deltas {
        id = id.add(delta as u16);
        ids.push(id.0);
    }
    assert_eq!(
        ids,
        [
            65530, 65531, 65533, 3, 10, 33, 57, 337, 618, 4995, 9373, 29373
        ]
    );
    assert_eq!(
        compat_vectors::vector("wrap_at_65535").sections[0].first_id,
        65535
    );
}
