//! Golden vectors for wire format v2.
//!
//! v2 changed only the schema fingerprint derivation (SHA-256 instead of FNV-1a), so only
//! the vectors carrying a hello differ from v1.
//!
//! These bytes are the protocol. A refactor that changes them is a protocol change: bump
//! `WIRE_VERSION` in the same commit and say why.

mod common;

use common::{PacketSpec, SectionSpec, encode, test_schema};
use dream_net::wire::{Decoded, Layout, WIRE_VERSION, decode};
use dream_net::{ChannelId, Fingerprint};

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
