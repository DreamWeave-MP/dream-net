//! Compatibility golden vectors as plain data, with no dependency on any crate, so the same
//! table pins this tree (`tests/wire_golden.rs`, `tests/compat_version.rs`). They were proven
//! equal to what dream-net 1.1.1's own `Schema` and `PacketWriter` build when the native
//! transport replaced it (2.0.0), so a vector here is not just what this tree writes today: it
//! is dream-net's wire format 2, which any change must keep reading or bump `WIRE_VERSION`.
//!
//! Payloads are runs of one byte. Hex strings write a run as `{xx*n}`: `n` bytes of `xx`.

#![allow(dead_code)]

/// Channel declarations: name, reliable-ordered (else unreliable-unordered), capacity.
pub type ChannelSpec = (&'static str, bool, u16);
/// Event declarations: name, channel index, maximum payload.
pub type EventSpec = (&'static str, usize, u32);

/// `tests/common`'s `test_schema()`, version 1, `max_messages_per_packet(32)`.
pub const TEST_CHANNELS: [ChannelSpec; 3] = [
    ("reliable", true, 64),
    ("state", false, 64),
    ("bulk", true, 16),
];
pub const TEST_EVENTS: [EventSpec; 5] = [
    ("Chat", 0, 256),
    ("Spawn", 0, 1024),
    ("Move", 1, 64),
    ("Ping", 1, 0),
    ("Blob", 2, 8000),
];

/// A schema whose reliable channel has the largest window (32768), so a section can reach
/// every `int_relative` tier a canonical writer uses. Version 1, `max_messages_per_packet(32)`.
pub const WIDE_CHANNELS: [ChannelSpec; 2] = [("log", true, 32768), ("tick", false, 8)];
pub const WIDE_EVENTS: [EventSpec; 3] = [("Note", 0, 8), ("Mark", 0, 3), ("Beat", 1, 2)];

/// Which schema a vector is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaSpec {
    Test,
    Wide,
}

impl SchemaSpec {
    pub fn channels(self) -> &'static [ChannelSpec] {
        match self {
            Self::Test => &TEST_CHANNELS,
            Self::Wide => &WIDE_CHANNELS,
        }
    }

    pub fn events(self) -> &'static [EventSpec] {
        match self {
            Self::Test => &TEST_EVENTS,
            Self::Wide => &WIDE_EVENTS,
        }
    }
}

/// The public catalogue of each schema, as both versions must build it: event ids follow the
/// byte order of the canonical names, never declaration order; channel ids follow
/// declaration order; and the fingerprint.
pub const TEST_EVENT_IDS: [(&str, u32); 5] = [
    ("Blob", 0),
    ("Chat", 1),
    ("Move", 2),
    ("Ping", 3),
    ("Spawn", 4),
];
/// (id, name, reliable, capacity, largest payload of its events)
pub const TEST_CHANNEL_CATALOGUE: [(u8, &str, bool, u16, u32); 3] = [
    (0, "reliable", true, 64, 1024),
    (1, "state", false, 64, 64),
    (2, "bulk", true, 16, 8000),
];
pub const TEST_FINGERPRINT: u128 = 0x6693_7746_fb6b_eb3a_04f8_a401_6bc6_0053;
pub const WIDE_EVENT_IDS: [(&str, u32); 3] = [("Beat", 0), ("Mark", 1), ("Note", 2)];
pub const WIDE_FINGERPRINT: u128 = 0xc755_1420_3454_a1bc_5d0d_6c54_c8d0_2d0d;
/// The fingerprint of `TEST_*` built as schema version 9: a peer with this schema is a
/// schema mismatch.
pub const TEST_V9_FINGERPRINT: u128 = 0xe359_74bf_f3b1_01b0_05ff_a015_8674_b20d;

/// The hello a vector carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelloSpec {
    /// No hello.
    None,
    /// The schema's own hello: `WIRE_VERSION` (2) and its fingerprint.
    Own,
    /// The schema's fingerprint under another wire version: a protocol mismatch.
    WireVersion(u16),
    /// Wire version 2 with another fingerprint: a schema mismatch.
    Fingerprint(u128),
}

/// A section: channel, first message id (reliable channels), forward deltas of the later ids,
/// and messages as (event name, payload length, payload byte).
#[derive(Debug, Clone, Copy)]
pub struct SectionSpec {
    pub channel: u8,
    pub first_id: u16,
    pub deltas: &'static [u32],
    pub messages: &'static [(&'static str, usize, u8)],
}

/// How a decoder of the vector's schema must answer it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Accepted; re-encodes to itself.
    Ok,
    /// Stopped at the hello (`DecodeError::Mismatch`), before any section.
    Mismatch,
}

#[derive(Debug, Clone, Copy)]
pub struct Vector {
    pub name: &'static str,
    pub schema: SchemaSpec,
    pub hello: HelloSpec,
    pub sections: &'static [SectionSpec],
    pub verdict: Verdict,
    pub hex: &'static str,
}

/// Every message id delta tier `int_relative` has below its absolute tier, at both ends of
/// each: 1 (the one-bit fast path), [2, 6], [7, 23], [24, 280], [281, 4377], [4378, 69914]
/// (here 20000, so the section stays inside one 32768 window). The ids start at 65530 and
/// wrap through 0.
const TIER_DELTAS: [u32; 11] = [1, 2, 6, 7, 23, 24, 280, 281, 4377, 4378, 20000];
const TIER_MESSAGES: [(&str, usize, u8); 12] = [
    ("Note", 0, 0),
    ("Note", 1, 0x01),
    ("Mark", 0, 0),
    ("Note", 2, 0x02),
    ("Mark", 3, 0x03),
    ("Note", 0, 0),
    ("Note", 8, 0x08),
    ("Mark", 1, 0x0b),
    ("Note", 0, 0),
    ("Note", 4, 0x44),
    ("Mark", 2, 0x22),
    ("Note", 5, 0x55),
];

/// 32 messages, the most one section may carry with `max_messages_per_packet(32)`.
const FULL_SECTION: [(&str, usize, u8); 32] = [("Chat", 1, 0x2a); 32];
const FULL_DELTAS: [u32; 31] = [1; 31];

pub const VECTORS: [Vector; 11] = [
    Vector {
        name: "relative_tiers_across_the_wrap",
        schema: SchemaSpec::Wide,
        hello: HelloSpec::None,
        sections: &[SectionSpec {
            channel: 0,
            first_id: 65530,
            deltas: &TIER_DELTAS,
            messages: &TIER_MESSAGES,
        }],
        verdict: Verdict::Ok,
        hex: "c8d2ff17000d01220052010202040d0303038402084004{08*9}b0000b10000810004a44444444200080042222a0410f0b5555555555",
    },
    Vector {
        name: "wrap_at_65535",
        schema: SchemaSpec::Wide,
        hello: HelloSpec::None,
        sections: &[SectionSpec {
            channel: 0,
            first_id: 65535,
            deltas: &[1, 1],
            messages: &[("Note", 1, 0xff), ("Note", 1, 0x00), ("Note", 1, 0x01)],
        }],
        verdict: Verdict::Ok,
        hex: "88f8ff3700ff0d000d01",
    },
    Vector {
        name: "payload_length_edges",
        schema: SchemaSpec::Test,
        hello: HelloSpec::None,
        sections: &[
            SectionSpec {
                channel: 0,
                first_id: 0,
                deltas: &[1, 1],
                // empty, Chat's own maximum (256), and Spawn's 1024, which is also the
                // channel's maximum (the length field's range)
                messages: &[("Chat", 0, 0), ("Chat", 256, 0xc1), ("Spawn", 1024, 0xc2)],
            },
            SectionSpec {
                channel: 1,
                first_id: 0,
                deltas: &[],
                messages: &[("Move", 64, 0xd1), ("Ping", 0, 0)],
            },
            SectionSpec {
                channel: 2,
                first_id: 15,
                deltas: &[],
                messages: &[("Blob", 8000, 0xe1)],
            },
        ],
        verdict: Verdict::Ok,
        hex: "1801001000000310{c1*256}0940{c2*1024}050101{d1*64}0300820700007d{e1*8000}",
    },
    Vector {
        name: "three_sections_without_a_hello",
        schema: SchemaSpec::Test,
        hello: HelloSpec::None,
        sections: &[
            SectionSpec {
                channel: 1,
                first_id: 0,
                deltas: &[],
                messages: &[("Ping", 0, 0), ("Move", 2, 0x10)],
            },
            SectionSpec {
                channel: 2,
                first_id: 40000,
                deltas: &[3],
                messages: &[("Blob", 1, 0x20), ("Blob", 2, 0x21)],
            },
            SectionSpec {
                channel: 0,
                first_id: 1,
                deltas: &[63],
                messages: &[("Spawn", 3, 0x30), ("Chat", 1, 0x31)],
            },
        ],
        verdict: Verdict::Ok,
        hex: "b830001200101006204e04002006020021218400000e003030307822010031",
    },
    Vector {
        name: "full_section",
        schema: SchemaSpec::Test,
        hello: HelloSpec::Own,
        sections: &[SectionSpec {
            channel: 0,
            first_id: 4096,
            deltas: &FULL_DELTAS,
            messages: &FULL_SECTION,
        }],
        verdict: Verdict::Ok,
        hex: "14009802305e0b20c527d0595fdb37ba9b348b0f009100002a13002a13002a13002a13002a13002a13002a13002a13002a13002a13002a13002a13002a13002a13002a13002a13002a13002a13002a13002a13002a13002a13002a13002a13002a13002a13002a13002a13002a13002a13002a13002a",
    },
    Vector {
        name: "hello_wire_version_1",
        schema: SchemaSpec::Test,
        hello: HelloSpec::WireVersion(1),
        sections: &[],
        verdict: Verdict::Mismatch,
        hex: "0c009802305e0b20c527d0595fdb37ba9b3403",
    },
    Vector {
        name: "hello_wire_version_3",
        schema: SchemaSpec::Test,
        hello: HelloSpec::WireVersion(3),
        sections: &[],
        verdict: Verdict::Mismatch,
        hex: "1c009802305e0b20c527d0595fdb37ba9b3403",
    },
    Vector {
        name: "hello_wire_version_3_then_a_section",
        schema: SchemaSpec::Test,
        hello: HelloSpec::WireVersion(3),
        sections: &[SectionSpec {
            channel: 0,
            first_id: 0,
            deltas: &[],
            messages: &[("Chat", 7, 0x67)],
        }],
        verdict: Verdict::Mismatch,
        hex: "1c009802305e0b20c527d0595fdb37ba9b340b000090030067676767676767",
    },
    Vector {
        name: "hello_wire_version_65535",
        schema: SchemaSpec::Test,
        hello: HelloSpec::WireVersion(65535),
        sections: &[],
        verdict: Verdict::Mismatch,
        hex: "fcff9f02305e0b20c527d0595fdb37ba9b3403",
    },
    Vector {
        name: "hello_foreign_fingerprint",
        schema: SchemaSpec::Test,
        hello: HelloSpec::Fingerprint(TEST_V9_FINGERPRINT),
        sections: &[],
        verdict: Verdict::Mismatch,
        hex: "14006890a533ac00fd2f800d889dffa5cb1a07",
    },
    Vector {
        name: "hello_foreign_fingerprint_then_a_section",
        schema: SchemaSpec::Test,
        hello: HelloSpec::Fingerprint(TEST_V9_FINGERPRINT),
        sections: &[SectionSpec {
            channel: 0,
            first_id: 0,
            deltas: &[],
            messages: &[("Chat", 7, 0x67)],
        }],
        verdict: Verdict::Mismatch,
        hex: "14006890a533ac00fd2f800d889dffa5cb1a0f000090030067676767676767",
    },
];

/// The version-rejection datagrams: the hello-only and hello-plus-section vectors above for wire
/// versions 1 and 3, each as the first datagram of a fresh reliable endpoint with dream-net's
/// default transport configuration (reliable's 8-byte header for sequence 0, then the packet).
/// A peer of this wire version sends exactly these first.
pub const REJECTION_DATAGRAMS: [(&str, u16, &str); 3] = [
    (
        "hello_wire_version_1",
        1,
        "3e000001000000000c009802305e0b20c527d0595fdb37ba9b3403",
    ),
    (
        "hello_wire_version_3",
        3,
        "3e000001000000001c009802305e0b20c527d0595fdb37ba9b3403",
    ),
    (
        "hello_wire_version_3_then_a_section",
        3,
        "3e000001000000001c009802305e0b20c527d0595fdb37ba9b340b000090030067676767676767",
    ),
];

/// The vector named `name`.
pub fn vector(name: &str) -> &'static Vector {
    VECTORS.iter().find(|v| v.name == name).unwrap()
}

/// The payload bytes of a message spec.
pub fn payload(len: usize, byte: u8) -> Vec<u8> {
    vec![byte; len]
}

/// Expands `{xx*n}` runs and parses the hex.
pub fn unhex(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rest = s;
    while !rest.is_empty() {
        if let Some(run) = rest.strip_prefix('{') {
            let end = run.find('}').unwrap();
            let (byte, count) = run[..end].split_once('*').unwrap();
            let byte = u8::from_str_radix(byte, 16).unwrap();
            out.extend(std::iter::repeat_n(byte, count.parse().unwrap()));
            rest = &run[end + 1..];
        } else {
            out.push(u8::from_str_radix(&rest[..2], 16).unwrap());
            rest = &rest[2..];
        }
    }
    out
}

/// Hex with every run of 8 or more equal bytes written as `{xx*n}`: the inverse of [`unhex`].
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    let mut i = 0;
    while i < bytes.len() {
        let mut j = i;
        while j < bytes.len() && bytes[j] == bytes[i] {
            j += 1;
        }
        if j - i >= 8 {
            let _ = write!(s, "{{{:02x}*{}}}", bytes[i], j - i);
        } else {
            for b in &bytes[i..j] {
                let _ = write!(s, "{b:02x}");
            }
        }
        i = j;
    }
    s
}
