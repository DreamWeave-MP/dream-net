//! The main crate's compatibility golden vectors (`tests/compat_vectors`, used by
//! `tests/wire_golden.rs` and `tests/compat_version.rs`) checked against dream-net 1.1.1: every
//! schema catalogue (event ids from sorted names, channel ids, fingerprints), every packet
//! (written with 1.1.1's own `Schema` and `PacketWriter` from the same plain-data
//! description), every decoder verdict, and every version-rejection datagram (framed by the
//! `reliable` 1.3.4 Rust port and by the C reliable) is byte for byte what the vector pins. The
//! goldens therefore pin compatibility with the last release, not only current behaviour.
//!
//! The same checks run against this tree too, so a divergence names its side.

// CI passes -W clippy::pedantic on the command line, overriding the manifest's lint table;
// test code casts freely between widths it controls.
#![allow(clippy::cast_possible_truncation)]

#[path = "../../tests/compat_vectors/mod.rs"]
mod compat_vectors;

use compat_vectors::{HelloSpec, SchemaSpec, VECTORS, Vector, Verdict};

/// The vector machinery over either crate.
macro_rules! codec {
    ($side:ident, $dn:ident) => {
        mod $side {
            use super::compat_vectors::{self, HelloSpec, SchemaSpec, Vector};
            use $dn::wire::{Decoded, Hello, Layout, PacketWriter, WIRE_VERSION, decode};
            use $dn::{ChannelConfig, ChannelId, Delivery, Fingerprint, Schema, Seq16};

            pub fn build(spec: SchemaSpec, version: u32) -> Schema {
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

            pub fn fingerprint(spec: SchemaSpec, version: u32) -> u128 {
                build(spec, version).fingerprint().0
            }

            pub fn event_ids(spec: SchemaSpec) -> Vec<(String, u32)> {
                let schema = build(spec, 1);
                spec.events()
                    .iter()
                    .map(|&(name, _, _)| (name.to_owned(), schema.event_id(name).unwrap().0))
                    .collect()
            }

            /// (id, name, reliable, capacity, max payload) for every channel.
            pub fn channels(spec: SchemaSpec) -> Vec<(u8, String, bool, u16, u32)> {
                let schema = build(spec, 1);
                schema
                    .channels()
                    .iter()
                    .map(|c| {
                        (
                            c.id.0,
                            c.name().to_owned(),
                            c.delivery() == Delivery::ReliableOrdered,
                            c.config.capacity,
                            c.max_payload,
                        )
                    })
                    .collect()
            }

            fn hello(v: &Vector, schema: &Schema) -> Option<Hello> {
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

            pub fn encode(v: &Vector) -> Vec<u8> {
                let schema = build(v.schema, 1);
                let layout = Layout::new(&schema);
                let mut buffer = vec![0u8; 64 * 1024];
                let mut w = PacketWriter::new(&mut buffer);
                w.header(&layout, hello(v, &schema), v.sections.len() as u32);
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

            /// The decoder's verdict in a version-neutral form: `Ok` with (event, id, payload)
            /// per message, or the mismatching hello.
            pub fn decode_verdict(
                v: &Vector,
                bytes: &[u8],
            ) -> Result<Vec<(u32, u16, Vec<u8>)>, String> {
                let schema = build(v.schema, 1);
                let layout = Layout::new(&schema);
                let mut decoded = Decoded::default();
                match decode(&layout, bytes, &mut decoded) {
                    Ok(()) => Ok(decoded
                        .messages
                        .iter()
                        .map(|m| (m.event.0, m.id.0, m.payload(bytes).to_vec()))
                        .collect()),
                    Err(e) => {
                        assert!(decoded.messages.is_empty());
                        Err(format!("{e:?}"))
                    }
                }
            }
        }
    };
}

codec!(old, dream_net_old);
codec!(new, dream_net);

#[test]
fn both_versions_build_the_pinned_catalogues() {
    for spec in [SchemaSpec::Test, SchemaSpec::Wide] {
        assert_eq!(old::event_ids(spec), new::event_ids(spec), "{spec:?}");
        assert_eq!(old::channels(spec), new::channels(spec), "{spec:?}");
        assert_eq!(old::fingerprint(spec, 1), new::fingerprint(spec, 1));
    }
    assert_eq!(
        old::fingerprint(SchemaSpec::Test, 1),
        compat_vectors::TEST_FINGERPRINT
    );
    assert_eq!(
        old::fingerprint(SchemaSpec::Test, 9),
        compat_vectors::TEST_V9_FINGERPRINT
    );
    assert_eq!(
        old::fingerprint(SchemaSpec::Wide, 1),
        compat_vectors::WIDE_FINGERPRINT
    );
    let mut ids = old::event_ids(SchemaSpec::Test);
    ids.sort_by_key(|(_, id)| *id);
    assert_eq!(
        ids,
        compat_vectors::TEST_EVENT_IDS.map(|(n, id)| (n.to_owned(), id))
    );
    let mut ids = old::event_ids(SchemaSpec::Wide);
    ids.sort_by_key(|(_, id)| *id);
    assert_eq!(
        ids,
        compat_vectors::WIDE_EVENT_IDS.map(|(n, id)| (n.to_owned(), id))
    );
    assert_eq!(
        old::channels(SchemaSpec::Test),
        compat_vectors::TEST_CHANNEL_CATALOGUE.map(|(id, n, r, c, m)| (id, n.to_owned(), r, c, m))
    );
}

fn check(v: &Vector) {
    let old_bytes = old::encode(v);
    assert_eq!(
        compat_vectors::hex(&old_bytes),
        v.hex,
        "1.1.1 writes {}",
        v.name
    );
    assert_eq!(new::encode(v), old_bytes, "this tree writes {}", v.name);
    let bytes = compat_vectors::unhex(v.hex);
    let (old_verdict, new_verdict) = (
        old::decode_verdict(v, &bytes),
        new::decode_verdict(v, &bytes),
    );
    assert_eq!(old_verdict, new_verdict, "{}", v.name);
    match v.verdict {
        Verdict::Ok => assert!(old_verdict.is_ok(), "{}: {old_verdict:?}", v.name),
        Verdict::Mismatch => {
            let text = old_verdict.unwrap_err();
            assert!(text.starts_with("Mismatch(Hello"), "{}: {text}", v.name);
            if let HelloSpec::WireVersion(w) = v.hello {
                assert!(text.contains(&format!("wire_version: {w},")), "{text}");
            }
        }
    }
}

#[test]
fn every_vector_is_what_both_versions_write_and_read() {
    for v in &VECTORS {
        check(v);
    }
}

#[test]
fn every_rejection_datagram_is_what_both_reliables_frame() {
    let config = dream_net::TransportConfig::default().reliable_config("golden");
    for (name, version, hex) in compat_vectors::REJECTION_DATAGRAMS {
        let v = compat_vectors::vector(name);
        assert_eq!(v.hello, HelloSpec::WireVersion(version));
        let packet = old::encode(v);
        let mut c = Vec::new();
        dream_net_native::reliable::Endpoint::new(config.clone(), 0.0)
            .unwrap()
            .send_packet(&packet, |_, d| c.push(d.to_vec()));
        let mut port = reliable_old::Endpoint::new(
            reliable_old::Config {
                name: config.name.clone(),
                max_packet_size: config.max_packet_size,
                fragment_above: config.fragment_above,
                max_fragments: config.max_fragments,
                fragment_size: config.fragment_size,
                ack_buffer_size: config.ack_buffer_size,
                sent_packets_buffer_size: config.sent_packets_buffer_size,
                received_packets_buffer_size: config.received_packets_buffer_size,
                fragment_reassembly_buffer_size: config.fragment_reassembly_buffer_size,
                rtt_smoothing_factor: config.rtt_smoothing_factor,
                rtt_history_size: config.rtt_history_size,
                packet_loss_smoothing_factor: config.packet_loss_smoothing_factor,
                bandwidth_smoothing_factor: config.bandwidth_smoothing_factor,
                packet_header_size: config.packet_header_size,
            },
            0.0,
        );
        let mut rust = Vec::new();
        port.send_packet(&packet, |_, d| rust.push(d.to_vec()));
        assert_eq!(c, rust, "{name}");
        assert_eq!(c.len(), 1);
        assert_eq!(compat_vectors::hex(&c[0]), hex, "{name}");
    }
}

/// Prints every vector as 1.1.1 writes it, for regenerating the table after adding one:
/// `cargo test --test golden_old_new -- --ignored --nocapture`.
#[test]
#[ignore = "prints the table; run by hand"]
fn print_vectors_as_written_by_1_1_1() {
    println!(
        "TEST_V9_FINGERPRINT {:032x}",
        old::fingerprint(SchemaSpec::Test, 9)
    );
    println!(
        "WIDE_FINGERPRINT {:032x}",
        old::fingerprint(SchemaSpec::Wide, 1)
    );
    println!("WIDE ids {:?}", old::event_ids(SchemaSpec::Wide));
    for v in &VECTORS {
        println!("{} {}", v.name, compat_vectors::hex(&old::encode(v)));
    }
    let config = dream_net::TransportConfig::default().reliable_config("golden");
    for (name, _, _) in compat_vectors::REJECTION_DATAGRAMS {
        let packet = old::encode(compat_vectors::vector(name));
        let mut c = Vec::new();
        dream_net_native::reliable::Endpoint::new(config.clone(), 0.0)
            .unwrap()
            .send_packet(&packet, |_, d| c.push(d.to_vec()));
        println!("datagram {name} {}", compat_vectors::hex(&c[0]));
    }
}
