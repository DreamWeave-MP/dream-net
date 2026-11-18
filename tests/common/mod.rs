//! Shared fixtures for the integration tests.

#![allow(dead_code)]

use dream_net::wire::{DecodeError, Decoded, Hello, Layout, PacketWriter, WIRE_VERSION, decode};
use dream_net::{ChannelConfig, ChannelId, Delivery, EventTypeId, Schema, Seq16};
use proptest::prelude::*;

/// Three channels (reliable window 64, unreliable, reliable "bulk"), five events.
pub fn test_schema() -> Schema {
    test_schema_versioned(1)
}

pub fn test_schema_versioned(version: u32) -> Schema {
    let mut b = Schema::builder(version).max_messages_per_packet(32);
    let reliable = b
        .channel(ChannelConfig::reliable_ordered("reliable").with_capacity(64))
        .unwrap();
    let state = b
        .channel(ChannelConfig::unreliable_unordered("state").with_capacity(64))
        .unwrap();
    let bulk = b
        .channel(ChannelConfig::reliable_ordered("bulk").with_capacity(16))
        .unwrap();
    b.event("Chat", reliable, 256).unwrap();
    b.event("Spawn", reliable, 1024).unwrap();
    b.event("Move", state, 64).unwrap();
    b.event("Ping", state, 0).unwrap();
    b.event("Blob", bulk, 8000).unwrap();
    b.build().unwrap()
}

/// A packet described as data, for round trips.
#[derive(Debug, Clone, PartialEq)]
pub struct PacketSpec {
    pub hello: Option<Hello>,
    pub sections: Vec<SectionSpec>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SectionSpec {
    pub channel: ChannelId,
    /// Reliable only: the first id and the forward deltas of the later ones.
    pub first_id: u16,
    pub deltas: Vec<u32>,
    pub messages: Vec<(EventTypeId, Vec<u8>)>,
}

impl SectionSpec {
    pub fn ids(&self) -> Vec<Seq16> {
        let mut id = Seq16(self.first_id);
        let mut ids = vec![id];
        for &delta in &self.deltas {
            id = id.add(delta as u16);
            ids.push(id);
        }
        ids
    }
}

/// Encodes `spec` with dream-net's writer.
pub fn encode(layout: &Layout, spec: &PacketSpec) -> Vec<u8> {
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
    let len = w.finish();
    buffer.truncate(len);
    buffer
}

/// Decodes `packet` with dream-net's decoder into a [`PacketSpec`].
pub fn decode_spec(
    layout: &Layout,
    schema: &Schema,
    packet: &[u8],
) -> Result<PacketSpec, DecodeError> {
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

/// Valid packets for [`test_schema`]: any subset of channels in any order, up to seven
/// messages per section, reliable ids spread within one window.
pub fn spec_strategy() -> impl Strategy<Value = PacketSpec> {
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
            let reliable = channel.delivery() == Delivery::ReliableOrdered;
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
