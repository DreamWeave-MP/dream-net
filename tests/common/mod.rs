//! Shared fixtures for the integration tests.

#![allow(dead_code)]

use std::net::SocketAddr;

use dream_net::wire::{DecodeError, Decoded, Hello, Layout, PacketWriter, WIRE_VERSION, decode};
use dream_net::{
    CONNECT_TOKEN_BYTES, ChannelConfig, ChannelId, Delivery, EventTypeId, Schema, Seq16,
};
use proptest::prelude::*;

/// The connection request a netcode client sends for `token`, byte for byte: everything the
/// server sees of an attempt until it answers. The token's public layout is the version (13
/// bytes), protocol id, create and expire timestamps, the nonce (24 bytes) and the encrypted
/// private part (1024 bytes); the request is a zero prefix byte and all of them but the create
/// timestamp. Used to present a token the current process refuses to pass to `connect` again
/// (`tests/native_netcode_support` has the same for the native binding's tests).
pub fn connection_request(token: &[u8; CONNECT_TOKEN_BYTES]) -> Vec<u8> {
    let mut request = vec![0u8];
    request.extend_from_slice(&token[0..21]);
    request.extend_from_slice(&token[29..1085]);
    assert_eq!(request.len(), 1078);
    request
}

/// The timeout (whole seconds) and the IPv4 server addresses a token lists, in order: after
/// the private part come the timeout (`i32`), the address count (`u32`) and the addresses,
/// each a type byte (1 for IPv4), four address bytes and a port, little-endian throughout.
pub fn token_servers(token: &[u8; CONNECT_TOKEN_BYTES]) -> (i32, Vec<SocketAddr>) {
    let timeout = i32::from_le_bytes(token[1085..1089].try_into().unwrap());
    let count = u32::from_le_bytes(token[1089..1093].try_into().unwrap()) as usize;
    let servers = (0..count)
        .map(|n| {
            let at = 1093 + 7 * n;
            assert_eq!(token[at], 1, "an IPv4 address");
            let ip = [token[at + 1], token[at + 2], token[at + 3], token[at + 4]];
            let port = u16::from_le_bytes([token[at + 5], token[at + 6]]);
            SocketAddr::from((ip, port))
        })
        .collect();
    (timeout, servers)
}

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
