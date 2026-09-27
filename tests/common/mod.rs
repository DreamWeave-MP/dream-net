//! Shared fixtures for the integration tests.

#![allow(dead_code)]

use dream_net::wire::{Hello, Layout, PacketWriter};
use dream_net::{ChannelConfig, ChannelId, EventTypeId, Schema, Seq16};

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
