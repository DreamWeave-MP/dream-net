//! dream-net's wire format against serialize's own streams: the packets dream-net writes are
//! exactly what serialize's `serialize_int`, `serialize_int_relative` and `serialize_bytes`
//! write, and serialize's checked `ReadStream` reads them back. Wire format v2 is defined as
//! serialize's bit stream, and these tests are what tie dream-net's own framing to it.

// CI passes -W clippy::pedantic on the command line, overriding the manifest's lint table;
// test code casts freely between widths it controls.
#![allow(
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]

#[path = "../../tests/common/mod.rs"]
mod common;

use common::{PacketSpec, SectionSpec, decode_spec, encode, spec_strategy, test_schema};
use dream_net::wire::{Hello, Layout};
use dream_net::{ChannelId, EventTypeId, Fingerprint, Schema};
use proptest::prelude::*;
use serialize::{ReadStream, Stream, WriteStream};

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

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    #[test]
    fn round_trips_and_matches_serialize_streams(spec in spec_strategy()) {
        let schema = test_schema();
        let layout = Layout::new(&schema);
        let packet = encode(&layout, &spec);
        prop_assert_eq!(&packet, &encode_reference(&schema, &spec));
        prop_assert_eq!(decode_spec(&layout, &schema, &packet).unwrap(), spec.clone());
        prop_assert_eq!(decode_reference(&schema, &packet).unwrap(), spec);
    }
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
