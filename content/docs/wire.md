+++
title = "Wire format"
description = "Wire format 2: the bits of a connection packet, the hello, what the decoder refuses, and what reliable and netcode add around it."
weight = 85

[extra]
kind = "reference"
+++

A connection packet is what dream-net hands reliable: one packet of events, before reliable adds
its header and fragments it, and before netcode encrypts it. This page is wire format 2, the
current `WIRE_VERSION`.

## Around the packet

| Layer | Adds | Size |
|---|---|---|
| dream-net | The connection packet below | Up to `max_packet_size`, 32 KiB by default |
| reliable | Sequence number and acknowledgements; a fragment header on each fragment | Up to 9 bytes; 5 more per fragment |
| netcode | Encryption, authentication and replay protection | A datagram of at most 1200 bytes of payload |

So an unfragmented connection packet is at most 1191 bytes (`MAX_UNFRAGMENTED_PACKET`), and a
fragment carries at most 1186 (`MAX_FRAGMENT_SIZE`).

## The packet

It is a serialize bit stream: little-endian 64-bit words, each value packed into the fewest bits
its range needs. `int[a, b]` below is a value in that range, in `bits_required(a, b)` bits.

```text
packet   := kind:2                    0 = data; 1..3 reserved and refused
            has_hello:1
            hello?                    wire_version:u16, fingerprint:u128
            section_count:int[0, channels]
            section*                  at most one per channel
            align                     zero padding; nothing may follow
section  := channel:int[0, channels-1]
            message_count:int[1, max_messages_per_packet]
            reliable only: first_id:u16, then each later id as serialize's int_relative
                           from the previous one, all within one channel window
            message*
message  := event:int[0, events-1]    an event of the section's channel
            length:int[0, channel_max_payload], at most the event's max payload
            align, payload[length]
```

The widths come from the schema: the number of channels and events, `max_messages_per_packet`, and
each channel's largest payload. That is why the hello comes first. A peer with a different schema
would read every later field at the wrong width, so the hello is compared before anything that
depends on the schema is read, and a different one is a mismatch rather than garbage.

A packet with nothing in it, which carries only reliable's acknowledgements, is a single zero byte
for a schema of up to 31 channels, and two bytes beyond that.

## A worked example

```rust
use dream_net::wire::{Decoded, Layout, PacketWriter, decode};
use dream_net::{ChannelConfig, Schema};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut schema = Schema::builder(1);
    let reliable = schema.channel(ChannelConfig::reliable_ordered("reliable"))?;
    let state = schema.channel(ChannelConfig::unreliable_unordered("state"))?;
    schema.event("Chat", reliable, 256)?;
    schema.event("Position", state, 12)?;
    let schema = schema.build()?;
    let position = schema.event_id("Position").expect("declared");
    let layout = Layout::new(&schema);

    // one section on the unreliable channel, carrying two events
    let mut buffer = [0u8; 64];
    let mut writer = PacketWriter::new(&mut buffer);
    writer.header(&layout, None, 1);
    writer.section(&layout, state, 2);
    writer.message(&layout, position, &[1, 2, 3]);
    writer.message(&layout, position, &[]);
    let len = writer.finish();
    let packet = &buffer[..len];
    println!("{}", packet.iter().map(|b| format!("{b:02x}")).collect::<String>());

    let mut decoded = Decoded::default();
    decode(&layout, packet, &mut decoded).expect("a packet this layout wrote decodes");
    assert_eq!(decoded.sections.len(), 1);
    assert_eq!(decoded.messages[0].payload(packet), &[1, 2, 3]);
    Ok(())
}
```

```text
68700001020301
```

## What the decoder refuses

The encoding is canonical: every packet the decoder accepts re-encodes to the same bytes. It
validates the whole packet before a connection acts on any of it, and refuses:

| `Malformed` | The packet |
|---|---|
| `Truncated` | Ends before a field does, including an empty packet |
| `ReservedKind` | Has a kind other than 0 |
| `ValueOutOfRange` | Has a field outside its range |
| `DuplicateChannel` | Has two sections for one channel |
| `EventOnWrongChannel` | Has an event in another channel's section |
| `PayloadTooLarge` | Has a payload over its event's maximum |
| `IdSpanExceedsWindow` | Has reliable ids spanning more than the channel's window |
| `NonzeroPadding` | Has padding bits that are not zero |
| `TrailingBytes` | Has bytes after the last section |
| `NonCanonical` | Uses serialize's absolute `int_relative` tier for an id, which dream-net never writes |
| `MissingHello` | Has no hello, and arrived before the peer's hello was verified |

A connection counts each refused packet, and fails with `MalformedData` at `malformed_limit`. A
hello that does not match is not malformed: it fails the connection with `SchemaMismatch` or
`ProtocolMismatch`.

## Changing it

`tests/wire_golden.rs` pins the bytes of five packets and the fingerprint of the test schema. A
change that alters either is a protocol change: `WIRE_VERSION` goes up in the same commit. The wire
version is in every hello and in every fingerprint, so builds speaking different versions refuse
each other with `ProtocolMismatch` and say so, instead of misreading each other.

Version 2 changed the fingerprint from FNV-1a to truncated SHA-256; the packet layout is the same as
version 1. dream-net 1.0.0 was the first release, and speaks version 2.
