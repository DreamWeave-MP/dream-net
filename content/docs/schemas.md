+++
title = "Schemas and events"
description = "Declaring channels and events, how event ids and the fingerprint are derived, what both ends must agree on, and the limits."
weight = 30

[extra]
kind = "guide"
+++

The engine's event system decides what events mean. Before networking starts, it hands dream-net
the transport view of the events that cross the wire: a name, a channel, and the largest payload
each may carry. That is a schema. It is frozen when it is built, and a server or client takes it
when it is created.

## Declaring one

```rust
use dream_net::{ChannelConfig, OverflowPolicy, Schema};

fn main() -> Result<(), dream_net::ConfigError> {
    let mut schema = Schema::builder(3);
    let reliable = schema.channel(ChannelConfig::reliable_ordered("reliable"))?;
    let state = schema.channel(
        ChannelConfig::unreliable_unordered("state").with_overflow(OverflowPolicy::DropOldest),
    )?;
    schema.event("Chat", reliable, 256)?;
    schema.event("SpellCast", reliable, 64)?;
    schema.event("ActorPosition", state, 28)?;
    let schema = schema.build()?;

    // ids come from the sorted names
    assert_eq!(schema.event_id("ActorPosition").map(|id| id.0), Some(0));
    assert_eq!(schema.event_id("Chat").map(|id| id.0), Some(1));
    assert_eq!(schema.event_id("SpellCast").map(|id| id.0), Some(2));
    println!("schema {} fingerprint {}", schema.schema_version(), schema.fingerprint());
    Ok(())
}
```

`Schema::builder` takes the host's catalogue version, a number the host bumps when its set of
events changes. `channel` returns the new channel's `ChannelId`, and `event` puts an event on one.
`build` sorts, numbers, freezes and fingerprints.

- **Channel ids follow declaration order**, from 0. The host declares its channels in one place,
  so that order is deterministic.
- **Event ids follow the sorted names**, byte by byte, from 0. The order events were declared in
  never matters: two hosts that register the same events in different orders get the same ids.
- **Names** are 1 to 255 bytes of `A-Z`, `a-z`, `0-9`, `_`, `.`, `:`, `/` and `-`, unique among
  channels and unique among events.

A built `Schema` is shared: cloning it is a reference count, and `ptr_eq` says whether two handles
are the same frozen schema.

## The fingerprint

`build` computes a 128-bit fingerprint: SHA-256 over a canonical encoding of the schema, truncated.
Every packet a connection sends carries it until the peer acknowledges one, and a peer with a
different one is refused on both ends before any event is accepted.

It covers everything the two ends must agree on to read each other's packets:

| Covered | Not covered |
|---|---|
| The wire version | Each channel's `overflow`, `packet_budget` and `resend_interval` |
| The catalogue version and `max_messages_per_packet` | The `TransportConfig` |
| Each channel's name, delivery class and capacity | The order events were declared in |
| Each event's id, name, channel, maximum payload and codec version | |

What is not covered is how each side sends, which the other side never needs to know. The
transport configuration need not match between peers at all.

A cryptographic digest rather than a fast checksum makes it impractical for an authenticated but
hostile peer to craft a different schema with the same fingerprint. It detects incompatible
schemas; it authenticates nothing, which is netcode's job.

`Fingerprint` displays as 32 hex digits. `halves()` splits it into two `u64`s for hosts without
128-bit integers, such as Luau.

## Codec versions

`event` declares an event with codec version 0. `event_with_codec` takes one explicitly:

```rust
use dream_net::{ChannelConfig, Schema};

fn main() -> Result<(), dream_net::ConfigError> {
    let build = |codec| -> Result<Schema, dream_net::ConfigError> {
        let mut schema = Schema::builder(1);
        let reliable = schema.channel(ChannelConfig::reliable_ordered("reliable"))?;
        schema.event_with_codec("Inventory", reliable, 512, codec)?;
        schema.build()
    };
    // the same event with a new payload encoding: peers must not mix them
    assert_ne!(build(1)?.fingerprint(), build(2)?.fingerprint());
    Ok(())
}
```

dream-net never decodes a payload. The codec version is how a host says its encoding of one event
changed, so that old and new builds refuse each other instead of misreading each other's bytes.

## Packets per section

`max_messages_per_packet` is how many events one packet may carry per channel, 64 unless set. It
shapes the wire format, so it is part of the fingerprint. It takes and returns the builder, so set
it first:

```rust
use dream_net::{ChannelConfig, Schema};

fn main() -> Result<(), dream_net::ConfigError> {
    let mut schema = Schema::builder(1).max_messages_per_packet(32);
    let reliable = schema.channel(ChannelConfig::reliable_ordered("reliable"))?;
    schema.event("Chat", reliable, 256)?;
    assert_eq!(schema.build()?.max_messages_per_packet(), 32);
    Ok(())
}
```

## Looking things up

| Call | Returns |
|---|---|
| `event_id(name)` | The `EventTypeId` of a name, by binary search |
| `channel_id(name)` | The `ChannelId` of a name |
| `event(id)`, `channel(id)` | The `EventDef` or `ChannelDef`, if the id exists |
| `events()`, `channels()` | Every definition, indexed by id |
| `fingerprint()`, `schema_version()`, `max_messages_per_packet()` | What was built |

A `ChannelDef` also knows the largest payload of any event on it and its events in id order.

## Limits

| Limit | Value |
|---|---|
| Channels | 64 (`MAX_CHANNELS`) |
| Events | 1,048,576 (`MAX_EVENT_TYPES`) |
| Name length | 255 bytes (`MAX_NAME_BYTES`) |
| Reliable window | 32768 messages (`MAX_RELIABLE_WINDOW`) |
| Payload per event | 16 MiB (`MAX_EVENT_PAYLOAD`) |
| `max_messages_per_packet` | 1 to 4096 (`MAX_MESSAGES_PER_PACKET`) |

The transport usually binds first. A server or client checks its schema against its
`TransportConfig` when it is created, and refuses an event whose maximum payload cannot fit one
packet of `max_packet_size`, 32 KiB by default, less the worst-case framing around it. Every
declaration error is a [`ConfigError`](@/docs/api/errors.md#configerror) that names what is wrong.
