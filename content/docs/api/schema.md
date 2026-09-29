+++
title = "Schema"
description = "Schema, SchemaBuilder, ChannelConfig, ChannelDef, EventDef, Delivery, OverflowPolicy, Fingerprint and the schema limits."
weight = 10

[extra]
kind = "api"
+++

Module `dream_net::schema`. Everything but the constants is re-exported from the root.
[Schemas and events](@/docs/schemas.md) explains how to use them.

## Schema

{{ api_signature(value="struct Schema") }}

A frozen schema. `Clone` shares it: a clone is a reference count, not a copy. `Debug`.

{{ api_signature(value="fn builder(schema_version: u32) -> SchemaBuilder") }}

Starts a [`SchemaBuilder`](#schemabuilder). The same as `SchemaBuilder::new`.

{{ api_signature(value="fn schema_version(&self) -> u32") }}

The host's catalogue version it was built with.

{{ api_signature(value="fn fingerprint(&self) -> Fingerprint") }}

The fingerprint peers compare during the handshake.

{{ api_signature(value="fn max_messages_per_packet(&self) -> u32") }}

The most events one packet may carry per channel.

{{ api_signature(value="fn channels(&self) -> &[ChannelDef]") }}

{{ api_signature(value="fn events(&self) -> &[EventDef]") }}

Every channel, indexed by `ChannelId`, and every event, indexed by `EventTypeId` and so sorted by
name.

{{ api_signature(value="fn channel(&self, id: ChannelId) -> Option<&ChannelDef>") }}

{{ api_signature(value="fn event(&self, id: EventTypeId) -> Option<&EventDef>") }}

A definition by id, or `None` for an id the schema does not have.

{{ api_signature(value="fn event_id(&self, name: &str) -> Option<EventTypeId>") }}

An event's id by name, found by binary search.

{{ api_signature(value="fn channel_id(&self, name: &str) -> Option<ChannelId>") }}

A channel's id by name.

{{ api_signature(value="fn ptr_eq(&self, other: &Self) -> bool") }}

Whether two handles share one frozen schema: identity, not structural equality. Two schemas built
separately from the same declarations are not `ptr_eq`, but have the same fingerprint.

## SchemaBuilder

{{ api_signature(value="struct SchemaBuilder") }}

Declares channels and events, then freezes them. `Clone`, `Debug`.

{{ api_signature(value="fn new(schema_version: u32) -> SchemaBuilder") }}

Starts a schema. `schema_version` is the host's catalogue version, and part of the fingerprint.
`max_messages_per_packet` starts at 64.

{{ api_signature(value="fn max_messages_per_packet(self, n: u32) -> SchemaBuilder") }}

Sets the most events one packet may carry per channel. It shapes the wire format, so it is part
of the fingerprint. `build` checks it is between 1 and `MAX_MESSAGES_PER_PACKET`, and the
transport configuration checks it against its received-packet window.

{{ api_signature(value="fn channel(&mut self, config: ChannelConfig) -> Result<ChannelId, ConfigError>") }}

Declares a channel and returns its id: its position in declaration order.

Refuses, in this order: an invalid name (`InvalidName`), a name already declared
(`DuplicateChannel`), a 65th channel (`TooManyChannels`), a capacity of 0 or a reliable window over
32768 (`InvalidCapacity`), a reliable channel with any overflow policy but `Fail`
(`ReliableOverflowPolicy`), and a resend interval that is negative or not finite
(`InvalidResendInterval`).

{{ api_signature(value="fn event(&mut self, name: impl Into<String>, channel: ChannelId, max_payload: u32) -> Result<(), ConfigError>") }}

Declares an event with codec version 0. Its id is assigned by `build`.

{{ api_signature(value="fn event_with_codec(&mut self, name: impl Into<String>, channel: ChannelId, max_payload: u32, codec_version: u32) -> Result<(), ConfigError>") }}

Declares an event with a codec version, which is part of the fingerprint.

Refuses, in this order: an invalid name (`InvalidName`), a channel not declared yet
(`UnknownChannel`), more than `MAX_EVENT_TYPES` events (`TooManyEvents`), a `max_payload` over
`MAX_EVENT_PAYLOAD` (`EventTooLarge`), and a name already declared (`DuplicateEvent`).

{{ api_signature(value="fn build(self) -> Result<Schema, ConfigError>") }}

Sorts the events by name, byte by byte, and numbers them from 0; records each channel's largest
payload and its events; and computes the fingerprint. Refuses a `max_messages_per_packet` outside
1 to 4096 with `InvalidMaxMessagesPerPacket`.

A name is 1 to `MAX_NAME_BYTES` bytes, each an ASCII letter or digit or one of `_ . : / -`.

## ChannelConfig

{{ api_signature(value="#[non_exhaustive] struct ChannelConfig { pub name: String, pub delivery: Delivery, pub capacity: u16, pub overflow: OverflowPolicy, pub packet_budget: Option<u32>, pub resend_interval: f64 }") }}

A channel to declare. `Clone`, `Debug`, `PartialEq`. Made with one of the two constructors, since
it is non-exhaustive; its fields can be read and assigned.

| Field | Meaning | Fingerprinted |
|---|---|---|
| `name` | Diagnostic name, unique in the schema | Yes |
| `delivery` | The delivery class | Yes |
| `capacity` | Reliable: the send and receive window, in events, at most 32768. Unreliable: the send queue | Yes |
| `overflow` | What a full unreliable queue does. Reliable channels must use `Fail` | No |
| `packet_budget` | The most payload and framing bytes this channel may put in one packet, or `None`. A single event larger than the budget is still sent, on its own | No |
| `resend_interval` | Reliable: seconds before an unacknowledged event is sent again | No |

{{ api_signature(value="fn reliable_ordered(name: impl Into<String>) -> ChannelConfig") }}

A reliable-ordered channel: capacity 1024, `Fail`, no packet budget, a 0.1-second resend interval.

{{ api_signature(value="fn unreliable_unordered(name: impl Into<String>) -> ChannelConfig") }}

An unreliable-unordered channel: capacity 1024, `Fail`, no packet budget, resend interval 0.

{{ api_signature(value="fn with_capacity(self, capacity: u16) -> ChannelConfig") }}

{{ api_signature(value="fn with_overflow(self, overflow: OverflowPolicy) -> ChannelConfig") }}

{{ api_signature(value="fn with_packet_budget(self, budget: u32) -> ChannelConfig") }}

{{ api_signature(value="fn with_resend_interval(self, seconds: f64) -> ChannelConfig") }}

Set one field and return the config. `with_packet_budget` sets `Some(budget)`.

## Delivery

{{ api_signature(value="enum Delivery { ReliableOrdered, UnreliableUnordered }") }}

`ReliableOrdered` delivers exactly once, in send order, resent until acknowledged.
`UnreliableUnordered` delivers at most once, in any order, never resent. `Clone`, `Copy`, `Debug`,
`Eq`, `Hash`.

## OverflowPolicy

{{ api_signature(value="enum OverflowPolicy { Fail, DropOldest, DropNewest }") }}

What an unreliable channel's `send` does when its queue is full: refuse with
`SendError::QueueFull`, drop the oldest queued event to make room, or drop the new event and report
success. `Fail` is the `Default`. `Clone`, `Copy`, `Debug`, `Eq`, `Hash`.

## ChannelDef

{{ api_signature(value="struct ChannelDef { pub id: ChannelId, pub config: ChannelConfig, pub max_payload: u32, pub events: Vec<EventTypeId> }") }}

A channel in a built schema: its id, its configuration, the largest `max_payload` of any event on
it (0 if it has none), and its events in id order. `Clone`, `Debug`, `PartialEq`.

{{ api_signature(value="fn name(&self) -> &str") }}

{{ api_signature(value="fn delivery(&self) -> Delivery") }}

Shorthand for `config.name` and `config.delivery`.

## EventDef

{{ api_signature(value="struct EventDef { pub id: EventTypeId, pub name: String, pub channel: ChannelId, pub max_payload: u32, pub codec_version: u32 }") }}

An event in a built schema: its id, its name, the channel that carries it, the largest payload it
may carry in bytes, and its codec version. `Clone`, `Debug`, `Eq`.

## Fingerprint

{{ api_signature(value="struct Fingerprint(pub u128)") }}

A 128-bit schema fingerprint: SHA-256 over a canonical encoding of the schema, truncated to its
first 16 bytes. It detects incompatible schemas and authenticates nothing. `Display` and `Debug`
print 32 lowercase hex digits. `Clone`, `Copy`, `Default`, `Eq`, `Hash`.

{{ api_signature(value="const fn halves(self) -> (u64, u64)") }}

The high and low 64 bits, for hosts without 128-bit integers.

## Constants

| Constant | Value | Limit on |
|---|---|---|
| `MAX_CHANNELS: usize` | 64 | Channels per schema |
| `MAX_EVENT_TYPES: usize` | `1 << 20` | Events per schema |
| `MAX_NAME_BYTES: usize` | 255 | A channel or event name |
| `MAX_RELIABLE_WINDOW: u16` | 32768 | A reliable channel's capacity: half the 16-bit id space, so wrapping comparisons stay unambiguous |
| `MAX_EVENT_PAYLOAD: u32` | `1 << 24` | An event's `max_payload`. The transport's packet size usually binds first |
| `MAX_MESSAGES_PER_PACKET: u32` | 4096 | `max_messages_per_packet` |
