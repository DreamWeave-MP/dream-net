+++
title = "Wire"
description = "The codec: Layout, PacketWriter, decode, Decoded, Section, Message, Hello, Malformed, DecodeError and WIRE_VERSION."
weight = 120

[extra]
kind = "api"
+++

Module `dream_net::wire`, not re-exported from the root. The codec every connection uses, public
for tools, tests and fuzzing. [Wire format](@/docs/wire.md) describes the bits and has a worked
example.

{{ api_signature(value="const WIRE_VERSION: u16 = 2") }}

The version of the wire format. It is carried in every hello and is part of every fingerprint.

## Layout

{{ api_signature(value="struct Layout") }}

Everything the codec needs from a schema, precomputed into flat tables: field widths, each
channel's facts, each event's channel and maximum payload, and this side's hello. `Clone`,
`Debug`.

{{ api_signature(value="fn new(schema: &Schema) -> Layout") }}

{{ api_signature(value="fn hello(&self) -> Hello") }}

The hello this side sends: `WIRE_VERSION` and the schema's fingerprint.

{{ api_signature(value="fn channel(&self, channel: ChannelId) -> &ChannelLayout") }}

A channel's wire facts. Panics for an id the schema does not have.

{{ api_signature(value="fn max_messages(&self) -> u32") }}

The most messages one section may carry: the schema's `max_messages_per_packet`.

{{ api_signature(value="fn header_bits(&self, hello: bool) -> u64") }}

{{ api_signature(value="fn section_bits(&self, channel: ChannelId) -> u64") }}

{{ api_signature(value="fn message_bits(&self, channel: ChannelId, len: usize) -> u64") }}

Bits of a packet header, with or without a hello; of a section header, including a reliable
section's first id; and at most of one message with a `len`-byte payload, counting alignment at
its worst, 7 bits.

{{ api_signature(value="fn worst_case_single_message_overhead(&self) -> usize") }}

The most bytes of framing around one message alone in a packet with a hello, so
`max_packet_size` less this is the largest payload that always fits.

## ChannelLayout

{{ api_signature(value="struct ChannelLayout { pub reliable: bool, pub window: u16, pub max_payload: u32, pub length_bits: u32 }") }}

Whether the channel is reliable and so carries message ids, its capacity, the largest payload of
any event on it, and the width of its length field. `Clone`, `Copy`, `Debug`.

## Hello

{{ api_signature(value="struct Hello { pub wire_version: u16, pub fingerprint: Fingerprint }") }}

The handshake a packet carries until the peer acknowledges one. `Clone`, `Copy`, `Debug`, `Eq`.

## PacketWriter

{{ api_signature(value="struct PacketWriter<'b>") }}

Writes one connection packet through serialize's `BitWriter`. The caller decides the section and
message counts first, since they precede their contents on the wire, and then writes exactly that
many. It is the trusted path: arguments are validated by the caller, and violations are debug
assertions. `Debug`.

{{ api_signature(value="fn new(buffer: &'b mut [u8]) -> PacketWriter<'b>") }}

Starts a packet in `buffer`, whose length must be a multiple of 8 and hold the packet plus one
word.

{{ api_signature(value="fn header(&mut self, layout: &Layout, hello: Option<Hello>, section_count: u32)") }}

{{ api_signature(value="fn section(&mut self, layout: &Layout, channel: ChannelId, message_count: u32)") }}

The packet header, then each section's header, without a reliable section's first id.

{{ api_signature(value="fn first_id(&mut self, id: Seq16)") }}

{{ api_signature(value="fn next_id(&mut self, delta: u32)") }}

A reliable section's first message id, then each later one as its forward distance from the
previous, at least 1. A distance past 69914, which no window of at most 32768 produces, panics.

{{ api_signature(value="fn message(&mut self, layout: &Layout, event: EventTypeId, payload: &[u8])") }}

One message: the event, the length, alignment, and the payload.

{{ api_signature(value="fn bits(&self) -> u64") }}

Bits written so far.

{{ api_signature(value="fn finish(self) -> usize") }}

Pads to a byte, flushes, and returns the packet's length in bytes.

{{ api_signature(value="fn relative_bits(delta: u32) -> u64") }}

A free function: the bits serialize's `int_relative` spends on a forward distance of `delta`, at
least 1. The packet builder uses it to cost a message id before writing it.

## decode

{{ api_signature(value="fn decode(layout: &Layout, packet: &[u8], out: &mut Decoded) -> Result<(), DecodeError>") }}

Decodes `packet` against `layout` into `out`, clearing it first. A hello that differs from the
layout's stops decoding with `Mismatch` before anything that depends on the schema is read. The
whole packet is validated before this returns `Ok`, so a caller never acts on part of a malformed
packet. Payloads are not copied: each `Message` says where its payload is in `packet`.

## Decoded

{{ api_signature(value="struct Decoded { pub hello: Option<Hello>, pub sections: Vec<Section>, pub messages: Vec<Message> }") }}

The result of `decode`: the packet's hello, if it carried one; its sections, and the messages of
all sections, in wire order. Reused across packets, so decoding allocates nothing once warm.
`Clone`, `Debug`, `Default`.

{{ api_signature(value="fn clear(&mut self)") }}

Empties it for reuse, keeping its capacity.

## Section

{{ api_signature(value="struct Section { pub channel: ChannelId, pub first: u32, pub count: u32 }") }}

A run of `count` messages on `channel`, starting at index `first` in `Decoded::messages`. `Clone`,
`Copy`, `Debug`, `Eq`.

## Message

{{ api_signature(value="struct Message { pub event: EventTypeId, pub id: Seq16, pub offset: u32, pub len: u32 }") }}

A decoded message: its event, its message id (reliable sections only; zero otherwise), and where
its payload lies in the packet. `Clone`, `Copy`, `Debug`, `Eq`.

{{ api_signature(value="fn payload<'p>(&self, packet: &'p [u8]) -> &'p [u8]") }}

The payload, borrowed from the decoded packet.

## DecodeError

{{ api_signature(value="enum DecodeError { Malformed(Malformed), Mismatch(Hello) }") }}

Decoding stopped: the packet is not valid wire format 2 for this schema, or it carries a hello
that does not match this side's, which is returned. `Display` prints the `Malformed`'s message, or
`mismatched hello: wire version 3, schema fingerprint ` and the foreign hello's fingerprint in 32
hex digits. `source()` is the `Malformed`, and nothing for a mismatch. `From<Malformed>`. `Clone`,
`Copy`, `Debug`, `Eq`, `std::error::Error`.

## Malformed

{{ api_signature(value="enum Malformed") }}

Why a packet was refused. `Clone`, `Copy`, `Debug`, `Eq`, `Display`, `std::error::Error`.

| Variant | `Display` |
|---|---|
| `Truncated` | `truncated packet` |
| `ReservedKind` | `reserved packet kind` |
| `ValueOutOfRange` | `value out of range` |
| `DuplicateChannel` | `duplicate channel section` |
| `EventOnWrongChannel` | `event on the wrong channel` |
| `PayloadTooLarge` | `payload larger than its event allows` |
| `IdSpanExceedsWindow` | `message ids span more than the channel window` |
| `NonzeroPadding` | `nonzero padding` |
| `TrailingBytes` | `trailing bytes` |
| `NonCanonical` | `non-canonical encoding` |
| `MissingHello` | `data before the handshake` |

[Wire format](@/docs/wire.md#what-the-decoder-refuses) says what each means.
`MissingHello` is never returned by `decode`: a connection reports it for a packet without a
hello before the peer's hello was verified.
