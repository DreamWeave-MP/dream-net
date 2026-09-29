+++
title = "Connection and inbox"
description = "Connection, Shared, ConnectionEvent, the connection constants, and Inbox, Record and MessageInfo."
weight = 90

[extra]
kind = "api"
+++

Modules `dream_net::connection` and `dream_net::inbox`. The types are re-exported from the root;
the constants are not. [Connections and the simulator](@/docs/simulator.md) shows how a host drives
them.

## Shared

{{ api_signature(value="struct Shared") }}

The schema, the transport configuration and the precomputed wire layout that every connection of
a host shares. `Debug`.

{{ api_signature(value="fn new(schema: Schema, config: TransportConfig) -> Result<Arc<Shared>, ConfigError>") }}

Checks `config` against `schema` with `validate_for`, and precomputes the layout.

{{ api_signature(value="fn schema(&self) -> &Schema") }}

{{ api_signature(value="fn config(&self) -> &TransportConfig") }}

## Connection

{{ api_signature(value="struct Connection") }}

One end of a connection, independent of any socket: the reliable endpoint, the channels, the packet
builder and the handshake. `Debug`.

It is the engine room, and trusts its caller: it accepts `send` before its handshake completes,
exposes raw datagram input and output, and takes whatever time it is given, as long as it does not
go backwards. `Server` and `Client` only let events through once a peer is announced.

{{ api_signature(value="fn new(shared: Arc<Shared>, peer: PeerId, time: f64) -> Connection") }}

A connection that delivers into its inbox as `peer`, starting at `time`, handshaking.

{{ api_signature(value="fn update(&mut self, time: f64)") }}

Advances time: refreshes the link statistics and fails the connection with `HandshakeTimeout` if it
is still handshaking `handshake_timeout` seconds after it was created. Call it at the start of a
frame, before that frame's `receive` calls, so acknowledgements carry the current time. A `time`
earlier than the last is treated as the last.

{{ api_signature(value="fn receive<L: Copy>(&mut self, datagram: &[u8], inbox: &mut Inbox<L>, transmit: impl FnMut(&[u8]))") }}

Processes one received datagram. reliable reassembles fragments and rejects duplicates; the packet
is decoded and validated whole; a hello is checked; reliable events are delivered in order or parked
behind a gap, and unreliable ones delivered, into `inbox` as `peer`. A packet whose events cannot all
be taken, because of the pending limits or the parked budget, is left unacknowledged. Malformed
packets are counted, and fail the connection at `malformed_limit`.

After `ACK_EVERY` received packets that carried a hello or events, with no packet sent since, it
sends a small acknowledgement through `transmit` at once. An empty datagram, or any datagram once the connection
has failed, is ignored.

{{ api_signature(value="fn take_event(&mut self) -> Option<ConnectionEvent>") }}

The next state change the caller has not seen: `Established` once, when the peer's hello matched,
and `Failed` once, when the connection failed. The events in the packet that completed the
handshake are already in the inbox by then; a host announcing the peer puts its own record ahead
of them.

{{ api_signature(value="fn send(&mut self, event: EventTypeId, payload: &[u8]) -> Result<(), SendError>") }}

Queues an event on its channel, copying the payload. Errors, with nothing queued: `UnknownEvent`,
`PayloadTooLarge`, `QueueFull`.

{{ api_signature(value="fn write_packets(&mut self, transmit: impl FnMut(&[u8]))") }}

Packs queued events into as many packets as needed, up to `max_packets_per_flush`, and hands each
resulting datagram to `transmit`. Sends a small packet anyway when acknowledgements are owed, the
hello is unacknowledged, or `idle_packet_interval` has passed. A connection that failed on a schema
or protocol mismatch sends only its hello, so the peer can see the mismatch too; any other failed
connection sends nothing.

{{ api_signature(value="fn peer(&self) -> PeerId") }}

{{ api_signature(value="fn state(&self) -> ConnectionState") }}

The peer it delivers as, and where it stands.

{{ api_signature(value="fn stats(&self) -> ConnectionStats") }}

{{ api_signature(value="fn counters(&self) -> Counters") }}

{{ api_signature(value="fn memory_usage(&self) -> MemoryUsage") }}

[Link estimates, counters and memory](@/docs/api/stats.md).

{{ api_signature(value="fn reliable_counters(&self) -> &reliable::Counters") }}

reliable's own counters: fragments, stale and duplicate packets.

{{ api_signature(value="fn queued(&self, channel: ChannelId) -> usize") }}

Events on a channel not yet sent, if it is unreliable, or not yet acknowledged, if it is reliable.
0 for a channel the schema does not have.

{{ api_signature(value="fn queued_bytes(&self) -> usize") }}

Payload bytes queued across every channel.

{{ api_signature(value="fn parked_bytes(&self) -> usize") }}

Bytes charged against `max_parked_bytes`: every reorder-buffer slot at `PARK_OVERHEAD` and every
parked payload buffer's capacity.

{{ api_signature(value="fn last_malformed(&self) -> Option<Malformed>") }}

Why the last malformed packet was refused, for diagnostics. See
[`Malformed`](@/docs/api/wire.md#malformed).

## ConnectionEvent

{{ api_signature(value="enum ConnectionEvent { Established, Failed(Failure) }") }}

A state change the host must act on: announce the peer, or tear the connection down. `Clone`,
`Copy`, `Debug`, `Eq`.

## Constants

| Constant | Value | Meaning |
|---|---|---|
| `ACK_EVERY: u32` | 16 | Received packets after which `receive` acknowledges at once: half of reliable's 33-packet acknowledgement window, leaving room for reordering |
| `PARK_OVERHEAD: usize` | 32 on 64-bit targets | Bytes charged against `max_parked_bytes` for each slot of reorder-buffer capacity: the slot's real size |

## Inbox

{{ api_signature(value="struct Inbox<L>") }}

A host's receive queue: lifecycle records of the host's own type `L` and messages, in arrival
order, with payloads in one arena. Every connection of a host delivers into one inbox. It keeps
one account per slot, which the connections check against the pending limits. `Debug`. The
methods need `L: Copy`.

{{ api_signature(value="fn new(slots: usize) -> Inbox<L>") }}

An empty inbox with accounts for `slots` connections. Every `PeerId` given to the other methods
must have a slot below `slots`.

{{ api_signature(value="fn open_slot(&mut self, peer: PeerId)") }}

Starts a new connection's account in `peer`'s slot. Records still queued for the slot's previous
peer stay deliverable, but no longer count against the slot.

{{ api_signature(value="fn push_lifecycle(&mut self, record: L)") }}

Queues a lifecycle record after everything already queued.

{{ api_signature(value="fn pop(&mut self) -> Option<(Record<L>, &[u8])>") }}

The next record, with a message's payload borrowed from the arena until the next call. A lifecycle
record comes with an empty slice.

{{ api_signature(value="fn pop_into(&mut self, buffer: &mut [u8]) -> Result<Option<Record<L>>, BufferTooSmall>") }}

The next record, with a message's payload copied into the front of `buffer`. If it does not fit,
returns `BufferTooSmall` and consumes nothing.

{{ api_signature(value="fn peek_len(&self) -> Option<usize>") }}

The payload length of the next record, if it is a message.

{{ api_signature(value="fn compact(&mut self)") }}

Reclaims arena space taken by polled messages. Call once per host update; when everything was
polled it only clears the arena, and otherwise it moves what is left down once at least half the
arena was polled.

{{ api_signature(value="fn len(&self) -> usize") }}

{{ api_signature(value="fn is_empty(&self) -> bool") }}

Records waiting.

{{ api_signature(value="fn pending(&self, peer: PeerId) -> (usize, usize)") }}

The events and payload bytes `peer` has waiting; `(0, 0)` for a peer whose slot has moved on.

{{ api_signature(value="fn has_room(&self, peer: PeerId, len: usize, max_events: usize, max_bytes: usize) -> bool") }}

Whether `peer`'s slot may queue another `len`-byte event under those limits.

{{ api_signature(value="fn memory_usage(&self) -> usize") }}

Approximate bytes held.

## Record

{{ api_signature(value="enum Record<L> { Message(MessageInfo), Lifecycle(L) }") }}

One polled record: a received event, or a host-defined lifecycle record. `Clone`, `Copy`, `Debug`,
`Eq`.

## MessageInfo

{{ api_signature(value="struct MessageInfo { pub peer: PeerId, pub event: EventTypeId, pub channel: ChannelId, pub len: usize }") }}

A received event without its payload: the authenticated sender, the event, the channel it arrived
on, and the payload's length. `Clone`, `Copy`, `Debug`, `Eq`.
