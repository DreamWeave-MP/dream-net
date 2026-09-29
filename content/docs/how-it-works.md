+++
title = "How it fits together"
description = "The layers from netcode up, one host frame, the schema handshake, what each channel promises, and how failures surface."
weight = 20

[extra]
kind = "guide"
+++

## The layers

| Layer | Owns |
|---|---|
| `Server`, `Client` | netcode's socket and client slots, `PeerId` handles, lifecycle events, one inbox per host |
| `Connection` | One peer: the reliable endpoint, the channels, the packet builder and the handshake |
| Channels | Reliable-ordered (resends, ack mapping, reordering) and unreliable-unordered queues |
| Wire | dream-net's packet format, bit-packed with serialize |
| reliable | Packet sequence numbers, acknowledgements, fragmentation, and RTT, loss and bandwidth estimates |
| netcode | Connect tokens, encryption, replay protection, timeouts and slots, over UDP |

A `Connection` never touches a socket: it turns queued events into datagrams and received datagrams
into inbox records, and whoever drives it moves the datagrams. `Server` and `Client` drive one per
peer over netcode. Tests and benchmarks drive two over the
[simulator](@/docs/simulator.md).

## One frame

A host drives the transport in one explicit network phase per frame:

```text
update(time)     receive, decrypt, decode, deliver, acknowledge, handshake, timers
poll()           lifecycle records and events, in arrival order, until None
send(...)        queue events; the payload is copied before send returns
flush()          pack queued events into packets, encrypt, send
```

Nothing calls into the host from inside any of these. A lost packet, an empty inbox or a slow link
is not an error: `poll` returns `None`, and the reliable channel sends again.

`time` is the host's clock in seconds, as an `f64`, and only moves forward: a value smaller than the
last one is treated as the last one. Resends, idle packets, the handshake timeout and the link
statistics all run on it, so a simulation can drive it however it likes.

## The handshake

A schema is fingerprinted when it is built, and every packet a connection sends carries a hello,
its wire version and that fingerprint, until the peer acknowledges one. The first packet from a
peer must carry a hello, and it is checked before anything else in the packet is read:

- the same wire version and fingerprint: the connection is established, and the host reports the
  peer as `Connected`;
- a different wire version: the connection fails with `ProtocolMismatch`;
- the same wire version and a different fingerprint: it fails with `SchemaMismatch`, carrying both
  fingerprints;
- no hello at all: the packet is malformed.

A server announces a peer only once its hello matched. A peer that fails is reported as `Rejected`
and was never addressable. A server keeps a mismatched client for `mismatch_linger` seconds, one by
default, sending only its own hello, so the client can report the mismatch with both fingerprints
too instead of seeing a bare disconnect. A peer that sends no hello within `handshake_timeout`, five
seconds by default, fails with `HandshakeTimeout`.

A peer's `Connected` record comes before any of its events, even when the packet that completed
the handshake carried events too.

## What each channel promises

| | Reliable-ordered | Unreliable-unordered |
|---|---|---|
| Delivered | Exactly once, in send order | At most once, in any order |
| Lost | Sent again every `resend_interval` until acknowledged | Gone |
| Queue full | `send` refuses with `QueueFull` | The channel's overflow policy: refuse, drop the oldest, or drop the new one |
| Receiver full | The packet goes unacknowledged; the sender resends it after the host polls | The event is dropped and counted |

An event is acknowledged when reliable acknowledges a packet that carried it. Each packet's header
acknowledges the latest packet received and the 32 before it. When a peer sends a burst, a
connection sends a small acknowledgement at once after every 16 packets it receives between two of
its own flushes, so no packet of the burst goes unacknowledged and is resent for nothing.

A connection that is idle still sends a small packet every `idle_packet_interval`, a tenth of a
second by default, because acknowledgements and link statistics only travel in packets.

## How failures surface

- **Misuse is an `Err`.** An unknown event, a payload over its maximum, a full queue, a peer that
  is not connected, a schema that does not validate.
- **Network conditions are not errors.** Loss, reordering, duplication and delay are what the
  channels exist for.
- **Malformed input is refused, counted, and ends the connection.** netcode authenticates every
  datagram, so malformed framing comes from a buggy or hostile peer, never from line noise. The
  default `malformed_limit` is one packet. Remote input never panics and never makes a connection
  allocate past its configured limits.

Every way a connection ends has a stable [`DisconnectReason`](@/docs/api/errors.md#disconnectreason),
with a camelCase name for scripts and logs.

## What dream-net does not do

It knows event ids, channel ids, peers and bytes. It has no actors, players, replication, authority,
RPC or rate limiting, and it never decodes a payload. The engine above it owns all of that; in
DreamWeave, that is Luau, through [l3i](https://github.com/DreamWeave-MP/l3i)'s `@dream/net`
module.
