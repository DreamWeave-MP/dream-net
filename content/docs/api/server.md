+++
title = "Server"
description = "Server, ServerConfig and ServerEvent."
weight = 30

[extra]
kind = "api"
+++

Module `dream_net::server`, all re-exported from the root. [Servers and clients](@/docs/hosts.md)
shows them in use.

## ServerConfig

{{ api_signature(value="struct ServerConfig { pub public_address: SocketAddr, pub protocol_id: u64, pub max_clients: usize, pub transport: TransportConfig }") }}

| Field | Meaning |
|---|---|
| `public_address` | The address clients connect to, which tokens name. Port 0 binds a free port and advertises it |
| `protocol_id` | netcode's protocol id: the game's protocol family. Tokens minted for another are refused |
| `max_clients` | Client slots, 1 to 256 |
| `transport` | The [`TransportConfig`](@/docs/api/transport.md) |

`Clone`, `Debug`, `PartialEq`.

## ServerEvent

{{ api_signature(value="enum ServerEvent<P> { Connected { peer, client_id }, Disconnected { peer, reason }, Rejected { peer, client_id, failure }, Message { peer, event, channel, payload: P } }") }}

A lifecycle record or an event. `P` is the payload: `&[u8]` from `poll`, its length as `usize`
from `poll_into`. `Clone`, `Copy`, `Debug`, `Eq`.

| Variant | Fields | Meaning |
|---|---|---|
| `Connected` | `peer: PeerId`, `client_id: u64` | A client completed the handshake and can be sent events. `client_id` is the authenticated id from its token |
| `Disconnected` | `peer: PeerId`, `reason: DisconnectReason` | A connected client left, and its handle is now invalid. Every `Connected` is followed by exactly one |
| `Rejected` | `peer: PeerId`, `client_id: u64`, `failure: Failure` | A client authenticated with netcode but failed the handshake. It was never announced, and has been disconnected. `peer` is the handle it would have had |
| `Message` | `peer: PeerId`, `event: EventTypeId`, `channel: ChannelId`, `payload: P` | An event from a connected client. `peer` is the authenticated sender |

A peer's `Connected` precedes its messages, and its `Disconnected` follows them.

## Server

{{ api_signature(value="struct Server") }}

A server over netcode: its socket, its private key, and a connection per client slot. `Debug`
prints the address, slot count, connected count, fingerprint and time, never the key. Dropping it
stops netcode, which tells every client at once.

### Creating

{{ api_signature(value="fn new(config: ServerConfig, private_key: &Key, schema: Schema, time: f64) -> Result<Server, Error>") }}

Checks the schema against `config.transport` with `validate_for`, binds the socket and starts
accepting clients. `time` is the host's clock now.

Errors: `Error::Config` for a transport configuration or schema that `validate_for` refuses;
`Error::Netcode` for a `max_clients` outside 1 to 256 or a socket that cannot bind.

{{ api_signature(value="fn set_capture(&mut self, sink: Option<Box<dyn CaptureSink>>)") }}

Installs a [capture sink](@/docs/api/capture.md) that records every event this server sends and
every record it polls, or removes it with `None`.

### The frame

{{ api_signature(value="fn update(&mut self, time: f64)") }}

Receives and processes everything that arrived, then advances timers. Call once per frame. A
`time` earlier than the last is treated as the last. It accepts new clients, reports those that
left, receives and delivers every datagram, completes handshakes, and fails connections that time
out or send malformed data. A client that failed on a schema or protocol mismatch is kept, and its
traffic ignored, for `mismatch_linger` seconds, then disconnected.

{{ api_signature(value="fn poll(&mut self) -> Option<ServerEvent<&[u8]>>") }}

The next record, with its payload borrowed from the inbox until the next call, or `None` when the
inbox is empty.

{{ api_signature(value="fn poll_into(&mut self, buffer: &mut [u8]) -> Result<Option<ServerEvent<usize>>, BufferTooSmall>") }}

The next record, with an event's payload copied into the front of `buffer` and its length in
`payload`. If the payload does not fit, returns `BufferTooSmall` with the length it needs and
consumes nothing.

{{ api_signature(value="fn send(&mut self, peer: PeerId, event: EventTypeId, payload: &[u8]) -> Result<(), SendError>") }}

Queues an event to one client, copying the payload before it returns. Errors, with nothing queued:
`UnknownPeer` for a handle that is not a connected client; `UnknownEvent`, `PayloadTooLarge` or
`QueueFull` from its connection.

{{ api_signature(value="fn broadcast(&mut self, event: EventTypeId, payload: &[u8]) -> Result<usize, SendError>") }}

{{ api_signature(value="fn broadcast_except(&mut self, except: Option<PeerId>, event: EventTypeId, payload: &[u8]) -> Result<usize, SendError>") }}

Queues an event to every connected client, or every one but `except`. Returns how many clients'
queues refused it: on a reliable channel, those whose window was full. `UnknownEvent` and
`PayloadTooLarge` are errors before anything is queued.

{{ api_signature(value="fn flush(&mut self)") }}

Packs and sends everything queued, plus owed acknowledgements, hellos and idle packets. netcode
only refuses a datagram outside 1 to 1200 bytes, which the transport configuration rules out; if
it ever refused one, that client would be failed with `TransportError` rather than silently lose
its traffic. Socket errors surface as loss, and in the end as a timeout.

### Peers

{{ api_signature(value="fn peers(&self) -> impl Iterator<Item = PeerId> + '_") }}

Every connected client, in slot order.

{{ api_signature(value="fn num_connected(&self) -> usize") }}

{{ api_signature(value="fn max_clients(&self) -> usize") }}

Connected clients, and slots.

{{ api_signature(value="fn client_id(&self, peer: PeerId) -> Option<u64>") }}

{{ api_signature(value="fn client_address(&self, peer: PeerId) -> Option<SocketAddr>") }}

{{ api_signature(value="fn client_user_data(&self, peer: PeerId) -> Option<&UserData>") }}

A connected client's id and user data from its connect token, and its address.

{{ api_signature(value="fn stats(&self, peer: PeerId) -> Option<ConnectionStats>") }}

{{ api_signature(value="fn counters(&self, peer: PeerId) -> Option<Counters>") }}

A connected client's [link estimates and counters](@/docs/api/stats.md).

{{ api_signature(value="fn peer_connection(&self, peer: PeerId) -> Option<&Connection>") }}

A connected client's [`Connection`](@/docs/api/connection.md), for diagnostics such as
`last_malformed` and `parked_bytes`.

Each returns `None` for a handle that is not a connected client, including a stale one.

{{ api_signature(value="fn disconnect(&mut self, peer: PeerId)") }}

Disconnects a client now. A connected client's `Disconnected { reason: Requested }` is queued; a
client still handshaking is dropped without a record. A stale handle does nothing.

{{ api_signature(value="fn disconnect_all(&mut self)") }}

Disconnects every client, as `disconnect` does.

### Everything else

{{ api_signature(value="fn schema(&self) -> &Schema") }}

{{ api_signature(value="fn address(&self) -> SocketAddr") }}

The schema, and the address clients connect to, with the port it bound.

{{ api_signature(value="fn memory_usage(&self) -> MemoryUsage") }}

Approximate native memory of every connection, with the inbox counted as `receive`.
