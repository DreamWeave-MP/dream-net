+++
title = "Client"
description = "Client, ClientConfig, ClientEvent and ClientStatus."
weight = 40

[extra]
kind = "api"
+++

Module `dream_net::client`, all re-exported from the root. [Servers and clients](@/docs/hosts.md)
shows them in use.

## ClientConfig

{{ api_signature(value="struct ClientConfig { pub bind_address: SocketAddr, pub transport: TransportConfig }") }}

`bind_address` is the local address to bind; port 0 lets the operating system choose. Its address
family must match the server addresses in connect tokens. `transport` is the
[`TransportConfig`](@/docs/api/transport.md). `Clone`, `Debug`, `PartialEq`.

## ClientEvent

{{ api_signature(value="enum ClientEvent<P> { Connected, Disconnected { reason }, ConnectFailed { reason, failure }, Message { event, channel, payload: P } }") }}

A lifecycle record or an event. `P` is the payload: `&[u8]` from `poll`, its length as `usize`
from `poll_into`. `Clone`, `Copy`, `Debug`, `Eq`.

| Variant | Fields | Meaning |
|---|---|---|
| `Connected` | | The handshake completed: events can be sent |
| `Disconnected` | `reason: DisconnectReason` | The connection ended after `Connected` |
| `ConnectFailed` | `reason: DisconnectReason`, `failure: Option<Failure>` | The attempt ended before `Connected`. `failure` is dream-net's handshake failure when that was the cause; a schema mismatch carries both fingerprints |
| `Message` | `event: EventTypeId`, `channel: ChannelId`, `payload: P` | An event from the server |

Every connect attempt ends in exactly one `Disconnected`, after `Connected`, or one
`ConnectFailed`, before it. `Connected` precedes the server's first event.

## ClientStatus

{{ api_signature(value="enum ClientStatus { Disconnected, Connecting, Handshaking, Connected }") }}

Idle; netcode exchanging connection requests and responses; netcode connected and waiting for the
server's hello; and events flowing. `Clone`, `Copy`, `Debug`, `Eq`.

## Client

{{ api_signature(value="struct Client") }}

A client over netcode. `Debug` prints its status, server address, fingerprint and time. Dropping
it disconnects.

{{ api_signature(value="fn new(config: ClientConfig, schema: Schema, time: f64) -> Result<Client, Error>") }}

Checks the schema against `config.transport` with `validate_for` and binds the socket. Errors:
`Error::Config` for a pairing `validate_for` refuses, `Error::Netcode` for a socket that cannot
bind.

{{ api_signature(value="fn connect(&mut self, token: &[u8; CONNECT_TOKEN_BYTES]) -> Result<(), Error>") }}

Starts connecting with a connect token, ending any attempt or connection in progress first, as
`disconnect` does. A token netcode cannot parse is `Error::Netcode`, and the attempt also ends with
`ConnectFailed { reason: Authentication, failure: None }`.

{{ api_signature(value="fn disconnect(&mut self)") }}

Tells the server and ends the connection or attempt, with `Disconnected` or `ConnectFailed` and
reason `Requested`. Does nothing when idle.

{{ api_signature(value="fn status(&self) -> ClientStatus") }}

Where the client stands.

{{ api_signature(value="fn update(&mut self, time: f64)") }}

Receives and processes everything that arrived, then advances timers. Call once per frame. A
`time` earlier than the last is treated as the last. When netcode connects, it starts the
connection; when the server's hello arrives, it queues `Connected`; when the attempt or connection
ends, it queues the one record that says why.

The reason comes from netcode's state when netcode ended it: `Authentication` for an expired or
invalid token, `TimedOut` for a request, response or connection that timed out, `Denied` when the
server refused, and `Remote` otherwise. When dream-net's handshake failed, it is the failure's
reason and `failure` says which.

{{ api_signature(value="fn poll(&mut self) -> Option<ClientEvent<&[u8]>>") }}

{{ api_signature(value="fn poll_into(&mut self, buffer: &mut [u8]) -> Result<Option<ClientEvent<usize>>, BufferTooSmall>") }}

As on the [server](@/docs/api/server.md#the-frame): the payload borrowed until the next call, or
copied into `buffer`, with `BufferTooSmall` consuming nothing.

{{ api_signature(value="fn send(&mut self, event: EventTypeId, payload: &[u8]) -> Result<(), SendError>") }}

Queues an event to the server, copying the payload before it returns. Errors, with nothing queued:
`NotConnected` before `Connected`; `UnknownEvent`, `PayloadTooLarge` or `QueueFull` from the
connection.

{{ api_signature(value="fn flush(&mut self)") }}

Packs and sends everything queued, plus owed acknowledgements, the hello and idle packets. If
netcode ever refused a datagram, the connection would end with `TransportError`.

{{ api_signature(value="fn set_capture(&mut self, sink: Option<Box<dyn CaptureSink>>)") }}

Installs a [capture sink](@/docs/api/capture.md), or removes it with `None`.

{{ api_signature(value="fn schema(&self) -> &Schema") }}

{{ api_signature(value="fn server_address(&self) -> Option<SocketAddr>") }}

{{ api_signature(value="fn port(&self) -> u16") }}

The schema; the server's address while connecting or connected; and the local port.

{{ api_signature(value="fn stats(&self) -> Option<ConnectionStats>") }}

{{ api_signature(value="fn counters(&self) -> Option<Counters>") }}

[Link estimates and counters](@/docs/api/stats.md), from the moment netcode connects, through the
handshake, until the connection ends; `None` before netcode connects and when idle.

{{ api_signature(value="fn memory_usage(&self) -> MemoryUsage") }}

Approximate native memory of the connection, with the inbox counted as `receive`.
