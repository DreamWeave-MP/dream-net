+++
title = "Lifecycle and errors"
description = "DisconnectReason, Failure, ConnectionState, ConfigError, SendError, BufferTooSmall and Error."
weight = 70

[extra]
kind = "api"
+++

Modules `dream_net::lifecycle` and `dream_net::error`, all re-exported from the root.

Misuse of the API is an `Err` of one of the error types here. Ordinary network conditions are not
errors at all. Malformed remote input never reaches the host as an error: it is refused, counted,
and ends the connection with a `Failure`. A tool that decodes packets itself gets the codec's
[`DecodeError`](@/docs/api/wire.md#decodeerror), which is a `std::error::Error` like these.

## DisconnectReason

{{ api_signature(value="enum DisconnectReason") }}

Why a connection ended. Stable, so hosts can map them to player-facing messages; they do not
promise a one-to-one mapping onto netcode's internal states. `Display` prints the name.
`Clone`, `Copy`, `Debug`, `Eq`, `Hash`.

| Variant | `name()` | Meaning |
|---|---|---|
| `Requested` | `requested` | This side asked to disconnect |
| `Remote` | `remote` | The other side closed the connection |
| `TimedOut` | `timeout` | Nothing was heard from the other side within netcode's timeout |
| `Denied` | `denied` | The server refused the connection: it is full, or the client id is already connected |
| `Authentication` | `authentication` | The connect token was invalid or expired |
| `ProtocolMismatch` | `protocolMismatch` | The peer speaks a different wire version |
| `SchemaMismatch` | `schemaMismatch` | The peer's schema fingerprint differs |
| `MalformedData` | `malformedData` | The peer sent malformed framing |
| `HandshakeTimeout` | `handshakeTimeout` | The peer never completed the handshake |
| `TransportError` | `transportError` | The transport failed |

{{ api_signature(value="const fn name(self) -> &'static str") }}

The stable camelCase name, for scripts and logs.

## Failure

{{ api_signature(value="enum Failure { ProtocolMismatch { local: u16, remote: u16 }, SchemaMismatch { local: Fingerprint, remote: Fingerprint }, MalformedData, HandshakeTimeout, TransportError }") }}

Why a connection failed, as dream-net saw it. A protocol mismatch carries both wire versions and a
schema mismatch both fingerprints, `local` being this side's. `MalformedData` means more malformed
packets than `malformed_limit`. `TransportError` means netcode refused a datagram, which dream-net
sizes so it cannot happen; if it ever does, it is reported rather than traffic silently dropped.
`Clone`, `Copy`, `Debug`, `Eq`.

{{ api_signature(value="const fn reason(self) -> DisconnectReason") }}

The disconnect reason of the same name.

## ConnectionState

{{ api_signature(value="enum ConnectionState { Handshaking, Established, Failed(Failure) }") }}

Where a [`Connection`](@/docs/api/connection.md) stands: waiting for the peer's hello, exchanging
events, or failed and waiting to be torn down. `Clone`, `Copy`, `Debug`, `Eq`.

## ConfigError

{{ api_signature(value="#[non_exhaustive] enum ConfigError") }}

A schema or transport configuration was refused. `Clone`, `Debug`, `Eq`, `Display`,
`std::error::Error`.

| Variant | `Display` |
|---|---|
| `InvalidName(String)` | `invalid name "a b": names are 1-255 bytes of [A-Za-z0-9_.:/-]` |
| `DuplicateChannel(String)` | `duplicate channel "state"` |
| `DuplicateEvent(String)` | `duplicate event "Chat"` |
| `TooManyChannels` | `too many channels` |
| `TooManyEvents` | `too many events` |
| `UnknownChannel(ChannelId)` | `unknown channel 9` |
| `InvalidCapacity { channel: String, capacity: u16 }` | `channel "chat" has invalid capacity 0` |
| `ReliableOverflowPolicy(String)` | `reliable channel "chat" must refuse on overflow, not drop` |
| `InvalidResendInterval(String)` | `channel "chat" has an invalid resend interval` |
| `InvalidMaxMessagesPerPacket(u32)` | `max messages per packet 0 is outside [1, 4096]` |
| `EventTooLarge { event: String, max_payload: u32, limit: u32 }` | `event "Snapshot" allows 65536 byte payloads, but at most 32743 fit` |
| `Transport(&'static str)` | `invalid transport configuration: fragment_size must be in [1, MAX_FRAGMENT_SIZE]` |

`EventTooLarge` comes from the schema, with `MAX_EVENT_PAYLOAD` as the limit, or from
`validate_for`, with what one packet can carry. `Transport` names the first bad value.

## SendError

{{ api_signature(value="#[non_exhaustive] enum SendError") }}

Queueing an outgoing event failed, and nothing was queued. `Clone`, `Copy`, `Debug`, `Eq`,
`Display`, `std::error::Error`.

| Variant | `Display` | Meaning |
|---|---|---|
| `UnknownPeer(PeerId)` | `peer 0:1 is not connected` | The peer never existed, has left, or has not finished its handshake |
| `NotConnected` | `not connected` | The client has not finished its handshake |
| `UnknownEvent(EventTypeId)` | `unknown event 9` | The schema has no such event |
| `PayloadTooLarge { event: EventTypeId, len: usize, max: u32 }` | `65 byte payload exceeds the 64 byte maximum of event 0` | The payload is over the event's maximum |
| `QueueFull(ChannelId)` | `channel 0 send queue is full` | A reliable channel's window is full, or an unreliable one's queue under `Fail` |

## BufferTooSmall

{{ api_signature(value="struct BufferTooSmall { pub needed: usize }") }}

The buffer given to `poll_into` cannot hold the next payload, of `needed` bytes. The event was not
consumed: grow the buffer and poll again. `Display` prints
`buffer too small: the next payload is 300 bytes`. `Clone`, `Copy`, `Debug`, `Eq`,
`std::error::Error`.

## Error

{{ api_signature(value="#[non_exhaustive] enum Error { Config(ConfigError), Netcode(netcode::Error) }") }}

Creating or starting a server or client failed: the schema or transport configuration was refused,
or netcode refused (a socket, a token, or a slot count). `Display` prints the `ConfigError`'s
message, or `netcode: ` and netcode's. `source()` is the inner error. `From<ConfigError>` and
`From<netcode::Error>`. `Debug`.

```rust
use dream_net::{ChannelConfig, ConfigError, Schema, TransportConfig};

fn main() {
    let mut schema = Schema::builder(1);
    let error = schema.channel(ChannelConfig::reliable_ordered("a b")).unwrap_err();
    assert_eq!(error, ConfigError::InvalidName("a b".into()));
    assert_eq!(
        error.to_string(),
        r#"invalid name "a b": names are 1-255 bytes of [A-Za-z0-9_.:/-]"#
    );

    let reliable = schema.channel(ChannelConfig::reliable_ordered("reliable")).unwrap();
    schema.event("Snapshot", reliable, 65536).unwrap();
    let schema = schema.build().unwrap();
    let error = TransportConfig::default().validate_for(&schema).unwrap_err();
    println!("{error}");
}
```

```text
event "Snapshot" allows 65536 byte payloads, but at most 32743 fit
```
