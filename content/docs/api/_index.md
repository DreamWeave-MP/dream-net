+++
title = "Rust API"
description = "Every public type, function and constant in dream-net, and what the crate root re-exports."
template = "docs/section.html"
page_template = "docs/page.html"
sort_by = "weight"
weight = 90

[extra]
kind = "api"
hide_child_cards = true
+++

```toml
[dependencies]
dream-net = "1"
```

The crate is `dream_net`. Its modules are public, and the types a host uses are also re-exported
from the root, so `dream_net::Server` and `dream_net::server::Server` are the same type.

| Page | Covers | Module |
|---|---|---|
| [Schema](@/docs/api/schema.md) | `Schema`, `SchemaBuilder`, `ChannelConfig`, `ChannelDef`, `EventDef`, `Delivery`, `OverflowPolicy`, `Fingerprint`, the schema limits | `schema` |
| [Ids and sequences](@/docs/api/ids.md) | `EventTypeId`, `ChannelId`, `PeerId`, `Seq16` | `id`, `sequence` |
| [Server](@/docs/api/server.md) | `Server`, `ServerConfig`, `ServerEvent` | `server` |
| [Client](@/docs/api/client.md) | `Client`, `ClientConfig`, `ClientEvent`, `ClientStatus` | `client` |
| [Keys and tokens](@/docs/api/tokens.md) | `generate_key`, `generate_connect_token`, `Key`, `UserData` and their sizes, from netcode | root |
| [TransportConfig](@/docs/api/transport.md) | Every limit and timer, its default and its rule, and the datagram constants | `config` |
| [Lifecycle and errors](@/docs/api/errors.md) | `DisconnectReason`, `Failure`, `ConnectionState`, `ConfigError`, `SendError`, `BufferTooSmall`, `Error` | `lifecycle`, `error` |
| [Statistics](@/docs/api/stats.md) | `ConnectionStats`, `Counters`, `MemoryUsage` | `stats` |
| [Connection and inbox](@/docs/api/connection.md) | `Connection`, `Shared`, `ConnectionEvent`, `Inbox`, `Record`, `MessageInfo` | `connection`, `inbox` |
| [Captures](@/docs/api/capture.md) | `CaptureSink`, `CaptureWriter`, `CaptureReader`, their records and header | `capture` |
| [Simulator](@/docs/api/sim.md) | `Pair`, `Link`, `LinkConfig`, `LinkCounters`, `Rng` | `sim` |
| [Wire](@/docs/api/wire.md) | `Layout`, `PacketWriter`, `decode`, `Decoded`, `Malformed`, and the rest of the codec | `wire` |

## The root

Re-exported from their modules:

```text
Client, ClientConfig, ClientEvent, ClientStatus          client
TransportConfig                                          config
Connection, ConnectionEvent, Shared                      connection
BufferTooSmall, ConfigError, Error, SendError            error
ChannelId, EventTypeId, PeerId                           id
Inbox, MessageInfo, Record                               inbox
ConnectionState, DisconnectReason, Failure               lifecycle
ChannelConfig, ChannelDef, Delivery, EventDef,
    Fingerprint, OverflowPolicy, Schema, SchemaBuilder   schema
Seq16                                                    sequence
Server, ServerConfig, ServerEvent                        server
ConnectionStats, Counters, MemoryUsage                   stats
```

And from netcode, so a backend can mint keys and tokens with dream-net alone:
`CONNECT_TOKEN_BYTES`, `KEY_BYTES`, `Key`, `USER_DATA_BYTES`, `UserData`,
`generate_connect_token` and `generate_key`. See [Keys and tokens](@/docs/api/tokens.md).

The `capture`, `sim` and `wire` modules, and the constants in `schema`, `config` and `connection`,
are reached through their modules.

## Conventions

- **Time** is `f64` seconds on the host's monotonic clock. Every `update(time)` ignores a time
  earlier than the last.
- **Payloads** are `&[u8]` going in and are copied before the call returns. Coming out, they are
  borrowed until the next poll, or copied into a buffer the caller owns.
- **Errors**: misuse returns an `Err`, network conditions are not errors, and malformed remote
  input is counted and ends the connection. No remote input panics.
- **Nothing calls back** into the host from `update`, `poll` or `flush`, except the closures a
  `Connection` is given to transmit with and a capture sink the host installed.
