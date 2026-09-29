+++
title = "Servers and clients"
description = "Keys and connect tokens, starting a server and a client, the frame loop, every lifecycle event, peers, sending, broadcasting and disconnecting."
weight = 50

[extra]
kind = "guide"
+++

`Server` and `Client` are the two hosts. Each owns a netcode socket, one `Connection` per peer, and
an inbox that everything it receives goes into, in arrival order.

## Keys and connect tokens

netcode authenticates clients with connect tokens. A trusted backend holds the server's private
key, mints one token per client, and hands it over a secure channel such as HTTPS. The client
presents it and never sees the key.

```rust
use dream_net::{KEY_BYTES, USER_DATA_BYTES};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = dream_net::generate_key();
    assert_eq!(key.len(), KEY_BYTES);

    let server: std::net::SocketAddr = "203.0.113.7:40000".parse()?;
    let mut user_data = [0u8; USER_DATA_BYTES];
    user_data[..5].copy_from_slice(b"guest");
    let token = dream_net::generate_connect_token(
        &[server],  // where the client connects
        &[server],  // what the server checks its own address against
        30,         // the token expires 30 seconds after it is made
        5,          // the connection times out after 5 seconds without a packet
        1001,       // the client id the server will report
        0x4452_4541_4d00_0001,
        &key,
        &user_data,
    )?;
    assert_eq!(token.len(), dream_net::CONNECT_TOKEN_BYTES);
    Ok(())
}
```

`generate_key`, `generate_connect_token`, `Key`, `UserData` and their sizes are netcode's,
re-exported so a backend can mint tokens with dream-net alone. The public and internal address
lists differ when servers sit behind NAT or a load balancer; they hold between 1 and 32 servers,
the same number in each. A negative expiry or timeout means never, for development only.

The key stays in trusted Rust. `Server` never exposes it, and its `Debug` output leaves it out.

## Starting a server

```rust
use dream_net::{ChannelConfig, Schema, Server, ServerConfig, TransportConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut schema = Schema::builder(1);
    let reliable = schema.channel(ChannelConfig::reliable_ordered("reliable"))?;
    schema.event("Chat", reliable, 256)?;

    let server = Server::new(
        ServerConfig {
            public_address: "127.0.0.1:0".parse()?,
            protocol_id: 0x4452_4541_4d00_0001,
            max_clients: 64,
            transport: TransportConfig::default(),
        },
        &dream_net::generate_key(),
        schema.build()?,
        0.0,
    )?;
    println!("listening on {}, {} slots", server.address(), server.max_clients());
    Ok(())
}
```

`public_address` is the address clients connect to and tokens name; port 0 binds a free port, and
`address()` says which. `protocol_id` is the game's protocol family: netcode refuses tokens minted
for another. Schema compatibility is checked separately, by fingerprint. `max_clients` is between 1
and 256. `new` fails with `Error::Config` if the schema does not fit the transport configuration,
and `Error::Netcode` for a bad slot count or a socket that cannot bind.

## Starting a client

`Client::new` takes a `ClientConfig`, the client's own copy of the schema, and the time. Its
`bind_address` is the local address, usually port 0; its address family must match the server
addresses in tokens. `connect(&token)` starts an attempt, ending any attempt in progress first. A
token netcode cannot parse is an `Err`, and the attempt ends with `ConnectFailed` as well.

`status()` says where it stands:

| `ClientStatus` | Meaning |
|---|---|
| `Disconnected` | Idle |
| `Connecting` | netcode is exchanging connection requests and responses |
| `Handshaking` | netcode connected; waiting for the server's hello |
| `Connected` | Events flow |

## The frame

Both hosts run the same phases, once per frame, with the host's monotonic time in seconds:

```text
update(time)   everything that arrived is decrypted, decoded and delivered to the inbox
poll()         lifecycle records and events, until None
send(...)      queue events, copied before send returns
flush()        pack, encrypt and send
```

Two ways to read the inbox:

| Call | Payload | Use |
|---|---|---|
| `poll()` | Borrowed from the inbox until the next call | Decode in place, then move on |
| `poll_into(&mut buffer)` | Copied into `buffer`; the event carries its length | Keep the bytes, or call `send` while handling the event |

`poll_into` with a buffer too small for the next payload returns `BufferTooSmall { needed }` and
consumes nothing: grow the buffer and poll again. A buffer as large as the schema's largest
`max_payload` never needs to grow.

## Server events

| `ServerEvent` | When |
|---|---|
| `Connected { peer, client_id }` | A client completed the handshake. It can be sent events from now on |
| `Message { peer, event, channel, payload }` | An event from a connected client |
| `Disconnected { peer, reason }` | A connected client left. Every `Connected` is followed by exactly one |
| `Rejected { peer, client_id, failure }` | A client authenticated with netcode but failed the handshake. It was never announced |

A peer's `Connected` precedes its messages, and its `Disconnected` follows them. `client_id` is
the authenticated id from its connect token.

A `Disconnected` reason is `Remote` when the client disconnected, `TimedOut` when netcode heard
nothing within the token's timeout, `Requested` when the server disconnected it, or the reason of
the failure that ended it, such as `MalformedData`.

## Client events

| `ClientEvent` | When |
|---|---|
| `Connected` | The handshake completed. Events can be sent from now on |
| `Message { event, channel, payload }` | An event from the server |
| `Disconnected { reason }` | The connection ended after `Connected` |
| `ConnectFailed { reason, failure }` | The attempt ended before `Connected` |

Every attempt ends in exactly one `Disconnected` or one `ConnectFailed`. `failure` is set when the
handshake itself failed, and a schema mismatch carries both fingerprints. Otherwise the reason is
netcode's: `Authentication` for an expired or invalid token, `TimedOut` for a server that never
answered or went silent, `Denied` for a full server or a client id already connected, and `Remote`
for a server that closed the connection.

## A mismatched schema, on both ends

```rust
use std::time::{Duration, Instant};

use dream_net::{
    ChannelConfig, Client, ClientConfig, ClientEvent, Schema, Server, ServerConfig, ServerEvent,
    TransportConfig, USER_DATA_BYTES,
};

const PROTOCOL: u64 = 0x4452_4541_4d00_0001;

fn schema(version: u32) -> Result<Schema, dream_net::ConfigError> {
    let mut schema = Schema::builder(version);
    let reliable = schema.channel(ChannelConfig::reliable_ordered("reliable"))?;
    schema.event("Chat", reliable, 256)?;
    schema.build()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = dream_net::generate_key();
    let config = ServerConfig {
        public_address: "127.0.0.1:0".parse()?,
        protocol_id: PROTOCOL,
        max_clients: 8,
        transport: TransportConfig::default(),
    };
    let mut server = Server::new(config, &key, schema(1)?, 0.0)?;
    let address = server.address();
    let token = dream_net::generate_connect_token(
        &[address], &[address], 30, 5, 7, PROTOCOL, &key, &[0; USER_DATA_BYTES],
    )?;

    // the client was built against catalogue version 2
    let config = ClientConfig {
        bind_address: "127.0.0.1:0".parse()?,
        transport: TransportConfig::default(),
    };
    let mut client = Client::new(config, schema(2)?, 0.0)?;
    client.connect(&token)?;

    let start = Instant::now();
    let (mut rejected, mut failed) = (None, None);
    while (rejected.is_none() || failed.is_none()) && start.elapsed() < Duration::from_secs(5) {
        let time = start.elapsed().as_secs_f64();
        server.update(time);
        client.update(time);
        while let Some(event) = server.poll() {
            if let ServerEvent::Rejected { client_id, failure, .. } = event {
                rejected = Some((client_id, failure));
            }
        }
        while let Some(event) = client.poll() {
            if let ClientEvent::ConnectFailed { reason, failure } = event {
                failed = Some((reason, failure));
            }
        }
        server.flush();
        client.flush();
        std::thread::sleep(Duration::from_millis(16));
    }
    println!("server: {rejected:?}");
    println!("client: {failed:?}");
    Ok(())
}
```

```text
server: Some((7, SchemaMismatch { local: Fingerprint(f21c691ac93b184cdb445b1f9ae7dd95), remote: Fingerprint(67fe5de2ec8f743b99d97fdf9ebade29) }))
client: Some((SchemaMismatch, Some(SchemaMismatch { local: Fingerprint(67fe5de2ec8f743b99d97fdf9ebade29), remote: Fingerprint(f21c691ac93b184cdb445b1f9ae7dd95) })))
```

Each side reports its own fingerprint as `local`. The server keeps the client for
`mismatch_linger` seconds, sending only its hello, which is how the client learns the server's
fingerprint; the client then disconnects.

## Peers

A `PeerId` is a server's handle to one client: the netcode slot in its low 16 bits and a
generation in the high 48. The generation grows every time any slot is filled, so a handle kept
after its client left fails as `UnknownPeer` instead of reaching the next client in that slot.

| Call | Returns |
|---|---|
| `peers()` | Every connected peer, in slot order |
| `num_connected()`, `max_clients()` | Connected clients, and slots |
| `client_id(peer)` | The client id from its token |
| `client_address(peer)` | Its address |
| `client_user_data(peer)` | The 256 bytes of user data from its token |
| `stats(peer)`, `counters(peer)` | Link estimates and counters. See [Memory and backpressure](@/docs/memory.md#watching-a-connection) |
| `peer_connection(peer)` | Its `Connection`, for diagnostics |

Each returns `None` for a peer that is not connected.

## Sending to many

`broadcast(event, payload)` queues an event to every connected client, and
`broadcast_except(Some(peer), event, payload)` to all but one. An unknown event or an oversized
payload is an `Err` before anything is queued. Otherwise each returns how many clients' queues
refused the event, which on a reliable channel means their window was full; call `send` per peer
when those need handling one by one.

## Disconnecting

`Server::disconnect(peer)` ends one client's connection at once and queues its
`Disconnected { reason: Requested }`; `disconnect_all()` ends every one. `Client::disconnect()`
tells the server and ends the attempt or connection with `Requested`.

Dropping a `Server` stops netcode, which tells every client now rather than letting them time out.
Dropping a `Client` disconnects it.

## From Luau

DreamWeave's scripts use dream-net through [l3i](https://github.com/DreamWeave-MP/l3i), which binds
it as the `@dream/net` module. The host creates each `Server` in Rust and hands it to scripts, so
the private key never reaches Luau, and scripts may create clients only when the runtime grants
them the capability. The module is l3i's, and documented with it.
