+++
title = "Start here"
description = "Add the crate, declare a schema, start a server, mint a connect token, connect a client, and exchange the first events."
weight = 10

[extra]
kind = "tutorial"
+++

## Add the crate

```sh
cargo add dream-net
```

It needs Rust 1.88 or newer. The crate's name in code is `dream_net`, and it has no features to
choose.

## The whole program

A server and a client in one process, over localhost: the client connects, says hello on a reliable
channel, and the server answers.

```rust
use std::time::{Duration, Instant};

use dream_net::{
    ChannelConfig, Client, ClientConfig, ClientEvent, Schema, Server, ServerConfig, ServerEvent,
    TransportConfig, USER_DATA_BYTES,
};

/// The game's protocol family. netcode refuses tokens minted for another one.
const PROTOCOL: u64 = 0x4452_4541_4d00_0001;

/// Both ends build the same schema. Here that is one reliable channel with one event on it.
fn schema() -> Result<Schema, dream_net::ConfigError> {
    let mut schema = Schema::builder(1);
    let reliable = schema.channel(ChannelConfig::reliable_ordered("reliable"))?;
    schema.event("Chat", reliable, 256)?;
    schema.build()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The server holds the private key. Port 0 picks a free port.
    let key = dream_net::generate_key();
    let mut server = Server::new(
        ServerConfig {
            public_address: "127.0.0.1:0".parse()?,
            protocol_id: PROTOCOL,
            max_clients: 8,
            transport: TransportConfig::default(),
        },
        &key,
        schema()?,
        0.0,
    )?;

    // A connect token for client 1001, valid for 30 seconds, timing out after 5 silent ones.
    // A real game mints it on a backend that has the key and hands it over HTTPS.
    let address = server.address();
    let user_data = [0u8; USER_DATA_BYTES];
    let token = dream_net::generate_connect_token(
        &[address], &[address], 30, 5, 1001, PROTOCOL, &key, &user_data,
    )?;

    let mut client = Client::new(
        ClientConfig {
            bind_address: "127.0.0.1:0".parse()?,
            transport: TransportConfig::default(),
        },
        schema()?,
        0.0,
    )?;
    client.connect(&token)?;
    let chat = client.schema().event_id("Chat").expect("declared in schema()");

    let start = Instant::now();
    let mut buffer = [0u8; 256];
    let mut answered = false;
    while !answered && start.elapsed() < Duration::from_secs(5) {
        // One frame: update, poll, send, flush.
        let time = start.elapsed().as_secs_f64();
        server.update(time);
        client.update(time);

        while let Some(event) = server.poll_into(&mut buffer)? {
            match event {
                ServerEvent::Connected { peer, client_id } => {
                    println!("server: {peer} connected, client id {client_id}");
                }
                ServerEvent::Message { peer, payload, .. } => {
                    let text = String::from_utf8_lossy(&buffer[..payload]);
                    println!("server: {peer} says {text:?}");
                    server.send(peer, chat, b"welcome")?;
                }
                other => println!("server: {other:?}"),
            }
        }
        while let Some(event) = client.poll_into(&mut buffer)? {
            match event {
                ClientEvent::Connected => {
                    println!("client: connected");
                    client.send(chat, b"hello")?;
                }
                ClientEvent::Message { payload, .. } => {
                    let text = String::from_utf8_lossy(&buffer[..payload]);
                    println!("client: server says {text:?}");
                    answered = true;
                }
                other => println!("client: {other:?}"),
            }
        }

        server.flush();
        client.flush();
        std::thread::sleep(Duration::from_millis(16));
    }
    assert!(answered, "no answer within five seconds");
    Ok(())
}
```

It prints:

```text
server: peer 0:1 connected, client id 1001
client: connected
server: peer 0:1 says "hello"
client: server says "welcome"
```

## What happened

**The schema.** Both ends declared the same channels and events and built them into a frozen
`Schema`. Its fingerprint travelled in each side's first packets, and each side checked the other's
before accepting anything. A client built from a different schema would have been refused on both
ends with `SchemaMismatch`. [Schemas and events](@/docs/schemas.md) says exactly what has to match.

**The token.** netcode authenticates clients with connect tokens: the server's private key signs
and encrypts one per client, and the client presents it without ever seeing the key. The client id
inside it, 1001 here, is what the server reports in `Connected`.

**The frame.** Each host did the same four things every frame: `update` with its clock, which reads
the socket and advances timers; `poll_into` until nothing is left; `send` to queue events; and
`flush` to pack and send them. Each side's `Connected` came in the frame the other side's hello
arrived; a client can send from that frame on, and not before.

**The peer.** `peer 0:1` is the `PeerId`: slot 0, generation 1. A later client in slot 0 gets a
higher generation, so an old handle fails as unknown instead of reaching someone else.

**The buffer.** `poll_into` copies each payload into `buffer` and returns its length. The buffer
has to fit the largest payload the schema allows, 256 bytes here; a smaller one returns
`BufferTooSmall` and leaves the event in place for a bigger buffer.

## Next

- [How it fits together](@/docs/how-it-works.md): the layers under this program.
- [Servers and clients](@/docs/hosts.md): every lifecycle event, disconnects and broadcasts.
- [Channels and packets](@/docs/channels.md): unreliable channels, and events larger than a
  datagram.
