+++
title = "dream-net"
description = "DreamWeave's networking substrate: secure UDP between authenticated peers, with reliable-ordered and unreliable event channels and a schema handshake."

[taxonomies]
tags = ["Rust", "Networking", "UDP", "Multiplayer"]

[extra]
sections = ["overview", "install", "releases", "credits"]
+++

A multiplayer engine needs two kinds of traffic. A chat line, a spell cast or an inventory change
must arrive exactly once and in order, however many packets the network loses. An actor's position
is stale the moment the next one exists, and resending it is worse than useless. Both kinds have to
share one encrypted connection, reach only peers that proved who they are, and never let a hostile
peer grow the server's memory or crash it.

dream-net is that transport for the DreamWeave engine. It moves opaque event payloads between
authenticated peers and stops there: it knows event ids, channels, peers and bytes, and never what
an event means. Who may send what, and where it goes next, is decided above it.

{{ schematic(data_path="data/schematics/event.json") }}

It is built on the Más Bandwidth crates, pinned exactly:
[netcode](https://github.com/mas-bandwidth/netcode.rs) for connect tokens, encryption, replay
protection and client slots; [reliable](https://github.com/mas-bandwidth/reliable.rs) for packet
acknowledgement, fragmentation and link statistics; and
[serialize](https://github.com/mas-bandwidth/serialize.rs) for bit-packing. dream-net adds the part
they leave out: channels of events, packed many to a datagram.

- **Events are the protocol unit.** A schema names every channel and event before networking
  starts. Event ids come from the sorted names, never the order they were declared in, and both
  ends compare a fingerprint of the whole schema before a single event is accepted. A mismatch is
  reported on both ends, with both fingerprints.
- **Polled, never called back.** A host runs one network phase per frame: `update`, `poll`, `send`,
  `flush`. Nothing calls into the host from inside the transport.
- **The sender is transport metadata.** A `PeerId` comes from the authenticated netcode slot and
  carries a generation, so a handle to a peer that left never reaches the next one in its slot.
- **Bounded memory.** Every queue has a limit, and what a peer can make a connection hold on
  receive has a fixed ceiling. Malformed input is refused, counted and disconnected, never a panic.

```rust
use dream_net::{ChannelConfig, Schema, Server, ServerConfig, ServerEvent, TransportConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut schema = Schema::builder(1);
    let reliable = schema.channel(ChannelConfig::reliable_ordered("reliable"))?;
    let state = schema.channel(ChannelConfig::unreliable_unordered("state"))?;
    schema.event("Chat", reliable, 256)?;
    schema.event("ActorPosition", state, 28)?;
    let schema = schema.build()?;
    let chat = schema.event_id("Chat").expect("declared above");

    let config = ServerConfig {
        public_address: "127.0.0.1:0".parse()?,
        protocol_id: 0x4452_4541_4d00_0001,
        max_clients: 16,
        transport: TransportConfig::default(),
    };
    let mut server = Server::new(config, &dream_net::generate_key(), schema, 0.0)?;
    let mut buffer = [0u8; 256];

    // once per frame, in one network phase
    server.update(1.0 / 60.0);
    while let Some(event) = server.poll_into(&mut buffer)? {
        match event {
            ServerEvent::Connected { peer, .. } => server.send(peer, chat, b"welcome")?,
            ServerEvent::Message { peer, event, payload, .. } => {
                println!("{peer} sent {event}: {:?}", &buffer[..payload]);
            }
            ServerEvent::Disconnected { .. } | ServerEvent::Rejected { .. } => {}
        }
    }
    server.flush();
    Ok(())
}
```

Luau scripts reach it through [l3i](https://github.com/DreamWeave-MP/l3i), which binds dream-net as
the `@dream/net` module. The host still creates servers in Rust: the private key never reaches a
script.

## Documentation

- **[Start here](@/docs/start-here.md)**: a server and a client in one program, exchanging their
  first events.
- **[Guide](@/docs/_index.md)**: how it fits together, schemas, channels, hosting, memory limits,
  captures and the simulator.
- **[Rust API](@/docs/api/_index.md)**: every public type and function.
- **[Compatibility and performance](@/docs/compatibility.md)**: the Rust version, the license, what
  is tested, and what a frame costs.
