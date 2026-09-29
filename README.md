# dream-net

The networking substrate of the DreamWeave engine: secure client/server UDP, reliable-ordered and
unreliable-unordered event channels, and a schema handshake, built on the Más Bandwidth
[netcode](https://github.com/mas-bandwidth/netcode.rs),
[reliable](https://github.com/mas-bandwidth/reliable.rs) and
[serialize](https://github.com/mas-bandwidth/serialize.rs) crates.

**Transport truth in Rust, network behaviour in Luau.** dream-net answers who is connected, which
authenticated peer sent which bytes, whether they arrived reliably and in order, and what the link
looks like. It never knows what an event means: no actors, players, replication, authority or RPC.

**Documentation, including the full Rust API reference: <https://dreamweave-mp.github.io/dream-net/>**

## Install

```sh
cargo add dream-net
```

Rust 1.88 or newer. No features.

## Usage

A host declares its schema, then drives a `Server` or `Client` once per frame: `update`, `poll`,
`send`, `flush`. Nothing calls back into it.

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

- **Events are the protocol unit.** Event ids come from sorted names, never registration order,
  and both ends compare a fingerprint of the schema before any event is accepted.
- **The sender is transport metadata**, from the authenticated netcode slot. A `PeerId` carries a
  generation, so a stale handle never reaches the slot's next occupant.
- **Bounded memory.** Every queue has a limit, and what a peer can make a connection hold on
  receive is at most `max_pending_bytes + 2 * max_parked_bytes`. Remote input never panics.

Luau scripts reach dream-net through [l3i](https://github.com/DreamWeave-MP/l3i)'s `@dream/net`
module.

## Where to read next

- [Start here](https://dreamweave-mp.github.io/dream-net/docs/start-here/): a server and a client
  in one program
- [How it fits together](https://dreamweave-mp.github.io/dream-net/docs/how-it-works/): the
  layers, the frame, the handshake and the delivery guarantees
- [Memory and backpressure](https://dreamweave-mp.github.io/dream-net/docs/memory/): every limit
- [Rust API](https://dreamweave-mp.github.io/dream-net/docs/api/)
- [Compatibility and performance](https://dreamweave-mp.github.io/dream-net/docs/compatibility/):
  what is tested, and benchmark numbers
- [Changelog](https://dreamweave-mp.github.io/dream-net/home/changelog/)

## Testing

`cargo test` runs the unit, property, golden-vector, simulator, localhost netcode, capture,
allocation, fuzz-smoke and short soak tests. The long gates:

```sh
DREAM_NET_SOAK_FRAMES=200000 cargo test --release --test soak -- --nocapture
cd fuzz && RUSTC_BOOTSTRAP=1 cargo fuzz run <target> -s none -O -- -max_total_time=600
```

Wire bytes are pinned by `tests/wire_golden.rs`; changing them means bumping `wire::WIRE_VERSION`.

## Credits

Networking built on netcode, reliable and serialize by Más Bandwidth LLC
(<https://mas-bandwidth.com>). Their license notices are in [`NOTICE.md`](NOTICE.md) and must
travel with any product that ships dream-net.

## License

dream-net is licensed under either of [Apache License 2.0](LICENSE-APACHE) or
[MIT](LICENSE-MIT) at your option.

## Support

Has dream-net been useful to you? Consider
[amplifying the signal](https://ko-fi.com/magicaldave) through ko-fi.
