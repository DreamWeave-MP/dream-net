# dream-net

[![crates.io](https://img.shields.io/crates/v/dream-net.svg)](https://crates.io/crates/dream-net)
[![docs](https://img.shields.io/badge/docs-rustdoc-blue)](https://dreamweave-mp.github.io/dream-net/)

The networking substrate of the DreamWeave engine: secure client/server UDP, reliable-ordered
and unreliable-unordered event channels, and schema handshakes, built on the Más Bandwidth
[netcode](https://github.com/mas-bandwidth/netcode.rs),
[reliable](https://github.com/mas-bandwidth/reliable.rs) and
[serialize](https://github.com/mas-bandwidth/serialize.rs) crates.

**Transport truth in Rust. Network behaviour in Luau.** dream-net answers who is connected,
which authenticated peer sent which bytes, whether they arrived reliably and in order, and what
the connection statistics are. It never knows what an event means: no actors, players,
replication, authority, or RPC.

## Shape

```text
Server / Client     netcode slots, PeerId handles, lifecycle, one inbox per host
Connection          reliable::Endpoint + channels + packet builder + handshake
channels            reliable-ordered (resend, ack mapping, reorder) and unreliable-unordered
wire                dream-net's own packet format, bit-packed with serialize
```

```rust
let schema = {
    let mut b = Schema::builder(1);
    let reliable = b.channel(ChannelConfig::reliable_ordered("reliable"))?;
    let state = b.channel(ChannelConfig::unreliable_unordered("state"))?;
    b.event("Chat", reliable, 256)?;
    b.event("ActorPosition", state, 28)?;
    b.build()?
};
let mut server = Server::new(config, &private_key, schema, time)?;

// once per frame, in one explicit network phase
server.update(time);
while let Some(event) = server.poll_into(&mut buffer)? {
    match event {
        ServerEvent::Connected { peer, client_id } => { /* ... */ }
        ServerEvent::Message { peer, event, payload: len, .. } => { /* decode buffer[..len] */ }
        ServerEvent::Disconnected { peer, reason } => { /* ... */ }
        ServerEvent::Rejected { failure, .. } => { /* e.g. schema mismatch, both fingerprints */ }
    }
}
server.send(peer, chat, &bytes)?;
server.flush();
```

- **Events are the protocol unit.** Event ids come from sorted names, never registration
  order; the schema is frozen before networking starts and fingerprinted (truncated SHA-256).
  Peers exchange fingerprints before any event is accepted, and a mismatch is reported with
  both fingerprints on both ends.
- **Polled, never called back.** Nothing calls into the host from inside `update`.
- **Sender identity is transport metadata**, from the authenticated netcode slot. `PeerId`
  carries a generation, so a stale handle never reaches the slot's next occupant.
- **Aggregation.** Many events share a packet sized to one netcode datagram; larger events get
  a packet of their own that reliable fragments.
- **Bounded memory.** Every queue has a limit. On receive, a reliable event is acknowledged only
  once it is delivered or parked behind a gap, parking has a byte budget, and what a peer can
  make a connection hold is at most `max_pending_bytes + 2 * max_parked_bytes`. Remote input
  never panics.
- **Warm paths allocate nothing** (tested with a counting allocator).

## Testing

`cargo test` runs unit, property, golden-vector, simulator, localhost netcode, capture,
allocation, fuzz-smoke, and short soak tests. The long gates:

```sh
DREAM_NET_SOAK_FRAMES=200000 cargo test --release --test soak -- --nocapture
cd fuzz && RUSTC_BOOTSTRAP=1 cargo fuzz run <target> -s none -O -- -max_total_time=600
cargo bench
```

Wire bytes are pinned by `tests/wire_golden.rs`; changing them means bumping
`wire::WIRE_VERSION`.

CI runs through [StroggForge](https://github.com/DreamWeave-MP/StroggForge): format, pedantic
clippy, tests on Linux, macOS, and Windows, `cargo audit`, and the MSRV check on every push;
API documentation at <https://dreamweave-mp.github.io/dream-net/>; and on tagged releases,
crates.io publishing and a `BENCHMARKS.md` generated from the Criterion suite, attached to the
release.

## Credits

Networking built on netcode, reliable and serialize by Más Bandwidth LLC
(<https://mas-bandwidth.com>). Their license notices are in [`NOTICE.md`](NOTICE.md) and must
travel with any product that ships dream-net.

## License

dream-net is licensed under either of [Apache License 2.0](LICENSE-APACHE) or
[MIT](LICENSE-MIT) at your option.
