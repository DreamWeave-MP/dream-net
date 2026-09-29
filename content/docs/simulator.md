+++
title = "Connections and the simulator"
description = "Driving a Connection without sockets, the inbox it delivers into, and the seeded link simulator dream-net's own tests run on."
weight = 80

[extra]
kind = "guide"
+++

Everything dream-net does to events happens in `Connection`, which never touches a socket: queued
events go in, datagrams come out through a closure, and received datagrams go in and come out as
inbox records. `Server` and `Client` drive one per peer over netcode. The `sim` module drives two
over simulated links, deterministically, which is how dream-net's own tests check delivery under
loss, reordering, duplication and corruption.

## Two connections over a lossy link

```rust
use dream_net::sim::{LinkConfig, Pair};
use dream_net::{ChannelConfig, Record, Schema, Shared, TransportConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut schema = Schema::builder(1);
    let reliable = schema.channel(ChannelConfig::reliable_ordered("reliable"))?;
    schema.event("Chat", reliable, 256)?;
    let schema = schema.build()?;
    let chat = schema.event_id("Chat").expect("declared above");

    let shared = Shared::new(schema, TransportConfig::default())?;
    // 30 ms each way, a fifth of all datagrams lost, seed 7
    let lossy = LinkConfig { loss: 0.2, ..LinkConfig::latency(0.03) };
    let mut pair = Pair::symmetric(&shared, lossy, 7);
    assert!(pair.handshake(1.0 / 60.0, 600));

    // 500 events of 200 bytes, numbered in their first four
    for n in 0u32..500 {
        let mut payload = [0u8; 200];
        payload[..4].copy_from_slice(&n.to_le_bytes());
        pair.b.send(chat, &payload)?;
    }
    let mut received = Vec::new();
    while received.len() < 500 {
        pair.step(1.0 / 60.0);
        while let Some((Record::Message(_), payload)) = pair.a_inbox.pop() {
            received.push(u32::from_le_bytes(payload[..4].try_into()?));
        }
    }
    // every event arrived once, in order, though some were sent more than once
    assert!(received.iter().copied().eq(0..500));
    let resent = pair.b.counters().events_resent;
    let lost = pair.b_to_a.counters().lost;
    println!("{resent} events resent, {lost} datagrams lost, {:.2} s", pair.time);
    Ok(())
}
```

```text
190 events resent, 26 datagrams lost, 0.33 s
```

The same seed gives the same run on every platform: the links draw from `sim::Rng`, a SplitMix64
generator, and time is the simulation's own.

## Pair

`Pair` joins two connections, `a` and `b`, with a link each way, and gives each an `Inbox<()>`.
`step(dt)` advances one frame the way a host does: update both connections, deliver the datagrams
due by then, and flush both. `handshake(dt, max_steps)` steps until both ends are established, and
`set_perfect()` heals both links for everything sent afterwards.

`Pair::symmetric` builds both ends from one `Shared`. `Pair::new` takes one for each end and a
`LinkConfig` for each direction, which is how the tests give two ends different schemas and watch
both fail with `SchemaMismatch`.

## Links

A `Link` is a one-way datagram pipe. `send(time, datagram)` offers a datagram, and
`deliver(time, receive)` hands over every datagram due by `time`, in arrival order.

| `LinkConfig` | Meaning |
|---|---|
| `latency` | One-way delay, seconds |
| `jitter` | Extra uniform delay in `[0, jitter)` seconds, which reorders datagrams |
| `loss` | Probability a datagram is lost |
| `duplicate` | Probability a datagram is delivered twice |
| `corrupt` | Probability one random bit of a datagram is flipped |

`LinkConfig::PERFECT`, also the default, has none of them, and `LinkConfig::latency(seconds)` only
the delay. A link counts what it did in `LinkCounters`: datagrams sent, lost, duplicated,
corrupted and delivered, and bytes offered.

## Driving a Connection yourself

A host of its own, over some other transport, does what `Pair::step` does, per peer:

1. `update(time)` first, so acknowledgements are timestamped with this frame's time.
2. `receive(datagram, &mut inbox, transmit)` for each datagram that arrived. `transmit` may be
   called with an acknowledgement to send at once.
3. `take_event()` until `None`: `Established` when the peer's hello matched, or `Failed(failure)`,
   after which the connection must be torn down.
4. `send(event, payload)` to queue.
5. `write_packets(transmit)` to flush.

The inbox takes one account per slot: `Inbox::new(slots)`, then `open_slot(peer)` for each new
peer, `compact()` once per update, and `pop` or `pop_into` to read. `push_lifecycle` queues a
host's own record, of whatever `Copy` type the host chose for `L`.

`Connection` is the engine room, and trusts its caller. It accepts `send` before its handshake
completes, and it delivers the events of the packet that completes the handshake before the caller
has seen `Established`. `Server` and `Client` handle both: they only let events through to a peer
they have announced, and announce it before its first event. Use them for real hosts.
