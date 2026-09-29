+++
title = "Channels and packets"
description = "Reliable and unreliable channels, windows and resends, overflow policies, how flush packs events into packets, and events larger than a datagram."
weight = 40

[extra]
kind = "guide"
+++

Every event travels on the channel its schema put it on. A channel is one of two delivery classes,
and a schema may declare up to 64 of them, mixing both.

## Reliable-ordered

```rust
use dream_net::ChannelConfig;

fn main() {
    let chat = ChannelConfig::reliable_ordered("chat");
    assert_eq!(chat.capacity, 1024);
    assert_eq!(chat.resend_interval, 0.1);

    let bulk = ChannelConfig::reliable_ordered("bulk")
        .with_capacity(64)
        .with_resend_interval(0.25);
    assert_eq!((bulk.capacity, bulk.resend_interval), (64, 0.25));
}
```

Every event arrives exactly once, in the order it was sent. The channel keeps each event until a
packet carrying it is acknowledged, and writes it again every `resend_interval` seconds until then.

`capacity` is the channel's window, 1024 by default and at most 32768: the most events it holds
unacknowledged. When the window is full, `send` refuses with `SendError::QueueFull` and queues
nothing; the host decides whether to wait, drop the event or disconnect. The same number is the
receiver's window, and part of the fingerprint, because both ends must agree on it. A reliable
channel never drops an event, so it only accepts the `Fail` overflow policy.

Message ids are 16-bit and wrap. Every comparison between them goes through
[`Seq16`](@/docs/api/ids.md#seq16), which treats an id up to half the space ahead as newer.

## Unreliable-unordered

```rust
use dream_net::{ChannelConfig, OverflowPolicy};

fn main() {
    let state = ChannelConfig::unreliable_unordered("state")
        .with_capacity(256)
        .with_overflow(OverflowPolicy::DropOldest);
    assert_eq!(state.overflow, OverflowPolicy::DropOldest);
}
```

Every event arrives at most once, in any order, and is never sent twice. The channel holds events
only until the next flush writes them into a packet. `capacity`, 1024 by default, bounds that
queue, and `overflow` says what `send` does when it is full:

| `OverflowPolicy` | `send` | The queue |
|---|---|---|
| `Fail` (default) | Refuses with `QueueFull` | Unchanged |
| `DropOldest` | Succeeds | Drops its oldest event to make room |
| `DropNewest` | Succeeds | Drops the new event |

Both drops are counted in `Counters::events_dropped_on_send`. `DropOldest` suits state where only
the latest value matters.

On receive, an unreliable event is delivered only with a packet the connection accepts, so a late
duplicate of the datagram cannot deliver it twice. When the inbox is over its limits, unreliable
events are dropped and counted instead; see [Memory and backpressure](@/docs/memory.md).

## Refusals, in one place

The same checks apply to `Server::send`, `Client::send` and `Connection::send`, and nothing is
queued when one fails:

```rust
use dream_net::{
    ChannelConfig, Connection, EventTypeId, OverflowPolicy, PeerId, Schema, SendError, Shared,
    TransportConfig,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut schema = Schema::builder(1);
    let reliable = schema.channel(ChannelConfig::reliable_ordered("reliable").with_capacity(2))?;
    let state = schema.channel(
        ChannelConfig::unreliable_unordered("state")
            .with_capacity(2)
            .with_overflow(OverflowPolicy::DropOldest),
    )?;
    schema.event("Chat", reliable, 64)?;
    schema.event("Position", state, 12)?;
    let schema = schema.build()?;
    let chat = schema.event_id("Chat").expect("declared");
    let position = schema.event_id("Position").expect("declared");

    // a connection on its own, with no peer: enough to show what send accepts
    let shared = Shared::new(schema, TransportConfig::default())?;
    let mut connection = Connection::new(shared, PeerId::new(0, 1), 0.0);

    connection.send(chat, b"one")?;
    connection.send(chat, b"two")?;
    assert_eq!(connection.send(chat, b"three"), Err(SendError::QueueFull(reliable)));
    assert!(matches!(
        connection.send(chat, &[0; 65]),
        Err(SendError::PayloadTooLarge { len: 65, max: 64, .. })
    ));
    assert_eq!(
        connection.send(EventTypeId(9), b""),
        Err(SendError::UnknownEvent(EventTypeId(9)))
    );

    for _ in 0..5 {
        connection.send(position, &[0; 12])?;
    }
    assert_eq!(connection.queued(state), 2);
    assert_eq!(connection.counters().events_dropped_on_send, 3);
    Ok(())
}
```

`Server::send` also refuses a `PeerId` that is not connected, with `UnknownPeer`, and
`Client::send` refuses with `NotConnected` before the handshake completes.

## How flush packs packets

`flush` turns what the channels hold into packets:

1. Each packet takes events from every channel with something due, up to the transport's
   `packet_budget`: 1191 bytes by default, the most that fits one netcode datagram unfragmented.
   Many small events share one packet, one encryption and one system call.
2. At most `max_messages_per_packet` events per channel go into one packet, and at most a
   channel's own `packet_budget`, when it has one, of payload and framing.
3. Channels take turns leading. A channel whose next event did not fit leads the next packet, so a
   large event is never starved by a stream of small ones.
4. Writing stops after `max_packets_per_flush` packets, 64 by default, or when half of the
   sent-packet window is in flight unacknowledged. What is left waits for the next flush.

A packet unacknowledged after twice the worst recent round trip, clamped between 50 ms and one
second, counts as lost and stops counting toward the in-flight half. That cap exists because
reliable can only match an acknowledgement to a packet still in its window: a sender that ran
further ahead would forget what it sent and resend all of it.

## Events larger than a packet

An event larger than the packet budget gets a packet of its own, up to the transport's
`max_packet_size`, 32 KiB by default. reliable splits such a packet into fragments of
`fragment_size` bytes, sends each in its own datagram, and reassembles them on the other side; a
lost fragment loses the packet, and a reliable channel sends the event again. A channel's own
`packet_budget` does not hold one event back either: an event larger than the budget is sent on
its own.

The largest payload an event may declare is `max_packet_size` less the worst-case framing around
it, which the schema is checked against when a server or client is created. Raise
`max_packet_size` for larger events, up to 256 fragments.

## Choosing

| Traffic | Channel |
|---|---|
| Chat, commands, inventory, anything that must not be lost | Reliable-ordered |
| Positions, animation state, anything superseded by the next update | Unreliable, `DropOldest` |
| Large, rare transfers that should not delay small reliable events | A second reliable channel, with a smaller window |

Order holds within one channel, not across channels: two reliable channels never wait for each
other.
