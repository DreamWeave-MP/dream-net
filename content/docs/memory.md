+++
title = "Memory and backpressure"
description = "The limit on every queue, what happens when one fills, the ceiling on what a peer can make a connection hold, and the numbers a host can watch."
weight = 60

[extra]
kind = "guide"
+++

Every queue in dream-net has a limit, and every limit is in the `TransportConfig` a server or
client is created with. Build one with struct update syntax over the default; the
[TransportConfig reference](@/docs/api/transport.md) lists every field.

```rust
use dream_net::{ChannelConfig, ConfigError, Schema, TransportConfig};

fn main() -> Result<(), ConfigError> {
    let mut schema = Schema::builder(1);
    let reliable = schema.channel(ChannelConfig::reliable_ordered("reliable"))?;
    schema.event("Snapshot", reliable, 64 * 1024)?;
    let schema = schema.build()?;

    // a 32 KiB packet cannot carry a 64 KiB event
    assert!(matches!(
        TransportConfig::default().validate_for(&schema),
        Err(ConfigError::EventTooLarge { .. })
    ));

    let config = TransportConfig {
        max_packet_size: 80 * 1024,
        ..TransportConfig::default()
    };
    config.validate_for(&schema)
}
```

`Server::new` and `Client::new` run `validate_for` themselves. After it passes, no packet
dream-net builds can trip one of reliable's assertions, and every datagram fits netcode.

## Sending

| Queue | Limit | When it is full |
|---|---|---|
| A reliable channel's window | Its `capacity` | `send` refuses with `QueueFull` |
| An unreliable channel's queue | Its `capacity` | Its [overflow policy](@/docs/channels.md#unreliable-unordered) |
| Each channel's spare payload buffers | `max_pooled_bytes`, 64 KiB | A returned buffer is freed instead of kept |

A reliable channel refuses rather than drops, always. Recycled buffers are what let a warm
connection send without allocating, and their byte limit is what stops one burst of large events
from keeping its memory for the life of the connection.

## Receiving

What a connection receives waits in its host's inbox until the host polls it:

| Limit | Default | Past it |
|---|---|---|
| `max_pending_events` | 4096 per connection | Unreliable events are dropped and counted. A reliable event that is next in order is refused |
| `max_pending_bytes` | 4 MiB per connection | The same |

A refused reliable event leaves its whole packet unacknowledged, and counted in
`packets_refused`. The sender still holds the event, and sends it again after its resend interval;
by then the host has polled and there is room. A host that stops polling stalls its reliable
traffic and loses its unreliable traffic, and its memory stays where it was.

### Events behind a gap

A reliable event that arrives ahead of one still missing waits outside the inbox, parked, until the
gap fills. `max_parked_bytes`, 1 MiB by default, is one budget for the whole connection across every
reliable channel, charged by what is really allocated: every slot of reorder-buffer capacity at
`PARK_OVERHEAD` bytes, empty gaps and spare capacity included, and every parked payload buffer's
capacity.

An event that would overflow the budget leaves its packet unacknowledged, to be sent again after
the gap fills. The event that fills a gap is delivered, never parked, so the budget can slow a
connection but never stall it.

### The ceiling

A connection acknowledges a reliable event only once it is delivered to the inbox or parked. That
keeps a sender inside the receiver's window, whatever the network does.

When a missing event arrives, the whole parked run behind it moves into the inbox at once. That is
the one way the inbox can pass its pending limits, and only by what was already parked. So what a
peer can make a connection hold on receive is at most

```text
max_pending_bytes + 2 * max_parked_bytes
```

of payload, 6 MiB with the defaults, whatever the schema's windows and channel count allow.

### What the configuration must allow

`validate_for` refuses a configuration that could deadlock or confuse the schema:

- `max_pending_bytes` must hold the largest payload any event may carry;
- `max_parked_bytes` must hold the largest reliable payload plus two reorder slots;
- `received_packets_buffer_size * max_messages_per_packet + 2 *` the largest reliable window must
  not exceed 65536, so a stale message id arriving late can never wrap around into the window and
  be taken for a new one.

## Allocation

A received payload is copied into the inbox straight out of the decoded packet, after waiting in
a buffer of its own if it was parked, and once more when polled into the host's buffer. Once a connection is warm, its send and receive paths
allocate nothing while its events fit the recycled buffers, which the tests prove with a counting
allocator. reliable allocates for each fragmented packet it reassembles, and netcode allocates for
each datagram.

## Watching a connection

All three are plain `Copy` values, read without allocating, so a host can read them every frame:
`Server::stats(peer)`, `counters(peer)` and `memory_usage()`, and the same on `Client` and
`Connection`. The server's are for a connected peer; the client's start when netcode connects, so
they cover the handshake too.

| `ConnectionStats` | Unit |
|---|---|
| `rtt`, `rtt_min`, `rtt_max`, `rtt_avg` | Smoothed, minimum, maximum and average round trip, ms |
| `jitter`, `jitter_max`, `jitter_stddev` | Average and maximum jitter against the minimum RTT, and the RTT's standard deviation, ms |
| `packet_loss` | Smoothed loss, percent |
| `sent_kbps`, `received_kbps`, `acked_kbps` | Bandwidth, kilobits per second |

`Counters` count, from the connection's start: packets and datagrams sent and received, bytes each
way, events queued, sent, resent, received and dropped on either side, duplicates, malformed
packets, and packets refused. `MemoryUsage` estimates native memory in four parts: the connection
itself, reliable's endpoint, the send queues and pools, and the receive side;
`Server::memory_usage` adds every connection and the inbox. The [stats reference](@/docs/api/stats.md)
defines each field.
