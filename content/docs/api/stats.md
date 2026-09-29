+++
title = "Statistics"
description = "ConnectionStats, Counters and MemoryUsage."
weight = 80

[extra]
kind = "api"
+++

Module `dream_net::stats`, all re-exported from the root. All three are plain `Copy` values read on
demand, and reading them allocates nothing, so a host or a script can read them every frame.

## ConnectionStats

{{ api_signature(value="struct ConnectionStats { pub rtt: f32, pub rtt_min: f32, pub rtt_max: f32, pub rtt_avg: f32, pub jitter: f32, pub jitter_max: f32, pub jitter_stddev: f32, pub packet_loss: f32, pub sent_kbps: f32, pub received_kbps: f32, pub acked_kbps: f32 }") }}

reliable's link estimates, refreshed by every connection update. `Clone`, `Copy`, `Debug`,
`Default`, `PartialEq`.

| Field | Unit | Meaning |
|---|---|---|
| `rtt` | ms | Smoothed round-trip time |
| `rtt_min`, `rtt_max`, `rtt_avg` | ms | Minimum, maximum and average round trip over the history window (`rtt_history_size` samples) |
| `jitter` | ms | Average jitter against the minimum round trip |
| `jitter_max` | ms | Maximum jitter against the minimum round trip |
| `jitter_stddev` | ms | Standard deviation of the round trip |
| `packet_loss` | percent | Smoothed packet loss |
| `sent_kbps` | kbit/s | Sent bandwidth |
| `received_kbps` | kbit/s | Received bandwidth |
| `acked_kbps` | kbit/s | Acknowledged sent bandwidth |

## Counters

{{ api_signature(value="#[non_exhaustive] struct Counters { pub packets_sent: u64, ... }") }}

Monotonic counters of one connection, from its start, for profiling. All `u64`. `Clone`, `Copy`,
`Debug`, `Default`, `Eq`.

| Field | Counts |
|---|---|
| `packets_sent` | Connection packets written |
| `datagrams_sent` | Datagrams handed to the transport; each fragment counts |
| `bytes_sent` | Datagram bytes handed to the transport |
| `datagrams_received` | Datagrams received from the transport |
| `bytes_received` | Datagram bytes received from the transport |
| `packets_received` | Connection packets accepted, after reassembly, duplicate rejection and decoding |
| `events_queued` | Events `send` accepted, including those an overflow policy then dropped |
| `events_sent` | Events written into a packet for the first time |
| `events_resent` | Reliable events written again because no acknowledgement arrived in time |
| `events_received` | Events delivered into the inbox |
| `events_dropped_on_send` | Unreliable events dropped by the overflow policy |
| `events_dropped_on_receive` | Unreliable events dropped because the inbox was over its limits, or their packet was refused |
| `duplicate_events` | Reliable events received again after delivery or while parked, because their acknowledgement was lost |
| `malformed_packets` | Packets refused as malformed |
| `packets_refused` | Well-formed packets left unacknowledged because a reliable event in them could be neither delivered nor parked. The sender resends them |

## MemoryUsage

{{ api_signature(value="struct MemoryUsage { pub connection: usize, pub reliable: usize, pub send: usize, pub receive: usize }") }}

Approximate native memory, in bytes, by category. `Clone`, `Copy`, `Debug`, `Default`, `Eq`.

| Field | Holds |
|---|---|
| `connection` | The connection itself and its scratch buffers |
| `reliable` | reliable's endpoint: packet tracking, the RTT history, reassembly |
| `send` | Channel send queues and their buffer pools |
| `receive` | Reliable reorder buffers; for a `Server` or `Client`, the inbox too |

{{ api_signature(value="fn total(&self) -> usize") }}

The sum of the four.

```rust
use dream_net::sim::{LinkConfig, Pair};
use dream_net::{ChannelConfig, Schema, Shared, TransportConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut schema = Schema::builder(1);
    let reliable = schema.channel(ChannelConfig::reliable_ordered("reliable"))?;
    schema.event("Chat", reliable, 256)?;
    let schema = schema.build()?;
    let chat = schema.event_id("Chat").expect("declared");

    let shared = Shared::new(schema, TransportConfig::default())?;
    let mut pair = Pair::symmetric(&shared, LinkConfig::latency(0.05), 1);
    assert!(pair.handshake(1.0 / 60.0, 600));
    for _ in 0..60 {
        pair.b.send(chat, b"ping")?;
        pair.step(1.0 / 60.0);
        while pair.a_inbox.pop().is_some() {}
    }
    let stats = pair.b.stats();
    let counters = pair.b.counters();
    println!("rtt {:.0} ms, {} events sent, {} bytes held", stats.rtt_avg, counters.events_sent,
        pair.b.memory_usage().total());
    Ok(())
}
```

```text
rtt 101 ms, 60 events sent, 97064 bytes held
```

Fifty milliseconds each way, measured in frames of a sixtieth of a second, comes to a round trip
of a little over 100 ms. Most of the memory is the 32 KiB packet buffers of the connection and of
reliable, sized by `max_packet_size`.
