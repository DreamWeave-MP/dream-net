+++
title = "TransportConfig"
description = "Every packet size, timer, limit and smoothing factor, with its default and its rule; validation; and the datagram constants."
weight = 60

[extra]
kind = "api"
+++

Module `dream_net::config`. `TransportConfig` is re-exported from the root.

{{ api_signature(value="struct TransportConfig { ... }") }}

The runtime network profile a `Server`, `Client` or `Shared` is created with. It bounds memory and
shapes what reaches netcode, and it need not match between peers: unlike the schema, it is not
fingerprinted. All fields are public; build one with struct update syntax over `Default`.
`Clone`, `Debug`, `PartialEq`.

## Packets

| Field | Default | Meaning |
|---|---|---|
| `max_packet_size: usize` | 32768 | The largest connection packet. It bounds the largest single event. Must be at least `fragment_above`, and need at most 256 fragments |
| `fragment_above: usize` | 1191 | Packets larger than this are fragmented. Must be 1 to `MAX_UNFRAGMENTED_PACKET` |
| `fragment_size: usize` | 1186 | Payload bytes per fragment. Must be 1 to `MAX_FRAGMENT_SIZE` |
| `packet_budget: usize` | 1191 | The size events are packed up to. An event larger than it gets a packet of its own. The default equals `fragment_above`, so ordinary packets are never fragmented. Must be 1 to `max_packet_size` |
| `max_packets_per_flush: usize` | 64 | The most packets one connection writes per `flush`. Must be at least 1 |

## Timers

| Field | Default | Meaning |
|---|---|---|
| `handshake_timeout: f64` | 5.0 | Seconds a new connection has to complete the handshake. Must be finite and above 0 |
| `mismatch_linger: f64` | 1.0 | Seconds a server keeps a client that failed with a schema or protocol mismatch, sending only its hello, so the client can report the mismatch itself. 0 disconnects at once. Must be finite and not negative |
| `idle_packet_interval: f64` | 0.1 | The longest gap between packets a connection sends. 0 sends one every flush. Must be finite and not negative |

## Memory

| Field | Default | Meaning |
|---|---|---|
| `max_pending_events: usize` | 4096 | Received events waiting to be polled, per connection. Must be at least 1 |
| `max_pending_bytes: usize` | 4 MiB | Received payload bytes waiting to be polled, per connection. Must hold the schema's largest payload |
| `max_parked_bytes: usize` | 1 MiB | Bytes of reliable events held behind a gap, per connection, charged by real allocation. Must hold the largest reliable payload plus 2 × `PARK_OVERHEAD` |
| `max_pooled_bytes: usize` | 64 KiB | Bytes of recycled payload buffers each channel keeps |
| `malformed_limit: u32` | 1 | Malformed packets tolerated before the peer is disconnected. Must be at least 1 |

Past the pending limits, unreliable events are dropped and a reliable event next in order is
refused, its packet left unacknowledged to be resent. [Memory and backpressure](@/docs/memory.md)
explains the parked budget and the ceiling the three together put on a connection.

## reliable's tracking

| Field | Default | Meaning |
|---|---|---|
| `sent_packets_buffer_size: usize` | 256 | Sent packets tracked for acknowledgements, loss and bandwidth. Events stop being added when half are in flight. Must be a power of two, at most 32768 |
| `received_packets_buffer_size: usize` | 256 | Received packets tracked; also reliable's duplicate window. Must be a power of two, at most 32768; see below |
| `fragment_reassembly_buffer_size: usize` | 16 | Packets that may be reassembling at once. Must be at least 1 |
| `rtt_history_size: usize` | 128 | Round-trip samples kept for the minimum, maximum, average and jitter. reliable rescans them every update, so this is most of an idle connection's cost; reliable's own default is 512. Must be at least 1 |
| `rtt_smoothing_factor: f32` | 0.0025 | Exponential smoothing of the RTT. Must be above 0 and at most 1 |
| `packet_loss_smoothing_factor: f32` | 0.1 | Exponential smoothing of the loss. Must be above 0 and at most 1 |
| `bandwidth_smoothing_factor: f32` | 0.1 | Exponential smoothing of the bandwidth. Must be above 0 and at most 1 |
| `packet_header_size: usize` | 28 | Assumed IP and UDP header bytes per packet, for bandwidth statistics only |

`received_packets_buffer_size × max_messages_per_packet + 2 ×` the schema's largest reliable window
must not exceed 65536, so that a stale message id arriving late can never wrap around into the
window and pass for a new one. With the defaults that is 256 × 64 + 2 × 1024 = 18432.

## Methods

{{ api_signature(value="fn validate(&self) -> Result<(), ConfigError>") }}

Checks every rule that does not depend on a schema, returning `ConfigError::Transport` with a
message naming the first bad value. Once it passes, no packet dream-net builds can trip one of
reliable's assertions, and every datagram fits netcode.

{{ api_signature(value="fn validate_for(&self, schema: &Schema) -> Result<(), ConfigError>") }}

`validate`, then the rules that do: every event's `max_payload` fits one `max_packet_size` packet
with worst-case framing around it (`EventTooLarge` otherwise, with the limit), the stale-id rule
above, `max_pending_bytes`, and `max_parked_bytes` when the schema has a reliable channel.
`Server::new`, `Client::new` and `Shared::new` call it.

{{ api_signature(value="fn max_fragments(&self) -> usize") }}

How many fragments the largest packet needs: `max_packet_size` divided by `fragment_size`,
rounded up.

{{ api_signature(value="fn reliable_config(&self, name: &str) -> reliable::Config") }}

The configuration of the reliable endpoint each connection creates, named `name`, with an
acknowledgement buffer of 64.

```rust
use dream_net::{ConfigError, TransportConfig};

fn main() {
    let config = TransportConfig { max_pending_events: 256, ..TransportConfig::default() };
    assert!(config.validate().is_ok());
    assert_eq!(config.max_fragments(), 28);

    let odd = TransportConfig { sent_packets_buffer_size: 300, ..TransportConfig::default() };
    assert_eq!(
        odd.validate(),
        Err(ConfigError::Transport("sent_packets_buffer_size must be a power of two <= 32768"))
    );
}
```

## Constants

| Constant | Value | Meaning |
|---|---|---|
| `DATAGRAM_BYTES: usize` | 1200 | The largest payload netcode carries in one datagram |
| `MAX_UNFRAGMENTED_PACKET: usize` | 1191 | The largest connection packet that fits one datagram with reliable's header |
| `MAX_FRAGMENT_SIZE: usize` | 1186 | The largest fragment that fits one datagram with reliable's packet and fragment headers |
