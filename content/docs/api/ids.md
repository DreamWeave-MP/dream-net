+++
title = "Ids and sequences"
description = "EventTypeId, ChannelId, PeerId and Seq16."
weight = 20

[extra]
kind = "api"
+++

Modules `dream_net::id` and `dream_net::sequence`, all re-exported from the root.

## EventTypeId

{{ api_signature(value="struct EventTypeId(pub u32)") }}

A wire event type, assigned densely from the sorted event names when a schema is built. `Display`
prints `event 3`. `Clone`, `Copy`, `Debug`, `Eq`, `Ord`, `Hash`.

## ChannelId

{{ api_signature(value="struct ChannelId(pub u8)") }}

A channel, numbered by its position in the schema's declaration order. `Display` prints
`channel 0`. `Clone`, `Copy`, `Debug`, `Eq`, `Ord`, `Hash`.

## PeerId

{{ api_signature(value="struct PeerId(pub u64)") }}

A server's handle to one client. The low 16 bits are the netcode slot, the high 48 a generation
that grows every time any slot is filled, so a handle to a client that has left never reaches the
slot's next occupant: it fails as unknown. It fits a Luau integer. `Display` prints `peer 0:1`
(slot, generation) and `Debug` `PeerId(slot 0, generation 1)`. `Clone`, `Copy`, `Eq`, `Ord`,
`Hash`.

A client's inbox records the server as slot 0, with a generation that grows with each connection.

{{ api_signature(value="const MAX_GENERATION: u64 = (1 << 48) - 1") }}

The largest generation a `PeerId` can hold.

{{ api_signature(value="const fn new(slot: u16, generation: u64) -> PeerId") }}

A handle from a slot and a generation, masked to 48 bits.

{{ api_signature(value="const fn slot(self) -> usize") }}

{{ api_signature(value="const fn generation(self) -> u64") }}

The netcode slot, and the generation the slot had when this peer connected.

```rust
use dream_net::PeerId;

fn main() {
    let peer = PeerId::new(3, 41);
    assert_eq!((peer.slot(), peer.generation()), (3, 41));
    assert_eq!(peer.to_string(), "peer 3:41");
    assert_ne!(peer, PeerId::new(3, 42));
}
```

## Seq16

{{ api_signature(value="struct Seq16(pub u16)") }}

A 16-bit sequence number that wraps, used for reliable message ids. Ordering is circular: `a` is
newer than `b` when it is at most 32768 ahead of it, exactly as reliable orders packet sequence
numbers. It has no `<`: comparing raw ids goes wrong as soon as the counter wraps, so dream-net
compares them only through these methods. `Display` prints the number.
`Clone`, `Copy`, `Debug`, `Default`, `Eq`, `Hash`.

{{ api_signature(value="const ZERO: Seq16") }}

Sequence number 0.

{{ api_signature(value="const fn next(self) -> Seq16") }}

{{ api_signature(value="const fn add(self, n: u16) -> Seq16") }}

The next number, and this one advanced by `n`, both wrapping from 65535 to 0.

{{ api_signature(value="const fn since(self, base: Seq16) -> u16") }}

The forward distance from `base` to `self`, modulo 2<sup>16</sup>. A window of `w` ids starting
at `base` contains `self` exactly when `self.since(base) < w`.

{{ api_signature(value="fn is_newer_than(self, other: Seq16) -> bool") }}

{{ api_signature(value="fn is_older_than(self, other: Seq16) -> bool") }}

Circular comparison: newer means at most 32768 ahead. A number is neither newer nor older than
itself.

```rust
use dream_net::Seq16;

fn main() {
    let last = Seq16(u16::MAX);
    assert_eq!(last.next(), Seq16(0));
    assert!(Seq16(0).is_newer_than(last));
    assert_eq!(Seq16(3).since(Seq16(u16::MAX - 1)), 5);
}
```
