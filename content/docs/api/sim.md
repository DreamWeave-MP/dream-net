+++
title = "Simulator"
description = "Pair, Link, LinkConfig, LinkCounters and Rng: the deterministic network simulator."
weight = 110

[extra]
kind = "api"
+++

Module `dream_net::sim`, not re-exported from the root. A deterministic network simulator for tests
and benchmarks. [Connections and the simulator](@/docs/simulator.md) shows it in use.

## Pair

{{ api_signature(value="struct Pair { pub a: Connection, pub b: Connection, pub a_inbox: Inbox<()>, pub b_inbox: Inbox<()>, pub a_to_b: Link, pub b_to_a: Link, pub time: f64 }") }}

Two connections joined by a link each way: `a`, by convention the server, and `b`, the client;
the inbox each delivers into; the two links; and the simulated time in seconds. `Debug`.

{{ api_signature(value="const PEER: PeerId = PeerId::new(0, 1)") }}

The peer each end delivers as.

{{ api_signature(value="fn new(a: Arc<Shared>, b: Arc<Shared>, a_to_b: LinkConfig, b_to_a: LinkConfig, seed: u64) -> Pair") }}

Joins a connection built from `a` with one built from `b`, both starting at time 0. The link from
`b` to `a` is seeded from `seed` too, differently.

{{ api_signature(value="fn symmetric(shared: &Arc<Shared>, link: LinkConfig, seed: u64) -> Pair") }}

Both ends from one `Shared`, over the same impairments each way.

{{ api_signature(value="fn step(&mut self, dt: f64)") }}

One frame of `dt` seconds, the way a host runs one: compact both inboxes, update both connections,
deliver every datagram due to `a` and then to `b`, with acknowledgements sent at once going back
over the other link, and flush `a` and then `b`.

{{ api_signature(value="fn handshake(&mut self, dt: f64, max_steps: usize) -> bool") }}

Steps until both ends are established, or `max_steps` frames pass. Whether both established.

{{ api_signature(value="fn set_perfect(&mut self)") }}

Heals both links: datagrams sent from now on are neither delayed nor lost. Those already in flight
arrive as they would have.

## Link

{{ api_signature(value="struct Link") }}

A one-way simulated datagram link. `Debug`.

{{ api_signature(value="fn new(config: LinkConfig, seed: u64) -> Link") }}

A link with `config`, seeded for reproducibility.

{{ api_signature(value="fn send(&mut self, time: f64, datagram: &[u8])") }}

Offers a datagram at `time`. It is lost with probability `loss`; otherwise it arrives after
`latency` plus up to `jitter` seconds, with one random bit flipped with probability `corrupt`, and
a second copy, drawn separately, is delivered with probability `duplicate`.

{{ api_signature(value="fn deliver(&mut self, time: f64, receive: impl FnMut(&[u8]))") }}

Hands every datagram due by `time` to `receive`, in arrival order; datagrams due at the same moment
arrive in the order they were sent.

{{ api_signature(value="fn set_config(&mut self, config: LinkConfig)") }}

Changes the impairments for datagrams sent from now on.

{{ api_signature(value="fn counters(&self) -> LinkCounters") }}

{{ api_signature(value="fn in_flight(&self) -> usize") }}

The link's totals, and the datagrams in flight.

## LinkConfig

{{ api_signature(value="struct LinkConfig { pub latency: f64, pub jitter: f64, pub loss: f64, pub duplicate: f64, pub corrupt: f64 }") }}

| Field | Meaning |
|---|---|
| `latency` | One-way delay, seconds |
| `jitter` | Extra uniform random delay in `[0, jitter)` seconds; it reorders datagrams |
| `loss` | Probability a datagram is lost |
| `duplicate` | Probability a datagram is delivered twice |
| `corrupt` | Probability one random bit of a datagram is flipped |

`Clone`, `Copy`, `Debug`, `PartialEq`. `Default` is `PERFECT`.

{{ api_signature(value="const PERFECT: LinkConfig") }}

No delay, no loss, nothing else.

{{ api_signature(value="fn latency(latency: f64) -> LinkConfig") }}

The given one-way delay, and nothing else.

## LinkCounters

{{ api_signature(value="struct LinkCounters { pub sent: u64, pub lost: u64, pub duplicated: u64, pub corrupted: u64, pub delivered: u64, pub bytes: u64 }") }}

Totals a link has seen: datagrams offered, dropped, copied, corrupted, and delivered (copies
included), and bytes offered. `Clone`, `Copy`, `Debug`, `Default`, `Eq`.

## Rng

{{ api_signature(value="struct Rng") }}

SplitMix64: small, fast, and the same on every platform, so a seed reproduces a run anywhere.
`Clone`, `Debug`.

{{ api_signature(value="fn new(seed: u64) -> Rng") }}

{{ api_signature(value="fn next_u64(&mut self) -> u64") }}

The next 64 random bits.

{{ api_signature(value="fn unit(&mut self) -> f64") }}

A uniform float in `[0, 1)`, from the top 53 bits.

{{ api_signature(value="fn chance(&mut self, p: f64) -> bool") }}

Whether an event of probability `p` happens. A `p` of 0 or less never happens and draws nothing.

{{ api_signature(value="fn below(&mut self, n: u64) -> u64") }}

An integer in `[0, n)`, by remainder; 0 when `n` is 0.
