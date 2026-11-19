+++
title = "Compatibility and performance"
description = "What the version promises, the supported Rust, the pinned dependencies, the license and notices, what is tested, and what the transport costs."
weight = 88

[extra]
kind = "reference"
+++

## Versions

dream-net is at 2.x: releases in 2.x keep the Rust API compatible, as Cargo's semver rules expect.
A minor release adds API or changes the transport underneath; a patch release only fixes.

Peers must speak the same netcode protocol and the same wire version, and share a schema
fingerprint.

- **netcode protocol.** 2.1.0 speaks NETCODE 1.03 (netcode 1.5.0), which derives fresh packet
  keys for every connection attempt and fixes
  [GHSA-8mrq-q9c6-h23v](https://github.com/mas-bandwidth/netcode/security/advisories/GHSA-8mrq-q9c6-h23v).
  2.0.0 and every 1.x release speak NETCODE 1.02. The two never connect: a server ignores the
  other protocol's requests, so the client's attempt ends with `ConnectFailed { reason:
  TimedOut }`. Upgrade servers and clients together.
- **Wire version.** Builds with different `WIRE_VERSION`s refuse each other with
  `ProtocolMismatch`, on both ends, rather than misreading each other. Every release so far
  speaks wire format 2.

## Rust and dependencies

- **Rust 1.95** or newer, declared as `rust-version` and checked in CI. Edition 2024.
- **Clang 18** or newer (Apple Clang 16 on macOS) compiles the vendored C. `build.rs` verifies
  the compiler is Clang and refuses GCC, MSVC's `cl` and flags such as `-ffast-math` rather than
  fall back. Cross-language LTO also needs Clang, LLD and `llvm-ar` of rustc's LLVM major.
- **Unsafe code only at the C boundary**: the bindings in the hidden `native` module; every other
  module is `#![forbid(unsafe_code)]`, which a test enforces.
- **No features.** Everything is always built.

| Dependency | Version | For |
|---|---|---|
| netcode (C, vendored) | v1.5.0, plus three local patches | Connect tokens, encryption, slots, timeouts |
| reliable (C, vendored) | v1.4.6 | Acknowledgements, fragmentation, link statistics |
| `sha2` | `0.11.1`, no default features | The schema fingerprint |
| `cc` (build) | `1.9` or newer | Driving the verified Clang from `build.rs` |

The C is vendored from upstream at pinned commits, with a SHA-256 for every file, and checked
against upstream plus dream-net's patches before each release. The patches make a server on port
0 advertise the port it bound, hold its ports exclusively on Windows, and keep the cause of a
socket failure on Windows. An upgrade is a deliberate change that reruns the golden, fuzz and soak
tests. netcode brings a subset of libsodium for its cryptography. Any `sha2` 0.11 computes the
same digest.

## License

dream-net's own code is **MIT OR Apache-2.0**, at your option. The crate as a whole is
`(MIT OR Apache-2.0) AND BSD-3-Clause AND ISC`: netcode and reliable are Más Bandwidth LLC's,
under BSD 3-clause terms, and netcode's libsodium subset is under the ISC license. Their notices
are in [`NOTICE.md`](https://github.com/DreamWeave-MP/dream-net/blob/main/NOTICE.md), and must
travel with any product that ships dream-net, with the credit line it gives.

## What is tested

Every push runs [StroggForge](https://github.com/DreamWeave-MP/StroggForge)'s library workflow: the
tests on Windows, Linux, and macOS on both Apple silicon and Intel; `rustfmt`; Clippy at the
pedantic level with warnings as errors; `cargo audit`; a check against Rust 1.95; and a dry run of
the crates.io publish. A tag publishes to crates.io, and attaches the Criterion results to its
GitHub release as `BENCHMARKS.md`.

| Suite | Covers |
|---|---|
| Unit and property tests | Sequence ordering across the wrap, schema ids and fingerprints, transport validation |
| `tests/wire.rs`, `tests/wire_golden.rs` | Round trips against serialize's own streams, every malformed class, every truncation, random bytes, and the golden packets |
| `tests/connection.rs` | Over the simulator: exactly-once ordered delivery under loss, reordering and duplication, id wrap, fragments, the handshake and both mismatches, malformed input, backpressure, the parked budget, acknowledgement bursts |
| `tests/netcode.rs` | `Server` and `Client` over localhost UDP: connecting, exchanging, disconnecting, mismatches, full servers, bad tokens, silent peers, reused slots, and `Connected` before the first event |
| `tests/capture.rs` | Capture round trips, hostile capture files, a live server's capture |
| `tests/alloc.rs` | Warm send and receive paths allocate nothing, under a counting allocator |
| `tests/fuzz_smoke.rs` | The five fuzz harnesses on the stable toolchain |
| `tests/soak.rs` | Sixteen pairs for 1500 frames: mixed channels, loss, jitter, duplication, fragments, reconnects, stalled polling and id wrap, checking delivery and memory throughout |

Two gates run longer than `cargo test` does:

```sh
DREAM_NET_SOAK_FRAMES=200000 cargo test --release --test soak -- --nocapture
cd fuzz && RUSTC_BOOTSTRAP=1 cargo fuzz run <target> -s none -O -- -max_total_time=600
```

The fuzz targets are `wire_decode`, `connection_stream`, `channel_schedule`, `handshake` and
`capture_read`. They run on the stable toolchain, which is what `RUSTC_BOOTSTRAP` is for.

## What it costs

Criterion means from the benchmarks CI ran for 1.0.0, on a GitHub `ubuntu-22.04` runner, from the
`BENCHMARKS.md` on its [GitHub release](https://github.com/DreamWeave-MP/dream-net/releases).
`cargo bench --bench <name>` runs one suite: `wire`, `connection`, `scale` or `netcode`.

### Per call

| Call (`connection/…`) | 16 B | 64 B | 256 B | 1024 B |
|---|---:|---:|---:|---:|
| `send`, reliable | 18.2 ns | 19.2 ns | 22.1 ns | 62.4 ns |
| `send`, unreliable | 17.0 ns | 17.7 ns | 20.9 ns | 60.8 ns |
| `poll_into` | 6.1 ns | | 8.2 ns | 23.7 ns |

### 256 events through one connection

| Benchmark | 16 B | 64 B | 256 B | 1024 B |
|---|---:|---:|---:|---:|
| `pack`: queued events into datagrams, reliable | 8.2 µs | 10.2 µs | 17.9 µs | 52.5 µs |
| `pack`, unreliable | 7.1 µs | 8.9 µs | 17.0 µs | 54.1 µs |
| `direct`: a full frame on both ends, reliable | 25.9 µs | 29.5 µs | 47.1 µs | 126.6 µs |
| `direct`, unreliable | 23.0 µs | 25.8 µs | 42.3 µs | 117.6 µs |

Sixteen 8 KiB reliable events, fragmented and reassembled, take 31.7 µs. An idle connection's
`update` costs 2.1 µs, and an idle frame on both ends 4.5 µs.

### Loss

20,000 reliable 64-byte events through the simulator, 50 ms each way with 10 ms of jitter, resends
included:

| Loss | 0% | 1% | 5% | 20% |
|---|---:|---:|---:|---:|
| Time | 7.04 ms | 7.10 ms | 7.45 ms | 8.45 ms |

### Many peers

One server's frame, with each client sending a 16-byte reliable event and a 64-byte unreliable one,
and the server sending each client the same plus a 64-byte state event, datagrams passed directly:

| Peers | 1 | 16 | 64 | 256 |
|---|---:|---:|---:|---:|
| Frame | 0.01 ms | 0.09 ms | 0.37 ms | 1.50 ms |
| Idle frame | | | 0.29 ms | 1.15 ms |

### Real sockets

Loopback UDP with netcode's encryption, each client sending 32 64-byte events a frame and the
server sending 32 back to each, against netcode alone sending one datagram per event:

| Clients | 1 | 8 | 32 |
|---|---:|---:|---:|
| dream-net | 0.06 ms | 0.49 ms | 1.94 ms |
| One datagram per event | 0.65 ms | 5.15 ms | 19.87 ms |

Aggregation is most of the difference: one encryption and one system call per packet instead of
per event.

### The codec

Encoding and decoding one packet (`wire/…`), reliable:

| Packet | Encode | Decode |
|---|---:|---:|
| 1 × 16 B | 26.6 ns | 25.4 ns |
| 8 × 64 B | 116.9 ns | 93.1 ns |
| 16 × 256 B | 253.6 ns | 167.7 ns |
| 64 × 64 B | 843.0 ns | 633.9 ns |
| 4 × 1024 B | 101.1 ns | 53.8 ns |

Decoding copies nothing: payloads stay in the packet until they are delivered.
