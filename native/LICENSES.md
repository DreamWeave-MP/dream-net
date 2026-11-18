# Native license report

The license of every file dream-net-native packages, and the evidence behind it. Reviewed
2026-11-18 at the pins in `vendor/PROVENANCE.toml`; redo this review whenever a pin moves or a
patch is added.

## Summary

| Component | Files | License | Source of truth |
| --- | --- | --- | --- |
| dream-net-native's own code | `build.rs`, `src/**`, `tests/**`, `examples/**`, `csrc/**`, `tools/**`, `patches/**`, documentation | MIT OR Apache-2.0 | `LICENSE-MIT`, `LICENSE-APACHE` |
| netcode v1.4.10 | `vendor/netcode/netcode.c`, `vendor/netcode/netcode.h`, `vendor/netcode/test.cpp`, `vendor/netcode/LICENCE` | BSD-3-Clause, Más Bandwidth LLC | `vendor/netcode/LICENCE`, and the same text at the head of each source file |
| reliable v1.4.6 | `vendor/reliable/reliable.c`, `vendor/reliable/reliable.h`, `vendor/reliable/test.cpp`, `vendor/reliable/LICENCE` | BSD-3-Clause, Más Bandwidth LLC | `vendor/reliable/LICENCE`, and the same text at the head of each source file |
| libsodium subset (bundled by netcode) | `vendor/netcode/sodium/sodium.c`, `vendor/netcode/sodium/sodium.h` | ISC, Frank Denis; the ChaCha20 reference code inside `sodium.c` is D. J. Bernstein's public-domain `chacha-merged.c` | the ISC comment heading both files (byte-identical to libsodium's `LICENSE` at 1.0.22) |
| netcode's notes on the subset | `vendor/netcode/sodium/NOTES.md` | BSD-3-Clause (part of the netcode repository) | `vendor/netcode/LICENCE` |
| `vendor/PROVENANCE.toml` | manifest | MIT OR Apache-2.0 (ours) | |

The package's SPDX expression is therefore `(MIT OR Apache-2.0) AND BSD-3-Clause AND ISC`.
The public-domain ChaCha20 reference code imposes no terms and has no SPDX identifier of its own;
libsodium distributes it under ISC, which covers it.

All three licenses are permissive and compatible with dream-net's MIT OR Apache-2.0. Their only
conditions are notice retention: BSD-3-Clause requires the copyright notice, conditions and
disclaimer in source redistributions and "in the documentation and/or other materials" of binary
redistributions, plus no endorsement using the copyright holder's name; ISC requires the
copyright and permission notice in all copies. `NOTICE.md` carries every required text verbatim,
and `tests/build_vendor.rs` fails if it stops doing so. Products shipping a binary that contains
this crate (dream-net, l3i, Jess) must reproduce `NOTICE.md`.

netcode and reliable also *request*, explicitly without requiring it, a product credit:
"netcode - Glenn Fiedler and Rowan Claude", "reliable - Glenn Fiedler and Rowan Claude".

## Third-party code inside the vendored files

- `netcode.c`, `netcode.h`, `reliable.c`, `reliable.h`, both `test.cpp`: only the Más Bandwidth
  BSD-3-Clause header. A search for "copyright", "license", "public domain", "adapted from",
  "based on", "taken from" and "borrowed" finds no other attribution.
- `sodium.c`, `sodium.h`: the libsodium ISC header and DJB's "Public domain." line for
  `chacha-merged.c`. libsodium's other contributors (`AUTHORS` at 1.0.22: Romain Dolbeau's
  SSSE3/AVX2 ChaCha20, Andrew Moon's poly1305-donna, and others) contributed under libsodium's ISC
  license; their files in the amalgamation carry no separate notice, and none is required beyond
  the ISC one.

## Forbidden terms scan

Command, run in `native/vendor/` on 2026-11-18:

```text
grep -r -n -i -E '\bgpl\b|lgpl|agpl|gnu general|lesser general|affero|mbsl|business source|non-?commercial|commons clause|sspl|server side public|creative commons|cc-by|cc0|unlicense|wtfpl|rocketnet|yojimbo|serialize\.h|patent' .
```

Result: no license text or term of GPL, LGPL, AGPL, MBSL, BUSL, SSPL, Commons Clause, any
non-commercial clause, or Creative Commons; no patent clause. The only matches are:

- the word "yojimbo" in comments of `sodium.c`, `sodium.h`, `sodium/NOTES.md` and one comment in
  `netcode.c`, because the same libsodium subset is shared with yojimbo. No yojimbo code is
  vendored;
- a SHA-256 in `PROVENANCE.toml` that happens to contain the letters `cc0`.

## Excluded on purpose

- **RocketNet** (AGPL): not vendored, not referenced, not depended on.
- **yojimbo** and the **C++ serialize** library: not vendored. Only netcode and reliable C are
  used; dream-net's own framing replaces serialize.
- Everything else in the upstream repositories: build systems (CMake, premake), examples,
  `client.c`/`server.c`/`soak.c`/`profile.c`, fuzz harnesses and corpora, conformance tools,
  Go/Rust bindings, documentation, CI files, Docker and OSS-Fuzz files.

## Build and test dependencies

- `cc` >= 1.2.8 (build-dependency; 1.11.2 in the workspace lockfile): MIT OR Apache-2.0. Its
  non-optional dependencies, `find-msvc-tools` and `shlex`, are MIT OR Apache-2.0.
- `sha2` 0.11 and `proptest` 1.12 (dev-dependencies): MIT OR Apache-2.0.

The Rust graph as a whole (normal, build and dev dependencies, every target) is gated by
`cargo deny check` against the workspace's `deny.toml`; the vendored C above is gated by the
workspace's `tools/check-native-licenses`, which runs this scan with the reviewed matches listed
above and fails on any other.
- Clang, LLD and the LLVM binutils are tools: the archive contains only objects compiled from the
  files above. (A sanitizer build, `BUILD.md`, links Clang's sanitizer runtime into test binaries;
  that build is never shipped.)
