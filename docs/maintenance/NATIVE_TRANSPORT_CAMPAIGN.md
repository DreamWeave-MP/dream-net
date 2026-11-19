# Native transport campaign

The living ledger for the migration tracked in
[#2](https://github.com/DreamWeave-MP/dream-net/issues/2): the Rust ports `netcode-official`,
`reliable` and `serialize-official` are replaced by the pinned upstream C `netcode` and
`reliable` from Más Bandwidth and by dream-net's own safe Rust bit framing.

Nothing here is pushed, tagged, or published. A row is `done` only when its evidence column
names a command that was actually run.

## Shared decisions

These hold for every workstream. Changing one is a director decision, recorded here first.

1. **One crate.** The owner decided on 2026-11-18 to fold `dream-net-native` back into
   `dream-net` before anything is published: a second crate whose only user is dream-net
   costs a crates.io name, a publish order and an exact pin, and "the main crate has no
   unsafe" says little when its one dependency holds all of it. dream-net's root is
   `#![deny(unsafe_code)]`, the FFI module alone allows it, and every other module forbids
   it. The manifest's license becomes `(MIT OR Apache-2.0) AND BSD-3-Clause AND ISC` because
   the package now contains the vendored sources; dream-net's own code stays
   `MIT OR Apache-2.0` and the obligations on redistributors are what they were. The work
   through #13 was done as two crates (`native/`), and the merge follows #12.
2. **Vendored, never fetched.** `native/vendor/` holds upstream sources at pinned commits,
   including the libsodium subset netcode bundles. A provenance manifest records each
   upstream URL, commit, and per-file SHA-256, and a checked-in script verifies the tree
   against it. Any local change to upstream C is a patch file in `native/patches/` with its
   reason; the vendored tree is reproducible as upstream plus those patches.
3. **Clang only.** `build.rs` compiles C with a compiler it has verified to be Clang and fails
   with a diagnostic otherwise. It never falls back to GCC or MSVC `cl.exe`. Cross-language
   LTO is an opt-in configuration that is proven by inspecting the linked output, not by a
   flag being accepted.
4. **Private symbols.** Every external C symbol the archive defines (`netcode_*`,
   `reliable_*`, `crypto_*`, `sodium_*`, `randombytes*`, …) is renamed under one dream-net
   prefix, so a host that links its own libsodium or netcode cannot collide. A test inspects
   the archive.
5. **Wrappers mirror the old call surface.** `dream_net::native::netcode` and
   `dream_net::native::reliable` (until the fold, `dream_net_native::netcode` and
   `dream_net_native::reliable`; hidden from the docs and not supported API) expose the
   subset of the `netcode-official` 1.0.0 and `reliable` 1.3.4 Rust APIs that dream-net calls, with the same names and semantics, so
   integration is a change of import rather than a redesign.
6. **No C struct is mirrored unchecked.** Rust passes scalars and byte pointers to a small C
   shim where it can; any struct it does mirror is pinned by `_Static_assert`s on size and
   field offsets in C.
7. **Callbacks end in Rust.** C callbacks land in trampolines that copy into Rust-owned,
   bounded storage or call a closure that cannot outlive the C call. No panic unwinds through
   a C frame. Nothing is ever called back into the host or Luau: everything stays polled.
8. **Public surface is preserved.** `Server`, `Client`, `PeerId`, `EventTypeId`, `Schema`,
   `send`, `poll_into`, the re-exported constants, and the auto traits (`Send`, `Sync`,
   `Unpin`) of every public type stay as they are in 1.1.1. Types that were re-exports of the
   Rust ports become dream-net's own with the same shape.
9. **Wire compatibility is tested, not assumed.** `tests/wire_golden.rs` stays byte for byte.
   Old (1.1.1 from crates.io) and new peers are run against each other from an unpublished
   `interop/` crate. The main crate does not depend on the Rust ports in any dependency
   kind. If a secure fix requires incompatibility, the protocol version changes and old
   peers are refused deterministically.
10. **Security is not traded.** Tests are never weakened to pass. A confirmed defect gets a
    permanent regression test; an unconfirmed one is recorded as a hypothesis.

11. **Pins.** netcode v1.4.10 (`d6bc96dafe2cc6c9b77903db7ce86f832a2de996`) and reliable v1.4.6
    (`b6245763cedb04d297ced7f196d6a1caeb0da239`). The audit found 1.4.10 fixes a receive stall
    that 1.4.9 still has.
12. **Where C is stricter on purpose, C wins.** Decision 5 covers the call surface, not the
    security behaviour. A connect token is single use, a token that could predate the
    server's start is refused, a server disconnect leaves the client disconnected, and
    zero-length datagrams are skipped. Tests that relied on the old behaviour are rewritten
    to assert the refusal; that is a correction, not a weakening.
13. **Asserts never fire on remote input and never exit the host.** The C is compiled with
    `NDEBUG` in every Cargo profile. The wrappers check every argument an upstream assert
    guards (empty sends, lengths, indices, config ranges) before calling in.
14. **Port 0 is patched.** One patch makes a server bound to port 0 advertise the port it
    was given, which dream-net and l3i both rely on.
15. **`TransportConfig::validate` refuses whatever C refuses**, so `Connection::new` stays
    infallible: window sizes are capped at 16384 (was 32768) and sizes must fit a C `int`.
16. **Auto traits.** `Connection` stays `Send + Sync + UnwindSafe + RefUnwindSafe`, by a
    justified `unsafe impl` in the native module. `Server` and `Client` were never `Send`.
17. **Token lifetime (proposed, owner decision pending).** `Server::new` keeps its signature
    and enforces the start floor with netcode's default maximum token lifetime of 30
    seconds; an additive constructor sets another maximum. Restart protection only covers
    tokens no longer-lived than that maximum. A token minted in the server's start second
    is refused, which changes one l3i test and three of ours.
18. **Release version 2.0.0 (owner decision, 2026-11-18).** The owner chose a major bump. It
    is warranted on its own by the public type changes (the `Error::Netcode` payload,
    `generate_connect_token`'s error, and the return types of `reliable_config` and
    `reliable_counters` are now dream-net's own types), the new build requirement (Clang),
    and the behaviour changes callers can observe (single-use connect tokens, the start
    floor, the `TransportConfig` window cap lowered from 32768 to 16384, `MemoryUsage.reliable`
    now a true bound). The `version = "2.0.0"` edit to `Cargo.toml` and `content/home/mod.toml`
    is made during release prep (#16), after the one-crate merge integrates, to avoid a
    conflict with the merge's own `Cargo.toml` rewrite.

## File ownership

| Area | Paths |
| --- | --- |
| Audit | `docs/maintenance/NATIVE_TRANSPORT_AUDIT.md` |
| Vendoring and build | `native/vendor/`, `native/patches/`, `native/csrc/`, `native/tools/`, `native/*.md`, `build.rs`, `examples/lto_probe.rs`, `tests/native_build_*.rs`, `tests/native_fuzz.rs` |
| netcode binding | `src/native/netcode.rs`, `src/native/netcode/`, `src/native/sys/netcode.rs`, `tests/native_netcode*.rs`, `tests/native_netcode_support/` |
| reliable binding | `src/native/reliable.rs`, `src/native/reliable/`, `src/native/sys/reliable.rs`, `tests/native_reliable*.rs`, `tests/native_reliable_support/` |
| Framing | `src/bits.rs`, `src/wire.rs`, `tests/wire*.rs`, `tests/common/` |
| Secure lifecycle | `src/server.rs`, `src/client.rs`, `src/error.rs`, `src/lib.rs`, `tests/netcode.rs`, `benches/netcode.rs` |
| Reliability backend | `src/connection.rs`, `src/stats.rs`, `src/config.rs`, `src/sequence.rs`, `tests/connection.rs`, `tests/harness/`, `benches/connection.rs`, `fuzz/` |
| Interoperability | `interop/` |
| Director | this file, root `Cargo.toml`, `src/native/mod.rs`, `tests/unsafe_confinement.rs`, `NOTICE.md`, CI, release notes, every integration |

## Dependency graph

```text
#3 audit ─┬─> #4 pin sources ──> #5 Clang build ─┬─> #6 netcode binding ──> #9 lifecycle ─┐
          │                                      └─> #7 reliable binding ─> #10 backend ──┤
          └─> #8 framing ─────────────────────────────────────────────────────────────────┤
                                                                                          v
              #11 interop, #12 hardening, #13 packaging, #14 benchmarks, #15 L3i ──> #16 release
```

#9 and #10 touch disjoint files (`Server`/`Client` against `Connection`) and run together.

## Ledger

| Issue | Scope | Owner | Depends on | Status | Commits | Evidence | Blockers |
| --- | --- | --- | --- | --- | --- | --- | --- |
| #3 | Audit and baseline | audit agent, director (baseline) | none | done | `TEST: Pin transport security behaviour against a live server`, `DOCS: Record the native transport audit baseline` | Baseline on `d6a81f5`: `cargo test --workspace --all-targets --all-features` 79 passed; 200k-frame soak passed (53.5 s, 438 MB peak RSS); `cargo audit` clean; four Criterion benches saved as `pre-native`. Audit: [NATIVE_TRANSPORT_AUDIT.md](NATIVE_TRANSPORT_AUDIT.md) | |
| #4 | Pin and vendor C sources | native build agent | #3 | done | `FEAT: Vendor pinned upstream C netcode and reliable sources`, `FEAT: Add the dream-net-native crate with vendor provenance checks`, `FIX: Publish the bound port of a netcode server created on port 0` | After integration: `native/tools/verify-vendor` reports 11 vendored files and 1 patch matching `PROVENANCE.toml`. Agent run: `verify-vendor --fetch` re-derives the tree from upstream plus the patch; forbidden-license scan clean; `native/SODIUM.md` identifies the bundled libsodium as 1.0.21/1.0.22 crypto over 1.0.17 support code, ISC | |
| #5 | Clang build, LTO proof | native build agent | #4 | done on Linux x86_64 | `FEAT: Build the native archive with a verified Clang under a private prefix`, `TEST: Run upstream netcode and reliable C unit tests from cargo test`, `TEST: Prove cross-language LTO by disassembling a Rust caller of the shim`, `DOCS: Document the native toolchain, flags, LTO and platform matrix` | After integration: fmt, pedantic clippy, `cargo test --workspace --all-targets --all-features` 109 passed, 1 ignored (upstream C suites, symbol-prefix check over the archive, LLD `.comment` check); `cargo test -p dream-net-native --test build_lto -- --ignored` passed (C inlined into the Rust caller). Agent run: identical archive hashes across clean builds; GCC, fast-math, GNU ar under LTO and LLVM mismatch each refused; upstream C suites clean under ASan+UBSan; packaged tarball builds offline; `cargo +1.88 check` passed | macOS, Windows and aarch64 are untested until CI runs. Thin LTO does not inline under the workspace's `lto = "fat"`; full LTO does |
| #6 | netcode binding | netcode binding agent | #4, #5 | done on Linux x86_64 | `FEAT: Add a safe netcode client, keys and connect tokens over the vendored C`, `FEAT: Add the safe netcode server with fixed-size slot events`, `TEST: Prove the netcode binding over loopback sockets`, `TEST: Reproduce netcode-official's eleven known-answer vectors with the C`, `TEST: Run the C netcode binding against netcode-official 1.0.0`; director: `FEAT: Initialise the native libraries once per process` | After integration: fmt, pedantic clippy, `cargo test --workspace --all-targets --all-features` 145 passed, 1 ignored; `interop/` `cargo test` 21 passed (old Rust port against new C, both directions). Agent run: native tests clean with the C under ASan+UBSan on nightly; all 11 known-answer vectors identical; `cargo +1.88 check` passed | A session that connects and disconnects between two event batches is not reported (by design; nobody saw it) |
| #7 | reliable binding | reliable binding agent | #4, #5 | done on Linux x86_64 | `FEAT: Bind the vendored C reliable behind a safe Endpoint`, `TEST: Exercise the reliable binding end to end`, `TEST: Prove Config::validate against C and receive_packet against hostile input`, `TEST: Measure the endpoint's memory with a counting allocator`, `TEST: Run the C binding against the reliable 1.3.4 Rust port` | After integration: fmt, pedantic clippy, `cargo test --workspace --all-targets --all-features` 179 passed, 1 ignored; `interop/` `cargo test` 29 passed (identical datagrams, deliveries, acks and counters between the Rust port and C, including a 70,000-frame run across the sequence wrap); symbol-prefix check passed. Agent run: upstream fuzz target 120 s with and without asserts, no crash; native tests clean under ASan+UBSan | Worst-case reassembly memory is about 581 KB per connection at dream-net's config; dream-net reported 300 B per slot. #10 corrects the accounting |
| #8 | Safe Rust framing | framing agent | #3 | done | `FEAT: Add a safe, total bit stream…`, `TEST: Add an interop crate…`, `REFACTOR: Frame connection packets…`, `DEPS: Drop serialize-official…`, `PERF: Pack byte runs…` | After integration: fmt, pedantic clippy, `cargo test --workspace --all-targets --all-features` 98 passed; `interop/` `cargo test` 17 passed (byte parity with dream-net 1.1.1 and serialize over random schemas, 285,301-decode sweep covering every `Malformed` reason); `cargo tree -i serialize-official` finds no package; golden vectors untouched. Agent run: `wire_decode` fuzzed 16.1M runs in 121 s, no crash | Docs outside the framing files still name serialize (director, with #16) |
| #9 | Secure lifecycle on C netcode | lifecycle agent | #6, #8 | done | `TEST: Pin the public surface of Server, Client and the token re-exports`, `FEAT: Run Server and Client on the C netcode binding`, `TEST: Pin peer handles and teardown through netcode's batched slot events`, `TEST: Assert the secure token, restart, flood and disconnect behaviour of C netcode`, `TEST: Run dream-net 1.1.1 peers against the C netcode lifecycle`; director: `DEPS: Drop netcode-official and its ctutils floor` | After integration: fmt, pedantic clippy, `cargo test --workspace --all-targets --all-features` 196 passed, 1 ignored; `interop/` `cargo test` 36 passed (dream-net 1.1.1 client and server against the new ones, both directions, events on both channels, schema mismatch in all four pairings). Agent run: `tests/api_surface.rs` written and passing on the old backend, unchanged after the port; the six security regressions fail on the pre-port tree; l3i (unmodified copy) `cargo check --all-targets` passed and 3 of 4 udp tests passed | l3i's `events_flow_both_ways_over_localhost` fails by design: it mints a 30-second token in the server's start second (decision 17). `dream-net-native` pins `cc` exactly, which forced a lockfile update in l3i (#13) |
| #10 | Reliability backend | reliability backend agent | #7, #8 | done | `TEST: Run old and new dream-net connections against each other and differentially`, `FIX: Refuse every transport configuration the C reliable would refuse`, `REFACTOR: Drive Connection's packet acks and fragments through the C reliable`, `FIX: Report reliable's memory as the native endpoint's true bound`, `TEST: Pin connection delivery and memory on the native reliable`, `DEPS: Drop the reliable Rust port`; director: `FEAT: Name reliable's configuration and counters from dream-net` | After integration and the last dependency removal: fmt, pedantic clippy, `cargo test --workspace --all-targets --all-features` 205 passed, 1 ignored; `interop/` `cargo test` 46 passed; `cargo tree -e all -i` finds none of `netcode-official`, `reliable`, `serialize-official`, `ctutils`; `cargo doc` no warnings; `cargo +1.88 check` passed; `cargo audit` clean; 200k-frame soak passed (30.4 s). Agent run: four old/new pairings byte-identical over five scenarios (795,872 events across the sequence wrap); five fuzz targets 60 s each, no crash; like-for-like endpoint memory 48,713 B (Rust port) against 49,329 B (C) at creation, 580,185 B against 581,185 B worst case | `packet_budget` below the header size trips a debug assertion; present in 1.1.1 too (#12). Site pages still state the 32768 window limit (#16) |
| #11 | Interop and wire parity | compatibility agent | #9, #10 | done on Linux x86_64 | `TEST: Pin compatibility golden vectors and prove them equal to dream-net 1.1.1`, `TEST: Run every old and new client and server pairing over loopback sockets`, `TEST: Pin protocol version rejection at connection level and over sockets`, `TEST: Compare every error text a host or script can see with dream-net 1.1.1`, `DOCS: Record what dream-net 1.1.1 peers and the native transport can say to each other` | After integration: `cargo test --workspace --all-targets --all-features` 215 passed, 1 ignored; `interop/` `cargo test` 67 passed, 1 ignored (a by-hand printer). Every cell of the old/new client/server matrix passes over loopback, IPv4 and IPv6; the five original golden vectors are unchanged and every added one equals what 1.1.1 writes. See [NATIVE_TRANSPORT_COMPATIBILITY.md](NATIVE_TRANSPORT_COMPATIBILITY.md) | No wire-version bump is needed. The release version (2.0.0 recommended, four public signatures changed type) is the owner's decision. Old against new under loss was run over simulated links only |
| #12 | Security hardening | hardening agent | #9, #10 | done | `FIX: Refuse a packet budget smaller than the largest packet header`, `TEST: Fuzz the native server, client and reliable receive paths with known keys`, `TEST: Pin nonce uniqueness, token replay, amplification and the history bound`, `TEST: Keep forged-fragment taint sticky and seed the native fuzzers`, `DOCS: Record the native transport security review`, and the withheld-finding mitigation `FIX: Refuse a connect token the process has already used` (landed with the merge) | After integration: `cargo test --locked --workspace --all-targets --all-features` 245 passed, 1 ignored; license gates passed. Agent run: eight native fuzz targets at 600 s each in both the production build and a build with asserts live and fatal, under ASan+UBSan, with no crash and no assert trip; three cargo-fuzz targets at 600 s with the C instrumented; whole workspace under ASan+UBSan with LSan active, 218 passed; soak under ASan passed. See [NATIVE_TRANSPORT_SECURITY.md](NATIVE_TRANSPORT_SECURITY.md) | The withheld netcode finding was reported to upstream by the owner. dream-net's client-side single-use-token mitigation has landed, so this is no longer a release blocker; the mitigation covers one process only, documented for hosts. A whole-tree sanitizer pass on the merged, one-crate tree is still owed (director) |
| #13 | Packaging, CI, licenses | packaging agent | #4, #5, #8, #9, #10 | done on Linux x86_64; CI unrun | Fourteen commits from `DEPS: Relax the cc pin to a semver floor and commit the workspace lockfile` to `DOCS: Record the packaging, publishing and license evidence for the native transport` | After integration: `cargo test --locked --workspace --all-targets --all-features` 215 passed, 1 ignored; `cargo deny check` advisories, bans, licenses and sources ok; `tools/check-native-licenses` passed; `cargo audit` clean; `cargo publish --workspace --dry-run --locked` passed; `cargo +1.88 check --locked` passed; `tools/check-offline-consumer` passed inside a network namespace (both tarballs tested debug and release, a fresh consumer in debug, release, fat LTO and cross-language LTO with 6 of 6 bitcode members, and `CC=gcc` refused). See [NATIVE_TRANSPORT_PACKAGING.md](NATIVE_TRANSPORT_PACKAGING.md) | No workflow has run on GitHub; macOS, Windows and aarch64 are unverified. `Cargo.lock` is now tracked, which the owner should confirm. dream-net 1.1.1 is already on crates.io, so a release needs a version bump |
| #14 | Benchmarks | director | #10 | done on Linux x86_64 | `DOCS: Record the native transport benchmarks` | All four Criterion benches (76 benchmarks) on `d6a81f5` and on `3eeccef`, back to back on one machine, saved as `before` and `after`; every benchmark that moved 7% or more rerun in the reverse order (`after2` then `before2`) to separate real change from drift. 200k-frame soak, release binary alone, twice per side: 33.2–34.3 s and 15.4 MB peak RSS before, 30.5–31.2 s and 16.0 MB after. See the note below | Four small slowdowns hold in both orders (below); none is above 0.4 µs per call |
| #15 | L3i ABI | compatibility agent | #10, #11 | done; one l3i-side test change outstanding | `TEST: Verify the caller-owned buffers and polled network phase l3i relies on`, `CHORE: Add a script that builds and tests l3i against this checkout`, `DOCS: Record how l3i behaves on the native transport` | Agent run with `tools/check-l3i` on an unmodified copy of l3i: `cargo check --all-targets` passed; 3 of 4 udp tests passed; the fourth passes on 1.1.1, fails here with a 30-second token and passes with 31 seconds, so the start floor is its only cause; `benches/udp.rs` smoke-ran. See [NATIVE_TRANSPORT_L3I.md](NATIVE_TRANSPORT_L3I.md) | l3i must change one test and its lockfile when it upgrades (proposed patch in the document, not applied). The module l3i registers is `@dream/udp`, not `@dream/net` |
| #16 | Maintenance docs, release prep | director | #11–#15 | queued | | | |

**2026-11-18: one crate.** The rows above describe the work as it was done, through #12, with the
C and its bindings in a separate crate, dream-net-native (`native/`). At the owner's decision
(decision 1) that crate was then folded into dream-net: `REFACTOR: Fold the native crate into
dream-net as one package`, `TEST: Build each native fuzz harness once per test process` (a
race between two tests that the packaged crate's fresh build exposed), `CHORE: Package, check
and run CI as one crate` and `DOCS: Describe dream-net as one crate with its native module`. The bindings are now `src/native/`
(`dream_net::native`, hidden), the build script is the root `build.rs`, the binding tests are
`tests/native_*.rs`, and `native/` keeps the C, patches, shim, tools and provenance. Evidence
after the fold: `cargo test --locked --workspace --all-targets --all-features` 232 passed, 1
ignored (227 and 1 before, plus the 5 tests of `tests/unsafe_confinement.rs`; all 228 earlier test
names still present, under their new binaries); the archive's objects byte-identical before and
after in debug and release (only cc's hashed member-name prefixes differ), with the same 722
(debug) and 679 (release) defined symbols; `tools/check-reproducible` passed (archive identical
from two checkout paths, the crate (about 470 KiB) identical across two packaging runs); `interop/`
`cargo test` 67 passed, 1 ignored; the LTO probe passed; 200k-frame soak passed (30.9 s);
`cargo +1.88 check` and `cargo +1.88 test --test native_build_lld` passed; `cargo deny check`,
`cargo audit` and `tools/check-native-licenses` clean; `tools/check-offline-consumer` passed in
a network namespace (the tarball's tests in debug and release, the consumer in debug, release,
fat LTO and cross-language LTO with 6 of 6 bitcode members, `CC=gcc` refused).

### Note (2026-11-18): one-crate merge integrated

The owner's one-crate decision (shared decision 1) is done. `dream-net-native` was folded
into `dream-net` as a `#[doc(hidden)]`, `#[allow(unsafe_code)]` `native` module; every other
module keeps `#![forbid(unsafe_code)]`, enforced by `tests/unsafe_confinement.rs`. The native
static archive is byte-identical before and after the fold (verified by `llvm-ar`/`llvm-nm`),
so it is a pure repackaging. The published crate is now `dream-net` alone, license
`(MIT OR Apache-2.0) AND BSD-3-Clause AND ISC`; `cargo publish --dry-run --locked` passes
plain. The merge commits are `REFACTOR: Fold the native crate into dream-net as one package`
through `FIX: Refuse a connect token the process has already used`. All eleven agent worktrees
have been removed.

### Note (2026-11-18): PR #17 raised

The branch `native-transport` is pushed and PR #17 is open against `main`
(https://github.com/DreamWeave-MP/dream-net/pull/17), with the owner's authorization. The PR
body carries the per-issue status and the exact remaining-work instructions. Still owed before
release, all recorded in the PR: #14 benchmarks (**not run** — needs a quiet machine) and the
before/after posters; the whole-tree sanitizer pass on the merged one-crate tree; the 2.0.0
version bump plus `content/home/mod.toml` release notes and README/site updates (#16); and a
green CI run on GitHub (never run; macOS/Windows/aarch64 unverified). The private vuln report,
image and PoC are kept out of git via `.git/info/exclude`.

### Note (2026-11-19): benchmarks run

Machine: the Linux x86_64 host under Environment, `performance` governor, load below 1, desktop
idle. Before is `d6a81f5` (the three Rust ports), after is `3eeccef` (the C netcode and reliable,
safe Rust framing). Medians, Criterion's default settings.

Gains come from the first pass only; the reversed rerun showed drift between passes of up to
about 12 points, so only the larger ones are firm:

- Wire encode of multi-event frames: −18% to −30% (`wire/encode/*/{8x64B,16x256B,64x16B,64x64B}`).
  This is #8's safe framing, not the C. Decode of 64-event frames: −8% to −16% (within drift).
- Real loopback netcode: `netcode/frame/netcode_per_event` −28% to −31% at 1, 8 and 32 events
  (C netcode's per-packet cost); dream-net's batched frame −18% at 32 events.
- Packing 256 small events (`connection/pack/*/256x{16,64}B`) −15% to −20%, and
  `connection/poll_into` −11% to −21%: likely real, at the edge of drift.
- Soak: about 9% less wall time, in both runs per side.

Four slowdowns hold when the run order is reversed (run 1 / run 2):

| Benchmark | Before → after (run 2) | Run 1 | Run 2 |
| --- | --- | --- | --- |
| `wire/decode/reliable/1x16B` | 19.3 → 22.0 ns | +20% | +14% |
| `connection/send/reliable/256B` | 20.0 → 21.7 ns | +10% | +8% |
| `connection/idle/frame_both_ends` | 5.11 → 5.46 µs | +8% | +7% |
| `connection/idle/reliable_update/history512` | 2.67 → 2.82 µs | +17% | +6% |

Peak soak memory rose 0.6 MB (15.4 → 16.0 MB), in line with #10's worst-case accounting of the C
reliable. The first pass also showed `connection/fragmented/16x8KiB` +13%, `scale/frame/256`
+11%, `scale/idle_frame/256` +17% and `reliable_update/history128` +8%; each reversed sign
(−11%, −7%, −6%, −9%) when rerun in the other order, so they are drift, not the migration.
No benchmark regresses by more than 0.4 µs per call, and every per-frame cost at 256 peers is
within run-to-run drift. The earlier draft poster's 438 MB soak figure included the build; the
soak binary alone peaks at about 16 MB on both sides.

## Environment

Linux x86_64 (Bazzite, kernel 7.3.4), rustc 1.100.0 (LLVM 23.1.5), clang 23.1.2, LLD 23.1.2.
The 1.88 MSRV toolchain is not installed on this machine. macOS and Windows are not available
locally: they are untested until CI runs.
