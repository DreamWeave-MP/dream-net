# Native transport campaign

The living ledger for the migration tracked in
[#2](https://github.com/DreamWeave-MP/dream-net/issues/2): the Rust ports `netcode-official`,
`reliable` and `serialize-official` are replaced by the pinned upstream C `netcode` and
`reliable` from Más Bandwidth and by dream-net's own safe Rust bit framing.

Nothing here is pushed, tagged, or published. A row is `done` only when its evidence column
names a command that was actually run.

## Shared decisions

These hold for every workstream. Changing one is a director decision, recorded here first.

1. **Two crates.** `dream-net` (the workspace root) keeps `#![forbid(unsafe_code)]` and gains
   no C. A new workspace member, `native/` (crate `dream-net-native`), carries the vendored C,
   its `build.rs`, the raw declarations, and the safe wrappers. It is the only place `unsafe`
   appears. Both crates are published; neither has Cargo features.
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
5. **Wrappers mirror the old call surface.** `dream_net_native::netcode` and
   `dream_net_native::reliable` expose the subset of the `netcode-official` 1.0.0 and
   `reliable` 1.3.4 Rust APIs that dream-net calls, with the same names and semantics, so
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
    justified `unsafe impl` in the native crate. `Server` and `Client` were never `Send`.
17. **Token lifetime (proposed, owner decision pending).** `Server::new` keeps its signature
    and enforces the start floor with netcode's default maximum token lifetime of 30
    seconds; an additive constructor sets another maximum. Restart protection only covers
    tokens no longer-lived than that maximum. A token minted in the server's start second
    is refused, which changes one l3i test and three of ours.

## File ownership

| Area | Paths |
| --- | --- |
| Audit | `docs/maintenance/NATIVE_TRANSPORT_AUDIT.md` |
| Vendoring and build | `native/vendor/`, `native/patches/`, `native/build.rs`, `native/csrc/`, `native/Cargo.toml`, `native/tools/` |
| netcode binding | `native/src/netcode.rs`, `native/src/sys/netcode.rs`, `native/tests/netcode*.rs` |
| reliable binding | `native/src/reliable.rs`, `native/src/sys/reliable.rs`, `native/tests/reliable*.rs` |
| Framing | `src/bits.rs`, `src/wire.rs`, `tests/wire*.rs`, `tests/common/` |
| Secure lifecycle | `src/server.rs`, `src/client.rs`, `src/error.rs`, `src/lib.rs`, `tests/netcode.rs`, `benches/netcode.rs` |
| Reliability backend | `src/connection.rs`, `src/stats.rs`, `src/config.rs`, `src/sequence.rs`, `tests/connection.rs`, `tests/harness/`, `benches/connection.rs`, `fuzz/` |
| Interoperability | `interop/` |
| Director | this file, root `Cargo.toml`, `NOTICE.md`, CI, release notes, every integration |

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
| #4 | Pin and vendor C sources | native build agent | #3 | in progress | | | |
| #5 | Clang build, LTO proof | native build agent | #4 | queued | | | |
| #6 | netcode binding | | #4, #5 | queued | | | |
| #7 | reliable binding | | #4, #5 | queued | | | |
| #8 | Safe Rust framing | framing agent | #3 | in progress | | | |
| #9 | Secure lifecycle on C netcode | | #6, #8 | queued | | | |
| #10 | Reliability backend | | #7, #8 | queued | | | |
| #11 | Interop and wire parity | | #9, #10 | queued | | | |
| #12 | Security hardening | | #9, #10 | queued | | | |
| #13 | Packaging, CI, licenses | | #4, #5, #8, #9, #10 | queued | | | |
| #14 | Benchmarks | | #10 | queued | | | |
| #15 | L3i ABI | | #10, #11 | queued | | | |
| #16 | Maintenance docs, release prep | director | #11–#15 | queued | | | |

## Environment

Linux x86_64 (Bazzite, kernel 7.3.4), rustc 1.100.0 (LLVM 23.1.5), clang 23.1.2, LLD 23.1.2.
The 1.88 MSRV toolchain is not installed on this machine. macOS and Windows are not available
locally: they are untested until CI runs.
