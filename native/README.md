# dream-net-native

The native half of [dream-net](https://github.com/DreamWeave-MP/dream-net): Más Bandwidth's C
[netcode](https://github.com/mas-bandwidth/netcode) and
[reliable](https://github.com/mas-bandwidth/reliable), vendored at pinned commits, compiled with
a verified Clang into one static archive whose symbols all carry the `dn_native_` prefix, and
wrapped in safe Rust. dream-net depends on it; nothing else should need to.

| What | Where |
| --- | --- |
| Pinned upstream sources | `vendor/`, manifest `vendor/PROVENANCE.toml` |
| Local changes to upstream C | `patches/` (one: port-0 server public address) |
| Our C shim and the symbol-prefix header | `csrc/` |
| Toolchain, flags, LTO, sanitizers, platforms | `BUILD.md` |
| Licenses | `NOTICE.md` (required notices), `LICENSES.md` (per-file report) |
| The bundled libsodium audit | `SODIUM.md` |
| Vendor verification | `tools/verify-vendor`, `tests/build_vendor.rs` |

Pins (2026-11-18):

| Upstream | Tag | Commit |
| --- | --- | --- |
| netcode | v1.4.10 | `d6bc96dafe2cc6c9b77903db7ce86f832a2de996` |
| reliable | v1.4.6 | `b6245763cedb04d297ced7f196d6a1caeb0da239` |
| libsodium (bundled in netcode) | crypto 1.0.21/1.0.22, support code 1.0.17 | via the netcode pin |

## Verifying the vendored tree

```sh
native/tools/verify-vendor              # offline: every SHA-256 against PROVENANCE.toml
native/tools/verify-vendor --fetch      # re-derive vendor/ from upstream at the pins + patches
native/tools/verify-vendor --upstream DIR   # same, from existing clones DIR/netcode, DIR/reliable
cargo test -p dream-net-native --test build_vendor   # the offline check, in Rust
```

## Moving a pin

A pin moves in its own commit (`DEPS:`), never together with other changes, and only after the
upstream diff since the current pin has been read.

1. **Review upstream.** Clone the repository outside this one with full history. Read
   `git log --stat <old commit>..<new tag>` and the diff of every vendored file. Prefer a release
   tag; pin a later commit only for a fix the tag lacks, and say why in the manifest's `note`.
   For netcode, also diff `sodium/` and redo the `SODIUM.md` comparison against libsodium if it
   changed (the method is in `SODIUM.md`).
2. **Re-vendor.** Copy exactly the files listed in `vendor/PROVENANCE.toml` from a clean checkout
   of the new commit (`git show <commit>:<path>` is byte-exact). Add a file only if building the
   library or its unit tests needs it.
3. **Update the manifest.** For the upstream: `tag`, `commit` (full 40 hex), `commit_date`,
   `reviewed`, `note`. For every file: `git_blob` (`git rev-parse <commit>:<path>`) and `sha256`.
4. **Re-apply patches.** Regenerate any patch in `patches/` that no longer applies, update its
   `sha256`, and drop patches upstream has absorbed.
5. **Re-check licenses.** Diff the `LICENCE` files and every source header, rerun the scan in
   `LICENSES.md`, and update `NOTICE.md` (its license blocks must stay byte-identical to the
   vendored texts; `tests/build_vendor.rs` checks).
6. **Regenerate the symbol-prefix header** if the set of external symbols changed:
   `native/tools/gen-prefix-header` (see `BUILD.md`). `tests/build_symbols.rs` fails otherwise.
7. **Verify and rerun the suites:**

   ```sh
   native/tools/verify-vendor --fetch
   cargo test -p dream-net-native                      # hashes, symbols, upstream C tests
   DREAM_NET_NATIVE_TEST_SANITIZE=address,undefined \
     cargo test -p dream-net-native --test build_upstream   # upstream C tests under ASan+UBSan
   native/tools/lto-probe                              # cross-language LTO still inlines
   cargo test --workspace --all-targets --all-features # dream-net's unit, golden, fuzz smoke
   DREAM_NET_SOAK_FRAMES=200000 cargo test --release --test soak
   cd fuzz && RUSTC_BOOTSTRAP=1 cargo fuzz run <target> -s none -O -- -max_total_time=600
   cargo package -p dream-net-native && cargo package --list -p dream-net-native
   ```

   plus the wire interoperability suite once it exists (issue #11).

## License

The crate's own code is MIT OR Apache-2.0. The vendored C is BSD-3-Clause (netcode, reliable)
and ISC (libsodium). See `NOTICE.md`.
