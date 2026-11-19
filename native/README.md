# dream-net's native C

The C half of [dream-net](https://github.com/DreamWeave-MP/dream-net): Más Bandwidth's C
[netcode](https://github.com/mas-bandwidth/netcode) and
[reliable](https://github.com/mas-bandwidth/reliable), vendored at pinned commits and compiled
by dream-net's `build.rs` with a verified Clang into one static archive
(`libdream_net_native.a`) whose symbols all carry the `dn_native_` prefix. This directory is not
a crate: it holds the C, its provenance and its tools, and ships inside the dream-net package.
The safe Rust bindings live in `src/native/` (`dream_net::native::{netcode, reliable}`, hidden
from the docs and not supported API), the only module of dream-net allowed to contain `unsafe`
code: the crate root is `deny(unsafe_code)`, every other module forbids it, and
`tests/unsafe_confinement.rs` checks both. Paths below are relative to this directory unless
they start with `src/`, `tests/` or `examples/`; commands run from the repository root.

| What | Where |
| --- | --- |
| Pinned upstream sources | `vendor/`, manifest `vendor/PROVENANCE.toml` |
| Local changes to upstream C | `patches/` (one: port-0 server public address) |
| Our C shim and the symbol-prefix header | `csrc/` |
| Toolchain, flags, LTO, sanitizers, platforms | `BUILD.md` |
| Licenses | the root `NOTICE.md` (required notices), `LICENSES.md` (per-file report) |
| The bundled libsodium audit | `SODIUM.md` |
| Our safe Rust bindings | `src/native/` (repository root) |
| Binding and build tests | `tests/native_*.rs` (repository root) |
| Vendor verification | `tools/verify-vendor`, `tests/native_build_vendor.rs` |

Pins (netcode 2026-11-19, reliable 2026-11-18):

| Upstream | Tag | Commit |
| --- | --- | --- |
| netcode | v1.5.0 | `776b82218c0eff98a4fea248269ecfe7b064e769` |
| reliable | v1.4.6 | `b6245763cedb04d297ced7f196d6a1caeb0da239` |
| libsodium (bundled in netcode) | crypto 1.0.21/1.0.22, support code 1.0.17 | via the netcode pin |

## Verifying the vendored tree

```sh
native/tools/verify-vendor              # offline: every SHA-256 against PROVENANCE.toml
native/tools/verify-vendor --fetch      # re-derive vendor/ from upstream at the pins + patches
native/tools/verify-vendor --upstream DIR   # same, from existing clones DIR/netcode, DIR/reliable
cargo test --test native_build_vendor   # the offline check, in Rust
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
   `LICENSES.md`, and update the root `NOTICE.md` (its license blocks must stay byte-identical
   to the vendored texts; `tests/native_build_vendor.rs` and `tools/check-native-licenses`
   check).
6. **Regenerate the symbol-prefix header** if the set of external symbols changed:
   `native/tools/gen-prefix-header` (see `BUILD.md`). `tests/native_build_symbols.rs` fails
   otherwise.
7. **Verify and rerun the suites:**

   ```sh
   native/tools/verify-vendor --fetch
   cargo test --workspace --all-targets --all-features # hashes, symbols, upstream C, bindings, all
   DREAM_NET_NATIVE_TEST_SANITIZE=address,undefined \
     cargo test --test native_build_upstream           # upstream C tests under ASan+UBSan
   native/tools/lto-probe                              # cross-language LTO still inlines
   DREAM_NET_SOAK_FRAMES=200000 cargo test --release --test soak
   cd fuzz && RUSTC_BOOTSTRAP=1 cargo fuzz run <target> -s none -O -- -max_total_time=600
   tools/check-native-licenses && cargo package --list   # licenses, notices, packaged files
   ```

## License

dream-net's own code here (the shim in `csrc/`, the tools, the manifest) is MIT OR Apache-2.0.
The vendored C is BSD-3-Clause (netcode, reliable) and ISC (libsodium), so the dream-net package
declares `(MIT OR Apache-2.0) AND BSD-3-Clause AND ISC`. See the root `NOTICE.md` and
`LICENSES.md`.
