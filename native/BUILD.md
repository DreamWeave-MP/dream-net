# Building dream-net-native

`build.rs` compiles the vendored C and our shim into one static archive with a compiler it has
verified to be Clang, archives it with LLVM's archiver, and renames every external symbol under
`dn_native_`. It is deterministic and offline: no downloads, no pkg-config, no CMake, no bindgen
or libclang. Everything below was checked on Linux x86_64 unless the platform matrix says
otherwise.

## Requirements

- **Clang >= 18** (Apple Clang >= 16), found as described below. 18 is the oldest major still
  shipped as a distribution default (Ubuntu 24.04) and supports every flag used; nothing older is
  tested. CI's MSRV job installs Clang 20 (rustc 1.88's LLVM), its test jobs Clang 23.
- **llvm-ar** of any recent release (required in LTO mode; see below).
- **LLD** (`ld.lld`, `ld64.lld` or `lld-link`) for the workspace's own links and for LTO mode.
- For LTO mode only: Clang and LLD of **the same LLVM major as rustc** (`rustc -vV`).

## Environment

| Variable | Effect |
| --- | --- |
| `DREAM_NET_NATIVE_CC` | The C compiler. Must be a single program (path or name on `PATH`). |
| `CC_<target>`, `CC_<target_with_underscores>`, `HOST_CC`/`TARGET_CC`, `CC` | Read as the `cc` crate reads them when `DREAM_NET_NATIVE_CC` is unset. Honoured, then verified: a `CC` naming GCC fails the build. |
| `DREAM_NET_NATIVE_AR`, then `AR_<target>`... `AR` | The archiver. Without them: `llvm-ar` next to the compiler (resolving symlinks), then on `PATH`, then `llvm-ar-<clang major>`. |
| `DREAM_NET_NATIVE_NM` | `llvm-nm` for `tests/build_symbols.rs`; default: next to the compiler, then `PATH`. |
| `DREAM_NET_NATIVE_LTO` | `off`, `thin` (`1`, `on`), `full` (`fat`). Unset: `thin` when `RUSTFLAGS` enable `-Clinker-plugin-lto`, else `off`. |
| `DREAM_NET_NATIVE_SANITIZE` | `address`, `undefined` or both: instruments the archive (see Sanitizers). |
| `DREAM_NET_NATIVE_TEST_SANITIZE` | Read at test time by `tests/build_upstream.rs`: also run the upstream C tests under these sanitizers. |
| `DREAM_NET_NATIVE_SKIP_SYMBOL_CHECK=1` | Lets `tests/build_symbols.rs` skip, saying so, when no `llvm-nm` exists. Otherwise it fails. |
| `CFLAGS`, `CFLAGS_<target>`, `CRATE_CC_NO_DEFAULTS` | Passed through by `cc`, then checked: fast-math flags, `-ffp-contract=on/fast`, `-w`, `-UNDEBUG`, `-DNETCODE_DEBUG`, `-DRELIABLE_DEBUG`, `-fvisibility=default`, and `-flto*` outside LTO mode fail the build. |

Every variable is declared with `cargo:rerun-if-env-changed`; `build.rs`, `csrc/` and `vendor/`
with `rerun-if-changed`. So are the ones `cc` and the compiler read by themselves, which `cc`
would declare if its cargo metadata were on: `CFLAGS` in all its forms, `CC_SHELL_ESCAPED_FLAGS`,
`CC_FORCE_DISABLE`, `CPATH`, `C_INCLUDE_PATH`, `COMPILER_PATH`, `SOURCE_DATE_EPOCH`,
`CCC_OVERRIDE_OPTIONS`, `CLANG_NO_DEFAULT_CONFIG`, MSVC's `INCLUDE`, `EXTERNAL_INCLUDE`, `CL`,
`_CL_`, `VCToolsInstallDir`, `VCINSTALLDIR`, and on Apple hosts `DEVELOPER_DIR`, `TOOLCHAINS`,
`SDKROOT`, the deployment-target variables and `RC_DEBUG_*`. (Before this, a changed `CFLAGS`
reused the cached archive and skipped the forbidden-flag check.) `PATH` is not tracked: after
switching toolchains on `PATH`, run `cargo clean -p dream-net-native`.

## Compiler verification

There is no silent fallback of any kind. `build.rs`:

1. picks the compiler as above, defaulting to `clang` (`clang-cl` on `*-windows-msvc`);
2. preprocesses a probe file with it and reads `__clang__`, `__clang_major__`,
   `__apple_build_version__`, `_MSC_VER`, `__GNUC__` and `__MINGW32__`;
3. fails if it is not Clang (naming what it found: GCC, MinGW GCC, MSVC `cl.exe`, unknown), if it
   cannot run, or if it is older than the minimum;
4. hands that exact path to the `cc` crate as the compiler and the verified archiver as the
   archiver, with `cc`'s rustflag inheritance off, and checks that `cc` resolved the same path,
   recognises it as Clang, and that the final command line (environment flags included) contains
   no forbidden flag.

Observed failures (Linux, this machine): `CC=gcc` and `DREAM_NET_NATIVE_CC=cc` both stop with
"... is GCC 16.2, not Clang"; a missing path, a GNU `ar` in LTO mode, `CFLAGS=-ffast-math`, an
LLVM-major mismatch in LTO mode (rustc 1.95 / LLVM 22 against Clang 23) and an unknown
`DREAM_NET_NATIVE_LTO` value each stop with their own message.

## Flags

Applied to every translation unit (gnu-style; wrapped in `/clang:` for clang-cl):

| Flag | Why |
| --- | --- |
| `-std=gnu99` (netcode, reliable, sodium), `-std=gnu11` (shim) | Upstream's CMake builds C99 with CMake's default GNU extensions; the shim may use `_Static_assert`. |
| `-ffp-contract=off -fno-fast-math` | Más Bandwidth's floor for its network libraries: no FMA contraction, no fast-math. Upstream's `test.cpp` canaries check it. |
| `-fno-strict-aliasing -fwrapv` | libsodium's own configure adds both; extended to netcode and reliable, whose byte-level serialisation is where aliasing or signed-overflow UB would bite. |
| `-fvisibility=hidden` | Nothing in the archive is exported from a shared object built on top of it (l3i, Jess). Hidden symbols still link within one image. |
| `-fstack-protector-strong` | Stack canaries on functions with arrays or address-taken locals (non-MSVC). |
| `-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2` | Checked libc string and memory calls, when optimising, on Unix, outside sanitizer builds. |
| `-ffile-prefix-map=<native dir>=/dream-net-native`, `...=<OUT_DIR>=/dream-net-native-out` | Reproducible `__FILE__` strings and debug info. |
| `-include csrc/dn_native_prefix.h` (`/FI` for clang-cl) | Symbol prefix, below. |
| `-Wall -Wextra` | Warnings on everywhere. netcode and reliable compile clean with Clang 23. |
| `-Wno-unknown-pragmas` (sodium only) | The one justified suppression: `#pragma GCC target("sse2")` in the `verify.c` section is GCC-only, guards code compiled only when `__SSE2__` is already defined, and is ignored by Clang. Upstream's CMake suppresses it too. |
| `-Werror` (shim only) | Our own C must stay warning-free. Vendored code is not `-Werror`: a future Clang's new warning must not break consumer builds; any new vendored warning is reviewed and either fixed upstream or suppressed individually here. CI (`.github/workflows/native.yml`) builds the archive with `CFLAGS=-Werror` in debug and release, so a vendored warning fails CI, not a consumer. Clean with Clang 23.1.2 on Linux x86_64. |
| `-fPIC`, `-ffunction-sections -fdata-sections`, `-O`/`-g`, `--target` | The `cc` crate's defaults, from Cargo's `OPT_LEVEL`, `DEBUG` and `TARGET` (debug and release both build). |

No fast-math, no `-march`: libsodium picks SSSE3/AVX2 ChaCha20 and SSE2 Poly1305 at run time
through per-function target attributes (`SODIUM.md`), so the archive runs on any x86-64 and the
dispatch is untouched by these flags.

### Defines

Every define that changes behaviour, chosen deliberately:

| Define | Value | Effect |
| --- | --- | --- |
| `NDEBUG` | set | `netcode_assert` and libsodium's `assert()` compile to nothing. |
| `NETCODE_RELEASE`, `RELIABLE_RELEASE` | set | `reliable_assert` compiles to nothing. Outside test code neither name changes anything else (checked by grep at the pins). |
| `NETCODE_ENABLE_LOGGING`, `RELIABLE_ENABLE_LOGGING` | 1 | Upstream default, stated. Logging is compiled in but silent (below). |
| `NETCODE_ENABLE_TESTS`, `RELIABLE_ENABLE_TESTS` | 0 | Test code never enters the archive. |
| `NETCODE_ENABLE_NONCE_AUDIT`, `NETCODE_CRYPTO_LOGS` | 0 | Test instrumentation and libsodium dispatch printfs, off. |
| `NETCODE_PACKET_TAGGING` | upstream default | 1 except MinGW; it only takes effect after `netcode_enable_packet_tagging()`. |
| `NETCODE_X64`, `NETCODE_AVX`, `NETCODE_AVX2` | unset | Run-time CPU dispatch, as upstream. |
| `NATIVE_LITTLE_ENDIAN`, `HAVE_PTHREAD`, `HAVE_ATOMIC_OPS`, other `HAVE_*` | unset | netcode's validated configuration of its amalgamation: portable byte loads, volatile `sodium_memzero`, no lock in `sodium_init` outside Windows (see Initialisation). |
| `SODIUM_STATIC` | unset | Only meaningful for MSVC DLL imports of a real libsodium; netcode.c sets it itself under `_MSC_VER`. |

## Assertions

**Policy (director decision): assertions are compiled out in every Cargo profile, debug and test
included, and the Rust wrappers validate every argument an assertion guarded.** Upstream's debug
assertions print to stdout and trap (`netcode_assert`'s default handler) or call `exit(1)` after
any handler returns (`reliable_assert`'s macro), and neither may ever happen inside a host.

`dn_native_hooks_install()` (in `csrc/`) still installs an abort-after-one-stderr-line handler for
both libraries, so a differently configured build fails stop rather than continuing into a broken
invariant or exiting.

Classification of the asserts in production code at the pins (netcode.c: 332 sites, reliable.c:
58, sodium.c: 9 `assert()`), by reading every function that contains one:

- **API preconditions** (null pointers, `client_index` in range, `max_clients` in 1..=256,
  `packet_bytes` in 1..=`NETCODE_MAX_PACKET_SIZE`, `server->running`, loopback state,
  `num_server_addresses` in 1..=32, `max_packet_size > 0`, reliable `packet_bytes > 0`, config
  sanity): reachable only through the public C API. **The binding agents must check each of these
  in Rust before the call** of each wrapped function; the sites are listed by
  `grep -n 'netcode_assert(\|reliable_assert(' vendor/*/*.c`, and every one in a public entry
  point is a precondition of that kind.
- **Internal invariants** established by an explicit check just before (e.g. a full server is
  answered with a denied packet before `netcode_server_find_free_client_index`'s result is asserted
  `!= -1`; `reliable_endpoint_receive_packet` rejects a short header before asserting
  `packet_header_bytes <= packet_bytes`; fixed-size reads asserting their own lengths). Network
  input reaches the check, not the assert.
- **OS-reachable, not attacker-controllable:** `netcode_socket_receive_packet` asserts if
  `getsockname`/`recvfrom` returns an address family it cannot convert, then returns 0 (packet
  dropped) anyway.

No assertion was found whose condition remote input controls and whose failure is the only guard
against an out-of-bounds access. That is an inspection result, not a proof: issue #12's fuzzing
(netcode's `fuzz_read_packet`/`fuzz_connect_token` corpus and reliable's) should run against the
archive's configuration to confirm it.

## Logging

Both libraries default to log level NONE, but their default printf hook is `printf` to stdout.
`dn_native_hooks_install()` sets both levels to NONE and both hooks to a function that discards
everything, so nothing reaches stdout or stderr even if a level is raised without a capturing
hook. Rust cannot define a C variadic function on stable, so a capturing hook must be a C shim
(`vsnprintf` into a bounded buffer the Rust side polls); none exists yet. The only other stdio
output in production code is behind `NETCODE_ENABLE_NONCE_AUDIT` and `NETCODE_CRYPTO_LOGS`, both 0.
`sodium_misuse()` calls `abort()`: reached only on an RNG failure or an AEAD length beyond
2^38 bytes, neither reachable from packets of at most 1300 bytes.

## Initialisation

`netcode_init` reference-counts with a plain `int` and calls `sodium_init`, whose lock is a no-op
outside Windows in this amalgamation (`SODIUM.md`). **The netcode binding must call
`dn_native_hooks_install()` then `netcode_init()` exactly once per process behind
`std::sync::Once`, and never call `netcode_term`.** `netcode_term` on the last reference runs
`WSACleanup` on Windows and resets the flag, racing any other thread still in netcode; there is no
benefit to it in a process that keeps networking. `reliable_init`/`reliable_term` are no-ops at
this pin but belong in the same `Once`.

## Symbol prefix

Every external symbol the archive defines is `dn_native_<name>`. `csrc/dn_native_prefix.h` holds
one `#define name dn_native_name` per external symbol of netcode, reliable and libsodium (315 at
the pins) and is force-included into every translation unit, so definitions and references are
renamed alike. It is generated by `tools/gen-prefix-header` (compile the three TUs, list external
definitions with `llvm-nm`, add the platform-only names in its `EXTRA` list) and checked in;
`tools/gen-prefix-header --check` reports staleness.

`tests/build_symbols.rs` runs `llvm-nm --defined-only --extern-only` over the built archive and
fails on any external symbol without the prefix (allowing only compiler-generated COFF COMDAT
names on Windows and ASan's ODR indicators in ASan builds), and checks that the main entry points
exist under their prefixed names and not under their plain ones. Linux: 313 external symbols, all
prefixed.

**Convention for the binding agents.** Declare the C function under its upstream name and link
the prefixed symbol:

```rust
unsafe extern "C" {
    #[link_name = "dn_native_netcode_init"]
    pub(crate) fn netcode_init() -> c_int;
}
```

Shim functions in `csrc/` are named `dn_native_*` directly and need no `link_name`. To add shim
C, drop a `.c` file in `csrc/` (top level only; `csrc/test/` holds test-only programs): build.rs
compiles every top-level `csrc/*.c` with `-Werror`, the vendored include directories, and the
prefix header, without any build.rs change. Prefer `_Static_assert` there for any struct layout
Rust relies on (shared decision 6).

## Linker

A library's build script cannot choose the linker of a downstream binary. What is enforced and
what is only documented:

| | Enforced | Evidence |
| --- | --- | --- |
| Workspace's own Linux links use LLD | `.cargo/config.toml` passes `-Clink-arg=-fuse-ld=lld` on Linux GNU targets (rustc >= 1.90 already defaults to rust-lld there; 1.88 does not) | `tests/build_lld.rs` reads its own ELF `.comment`: `Linker: LLD 23.1.5` on stable and `LLD` on 1.88. Without the config, 1.88 links with GNU ld and the test fails (checked). |
| LTO mode has a usable LLD | build.rs finds `ld.lld`/`ld64.lld`/`lld-link` of rustc's LLVM major or fails | negative checks above |
| Downstream binaries link with LLD | **not enforceable**: documented | in non-LTO mode the archive holds ordinary ELF/Mach-O/COFF objects that any conforming linker accepts (a GNU ld link of the test binary works) |

`RUSTFLAGS` in the environment replace the config's rustflags; add `-Clink-arg=-fuse-ld=lld`
yourself then. Downstream consumers wanting LLD set the same flag (or
`-Clinker=clang -Clink-arg=-fuse-ld=lld`) in their own config.

## Cross-language LTO

Opt-in. Default builds produce ordinary objects. LTO mode (`DREAM_NET_NATIVE_LTO=thin|full`, or
`thin` automatically when `RUSTFLAGS` contain `-Clinker-plugin-lto`) emits LLVM bitcode
(`-flto=thin`/`-flto=full`), requires LLVM's archiver, Clang and LLD of rustc's LLVM major, and
refuses Apple Clang (its version cannot be matched to rustc's LLVM).

Evidence, from `tools/lto-probe` (also `cargo test -p dream-net-native --test build_lto --
--ignored --nocapture`), on Linux x86_64, rustc 1.100.0 (LLVM 23.1.5), Clang 23.1.2, LLD 23.1.2:

| Build | Archive members | `probe_caller` (Rust) |
| --- | --- | --- |
| C off, Rust `lto = "fat"` (the workspace's release profile) | ELF | `callq *...(%rip)` through the GOT |
| C off, Rust `lto = off` | ELF | `callq *...(%rip)` |
| C thin, `-Clinker-plugin-lto -Clinker=clang -fuse-ld=lld`, Rust `lto = "fat"` | LLVM bitcode | `callq <dn_native_probe_mix>`: resolved, **not inlined** |
| C thin, linker-plugin LTO, Rust `lto = off` | LLVM bitcode | `xorl $0x9e3779b9,%edi; imull $0x85ebca6b,%edi,%eax; incl; retq`: **inlined** |
| C full (`DREAM_NET_NATIVE_LTO=full`), linker-plugin LTO, Rust `lto = "fat"` | LLVM bitcode | the same inlined body |

Rust's fat LTO hands LLD one module for its regular (full) LTO partition, while ThinLTO C
bitcode is optimised in separate backends, so nothing crosses; full-LTO C joins the same
partition. **To inline across the boundary with the workspace's `lto = "fat"`, set
`DREAM_NET_NATIVE_LTO=full` alongside `-Clinker-plugin-lto`.** All five configurations link and
run. Only this one target and toolchain set was verified.

## Sanitizers

- **Upstream C tests, any toolchain:** `DREAM_NET_NATIVE_TEST_SANITIZE=address,undefined cargo
  test -p dream-net-native --test build_upstream` additionally builds and runs netcode's and
  reliable's unit tests and the port-0 test with `-fsanitize=address,undefined
  -fno-sanitize-recover=all`, linked by Clang with its runtimes. Result on Linux x86_64 (Clang
  23.1.2): all three pass, no reports. Upstream exempts the libsodium object from UBSan's alignment
  check; we do not, and it is clean on this x86-64 (SSSE3/AVX2 paths selected).
- **The archive, with Rust:** `DREAM_NET_NATIVE_SANITIZE=address,undefined RUSTFLAGS="-Zsanitizer=address
  -Clink-arg=-fuse-ld=lld" RUSTDOCFLAGS=-Zsanitizer=address cargo +nightly test --workspace
  --target x86_64-unknown-linux-gnu`. ASan instruments the archive and links against Rust's ASan
  runtime (build.rs refuses `address` without `-Zsanitizer=address` in the rustflags); UBSan uses
  `-fsanitize-trap=undefined`, so it needs no runtime and also works on stable. **Doctests need
  `RUSTDOCFLAGS` too:** rustdoc does not read `RUSTFLAGS`, so without it every doctest fails to
  link (`undefined symbol: __asan_report_store8` and friends). The Rust tests of both crates call
  into the C through the netcode and reliable bindings, so this exercises the real code. Result
  on nightly 1.101 / LLVM 23.1.5 with Clang 23.1.2: every test of both crates and both doctest
  suites pass, no reports (about two minutes). CI runs it (`native.yml`, `sanitizers`).

## Upstream tests

`tests/build_upstream.rs` compiles, at test time and into `OUT_DIR`, netcode's `test.cpp` (which
includes `netcode.c` with `NETCODE_ENABLE_TESTS`) with libsodium, and reliable's `test.cpp` with
`reliable.c` under `RELIABLE_ENABLE_TESTS`, using the archive's own flags (so `NDEBUG` and the
prefix header included), links them with Clang (and LLD), and runs them. Test code never enters
the archive. At the pins: netcode 65 test functions, reliable 38, both `*** ALL TESTS PASSED ***`.
netcode's real-socket functional tests stay opt-in as upstream (`NETCODE_TEST_FUNCTIONAL`). The
same test builds `csrc/test/port_zero.c`, which proves `patches/0001` over loopback sockets (it
fails against unpatched netcode: the client stays in state 1 until it gives up).

## Reproducibility

Two clean builds in different target directories produce byte-identical archives, debug and
release (SHA-256 compared). `-ffile-prefix-map` removes the checkout and `OUT_DIR` paths, object
names are relative-path hashes, members are sorted, and `llvm-ar rcsD` zeroes timestamps, owners
and modes. The debug archive still names the Clang resource directory (system header paths in
DWARF), so it is reproducible per toolchain installation, not across them. Member names are
hashes that the `cc` crate computes and changed at `cc` 1.9.0; the objects themselves are
byte-identical for every `cc` from 1.2.8 (the floor) to 1.11.2 (the lockfile's). The workspace's
`tools/check-reproducible` checks the archive from two checkout paths and two target
directories, debug and release, and that `cargo package` gives identical tarballs twice.

Offline: build.rs runs only the compiler, archiver, `rustc -vV` and `--version` probes, and
nothing downloads. The workspace's `tools/check-offline-consumer` proves it: both packaged
tarballs build and pass their tests, and a fresh consumer builds and runs, in a network
namespace with only loopback, an empty `CARGO_HOME` and `--frozen`.

## Platform matrix

"Executed" means run on that platform; "reasoned" means read from code, package metadata or
tool documentation and not run. Nothing below macOS or Windows has been executed: CI's first run
of `.github/workflows/ci.yml` (StroggForge v55's `test` matrix: `macos-latest`, `macos-15-intel`,
`ubuntu-22.04`, `windows-2025-vs2026`) is their first test.

| Platform | Status |
| --- | --- |
| Linux x86_64 (glibc), Clang 23.1.2, LLD 23.1.2, rustc 1.100 / 1.88 / nightly 1.101 | **Executed**: build (debug, release), all tests, upstream C tests under ASan+UBSan, both crates under ASan+UBSan, LTO probe, `-Werror` over the vendored C, reproducibility, MSRV (1.88 links through LLD), packaged tarballs and a consumer offline in a network namespace, every compiler-gate refusal. |
| Linux, missing LLVM binutils | **Executed** (PATH stripped, Clang behind a wrapper): no `llvm-ar` stops with "llvm-ar was not found ... set DREAM_NET_NATIVE_AR"; a GNU `ar` named explicitly works outside LTO and is refused in LTO mode; a missing compiler stops with "was not found". |
| Linux aarch64 | Untested. Expected to work (portable libsodium paths; `test.cpp`'s FMA canaries have teeth there). |
| macOS arm64, LLVM.org Clang (CI `macos-latest`) | Untested. Reasoned: StroggForge's `setup-llvm.sh` unpacks LLVM's own release, which ships `llvm-ar`, `llvm-nm` and `ld64.lld` next to `clang`, and sets `SDKROOT`; build.rs finds them next to the compiler. Archive is written with `--format=darwin` and linked by Apple's ld64 through rustc. The symbol and upstream tests strip Mach-O's leading underscore; `tests/build_lld.rs` is ignored (no linker marker in Mach-O). |
| macOS x86_64, conda-forge Clang (CI `macos-15-intel`) | Untested. Reasoned from conda-forge's metadata: `clang` depends on `clang_impl_osx-64`, which depends on `llvm-tools`, so `llvm-ar` should sit in the same `bin/` as `clang` (an earlier note here expected it missing). If it is missing after all, the build stops asking for `DREAM_NET_NATIVE_AR`, and Apple's `ar` is refused up front (it takes neither `D` nor `--format=darwin`). |
| macOS, Apple Clang + ld64 | Accepted as a compiler (>= 16) in non-LTO mode, untested. Unless an `llvm-ar` is on `PATH` (Xcode's toolchain is not expected to provide one; unverified), it also needs LLVM's (`DREAM_NET_NATIVE_AR`). Refused in LTO mode. |
| Windows MSVC, clang-cl + lld-link (CI `windows-2025-vs2026`) | Untested; written but unverified: cl-mode probe (`/EP`), flags passed through `/clang:`, `/FI` force-include, archive via `llvm-ar --format=coff`, links `ws2_32 iphlpapi advapi32 qwave`. Reasoned: `setup-llvm.sh` unpacks LLVM's Windows release (`clang-cl`, `llvm-ar`, `lld-link`, `llvm-nm` together) and pins `CARGO_BUILD_TARGET`; clang-cl finds the MSVC and SDK headers itself. A non-LLVM archiver is refused. `tests/build_upstream.rs` is ignored there (its build commands are gnu-style); the symbol test allows COFF COMDAT names. Expected first-run risk: a Windows-only warning in our shim under `-WX`. |
| Windows GNU (MinGW) with Clang | Untested. MinGW GCC is refused. |
| Cross-compiling to Apple from Linux | Unsupported: without an Apple SDK, Clang falls back to the host's headers and the C fails to compile. |
| Anything with GCC or MSVC `cl.exe` | Refused by design (executed for GCC: `CC`, `CC_<target>` and `DREAM_NET_NATIVE_CC`). |
