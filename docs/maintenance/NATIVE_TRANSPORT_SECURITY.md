# Native transport security review

Issue [#12](https://github.com/DreamWeave-MP/dream-net/issues/12) of the native transport
campaign ([NATIVE_TRANSPORT_CAMPAIGN.md](NATIVE_TRANSPORT_CAMPAIGN.md)): an adversarial review of
the C trust boundary that `dream-net-native` introduced (vendored netcode v1.4.10 plus patch
0001, reliable v1.4.6, the bundled libsodium subset, the C shim and the `unsafe` Rust around
them), with fuzzing under sanitizers and permanent regressions. It builds on the audit
([NATIVE_TRANSPORT_AUDIT.md](NATIVE_TRANSPORT_AUDIT.md), section 6, findings S1 to S13).

This is a public document. It describes defects by class and code path, never as a recipe.

## How to read this

| Status | Meaning |
| --- | --- |
| CONFIRMED, fixed | Reproduced, fixed in this repository, a regression test fails without the fix |
| CONFIRMED, accepted | Reproduced or proven by reading; kept, with the rationale and the guidance given |
| HYPOTHESIS | Plausible from the code, not reproduced |
| NOT AFFECTED | Checked (by test, fuzzing or reading, as stated) and not a defect |

Severity is for a dream-net host on the public internet: High (remote compromise of
confidentiality or integrity, or memory unsafety), Medium (remote denial of service, or a
confidentiality loss that needs a host misconfiguration), Low (needs the attacker to hold a
valid token, or costs only the attacker).

**Release-blocking disposition, in short: nothing found here blocks the release on its own,
provided the director accepts the residuals in "Residual risks" (they are upstream netcode's
documented design) and handles the withheld finding (W1) before release.**

## 1. Findings

| ID | Finding | Status | Severity | Pinned by | Blocks release |
| --- | --- | --- | --- | --- | --- |
| F1 | A `packet_budget` below the largest packet header (20 bytes) passed `TransportConfig::validate` | CONFIRMED, fixed | Low | `tests/security.rs` | No (fixed) |
| F2 | Connect-token reuse after a session (audit S1) | NOT AFFECTED on C 1.4.10 | (was High) | `tests/lifecycle_security.rs`, `tests/security_netcode.rs::aead_nonces_never_repeat_across_sessions_attempts_and_restarts`, server fuzz oracle 1 | No |
| F3 | Restart replay within the maximum token lifetime (audit S2) | NOT AFFECTED (start floor) | (was High) | same, and `a_restart_refuses_tokens_from_before_it` | No |
| F4 | Restart replay of tokens living longer than the maximum, or never expiring: AEAD nonce reuse after a restart on the same key | CONFIRMED, accepted (documented upstream and in dream-net's `Server` docs) | Medium | `tests/security_netcode.rs::tokens_beyond_the_maximum_lifetime_survive_a_restart_and_repeat_nonces` | No, if accepted (section 4) |
| F5 | A token listing several servers that share a key opens one session per listed server under the same keys (audit S2, related hypothesis) | CONFIRMED, accepted | Low | `tests/security_netcode.rs::a_multi_address_token_opens_one_session_per_listed_server_under_the_same_keys` | No, if accepted |
| F6 | Token-history exhaustion (audit S10) | CONFIRMED, accepted, bounded | Low | `tests/security_netcode.rs::a_full_token_history_refuses_new_tokens_until_entries_expire` | No |
| F7 | A server's receive loop has no per-update bound: a sustained flood faster than it can drain keeps one `update` running | CONFIRMED by reading and measurement, accepted (upstream design) | Medium | measured (section 5); no test can bound it | No, if accepted |
| F8 | Zero-length datagrams stall the receive loop (audit S3) | NOT AFFECTED on C 1.4.10 | (was Medium) | `tests/lifecycle_security.rs::zero_length_datagrams_do_not_stall_a_server_or_a_client` | No |
| F9 | A server disconnect sends a multi-address client to the next server (audit S4) | NOT AFFECTED on C 1.4.10 | (was Low) | `a_server_disconnect_does_not_send_the_client_to_the_next_address`, client fuzz oracle 4 | No |
| F10 | An upstream assert as the only guard on remote input (audit S8) | NOT AFFECTED: 0 trips | (would be High) | live-assert fuzzing (section 3), `native/tests/fuzz_native.rs` | No |
| F11 | Fragment reassembly memory (audit S9) | CONFIRMED, accepted, bounded and reported | Low | `tests/alloc.rs::a_fragment_storm_fills_reassembly_to_the_reported_bound_and_no_further`, reliable fuzz oracle 3 | No |
| F12 | Handshake reflection or amplification | NOT AFFECTED: 333 bytes out per 1078 in, to the token's first address only | (would be Medium) | `the_handshake_answers_less_than_it_receives_and_never_a_stranger` | No |
| F13 | Token replay to an unlisted server, after expiry, with authenticated fields altered | NOT AFFECTED | (would be High) | `a_token_is_refused_elsewhere_and_with_any_authenticated_field_altered`, `tests/adversarial.rs::tokens_for_another_protocol_key_or_time_are_refused` | No |
| F14 | Replay window edges, sequence reuse, the reserved sequence `u64::MAX` | NOT AFFECTED | (would be High) | `native/tests/fuzz_native.rs::the_server_replay_window_holds_at_its_edges`, server and client fuzz oracles 2 and 3, `tests/adversarial.rs::forged_packets_from_an_authenticated_address_do_not_disturb_the_session` | No |
| F15 | Authenticated malformed packets (every type nibble, every decrypted size, non-minimal sequence lengths) | NOT AFFECTED | (would be High) | server and client harnesses (op 7), 10 minutes each per configuration | No |
| F16 | netcode's process-global create-error codes race when servers or clients are created on several threads | CONFIRMED in C (ThreadSanitizer), NOT AFFECTED in dream-net (creates are serialised) | (would be Low) | TSan probe (section 3); `create_lock` in `native/src/netcode.rs` | No |
| W1 | One further finding in the vendored netcode, reported privately to the director for upstream's private channel (netcode `SECURITY.md`) | Withheld until coordinated disclosure | see private report | not in the repository | **Director's decision** |

### F1. A packet budget below the header (CONFIRMED, fixed)

`Core::write_selected` (`src/connection.rs`) asserts in debug builds that every packet stays
within `packet_budget`, and admission (`Fill::admit`) counts the header, but `validate`
accepted any budget from 1. The header that carries the handshake is up to 20 bytes (2 kind
bits, the hello flag, the 144-bit hello, a 7-bit section count for 64 channels). With a smaller
budget the header-only hello packet was already over it: debug builds hit the assertion; release
builds sent packets over the budget, and when `max_packet_size` was also below the header the
reliable endpoint refused them as too large, so no handshake could complete. dream-net 1.1.1 had
the same gap. `validate` now refuses budgets below `wire::MAX_HEADER_BYTES` (20) with
`"packet_budget must be in [20, max_packet_size]"`. With any accepted budget every packet stays
within it, except the deliberate lone oversize event, which is bounded by `max_packet_size`.
Fixed in `FIX: Refuse a packet budget smaller than the largest packet header`; the test runs a
64-channel schema at exactly the minimum in a debug build.

### F2, F3, F8, F9. The audit's fixed items

C 1.4.10 consumes a token on the session it admits, refuses tokens at or below the start floor,
skips zero-length datagrams, and leaves a client disconnected after a server disconnect. The
earlier campaign tests pin these through dream-net's API. This review adds a byte-level nonce
ledger over a session, an attempt with the used token, a restart, and a used and an unused
pre-restart token afterwards: no (key, nonce) pair encrypts two datagrams and no ciphertext
recurs. The server fuzz harness checks the same property (oracle 1) over every script it runs,
including in-process restarts, and the client harness checks that a disconnected client never
moves on (oracle 4).

### F4. Long-lived tokens across a restart (CONFIRMED, accepted)

The start floor is `start second + max_connect_token_lifetime`. A token living `L > M` seconds
passes the floor of a restart that happens less than `L - M` seconds after it was minted, and a
token that never expires (`expire_seconds < 0`) passes every floor. If such a token was used
before a restart on the same private key, the restarted server admits it again, and the new
session encrypts from sequence 0 under the same keys as the first: the regression test sees the
first sequences of both directions repeat with different ciphertext. The global packets
(challenge, denied) collide the same way after an in-process restart, which the server fuzz
harness found within seconds when it was not told to expect it.

This is upstream's documented design (`netcode.h`, on `netcode_generate_connect_token`: a token
with a negative `expire_seconds` "bypasses the server restart expiry floor"), and dream-net's
`Server::new`/`with_max_token_lifetime` docs state the rule for hosts: a host that keeps its key
across starts must mint tokens no longer-lived than the maximum it gives the server; a host that
generates a fresh key per start (as l3i does) is not exposed. Accepted on that basis. Options for
the director, none required by this review: refuse negative `expire_seconds` in dream-net's
re-exported `generate_connect_token`, or document l3i's 300-second default lifetime against a
kept key.

### F5. Multi-address tokens (CONFIRMED, accepted)

Single use is per server: each server keeps its own token history. Two servers that share a
private key and both appear in one token each admit it once, so a holder gets two sessions
under the same session keys, each counting its per-client sequence from 0 (the test connects the
first session, then the same token from a second client, which the first server ignores and the
second admits). Separately, the global packets of two servers start from the same sequence, so
a client that gives up on the first listed server and is challenged by the second can see the
same nonce under its key from both. Exposure is limited to the token holder's own traffic, which
it can decrypt anyway; a passive observer gains relations between plaintexts sent to that client.
dream-net and l3i mint single-address tokens by default; this is reachable only by listing
several addresses in `generate_connect_token`. Guidance: list several addresses only for servers
that do not share a private key, or accept the exposure for fail-over.

### F6. Token-history exhaustion (CONFIRMED, accepted, bounded)

The history holds `NETCODE_MAX_CLIENTS * 8` = 2048 entries; an entry lives until its token
expires; a full history refuses new tokens instead of evicting (eviction is what would let a
used token back in). The test fills it from one address with 2048 distinct valid tokens (each
answered by one challenge), after which a client with a fresh token is ignored and times out.
What an attacker can and cannot do: without valid tokens, nothing (a request that does not
decrypt never creates an entry, section 5); with one token, one entry (a pending entry admits
only the address that created it, and a used one admits nobody); with 2048 unexpired tokens from
the backend, a lockout of new tokens lasting at most one token lifetime. Guidance: the backend
that mints tokens rate-limits issuance per account; keep token lifetimes short.

### F7. Unbounded receive loop (CONFIRMED, accepted)

`netcode_server_receive_packets` loops until the socket is empty (`while ( 1 )`), so `update`
returns only when the attacker stops or the server outpaces the attacker. Measured per-datagram
costs on this machine (`-O2`, one core, loaded): a well-formed request whose token does not
authenticate 1.7 µs (one XChaCha20-Poly1305 decryption of 1 KiB), an encrypted-type datagram
from an address with no session 0.4 µs, a valid request replayed from new addresses 5.8 µs (the
decryption plus the constant-time scan of the 2048-entry history). A flood above roughly 500,000
datagrams per second per core (about 4 Gbit/s of requests) keeps one `update` from returning;
below that the loop drains and returns. This is the same class as the audit's S3 (fixed for
zero-length datagrams), at a far higher cost to the attacker. Accepted as upstream design;
guidance: rate-limit UDP at the host or network edge. A per-update cap would need a vendored
patch, which is the director's decision (it would delay, not drop, legitimate traffic).

### F10. Asserts as the only guard (NOT AFFECTED)

Two earlier agents concluded by reading that no `netcode_assert` or `reliable_assert` is the only
guard on remote input. This review checked it mechanically: every harness, ours and upstream's,
was built twice, once with the production defines and once with every assert compiled in and
fatal (an installed handler that aborts, or upstream's own trap), and both builds were fuzzed
with the same budgets under ASan and UBSan (section 3). **Assert trips across every live-assert
run: 0.** No input the fuzzers found reached a failing assert, so no production behaviour rests
on an assert for any input they reached.

### F11. Reassembly memory (CONFIRMED, accepted, bounded)

One authenticated datagram of at most 1200 bytes that names a new fragmented sequence makes the
receiver allocate one reassembly buffer of 33,241 bytes (the hook's 16-byte header, 9, 28 x 1186,
and 8), about 28 bytes held per byte received, until the slot is superseded or completed. Sixteen
slots (dream-net's default `fragment_reassembly_buffer_size`) bound it at 531,856 bytes per
connection, which `MemoryUsage::reliable` reports (581,185 bytes with the 49,329 bytes the
endpoint holds from creation). The test fills every slot with never-completed sets and checks
the peak never exceeds the bound; the reliable fuzz harness checks the bound after every
datagram it delivers, mutated or not. Reliable never sees an unauthenticated datagram: netcode
drops it first.

### F12 to F15. Handshake, token replay, replay window, malformed packets (NOT AFFECTED)

- A valid connection request (1078 bytes) is answered by one challenge (333 bytes), and only to
  the address that first presented the token: reflection through a spoofed source gets nothing,
  and so does a request whose token does not decrypt.
- A token is refused by a server it does not name (same key and protocol), and refused with any
  server-authenticated public field altered: version, protocol id, expire timestamp, nonce, the
  encrypted private part or its tag, either session key. The create timestamp, timeout and
  address list are client-side only.
- The replay window, through the real server path with real keys: each sequence is delivered at
  most once; the oldest sequence inside the 256-wide window is accepted and the next older one
  refused; `u64::MAX` is refused (netcode reserves it); a jump to the far end of the sequence
  space is accepted and leaves everything older refused, which costs only the peer that jumped.
- Authenticated packets of every type nibble (including the 9 undefined ones), every decrypted
  size from 0 to 1263 bytes, and 1 to 8 sequence bytes are refused or handled without fault in
  both harnesses.

### F16. The create-error globals (CONFIRMED in C, NOT AFFECTED in dream-net)

netcode reports why a create failed through process-global `server_create_error` and
`client_create_error`, written by every create. ThreadSanitizer reports the race when servers
are created on several threads at once (probe below). The Rust binding takes one process-wide
lock around every create and reads the code under it (`create_lock`, `native/src/netcode.rs`);
with creates serialised the same way the probe is clean.

## 2. Unsafe and shim audit

Every `unsafe` block in `native/src/` and every line of `native/csrc/dn_native_*.c` was read
against the C it calls. Line numbers are at this review's commit.

| # | Area | Result |
| --- | --- | --- |
| A1 | Ownership and exactly-once destruction: `Server` (`netcode/server.rs`, `Drop`), `Client` (`netcode/client.rs`, `Drop`), `Endpoint` (`reliable/endpoint.rs`, `Drop`) | NOT AFFECTED. Each handle is `NonNull`, destroyed only in `Drop`, never copied out. The shim's `dn_native_nc_server_destroy` (`dn_native_netcode.c:419-428`) destroys the netcode server (whose stop fires the callback) before zeroing and freeing the slot storage. `Endpoint::drop` destroys the C endpoint (which frees through the hooks, still pointing at the live context) before freeing the context. |
| A2 | Callback context lifetime during stop, destroy, drop and after a panic | NOT AFFECTED. The netcode callback lands in C (`dn_native_netcode.c:342-368`) and writes only the handle's fixed slots. The reliable `Context` is boxed for the endpoint's life; a `Call` points at a `Frame` on the caller's stack and is cleared by a drop guard after the C call (`endpoint.rs:356-372`), so a callback outside a call reaches nothing (unit test `callbacks_outside_a_call_are_inert`). Closure panics are caught in the trampoline and resumed after C returns; `extern "C"` hooks abort rather than unwind. |
| A3 | Aliasing of pointers C receives | NOT AFFECTED. `connect_token.as_ptr().cast_mut()`: `netcode_client_connect` only reads the token (`netcode_read_connect_token` copies out; no write to the buffer anywhere in its path). `reliable_endpoint_send_packet` reads its input only as a `memcpy` source; `reliable_endpoint_receive_packet` only reads it and keeps no pointer. The process callback's slice points into the caller's datagram or the reassembly buffer, both unwritten while it runs. |
| A4 | Layout of every struct crossing the boundary | NOT AFFECTED. `dn_native_nc_address_t`, `dn_native_nc_slot_events_t` and `dn_native_reliable_params` are pinned field by field by `_Static_assert` in C, `const` assertions in Rust, and a run-time comparison in unit tests; the counter array by its 11 indices and size. Rust touches no other C struct. |
| A5 | Integer conversions | NOT AFFECTED. Every `usize` to `int` goes through `try_from` after a range check (payloads 1..=1200, slots < 256, `max_clients` 1..=256, config fields by `Config::validate`); sizes C hands back go through `usize::try_from` and a range check before any slice is made (`copy_payload`, `borrowed`, `acks`). |
| A6 | `Endpoint: Send + Sync` | NOT AFFECTED. Every `&self` method calls a C getter that only loads fields (checked in `reliable.c`), and every write happens in a `&mut self` call. The only globals reliable touches are the log level and hooks, written once inside `ensure_init`. ThreadSanitizer (section 3) runs three threads reading one endpoint's getters concurrently, and endpoints used on other threads, with no report. |
| A7 | Global state | NOT AFFECTED. `ensure_init` runs the hooks and both initialisers once in a `OnceLock`, before any other call (every constructor and `generate_key`/`generate_connect_token` call it first). The other mutable globals in the archive's code are the create-error codes (F16, locked), the log level and hooks (written once), and `netcode_time`'s lazy start (never called by the binding). |
| A8 | Allocation failure inside C | NOT AFFECTED. netcode uses its default `malloc` hooks and checks every result on the receive paths (`netcode_read_packet`, payload packets, server and client create). reliable checks every allocation, including reassembly on receive; the Rust hook returns null for a size that cannot be a `Layout` or when the global allocator fails, never aborts (unit test `allocator_hooks_count_align_and_refuse`). |
| A9 | Re-entrancy | NOT AFFECTED. No Rust runs inside a netcode call. A reliable callback cannot reach its own endpoint (borrowed mutably); reaching another endpoint is allowed by reliable. |
| A10 | The assert hook | NOT AFFECTED. `dn_native_hooks_install` installs an abort-after-one-line handler; it only matters in a build with asserts on, which build.rs refuses. |

No defect was found in the `unsafe` code or the shim, so there is no `FIX:` commit for them.

## 3. Fuzzing and sanitizer evidence

All runs on Linux x86_64 (16 cores, shared), Clang 23.1.2 with libFuzzer, ASan and UBSan,
`-fno-sanitize-recover=all`. "prod" is the archive's defines (`NDEBUG`, `NETCODE_RELEASE`,
`RELIABLE_RELEASE`: every assert compiled out); "live" compiles every assert in and makes it
fatal. Upstream targets were built from upstream's harness sources at the pinned tags against
**our** vendored sources (netcode v1.4.10 plus patch 0001, reliable v1.4.6).

Command (both configurations, 6 jobs at once):

```
native/tools/fuzz-native --seconds 600 --jobs 6 --upstream <dir with netcode and reliable clones>
```

| Target | Entry point | Config | Duration | Executions | Result |
| --- | --- | --- | --- | --- | --- |
| `fuzz_netcode_server` (ours) | `netcode_server_update` with known keys | prod / live | 600 s | 170,231 / 170,389 | clean |
| `fuzz_netcode_server` (ours, seeded, `-len_control=0`) | same | prod / live | 1,200 s | 236,903 / 252,273 | clean (872 edges live) |
| `fuzz_netcode_client` (ours) | `netcode_client_update` with known keys | prod / live | 600 s | 1,053,640 / 989,623 | clean |
| `fuzz_reliable_pair` (ours) | `reliable_endpoint_receive_packet` behind an honest sender | prod / live | 600 s | 257,798 / 688,841 | live clean; prod stopped once on a harness oracle error (below) |
| `fuzz_reliable_pair` (ours, fixed, `-len_control=0`) | same | prod / live | 600 s | 452,075 / 424,642 | clean |
| `fuzz_read_packet` (upstream) | `netcode_read_packet` | prod / live | 600 s | 17,105,523 / 16,169,822 | clean |
| `fuzz_connect_token` (upstream) | public and private token readers | prod / live | 600 s | 26,899,587 / 25,918,865 | clean |
| `fuzz_parse_address` (upstream, upstream's corpus) | `netcode_parse_address` | prod / live | 600 s | 225,262,903 / 198,228,825 | clean |
| `fuzz_target` (upstream reliable) | two endpoints, scripted | prod / live | 600 s | 254,543 / 258,633 | clean |
| `connection_stream` (cargo-fuzz) | `Connection::receive` through the C reliable | nightly, Rust ASan, C ASan + `-fsanitize=fuzzer-no-link` | 600 s | 725,014 | clean |
| `handshake` (cargo-fuzz) | the schema handshake | same | 600 s | 4,078,800 | clean |
| `channel_schedule` (cargo-fuzz) | channel scheduling and flush | same | 600 s | 324,189 | clean |

The one stop: `fuzz_reliable_pair` (prod) reported a reassembled packet that differed from what
its sender sent. Triage showed a mutated fragment that claimed the next sequence before the
sender sent it; reliable keeps the first copy of each fragment, so the forgery is in the packet.
That is reliable working as designed (it authenticates nothing; netcode's AEAD stops forgeries in
dream-net), and the harness's taint bookkeeping was wrong to clear the claim on send. Fixed in
`TEST: Keep forged-fragment taint sticky and seed the native fuzzers`; the input passes since.

cargo-fuzz command (from `fuzz/`): `DREAM_NET_NATIVE_SANITIZE=address
CFLAGS=-fsanitize=fuzzer-no-link cargo +nightly fuzz run <target> -- -max_total_time=600`.
AGENTS.md's stable form (`RUSTC_BOOTSTRAP=1 cargo fuzz run <target> -s none -O`) runs no
sanitizer and does not instrument the C; use it for speed, not as sanitizer evidence.

Whole-stack and other sanitizer runs:

| Run | Command | Result |
| --- | --- | --- |
| Whole workspace, C under ASan + UBSan (trap), Rust under ASan, LSan on | `DREAM_NET_NATIVE_SANITIZE=address,undefined RUSTFLAGS="-Zsanitizer=address -Clink-arg=-fuse-ld=lld" RUSTDOCFLAGS=<same> CARGO_TARGET_DIR=<separate> cargo +nightly test --workspace --all-targets --target x86_64-unknown-linux-gnu` (nightly 1.101, LLVM 23.1.5) | 218 passed, 0 failed, 1 ignored, no report, 156 s. Includes the upstream C suites and the native fuzz smoke built with the same sanitizers |
| Soak, same configuration | as above with `--release --test soak`, `DREAM_NET_SOAK_FRAMES=200000` | passed, no report, 127 s |
| Native fuzz smoke | `DREAM_NET_NATIVE_TEST_SANITIZE=address,undefined cargo test -p dream-net-native --test fuzz_native` | passed (each harness in prod and live, plain and sanitized) |
| ThreadSanitizer, C | a scratch probe (not checked in): one `netcode_init`, then four threads each running a server and a client through a handshake and 100 payloads, two threads minting tokens and keys, three threads running fragmenting reliable pairs, three threads reading one shared endpoint's getters; `clang -fsanitize=thread` over netcode.c, sodium.c, reliable.c with the archive's defines | with creates unserialised: the F16 race, nothing else; with creates serialised as the binding does: clean |

The leak check is live: ASan on this toolchain enables LeakSanitizer by default (a deliberately
leaking `-Zsanitizer=address` program reports its 4096 bytes), and the whole-stack run reports no
leak, so every drop path frees what C and Rust allocated.

## 4. Resource bounds

| Per | What | Bound |
| --- | --- | --- |
| Server (fixed, at create) | `netcode_server_t`, including 1024 encryption mappings (131,080 B), the 2048-entry token history (131,072 B), 256 replay windows (2,056 B each) and 256 packet queues (4,128 B each) | 2,454,840 B, plus the shim's slot storage (256 x 312 B) |
| Pending client (pre-session) | one encryption mapping (keys, address, timers) and one token-history entry (64 B), both inside the fixed arrays above; nothing is allocated | mappings: 1024 per server; history: 2048 per server, each held until its token expires |
| Connection request in flight | one 1,080 B allocation, freed in the same call | transient |
| Connected client, netcode | up to 256 queued payloads of at most 1,216 B each between `update` and the drain dream-net does after it | 311,296 B per slot, transient |
| Connected client, reliable | everything at creation plus 16 reassembly slots of 33,241 B | 581,185 B with dream-net's defaults (`MemoryUsage::reliable`) |
| Connected client, dream-net | pending, parked and pooled bytes | `max_pending_bytes + 2 * max_parked_bytes` (README, `MemoryUsage`) |
| Server, all slots | 256 x (581,185 + 311,296) B worst case plus the fixed server | about 231 MB, of which about 149 MB reassembly |
| Handshake reply | one challenge (333 B) per valid request (1,078 B), to its first address only | ratio 0.31 |

## 5. Residual risks and operational guidance

- **Keep your key, keep your lifetimes short (F4).** A host that keeps its private key across
  server starts must mint tokens no longer-lived than the server's `max_connect_token_lifetime`,
  and never with a negative `expire_seconds` in production. A host that generates a fresh key at
  every start (l3i) is not exposed.
- **Multi-address tokens (F5).** List several servers in one token only if they do not share a
  private key, or accept that the token holder can open one session per listed server.
- **Public address binding.** Tokens are checked against the server's public address byte for
  byte; give the address clients use (an unspecified address cannot complete a connection).
- **Token issuance (F6).** Rate-limit token minting per account at the backend; 2048 unexpired
  tokens lock new tokens out for at most one lifetime.
- **Floods (F7).** Rate-limit UDP to the server port at the host or network edge. Pre-auth input
  costs at most about 6 µs per datagram, but the receive loop drains without bound.
- **One token, one `connect` call.** Tokens are single use; mint a fresh one for every attempt.

## 6. What was not tested

- Platforms other than Linux x86_64 (macOS, Windows, aarch64): no fuzzing or sanitizer run.
- ThreadSanitizer on the Rust side: Rust TSan needs a TSan-built standard library
  (`-Zbuild-std`), not set up here. The C was checked with a TSan probe instead (section 3).
- MemorySanitizer: not run.
- Timing side channels: out of scope, beyond noting that tag verification is libsodium's
  constant-time `crypto_verify_16`.
- Socket-level behaviour under real packet loss and kernel buffer overflow beyond what the
  existing loopback tests do.
- The libsodium subset beyond what the AEAD, XChaCha and RNG paths the harnesses exercise reach.
