# Native transport audit

The baseline for [#3](https://github.com/DreamWeave-MP/dream-net/issues/3), part of the
campaign in [#2](https://github.com/DreamWeave-MP/dream-net/issues/2): what dream-net 1.1.1
ships, what the Más Bandwidth Rust ports it depends on actually do, how they compare with the
upstream C `netcode` and `reliable` the campaign moves to, and what that move must preserve,
fix, and watch.

Audited tree: branch `native-transport` at `f3dd398` (dream-net 1.1.1). Legacy sources are the
crates.io packages `netcode-official 1.0.0`, `reliable 1.3.4`, `serialize-official 2.4.0`
from the local registry cache. Upstream C was cloned with full history from
`github.com/mas-bandwidth/netcode` and `github.com/mas-bandwidth/reliable`. Rust-port history
comes from `github.com/mas-bandwidth/netcode.rs`, `reliable.rs`, and `serialize.rs`.

## How to read this

Every security item is classified:

- **CONFIRMED** means it was reproduced here, or the exact code path is cited. The entry says
  which.
- **HYPOTHESIS** means a plausible class that was not reproduced and has no proven path.
- **NOT AFFECTED** means the code path was checked and the class does not apply.

"Verified" means a command was run and its output read. "Inferred" means the claim comes
from reading code. Descriptions stay at the level of class and code path. Reproducers are
described, not published as tools.

File references use these roots:

| Prefix | Root |
| --- | --- |
| `src/`, `tests/`, `benches/`, `fuzz/` | this repository |
| `nc-rs:` | `~/.cargo/registry/src/index.crates.io-*/netcode-official-1.0.0/` |
| `rel-rs:` | `~/.cargo/registry/src/index.crates.io-*/reliable-1.3.4/` |
| `ser-rs:` | `~/.cargo/registry/src/index.crates.io-*/serialize-official-2.4.0/` |
| `netcode.c`, `netcode.h` | C netcode at tag `v1.4.10` (`d6bc96d`) unless a tag is named |
| `reliable.c`, `reliable.h` | C reliable at tag `v1.4.6` (`b624576`) |
| `l3i:` | `DreamWeave-MP/l3i` working tree (read only), which pins `dream-net = "=1.1.1"` |

## 1. Summary

### Top findings

| # | Finding | Class | Risk | Affects | Fixed upstream in |
| --- | --- | --- | --- | --- | --- |
| S1 | Reusing a connect token after disconnect starts a second session under the same keys, with packet sequences restarting at 0. That is AEAD nonce reuse in both directions. | CONFIRMED (reproduced against dream-net 1.1.1) | High | netcode-official 1.0.0; C ≤ 1.4.4 (GHSA-v29p-3vj4-vg4f) | C 1.4.5; netcode.rs 1.1.2 (MBSL, unpublished) |
| S2 | A server restarted with the same private key accepts a token it already accepted before the restart. The token history lives in memory and 1.0.0 has no start floor. Same nonce reuse. | CONFIRMED (reproduced) | High | netcode-official 1.0.0; C ≤ 1.4.4 | C 1.4.5 start floor, which is only effective when token lifetime ≤ `max_connect_token_lifetime` |
| S3 | A zero-length UDP datagram ends the receive drain for that update. Sending them from anywhere, with no authentication, starves the server (and client) receive path. | CONFIRMED (reproduced) | Medium | netcode-official 1.0.0; C ≤ 1.4.9 | C 1.4.10 |
| S4 | A connected client that receives a disconnect moves on to the next server in its token instead of disconnecting. dream-net's `Client` then keeps its old `Connection`. | CONFIRMED (code path) | Low, and only with multi-address tokens | netcode-official 1.0.0; C ≤ 1.4.9 | C 1.4.10 |
| S5 | C 1.4.10's start floor refuses tokens whose expiry is ≤ start + `max_connect_token_lifetime` (default 30 s). dream-net's own tests and l3i's localhost test mint 30-second tokens in the server's start second, so they would be refused. Tokens longer than that lifetime (l3i defaults to 300 s, up to 86 400 s) bypass the floor, which reopens S2. | CONFIRMED (code path; compatibility + residual security) | High (migration blocker) | migration to C ≥ 1.4.5 | needs a dream-net decision (§9) |
| S6 | A C server created with port 0 keeps port 0 as its public address, so a token naming the real bound port fails the whitelist. The Rust port advertises the bound port. dream-net and l3i rely on port 0. | CONFIRMED (code path) | High (migration blocker) | C at every candidate tag | needs a patch or wrapper workaround (§9) |
| S7 | C `reliable` refuses sent/received/reassembly buffer sizes above 16 384. dream-net's `TransportConfig::validate` allows 32 768, and `Connection::new` cannot fail. | CONFIRMED (code path) | Medium (migration) | migration | dream-net must tighten validation |
| S8 | In C, `netcode_assert`/`reliable_assert` exit or trap in debug builds and compile to nothing in release. `reliable_endpoint_send_packet` has no release-mode check behind two of its asserts. | CONFIRMED (code path) | Medium (FFI design) | C at every tag | wrapper requirements (S8, S12) |

### Wire compatibility (verified)

- **netcode:** all 11 known-answer vectors shipped with netcode-official 1.0.0 (tokens, every
  packet type, AEAD output) are byte-identical to what C netcode **1.4.10** and **1.4.9**
  produce from the same inputs (§5.1). Version string `"NETCODE 1.02"` on both sides.
- **reliable:** a deterministic 120-frame, two-endpoint exchange using dream-net's default
  transport sizes, with packets of 1 to 32 768 bytes (fragmented and unfragmented) and one
  datagram in three dropped, produces byte-identical datagrams, deliveries, ack lists,
  counters and statistics from reliable 1.3.4 (Rust) and C reliable **1.4.6** (§5.2).
- **Expected:** a dream-net 1.1.1 peer and a peer on C netcode 1.4.10 / reliable 1.4.6
  interoperate on the wire. The differences are behavioural: what each side refuses, when it
  times out, and how it treats tokens (§5.3). None changes a byte.

### Recommended pins

- netcode **v1.4.10**, commit `d6bc96dafe2cc6c9b77903db7ce86f832a2de996`. This is newer than
  the v1.4.9 named in the brief. It fixes S3 and several client defects, and its
  libsodium subset is identical to v1.4.9's.
- reliable **v1.4.6**, commit `b6245763cedb04d297ced7f196d6a1caeb0da239`.

## 2. Environment and baseline

Verified on Linux x86_64 with rustc 1.100.0 (0ef1bc386 2026-11-09), cargo 1.100.0, clang
23.1.2, and LLD 23.1.2. The 1.88 MSRV toolchain is not installed, so `cargo +1.88 check` was
**not** run. Network access was used only to clone upstream, read crates.io and GitHub
metadata, and refresh the RustSec database for `cargo audit`. `Cargo.lock` is gitignored, so the resolution below is a local resolve and nothing
is pinned in git.

| Command | Result |
| --- | --- |
| `cargo test --workspace --all-targets --all-features` | pass. lib 10, adversarial 7 (new), alloc 2, capture 4, connection 31, fuzz_smoke 5, netcode 11, soak 1, wire 11, wire_golden 4. Benches built and run in test mode. |
| `cargo clippy --workspace --all-targets --all-features -- -W clippy::pedantic -D warnings` | pass |
| `cargo fmt --all --check` | pass |
| `cargo audit` (advisory DB 1533 advisories, 107 crates) | no vulnerabilities reported, exit 0 |
| `cargo test --test adversarial`, run 6 times in debug and once with `--release` | 7/7 pass every time, about 2.1 s |

Golden vectors that the migration must keep:

- dream-net framing: `tests/wire_golden.rs` (unchanged by this audit).
- netcode: the 11 files in `nc-rs:tests/vectors/` (SHA-256 listed in §5.1), reproduced from C
  by the program in Appendix A.
- reliable: the scenario in Appendix B. Both implementations print the same transcript, with
  SHA-256 `0a4ddb67d23b1ce5c52d365b8a81d8f4c81d5712b56efdad6b485ea56aec3b7a` (1554 lines,
  1200 datagrams, 110 deliveries).

Benchmarks were not run (the director captures them).

## 3. Dependency accounting

### 3.1 Graphs (verified)

```text
$ cargo tree -i netcode-official
netcode-official v1.0.0
└── dream-net v1.1.1

$ cargo tree -i reliable
reliable v1.3.4
└── dream-net v1.1.1

$ cargo tree -i serialize-official
serialize-official v2.4.0
└── dream-net v1.1.1

$ cargo tree -e normal
dream-net v1.1.1
├── ctutils v0.4.8
│   └── cmov v0.5.4
├── netcode-official v1.0.0
│   ├── chacha20poly1305 v0.11.0
│   │   ├── aead v0.6.1 (crypto-common 0.2.2, getrandom 0.4.3, rand_core 0.10.1, hybrid-array 0.4.15, typenum 1.20.1, inout 0.2.6)
│   │   ├── chacha20 v0.10.2 (cipher 0.5.2, block-buffer 0.12.1, cpufeatures 0.3.1)
│   │   └── poly1305 v0.9.1 (universal-hash 0.6.1 → ctutils 0.4.8)
│   ├── getrandom v0.4.3 (cfg-if, libc 0.2.191)
│   ├── log v0.4.35
│   └── socket2 v0.6.5 (libc)
├── reliable v1.3.4
│   └── log v0.4.35
├── serialize-official v2.4.0
└── sha2 v0.11.1 (cfg-if, cpufeatures, digest 0.11.3)

$ cargo tree -e build
dream-net v1.1.1          # no build dependencies, no build script

$ cargo tree -e dev --depth 1
dream-net v1.1.1
[dev-dependencies]
├── criterion v0.8.2
└── proptest v1.12.0

$ cargo tree -i ctutils -e normal
ctutils v0.4.8
├── dream-net v1.1.1
└── universal-hash v0.6.1 → poly1305 → chacha20poly1305 → netcode-official → dream-net
```

`fuzz/` is its own workspace. It depends on `reliable = "=1.3.4"` directly
(`fuzz/Cargo.toml`) as well as through dream-net. `cargo tree -i reliable` in `fuzz/` shows
both edges. The crate has no Cargo features, so there are no feature-gated paths.

`ctutils` exists only as a version floor under netcode-official's Poly1305
(`Cargo.toml` comment, RUSTSEC-2026-0385). Once netcode-official is gone, nothing else uses
it (sha2 does not), and the floor should go with it.

### 3.2 Every path that reaches a legacy crate

| Crate | File:line | Use |
| --- | --- | --- |
| netcode | `src/lib.rs:103-106` | public re-export `CONNECT_TOKEN_BYTES, KEY_BYTES, Key, USER_DATA_BYTES, UserData, generate_connect_token, generate_key` |
| netcode | `src/error.rs:167, 174, 183, 194-196` | `Error::Netcode(netcode::Error)`, its `Display` (`"netcode: {error}"`), `source`, `From` |
| netcode | `src/config.rs:11` | `DATAGRAM_BYTES = netcode::MAX_PAYLOAD_BYTES` |
| netcode | `src/server.rs:119, 171, 176-178, 212, 236-271, 281, 285, 294-297, 344, 525, 549, 574, 578-580, 619, 631` | `Server` owns `netcode::Server`; `new` takes `&netcode::Key`; `client_user_data -> Option<&netcode::UserData>` |
| netcode | `src/client.rs:93, 135, 171, 176, 199, 221-224, 238-241, 245, 260, 268-277, 375, 379, 389, 394, 427, 436` | `Client` owns `netcode::Client`; `connect(&[u8; netcode::CONNECT_TOKEN_BYTES])` |
| netcode | `tests/netcode.rs:409-412` | a bare `netcode::Client` that authenticates but never speaks dream-net |
| netcode | `benches/netcode.rs:146-210` | `RawWorld`: raw `netcode::Server`/`Client` baseline (`generate_key`, `Server::new`, `start`, `update`, `next_event`, `max_clients`, `num_connected_clients`, `receive_packet`, `send_packet`, `Client::new`, `connect`, `state`) |
| reliable | `src/config.rs:15, 18` | `FRAGMENT_HEADER_BYTES`, `MAX_PACKET_HEADER_BYTES` in public consts |
| reliable | `src/config.rs:296-314` | public `TransportConfig::reliable_config(&self, &str) -> reliable::Config` |
| reliable | `src/config.rs:328-333` (unit test) | constants |
| reliable | `src/connection.rs:246, 254, 374-376, 391-399, 414, 440-441, 454, 469, 482-487, 501, 511-513` | `Connection` owns `reliable::Endpoint`; public `reliable_counters() -> &reliable::Counters` |
| reliable | `src/stats.rs:34-48` | crate-private `ConnectionStats::from_endpoint(&reliable::Endpoint)` |
| reliable | `src/sequence.rs:46, 53` | `Seq16` comparisons via `reliable::sequence_greater_than/less_than` |
| reliable | `tests/harness/mod.rs:125-186, 318-344` | `reliable::Endpoint` as the scripted remote: `new`, `send_packet`, `receive_packet`, `update`, `clear_acks`. Shared by `tests/fuzz_smoke.rs` and every `fuzz/fuzz_targets/*.rs` (`#[path = "../../tests/harness/mod.rs"]`) |
| reliable | `tests/connection.rs:123, 441-448, 956` | `MAX_PACKET_HEADER_BYTES`, scripted `Endpoint` |
| reliable | `benches/connection.rs:268-276` | raw `Endpoint::update` cost per `rtt_history_size` (mutates `Config.rtt_history_size`) |
| reliable | `fuzz/Cargo.toml` | direct dependency `reliable = "=1.3.4"` |
| serialize | `src/wire.rs:38` (private: `BitReader`, `BitWriter`, `bits_required`; `PacketWriter.w` is a private field) | the framing codec |
| serialize | `tests/wire.rs:19, 110` | an independent reference decoder (`BitWriter, ReadStream, Stream, WriteStream`, `serialize::Result`) |

`benches/scale.rs` and `benches/wire.rs` reach the legacy crates only through dream-net. So
do `tests/alloc.rs`, `tests/capture.rs`, `tests/soak.rs`, and `tests/wire_golden.rs`.
Packaging: the `include` allowlist ships `/src/**`, `/tests/**`, `/benches/**`, so every row
above except `fuzz/` is in the published crate.

### 3.3 Public API leaks, and what l3i uses

l3i's use was found by grepping `l3i:src/udp.rs`, `l3i:tests/udp.rs`, and
`l3i:benches/udp.rs` for `dream_net::` and for the methods involved.

| Leak | Where | Used by l3i? |
| --- | --- | --- |
| `Key` (`[u8; 32]`) | `src/lib.rs:104`, `Server::new(.., &Key, ..)` | **yes**: `udp.rs:308` (`TokenIssuer.key`), `udp.rs:614` |
| `generate_key()` | `src/lib.rs:105` | **yes**: `udp.rs:614`, `benches/udp.rs:41` |
| `generate_connect_token(&[SocketAddr], &[SocketAddr], i32, i32, u64, u64, &Key, &UserData) -> Result<[u8; 2048], netcode::Error>` | `src/lib.rs:105` | **yes**: `udp.rs:695-704` (expiry 1..=86 400 s, default 300; timeout 1..=300 s, default 30), `benches/udp.rs:51-60` (300/30). Errors only through `Display` (`config_error`, `udp.rs:88-90`). |
| `CONNECT_TOKEN_BYTES` | `src/lib.rs:104`, `Client::connect` | **yes**: `udp.rs:546, 839` |
| `USER_DATA_BYTES` | `src/lib.rs:104` | **yes**: `udp.rs:694`, `benches/udp.rs:59` |
| `KEY_BYTES` | `src/lib.rs:104` | no |
| `UserData` (`[u8; 256]`), `Server::client_user_data` | `src/lib.rs:104`, `src/server.rs:578` | no |
| `Error::Netcode(netcode::Error)` | `src/error.rs:167` | not matched by variant. l3i only formats `dream_net::Error` through `Display`, so the text `"netcode: …"` reaches Luau error messages. |
| `Connection::reliable_counters() -> &reliable::Counters` | `src/connection.rs:511` | no (l3i never touches `Connection`) |
| `TransportConfig::reliable_config() -> reliable::Config` | `src/config.rs:296` | no (l3i uses `TransportConfig::default()` only) |
| `config::{DATAGRAM_BYTES, MAX_FRAGMENT_SIZE, MAX_UNFRAGMENTED_PACKET}` (values derived from the ports) | `src/config.rs:11-18` | no |
| `ServerConfig` (exhaustive struct, four public fields) | `src/server.rs:32` | **yes**, built with a struct literal: `udp.rs:615-620`, `benches/udp.rs:42-47`. **Adding a field is a breaking change for l3i.** |

### 3.4 Why the ports are obsolete (verified from crates.io and repository history)

- `netcode-official` has exactly one release on crates.io, 1.0.0 (2026-07-12, BSD-3-Clause).
  The repository went on to v1.1.0 to v1.1.3. Every one of those is **relicensed to the Más
  Bandwidth Source License** (`netcode.rs` commits `a4c25ca`, `cb62a52`, 2026-07-18;
  `Cargo.toml` at v1.1.3: `license = "LicenseRef-MBSL"`), and none is published. The fixes
  for S1–S4 exist only under MBSL (netcode.rs issues #24 and #38; #38 is the dream-net
  maintainer's public request to publish 1.1.2).
- `reliable` 1.3.4 is the last BSD-3-Clause release on crates.io. reliable.rs relicensed to
  MBSL at v1.4.0 (`d788ff4`), and v1.4.x is unpublished (reliable.rs issue #33).
- `serialize-official` 2.4.0 is BSD-3-Clause and serialize.rs stays BSD (v5.0.1, renamed
  `serialize`). The campaign replaces it with dream-net's own framing (#8) for scope, not
  security. It has no `unsafe` (`grep unsafe ser-rs:src` matches comments only). Its reader
  contracts are debug asserts that turn into bounds panics in release
  (`ser-rs:src/bitpacker.rs:253-265`). dream-net reads only through its own checked reader
  (`src/wire.rs:31-38`).
- `cargo audit`: no RustSec advisory names any of the three. The two upstream GitHub
  advisories (GHSA-v29p-3vj4-vg4f and GHSA-3x95-24j9-7448) are filed against the C library
  and yojimbo, and RustSec does not track them. `cargo audit` being clean is therefore no
  evidence about S1/S2.
- Missing upstream fixes for the Rust ports are itemized in §5.3 and §6.

So there is no permissively licensed, published Rust release that carries the fixes, which
is the premise of #2.

## 4. Behaviour and compatibility map

### 4.1 Server lifecycle (`src/server.rs`)

- `Server::new(config, &Key, schema, time)` (`:169-197`) validates schema against transport
  (`Shared::new`). It then calls `netcode::Server::new(public_address, protocol_id, key, time)`,
  which binds `0.0.0.0:port` or `[::]:port` (IPv6 only-v6) with 4 MiB socket buffers,
  non-blocking (`nc-rs:src/socket.rs`). **Port 0 binds an ephemeral port and rewrites the
  public address to it** (`nc-rs:src/server.rs:353-356`). It then calls `start(max_clients)`,
  which errors outside `[1, 256]`. Slots are created as `PeerId(slot, 0)`.
- `update(time)` (`:232-320`): time is clamped monotonic (`self.time.max(time)`). Then
  `netcode.update(time)` (receive everything, keep-alives at 10 Hz, timeouts), then drain
  `next_event()`:
  - `ClientConnected{i}`: bump the global `generation`, `PeerId::new(i, generation)`, read
    `client_id(i)` **now**, create a `Connection`, and open the inbox slot. No host event yet.
  - `ClientDisconnected{i, reason}`: drop the connection. Only an *established* peer produces
    `ServerEvent::Disconnected`, with reason mapped `TimedOut→TimedOut`,
    `ClientDisconnect→Remote`, `ServerDisconnect→Requested`.
  - Per slot: a lingering mismatched slot (`closing_until`) discards payloads until the
    linger ends, then `disconnect_client`. Otherwise `connection.update`, then every queued
    payload goes through `connection.receive`. Acks owed mid-burst go out at once through
    `netcode.send_packet`, and any `Err` fails the slot with `TransportError`. Then
    `take_event`: `Established` inserts `Connected` *before* any message that packet
    delivered. `Failed` goes to `close_slot`.
- `close_slot` (`:324-346`): `Rejected` if never announced, `Disconnected(failure.reason())`
  if it was. A schema or protocol mismatch lingers `mismatch_linger` seconds and keeps
  sending only its hello. Anything else is disconnected at once.
- `flush` (`:516-532`): `write_packets` per slot. A `send_packet` refusal is treated as a
  dream-net bug (`debug_assert!`) and closes the slot.
- `disconnect(peer)` validates the full `PeerId` (slot and generation) before acting.
  `Drop` calls `netcode.stop()`, which sends 10 disconnect packets per connected client.
- Getters (`client_id`, `client_address`, `client_user_data`, `stats`, `counters`,
  `peer_connection`) answer only for an *established* peer whose full `PeerId` matches.
- `Debug` is hand-written so the private key never reaches a log (`:615-626`).

### 4.2 Client lifecycle (`src/client.rs`)

- `connect(token)` (`:171-181`) ends any attempt in progress (`disconnect`, which queues its
  terminal event), then `netcode.connect(token)`. A token that does not parse returns `Err`
  **and** queues `ConnectFailed{Authentication}`.
- `update` (`:217-280`): when `netcode.state() == Connected` with no `Connection` while
  attempting, bump `generation` and create a `Connection` (`Handshaking`). Payloads go to
  `connection.receive`. `Established` inserts `Connected` before the first message. When
  netcode is disconnected while attempting, the terminal event maps `ConnectTokenExpired`
  and `InvalidConnectToken` to `Authentication`, the three timeouts to `TimedOut`,
  `ConnectionDenied` to `Denied`, and anything else (a server disconnect, which netcode
  reports as `Disconnected`) to `Remote`.
- Every attempt ends in exactly one `Disconnected` (after `Connected`) or `ConnectFailed`.
- **Dependency on netcode semantics:** the `Connection` is created once per attempt, keyed
  on netcode reaching `Connected`. If netcode ever goes `Connected → SendingConnectionRequest
  → Connected` without passing through a disconnected state, which 1.0.0 does on a server
  disconnect with a multi-address token (S4), dream-net reuses the old `Connection` against
  a new session. C 1.4.10 goes to `Disconnected` instead.

### 4.3 Connect tokens

- Minted by `generate_connect_token` (re-export). A 2048-byte public token with version
  `"NETCODE 1.02\0"`, protocol id, create/expire timestamps (wall clock, whole seconds),
  a 24-byte nonce, 1024 bytes of private data (XChaCha20-Poly1305 under the server private
  key, with associated data version+protocol+expiry), timeout, server addresses, and the two
  per-token session keys. The keys and the client id come from the backend, so **every
  session's AEAD keys are a function of the token alone.** The server and its restart history
  are not inputs.
- The server whitelists its public address against the token's list, refuses an address or
  client id already connected, and records the token's MAC in a history:

  | | netcode-official 1.0.0 | C 1.4.10 |
  | --- | --- | --- |
  | History size | 2048 (`MAX_CLIENTS*8`) | 2048 |
  | Same token, same address | admitted forever (`nc-rs:src/server.rs:268`) | admitted only while the entry is *pending*. Consumed on install. |
  | Same token, other address | refused | refused |
  | History full | evict oldest (`:251-266`) | refuse the new token until an entry's token expires (`netcode.c:4093-4155`) |
  | Token predating server start | accepted | refused if `expire ≤ start + max_connect_token_lifetime` (`netcode.c:2004, 4454`) |
  | Pending mapping, negative token timeout | never expires (`nc-rs:src/server.rs:764-768` with `EncryptionEntry::expired`, `:79-82`) | bounded by the token's remaining lifetime (`netcode.c:4803-4809`) |

### 4.4 `PeerId`, generations, slot reuse (`src/id.rs`, `src/server.rs`)

`PeerId = (generation & (2^48-1)) << 16 | slot`. The server's `generation` is a `u64`
incremented on every netcode connect, across all slots. Every handle-taking API compares the
whole `PeerId`, and stale handles are refused (`connection_mut`/`connection`,
`src/server.rs:401-415`; `disconnect`, `:535-550`). The client uses slot 0 and its own
generation. This is pure dream-net logic, independent of the transport. It must be fed
`ClientConnected`/`ClientDisconnected` in the order netcode produced them, with the client id
**as of the connect**.

### 4.5 Handshake and schema fingerprint

Inside the encrypted netcode session, each side's first connection packets carry a hello
(`wire_version: u16 = 2`, `fingerprint: u128` = SHA-256 of the canonical schema, truncated).
A connection acks nothing and delivers nothing until a valid hello arrives
(`src/connection.rs:616-624`). A different `wire_version` is `ProtocolMismatch`, and a
different fingerprint is `SchemaMismatch` (`:599-612`). A server lingers so the client can
diagnose. The handshake times out after `handshake_timeout` (5 s). The netcode `protocol_id`
is separate: a wrong one is never answered (the request is ignored), so the client times out.

### 4.6 Packet path

```text
host event ─► Channel queue ─► Connection::write_packets
   wire frame (serialize bit stream, ≤ packet_budget = 1191 B, or one oversize event ≤ 32 KiB)
   ─► reliable::Endpoint::send_packet: header ≤ 9 B (prefix, seq u16, ack u8/u16, 0-4 ack bytes)
        or, above fragment_above = 1191 B, fragments: 5 B fragment header (+ packet header in
        fragment 0) + ≤ 1186 B each, ≤ 28 fragments with the default 32 KiB max_packet_size
   ─► netcode send_packet: payload 1..=1200 B, encrypted: prefix (type | seq_bytes<<4),
        1-8 sequence bytes, ChaCha20-Poly1305 ciphertext, 16 B tag ─► UDP (≤ 1225 B)
receive: UDP ─► netcode read/decrypt/replay ─► per-client queue (≤ 256)
   ─► Connection::receive ─► reliable receive (stale/duplicate/reassembly) ─► process closure
   ─► wire::decode (canonical, refuses padding/trailing bytes) ─► channels ─► inbox
```

`DATAGRAM_BYTES = 1200`, `MAX_FRAGMENT_SIZE = 1186`, and `MAX_UNFRAGMENTED_PACKET = 1191`
are derived from the port's constants. The C constants have the same values
(`netcode.h:137` `NETCODE_MAX_PACKET_SIZE 1200`, `reliable.h:91-92` 9 and 5). acks are
drained after every received datagram (`ack_buffer_size: 64`). Every `ACK_EVERY = 16` received
packets with content, a control packet is sent immediately.

### 4.7 Stats and counters

`ConnectionStats` copies reliable's `rtt`, `rtt_min/max/avg`, the three jitter values,
`packet_loss`, and `Bandwidth{sent,received,acked}_kbps` (`src/stats.rs:34-48`). dream-net's
own `Counters` do not depend on reliable. `MemoryUsage.reliable` is an *estimate*
(`src/connection.rs:551-555`) that charges 300 B per reassembly slot. See S9.

### 4.8 Error mapping

`dream_net::Error` is `Config(ConfigError) | Netcode(netcode::Error)`, `#[non_exhaustive]`.
The netcode errors that can occur are `Io(io::Error)` from socket create/bind in
`Server::new`/`Client::new`, `InvalidMaxClients` from `Server::new`, `InvalidConnectToken`
from `Client::connect`, and `InvalidServerAddresses`/`EncryptFailed` from
`generate_connect_token`. `InvalidPayloadSize` comes from `send_packet` and is never surfaced:
it is turned into `Failure::TransportError`. `Display` strings reach Luau through l3i.

### 4.9 What l3i expects (read from `l3i:src/udp.rs`)

- It creates `Server` from Luau with `ServerConfig { public_address: parsed, protocol_id,
  max_clients, transport: TransportConfig::default() }` and `generate_key()` (`:614-622`). The
  key stays in a Rust userdata. `connectToken` mints single-address tokens for
  `server.address()` (`:681-709`). **It relies on port-0 servers advertising the bound port**
  (`tests/udp.rs:87`, `'127.0.0.1:0'`).
- It uses `poll_into` with Luau buffers (borrowed `&mut [u8]`, `udp.rs:342-344`), `send`,
  `broadcast`, `broadcast_except`, `flush`, `update` (with its own monotonic clock), `stats`,
  `counters`, `memory_usage`, `num_connected`, `max_clients`, `address`, and on the client
  `connect`, `disconnect`, `status`, `port`, `server_address`.
- Nothing calls back into Luau. All of the above is polled. `unsafe impl Userdata for
  Server` (`udp.rs:312-316`) rests on "`dream_net::Server` is plain Rust state with no Lua
  references". A C-backed server keeps that true only if no C callback can reach the host.
- `tests/udp.rs:87` mints a **30-second** token right after creating the server and expects
  it to connect. See S5.

### 4.10 Auto traits (verified by a throwaway compile probe)

A scratch crate depending on this tree by path printed the following, using an
inherent-method-over-trait probe. The `Send`/`Sync` results for `Server`, `Client`, and
`Connection` were cross-checked with `fn s<T: Send>()` bounds, and the compiler rejected
`Server` and `Client` with "`dyn CaptureSink` cannot be sent between threads safely".

| Type | Send | Sync | Unpin | UnwindSafe | RefUnwindSafe |
| --- | --- | --- | --- | --- | --- |
| `Server` | **no** | **no** | yes | no | no |
| `Client` | **no** | **no** | yes | no | no |
| `Connection` | yes | yes | yes | yes | yes |
| `Shared`, `Arc<Shared>` | yes | yes | yes | yes | yes |
| `Schema` | yes | yes | yes | yes | yes |
| `Inbox<()>` | yes | yes | yes | yes | yes |
| `Error` | yes | yes | yes | no | no |
| `ConfigError`, `SendError`, `ServerConfig`, `ClientConfig`, `TransportConfig`, `ConnectionStats`, `Counters`, `PeerId`, `Key`, `UserData`, `sim::Pair` | yes | yes | yes | yes | yes |

`Server` and `Client` are `!Send + !Sync` because of `capture: Option<Box<dyn CaptureSink>>`,
not because of netcode. The C migration therefore has no `Send` to preserve on them, but it
**must not make `Connection` lose `Send`, `Sync`, `UnwindSafe`, or `RefUnwindSafe`**. A raw C
endpoint pointer gives none of those. The wrapper needs a justified `unsafe impl Send + Sync`,
which is sound only because every `&self` method on it is a pure read. `Error` must stay
`Send + Sync`. Gaining `UnwindSafe` there is harmless.

## 5. Wire comparison

### 5.1 netcode: known-answer vectors (verified)

netcode-official 1.0.0's `src/wire_compat.rs` claims its `tests/vectors/*.bin` were
"generated by the reference C implementation … from fixed inputs" and pin "token layouts,
packet framing, sequence encoding, endianness, AEAD construction (cipher choice, nonce
layout, associated data)". Those tests are `#[cfg(test)]` in the crate and only prove
Rust-equals-file. To check the claim against the candidate pins, the program in Appendix A
(a unity build over `netcode.c`) writes every vector from the same inputs. Command and
output:

```text
$ clang -O1 -w -DNDEBUG -DNETCODE_RELEASE -I../nc-1.4.10 -I../nc-1.4.10/sodium kat.c ../nc-1.4.10/sodium/sodium.c -o kat-1.4.10
$ ./kat-1.4.10 out-1.4.10    # then cmp each against netcode-official's tests/vectors
ok 1.4.10
IDENTICAL challenge_token_encrypted.bin 300
IDENTICAL connect_token.bin 2048
IDENTICAL packet_challenge.bin 330
IDENTICAL packet_denied.bin 22
IDENTICAL packet_disconnect.bin 22
IDENTICAL packet_keep_alive.bin 30
IDENTICAL packet_payload.bin 1222
IDENTICAL packet_request.bin 1078
IDENTICAL packet_response.bin 330
IDENTICAL private_connect_token_encrypted.bin 1024
IDENTICAL private_connect_token_plaintext.bin 1024
```

The same build against v1.4.9 produced identical files. Vector SHA-256 (first 16 hex):
`challenge 33c5560aaed4192f`, `connect_token 12cd58f0e2d17b00`, `packet_challenge
22fc408d3ab1e865`, `packet_denied ecc44891ea58f39f`, `packet_disconnect e79e7c56a01a8c06`,
`packet_keep_alive c96b56dbef593cab`, `packet_payload e991282ba33dae3d`, `packet_request
fc7d9221a4b2d74d`, `packet_response d7f8965bb2961ae0`, `private_enc 3fc190a87b816c43`,
`private_plain 7b1896a06c8dd068`.

This proves, for both implementations, the token layout (IPv4 and IPv6 address forms,
padding), the prefix byte and minimal little-endian sequence encoding, the XChaCha20-Poly1305
private-token construction (associated data `"NETCODE 1.02\0" ‖ protocol_id ‖ expire`), the
ChaCha20-Poly1305 packet construction (nonce `0x00000000 ‖ sequence_le64`, associated data
`version ‖ protocol_id ‖ prefix_byte`), and the challenge-token construction (nonce from the
challenge sequence).

Static agreement, read side by side:

| Item | netcode-official 1.0.0 | C 1.4.10 |
| --- | --- | --- |
| Version info | `nc-rs:src/lib.rs:138` `"NETCODE 1.02\0"` | `netcode.c:55` |
| Token / private / challenge / nonce sizes | 2048 / 1024 / 300 / 24 (`nc-rs:src/lib.rs:112`, `token.rs:18-20`) | `netcode.h:90`, `netcode.c:40-42` |
| Packet types 0-6 | `nc-rs:src/packet.rs:17-24` | `netcode.c:1495-1502` |
| Sequence bytes in prefix high nibble, 1..=8 | `packet.rs:247-252` | `netcode.c:2081` |
| Request length exactly 1078 | `packet.rs:369` | `netcode.c:1955-1958` |
| Max packet 1300, payload 1..=1200 | `lib.rs:139, 130`, `packet.rs:336` | `netcode.c:44-45` |
| Replay window 256, checked before decrypt, advanced after | `replay.rs:9`, `packet.rs:263-295` | `netcode.c:47, 1870-1910` |
| Global (challenge/denied) sequence in top half, reseeded on start | `server.rs:400-404, 421` | `netcode.c:4380, 4463` |
| Keep-alive send rate 10 Hz; 10 redundant disconnects | `lib.rs:140-141` | `netcode.c:56-57` |
| Encryption mappings 1024, token history 2048 | `server.rs:50, 218` | `netcode.c:3838, 4047` |

### 5.2 reliable: exchange transcript (verified)

reliable.rs states that reliable's wire did not change from C 1.3.4 to 1.4.5 (its CHANGELOG
1.4.5 entry). To check 1.3.4-Rust against 1.4.6-C directly, Appendix B runs one scenario
through both: two endpoints with dream-net's default `reliable_config` (max 32 768, fragment
above 1191, fragment 1186 × 28, acks 64, windows 256/256/16, history 128), 120 frames at
60 Hz, both sides sending sizes cycling through {1, 10, 1191, 1192, 5000, 32768, 77, 300},
with every third datagram dropped. The transcript prints every datagram in hex, every
delivery (sequence, length, FNV-1a), the drained acks each frame, all 11 counters, and the
statistics.

```text
$ clang -O1 -w -DNDEBUG -Irl-1.4.6 rel.c rl-1.4.6/reliable.c -lm -o rel-c && ./rel-c > rel-c.out
$ (cd rel-rs && cargo run --offline -q --release) > rel-rs.out     # reliable = "=1.3.4"
$ cmp rel-c.out rel-rs.out && echo IDENTICAL_OUTPUT
IDENTICAL_OUTPUT
$ grep -c '^TX' rel-c.out; grep -c '^RX' rel-c.out
1200
110
COUNTERS 0 120 55 54 0 0 0 0 525 350 0 0       # same on both, both endpoints
```

Static agreement: the header encoding (`rel-rs:src/packet.rs:24-86` and `reliable.c:907-975`),
header parse (`packet.rs:88-160`, `reliable.c:1082-1164`), fragment header parse including the
canonical-header check (`packet.rs:161-250`, `reliable.c:1166-1267`), acks of a
process-accepted packet only, and `sequence_greater_than` (half-space).

### 5.3 Every difference found

None of these changes a byte on the wire. "→" marks what the migrated code will do.

| # | Area | Rust port (file:line) | C (file:line) | Effect on dream-net |
| --- | --- | --- | --- | --- |
| D1 | Token reuse after disconnect | allowed from same address (`nc-rs:src/server.rs:268`) | consumed on install (`netcode.c:4093-4166`) | → second `connect` with the same token is refused. S1 fixed. l3i scripts that reconnect with an old token start failing (§9 Q4). |
| D2 | Token predating start | accepted | refused at ≤ floor (`netcode.c:2004`, 1.4.9: `<` at `:1953`) | → S5: 30-second tokens minted in the start second are refused |
| D3 | History full | evict oldest | refuse new tokens | → possible refusal under a token flood (S10) |
| D4 | Pending mapping lifetime (negative timeout) | never expires | bounded by token lifetime | minor |
| D5 | Zero-length datagram | ends the receive loop (`nc-rs:src/socket.rs:29`) | skipped (1.4.10) | S3 fixed |
| D6 | Packet sequence `2^64-1` | accepted, but replay protection's `EMPTY` sentinel is `u64::MAX` (`nc-rs:src/replay.rs:11, 39`) | ignored for every type (`netcode.c:1876, 1901, 2104`) | unreachable in practice (S11) |
| D7 | Client: source address check | after decrypt and replay advance (`nc-rs:src/client.rs:532-546`) | before reading (1.4.10) | → off-path packets cost nothing |
| D8 | Client: server disconnect while connected | next server address (`client.rs:252, 597`) | `Disconnected` | S4 fixed |
| D9 | Client: keep-alive validation | any `client_index`/`max_clients` | ignored unless `1 ≤ max ≤ 256`, `index < max` | none (dream-net ignores both) |
| D10 | Client: token expiry clock | restarts per server address (`client.rs:242`, `reset_before_next_connect`) | from `connect` | minor |
| D11 | Port 0 server | advertises bound port (`nc-rs:src/server.rs:353-356`) | public address keeps port 0, whitelist compares it (`netcode.c:791-806, 4377-4378, 4734-4747`) | → S6, blocker |
| D12 | Config refusals | `Endpoint::new` asserts > 0 and `max_fragments ≤ 256` only (`rel-rs:src/endpoint.rs:258-267`) | NULL on buffer size > 16 384, `fragment_above > max_packet_size`, fragment coverage, `int` overflow, negative header size, smoothing outside [0, 1] (`reliable.c:588-722`) | → S7 |
| D13 | Buffer sizes | used as given (`%` on non-power-of-two) | rounded up to a power of two (`reliable.c:192-207`) | none for sent/received (dream-net requires powers of two). `fragment_reassembly_buffer_size` (not required to be a power of two) may round up, doubling the reassembly memory bound. |
| D14 | Empty input | `send_packet`/`receive_packet` panic (`endpoint.rs:317, 439`) | receive counts invalid (`reliable.c:1328-1332`). Send is assert-only (`reliable.c:981`): release sends a header-only packet. | wrapper must refuse empty sends |
| D15 | Negative RTT sample | `debug_assert!` (`endpoint.rs:540`) | clamped to 0 (`reliable.c:1429-1432`) | none (dream-net time is monotonic) |
| D16 | `rtt_min` "no samples" | sentinel `10000.0` (`endpoint.rs:727, 743`) | sample count (C 1.4.2) | stats differ only when RTT ≥ 10 s |
| D17 | Unstorable fragment | counted as received | counted invalid, not received (`reliable.c:1565-1578`) | unreachable after header validation in both |
| D18 | Counters | `&Counters` struct (11 `u64` fields) | `const uint64_t[11]` view (`reliable.h:78-89`) | same indices and meaning |
| D19 | `Endpoint::reset` | does not clear statistics | clears everything (C 1.4.2) | dream-net never calls reset |
| D20 | Key zeroization | none | `sodium_memzero` on teardown (`netcode.c:4417`, mappings) | → improvement |
| D21 | Sockets | `SocketAddr` API, `getrandom` RNG, `chacha20poly1305` crate | address *strings*, libsodium `randombytes_buf` | wrapper formats addresses, including `[v6]:port` |
| D22 | Logging | `log` crate, silent unless a logger is installed | process-global `printf` hook and level, level NONE by default (`netcode.c:117-119`; `reliable.h` setters) | wrapper must not install a hook that reaches the host |

## 6. Security review

Scope: all network input is hostile. Unauthenticated means anyone who can send UDP to the
port. Authenticated means a peer holding a valid token for this server, which is a real
client: it can harm its own session, and the question is whether it can harm the server or
other peers.

### S1. Connect-token reuse after disconnect gives AEAD nonce reuse. CONFIRMED (reproduced)

- **Path (Rust 1.0.0):** `find_or_add_connect_token_entry` admits a known MAC from the same
  address (`nc-rs:src/server.rs:239-270`, line 268). `connect_client` sets
  `client.sequence = 0` (`:893`), and the encryption mapping takes its keys from the token
  (`:770-780`). The client resets its own sequence (`nc-rs:src/client.rs:368-369`). Both
  directions therefore reuse (key, nonce) pairs.
- **Reproduced:** a temporary integration test, not committed, put a recording UDP relay
  between a dream-net `Client` and `Server`. It connected with a token, disconnected,
  reconnected with the same token from the same socket, and compared the server-to-client
  datagrams of both sessions. The second session was fully established at the dream-net
  level. Its first four per-client datagrams, at sequences 0 to 3 (two keep-alives, two
  payload packets), were **byte-identical** to the first session's, ciphertext included.
  Identical plaintext gives identical ciphertext. Different plaintext under the same (key,
  nonce) is the two-time-pad case, and it also exposes the Poly1305 one-time key at those
  nonces.
- **Reachability:** anyone holding the token. Through dream-net's public API this is
  `Client::connect` with a token that was used before. Through l3i it is `client:connect(token)`
  called twice with the same buffer, which the API permits. The server also encrypts under
  the reused keys, so an observer of both sessions learns relations between the *server's*
  plaintexts, not only the client's.
- **Affected:** netcode-official 1.0.0, so dream-net ≤ 1.1.1. C netcode ≤ 1.4.4
  (GHSA-v29p-3vj4-vg4f, high). **Not affected:** C ≥ 1.4.5.
- **Risk:** High.
- **Regression plan:** after migration, a test in `tests/adversarial.rs` style. The second
  `connect` with a used token must end in `ConnectFailed`, the server must report no second
  `Connected`, and a relay must see no server-to-client datagram repeat a (prefix, sequence)
  pair already seen under that token. Add the same for a token whose first session timed
  out. This cannot be a test today because it fails on 1.1.1.

### S2. Token accepted again after a server restart. CONFIRMED (reproduced)

- **Path (Rust 1.0.0):** the token history and encryption mappings are in-memory
  (`server.rs:360-361, 426-427`). There is no notion of the server's start time in
  `read_connection_request_packet` (`packet.rs:357-424`).
- **Reproduced:** same harness as S1. The `Server` was dropped and a new one created on the
  same address with the same key, and the client reconnected with the same token. The new
  server accepted it, and the first keep-alive was byte-identical to the one from before the
  restart. Global packets (challenge, denied) are affected as well, because the global
  sequence restarts at `1<<63` on every start (`server.rs:404`).
- **Affected:** netcode-official 1.0.0. C ≤ 1.4.4. In C ≥ 1.4.5 it is mitigated only for
  tokens whose lifetime is ≤ `max_connect_token_lifetime` (`netcode.h:304-316`). A token
  issued before the start with a longer lifetime is still accepted, by documented design. l3i
  issues 300-second tokens by default and up to 86 400 s, and dream-net's
  `generate_connect_token` takes any `i32`, with negative meaning never expires.
- **Related design limitation (HYPOTHESIS, both implementations):** a token that lists *N*
  server addresses carries one key pair. Each listed server keeps its own history, so a
  holder can open one session per listed server under the same keys. l3i mints
  single-address tokens, so this is reachable only through `generate_connect_token` with
  several addresses. Not reproduced.
- **Risk:** High.
- **Regression plan:** restart a server in-process on the same key and address and present
  a token issued before the restart (lifetime ≤ the configured maximum). It must be refused.
  Separately, assert that whatever token-issuing API dream-net ends up exposing cannot mint
  a lifetime above the server's maximum (§9 Q1).

### S3. Zero-length datagrams stall the receive loop. CONFIRMED (reproduced)

- **Path:** `socket::receive_packet` returns `None` on `Ok((0, _))` (`nc-rs:src/socket.rs:29`).
  The server (`server.rs:593-601`) and client (`client.rs:505-524`) loops stop at the first
  empty datagram and leave the rest queued until the next update.
- **Reproduced:** a temporary test queued *k* zero-length datagrams at a server before a
  client connected, then counted the server updates (1 ms apart) until the handshake
  completed: k=0 took 97 updates (0.10 s), k=200 took 285 (0.31 s), and k=2000 took 2057
  (2.21 s). Each empty datagram costs one update's worth of receive, so a sustained flood
  from an unauthenticated source starves every client's traffic and lets the kernel buffer
  fill and drop legitimate datagrams.
- **Affected:** netcode-official 1.0.0, and C ≤ 1.4.9 per its 1.4.10 notes ("receive loops
  skip zero-length datagrams"). C 1.4.10 `netcode_socket_receive_packet` `continue`s on 0.
- **Risk:** Medium (cheap remote DoS, pre-auth).
- **Regression plan:** after migration, a test that sprays a few thousand empty datagrams at
  a live server and at a client, then requires an event round trip within a small number of
  updates. It cannot be added now because it fails today. `tests/adversarial.rs` includes
  only a single empty datagram.

### S4. A server disconnect makes a multi-address client move to the next server. CONFIRMED (code path)

- **Path:** a `Disconnect` while `Connected` sets `should_disconnect = Some(Disconnected)`
  (`nc-rs:src/client.rs:594-599`). `update` then tries `connect_to_next_server()` first
  (`:250-256`). dream-net's `Client::update` sees `SendingConnectionRequest` and then
  `Connected` again without a disconnected state in between, so it keeps the established
  `Connection` (`src/client.rs:224-230, 268`).
- **Reachability:** a server or on-path party with the session keys. Only tokens with more
  than one address. Not reproduced.
- **Affected:** 1.0.0, C ≤ 1.4.9. **Risk:** Low.
- **Regression plan:** with two listed servers, disconnect from the first. The client must
  report `Disconnected{Remote}` and must not connect to the second.

### S5. Start floor versus dream-net and l3i token lifetimes. CONFIRMED (code path)

- **Path:** `min_connect_token_expire_timestamp = now + max_connect_token_lifetime` at start
  (`netcode.c:4454`). Requests with `expire ≤ min` are ignored (`:2004`). The default lifetime
  is 30 (`netcode.h:95`).
- **Effect:** dream-net's `tests/netcode.rs` (`World::token`: 30 s, `:79-89`),
  `tests/capture.rs:276-282` (30 s), and l3i's `events_flow_both_ways_over_localhost` (30 s,
  `l3i:tests/udp.rs:87`) all mint in the server's start second. Under 1.4.10 and the default,
  those tokens are refused. Under 1.4.9's `<` they were accepted. Tokens longer than the
  configured lifetime pass, which keeps S2 open for them.
- **Risk:** High as a migration blocker. Security residual as in S2.
- **Plan:** see §9 Q1. `tests/adversarial.rs` deliberately mints accepted tokens with a
  one-hour lifetime so it is independent of this choice as long as the maximum lifetime is
  under an hour.

### S6. Port-0 servers under C. CONFIRMED (code path)

`netcode_socket_create` reads the bound port back into the *socket's* address
(`netcode.c:789-806`), but `server->address = server_address1` keeps port 0
(`netcode.c:4377`). `netcode_process_connection_request` whitelists against
`server->address` (`:4734-4747`). Upstream's own tests avoid it by picking a free port first
(commit `e3c82df`), which is racy. dream-net (`tests/*`, docs) and l3i depend on port 0.
Fix it with a `native/patches/` change that copies the bound port into
`server->address`/`address2`, with a test.

### S7. Window sizes above 16 384. CONFIRMED (code path)

`reliable_config_valid` refuses any buffer size > `RELIABLE_MAX_SEQUENCE_BUFFER_SIZE`
(16 384, `reliable.c:154, 628-646`). dream-net validates `≤ 32768` (`src/config.rs:201-209`),
and `Connection::new` is infallible. `rtt_history_size` and `packet_header_size` are
unbounded `usize` in dream-net but `int` in C. `TransportConfig::validate` must refuse every
config C refuses (16 384 cap, `int` ranges, and the C relationships in D12), so that
`Connection::new` stays infallible. The doc comment "at most 32768" changes, which is a
documented behaviour change.

### S8. C assert and abort paths. CONFIRMED (code path)

- `netcode_assert` is compiled by `NDEBUG` alone (`netcode.h:394-405`). In debug its default
  handler prints and then `__builtin_trap()`/`exit(1)`s (`netcode.c:106-115`). A custom
  handler may return. `reliable_assert` follows `RELIABLE_DEBUG` (derived from `NDEBUG`) and
  calls `exit(1)` after the handler (`reliable.h:316-327`).
- **Remote-reachable asserts:** in the receive paths (`netcode_read_packet`, client/server
  process functions, `reliable_endpoint_receive_packet`, header readers), every assert found
  is structural (non-null pointers, internal length identities such as
  `buffer - start == …`). They are not conditions on packet content. All content checks are
  real `if`s. **NOT AFFECTED** as far as read. This was not fuzzed here; #12 owns that.
- **API-reachable asserts with no release check:** `reliable_endpoint_send_packet` checks
  `packet_bytes > 0` and `num_fragments ≤ max_fragments` only by assert (`reliable.c:981,
  1035-1036`). Netcode's `send_packet`, `server_start`, and `generate_connect_token` *do*
  re-check in release (`netcode.c:3641-3655, 4421-4434`; generate since #173).
- **Requirement:** always build the C with `NDEBUG` (and `NETCODE_RELEASE`,
  `RELIABLE_RELEASE`), including under `cargo test`'s debug profile, so that no assert can
  `exit` the host. The Rust wrapper must validate every argument an assert guards before
  calling. Do not install a custom assert handler that unwinds.

### S9. Fragment reassembly memory: bounded, under-reported. CONFIRMED (code path)

An authenticated peer can open up to `fragment_reassembly_buffer_size` (16) reassemblies,
each allocating `9 + num_fragments × 1186` bytes, at most 33 217 B with 28 fragments
(`rel-rs:src/endpoint.rs:603-607`; C adds 8 B, `reliable.c:1517`). That is about 531 KB per
connection, or about 136 MB across 256 hostile clients. It is freed when superseded, and
`MemoryUsage.reliable` charges 300 B per slot (`src/connection.rs:552`). A peer can also
advance its own receive window by up to 32 767 with one fragment
(`endpoint.rs:609`/`reliable.c:1515`), which only stales its own traffic. **Risk:** Low. Plan:
make `memory_usage` report the true worst case. A soak test with a hostile scripted remote
already exists in spirit (`tests/harness`). Add an assertion on peak allocation in
`tests/alloc.rs` style.

### S10. Token-history exhaustion under C ≥ 1.4.5. HYPOTHESIS

A full history refuses new tokens (D3), and entries live until their token expires. 2048
distinct *valid* tokens within their lifetime would lock out new clients until expiries
free entries. This needs the backend to mint them, or an l3i script with the transport
capability and `connectToken`, which is host-trusted. Not reproduced. Mitigate by capping
token lifetime (§9 Q1) and rate-limiting issuance above dream-net. **Risk:** Low.

### S11. Other netcode items

| Item | Class | Notes |
| --- | --- | --- |
| Replay protection window and wrap | NOT AFFECTED | 64-bit sequences never wrap in practice. Both check before decrypt and advance after (`nc-rs:src/packet.rs:263-295`). `tests/adversarial.rs::forged_packets_from_an_authenticated_address_do_not_disturb_the_session` sprays forged headers at the edges of the 64-bit space from the session's own address, then proves 40 reliable events still arrive in order. |
| Sequence `2^64-1` sentinel (D6) | NOT AFFECTED | needs an authentic packet at that sequence, and no sender reaches it |
| Global-packet nonce reuse on in-process restart (GHSA-3x95) | NOT AFFECTED (1.0.0) | 1.0.0 already reseeds on `start` (`server.rs:400-404`), despite SECURITY.md listing netcode.rs as fixed "from 1.1.0". dream-net never restarts in-process. The cross-process case is S2. |
| Challenge token | NOT AFFECTED | fresh random challenge key per start (`server.rs:399`, `netcode.c:4447`). Nonce is a per-run counter. Response requires an encryption mapping for the source address. |
| Connect-token replay from another address | NOT AFFECTED | refused by both (D1 table). Covered by `a_connect_token_is_refused_from_a_second_address` and `replayed_traffic_delivers_nothing_twice_and_admits_nobody`. |
| Malformed or truncated input, pre-auth | NOT AFFECTED (Rust: `unreachable!` arms are guarded by `AllowedPackets` before dispatch, `server.rs:704`, `client.rs:602`) | covered by `hostile_datagrams_*` tests: every prefix byte at 15 lengths, request shapes with each field wrong, 1500-byte noise, to the server and to a client |
| Pre-auth CPU cost | HYPOTHESIS (accepted design) | a well-formed request costs one 1 KiB XChaCha20-Poly1305 decrypt in both implementations. No byte amplification: replies need a valid token and are smaller. Rate-limit at the host or firewall if needed. |
| Unbounded allocation | NOT AFFECTED | per-client queues ≤ 256 (`server.rs:687`, `client.rs` same), payload ≤ 1200. The Rust server event queue is unbounded but drained every `update` by dream-net. |
| Stale identity / slot reuse | NOT AFFECTED (dream-net `PeerId` generations) | the wrapper must capture `client_id` at the connect callback. Covered by `a_stale_peer_handle_cannot_reach_the_slots_next_occupant`. |
| Key material lifetime | CONFIRMED (code path), Low | Rust 1.0.0 never zeroes keys. C ≥ 1.4.5 does. dream-net's `Server` `Debug` already hides the key. |

### S12. C global state, threads, callbacks, teardown (requirements; CONFIRMED by reading)

- `netcode_init` reference-counts with a plain `int` (`netcode.c:439-466`), not thread-safe.
  `reliable_init` is a no-op (`reliable.c:140-147`). Call `netcode_init` once per process
  behind `std::sync::Once`, and never `netcode_term` (or refcount under a mutex).
- Log level, `printf` hook, and assert hook are process-global in both libraries
  (`netcode.c:117-119`, `reliable.h` setters). Leave the levels at NONE and never route them
  into the host.
- Callbacks: `connect_disconnect_callback` fires inside `netcode_server_update`, and also
  inside `netcode_server_disconnect_client`, `disconnect_all_clients`, `stop`, and `destroy`
  (`netcode.c:4605, 4940`; callers in `stop`/`destroy`, `:4407-4419, 4654`). The callback
  context must outlive `destroy`. Record `(index, connected, client_id)` into bounded Rust
  storage. 1.4.10 guarantees the slot still reads id, address, and user data inside the
  disconnect callback. reliable's `transmit`/`process` callbacks fire synchronously inside
  `send_packet`/`receive_packet`. dream-net's harness re-enters a *different* endpoint from
  inside one (`tests/harness/mod.rs:176`), which is allowed. Re-entering the same endpoint
  is not (`reliable.h` config comment). Panics in closures must be caught at the trampoline
  and resumed after C returns.
- `reliable_endpoint_receive_packet` takes `uint8_t *`. Its body only reads the input
  (`reliable.c:1323-1593`, read here), so passing a pointer derived from `&[u8]` is sound
  today. The binding should document that, or copy into owned scratch.
- Sodium's Windows `CRITICAL_SECTION` is never deleted (upstream ROADMAP item, from
  rocketnet). This matters only if dream-net is unloaded from a DLL.

### S13. What `tests/adversarial.rs` covers (new, passes on 1.1.1)

Written only against dream-net's public API plus `std::net::UdpSocket`, with no legacy crate.
Accepted tokens live 3600 s. Each test is wall-clock bounded (20 s) and the file runs in
about 2.1 s.

1. `hostile_datagrams_before_authentication_admit_nobody`
2. `hostile_datagrams_to_a_client_are_ignored`
3. `forged_packets_from_an_authenticated_address_do_not_disturb_the_session`
4. `replayed_traffic_delivers_nothing_twice_and_admits_nobody` (includes replaying the
   original connection request from a stranger's address)
5. `a_connect_token_is_refused_from_a_second_address` (while held, and after release)
6. `tokens_for_another_protocol_key_or_time_are_refused`
7. `a_stale_peer_handle_cannot_reach_the_slots_next_occupant`

S1, S2, and S3 regressions are specified above and belong in the migrated suite (#12),
because they fail on 1.1.1.

## 7. Recommended pins

| Library | Tag | Commit | Why |
| --- | --- | --- | --- |
| netcode | v1.4.10 (2026-11-10, lightweight tag) | `d6bc96dafe2cc6c9b77903db7ce86f832a2de996` | Latest release. Over v1.4.9 it adds the zero-length datagram fix (S3), the client fixes (D7-D10), history consumption only by the request's own connection, a bounded pending mapping, cleared token bytes, and known-answer tests. Wire identical to v1.4.9 (§5.1). `sodium/` unchanged since v1.4.9 (`git diff --stat v1.4.9 v1.4.10` touches only `netcode.c`/`netcode.h`). `main` is one roadmap commit ahead with no code change. |
| reliable | v1.4.6 (2026-11-10, HEAD of `main`) | `b6245763cedb04d297ced7f196d6a1caeb0da239` | Latest. It carries the fragment-arithmetic hardening (64-bit sizes, overflow refusals), NULL-allocator handling on receive, zeroed reassembly buffers, the 16 384 cap and power-of-two rounding, and empty-packet refusal. |

Both are BSD-3-Clause at those tags (LICENCE text checked). Both READMEs ask for a credit
line, which is not a licence term. File hashes at the pins: `netcode.c cbe93242…faad9`,
`netcode.h c715b4dd…0be`, `sodium/sodium.c b2bf049f…0dd5`, `sodium/sodium.h 790c509b…fe9`,
`reliable.c 759bb1aa…a7fa`, `reliable.h 51fdd944…d9d3` (SHA-256). The provenance manifest
owner (#4) should record the full values.

### Vendored libsodium subset (flags for #4)

- `sodium/` is **two amalgamated files** (`sodium.c` 196 739 B, `sodium.h` 48 771 B) plus
  `NOTES.md`. They are not upstream files. `SODIUM_VERSION_STRING "1.0.22"`. The 17
  concatenated upstream sources are `version, utils, verify, runtime,
  randombytes_sysrandom, randombytes, core, chacha20-ref, dolbeau chacha20-ssse3,
  dolbeau chacha20-avx2, stream_chacha20, core_hchacha20, poly1305_donna, poly1305-sse2,
  onetimeauth_poly1305, aead_chacha20poly1305, aead_xchacha20poly1305`.
- Licence: ISC header on both files ("Copyright (c) 2013-2026"). Permissive. The NOTICE must
  carry it.
- Concerns. **(a)** Provenance cannot be checked file-for-file against a libsodium tarball.
  The amalgamation has to be regenerated from libsodium 1.0.22 by the procedure in
  `NOTES.md` and diffed, otherwise the "byte-for-byte upstream crypto text" claim is
  unverified. **(b)** `NOTES.md` says on PS4/PS5 `randombytes_sysrandom_buf` is empty, so keys
  would be predictable. That does not affect dream-net's targets but should be recorded.
  **(c)** The SSSE3/AVX2 kernels use runtime CPU dispatch with target attributes, so the
  Clang build (#5) must not strip them or force flags that break dispatch. **(d)** Every
  external `crypto_*`/`sodium_*`/`randombytes_*` symbol needs the dream-net prefix
  (ledger decision 4). **(e)** The Windows lock leak noted in S12.

## 8. Replacement map

| File | Legacy item | Replacement |
| --- | --- | --- |
| `Cargo.toml` | `netcode-official =1.0.0`, `reliable =1.3.4`, `serialize-official =2.4.0`, `ctutils >=0.4.4` floor | `dream-net-native` (path + exact version). Drop `ctutils` (its only consumer was netcode's Poly1305). `sha2` stays. |
| `src/lib.rs:103-106` | `pub use netcode::{CONNECT_TOKEN_BYTES, KEY_BYTES, Key, USER_DATA_BYTES, UserData, generate_connect_token, generate_key}` | dream-net's own items with identical names, types (`[u8; 32]`, `[u8; 256]`, `usize` consts), and signature. `generate_connect_token` returns `Result<[u8; 2048], dream_net::…Error>`. Keep `Display` texts. |
| `src/lib.rs:5-8, 52-54` | docs naming the Rust ports | name the vendored C |
| `src/error.rs:167-196` | `Error::Netcode(netcode::Error)` | `Error::Netcode(dream_net::NetcodeError)` (or `TransportError`), with variants mirroring `InvalidConnectToken`, `EncryptFailed`, `DecryptFailed`, `InvalidPayloadSize(usize)`, `InvalidServerAddresses`, `InvalidMaxClients(usize)`, `Io(io::Error)`, `#[non_exhaustive]`, same `Display` text. The type path changes, which is semver-visible for anyone naming `netcode::Error`. l3i does not. |
| `src/config.rs:11-18` | `netcode::MAX_PAYLOAD_BYTES`, `reliable::{FRAGMENT,MAX_PACKET}_HEADER_BYTES` | dream-net consts 1200 / 5 / 9, statically asserted against the C headers in `native/` |
| `src/config.rs:201-224` | `≤ 32768` windows, unbounded sizes | S7: ≤ 16 384, `int`-range checks, every C refusal |
| `src/config.rs:296-314` | `reliable_config() -> reliable::Config` | `-> dream_net_native::reliable::Config` (same 14 public fields) or a dream-net-owned `ReliableConfig`. It is public, so it must exist either way. Benches mutate `rtt_history_size`. |
| `src/connection.rs:246, 254, 374-399, 414, 440, 454, 469, 482, 501` | `reliable::Endpoint` | the native wrapper with the same method subset (API mirror spec below) |
| `src/connection.rs:511` | `reliable_counters() -> &reliable::Counters` | `-> &ReliableCounters` (same 11 fields, `#[non_exhaustive]`, `Clone, Default, PartialEq, Eq, Debug`), refreshed by the wrapper after every mutating call |
| `src/stats.rs:34-48` | `from_endpoint(&reliable::Endpoint)` | same over the wrapper |
| `src/sequence.rs:46, 53` | `reliable::sequence_greater_than/less_than` | inline the half-space comparison in `Seq16` (pure, no FFI). Proptests already pin it. |
| `src/server.rs` | `netcode::Server`, `ServerEvent`, `DisconnectReason`, `Key`, `UserData` | wrapper `Server` (API mirror spec below), events built from the connect/disconnect callback with `client_id` captured. Port 0 per S6. |
| `src/client.rs` | `netcode::Client`, `ClientState`, `CONNECT_TOKEN_BYTES` | wrapper `Client`. `ClientState` mapping from C ints `-6..=3` (`netcode.h:97-106`). |
| `src/wire.rs:38` | `serialize::{BitReader, BitWriter, bits_required}` | `src/bits.rs` (#8). `tests/wire_golden.rs` byte-for-byte. |
| `tests/wire.rs:19, 110` | `serialize` reference decoder | an independent decoder over `src/bits.rs` or a hand-rolled bit reader (#8) |
| `tests/netcode.rs:409` | bare `netcode::Client` | wrapper client from `dream-net-native` (dev-dependency), or a test-only raw client |
| `tests/harness/mod.rs`, `tests/connection.rs:123, 441-448, 956`, `fuzz/Cargo.toml` | scripted `reliable::Endpoint`, `MAX_PACKET_HEADER_BYTES` | the native reliable wrapper. `fuzz/Cargo.toml` depends on `dream-net-native` instead of `reliable`. |
| `benches/netcode.rs:146-210` | `RawWorld` over `netcode::*` | the native netcode wrapper |
| `benches/connection.rs:268-276` | `reliable::Endpoint::new/update` | the native reliable wrapper |
| `NOTICE.md` | Rust-port notices | C netcode, C reliable, libsodium ISC |

### API mirror spec

This is the exact subset dream-net (src, tests, benches, fuzz) calls. The binding agents must
reproduce these semantics, not C's where they differ.

**netcode** (module `dream_net_native::netcode`):

| Item | Signature (1.0.0) | Semantics to reproduce |
| --- | --- | --- |
| consts | `CONNECT_TOKEN_BYTES = 2048`, `KEY_BYTES = 32`, `USER_DATA_BYTES = 256`, `MAX_PAYLOAD_BYTES = 1200`, `MAX_CLIENTS = 256`, `MAX_SERVERS_PER_CONNECT = 32` | equal to C headers |
| types | `type Key = [u8; 32]`, `type UserData = [u8; 256]` | plain arrays |
| `generate_key() -> Key` | | OS CSPRNG. Panics only if the OS RNG fails. |
| `generate_connect_token(public: &[SocketAddr], internal: &[SocketAddr], expire_seconds: i32, timeout_seconds: i32, client_id: u64, protocol_id: u64, key: &Key, user_data: &UserData) -> Result<[u8; 2048], Error>` | | `Err(InvalidServerAddresses)` if lengths differ or are outside `1..=32`, checked in Rust (C takes one count). Negative expiry means `u64::MAX` expiry. Wall-clock create time. |
| `Server::new(public: SocketAddr, protocol_id: u64, key: &Key, time: f64) -> Result<Server, Error>` | | binds `0.0.0.0`/`[::]` on the port, IPv6 only-v6. **Port 0 means ephemeral, advertised by `address()`/`port()`** (S6). `Io` on bind failure (map C create error codes to `io::ErrorKind` where possible). |
| `start(&mut self, max_clients: usize) -> Result<(), Error>` | | `InvalidMaxClients` outside `1..=256`, checked in Rust. Restarting stops first. |
| `update(&mut self, time: f64)` | | receive all, send keep-alives, timeouts. Queue events in order. |
| `next_event(&mut self) -> Option<ServerEvent>` | `ServerEvent::{ClientConnected{client_index}, ClientDisconnected{client_index, reason: DisconnectReason::{TimedOut, ClientDisconnect, ServerDisconnect}}}` | FIFO, bounded. Built from the C callback. The client id must be the one at connect time. |
| `client_id(&self, i) -> u64` | 0 if not connected | |
| `client_address(&self, i) -> Option<SocketAddr>` | | |
| `client_user_data(&self, i) -> Option<&UserData>` | | borrow tied to `&self`. Copy into Rust storage at connect. |
| `send_packet(&mut self, i, payload: &[u8]) -> Result<(), Error>` | | **`Err(InvalidPayloadSize(len))` for `len == 0 \|\| len > 1200`, checked in Rust** (C returns void). `Ok(())` and no-op if not running, the index is out of range, or the slot is not connected. |
| `receive_packet(&mut self, i) -> Option<(Vec<u8>, u64)>` | | `None` if not running or out of range. Copy and free the C packet. A borrowed-buffer variant is welcome for performance. |
| `disconnect_client(&mut self, i)` | | no-op unless connected. Sends redundant disconnects. Queues `ClientDisconnected{ServerDisconnect}`. |
| `stop(&mut self)` | | disconnect all, then reset. Called from dream-net's `Drop`. |
| `address(&self) -> SocketAddr`, `max_clients(&self) -> usize`, `num_connected_clients(&self) -> usize` | | (benches use the last two) |
| `Client::new(bind: SocketAddr, time: f64) -> Result<Client, Error>` | | |
| `Client::connect(&mut self, token: &[u8; 2048]) -> Result<(), Error>` | | disconnects first. Unparseable token gives `Err(InvalidConnectToken)` and state `InvalidConnectToken`. |
| `Client::{update(time), state() -> ClientState, receive_packet() -> Option<(Vec<u8>, u64)>, send_packet(&[u8]) -> Result<(), Error>, disconnect(), server_address() -> Option<SocketAddr>, port() -> u16}` | `ClientState::{ConnectTokenExpired, InvalidConnectToken, ConnectionTimedOut, ConnectionResponseTimedOut, ConnectionRequestTimedOut, ConnectionDenied, Disconnected, SendingConnectionRequest, SendingConnectionResponse, Connected}`, `is_disconnected()` true for the first seven | `send_packet` size check as on the server. `Drop` disconnects. |
| `Error` | variants in §8 row `src/error.rs` | `Display` text as 1.0.0 (`nc-rs:src/error.rs`). `source()` only for `Io`. |

**reliable** (module `dream_net_native::reliable`):

| Item | Signature (1.3.4) | Semantics to reproduce |
| --- | --- | --- |
| consts | `MAX_PACKET_HEADER_BYTES = 9`, `FRAGMENT_HEADER_BYTES = 5` | |
| `Config` | `{ name: String, max_packet_size, fragment_above, max_fragments, fragment_size, ack_buffer_size, sent_packets_buffer_size, received_packets_buffer_size, fragment_reassembly_buffer_size, rtt_history_size, packet_header_size: usize, rtt_smoothing_factor, packet_loss_smoothing_factor, bandwidth_smoothing_factor: f32 }`, `Clone, Debug, Default` (defaults `rel-rs:src/endpoint.rs:43-62`) | plain struct, fields mutable |
| `Endpoint::new(Config, time: f64) -> Endpoint` | | panics on an invalid config (1.3.4 asserts at `endpoint.rs:259-267`). The wrapper panics on C's NULL with the reason. dream-net guarantees validity first (S7). |
| `next_packet_sequence(&self) -> u16` | | |
| `send_packet(&mut self, data: &[u8], transmit: impl FnMut(u16, &[u8]))` | | **panics on empty** (C would send a header-only packet). Over `max_packet_size`: count `num_packets_too_large_to_send` and return without calling `transmit`. `transmit` is called synchronously, one or more times (fragments), with a slice valid for that call only, before `send_packet` returns. |
| `receive_packet(&mut self, data: &[u8], process: impl FnMut(u16, &[u8]) -> bool)` | | 1.3.4 panics on empty, and dream-net never passes empty (`src/connection.rs:367`). The C counts it as invalid, and keeping that is fine. `process` is called synchronously at most once per accepted packet, including once per *completed reassembly*. `true` acks and records the packet, `false` leaves it unacked and its piggy-backed acks discarded. Stale, duplicate, invalid, and oversized inputs never reach `process`. Header validation: §5.2. |
| `update(&mut self, time: f64)` | | recomputes rtt, jitter, loss, and bandwidth. Time is non-decreasing. |
| `drain_acks(&mut self) -> impl Iterator<Item = u16>` | | acked sequences since the last drain or clear, in the order they were recorded, then empty. At most `ack_buffer_size` are held, and overflow drops acks (logged). |
| `clear_acks(&mut self)` | | (tests/harness) |
| `rtt, rtt_min, rtt_max, rtt_avg, jitter_avg_vs_min_rtt, jitter_max_vs_min_rtt, jitter_stddev_vs_avg_rtt, packet_loss (&self) -> f32`; `bandwidth(&self) -> Bandwidth{sent_kbps, received_kbps, acked_kbps: f32}` | | milliseconds, percent, kbps. `&self` reads only (needed for `Sync`). |
| `counters(&self) -> &Counters` | `Counters{num_packets_sent, num_packets_received, num_packets_acked, num_packets_stale, num_packets_invalid, num_packets_too_large_to_send, num_packets_too_large_to_receive, num_fragments_sent, num_fragments_received, num_fragments_invalid, num_packets_duplicate: u64}`, `#[non_exhaustive]` | same order as `reliable.h:78-88` |
| `Debug for Endpoint` | | needed by `#[derive(Debug)] Connection` |
| `sequence_greater_than(u16, u16) -> bool`, `sequence_less_than` | `rel-rs:src/lib.rs:102-109` | pure. Keep in Rust. |
| auto traits | `Endpoint: Send + Sync + Unpin + UnwindSafe + RefUnwindSafe` | §4.10 |

## 9. Review of the shared decisions, and open questions

Things in `NATIVE_TRANSPORT_CAMPAIGN.md` that I believe are wrong or risky:

1. **Decision 8 (auto traits).** The intent is right. The facts: `Server` and `Client` are
   *not* `Send`/`Sync` in 1.1.1 (capture sink). `Connection` is `Send + Sync + UnwindSafe +
   RefUnwindSafe`, and that is the one at risk (§4.10). Suggested ledger wording: "`Connection`
   keeps Send, Sync, UnwindSafe, and RefUnwindSafe. No public type loses an auto trait."
   Add a compile-time test (`fn assert_send_sync<T: Send + Sync>()`) to the suite.
2. **Decision 5 ("same names and semantics").** This should except the security semantics the
   C fixes on purpose (D1, D2, D5, D8). Mirroring 1.0.0 there would re-import S1–S4. It should
   also say which side wins where they differ: payload-size errors, empty-input panics, and
   port 0 follow the Rust API. Token and receive rules follow C 1.4.10.
3. **Decision 9 (interop).** The wire is proven identical (§5). But an old-new interop test
   that reconnects with a reused token, or that mints a 30-second token in the server's start
   second, *will* fail against the new server by design. The interop crate should assert those
   refusals rather than treat them as regressions.
4. **Decision 2 (patches).** At least one patch is needed (S6, port 0). Plan for it in #4/#5.
5. **Decisions 3 and 6.** The libsodium SIMD dispatch and `NDEBUG` must be part of the
   verified Clang configuration (S8, §7). A debug-profile `cargo test` must still compile the
   C with `NDEBUG`.

Open questions for the director:

- **Q1. The token-lifetime model (S2, S5).** C needs `max_connect_token_lifetime`.
  `ServerConfig` is an exhaustive struct that l3i builds by literal, so a new field is
  breaking. Options:
  - (a) A fixed internal value (for example 30 s, upstream's default), with dream-net's and
    l3i's tests minting in a later second or with longer tokens. Longer tokens then reopen
    S2 unless dream-net caps the lifetime in its own `generate_connect_token`. That cap is
    also a behaviour change for l3i's default 300 s and maximum 86 400 s.
  - (b) An additive API, such as `Server::with_options` or a setter, plus a default.
  - (c) `#[non_exhaustive]` on `ServerConfig` in a breaking release.

  This also decides whether l3i's `connectToken` range must shrink. That belongs in #15.
- **Q2.** Should the wrapper patch C for port 0 (S6), or bind a pre-picked port? The second
  is racy, so I recommend a patch with a test.
- **Q3.** Pin netcode v1.4.10 rather than the brief's v1.4.9? I recommend v1.4.10 (§7).
- **Q4.** Single-use tokens change observable behaviour: a Luau script that reconnects with a
  stored token gets `ConnectFailed` after migration. Release notes and the site should say
  so, and l3i's docs should tell scripts to request a fresh token.
- **Q5.** `TransportConfig` tightening (S7) changes what `validate` accepts. Is that a minor
  release, or a breaking one under the crate's policy?
- **Q6.** Multi-address tokens (S2 note, S4): should dream-net document or refuse tokens
  with more than one address, given that each listed server admits the same keys once?

## Appendix A. netcode known-answer program

Built and run as shown in §5.1, with the inputs from `nc-rs:src/wire_compat.rs`.

```c
/* Known-answer check: reproduce netcode-official 1.0.0's tests/vectors/*.bin with the C
   reference, using the inputs in netcode-official's src/wire_compat.rs. Unity build. */
#include "netcode.c"
static void out(const char *dir, const char *name, const uint8_t *b, int n){
    char p[512]; snprintf(p,sizeof p,"%s/%s",dir,name); FILE*f=fopen(p,"wb"); fwrite(b,1,n,f); fclose(f);
}
int main(int argc,char**argv){
    const char*dir=argv[1];
    netcode_init();
    uint64_t pid=0x1122334455667788ULL, cid=0x0102030405060708ULL;
    uint64_t create=1720000000ULL, expire=1720000100ULL, chseq=1000, pseq=0x1122334455ULL;
    uint8_t priv_key[32]={0x60,0x6a,0xbe,0x6e,0xc9,0x19,0x10,0xea,0x9a,0x65,0x62,0xf6,0x6f,0x2b,0x30,0xe4,
        0x43,0x71,0xd6,0x2c,0xd1,0x99,0x27,0x26,0x6b,0x3c,0x60,0xf4,0xb7,0x15,0xab,0xa1};
    uint8_t c2s[32],s2c[32],chk[32],pk[32],ud[256],nonce[24];
    for(int i=0;i<32;i++){c2s[i]=i;s2c[i]=255-i;chk[i]=(uint8_t)(i*2);pk[i]=i+17;}
    for(int i=0;i<256;i++)ud[i]=(uint8_t)i;
    for(int i=0;i<24;i++)nonce[i]=100+i;
    struct netcode_address_t addrs[2];
    netcode_parse_address("127.0.0.1:40000",&addrs[0]);
    netcode_parse_address("[::1]:50000",&addrs[1]);

    struct netcode_connect_token_private_t pt; memset(&pt,0,sizeof pt);
    pt.client_id=cid; pt.timeout_seconds=15; pt.num_server_addresses=2;
    memcpy(pt.server_addresses,addrs,sizeof addrs);
    memcpy(pt.client_to_server_key,c2s,32); memcpy(pt.server_to_client_key,s2c,32); memcpy(pt.user_data,ud,256);
    uint8_t ptb[1024]; memset(ptb,0,sizeof ptb);
    netcode_write_connect_token_private(&pt,ptb,1024);
    out(dir,"private_connect_token_plaintext.bin",ptb,1024);
    uint8_t pte[1024]; memcpy(pte,ptb,1024);
    if(netcode_encrypt_connect_token_private(pte,1024,NETCODE_VERSION_INFO,pid,expire,nonce,priv_key)!=NETCODE_OK) return 2;
    out(dir,"private_connect_token_encrypted.bin",pte,1024);

    struct netcode_connect_token_t ct; memset(&ct,0,sizeof ct);
    memcpy(ct.version_info,NETCODE_VERSION_INFO,13); ct.protocol_id=pid; ct.create_timestamp=create; ct.expire_timestamp=expire;
    memcpy(ct.nonce,nonce,24); memcpy(ct.private_data,pte,1024); ct.timeout_seconds=15; ct.num_server_addresses=2;
    memcpy(ct.server_addresses,addrs,sizeof addrs); memcpy(ct.client_to_server_key,c2s,32); memcpy(ct.server_to_client_key,s2c,32);
    uint8_t ctb[2048]; memset(ctb,0,sizeof ctb);
    netcode_write_connect_token(&ct,ctb,2048);
    out(dir,"connect_token.bin",ctb,2048);

    struct netcode_challenge_token_t ch; ch.client_id=cid; memcpy(ch.user_data,ud,256);
    uint8_t chb[300]; memset(chb,0,sizeof chb);
    netcode_write_challenge_token(&ch,chb,300);
    if(netcode_encrypt_challenge_token(chb,300,chseq,chk)!=NETCODE_OK) return 3;
    out(dir,"challenge_token_encrypted.bin",chb,300);

    uint8_t buf[2048]; int n;
    struct netcode_connection_request_packet_t rq; memset(&rq,0,sizeof rq);
    rq.packet_type=0; memcpy(rq.version_info,NETCODE_VERSION_INFO,13); rq.protocol_id=pid; rq.connect_token_expire_timestamp=expire;
    memcpy(rq.connect_token_nonce,nonce,24); memcpy(rq.connect_token_data,pte,1024);
    n=netcode_write_packet(&rq,buf,sizeof buf,pseq,pk,pid); out(dir,"packet_request.bin",buf,n);
    struct netcode_connection_denied_packet_t dn={1};
    n=netcode_write_packet(&dn,buf,sizeof buf,pseq,pk,pid); out(dir,"packet_denied.bin",buf,n);
    struct netcode_connection_challenge_packet_t cp; cp.packet_type=2; cp.challenge_token_sequence=chseq; memcpy(cp.challenge_token_data,chb,300);
    n=netcode_write_packet(&cp,buf,sizeof buf,pseq,pk,pid); out(dir,"packet_challenge.bin",buf,n);
    struct netcode_connection_response_packet_t rp; rp.packet_type=3; rp.challenge_token_sequence=chseq; memcpy(rp.challenge_token_data,chb,300);
    n=netcode_write_packet(&rp,buf,sizeof buf,pseq,pk,pid); out(dir,"packet_response.bin",buf,n);
    struct netcode_connection_keep_alive_packet_t ka; ka.packet_type=4; ka.client_index=7; ka.max_clients=32;
    n=netcode_write_packet(&ka,buf,sizeof buf,pseq,pk,pid); out(dir,"packet_keep_alive.bin",buf,n);
    struct netcode_connection_payload_packet_t *pp=netcode_create_payload_packet(1200,NULL,NULL);
    for(int i=0;i<1200;i++)pp->payload_data[i]=(uint8_t)i;
    n=netcode_write_packet(pp,buf,sizeof buf,pseq,pk,pid); out(dir,"packet_payload.bin",buf,n);
    struct netcode_connection_disconnect_packet_t dc={6};
    n=netcode_write_packet(&dc,buf,sizeof buf,pseq,pk,pid); out(dir,"packet_disconnect.bin",buf,n);
    netcode_term();
    printf("ok %s\n", NETCODE_VERSION_FULL);
    return 0;
}
```

## Appendix B. reliable exchange programs

C side (`rel.c`, built against `reliable.c` v1.4.6 with `-DNDEBUG`):

```c
#include "reliable.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static uint8_t q[2][4096][1300]; static int qlen[2][4096]; static int qn[2];
static int dgram_index[2];

static void tx(void *ctx, uint64_t id, uint16_t seq, uint8_t *d, int n){
    (void)ctx; (void)seq;
    int side=(int)id;
    printf("TX %d %d ", side, n); for(int i=0;i<n;i++) printf("%02x", d[i]); printf("\n");
    int k=dgram_index[side]++;
    if (k % 3 == 2) return; /* drop every third datagram */
    memcpy(q[side][qn[side]], d, n); qlen[side][qn[side]]=n; qn[side]++;
}
static int proc_(void *ctx, uint64_t id, uint16_t seq, uint8_t *d, int n){
    (void)ctx;
    unsigned h=2166136261u; for(int i=0;i<n;i++){h^=d[i];h*=16777619u;}
    printf("RX %d %u %d %08x\n",(int)id,seq,n,h);
    return 1;
}
int main(void){
    reliable_init();
    struct reliable_endpoint_t *e[2];
    for(int s=0;s<2;s++){
        struct reliable_config_t c; reliable_default_config(&c);
        strcpy(c.name, s? "b":"a");
        c.id=s; c.max_packet_size=32768; c.fragment_above=1191; c.max_fragments=28; c.fragment_size=1186;
        c.ack_buffer_size=64; c.sent_packets_buffer_size=256; c.received_packets_buffer_size=256;
        c.fragment_reassembly_buffer_size=16; c.rtt_smoothing_factor=0.0025f; c.rtt_history_size=128;
        c.packet_loss_smoothing_factor=0.1f; c.bandwidth_smoothing_factor=0.1f; c.packet_header_size=28;
        c.transmit_packet_function=tx; c.process_packet_function=proc_;
        e[s]=reliable_endpoint_create(&c,0.0);
        if(!e[s]){printf("create failed\n");return 1;}
    }
    static uint8_t payload[32768];
    int sizes[]={1,10,1191,1192,5000,32768,77,300};
    double t=0.0;
    for(int frame=0; frame<120; frame++){
        t += 1.0/60.0;
        for(int s=0;s<2;s++) reliable_endpoint_update(e[s],t);
        for(int s=0;s<2;s++){
            int sz=sizes[(frame*3+s)%8];
            for(int i=0;i<sz;i++) payload[i]=(uint8_t)(i*7+frame+s);
            reliable_endpoint_send_packet(e[s],payload,sz);
        }
        for(int s=0;s<2;s++){
            int other=1-s;
            for(int i=0;i<qn[s];i++) reliable_endpoint_receive_packet(e[other],q[s][i],qlen[s][i]);
            qn[s]=0;
        }
        for(int s=0;s<2;s++){
            int n; const uint16_t *a=reliable_endpoint_get_acks(e[s],&n);
            printf("ACKS %d",s); for(int i=0;i<n;i++) printf(" %u",a[i]); printf("\n");
            reliable_endpoint_clear_acks(e[s]);
        }
    }
    for(int s=0;s<2;s++){
        const uint64_t *c=reliable_endpoint_counters(e[s]);
        printf("COUNTERS %d",s); for(int i=0;i<RELIABLE_ENDPOINT_NUM_COUNTERS;i++) printf(" %llu",(unsigned long long)c[i]); printf("\n");
        float sk,rk,ak; reliable_endpoint_bandwidth(e[s],&sk,&rk,&ak);
        printf("STATS %d %.3f %.3f %.3f %.3f %.3f\n",s,reliable_endpoint_rtt(e[s]),reliable_endpoint_rtt_min(e[s]),reliable_endpoint_rtt_max(e[s]),reliable_endpoint_packet_loss(e[s]),sk);
    }
    return 0;
}
```

Rust side (a standalone crate with `reliable = "=1.3.4"`, line for line). It mirrors the
above with `Endpoint::new(Config{..same values..}, 0.0)`, `update(t)`, and
`send_packet(&payload[..sz], |_, d| …)`. It prints `TX`, drops every third datagram per side,
and queues the rest. It uses `receive_packet(&d, |seq, p| { print RX; true })`, prints
`drain_acks()` as `ACKS`, then prints `COUNTERS` in `reliable.h` index order and
`STATS rtt rtt_min rtt_max packet_loss sent_kbps` with `{:.3}`.
