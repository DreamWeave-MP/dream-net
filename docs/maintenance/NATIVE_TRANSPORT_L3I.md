# Native transport and l3i

Whether l3i's Luau network surface survives dream-net's move to the native transport, verified
without modifying l3i: what was built and run, the contract l3i relies on with the evidence for
each claim, every difference a script author or l3i maintainer will see, and the proposed l3i
patch. Tracked in [#15](https://github.com/DreamWeave-MP/dream-net/issues/15); the protocol
side is in [NATIVE_TRANSPORT_COMPATIBILITY.md](NATIVE_TRANSPORT_COMPATIBILITY.md).

Everything below ran on Linux x86_64 (rustc and cargo 1.100.0, clang 23.1.2) on 2026-11-18,
against l3i 3.0.0 at `2159fa2` (read-only; every run used a copy) and this tree.

*Note, 2026-11-18:* those runs predate two changes on dream-net's side. The `cc` pin became a
semver floor (`cc = "1.2.8"`), so `--precise cc=1.11.2` is no longer needed, and the C and its
bindings were folded from the separate crate `dream-net-native` into dream-net itself, so l3i's
lockfile gains no `dream-net-native` entry. The transcripts below are kept as they ran;
`tools/check-l3i` now also takes `--target DIR` to put the multi-GB target directory on a disk.

**Naming.** The issue calls the module `@dream/net`. l3i registers extension **`dream.udp`**,
module **`@dream/udp`**, userdata types `dream.udp.Server`, `dream.udp.Client` and
`dream.udp.Schema` (`l3i:src/udp.rs:47-49`). No l3i registers `@dream/net`: Jess's untracked
`MJ12/` sample requires `@dream/net` and cannot load with any l3i, before or after this
migration. Jess's tracked code depends on l3i 2.11.0 from crates.io (not on dream-net directly)
and touches `@dream/udp` only in two tests that build a schema and a client without connecting
(`jess:tests/cli/toplevel.rs`, `jess:tests/lua/network_capability.rs`); it sees this change only
when it moves to an l3i built on it.

## Results

| What | Result |
| --- | --- |
| `cargo check --all-targets` (lib, tests, benches, examples) | **passes** unchanged |
| `udp::` integration tests (4) | **3 pass; `events_flow_both_ways_over_localhost` fails**, every time (3 runs), from the start floor alone (below) |
| The same with the one-line test change proposed below | **4 pass** |
| Proposed contract test `udp_contract::buffers_peers_and_fields_hold_across_many_frames` (Luau-level stress, peer origin, re-entrancy guard, field names) | **passes** against this tree and against dream-net 1.1.1 |
| `benches/udp.rs`, `cargo bench --bench main -- --test udp` (Criterion test mode, no measurement) | **compiles and runs**: `udp_bridge/client sendEvent + flush`, `udp_bridge/client send, server update + pollInto`, `udp_bridge/idle update + empty pollInto, both ends` all `Success` |
| Lockfile | the override itself changes l3i's `Cargo.lock` (13 packages leave, `dream-net-native` arrives); with this tree's exact `cc = "=1.11.2"` pin, l3i must also run `cargo update -p cc --precise 1.11.2` (resolution fails otherwise); with a caret `cc` requirement no `cc` change is needed (verified on a copy with `cc = "1"`: l3i's locked cc 1.9.0 built the native archive and the udp tests passed) |

### Commands

`tools/check-l3i` does every step on a scratch copy (`/tmp/claude-1000/dn-l3i/l3i`, target dir
`/tmp/claude-1000/dn-l3i/target`); `--overlay DIR` lays proposed files over the copy,
`--baseline` runs the same steps against dream-net 1.1.1 from crates.io.

```text
$ tools/check-l3i                                   # without --precise
error: failed to select a version for `cc`.
    ... required by package `dream-net-native v0.1.0 (.../native)`
versions that meet the requirements `=1.11.2` are: 1.11.2
  previously selected package `cc v1.9.0`
    ... which satisfies dependency `cc = "^1"` (locked to 1.9.0) of package `l3i v3.0.0`

$ tools/check-l3i --precise cc=1.11.2 --bench-smoke
== cargo update -p cc --precise 1.11.2
    Removing aead v0.6.1
    Updating cc v1.9.0 -> v1.11.2
    Removing chacha20 v0.10.2, chacha20poly1305 v0.11.0, cipher v0.5.2, cmov v0.5.4,
             ctutils v0.4.8, inout v0.2.5, netcode-official v1.0.0, poly1305 v0.9.1,
             rand_core v0.10.1, reliable v1.3.4, serialize-official v2.4.0, universal-hash v0.6.1
      Adding dream-net v1.1.1 (this checkout), dream-net-native v0.1.0 (this checkout/native)
== cargo check --all-targets
    Finished `dev` profile [unoptimized + debuginfo] target(s)
== cargo test --test integration -- udp::
test udp::the_plan_supplies_the_transport_clock ... ok
test udp::client_creation_is_gated_by_the_transport_capability ... ok
test udp::schema_builds_from_options_and_reports_ids ... ok
test udp::events_flow_both_ways_over_localhost ... FAILED
thread 'udp::events_flow_both_ways_over_localhost' panicked at tests/udp.rs:140:5:
handshake or events did not complete
test result: FAILED. 3 passed; 1 failed; 0 ignored; 0 measured; 252 filtered out; finished in 3.21s

$ tools/check-l3i --precise cc=1.11.2 --overlay <wait>       # mint after the start second
test udp::events_flow_both_ways_over_localhost ... ok           (4 passed)
== cargo bench --bench main -- --test udp
Testing udp_bridge/client sendEvent + flush                       Success
Testing udp_bridge/client send, server update + pollInto          Success
Testing udp_bridge/idle update + empty pollInto, both ends        Success

$ tools/check-l3i --precise cc=1.11.2 --overlay <31-second token>
test udp::events_flow_both_ways_over_localhost ... ok           (4 passed)
$ tools/check-l3i --precise cc=1.11.2 --overlay <proposed: 60-second token>
test udp::events_flow_both_ways_over_localhost ... ok           (4 passed)

$ tools/check-l3i --precise cc=1.11.2 --overlay <contract> --filter udp --show-output
test udp_contract::buffers_peers_and_fields_hold_across_many_frames ... ok   (5 passed)
memoryUsage per server with 2 peers   104336  1162370  41632  9084
client memoryUsage                    581185

$ tools/check-l3i --baseline --overlay <contract> --filter udp --show-output   # dream-net 1.1.1
test udp_contract::buffers_peers_and_fields_hold_across_many_frames ... ok   (5 passed)
memoryUsage per server with 2 peers   105040  100992  41632  9084
client memoryUsage                    50496
```

### The one failing test

`l3i:tests/udp.rs:87` creates a server (`udp.server{ address = '127.0.0.1:0', ... }`) and, in
the same Luau chunk, mints `server:connectToken(id, 30, 5)`: a 30-second token in the server's
start second. The C netcode records `floor = start second + max_connect_token_lifetime` (30 with
`Server::new`) and refuses every token whose expiry is not later than the floor (campaign
decision 17, audit D2/S5): `mint + 30 <= start + 30`. The request is never answered, so the
client is still connecting when the test's 3000-frame budget (about 3 seconds) runs out.

The start floor is the only cause:

- With the token minted after the wall clock has left the start second (the `<wait>` overlay
  above), the test passes.
- With a 31-second token minted in the start second, it passes (`mint + 31 > start + 30`);
  with 30 it fails: the boundary is exactly the floor.
- The same unmodified test passes against dream-net 1.1.1 (`--baseline`), which has no floor.

The refusal is deliberate and stays: without it, a server restarted on the same key would
accept a token used before the restart, reopening a session under the same keys (audit S2).
`interop/tests/matrix.rs` asserts it for every client and server pairing.

## Contract

How each claim was verified: **Luau** = from Luau through l3i on a scratch copy (l3i's own tests
or the proposed contract test), **Rust** = at dream-net's public API in this repository's tests,
**source** = by reading l3i's and dream-net's code, cited.

| Claim | Evidence | Verified at |
| --- | --- | --- |
| Extension `dream.udp`, module `@dream/udp`, the three userdata types and their members register and work unchanged | l3i compiles unchanged; `udp::schema_builds_from_options_and_reports_ids`, `udp::client_creation_is_gated_by_the_transport_capability`, `udp::the_plan_supplies_the_transport_clock` pass; registration is l3i code (`l3i:src/udp.rs:532-626`), and every dream-net item it binds keeps its name and signature (`tests/api_surface.rs`) | Luau |
| `Server`/`Client` handles are trusted userdata; no native pointer and no key reaches Luau | `l3i:src/udp.rs:301-326`: the key lives in the private `TokenIssuer` inside the userdata; `connectToken` returns only the 2048-byte token; no member returns the key, an address of native memory, or the `dream_net::Server`. dream-net itself keeps no key: `Server::new` hands it to the C netcode server, which zeroes it on destruction (audit D20), and `Server`'s `Debug` prints address, slots, count, fingerprint and time only (`src/server.rs` `impl Debug`). The C pointers the native backend adds are private fields of `dream-net-native` types. l3i's `unsafe impl Userdata for Server` rests on "plain Rust state with no Lua references; dropping it stops the transport without touching the Lua API": still true (the state now includes C allocations, freed by Rust `Drop`, which calls only netcode) | source |
| Peer ids are exact integers with the same values | `PeerId = generation << 16 \| slot` (`src/id.rs`, byte-identical to 1.1.1); l3i pushes `peer.0` as an exact number (`l3i:src/udp.rs:70-78`). The contract test asserts the two peers of a fresh server are 65536 and 131073, on this tree and on 1.1.1 | Luau (both versions) |
| Event and channel ids are exact integers with the same values | ids come from byte-sorted names and declaration order (`src/schema.rs`, byte-identical to 1.1.1); pinned against 1.1.1 by `tests/wire_golden.rs` and `interop/tests/golden_old_new.rs`; `udp::schema_builds_from_options_and_reports_ids` | Rust, Luau |
| Generations after slot reuse | a stale handle is refused by every handle-taking call, unchanged. One difference: the C netcode reports slot changes per update batch, so a session that connects and disconnects within one batch is never reported and takes no generation (ledger #6 note; pinned by `tests/lifecycle_peers.rs`). Scripts never saw such a session as usable either; peer numbers stay unique and increasing | Rust |
| Explicit update phase; nothing runs in Luau during `update`/`flush` | l3i's `update` reads the plan's clock (a host `Rc<dyn Fn() -> f64>`, never a Luau function) and then calls `dream_net::Server::update(now)` (`l3i:src/udp.rs:672-677, 849-854`). `tests/compat_l3i.rs` `the_network_phase_runs_no_host_code` pins that `update` and `flush` take only `(&mut self, f64)`/`(&mut self)` and that the one piece of host code dream-net can run, a capture sink, never runs inside them; l3i installs none (`grep set_capture` in l3i: nothing). Inside dream-net-native, C calls back only into the reliable transmit/process trampolines (closures dream-net passes for one call) and its allocator hooks (`src/native/reliable/endpoint.rs:695-766`); netcode's connect/disconnect callbacks end in the C shim's slot table, read by polling (`src/native/netcode/server.rs` `collect_events`). The contract test's Luau guard (a flag set around every `update`/`flush`, asserted in every Luau function of the test) never fired | Rust, source, Luau (smoke) |
| `sendEvent` hands over a caller-owned buffer and copies before returning; no Lua string round trip | Luau buffer or string → `BytesView` → `payload_range` borrows its bytes as `&[u8]` for the call (`l3i:src/udp.rs:268-293`) → `Server::send`/`Client::send` → `Connection::send` → the channel queue copies. `send`'s body and `src/channel.rs` are byte-identical to 1.1.1. Both stress tests overwrite the sender's buffer right after every send and check every received byte; the contract test also sends every seventh payload as a string | Rust, Luau |
| `pollInto` copies one payload into a caller-owned buffer, retains nothing, `BufferTooSmall` consumes nothing | `BufferView` → `&mut [u8]` for the call (`l3i:src/udp.rs:338-344`) → `poll_into` → `Inbox::pop_into` copies `arena[offset..offset+len]` into `buffer[..len]` once and returns only the length (`ServerEvent<usize>` borrows nothing: `tests/compat_l3i.rs` pins the signature). `poll_into` and `src/inbox.rs` are byte-identical to 1.1.1. Too small: `Err(BufferTooSmall { needed })` before anything is popped; l3i raises "pollInto buffer of X bytes is too small for a N-byte payload". Both stress tests poll through empty, 7-byte, 64-byte, exact and oversized buffers with a sentinel tail, regrow to exactly `needed` after a refusal, and check that the same event comes back and nothing past the payload (or anything at all, on a refusal) was written; `udp::events_flow_both_ways_over_localhost` checks the same with 8 and 64 bytes | Rust, Luau |
| No extra copy introduced by the migration | receive: one copy from netcode's C packet into a reused Rust buffer (1.1.1 allocated a fresh `Vec` per payload), reliable reassembly in C, zero-copy decode, one copy into the inbox arena, one into the Luau buffer: the same count as 1.1.1. Send: one copy into the channel queue, unchanged | source |
| The peer in a polled message is the authenticated slot, never a payload field | the wire has no sender field; a `Connection` delivers as the `PeerId` of the netcode slot that completed the encrypted handshake (see the compatibility document). The contract test checks every non-empty server message's first byte against the sender the peer number maps to, through 1500 frames per peer with payloads that start with the claimed sender; `interop/tests/matrix.rs` sends payloads naming the other client's peer and client id on both server versions | Luau, Rust |
| `stat` fields (`rtt`, `jitter`, `packetLoss`, `sentKbps`, `receivedKbps`, `ackedKbps`) keep their meaning | `ConnectionStats::from_endpoint` maps the same reliable estimates as 1.1.1 (only its parameter type changed); reliable's estimators produce identical values from identical input except `rtt_min` with no samples (D16), which l3i does not expose (`interop/tests/reliable_differential.rs`) | Rust, source |
| `counters` field names and meanings | the contract test asserts the exact 15 names and that `malformedPackets` is 0; `Counters` and the code that counts are unchanged (`interop/tests/connection_differential.rs`: identical counters old and new) | Luau, Rust |
| `memoryUsage` field names; values | names `connection`, `reliable`, `send`, `receive`, `total` and `total` = the sum: asserted from Luau. **Value change:** `reliable` is now the C endpoint's true upper bound, 581,185 bytes per connection with the default transport, was an estimate of 50,496; a server with two peers reports 1,162,370, was 100,992 (contract test output above, both versions) | Luau |
| Error strings scripts might match | `dream.udp: ` + `dream_net::Error`'s `Display` (`l3i:src/udp.rs:84-90`): texts compared pair by pair in `interop/tests/matrix_errors.rs`. Changed: socket errors (`udp.server{}` on a port in use, `udp.client{ bind = ... }` on an address in use or not on this host) gain netcode's description of the failed step; `client:connect(token)` with a token that names no server of the client's address family now raises `dream.udp: netcode: invalid connect token` (1.1.1 accepted it). Unchanged: `maxClients` range (l3i checks `[1, 256]` itself first), unreadable tokens, `SendError` texts (`queue is full`, `unknown event`, `exceeds the ... byte maximum`, `is not connected`) | Rust |
| Token minting through `connectToken` | unchanged call (`generate_connect_token` keeps its signature apart from the error type, which l3i only formats). Behaviour: see below | Luau, source |
| `CONNECT_TOKEN_BYTES` (2048), `USER_DATA_BYTES` (256), `MAX_EVENT_PAYLOAD`, `MAX_CHANNELS` (64) | same values (`src/native/netcode.rs:183-192`, `src/schema.rs` unchanged); `udp::schema_builds_from_options_and_reports_ids` asserts `CONNECT_TOKEN_BYTES == 2048 and MAX_CHANNELS == 64` | Luau |

### Token lifetimes and the start floor in l3i

l3i's `connectToken(clientId, expiresInSeconds = 300, timeoutSeconds = 30)` accepts lifetimes
1 to 86,400 seconds; the server l3i creates for Luau uses `Server::new`, so its maximum token
lifetime is 30 seconds.

- **What the floor protects:** a token replayed to a *restarted* server with the *same key*.
  l3i generates a fresh key for every Luau-created server (`l3i:src/udp.rs:614`) and the key
  never leaves the userdata, so a token minted for one server cannot decrypt on any other, and
  restart replay does not apply to l3i's own tokens, whatever their lifetime. Host-created
  servers (`Server::push`) have no token issuer in l3i; their hosts mint tokens themselves and
  must follow the host rules in the compatibility document.
- **What it costs l3i scripts:** a token of 30 seconds or less minted in the wall-clock second
  the server was created is silently refused (the client times out). The default 300 seconds
  is unaffected, as is any lifetime above 30.
- **Single use** holds whatever the lifetime: a token admits one session on its server, so a
  reconnect needs `connectToken` again.

Recommendation: **no lifetime cap and no `with_max_token_lifetime` call are needed for
security.** Capping lifetimes at 30 would subject every l3i token to the floor and add no
protection, since the keys are per server. If l3i wants short tokens to work immediately after
`udp.server{}`, it can create its Luau servers with `Server::with_max_token_lifetime(.., 1)`:
only a 1-second token minted in the start second would then be refused, and with per-server
keys nothing is lost. That is optional and a behaviour choice for l3i; the minimal upgrade
keeps `Server::new` and documents the rule. If l3i ever lets a host hand a persistent key to a
Luau token issuer, it must then create that server with a maximum at least the longest lifetime
`connectToken` allows, or cap `expiresInSeconds` at the server's maximum.

## What l3i script authors and maintainers will see

1. A connect token works once: `client:connect(token)` again after a disconnect ends in
   `connectFailed`, `timeout`. Mint a token per connection attempt.
2. A token of 30 seconds or less minted in the second a server was created ends in
   `connectFailed`, `timeout` (the l3i test above). Use the default lifetime, more than 30
   seconds, or mint a second later.
3. A server restarted on the same key refuses tokens used before the restart (l3i-created
   servers always have a new key, so only host-created servers can see this).
4. A server disconnect ends a client's session even when its token lists more servers.
5. `client:connect(token)` raises `dream.udp: netcode: invalid connect token` for a token that
   names no server of the client's address family (an IPv4-bound client, the default
   `0.0.0.0:0`, given a token for an IPv6 server), and a `connectFailed`, `authentication` record
   follows; 1.1.1 accepted the call.
6. `memoryUsage().reliable` is about 581 KB per connection (was about 50 KB), and `total` grows
   with it.
7. `udp.server{}`/`udp.client{}` socket errors read `dream.udp: netcode: socket error: netcode
   could not bind the server's IPv4 socket: Address already in use (os error 98)` (the step is
   new; the OS text is the same).
8. Building l3i needs Clang (dream-net's build script compiles C and refuses GCC and MSVC
   `cl.exe`).
9. Unchanged: every module member, signature and type name; ids and their values; buffer
   handoff; `pollInto` results and too-small errors; counters; the capability gate; schema
   construction errors.

## Proposed l3i patch (not applied)

Against l3i `2159fa2`, for the release that ships this campaign (`X.Y.Z` below, the director's
choice):

```diff
--- a/Cargo.toml
+++ b/Cargo.toml
@@
-dream-net = "=1.1.1"
+dream-net = "=X.Y.Z"
```

```text
cargo update -p dream-net
```

Lockfile result: `netcode-official`, `reliable`, `serialize-official`, `ctutils`, `aead`,
`chacha20`, `chacha20poly1305`, `cipher`, `cmov`, `inout`, `poly1305`, `rand_core` and
`universal-hash` removed. When this was measured, `dream-net-native` was added and `cc` moved
1.9.0 → 1.11.2 under the then exact pin; with the C inside dream-net and `cc` a floor, neither
applies.

```diff
--- a/tests/udp.rs
+++ b/tests/udp.rs
@@ -82,10 +82,12 @@
 #[test]
 fn events_flow_both_ways_over_localhost() {
     let runtime = Runtime::from_plan(&plan(true)).unwrap();
+    // A token no longer-lived than the server's maximum (30 s) is refused in the second the
+    // server started (netcode's start floor), so this one lives longer.
     runtime
         .exec(&format!(
             "{SCHEMA} server = udp.server{{ schema = schema, address = '127.0.0.1:0', protocolId = bits64.fromHex('{PROTOCOL:x}'), maxClients = 4 }} \
-             token = server:connectToken(bits64.fromHex('8000000000000077'), 30, 5) assert(buffer.len(token) == udp.CONNECT_TOKEN_BYTES)"
+             token = server:connectToken(bits64.fromHex('8000000000000077'), 60, 5) assert(buffer.len(token) == udp.CONNECT_TOKEN_BYTES)"
         ))
         .unwrap();
```

(Verified exactly as shown: `tools/check-l3i --precise cc=1.11.2 --overlay <proposed>`, 4 passed.)

Documentation (`l3i:content/docs/builtin-extensions.md`, the `dream.udp` section): say that a
token is single use, that a token of 30 seconds or less is refused in the second the server
was created, and that `memoryUsage().reliable` is an upper bound. Optional: the
`with_max_token_lifetime(.., 1)` policy above.

### Proposed contract test

`tests/udp_contract.rs`, with `mod udp_contract;` added after `mod udp;` in `tests/main.rs`.
It passes against this tree and against dream-net 1.1.1.

<details>
<summary><code>tests/udp_contract.rs</code></summary>

```rust
//! The `@dream/udp` contract a migration of dream-net must keep, driven from Luau over real
//! localhost UDP with two peers: caller-owned buffers through `sendEvent` and `pollInto`
//! (reused, replaced by buffers of other sizes, empty, exactly sized, too small, oversized,
//! zero-length and maximum-length payloads, fragmenting ones, string payloads), payload
//! integrity and reliable order across many frames, peers attributed by the authenticated
//! slot, a Luau-side guard that no Luau runs while the transport is inside `update` or
//! `flush`, and the field names of `counters` and `memoryUsage`.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use l3i::Runtime;
use l3i::extension::{RuntimePlan, RuntimePolicy};
use l3i::udp;

fn plan() -> std::rc::Rc<RuntimePlan> {
    let policy = RuntimePolicy::new()
        .compat_global("@dream/udp", "udp")
        .compat_global("@dream/bits64", "bits64")
        .capability(udp::TRANSPORT_CAPABILITY);
    RuntimePlan::builder().policy(policy).finalize().unwrap()
}

/// A server refuses a token that could predate its start (netcode's start floor), so tokens
/// with the server's maximum lifetime (30 seconds) are minted once the wall clock has left the
/// server's start second.
fn wait_for_the_next_second() {
    let now = || SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let second = now().as_secs();
    while now() < Duration::from_secs(second + 1) + Duration::from_millis(50) {
        std::thread::sleep(Duration::from_millis(5));
    }
}

const SETUP: &str = "
schema = udp.schema{ version = 15,
    channels = { { name = 'rel', delivery = 'reliableOrdered', capacity = 256 },
                 { name = 'unrel', delivery = 'unreliableUnordered', capacity = 256 } },
    events = { { name = 'Big', channel = 'rel', maxPayload = 4000 },
               { name = 'Small', channel = 'rel', maxPayload = 64 },
               { name = 'Zero', channel = 'rel', maxPayload = 0 },
               { name = 'Tick', channel = 'unrel', maxPayload = 32 },
               { name = 'Nil', channel = 'unrel', maxPayload = 0 } } }
server = udp.server{ schema = schema, address = '127.0.0.1:0', protocolId = bits64.fromHex('d4ea4e7000000015'), maxClients = 2 }
clients = { udp.client{ schema = schema }, udp.client{ schema = schema } }
";

const CONNECT: &str = "
for i = 1, 2 do clients[i]:connect(server:connectToken(bits64.fromNumber(1000 + i), 30, 5)) end
";

const DRIVE: &str = r#"
local BIG, SMALL, ZERO = schema:eventId('Big'), schema:eventId('Small'), schema:eventId('Zero')
local TICK, NIL = schema:eventId('Tick'), schema:eventId('Nil')
local RELIABLE = { [BIG] = true, [SMALL] = true, [ZERO] = true }
local SENTINEL = 0xEE
local SIZES = { 0, 7, 64, 4000, 4064 }
local pool = {}
for i, n in SIZES do pool[i] = buffer.create(n) end
local out = buffer.create(4016)
local round = 0
refusals, stringSends, frame, FRAMES = 0, 0, 0, 1500
local inNetworkPhase = false
peers = {}            -- server peer number -> client index
local connected = { false, false }
-- streams 1, 2: client i to the server; 3, 4: the server to client i
streams = {}
for s = 1, 4 do streams[s] = { seq = 0, rel = {}, head = 1, tail = 0, unrel = {}, delivered = 0, backlog = {} } end

local function guard()
    assert(not inNetworkPhase, 'Luau ran inside the transport update or flush')
end

local function byteAt(stream, seq, i)
    if i == 0 then return stream end
    if i <= 4 then return bit32.extract(seq, (i - 1) * 8, 8) end
    return (seq * 31 + i * 7 + stream) % 256
end

local function frameEvents(f, stream)
    local events = {
        { SMALL, (f + stream) % 65 }, { ZERO, 0 }, { TICK, (f * 3 + stream) % 33 }, { NIL, 0 },
    }
    if f % 25 == stream % 25 then
        local n = f // 25
        table.insert(events, { BIG, if n % 11 == 0 then 4000 else (n * 997) % 4000 })
    end
    return events
end

-- Writes each payload into the one reused `out` buffer, sends it (sometimes as a string), then
-- scribbles over the buffer: the transport must have copied it already.
local function sendFrame(stream, send)
    guard()
    local s = streams[stream]
    for _, e in frameEvents(frame, stream) do table.insert(s.backlog, e) end
    while #s.backlog > 0 do
        local event, len = s.backlog[1][1], s.backlog[1][2]
        for i = 0, len - 1 do buffer.writeu8(out, i, byteAt(stream, s.seq, i)) end
        local key = event .. ':' .. buffer.readstring(out, 0, len)
        local ok, err
        if s.seq % 7 == 0 then
            stringSends += 1
            ok, err = pcall(send, event, buffer.readstring(out, 0, len))
        else
            ok, err = pcall(send, event, out, 0, len)
        end
        if not ok then
            assert(string.find(err, 'queue is full'), err)
            if RELIABLE[event] then break end
            table.remove(s.backlog, 1)
            continue
        end
        buffer.fill(out, 0, 0x5A)
        table.remove(s.backlog, 1)
        if RELIABLE[event] then
            -- an explicit tail: delivered entries become holes, so `#s.rel` is no index
            s.tail += 1
            s.rel[s.tail] = { event, len, s.seq }
        else
            s.unrel[key] = (s.unrel[key] or 0) + 1
        end
        s.seq += 1
    end
end

-- Polls once through a buffer from the pool (sentinel-filled); a too-small buffer is replaced
-- by one of exactly the size the error names, and the same event must come back.
local function pollOne(transport)
    guard()
    round += 1
    local buf = pool[round % #SIZES + 1]
    buffer.fill(buf, 0, SENTINEL)
    while true do
        local ok, kind, peer, a, b, c = pcall(transport.pollInto, transport, buf)
        if ok then return buf, kind, peer, a, b, c end
        local needed = tonumber(string.match(kind, 'for a (%d+)%-byte payload'))
        assert(needed and needed > buffer.len(buf), kind)
        for i = 0, buffer.len(buf) - 1 do assert(buffer.readu8(buf, i) == SENTINEL, 'a refused poll wrote') end
        refusals += 1
        buf = buffer.create(needed)
        buffer.fill(buf, 0, SENTINEL)
    end
end

local function arrived(stream, buf, event, len)
    local s = streams[stream]
    s.delivered += 1
    -- nothing past the payload was written
    for i = len, math.min(len + 32, buffer.len(buf)) - 1 do
        assert(buffer.readu8(buf, i) == SENTINEL, 'pollInto wrote past the payload')
    end
    if RELIABLE[event] then
        local expected = s.rel[s.head]
        assert(expected, 'unexpected reliable event')
        s.rel[s.head] = nil
        s.head += 1
        assert(event == expected[1] and len == expected[2], 'reliable order')
        for i = 0, len - 1 do
            assert(buffer.readu8(buf, i) == byteAt(stream, expected[3], i), 'reliable payload')
        end
    else
        local key = event .. ':' .. buffer.readstring(buf, 0, len)
        assert((s.unrel[key] or 0) > 0, 'unreliable payload unknown or duplicated')
        s.unrel[key] -= 1
    end
end

function step()
    inNetworkPhase = true
    server:update()
    clients[1]:update()
    clients[2]:update()
    inNetworkPhase = false
    while true do
        local buf, kind, peer, a, b, c = pollOne(server)
        if not kind then break end
        if kind == 'connected' then
            peers[peer] = if a == bits64.fromNumber(1001) then 1 else 2
        elseif kind == 'message' then
            local from = peers[peer]
            -- the authenticated slot names the sender, whatever the payload claims
            if c > 0 then assert(buffer.readu8(buf, 0) == from, 'attributed to its sender') end
            arrived(from, buf, a, c)
        else
            error('server: ' .. kind)
        end
    end
    for i = 1, 2 do
        while true do
            local buf, kind, _, a, b, c = pollOne(clients[i])
            if not kind then break end
            if kind == 'connected' then connected[i] = true
            elseif kind == 'message' then arrived(2 + i, buf, a, c)
            else error('client: ' .. kind) end
        end
    end
    local peerCount = 0
    for _ in peers do peerCount += 1 end
    local ready = connected[1] and connected[2] and peerCount == 2
    if ready and frame < FRAMES then
        for peer, i in peers do
            sendFrame(i, function(...) clients[i]:sendEvent(...) end)
            sendFrame(2 + i, function(...) server:sendEvent(peer, ...) end)
        end
        frame += 1
    end
    inNetworkPhase = true
    server:flush()
    clients[1]:flush()
    clients[2]:flush()
    inNetworkPhase = false
    local drained = true
    for s = 1, 4 do
        if streams[s].rel[streams[s].head] ~= nil or #streams[s].backlog > 0 then drained = false end
    end
    return frame == FRAMES and drained
end
"#;

#[test]
fn buffers_peers_and_fields_hold_across_many_frames() {
    let runtime = Runtime::from_plan(&plan()).unwrap();
    runtime.exec(SETUP).unwrap();
    wait_for_the_next_second();
    runtime.exec(CONNECT).unwrap();
    runtime.exec(DRIVE).unwrap();
    let step = runtime.load_function("return step").unwrap();
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if step.invoke::<bool, ()>(&runtime.stack(), ()).unwrap() {
            break;
        }
        assert!(Instant::now() < deadline, "frames did not complete");
        std::thread::sleep(Duration::from_micros(500));
    }
    runtime
        .exec(
            "for s = 1, 4 do assert(streams[s].seq > FRAMES * 4, 'sent ' .. streams[s].seq) \
                 assert(streams[s].delivered >= FRAMES * 2, 'delivered ' .. streams[s].delivered) end \
             assert(refusals > 500, 'too-small buffers exercised: ' .. refusals) \
             assert(stringSends > 100) \
             local numbers = {} for peer in peers do table.insert(numbers, peer) end table.sort(numbers) \
             assert(numbers[1] == 65536 and numbers[2] == 131073, 'peer numbers ' .. numbers[1] .. ' ' .. numbers[2]) \
             local counters = server:counters(numbers[1]) local names = {} \
             for name, value in counters do assert(type(value) == 'number') table.insert(names, name) end \
             table.sort(names) \
             assert(table.concat(names, ',') == 'bytesReceived,bytesSent,datagramsReceived,datagramsSent,duplicateEvents,eventsDroppedOnReceive,eventsDroppedOnSend,eventsQueued,eventsReceived,eventsResent,eventsSent,malformedPackets,packetsReceived,packetsRefused,packetsSent', table.concat(names, ',')) \
             assert(counters.malformedPackets == 0) \
             local memory = server:memoryUsage() names = {} \
             for name in memory do table.insert(names, name) end table.sort(names) \
             assert(table.concat(names, ',') == 'connection,receive,reliable,send,total') \
             assert(memory.total == memory.connection + memory.reliable + memory.send + memory.receive) \
             print('memoryUsage per server with 2 peers', memory.connection, memory.reliable, memory.send, memory.receive) \
             print('client memoryUsage', clients[1]:memoryUsage().reliable)",
        )
        .unwrap();
}
```

</details>

## Not verified

- l3i on macOS and Windows; only Linux x86_64 here.
- `typed_definitions` (needs l3i's `analysis`, `soft-render` and `jit` features, a large C++
  build) was not run. Its `@dream/udp` declarations are l3i's own strings
  (`describe_server`, `describe_client`), which this migration does not touch.
- Benchmarks were smoke-run only (`--test`), not measured; the director runs them.
- That no Luau runs inside `update`/`flush` is verified structurally and at the Rust level;
  the Luau-level guard is a smoke test: it would catch a call into one of the test's own
  functions, and l3i exposes no way for a script to register any other.
- Jess was not built or run; it does not depend on dream-net directly.
