# Native transport compatibility

What dream-net peers on the native transport (C netcode 1.4.10 and C reliable 1.4.6 through
`dream-net-native`, with dream-net's own bit framing) can and cannot talk to, layer by layer,
with the test that proves each claim. Tracked in
[#11](https://github.com/DreamWeave-MP/dream-net/issues/11); campaign ledger in
[NATIVE_TRANSPORT_CAMPAIGN.md](NATIVE_TRANSPORT_CAMPAIGN.md), audit in
[NATIVE_TRANSPORT_AUDIT.md](NATIVE_TRANSPORT_AUDIT.md) (§5 wire comparison, §5.3 differences
D1 to D22).

"Old" is dream-net 1.1.1 from crates.io (`netcode-official` 1.0.0, `reliable` 1.3.4,
`serialize-official` 2.4.0). "New" is this tree. Every result below was observed on Linux
x86_64 (rustc 1.100.0, clang 23.1.2) on 2026-11-18. macOS and Windows run the main crate's
tests in CI only; the `interop/` crate (outside the workspace, never packaged) runs locally.

## Verdict

- **Every layer is byte-identical.** netcode tokens and packets, reliable headers and
  fragments, and dream-net's framing are the same bytes on both sides, and both sides read
  them to the same verdicts. Old and new clients and servers interoperate in all four
  pairings, over IPv4 and IPv6, for every cell of the matrix below.
- **The differences are refusals, all on purpose** (campaign decision 12): a new server
  admits each connect token once, refuses a token that could predate its start, and so
  refuses a token replayed to it after a restart. A new client ends its session when a server
  disconnects it instead of moving to the token's next server, and refuses at `connect` a
  token that lists no server of its address family. No old peer's bytes are parsed
  differently.
- **No `WIRE_VERSION` bump and no protocol id change are needed** (reasoning below).
- **Recommended release: 2.0.0** (reasoning below; 1.2.0 is defensible only under a narrow
  reading of the public API).

## Layer by layer

| Layer | Verdict | Proven by |
| --- | --- | --- |
| netcode connect token (2048 bytes: version info, protocol id, timestamps, nonce, encrypted private part, timeout, server addresses in IPv4 and IPv6 form, session keys) | byte-identical | `native/tests/netcode_kat.rs` `the_c_reproduces_netcode_officials_eleven_vectors`: the vendored C writes `connect_token.bin`, `private_connect_token_plaintext.bin` and `private_connect_token_encrypted.bin` identical (SHA-256) to the files `netcode-official` 1.0.0 ships. Live: `interop/tests/netcode_old_new.rs` `every_mix_of_old_and_new_connects_and_carries_payloads` and `interop/tests/matrix.rs` (tokens from either generator accepted by either server) |
| Version string | identical, `"NETCODE 1.02\0"` | audit §5.1 static table; the token and packet vectors above carry it in their associated data |
| Protocol id handling | identical: part of the token, the private token's associated data and every packet's associated data; a mismatch is never answered | KAT vectors (associated data); `matrix.rs` `every_pairing_ignores_a_wrong_protocol_id` (all four pairings: the client times out, the server reports nothing) |
| Handshake packets (request 1078 bytes, denied, challenge, response) | byte-identical | KAT vectors `packet_request.bin`, `packet_denied.bin`, `packet_challenge.bin`, `packet_response.bin`, `challenge_token_encrypted.bin` |
| Encrypted packet rules (prefix byte, 1 to 8 little-endian sequence bytes, ChaCha20-Poly1305 with nonce `0^32 ‖ seq_le64`, associated data version ‖ protocol id ‖ prefix, 16-byte tag; keep-alive, payload, disconnect) | byte-identical | KAT vectors `packet_keep_alive.bin`, `packet_payload.bin`, `packet_disconnect.bin`. Replay window 256, payload 1..=1200: audit §5.1 static table |
| reliable packet header (prefix byte, sequence, ack, ack bits) and fragment header (5 bytes, header in fragment 0), acks, fragmentation and reassembly | byte-identical datagrams, deliveries, acks and counters | `interop/tests/reliable_differential.rs`: `appendix_b_transcript_is_identical`, `seeded_lossy_exchanges_are_identical`, `the_sequence_wrap_is_identical`, `hostile_input_is_handled_identically` (old-old, new-new and both mixed pairings); `interop/tests/reliable_old_new.rs` `old_to_new_and_new_to_old`. New in #11: `interop/tests/golden_old_new.rs` `every_rejection_datagram_is_what_both_reliables_frame` pins three first datagrams byte for byte from both |
| reliable documented differences | statistics and config edge cases only, none on the wire | `reliable_differential.rs` `rtt_min_on_a_ten_second_link_differs_as_documented` (D16), `reset_differs_as_documented` (D19), `non_power_of_two_windows_differ_as_documented` (D13) |
| dream-net bit stream | byte-identical to serialize 2.4.0 | `interop/tests/bits.rs` (four property tests), `interop/tests/wire_reference.rs` |
| dream-net wire framing v2 (hello, sections, int_relative ids, lengths, alignment) | byte-identical encoding; identical decoder verdicts down to each `Malformed` reason | `tests/wire_golden.rs` (original five vectors, unchanged); `interop/tests/wire_old_new.rs` (`encoders_agree_and_decoders_agree`, `decoders_agree_on_arbitrary_bytes`, `every_refusal_class_agrees`, `sweep_reaches_every_verdict`); new in #11: the eleven compatibility vectors below, generated by 1.1.1 |
| Schema fingerprint, event ids from sorted names, channel ids | identical | `tests/wire_golden.rs` `schema_fingerprint_is_pinned`, `compat_schemas_have_the_pinned_catalogue`; `interop/tests/golden_old_new.rs` `both_versions_build_the_pinned_catalogues`; `matrix.rs` `both_versions_agree_on_every_variant` |
| `Connection` (channels, acks, aggregation, backpressure, schema mismatch) | identical datagram streams, deliveries, states and counters | `interop/tests/connection_differential.rs` (five scenarios incl. both wraps and hostile datagrams), `interop/tests/connection_old_new.rs` |

Every one of these interop suites was rerun on this tree, where the new side is C netcode and
C reliable throughout (they were first written while one backend was still the Rust port):
`interop/` `cargo test`, three consecutive runs, 67 passed and 1 ignored (a by-hand printer)
each time.

## Compatibility matrix

Every row runs each (client, server) pairing: old/old, old/new, new/old, new/new, over real
loopback sockets on the wall clock. "pass" means the asserted records were seen on both sides
in all four pairings. Tests are in `interop/tests/` unless a path is given.

| Cell | Test | Result |
| --- | --- | --- |
| Connect and schema handshake, IPv4, token minted by old and by new `generate_connect_token` | `matrix.rs` `every_pairing_carries_every_kind_of_traffic_over_ipv4` | pass, 8 sessions |
| The same over IPv6 (`[::1]`) | `matrix.rs` `every_pairing_carries_every_kind_of_traffic_over_ipv6` | pass, 8 sessions |
| Reliable-ordered events both ways | both of the above (32 `Chat` events each way, checked in order) | pass |
| Unreliable events both ways, incl. zero-length | both of the above (`Move`, `Ping`) | pass |
| An event that fragments at the reliable layer (8000 bytes, above the 1191-byte fragment threshold), both ways | both of the above (payload checked byte for byte; receiver counts at least 6 more datagrams than packets) | pass |
| Many small events aggregated in one packet | both of the above: 32 queued events, one `flush`, exactly 1 packet and 32 events sent, both directions | pass |
| Client-initiated disconnect | both of the above: server `Disconnected { remote }`, client `Disconnected { requested }` | pass |
| Server-initiated disconnect | `matrix.rs` `every_pairing_reports_a_server_disconnect`: server `requested`, client `remote` | pass |
| Client falls silent (timeout) | `matrix.rs` `every_pairing_times_out_a_silent_client`: server `Disconnected { timeout }` | pass |
| Server falls silent (timeout) | `matrix.rs` `every_pairing_times_out_a_silent_server`: client `Disconnected { timeout }` | pass |
| Schema mismatch: schema version | `matrix.rs` `every_pairing_reports_every_schema_mismatch`; also `lifecycle_old_new.rs` `a_schema_mismatch_fails_the_same_way_across_versions` | pass: server `Rejected { failure: SchemaMismatch { local, remote } }`, client `ConnectFailed { reason: schemaMismatch, failure: SchemaMismatch { local, remote } }`, nothing announced or delivered |
| Schema mismatch: one more event | same test | pass, same records |
| Schema mismatch: different channel window | same test | pass, same records |
| Schema mismatch: different payload limit | same test | pass, same records |
| Client of another wire version (1 or 3), carrying the server's own schema | `version_rejection.rs` `both_servers_reject_a_client_of_another_wire_version` (hand-driven C netcode client against both server versions) | pass: server `Rejected { failure: ProtocolMismatch { local: 2, remote: 1 or 3 } }`; the fake hears only the server's version-2 hello; the event behind the foreign hello is never delivered. Control: the same fake with version 2 is admitted and its event delivered |
| Server of another wire version (1 or 3) | `version_rejection.rs` `both_clients_reject_a_server_of_another_wire_version` (hand-driven C netcode server against both client versions) | pass: client `ConnectFailed { reason: protocolMismatch, failure: ProtocolMismatch { local: 2, remote: 1 or 3 } }` |
| Another wire version at `Connection` level | `version_rejection.rs` `both_connections_refuse_a_foreign_wire_version_and_deliver_nothing`; main crate `tests/compat_version.rs` (runs in CI) | pass: `Failed(ProtocolMismatch)`, 0 delivered, 0 counted malformed, answers with its own hello; identical bytes from old and new |
| Wrong protocol id | `matrix.rs` `every_pairing_ignores_a_wrong_protocol_id` | pass: client `ConnectFailed { timeout }`, server silent |
| Peer origin: events are attributed to the authenticated slot | `matrix.rs` `every_server_attributes_events_to_the_authenticated_slot` (an old and a new client on each server version, payloads naming the other's handle and client id); main crate `tests/compat_l3i.rs` | pass: all 80 messages per server attributed to the sending slot |
| Deliberate: token reused after a disconnect (D1/S1) | `matrix.rs` `every_pairing_answers_a_reused_token_as_its_server_version_decides`; also `lifecycle_old_new.rs`, `netcode_old_new.rs` | new server: refused, client `ConnectFailed { timeout }`; old server: admitted again (the defect) |
| Deliberate: 30-second token minted in the server's start second (D2/S5) | `matrix.rs` `every_pairing_answers_a_token_from_the_start_second_as_its_server_version_decides` | new server: refused, `ConnectFailed { timeout }`; old server: admitted |
| Deliberate: token used, server restarted on the same key and address, token presented again (S2) | `matrix.rs` `every_pairing_answers_a_token_replayed_to_a_restarted_server_as_its_server_version_decides` | new server: refused, `ConnectFailed { timeout }`; old server: admitted again (the defect) |
| Deliberate: server disconnects a client holding a two-address token (D8/S4) | `lifecycle_old_new.rs` `a_server_disconnect_leaves_a_new_client_disconnected` (old and new server), `netcode_old_new.rs` `a_server_disconnect_ends_a_multi_address_session_only_for_the_new_client` | new client: `Disconnected { remote }` and never contacts the second address; an old client moves on (the defect) |
| Error texts and refusals at the API | `matrix_errors.rs` `error_texts_old_and_new` | asserted pair by pair; see [Error texts](#error-texts) |

Run time: `matrix.rs` about 8 seconds, `version_rejection.rs` about 6 seconds. Three
consecutive full `interop/` runs passed with no failure, and the socket tests pace on the
wall clock themselves (each mints after the start second it needs, deadlines of 20 seconds
are only reached on failure).

## Golden vectors

`tests/wire_golden.rs` keeps its five original vectors byte for byte. #11 adds the data-only
table `tests/compat_vectors/mod.rs`, checked three ways: the main crate encodes and decodes it
(`encodes_compat_vectors`, `decodes_compat_vectors`, `compat_schemas_have_the_pinned_catalogue`,
`compat_vector_ids_wrap_through_zero`); `interop/tests/golden_old_new.rs` builds every schema
and packet with dream-net 1.1.1's own `Schema` and `PacketWriter` and asserts the same bytes,
the same decoder verdict from both versions, and the same catalogue; and the version-rejection
datagrams are framed by both the C reliable and the 1.3.4 port. The hex was generated by 1.1.1
(`cargo test --test golden_old_new -- --ignored --nocapture` prints it), so the goldens pin
compatibility with the last release, not just current behaviour.

| Vector | Covers |
| --- | --- |
| catalogue (`TEST_EVENT_IDS`, `TEST_CHANNEL_CATALOGUE`, three fingerprints) | event ids from byte-sorted names (Blob 0, Chat 1, Move 2, Ping 3, Spawn 4), channel ids in declaration order with delivery, window and largest payload, the fingerprints of the test schema at versions 1 and 9 and of a wide schema |
| `relative_tiers_across_the_wrap` | message ids 65530 → 29373 through 0 with deltas 1, 2, 6, 7, 23, 24, 280, 281, 4377, 4378, 20000: every `int_relative` tier at both ends |
| `wrap_at_65535` | ids 65535, 0, 1 |
| `payload_length_edges` | lengths 0, the event maximum (256), the channel maximum (1024), 64 on the unreliable channel, 8000 on the bulk channel |
| `three_sections_without_a_hello` | three sections in channel order 1, 2, 0, a delta of 63 in a window of 64 |
| `full_section` | a hello and one section of 32 messages, the most `max_messages_per_packet(32)` allows |
| `hello_wire_version_1`, `_3`, `_65535` | hellos of another wire version: every decoder stops with `Mismatch` |
| `hello_wire_version_3_then_a_section` | a foreign hello followed by a section a version-2 decoder would deliver: stopped at the hello |
| `hello_foreign_fingerprint`, `..._then_a_section` | wire version 2 with the version-9 fingerprint: `Mismatch`, a `SchemaMismatch` at `Connection` level |
| `REJECTION_DATAGRAMS` (three) | the first datagram a wire-version-1 or -3 peer sends: reliable's 8-byte header `3e00000100000000`, then the packet |

**Authoritative peer origin.** The wire has no sender field: the decoded `Message` is
`{ event, id, offset, len }` (`src/wire.rs`), and a `Connection` delivers everything it
decodes as the `PeerId` it was created with (`src/connection.rs` `apply_reliable`,
`apply_unreliable`). A server creates that `Connection` for the netcode slot that completed
the encrypted handshake, so `ServerEvent::Message::peer` is always the slot's authenticated
occupant. Tested on both versions with payloads crafted to name another peer
(`matrix.rs` `every_server_attributes_events_to_the_authenticated_slot`), at thousands of
frames with zero-length payloads that carry nothing at all (`tests/compat_l3i.rs`), and from
Luau through l3i (see [NATIVE_TRANSPORT_L3I.md](NATIVE_TRANSPORT_L3I.md)).

## Protocol version rejection

What happens today when wire versions differ, established by the tests above:

1. The hello is the first field after the 2-bit kind and the 1-bit hello flag, before any
   field whose width depends on the schema (`src/wire.rs` `decode`). A hello whose
   `wire_version` or fingerprint differs from the receiver's stops decoding with
   `DecodeError::Mismatch`; nothing after it is read.
2. The `Connection` fails with `Failure::ProtocolMismatch { local: 2, remote }` when the
   versions differ, else `Failure::SchemaMismatch` (`src/connection.rs` `process`). It returns
   `false` to reliable, so the packet is not acked, and it delivers nothing, ever: a failed
   connection ignores every later datagram.
3. A failed side keeps sending only its own hello (`write_packets`), so the other side
   diagnoses the mismatch too. A server reports the slot as `Rejected` (never announced),
   lingers `mismatch_linger` seconds and then disconnects it. A client reports
   `ConnectFailed { reason: protocolMismatch }`.
4. `WIRE_VERSION` is also an input of the schema fingerprint, so peers of different wire
   versions also differ in fingerprint; the version comparison runs first, so they are
   reported as a protocol mismatch, not a schema mismatch.

Both 1.1.1 and this tree do exactly this, on identical bytes.

### Does this migration need a `WIRE_VERSION` bump or a protocol id change?

No. Reasons:

- **Nothing on the wire changed.** Every byte at every layer is identical and every decoder
  reaches the same verdict on the same input (old/new property tests over random schemas,
  285,301 decodes covering every `Malformed` reason, hostile reliable datagrams, eleven
  netcode vectors). An old peer's packets cannot be misparsed by a new one, or the reverse,
  because both parse the same grammar with the same refusals.
- **The security fixes are acceptance rules, not formats.** Token single use (S1), the start
  floor (S2/S5) and the zero-length datagram fix (S3) are decisions a *server* makes about
  input it reads identically. A wire version bump would make new servers refuse old clients
  that behave correctly, and new clients refuse old servers, without making any old server
  safer: an attacker who wants to replay a token against an old server uses an old client.
  The fix for S1/S2 on a fleet is upgrading its servers, which interoperate with every client.
- **Mixed fleets work and degrade safely.** New server with old clients: everything works;
  an old client that reuses a token or mints a 30-second token in the server's start second
  times out (`ConnectFailed { timeout }`), which is the intended refusal. Old server with new
  clients: everything works; the server keeps its old defects (S1, S2, S3), the new client
  gains S4's fix. Decision 9 asks for a bump only if a secure fix requires incompatibility;
  none does.
- **A bump would cost every user.** `WIRE_VERSION` feeds the fingerprint, so every schema's
  fingerprint would change and every deployed peer would be refused, for no protocol change.
- **The netcode protocol id is the application's**, not dream-net's: hosts (and l3i scripts
  through `protocolId`) choose it to separate games and their own breaking releases. A host
  that wants to force its own fleet onto the new security behaviour (refuse old clients
  outright) can change its protocol id; dream-net should not.

Revisit only if a future change alters bytes on the wire (then bump `WIRE_VERSION` in the same
commit, as `tests/wire_golden.rs` says) or if a fix ever needs a peer to send something old
peers cannot (none of D1 to D22 does).

## Deliberate incompatibilities and upgrade instructions

What a host or script author will see, and what to do.

| Change | Symptom | What to do |
| --- | --- | --- |
| A connect token admits one session (D1/S1) | A client that reconnects with a token it already used never connects: `ConnectFailed { reason: timeout }` after the token's timeout (no error at `connect`) | Mint a fresh token for every connection attempt, including reconnects. A token that never completed a session (a lost handshake packet) can be retried from the same address |
| The start floor (D2/S5): a token is refused unless `expire > start second + max lifetime` (30 s with `Server::new`) | A 30-second token minted in the same wall-clock second the server started never connects: `ConnectFailed { timeout }` | Mint after the server has started and the wall clock has moved to the next second, or mint tokens that live longer than the server's maximum (only with a key that is fresh for each server start, see next row) |
| Token lifetime against the server's maximum | Tokens that live longer than the server's maximum pass the floor, so they are only protected against replay across a restart if the server's key changes at every start | A host that keeps its private key across restarts: mint every token with `expire_seconds <= M` and create the server with `Server::with_max_token_lifetime(.., M)` (or `Server::new` for M = 30). A host that generates a key per server start (as l3i does): any lifetime is safe; keep tokens short anyway, they are bearer credentials |
| A restarted server refuses tokens used before the restart (S2) | Clients that kept a token across a server restart time out | Mint fresh tokens after a restart (needed anyway: single use) |
| A server disconnect ends the session (D8/S4) | A client with a multi-address token reports `Disconnected { remote }` and does not try the next address | Reconnect explicitly with a fresh token if failover is wanted |
| A client refuses at `connect` a token with no server of its address family | `Client::connect` returns `Err(Netcode(InvalidConnectToken))` ("netcode: invalid connect token") and queues `ConnectFailed { authentication }`; 1.1.1 returned `Ok` | Bind the client to the family the token names (`[::]:0` for IPv6 servers) |
| `TransportConfig::validate` caps `sent_packets_buffer_size`, `received_packets_buffer_size` and `fragment_reassembly_buffer_size` at 16384 (was 32768, and unbounded for reassembly) | `Server::new`/`Client::new`/`Shared::new` return `ConfigError::Transport` for configurations 1.1.1 accepted | Use 16384 or less (the defaults are 256/256/16) |
| `MemoryUsage::reliable` is the endpoint's true bound | About 581,185 bytes per connection with the default config, was an estimate of about 50,496 (`interop/tests/connection_memory.rs`); `total` per connection about 624,841, was about 94,504 | Re-baseline budgets and dashboards: the memory was always reachable by a peer, it is now reported |
| Socket error texts | `"netcode: socket error: netcode could not bind the server's IPv4 socket: Address already in use (os error 98)"`, was `"netcode: socket error: Address already in use (os error 98)"`; the `io::ErrorKind` is unchanged | Match on `ErrorKind`, not on text |
| Build requirement | Building dream-net needs Clang (the native crate compiles vendored C and refuses GCC and MSVC `cl.exe`) | Install Clang (and LLD for LTO); see `native/BUILD.md` |
| Public types | `Error::Netcode` carries `NetcodeError` (`dream_net_native::netcode::Error`, same variants and texts as `netcode_official::Error` plus `InvalidConnectTokenLifetime`); `TransportConfig::reliable_config` returns `ReliableConfig` and `Connection::reliable_counters` returns `&ReliableCounters` (the native crate's, same fields) | Code that named `netcode_official::Error` or `reliable::{Config, Counters}` switches to `dream_net::{NetcodeError, ReliableConfig, ReliableCounters}` |

For l3i script authors these appear through `@dream/udp`; the l3i-specific list, with the
proposed l3i patch, is in [NATIVE_TRANSPORT_L3I.md](NATIVE_TRANSPORT_L3I.md).

## Error texts

`interop/tests/matrix_errors.rs` asserts every pair (Linux OS texts):

| Path | 1.1.1 | This tree |
| --- | --- | --- |
| `Server::new`, port in use | `netcode: socket error: Address already in use (os error 98)` | `netcode: socket error: netcode could not bind the server's IPv4 socket: Address already in use (os error 98)` |
| `Server::new`, `max_clients` 0 / 257 | `netcode: max clients 0 is out of range [1,256]` | unchanged |
| `Client::new`, address in use | `netcode: socket error: Address already in use (os error 98)` | `netcode: socket error: netcode could not create or bind the client's IPv4 socket: Address already in use (os error 98)` |
| `Client::new`, address not on this host | `netcode: socket error: Cannot assign requested address (os error 99)` | `netcode: socket error: netcode could not create or bind the client's IPv4 socket: Cannot assign requested address (os error 99)` |
| `Client::connect`, unreadable token | `netcode: invalid connect token`, then `ConnectFailed(authentication)` | unchanged |
| `Client::connect`, IPv4 client, IPv6-only token | `Ok`, nothing queued | `netcode: invalid connect token`, then `ConnectFailed(authentication)` |
| `generate_connect_token`, 0 or 33 addresses | `number of server addresses is out of range [1,32] or public and internal address lists differ in length` | unchanged |
| `TransportConfig::validate`, a window of 32768 | `Ok` | `invalid transport configuration: sent_packets_buffer_size must be a power of two <= 16384` (and the `received_` and `fragment_reassembly_` equivalents) |

`ConfigError`, `SendError` and `BufferTooSmall` texts are unchanged (their source is
unchanged apart from the three transport limits).

## Version and semver recommendation

For the director and the owner; nothing here was changed in `Cargo.toml` or `mod.toml`.

What changed in the public API and behaviour, against 1.1.1:

| Change | Kind under Rust semver |
| --- | --- |
| `Error::Netcode(netcode_official::Error)` becomes `Error::Netcode(NetcodeError)`, a different type with the same variants (plus one) and texts | **breaking** for code that names or matches the old type (a type in a public signature changed) |
| `generate_connect_token`'s error type, same change | **breaking**, same reason |
| `TransportConfig::reliable_config() -> reliable::Config` becomes `-> ReliableConfig`; `Connection::reliable_counters() -> &reliable::Counters` becomes `&ReliableCounters` | **breaking** for code that passed them to the `reliable` crate or named those types |
| `TransportConfig::validate` refuses windows above 16384 | **breaking** for configurations that used them (runtime refusal of formerly valid input) |
| Single-use tokens, start floor, restart refusal, server disconnect ends a session, IPv4/IPv6 token refusal at `connect` | behavioural, security fixes; observable by working code (l3i's own test fails on the start floor) |
| `MemoryUsage::reliable` now an upper bound, about 11.5 times larger | behavioural (documented meaning changed) |
| Socket error texts | behavioural (text only; kinds unchanged) |
| Building needs Clang; new `links = "dream_net_native"` native dependency | build environment requirement; can break downstream builds that worked |
| New: `NetcodeError`, `ReliableConfig`, `ReliableCounters`, `DEFAULT_MAX_CONNECT_TOKEN_LIFETIME`, `Server::with_max_token_lifetime`, `NetcodeError::InvalidConnectTokenLifetime` | additive: minor |
| `Server`, `Client`, `PeerId`, `EventTypeId`, `Schema`, `send`, `poll_into`, constants, auto traits | unchanged (`tests/api_surface.rs`; `inbox.rs`, `id.rs`, `schema.rs`, `channel.rs`, `capture.rs`, `lifecycle.rs` are byte-identical to 1.1.1, and `poll_into`/`send` bodies too) |

**Recommendation: 2.0.0.** The Rust convention (the Cargo book's SemVer compatibility
chapter) treats changing the type of an item in a public signature as a major change, and
four public signatures changed type (`Error::Netcode`, `generate_connect_token`,
`TransportConfig::reliable_config`, `Connection::reliable_counters`); a build that now needs
Clang and a token policy that refuses what working code did (l3i's test) are breaking in
practice too. The project's release rule ("added
public API is a minor release") sets the floor at minor for the additions, not a ceiling.
The wire is unchanged, so 2.0.0 peers and 1.1.1 peers interoperate as tested above; the
release notes should say so plainly, so nobody reads the major bump as a protocol break.

The case for 1.2.0: the changed types came from crates dream-net never re-exported, so only
code that also depended on `netcode-official` or `reliable` directly could name them; l3i,
the only known consumer, compiles unchanged; and l3i pins `=1.1.1`, so it must edit its
manifest for any version anyway. That is a reasonable reading if the owner considers those
types implementation details, but it relies on nobody having named them, and it hides a new
build requirement and new refusals in a minor release. If 1.2.0 is chosen, the release notes
must list every row of the table above under `breaking`.

`dream-net-native` is a new crate; 0.1.0 is appropriate (its API is a binding mirror, not a
stable surface). dream-net pins it exactly, so every native upgrade is a dream-net release.

## Not verified

- macOS and Windows: no matrix run (the `interop/` crate does not run in CI; the main crate's
  `tests/compat_version.rs` and `tests/compat_l3i.rs` do).
- Loss, delay and reordering over real sockets between old and new: the socket matrix runs on
  clean loopback; lossy old/new behaviour is covered over simulated links
  (`connection_old_new.rs`, `connection_differential.rs`, `reliable_differential.rs`), not
  over sockets.
- What a 1.1.1 IPv4 client eventually does with an IPv6-only token after `connect` returned
  `Ok` was not measured (presumably a timeout).
- Releases with wire version 1 (before dream-net 1.1.0, which already speaks version 2) were
  not run: they are represented by the hand-driven wire-version-1 peer only.
