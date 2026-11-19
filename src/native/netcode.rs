//! Safe wrapper over the vendored C netcode (v1.4.10 plus `native/patches/0001`).
//!
//! The public surface mirrors the subset of `netcode-official` 1.0.0 that dream-net calls, with
//! the same names and signatures, so moving dream-net onto it is a change of import. Where C
//! netcode is stricter on purpose, C wins (campaign decision 12): see "Behaviour that differs
//! from netcode-official" below. Additions: [`Server::receive_packet_into`] and
//! [`Client::receive_packet_into`] (allocation-free receive into a reused buffer),
//! [`Server::with_options`] with [`ServerOptions`] (the maximum connect-token lifetime),
//! [`Server::options`] and [`Error::InvalidConnectTokenLifetime`].
//!
//! # Ownership and threads
//!
//! [`Client`] owns one C `netcode_client_t`; [`Server`] owns one shim handle holding a C
//! `netcode_server_t` and the fixed per-slot storage its connect/disconnect callback writes.
//! `Drop` destroys each exactly once: the client disconnects first (sending disconnect
//! packets), the server stops first (disconnecting everyone) and only then is the callback's
//! storage freed, so no callback can outlive its context. No C pointer, handle, key or token
//! appears in any public signature, `Debug` output or error message; the server's private key
//! is copied into netcode (which zeroes it on destruction) and not kept in Rust.
//!
//! `Server` and `Client` are neither `Send` nor `Sync`. Nothing needs them to be (dream-net's own
//! `Server` and `Client` never were), and netcode's objects are not designed for use from
//! several threads. They are `Unpin`. [`Error`], [`ClientState`], [`ServerEvent`],
//! [`DisconnectReason`] and [`ServerOptions`] are plain data, `Send + Sync`. All of this is
//! pinned by compile-time assertions in `tests/native_netcode_traits.rs`.
//!
//! Different threads may each own their own servers and clients: creates are serialised behind
//! one process-wide lock (they write netcode's process-global create-error code, which the
//! wrapper reads under the same lock), and nothing else in netcode's create, update, send or
//! receive paths writes process-global state (packet tagging is never enabled, logging is
//! silenced once at initialisation). [`generate_key`] and [`generate_connect_token`] may be
//! called from any thread: they initialise the library once behind a lock and then only use
//! libsodium's `randombytes_buf` (reentrant after `sodium_init`, `native/SODIUM.md`), its AEAD, and
//! `time(NULL)`.
//!
//! # Time
//!
//! Two clocks are involved, and they must not be confused:
//!
//! - The **caller's clock**: the `time` argument (seconds, `f64`) of the constructors and of
//!   `update`. It drives every state machine: keep-alives (10 Hz), connection and handshake
//!   timeouts (the token's `timeout_seconds`), the client's token-expiry check (the token's
//!   lifetime counted from `connect`), and the server's encryption-mapping and pending-token
//!   lifetimes. netcode requires it to be non-decreasing; the wrappers replace an earlier or
//!   non-finite time with the latest one (and a non-finite initial time with 0).
//! - The **wall clock**: `time(NULL)`, whole Unix seconds, read inside C. It stamps a token's
//!   create and expire timestamps in [`generate_connect_token`], decides on the server whether a
//!   token has expired (`expire <= now` is refused), and sets the server's start floor in
//!   [`Server::start`]. None of these can be driven by the caller's clock.
//!
//! # Token lifetime and the start floor
//!
//! [`Server::start`] records `floor = wall_clock_now + max_connect_token_lifetime` (30 s by
//! default, [`ServerOptions`] to change it). A connection request is ignored when its token's
//! expire timestamp is `<= floor` (`netcode.c`: `packet_connect_token_expire_timestamp <=
//! min_connect_token_expire_timestamp`). So, with lifetime `L` and maximum `M`:
//!
//! - a token minted `k` whole seconds after the start second is accepted only if `k + L > M`;
//!   in particular a token with `L <= M` minted in the start second itself is **refused**, and
//!   a token with the default 30 s lifetime is accepted from the next second on (with `M = 30`);
//! - a token minted before the start (any `k < 0`) with `L <= M` is refused: this is the
//!   restart protection (audit S2). A token with `L > M` minted before the start can still be
//!   accepted, so the protection covers only tokens no longer-lived than `M`;
//! - a token that never expires (negative `expire_seconds`) always passes the floor.
//!
//! The floor is set again on every `start`, including a restart of the same `Server`.
//! `netcode-official` 1.0.0 had no floor.
//!
//! # Events
//!
//! netcode reports slot changes through a `connect_disconnect_callback`. It lands in C, in the
//! shim (`native/csrc/dn_native_netcode.c`), never in Rust, so nothing can unwind through a C frame.
//! The callback only writes fixed per-slot storage in the server handle: a connect count, a
//! disconnect count, the reason of the first disconnect since the last read, the connected
//! flag, and the client id, address and user data captured at connect time. It never
//! allocates. It fires inside [`Server::update`], [`Server::disconnect_client`],
//! [`Server::disconnect_all_clients`], [`Server::stop`], [`Server::start`] (a restart stops
//! first), and `Drop`.
//!
//! [`Server::next_event`] turns that record into events when its queue runs empty: every
//! `ClientDisconnected` first, in slot order, then every `ClientConnected`, in slot order. The
//! queue holds at most two events per slot (512) and is allocated once. Per slot this
//! guarantees:
//!
//! - a reported `ClientConnected` is always followed by exactly one `ClientDisconnected` before
//!   the slot's next `ClientConnected`, even when the slot was vacated and reused inside one
//!   `update`; the reason is the one netcode recorded for the end of the reported session;
//! - the identity [`Server::client_id`], [`Server::client_address`] and
//!   [`Server::client_user_data`] return is the one captured when the current occupant
//!   connected, and they answer only while netcode reports the slot connected, so a stale
//!   identity never survives a reuse;
//! - a session that both began and ended between two batches (a client that completed its
//!   handshake and left again inside one `update`) is not reported at all. No host-visible
//!   traffic can have flowed in it. This is the price of fixed-size storage: netcode's receive
//!   loop drains the socket without bound, so no fixed queue could hold every transition.
//!
//! Drain `next_event` after every `update`, as dream-net does: an event read after a later
//! call that changed the slot again describes the slot as of the batch it came from.
//!
//! # Addresses
//!
//! Addresses are `SocketAddr`, IPv4 or IPv6, passed to C as `a.b.c.d:port` / `[v6]:port`
//! strings and read back through the shim's layout-pinned flat form. netcode cannot represent an
//! IPv6 scope id or flow label: [`Client::new`] refuses a bind address with a scope id
//! ([`Error::Io`], `InvalidInput`) rather than binding without it; [`Server::new`] (which binds
//! the unspecified address anyway) and [`generate_connect_token`] ignore both, as
//! `netcode-official` did. Addresses read back always have both zero.
//!
//! A server's public address is what tokens are checked against, byte for byte (IP and port).
//! Port 0 binds an ephemeral port, which [`Server::address`]/[`Server::port`] report and tokens
//! must name (patch 0001). An unspecified public address (`0.0.0.0`/`[::]`) is accepted, but
//! then only tokens naming that unspecified address pass the check, and a client cannot
//! usefully connect to it (replies come from a concrete address, which the client refuses):
//! give the server the address clients will use. `netcode-official` 1.0.0 behaved the same.
//!
//! # Behaviour that differs from `netcode-official` 1.0.0
//!
//! | | `netcode-official` 1.0.0 | this binding (C 1.4.10) |
//! | --- | --- | --- |
//! | Token reuse (audit D1, S1) | the same token reconnects from the same address | single use: refused once a session was established with it |
//! | A token passed to `Client::connect` again in the same process | starts another attempt | refused by `connect` with `InvalidConnectToken` before anything is sent: a token admits one connection attempt ([`Client::connect`]) |
//! | Token predating the start (D2, S2, S5) | accepted | refused at or below the start floor (above) |
//! | Zero-length datagram (D5, S3) | ends the receive loop for that update | skipped |
//! | Server disconnect, multi-address token (D8, S4) | client tries the next server | client goes `Disconnected` |
//! | Token history full (D3) | evicts the oldest entry | refuses new tokens until one expires |
//! | Token with no address of the client's family | accepted, then times out | `connect` returns `InvalidConnectToken` |
//! | `next_event` | unbounded FIFO of every transition | bounded, per-slot synthesis (above) |
//! | Getters for a slot | read slot state | identity captured at connect |
//! | Time | used as given | clamped non-decreasing, non-finite ignored |
//! | `Client::new` with an IPv6 scope id | bound with it | refused |
//! | Errors | `Io` carries the OS error | `Io` built from netcode's create code plus the OS error seen right after |
//!
//! Payload sizes, the `Ok(())` no-ops of sends to empty slots or stopped servers, `Display`
//! texts, port 0, state names and the meaning of every getter follow `netcode-official`.
//!
//! # Preconditions
//!
//! The C is compiled with `NDEBUG` (native/BUILD.md, "Assertions"), so a `netcode_assert` is never a
//! check. Every assert in each C function this module calls is either guaranteed by
//! construction or checked in Rust before the call:
//!
//! | C function | Asserts | Where it is enforced |
//! | --- | --- | --- |
//! | `netcode_init` | (none) | `sys::ensure_init`, once per process, before any other call |
//! | `netcode_random_bytes` | `data`, `bytes > 0` | [`generate_key`]: a 32-byte array |
//! | `netcode_generate_connect_token` | `1 <= num <= 32`, address arrays, key, user data, output non-null | [`generate_connect_token`] checks the count and that both lists match (also re-checked in C); every pointer is to a Rust buffer of the size C uses; addresses are formatted by us and always parse |
//! | `netcode_client_create` (shim) | config non-null, `netcode.initialized` | shim builds the config; constructor calls `ensure_init` |
//! | `netcode_client_destroy` | `client` | `NonNull`, only in `Drop` |
//! | `netcode_client_connect` | `client`, `connect_token` | `NonNull`; `&[u8; 2048]` (C reads exactly 2048 and never writes) |
//! | `netcode_client_update`, `_disconnect`, receive/send internals | `client`, `!loopback` | `NonNull`; loopback is never entered |
//! | `netcode_client_send_packet` | `client`, `packet_data`, `1 <= bytes <= 1200` | [`Client::send_packet`] refuses other sizes with `InvalidPayloadSize` |
//! | `netcode_client_receive_packet` | `client`, `packet_bytes`, payload size `0..=1200` | out-pointers are locals; a size outside `1..=1200` is dropped |
//! | `netcode_client_free_packet` | `client`, `packet` | only a non-null pointer just received, freed once |
//! | `netcode_client_state`, `_index`, `_max_clients`, `_next_packet_sequence`, `_get_port`, `_server_address` | `client` | `NonNull` |
//! | `netcode_server_create` (shim) | config non-null, `netcode.initialized` | as the client; the lifetime is checked `> 0` and `<= i32::MAX` |
//! | `netcode_server_destroy` (shim), `_stop`, `_update`, `_running`, `_num_connected_clients`, `_disconnect_all_clients`, `_get_port` | `server` | `NonNull`, destroy only in `Drop` |
//! | `netcode_server_start` | `server`, `1 <= max_clients <= 256` | [`Server::start`] refuses others with `InvalidMaxClients` |
//! | `netcode_server_disconnect_client` | `server`, `running`, `0 <= index < max_clients`, slot connected and not loopback | called only for a slot `netcode_server_client_connected` reports connected |
//! | `netcode_server_send_packet` | `server`, `packet_data`, `1 <= bytes <= 1200`, `0 <= index < max_clients` | size checked first (`InvalidPayloadSize`); then only for a connected slot |
//! | `netcode_server_receive_packet` | `server`, `packet_bytes`, `0 <= index < max_clients`, payload size | only for a connected slot; sizes as the client |
//! | `netcode_server_free_packet` | `server`, `packet` | as the client |
//! | `netcode_server_next_packet_sequence` | `server`, `0 <= index < max_clients` | only for a connected slot |
//! | `netcode_server_client_connected` | `server` | range and running checked by C itself; Rust passes only `index < 256` |
//! | `netcode_server_client_id`, `_client_address`, `_client_user_data`, `_client_disconnect_reason` | `server`, index range | called only from the shim's callback, with the index netcode passed it |
//!
//! Remote input reaches only netcode's receive paths, whose asserts are structural (native/BUILD.md,
//! "Assertions"; audit S8); every content check there is a real `if`.

mod address;
mod client;
mod error;
mod server;
mod token;
mod used_tokens;

use core::ffi::c_int;
use std::sync::{Mutex, MutexGuard, PoisonError};

pub use client::{Client, ClientState};
pub use error::Error;
pub use server::{DisconnectReason, Server, ServerEvent, ServerOptions};
pub use token::{generate_connect_token, generate_key};
pub use used_tokens::CONNECT_TOKEN_RECORD_CAPACITY;

/// Bytes in a connect token (`NETCODE_CONNECT_TOKEN_BYTES`).
pub const CONNECT_TOKEN_BYTES: usize = 2048;

/// Bytes in a private key (`NETCODE_KEY_BYTES`).
pub const KEY_BYTES: usize = 32;

/// Bytes in an AEAD tag (`NETCODE_MAC_BYTES`).
pub const MAC_BYTES: usize = 16;

/// Bytes of user data in a connect token (`NETCODE_USER_DATA_BYTES`).
pub const USER_DATA_BYTES: usize = 256;

/// Most server addresses a connect token can list (`NETCODE_MAX_SERVERS_PER_CONNECT`).
pub const MAX_SERVERS_PER_CONNECT: usize = 32;

/// Most client slots a server can have (`NETCODE_MAX_CLIENTS`).
pub const MAX_CLIENTS: usize = 256;

/// Largest payload in one packet (`NETCODE_MAX_PACKET_SIZE`).
pub const MAX_PAYLOAD_BYTES: usize = 1200;

/// A private key.
pub type Key = [u8; KEY_BYTES];

/// User data carried in a connect token.
pub type UserData = [u8; USER_DATA_BYTES];

// The values above are the C headers' (pinned by _Static_assert in native/csrc/dn_native_netcode.c).

/// Serialises every client and server create: each writes a process-global error code that is
/// read back right after.
fn create_lock() -> MutexGuard<'static, ()> {
    static CREATE: Mutex<()> = Mutex::new(());
    CREATE.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The caller's clock, kept non-decreasing and finite as netcode requires.
#[derive(Debug, Clone, Copy)]
struct Time(f64);

impl Time {
    fn new(time: f64) -> Self {
        Self(if time.is_finite() { time } else { 0.0 })
    }

    fn now(self) -> f64 {
        self.0
    }

    fn advance(&mut self, time: f64) -> f64 {
        if time.is_finite() && time > self.0 {
            self.0 = time;
        }
        self.0
    }
}

/// Copies a received payload into `buffer`; false (buffer left empty) for a size netcode never
/// produces.
///
/// # Safety
///
/// `packet` must be non-null and point at `bytes` readable bytes for the duration of the call.
unsafe fn copy_payload(packet: *const u8, bytes: c_int, buffer: &mut Vec<u8>) -> bool {
    let Ok(len) = usize::try_from(bytes) else {
        return false;
    };
    if len == 0 || len > MAX_PAYLOAD_BYTES {
        return false;
    }
    // SAFETY: the caller guarantees `len` readable bytes at the non-null `packet`; the slice
    // lives only for this copy.
    let payload = unsafe { std::slice::from_raw_parts(packet, len) };
    buffer.extend_from_slice(payload);
    true
}

#[cfg(test)]
mod tests {
    use super::Time;

    #[test]
    fn time_never_goes_backwards_or_leaves_the_finite_numbers() {
        let mut t = Time::new(f64::NAN);
        assert!(t.now().abs() < f64::EPSILON);
        assert!((t.advance(2.0) - 2.0).abs() < f64::EPSILON);
        assert!((t.advance(1.0) - 2.0).abs() < f64::EPSILON);
        assert!((t.advance(f64::INFINITY) - 2.0).abs() < f64::EPSILON);
        assert!((t.advance(f64::NAN) - 2.0).abs() < f64::EPSILON);
        assert!((t.advance(2.5) - 2.5).abs() < f64::EPSILON);
    }
}
