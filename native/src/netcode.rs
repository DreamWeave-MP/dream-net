//! Safe wrapper over the vendored C netcode (v1.4.10 plus `patches/0001`).
//!
//! The public surface mirrors the subset of `netcode-official` 1.0.0 that dream-net calls, with
//! the same names and signatures, so moving dream-net onto it is a change of import. This
//! commit has the client side: [`Client`], [`ClientState`], [`generate_key`],
//! [`generate_connect_token`], [`Error`] and the constants. [`Client::receive_packet_into`] is an
//! addition: an allocation-free receive into a reused buffer.
//!
//! [`Client`] owns one C `netcode_client_t` and destroys it exactly once in `Drop`, which
//! disconnects first. It is neither `Send` nor `Sync`. No C pointer, key or token appears in any
//! public signature, `Debug` output or error message. Client creation is serialised behind one
//! process-wide lock, because it writes netcode's process-global create-error code, which is
//! read back under the same lock. [`generate_key`] and [`generate_connect_token`] may be called
//! from any thread: they initialise the library once behind a lock and then only use libsodium's
//! `randombytes_buf` (reentrant after `sodium_init`), its AEAD, and `time(NULL)`.
//!
//! The C is compiled with `NDEBUG`, so the wrappers check every precondition a `netcode_assert`
//! guards before calling in: payload sizes `1..=MAX_PAYLOAD_BYTES` (else
//! [`Error::InvalidPayloadSize`]), token address counts `1..=MAX_SERVERS_PER_CONNECT`, exact
//! buffer sizes, and non-null handles. The caller's clock is kept non-decreasing and finite, as
//! netcode requires; token timestamps use the wall clock (`time(NULL)`).

mod address;
mod client;
mod error;
mod token;

use core::ffi::c_int;
use std::sync::{Mutex, MutexGuard, PoisonError};

pub use client::{Client, ClientState};
pub use error::Error;
pub use token::{generate_connect_token, generate_key};

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

// The values above are the C headers' (pinned by _Static_assert in csrc/dn_native_netcode.c).

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
