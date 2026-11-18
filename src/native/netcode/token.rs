//! Keys and connect tokens.

use core::ffi::{c_char, c_int};
use std::net::SocketAddr;

use super::address::CAddress;
use super::{CONNECT_TOKEN_BYTES, Error, KEY_BYTES, Key, MAX_SERVERS_PER_CONNECT, UserData};
use crate::native::sys;
use crate::native::sys::netcode as ffi;

/// A fresh private key from the operating system's CSPRNG (libsodium's `randombytes_buf`,
/// through `netcode_random_bytes`).
///
/// Callable from any thread: the library is initialised once behind a lock first, and
/// `randombytes_buf` is reentrant after that (`native/SODIUM.md`).
///
/// # Panics
///
/// If the native library cannot be initialised (libsodium's `sodium_init` failed, which means
/// the OS random source is unusable). libsodium itself aborts the process if a later read of
/// the OS random source fails, so a key is never made from an unfilled buffer.
pub fn generate_key() -> Key {
    const KEY_LEN: c_int = 32;
    const _: () = assert!(KEY_LEN as usize == KEY_BYTES);
    assert!(
        sys::ensure_init(),
        "the native netcode library could not be initialised"
    );
    let mut key = [0u8; KEY_BYTES];
    // SAFETY: the library is initialised; `key` is a writable buffer of exactly the length
    // passed, which is positive (netcode_random_bytes asserts data != NULL and bytes > 0).
    unsafe { ffi::netcode_random_bytes(key.as_mut_ptr(), KEY_LEN) };
    key
}

/// Mints a connect token, as `netcode-official` 1.0.0's function of the same name.
///
/// `public_server_addresses` go into the token's public part, which the client reads to know
/// where to connect; `internal_server_addresses` go into the encrypted part, which a server
/// checks its own public address against. Both lists must have the same length, in
/// `1..=MAX_SERVERS_PER_CONNECT`, or the result is [`Error::InvalidServerAddresses`]. Only the
/// IP and port of each address are written: an IPv6 scope id or flow label is ignored, because
/// the token format cannot carry it (as in `netcode-official`).
///
/// The create timestamp is the **wall clock** (`time(NULL)`, whole seconds), and the token
/// expires `expire_seconds` later; a negative `expire_seconds` means it never expires
/// (`u64::MAX`). Such a token also passes every server's start floor (see the module docs),
/// so prefer a finite lifetime no longer than the servers' maximum connect-token lifetime.
/// A negative `timeout_seconds` disables the connection timeout for sessions made with it.
///
/// Callable from any thread.
///
/// # Errors
///
/// [`Error::InvalidServerAddresses`] as above, [`Error::EncryptFailed`] if netcode could not
/// encrypt the token, and [`Error::Io`] if the native library cannot be initialised.
#[allow(clippy::too_many_arguments)]
pub fn generate_connect_token(
    public_server_addresses: &[SocketAddr],
    internal_server_addresses: &[SocketAddr],
    expire_seconds: i32,
    timeout_seconds: i32,
    client_id: u64,
    protocol_id: u64,
    private_key: &Key,
    user_data: &UserData,
) -> Result<[u8; CONNECT_TOKEN_BYTES], Error> {
    let count = public_server_addresses.len();
    if count == 0 || count > MAX_SERVERS_PER_CONNECT || count != internal_server_addresses.len() {
        return Err(Error::InvalidServerAddresses);
    }
    let Ok(num_server_addresses) = c_int::try_from(count) else {
        return Err(Error::InvalidServerAddresses);
    };
    if !sys::ensure_init() {
        return Err(super::error::init_failed());
    }
    let public: Vec<CAddress> = public_server_addresses
        .iter()
        .map(|a| CAddress::new(*a))
        .collect();
    let internal: Vec<CAddress> = internal_server_addresses
        .iter()
        .map(|a| CAddress::new(*a))
        .collect();
    let public_ptrs: Vec<*const c_char> = public.iter().map(CAddress::as_ptr).collect();
    let internal_ptrs: Vec<*const c_char> = internal.iter().map(CAddress::as_ptr).collect();
    // netcode declares user_data non-const; give it a copy so the caller's stays untouched
    // whatever the C does with it (it only reads it).
    let mut user_data = *user_data;
    let mut token = [0u8; CONNECT_TOKEN_BYTES];
    // SAFETY: the library is initialised. `count` is in 1..=32 (checked above), and both pointer
    // arrays hold exactly `count` pointers to NUL-terminated strings that outlive the call
    // (`public`, `internal`). `private_key` points at KEY_BYTES readable bytes, `user_data` at
    // USER_DATA_BYTES writable bytes, `token` at CONNECT_TOKEN_BYTES writable bytes: the sizes
    // netcode reads and writes. These are every assert in netcode_generate_connect_token. The
    // function touches no process global other than libsodium's initialised RNG and
    // `time(NULL)`, so concurrent calls are sound.
    let result = unsafe {
        ffi::netcode_generate_connect_token(
            num_server_addresses,
            public_ptrs.as_ptr(),
            internal_ptrs.as_ptr(),
            expire_seconds,
            timeout_seconds,
            client_id,
            protocol_id,
            private_key.as_ptr(),
            user_data.as_mut_ptr(),
            token.as_mut_ptr(),
        )
    };
    if result == ffi::OK {
        Ok(token)
    } else {
        // Every address was formatted by us and parses, so the only failure left is the
        // encryption of the private part.
        Err(Error::EncryptFailed)
    }
}
