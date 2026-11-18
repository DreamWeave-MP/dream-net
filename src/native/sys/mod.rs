//! Raw declarations of the C functions in the native archive.
//!
//! Every external C symbol carries the `dn_native_` prefix (`native/csrc/dn_native_prefix.h`), so a
//! declaration names the prefixed symbol, for example
//! `#[link_name = "dn_native_netcode_init"] fn netcode_init() -> c_int;`. Nothing here is
//! public; the safe wrappers in [`crate::native::netcode`] and [`crate::native::reliable`] are the only callers.

pub(crate) mod netcode;
pub(crate) mod reliable;

use core::ffi::c_int;
use std::sync::OnceLock;

// SAFETY: these declarations match `native/csrc/dn_native_shim.h`, `native/vendor/netcode/netcode.h` and
// `native/vendor/reliable/reliable.h` at the pinned commits: no arguments, and `int` or `void` returns.
unsafe extern "C" {
    fn dn_native_hooks_install();
    #[link_name = "dn_native_netcode_init"]
    fn netcode_init() -> c_int;
    #[link_name = "dn_native_reliable_init"]
    fn reliable_init() -> c_int;
}

/// Initialises the vendored libraries once for the process, and reports whether that worked.
///
/// Every wrapper constructor calls this before its first call into C. The C initialisers are
/// not thread safe (`netcode_init` counts references in a plain `int`, and libsodium's
/// `sodium_init` takes no lock outside Windows), so they run exactly once, here, inside the
/// [`OnceLock`]: concurrent first callers block until the one initialisation finishes.
///
/// Nothing is ever torn down. `netcode_term` on the last reference runs `WSACleanup` on
/// Windows, which would break every other socket user in the process.
pub(crate) fn ensure_init() -> bool {
    static READY: OnceLock<bool> = OnceLock::new();
    *READY.get_or_init(|| {
        // SAFETY: `OnceLock` runs this closure at most once and before any other call into the
        // archive, which is what `dn_native_hooks_install` requires. It takes no arguments and
        // only stores function pointers and log levels in the libraries' globals.
        unsafe { dn_native_hooks_install() };
        // SAFETY: called once, serialised by the `OnceLock`, with no arguments.
        let netcode = unsafe { netcode_init() };
        // SAFETY: as above.
        let reliable = unsafe { reliable_init() };
        // both return 1 (NETCODE_OK, RELIABLE_OK) on success
        netcode == 1 && reliable == 1
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn initialisation_succeeds_and_repeats() {
        assert!(super::ensure_init());
        assert!(super::ensure_init());
    }
}
