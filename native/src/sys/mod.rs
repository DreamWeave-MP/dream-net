//! Raw declarations of the C functions in the native archive.
//!
//! Every external C symbol carries the `dn_native_` prefix (`csrc/dn_native_prefix.h`), so a
//! declaration names the prefixed symbol, for example
//! `#[link_name = "dn_native_netcode_init"] fn netcode_init() -> c_int;`. Nothing here is
//! public; the safe wrappers in [`crate::netcode`] and [`crate::reliable`] are the only callers.

pub(crate) mod netcode;
pub(crate) mod reliable;
