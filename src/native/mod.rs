//! **Not supported API.** The safe Rust bindings over Más Bandwidth's C
//! [netcode](https://github.com/mas-bandwidth/netcode) and
//! [reliable](https://github.com/mas-bandwidth/reliable) that dream-net is built on.
//!
//! This module is public only so that dream-net's own binding tests, benchmarks, fuzz
//! harnesses and interoperability crate can drive the bindings directly. It is hidden from the
//! documentation, it is not covered by semver, and it may change or disappear in any release.
//! Hosts use [`Server`](crate::Server), [`Client`](crate::Client) and the re-exports at the
//! crate root instead.
//!
//! The C is vendored at pinned commits under `native/vendor/` (see
//! `native/vendor/PROVENANCE.toml`), built by the crate's `build.rs` with a verified Clang into
//! one static archive whose every external symbol carries the `dn_native_` prefix, and wrapped
//! here in safe Rust. This module is the only place in dream-net where `unsafe` code is
//! allowed: the crate root denies it and every other module forbids it
//! (`tests/unsafe_confinement.rs` checks both).
//!
//! - [`netcode`](crate::native::netcode): secure connections over UDP (connect tokens,
//!   encryption, replay protection).
//! - [`reliable`](crate::native::reliable): packet acknowledgement, fragmentation and link
//!   statistics.
//!
//! `native/BUILD.md` documents the toolchain requirements and environment overrides,
//! `NOTICE.md` the licenses of the vendored code.

// The FFI rules the bindings were written under, kept as source attributes because CI's
// `-W clippy::pedantic -D warnings` on the command line overrides the manifest's levels.
#![deny(unsafe_op_in_unsafe_fn, clippy::undocumented_unsafe_blocks)]
#![warn(clippy::multiple_unsafe_ops_per_block)]
// The crate root allows the pedantic cast lints for dream-net's bit packing. The bindings were
// written and reviewed with them on, at every C boundary, so they stay on here.
#![warn(
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]

pub mod netcode;
pub mod reliable;
mod sys;
