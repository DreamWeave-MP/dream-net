//! **dream-net-native** compiles and links Más Bandwidth's C
//! [netcode](https://github.com/mas-bandwidth/netcode) and
//! [reliable](https://github.com/mas-bandwidth/reliable) for dream-net.
//!
//! The C is vendored at pinned commits under `vendor/` (see `vendor/PROVENANCE.toml`), built
//! by `build.rs` with a verified Clang into one static archive whose every external symbol
//! carries the `dn_native_` prefix, and wrapped here in safe Rust. This is the only crate in
//! dream-net that contains `unsafe` code; dream-net itself stays `forbid(unsafe_code)`.
//!
//! - [`netcode`]: secure connections over UDP (connect tokens, encryption, replay protection).
//! - [`reliable`]: packet acknowledgement, fragmentation and link statistics.
//!
//! `BUILD.md` documents the toolchain requirements and environment overrides, `NOTICE.md` the
//! licenses of the vendored code.

// CI passes -W clippy::pedantic on the command line, which overrides the manifest's lint
// table, so the crate's allows are repeated here.
#![allow(clippy::module_name_repetitions, clippy::must_use_candidate)]
#![deny(unsafe_op_in_unsafe_fn, clippy::undocumented_unsafe_blocks)]
#![warn(clippy::multiple_unsafe_ops_per_block)]

pub mod netcode;
pub mod reliable;
mod sys;
