//! The cross-language LTO probe: Rust calling a C function from the native archive.
//!
//! `tools/lto-probe` builds this twice, with and without linker-plugin LTO, and disassembles
//! `probe_caller`: inlined, it holds `dn_native_probe_mix`'s constants and no call to it; not
//! inlined, it calls it. Run directly, it only prints a value.

// CI passes -W clippy::pedantic on the command line, overriding the manifest's lint table.
#![allow(clippy::module_name_repetitions, clippy::cast_possible_truncation)]
#![deny(unsafe_op_in_unsafe_fn, clippy::undocumented_unsafe_blocks)]

// Links the native archive (and its build script's link directives) into this binary.
use dream_net_native as _;

unsafe extern "C" {
    #[link_name = "dn_native_probe_mix"]
    safe fn probe_mix(x: u32) -> u32;
}

/// The Rust function whose body the probe inspects.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn probe_caller(x: u32) -> u32 {
    probe_mix(x).wrapping_add(1)
}

fn main() {
    let input = std::hint::black_box(std::env::args().count() as u32);
    println!("{}", probe_caller(input));
}
