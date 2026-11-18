//! Cross-language LTO evidence (BUILD.md, "Cross-language LTO"), as an opt-in test.
//!
//! Runs `tools/lto-probe`, which builds `examples/lto_probe.rs` five ways in release under its
//! own target directory and disassembles the Rust caller of a C function. Ignored by default: it
//! runs five release builds and needs a Linux host with Clang, LLD and llvm-objdump of rustc's
//! LLVM major.
//!
//! ```sh
//! cargo test -p dream-net-native --test build_lto -- --ignored --nocapture
//! ```

// CI passes -W clippy::pedantic on the command line, overriding the manifest's lint table.
#![allow(clippy::module_name_repetitions)]

use std::process::Command;

#[test]
#[ignore = "five release builds; run with --ignored on Linux with Clang/LLD of rustc's LLVM major"]
fn clang_bitcode_inlines_into_rust_across_the_ffi_boundary() {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tools/lto-probe");
    let output = Command::new("sh")
        .arg(script)
        // The probe sets its own RUSTFLAGS per build; this test's must not leak in.
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("DREAM_NET_NATIVE_LTO")
        .output()
        .expect("running tools/lto-probe");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    println!("{text}");
    assert!(output.status.success(), "tools/lto-probe failed");
    assert!(text.contains("lto-probe: PASS"));
}
