//! Every external symbol the native archive defines carries the `dn_native_` prefix (shared
//! decision 4), so a host linking its own netcode, reliable or libsodium cannot collide with it.
//!
//! Runs `llvm-nm` (found by build.rs: `DREAM_NET_NATIVE_NM`, next to Clang, or on PATH) over the
//! archive build.rs produced. Without llvm-nm the test fails, unless
//! `DREAM_NET_NATIVE_SKIP_SYMBOL_CHECK=1` is set, in which case it says so and skips.

// CI passes -W clippy::pedantic on the command line, overriding the manifest's lint table.
#![allow(clippy::module_name_repetitions)]

use std::collections::BTreeSet;
use std::process::Command;

const PREFIX: &str = "dn_native_";

/// Compiler-generated, content-addressed COMDAT names that COFF objects define externally
/// (MSVC-ABI string literals and floating-point constants). They cannot carry a prefix and two
/// definitions of one name are identical by construction.
const COFF_GENERATED: &[&str] = &["??_C@", "__real@", "__xmm@", "__ymm@", "__zmm@", "@feat.00"];

fn defined_external_symbols() -> Option<BTreeSet<String>> {
    let nm = env!("DN_NATIVE_NM");
    if nm.is_empty() {
        if std::env::var_os("DREAM_NET_NATIVE_SKIP_SYMBOL_CHECK").is_some_and(|v| v == "1") {
            println!("SKIPPED: llvm-nm not found and DREAM_NET_NATIVE_SKIP_SYMBOL_CHECK=1");
            return None;
        }
        panic!(
            "llvm-nm was not found, so the symbol prefix cannot be checked. Install the LLVM \
             binutils, set DREAM_NET_NATIVE_NM, or set DREAM_NET_NATIVE_SKIP_SYMBOL_CHECK=1 to \
             skip this check knowingly."
        );
    }
    let archive = env!("DN_NATIVE_ARCHIVE");
    let output = Command::new(nm)
        .args([
            "--defined-only",
            "--extern-only",
            "--format=just-symbols",
            archive,
        ])
        .output()
        .unwrap_or_else(|e| panic!("running {nm}: {e}"));
    assert!(
        output.status.success(),
        "{nm} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).expect("llvm-nm prints UTF-8");
    let apple = cfg!(target_vendor = "apple");
    Some(
        text.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.ends_with(':'))
            .map(|l| {
                if apple {
                    l.strip_prefix('_').unwrap_or(l)
                } else {
                    l
                }
            })
            .map(str::to_owned)
            .collect(),
    )
}

#[test]
fn every_defined_external_symbol_has_the_prefix() {
    let Some(symbols) = defined_external_symbols() else {
        return;
    };
    let unprefixed: Vec<&String> = symbols
        .iter()
        .filter(|s| !s.starts_with(PREFIX))
        .filter(|s| !(cfg!(windows) && COFF_GENERATED.iter().any(|g| s.starts_with(g))))
        // An ASan-instrumented archive (DREAM_NET_NATIVE_SANITIZE=address) adds the runtime's
        // registration flag and one ODR indicator per instrumented global, named after the
        // already-prefixed global.
        .filter(|s| {
            !(env!("DN_NATIVE_SANITIZE").contains("address")
                && (s.as_str() == "___asan_globals_registered"
                    || s.starts_with(&format!("__odr_asan_gen_{PREFIX}"))))
        })
        .collect();
    assert!(
        unprefixed.is_empty(),
        "the native archive defines {} external symbols without the {PREFIX} prefix: {unprefixed:?}\n\
         Add them to native/csrc/dn_native_prefix.h by running native/tools/gen-prefix-header (or, for a \
         platform-only symbol, to its EXTRA list).",
        unprefixed.len()
    );
    println!("{} external symbols, all prefixed", symbols.len());
}

#[test]
fn the_archive_defines_the_entry_points_under_their_prefixed_names() {
    let Some(symbols) = defined_external_symbols() else {
        return;
    };
    for name in [
        "netcode_init",
        "netcode_server_create",
        "netcode_generate_connect_token",
        "reliable_init",
        "reliable_endpoint_create",
        "sodium_init",
        "crypto_aead_xchacha20poly1305_ietf_encrypt",
        "randombytes_buf",
    ] {
        assert!(
            symbols.contains(&format!("{PREFIX}{name}")),
            "{PREFIX}{name} is not defined"
        );
        assert!(
            !symbols.contains(name),
            "{name} is defined without the prefix"
        );
    }
    for shim in ["dn_native_hooks_install", "dn_native_probe_mix"] {
        assert!(symbols.contains(shim), "{shim} is not defined");
    }
}
