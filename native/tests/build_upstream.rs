//! Upstream's own C unit tests, and the port-0 regression for `patches/0001`, built from the
//! vendored sources with the archive's compiler and flags and run as separate executables.
//!
//! The test-enabled code is compiled here, at test time, into executables under `OUT_DIR`: it
//! never enters the production archive. Set `DREAM_NET_NATIVE_TEST_SANITIZE=address,undefined`
//! (any subset) to also build and run every program under Clang's sanitizers with their full
//! runtimes; a build with `DREAM_NET_NATIVE_SANITIZE` does the same. `BUILD.md` has the details.

// CI passes -W clippy::pedantic on the command line, overriding the manifest's lint table.
#![allow(clippy::module_name_repetitions)]

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

const PASSED: &str = "*** ALL TESTS PASSED ***";

/// The sanitizers build.rs instrumented the archive with (`DREAM_NET_NATIVE_SANITIZE`).
const BUILD_SANITIZE: &str = env!("DN_NATIVE_SANITIZE");

fn native() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The archive's own compile flags (from build.rs), minus what only the archive wants.
fn base_flags(sanitize: &str) -> Vec<String> {
    env!("DN_NATIVE_TEST_CFLAGS")
        .split('\u{1f}')
        .filter(|f| !f.is_empty())
        .filter(|f| {
            !f.starts_with("-DNETCODE_ENABLE_TESTS") && !f.starts_with("-DRELIABLE_ENABLE_TESTS")
        })
        // FORTIFY and ASan both interpose the libc string functions.
        .filter(|f| sanitize.is_empty() || !f.contains("_FORTIFY_SOURCE"))
        .map(str::to_owned)
        .collect()
}

fn sanitize_flags(sanitize: &str) -> Vec<String> {
    if sanitize.is_empty() {
        return Vec::new();
    }
    vec![
        format!("-fsanitize={sanitize}"),
        "-fno-sanitize-recover=all".to_owned(),
        "-fno-omit-frame-pointer".to_owned(),
    ]
}

fn run(command: &mut Command, what: &str) -> String {
    let output = command
        .output()
        .unwrap_or_else(|e| panic!("{what}: could not run {command:?}: {e}"));
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success(),
        "{what} failed ({}):\n{command:?}\n{text}",
        output.status
    );
    text
}

struct Unit<'a> {
    source: PathBuf,
    cxx: bool,
    extra: &'a [&'a str],
}

/// Compiles `units` and links them into one executable, which it returns.
fn build(name: &str, sanitize: &str, units: &[Unit<'_>]) -> PathBuf {
    let label = if sanitize.is_empty() {
        "plain".to_owned()
    } else {
        sanitize.replace(',', "+")
    };
    let dir = PathBuf::from(env!("OUT_DIR"))
        .join("upstream-tests")
        .join(name)
        .join(&label);
    std::fs::create_dir_all(&dir).expect("creating the test build directory");
    let cc = env!("DN_NATIVE_CC");
    let flags = base_flags(sanitize);
    let mut objects = Vec::new();
    for (index, unit) in units.iter().enumerate() {
        let object = dir.join(format!("{index}.o"));
        let mut command = Command::new(cc);
        command
            .args(&flags)
            .args(sanitize_flags(sanitize))
            .args(unit.extra);
        if unit.cxx {
            command.args(["-x", "c++", "-std=gnu++17", "-fno-exceptions", "-fno-rtti"]);
        } else {
            command.arg("-std=gnu99");
        }
        command.arg("-c").arg(&unit.source).arg("-o").arg(&object);
        run(
            &mut command,
            &format!("compiling {}", unit.source.display()),
        );
        objects.push(object);
    }
    let exe = dir.join(name);
    let mut link = Command::new(cc);
    link.args(flags.iter().filter(|f| f.starts_with("--target=")))
        .args(sanitize_flags(sanitize))
        .args(&objects)
        .arg("-o")
        .arg(&exe);
    if !env!("DN_NATIVE_LLD").is_empty() {
        link.arg("-fuse-ld=lld");
    }
    if cfg!(all(unix, not(target_vendor = "apple"))) {
        link.arg("-lm");
    }
    run(&mut link, &format!("linking {name}"));
    exe
}

/// Every sanitizer variant to run: always the plain build, plus the requested sanitizers.
fn variants() -> Vec<String> {
    let mut list = vec![String::new()];
    let requested = env::var("DREAM_NET_NATIVE_TEST_SANITIZE")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| BUILD_SANITIZE.to_owned());
    if !requested.is_empty() {
        list.push(requested);
    }
    list
}

fn execute(exe: &Path, expect: &str) {
    let mut command = Command::new(exe);
    // Upstream's real-socket functional tests stay opt-in, as in upstream's own CI default.
    command.env_remove("NETCODE_TEST_FUNCTIONAL");
    let output = run(&mut command, &exe.display().to_string());
    println!("{output}");
    assert!(
        output.contains(expect),
        "{} did not print {expect:?}",
        exe.display()
    );
}

fn sodium_unit() -> Unit<'static> {
    Unit {
        source: native().join("vendor/netcode/sodium/sodium.c"),
        cxx: false,
        extra: &["-Wno-unknown-pragmas"],
    }
}

#[test]
#[cfg_attr(
    target_env = "msvc",
    ignore = "the test build is not written for clang-cl yet (BUILD.md)"
)]
fn netcode_upstream_unit_tests_pass() {
    for sanitize in variants() {
        println!(
            "== netcode unit tests [{}]",
            if sanitize.is_empty() {
                "plain"
            } else {
                &sanitize
            }
        );
        let exe = build(
            "netcode_test",
            &sanitize,
            &[
                Unit {
                    source: native().join("vendor/netcode/test.cpp"),
                    cxx: true,
                    extra: &[],
                },
                sodium_unit(),
            ],
        );
        execute(&exe, PASSED);
    }
}

#[test]
#[cfg_attr(
    target_env = "msvc",
    ignore = "the test build is not written for clang-cl yet (BUILD.md)"
)]
fn reliable_upstream_unit_tests_pass() {
    for sanitize in variants() {
        println!(
            "== reliable unit tests [{}]",
            if sanitize.is_empty() {
                "plain"
            } else {
                &sanitize
            }
        );
        let exe = build(
            "reliable_test",
            &sanitize,
            &[
                Unit {
                    source: native().join("vendor/reliable/test.cpp"),
                    cxx: true,
                    extra: &[],
                },
                Unit {
                    source: native().join("vendor/reliable/reliable.c"),
                    cxx: false,
                    extra: &["-DRELIABLE_ENABLE_TESTS=1"],
                },
            ],
        );
        execute(&exe, PASSED);
    }
}

#[test]
#[cfg_attr(
    target_env = "msvc",
    ignore = "the test build is not written for clang-cl yet (BUILD.md)"
)]
fn a_port_zero_server_publishes_its_bound_port_and_accepts_tokens_for_it() {
    for sanitize in variants() {
        let exe = build(
            "port_zero",
            &sanitize,
            &[
                Unit {
                    source: native().join("csrc/test/port_zero.c"),
                    cxx: false,
                    extra: &[],
                },
                Unit {
                    source: native().join("vendor/netcode/netcode.c"),
                    cxx: false,
                    extra: &[],
                },
                sodium_unit(),
            ],
        );
        execute(&exe, "port_zero: OK");
    }
}
