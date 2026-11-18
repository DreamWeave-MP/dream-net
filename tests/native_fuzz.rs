//! The deterministic smoke form of the native fuzz harnesses (`native/csrc/test/fuzz_*.c`, issue #12).
//!
//! Each harness is built here, at test time, as a standalone program (`-DDN_FUZZ_STANDALONE`)
//! with the archive's own flags, and run over a fixed number of seeded pseudo-random inputs, in
//! two configurations: the production one (asserts compiled out, as in the archive) and one
//! with every `netcode_assert` and `reliable_assert` compiled in and fatal. A failed oracle,
//! a live assert, or (with `DREAM_NET_NATIVE_TEST_SANITIZE=address,undefined`, or an archive
//! built with `DREAM_NET_NATIVE_SANITIZE`) a sanitizer report fails the test. Each run must
//! also reach the states that make it meaningful (connections, deliveries, processed packets),
//! so a harness that silently stopped reaching them fails too.
//!
//! The same harnesses run under libFuzzer for hours with `native/tools/fuzz-native`; nothing here
//! enters the production archive.

// CI passes -W clippy::pedantic on the command line, overriding the manifest's lint table.
#![allow(clippy::module_name_repetitions)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Mutex, PoisonError};

/// The sanitizers build.rs instrumented the archive with (`DREAM_NET_NATIVE_SANITIZE`).
const BUILD_SANITIZE: &str = env!("DN_NATIVE_SANITIZE");

fn native() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("native")
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

#[derive(Clone, Copy, PartialEq)]
enum Asserts {
    /// The archive's configuration: `NDEBUG`, `NETCODE_RELEASE`, `RELIABLE_RELEASE`.
    Production,
    /// Every assert compiled in; the harness makes each one fatal.
    Live,
}

/// The archive's flags, adjusted for `asserts` and `sanitize`.
fn flags(asserts: Asserts, sanitize: &str) -> Vec<String> {
    let mut flags: Vec<String> = env!("DN_NATIVE_TEST_CFLAGS")
        .split('\u{1f}')
        .filter(|f| !f.is_empty())
        // FORTIFY and ASan both interpose the libc string functions.
        .filter(|f| sanitize.is_empty() || !f.contains("_FORTIFY_SOURCE"))
        .filter(|f| {
            asserts == Asserts::Production
                || !(f.starts_with("-DNDEBUG")
                    || f.starts_with("-DNETCODE_RELEASE")
                    || f.starts_with("-DRELIABLE_RELEASE"))
        })
        .map(str::to_owned)
        .collect();
    if asserts == Asserts::Live {
        flags.extend(["-UNDEBUG", "-DNETCODE_DEBUG", "-DRELIABLE_DEBUG"].map(str::to_owned));
    }
    if !sanitize.is_empty() {
        flags.extend([
            format!("-fsanitize={sanitize}"),
            "-fno-sanitize-recover=all".to_owned(),
            "-fno-omit-frame-pointer".to_owned(),
        ]);
    }
    flags.push("-DDN_FUZZ_STANDALONE".to_owned());
    flags.push(format!("-I{}", native().join("vendor/reliable").display()));
    flags.push(format!("-I{}", native().join("csrc/test").display()));
    flags
}

/// Builds `harness` (with sodium for the netcode ones) once per test process and returns the
/// executable.
///
/// Tests run on parallel threads and two of them run the server harness, so the builds are
/// serialised and remembered: rebuilding an executable in place while another test executes
/// it fails that test with "No such file or directory" while the linker replaces the file.
fn build(harness: &str, asserts: Asserts, sanitize: &str) -> PathBuf {
    static BUILT: Mutex<BTreeMap<(String, bool, String), PathBuf>> = Mutex::new(BTreeMap::new());
    let mut built = BUILT.lock().unwrap_or_else(PoisonError::into_inner);
    let key = (
        harness.to_owned(),
        asserts == Asserts::Live,
        sanitize.to_owned(),
    );
    if let Some(exe) = built.get(&key) {
        return exe.clone();
    }
    let exe = build_uncached(harness, asserts, sanitize);
    built.insert(key, exe.clone());
    exe
}

fn build_uncached(harness: &str, asserts: Asserts, sanitize: &str) -> PathBuf {
    let label = format!(
        "{}-{}",
        if asserts == Asserts::Live {
            "live"
        } else {
            "prod"
        },
        if sanitize.is_empty() {
            "plain".to_owned()
        } else {
            sanitize.replace(',', "+")
        }
    );
    let dir = PathBuf::from(env!("OUT_DIR"))
        .join("fuzz-native")
        .join(harness)
        .join(label);
    std::fs::create_dir_all(&dir).expect("creating the test build directory");
    let cc = env!("DN_NATIVE_CC");
    let flags = flags(asserts, sanitize);
    let mut units = vec![(native().join(format!("csrc/test/{harness}.c")), Vec::new())];
    if harness.contains("netcode") {
        units.push((
            native().join("vendor/netcode/sodium/sodium.c"),
            vec!["-Wno-unknown-pragmas"],
        ));
    }
    let mut objects = Vec::new();
    for (index, (source, extra)) in units.iter().enumerate() {
        let object = dir.join(format!("{index}.o"));
        run(
            Command::new(cc)
                .args(&flags)
                .args(extra)
                .arg("-std=gnu99")
                .arg("-c")
                .arg(source)
                .arg("-o")
                .arg(&object),
            &format!("compiling {}", source.display()),
        );
        objects.push(object);
    }
    let exe = dir.join(harness);
    let mut link = Command::new(cc);
    link.args(
        flags
            .iter()
            .filter(|f| f.starts_with("--target=") || f.starts_with("-fsanitize")),
    )
    .args(&objects)
    .arg("-o")
    .arg(&exe);
    if !env!("DN_NATIVE_LLD").is_empty() {
        link.arg("-fuse-ld=lld");
    }
    if cfg!(all(unix, not(target_vendor = "apple"))) {
        link.arg("-lm");
    }
    run(&mut link, &format!("linking {harness}"));
    exe
}

/// The sanitizer variants to run besides the plain build.
fn sanitize_variants() -> Vec<String> {
    let mut list = vec![String::new()];
    let requested = std::env::var("DREAM_NET_NATIVE_TEST_SANITIZE")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| BUILD_SANITIZE.to_owned());
    if !requested.is_empty() {
        list.push(requested);
    }
    list
}

/// Runs `harness` over `iterations` inputs of up to `max_len` bytes in every configuration and
/// requires each counter in `reached` to be non-zero.
fn smoke(harness: &str, iterations: u32, max_len: u32, reached: &[&str]) {
    for sanitize in sanitize_variants() {
        for asserts in [Asserts::Production, Asserts::Live] {
            let exe = build(harness, asserts, &sanitize);
            let output = run(
                Command::new(&exe).args([
                    "--iterations",
                    &iterations.to_string(),
                    "--seed",
                    "20261118",
                    "--max-len",
                    &max_len.to_string(),
                ]),
                harness,
            );
            println!("{output}");
            assert!(
                output.contains(&format!("{harness}: {iterations} inputs OK")),
                "{output}"
            );
            for counter in reached {
                let line = output
                    .lines()
                    .find(|l| l.starts_with(&format!("{harness}: {counter} ")))
                    .unwrap_or_else(|| panic!("{harness} never reached `{counter}`:\n{output}"));
                let count: u64 = line.rsplit(' ').next().unwrap().parse().unwrap();
                assert!(count > 0, "{line}");
            }
        }
    }
}

#[test]
#[cfg_attr(
    target_env = "msvc",
    ignore = "the test build is not written for clang-cl yet (native/BUILD.md)"
)]
fn the_netcode_server_harness_holds_its_oracles() {
    smoke(
        "fuzz_netcode_server",
        1500,
        1024,
        &[
            "connects",
            "disconnects",
            "payloads delivered",
            "challenges",
        ],
    );
}

#[test]
#[cfg_attr(
    target_env = "msvc",
    ignore = "the test build is not written for clang-cl yet (native/BUILD.md)"
)]
fn the_netcode_client_harness_holds_its_oracles() {
    smoke(
        "fuzz_netcode_client",
        6000,
        1024,
        &[
            "connected",
            "payloads received",
            "connected sessions ended",
            "moved to the next server",
        ],
    );
}

#[test]
#[cfg_attr(
    target_env = "msvc",
    ignore = "the test build is not written for clang-cl yet (native/BUILD.md)"
)]
fn the_reliable_pair_harness_holds_its_oracles() {
    smoke(
        "fuzz_reliable_pair",
        6000,
        1024,
        &["packets processed", "inputs holding reassembly memory"],
    );
}

/// Runs `harness` on one scripted input in every configuration and returns each output.
fn scripted(harness: &str, name: &str, input: &[u8]) -> Vec<String> {
    let path = PathBuf::from(env!("OUT_DIR")).join(format!("fuzz-native-{name}.bin"));
    std::fs::write(&path, input).expect("writing the scripted input");
    let mut outputs = Vec::new();
    for sanitize in sanitize_variants() {
        for asserts in [Asserts::Production, Asserts::Live] {
            let exe = build(harness, asserts, &sanitize);
            let output = run(Command::new(&exe).arg(&path), harness);
            assert!(
                output.contains(&format!("{harness}: 1 inputs OK")),
                "{output}"
            );
            outputs.push(output);
        }
    }
    outputs
}

/// The value of a harness counter in `output`, 0 when it was never bumped.
fn counter(output: &str, harness: &str, name: &str) -> u64 {
    output
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{harness}: {name} ")))
        .map_or(0, |n| n.parse().unwrap())
}

/// An authenticated client's payload at `sequence` in the server harness's script encoding
/// (op 4: a length byte pair, a fill byte, sequence mode 9 with the 64-bit sequence, minimal
/// sequence bytes, sent from the token's own address), then a server update and a drain.
fn payload_at(script: &mut Vec<u8>, sequence: u64, fill: u8) {
    script.extend_from_slice(&[4, 0, 15, 0, fill, 9]);
    script.extend_from_slice(&sequence.to_le_bytes());
    script.extend_from_slice(&[1, 2, 10, 0, 2, 11, 0]);
}

/// The replay window at its edges, at the byte level, through the real server datagram path:
/// a client holding the session keys completes the handshake honestly, then seals payloads at
/// chosen sequences. Each sequence is delivered at most once; a sequence at or below
/// `most_recent - 256` is refused; `u64::MAX` (netcode's reserved empty marker) is refused
/// even as the first of its kind; a far-future jump is accepted and then makes everything at
/// or below its window refused, which only costs the peer that made it. The harness's own
/// oracles also check every delivery against what was sealed.
#[test]
#[cfg_attr(
    target_env = "msvc",
    ignore = "the test build is not written for clang-cl yet (native/BUILD.md)"
)]
fn the_server_replay_window_holds_at_its_edges() {
    let harness = "fuzz_netcode_server";
    let mut script = vec![0u8]; // one client slot
    script.extend_from_slice(&[0, 0, 2]); // token 0 sends its connection request
    script.extend_from_slice(&[10, 0, 2]); // the server answers with a challenge
    script.extend_from_slice(&[2, 0, 0, 1, 2]); // the response, at the client's sequence 0
    script.extend_from_slice(&[10, 0, 2]); // the server connects the client
    let cases: [(u64, bool); 11] = [
        (0, true),             // the first payload, at 0 (the response used 0, unprotected)
        (0, false),            // the same sequence again, other contents
        (1000, true),          // a jump ahead
        (1000, false),         // a replay of it
        (1000 - 255, true),    // the oldest sequence still inside the window
        (1000 - 256, false),   // the first one outside it
        (999, true),           // inside, never seen
        (u64::MAX, false),     // the reserved value
        (u64::MAX - 1, true),  // the far end of the sequence space
        (u64::MAX - 1, false), // replayed
        (1001, false),         // now far behind the window
    ];
    for (index, (sequence, _)) in cases.iter().enumerate() {
        payload_at(&mut script, *sequence, u8::try_from(index).unwrap());
    }
    let expected = cases.iter().filter(|(_, delivered)| *delivered).count() as u64;
    for output in scripted(harness, "replay-window", &script) {
        assert_eq!(counter(&output, harness, "connects"), 1, "{output}");
        assert_eq!(
            counter(&output, harness, "payloads delivered"),
            expected,
            "{output}"
        );
    }
}
