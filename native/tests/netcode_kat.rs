//! The eleven netcode known-answer vectors (audit §5.1, Appendix A), reproduced by the vendored
//! C and compared, by SHA-256, with the files netcode-official 1.0.0 ships in `tests/vectors/`.
//! They pin the token layouts, packet framing, sequence encoding and both AEAD constructions
//! the binding's peers put on the wire, so the old Rust port and this C agree byte for byte.
//!
//! The vectors need netcode's internal writers, so `csrc/test/netcode_kat.c` is a unity build
//! over `netcode.c`, compiled here at test time with the archive's compiler and flags (as
//! `tests/build_upstream.rs` does) and never part of the archive or the public API. Set
//! `DREAM_NET_NATIVE_TEST_SANITIZE=address,undefined` to also run it under the sanitizers.

// CI passes -W clippy::pedantic on the command line, overriding the manifest's lint table.
#![allow(clippy::module_name_repetitions)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::Command;

use sha2::{Digest, Sha256};

/// SHA-256 of each file in netcode-official 1.0.0's `tests/vectors/`, with its length.
const EXPECTED: [(&str, usize, &str); 11] = [
    (
        "challenge_token_encrypted.bin",
        300,
        "33c5560aaed4192fc714fbba4910c38f235a4298f9121901c0d47549cc0a62e0",
    ),
    (
        "connect_token.bin",
        2048,
        "12cd58f0e2d17b002b629359f207018eac54e8cff2064382e600df738cfd4410",
    ),
    (
        "packet_challenge.bin",
        330,
        "22fc408d3ab1e8655d9edf9dd9bdad69b06978ff85323a564c0563fc7dfbf6a7",
    ),
    (
        "packet_denied.bin",
        22,
        "ecc44891ea58f39f107287bfbbe90e6be82ba6e9b0b53b2b5da1dffa007c2fc8",
    ),
    (
        "packet_disconnect.bin",
        22,
        "e79e7c56a01a8c066aa90236fe71ba74fdc5d29249472150d96aea42c1d3357e",
    ),
    (
        "packet_keep_alive.bin",
        30,
        "c96b56dbef593cab4e6c2ef9cbce7c44132d8240fbfeb4958d0c4ac22390d9c3",
    ),
    (
        "packet_payload.bin",
        1222,
        "e991282ba33dae3d19f4a9ecd0577f876a8175cf399180af5e3b21a33a4c6377",
    ),
    (
        "packet_request.bin",
        1078,
        "fc7d9221a4b2d74dfaa7accd870730d434caa2315724cce1141c91ad47969968",
    ),
    (
        "packet_response.bin",
        330,
        "d7f8965bb2961ae0c355f50ecedc13347575d38832668b6e4b7c5f6ae49973e9",
    ),
    (
        "private_connect_token_encrypted.bin",
        1024,
        "3fc190a87b816c4340e0894a16d5b0d9c55507bab095d77da9c07daf7e3bf98a",
    ),
    (
        "private_connect_token_plaintext.bin",
        1024,
        "7b1896a06c8dd0688fece1cfdcfe06c21871d429ef9dee2070ae40e9f8e534bc",
    ),
];

/// The sanitizers build.rs instrumented the archive with (`DREAM_NET_NATIVE_SANITIZE`).
const BUILD_SANITIZE: &str = env!("DN_NATIVE_SANITIZE");

fn native() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
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

/// Builds the program with the archive's flags (plus `sanitize`, when not empty).
fn build(sanitize: &str) -> PathBuf {
    let label = if sanitize.is_empty() {
        "plain".to_owned()
    } else {
        sanitize.replace(',', "+")
    };
    let dir = PathBuf::from(env!("OUT_DIR"))
        .join("netcode-kat")
        .join(label);
    std::fs::create_dir_all(&dir).expect("creating the test build directory");
    let cc = env!("DN_NATIVE_CC");
    let flags: Vec<&str> = env!("DN_NATIVE_TEST_CFLAGS")
        .split('\u{1f}')
        .filter(|f| !f.is_empty())
        // FORTIFY and ASan both interpose the libc string functions.
        .filter(|f| sanitize.is_empty() || !f.contains("_FORTIFY_SOURCE"))
        .collect();
    let sanitize_flags: Vec<String> = if sanitize.is_empty() {
        Vec::new()
    } else {
        vec![
            format!("-fsanitize={sanitize}"),
            "-fno-sanitize-recover=all".to_owned(),
            "-fno-omit-frame-pointer".to_owned(),
        ]
    };
    let units = [
        (native().join("csrc/test/netcode_kat.c"), &[][..]),
        (
            native().join("vendor/netcode/sodium/sodium.c"),
            &["-Wno-unknown-pragmas"][..],
        ),
    ];
    let mut objects = Vec::new();
    for (index, (source, extra)) in units.iter().enumerate() {
        let object = dir.join(format!("{index}.o"));
        run(
            Command::new(cc)
                .args(&flags)
                .args(&sanitize_flags)
                .args(*extra)
                .arg("-std=gnu99")
                .arg("-c")
                .arg(source)
                .arg("-o")
                .arg(&object),
            &format!("compiling {}", source.display()),
        );
        objects.push(object);
    }
    let exe = dir.join("netcode_kat");
    let mut link = Command::new(cc);
    link.args(flags.iter().filter(|f| f.starts_with("--target=")))
        .args(&sanitize_flags)
        .args(&objects)
        .arg("-o")
        .arg(&exe);
    if !env!("DN_NATIVE_LLD").is_empty() {
        link.arg("-fuse-ld=lld");
    }
    if cfg!(all(unix, not(target_vendor = "apple"))) {
        link.arg("-lm");
    }
    run(&mut link, "linking netcode_kat");
    exe
}

fn check(sanitize: &str) {
    let exe = build(sanitize);
    let output = run(&mut Command::new(&exe), "netcode_kat");
    assert!(
        output.contains("netcode_kat: OK 1.4.10"),
        "unexpected output:\n{output}"
    );
    let mut produced = BTreeMap::new();
    for line in output
        .lines()
        .filter(|l| l.split(' ').next().is_some_and(|n| n.contains(".bin")))
    {
        let mut fields = line.split(' ');
        let name = fields.next().unwrap();
        let length: usize = fields.next().unwrap().parse().unwrap();
        let hex = fields.next().unwrap();
        assert_eq!(hex.len(), 2 * length, "{name}");
        produced.insert(name.to_owned(), (length, hex.to_owned()));
    }
    assert_eq!(produced.len(), EXPECTED.len(), "{output}");
    for (name, length, sha) in EXPECTED {
        let (got_length, hex) = &produced[name];
        assert_eq!(*got_length, length, "{name}: length");
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let digest = Sha256::digest(&bytes)
            .iter()
            .fold(String::new(), |mut s, b| {
                let _ = write!(s, "{b:02x}");
                s
            });
        assert_eq!(
            digest, sha,
            "{name}: not identical to netcode-official's vector"
        );
        println!("IDENTICAL {name} {length}");
    }
}

#[test]
#[cfg_attr(
    target_env = "msvc",
    ignore = "the test build is not written for clang-cl yet (BUILD.md)"
)]
fn the_c_reproduces_netcode_officials_eleven_vectors() {
    check("");
    let requested = std::env::var("DREAM_NET_NATIVE_TEST_SANITIZE")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| BUILD_SANITIZE.to_owned());
    if !requested.is_empty() {
        println!("== under -fsanitize={requested}");
        check(&requested);
    }
}
