//! The netcode known-answer vectors (audit §5.1, Appendix A), reproduced by the vendored C and
//! compared, by SHA-256, with netcode-official 1.2.0: the eleven files it ships in
//! `tests/vectors/` and its per-connection key derivation known answer. They pin the NETCODE
//! 1.03 token layouts, packet framing (the client salt in requests, the server nonce in denied
//! and challenge packets), sequence encoding, both AEAD constructions and the `HChaCha20` key
//! derivation, so the Rust port of the same protocol and this C agree byte for byte.
//!
//! The vectors need netcode's internal writers, so `native/csrc/test/netcode_kat.c` is a unity build
//! over `netcode.c`, compiled here at test time with the archive's compiler and flags (as
//! `tests/native_build_upstream.rs` does) and never part of the archive or the public API. Set
//! `DREAM_NET_NATIVE_TEST_SANITIZE=address,undefined` to also run it under the sanitizers.

// CI passes -W clippy::pedantic on the command line, overriding the manifest's lint table.
#![allow(clippy::module_name_repetitions)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::Command;

use sha2::{Digest, Sha256};

/// SHA-256 of each file in netcode-official 1.2.0's `tests/vectors/` (the crates.io package,
/// built from netcode.rs commit `b0b6b33efc95d46b9cd923f76da7b583241a7325`), with its length,
/// then of the two keys its `src/crypto.rs` `test_derive_packet_keys_kat` derives (client to
/// server, then server to client; upstream C v1.5.0 pins the same 64 bytes in its own
/// `test_derive_packet_keys_kat`).
const EXPECTED: [(&str, usize, &str); 12] = [
    (
        "challenge_token_encrypted.bin",
        300,
        "33c5560aaed4192fc714fbba4910c38f235a4298f9121901c0d47549cc0a62e0",
    ),
    (
        "connect_token.bin",
        2048,
        "4bee4b774a34f0581691027fa9150f86af2b5ff4ff55ba251ee5f01fe8bf4caa",
    ),
    (
        "packet_challenge.bin",
        338,
        "e3b85fa234550846b87882674340effbe387a23650bca33d94d5649a243ce82d",
    ),
    (
        "packet_denied.bin",
        30,
        "00e578917fc75e46dfeaed63055004e674321249b6f768388ded05ecb7f0e68d",
    ),
    (
        "packet_disconnect.bin",
        22,
        "0edb0d46d5de7163b20fa661def6cb5e64bb5c94c8dcd8a9c9480e0908d20d76",
    ),
    (
        "packet_keep_alive.bin",
        30,
        "007444b72073998dc2d688c5e02548abd0a42c3ac4a993544d329786ccf1b2e5",
    ),
    (
        "packet_payload.bin",
        1222,
        "568eb093ce93309cd764d7f7a17d7d468e84b0d38f2bb34131f5c2e8a7c1d647",
    ),
    (
        "packet_request.bin",
        1086,
        "0ce75dff353cbf19e7a6f916f8eeeb96bdf8e6b1a0f65710fa158ba675261570",
    ),
    (
        "packet_response.bin",
        330,
        "88e9e429dcd818d3eeafeeb40807ba738c416c0e83abbf5b46c9067cf4ac1651",
    ),
    (
        "private_connect_token_encrypted.bin",
        1024,
        "ae4b82b034b7619f094022abf44115be7ec5c08a04ce2f16bd2bd2bcbf30b73b",
    ),
    (
        "private_connect_token_plaintext.bin",
        1024,
        "7b1896a06c8dd0688fece1cfdcfe06c21871d429ef9dee2070ae40e9f8e534bc",
    ),
    (
        "derived_packet_keys.kat",
        64,
        "c31b2ae92ec2abd348f6668310bbb24198dbe710107144e08bd2316797eb7c18",
    ),
];

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
        output.contains("netcode_kat: OK 1.5.0"),
        "unexpected output:\n{output}"
    );
    let mut produced = BTreeMap::new();
    for line in output
        .lines()
        .filter(|l| l.split(' ').next().is_some_and(|n| n.contains('.')))
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
    ignore = "the test build is not written for clang-cl yet (native/BUILD.md)"
)]
fn the_c_reproduces_netcode_officials_known_answers() {
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
