//! The vendored C tree matches `native/vendor/PROVENANCE.toml`, file for file and byte for byte.
//!
//! This is the offline half of `native/tools/verify-vendor`, in Rust so that `cargo test` (and the
//! packaged crate's tests) catch a drifted, missing or extra vendored file without Python. The
//! manifest is written in a strict TOML subset that this parser and the script's share.

// CI passes -W clippy::pedantic on the command line, overriding the manifest's lint table.
#![allow(clippy::module_name_repetitions)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

type Table = BTreeMap<String, String>;

struct Manifest {
    top: Table,
    tables: BTreeMap<String, Vec<Table>>,
}

fn native_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("native")
}

/// Parses the manifest's TOML subset: `[[name]]` headers, `key = "value"` lines, blank lines
/// and `#` comments. Anything else is an error, exactly as in `native/tools/verify-vendor`.
fn parse(text: &str) -> Result<Manifest, String> {
    let mut manifest = Manifest {
        top: Table::new(),
        tables: BTreeMap::new(),
    };
    let mut current: Option<(String, usize)> = None;
    for (number, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line
            .strip_prefix("[[")
            .and_then(|rest| rest.strip_suffix("]]"))
        {
            if name.is_empty() || !name.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') {
                return Err(format!("line {}: bad table name {name:?}", number + 1));
            }
            let list = manifest.tables.entry(name.to_owned()).or_default();
            list.push(Table::new());
            current = Some((name.to_owned(), list.len() - 1));
            continue;
        }
        let (key, value) = line
            .split_once(" = ")
            .and_then(|(key, value)| {
                let value = value.strip_prefix('"')?.strip_suffix('"')?;
                let key_ok = !key.is_empty()
                    && key
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
                let value_ok = !value.contains('"') && !value.contains('\\');
                (key_ok && value_ok).then_some((key, value))
            })
            .ok_or_else(|| {
                format!(
                    "line {}: not in the manifest's TOML subset: {raw:?}",
                    number + 1
                )
            })?;
        let table = match &current {
            None => &mut manifest.top,
            Some((name, index)) => {
                &mut manifest.tables.get_mut(name).expect("table exists")[*index]
            }
        };
        if table.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(format!("line {}: duplicate key {key:?}", number + 1));
        }
    }
    Ok(manifest)
}

fn load() -> Manifest {
    let path = native_dir().join("vendor/PROVENANCE.toml");
    let text =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    let manifest = parse(&text).unwrap_or_else(|e| panic!("PROVENANCE.toml: {e}"));
    assert_eq!(
        manifest.top.get("schema").map(String::as_str),
        Some("1"),
        "unsupported schema"
    );
    manifest
}

fn sha256_hex(path: &Path) -> String {
    let bytes = fs::read(path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    let mut hex = String::with_capacity(64);
    for byte in Sha256::digest(&bytes) {
        write!(hex, "{byte:02x}").expect("writing to a String");
    }
    hex
}

fn files_under(root: &Path) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                pending.push(path);
            } else {
                let relative = path.strip_prefix(root).expect("under root");
                found.insert(relative.to_string_lossy().replace('\\', "/"));
            }
        }
    }
    found
}

fn table<'a>(manifest: &'a Manifest, name: &str) -> &'a [Table] {
    manifest.tables.get(name).map_or(&[], Vec::as_slice)
}

fn field<'a>(table: &'a Table, key: &str) -> &'a str {
    table
        .get(key)
        .unwrap_or_else(|| panic!("entry {table:?} has no {key:?}"))
}

#[test]
fn every_vendored_file_matches_its_recorded_sha256() {
    let manifest = load();
    let vendor = native_dir().join("vendor");
    let mut problems = Vec::new();

    let listed: BTreeSet<String> = table(&manifest, "file")
        .iter()
        .map(|f| field(f, "path").to_owned())
        .collect();
    assert_eq!(
        listed.len(),
        table(&manifest, "file").len(),
        "a vendored path is listed twice"
    );
    let mut present = files_under(&vendor);
    present.remove("PROVENANCE.toml");
    for missing in listed.difference(&present) {
        problems.push(format!("missing: vendor/{missing}"));
    }
    for extra in present.difference(&listed) {
        problems.push(format!("extra (not in PROVENANCE.toml): vendor/{extra}"));
    }

    let upstreams: BTreeSet<&str> = table(&manifest, "upstream")
        .iter()
        .map(|u| field(u, "name"))
        .collect();
    for file in table(&manifest, "file") {
        let path = field(file, "path");
        assert!(
            upstreams.contains(field(file, "upstream")),
            "{path}: unknown upstream"
        );
        let expected = field(file, "sha256");
        assert!(
            expected.len() == 64
                && expected
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        let on_disk = vendor.join(path);
        if on_disk.exists() {
            let actual = sha256_hex(&on_disk);
            if actual != expected {
                problems.push(format!(
                    "changed: vendor/{path} sha256 {actual}, manifest {expected}"
                ));
            }
        }
    }
    assert!(
        problems.is_empty(),
        "vendor/ does not match PROVENANCE.toml:\n{}",
        problems.join("\n")
    );
}

#[test]
fn every_patch_is_listed_and_unchanged() {
    let manifest = load();
    let patches_dir = native_dir().join("patches");
    let present: BTreeSet<String> = files_under(&patches_dir)
        .into_iter()
        .filter(|p| Path::new(p).extension().is_some_and(|e| e == "patch"))
        .collect();
    let listed: BTreeSet<String> = table(&manifest, "patch")
        .iter()
        .map(|p| field(p, "file").to_owned())
        .collect();
    assert_eq!(
        present, listed,
        "patches/ and the [[patch]] entries of PROVENANCE.toml disagree"
    );
    for patch in table(&manifest, "patch") {
        assert!(
            !field(patch, "reason").is_empty(),
            "every patch states its reason"
        );
        let file = field(patch, "file");
        assert_eq!(
            sha256_hex(&patches_dir.join(file)),
            field(patch, "sha256"),
            "patches/{file} changed"
        );
    }
}

#[test]
fn every_upstream_is_pinned_to_a_full_commit_with_its_license() {
    let manifest = load();
    let vendor = native_dir().join("vendor");
    for upstream in table(&manifest, "upstream") {
        let name = field(upstream, "name");
        let commit = field(upstream, "commit");
        assert!(
            commit.len() == 40
                && commit
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "{name}: commit must be a full 40-hex id, not {commit:?}"
        );
        assert_ne!(field(upstream, "tag"), "", "{name}: no tag");
        let license = field(upstream, "license");
        assert!(
            ["BSD-3-Clause", "ISC"].contains(&license),
            "{name}: license {license} is not on the approved list"
        );
        let license_file = vendor.join(field(upstream, "license_file"));
        assert!(
            license_file.exists(),
            "{name}: {} missing",
            license_file.display()
        );
    }
}

#[test]
fn notice_reproduces_every_vendored_license_verbatim() {
    let native = native_dir();
    // The package's one NOTICE.md, at its root, beside native/.
    let notice = fs::read_to_string(native.join("../NOTICE.md")).expect("NOTICE.md");
    for license in ["vendor/netcode/LICENCE", "vendor/reliable/LICENCE"] {
        let text = fs::read_to_string(native.join(license)).expect(license);
        assert!(
            notice.contains(&text),
            "NOTICE.md does not reproduce {license} byte for byte"
        );
    }
    // libsodium's ISC notice is the comment that heads both sodium files.
    for file in [
        "vendor/netcode/sodium/sodium.c",
        "vendor/netcode/sodium/sodium.h",
    ] {
        let source = fs::read_to_string(native.join(file)).expect(file);
        let end = source.find(" */\n").expect("a leading comment") + " */\n".len();
        let header = &source[..end];
        assert!(
            header.contains("ISC License"),
            "{file} no longer starts with the ISC notice"
        );
        assert!(
            notice.contains(header),
            "NOTICE.md does not reproduce the notice heading {file}"
        );
    }
}

#[test]
fn the_parser_rejects_anything_outside_the_subset() {
    assert!(parse("key = 'single quotes'").is_err());
    assert!(parse("[table]").is_err());
    assert!(parse("key = \"a\"\nkey = \"b\"").is_err());
    assert!(parse("[[file]]\npath = \"x\" # trailing comment").is_err());
    assert!(parse("# only a comment\n\n[[file]]\npath = \"x\"").is_ok());
}
