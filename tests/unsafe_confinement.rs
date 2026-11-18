//! `unsafe` is confined to the `native` module (the C bindings), and the compiler is set up to
//! keep it there.
//!
//! The crate root is `#![deny(unsafe_code)]` and allows it for `pub mod native` alone; every
//! other module file starts with `#![forbid(unsafe_code)]`, which no inner `allow` can undo.
//! This test reads the sources and fails if any of that changes: an `unsafe` token in code
//! outside `src/native/`, a module file outside it without the `forbid`, a second
//! `allow(unsafe_code)`, or a build script that grows `unsafe` (it has none). Comments, doc
//! comments and string literals are not code, so the word "unsafe" in them is ignored.

// CI passes -W clippy::pedantic on the command line, overriding the manifest's lint table.
#![allow(clippy::module_name_repetitions)]

use std::fs;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(file: &Path) -> String {
    fs::read_to_string(root().join(file))
        .unwrap_or_else(|e| panic!("reading {}: {e}", file.display()))
}

/// Every `.rs` file under `dir` (relative to the package root), sorted, relative to the root.
fn rust_files(dir: &str) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut pending = vec![root().join(dir)];
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(&dir).expect("reading a source directory") {
            let path = entry.expect("a directory entry").path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let relative = path.strip_prefix(root()).expect("under the package root");
                files.push(relative.to_path_buf());
            }
        }
    }
    files.sort();
    files
}

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// The end (exclusive) of the comment or literal that starts at `i`, if one does.
fn literal_or_comment_end(chars: &[char], i: usize) -> Option<usize> {
    let at = |j: usize| chars.get(j).copied();
    match (chars[i], at(i + 1)) {
        ('/', Some('/')) => Some(
            chars[i..]
                .iter()
                .position(|&c| c == '\n')
                .map_or(chars.len(), |n| i + n),
        ),
        ('/', Some('*')) => {
            let (mut j, mut depth) = (i, 0);
            loop {
                match (at(j), at(j + 1)) {
                    (Some('/'), Some('*')) => (depth, j) = (depth + 1, j + 2),
                    (Some('*'), Some('/')) => (depth, j) = (depth - 1, j + 2),
                    (Some(_), _) => j += 1,
                    (None, _) => panic!("unterminated block comment"),
                }
                if depth == 0 {
                    return Some(j);
                }
            }
        }
        ('r', _) => {
            // r"..", r#".."#, and br/cr forms; any other `r` starts or continues an identifier
            let hashes = chars[i + 1..].iter().take_while(|&&c| c == '#').count();
            let prefix_ok = i == 0 || !is_ident(chars[i - 1]) || {
                matches!(chars[i - 1], 'b' | 'c') && (i == 1 || !is_ident(chars[i - 2]))
            };
            if !prefix_ok || at(i + 1 + hashes) != Some('"') {
                return None;
            }
            let mut j = i + 2 + hashes;
            while !(chars[j] == '"' && chars[j + 1..].iter().take(hashes).all(|&c| c == '#')) {
                j += 1;
            }
            Some(j + 1 + hashes)
        }
        ('"', _) => {
            let mut j = i + 1;
            while chars[j] != '"' {
                j += if chars[j] == '\\' { 2 } else { 1 };
            }
            Some(j + 1)
        }
        // a character literal ('x', '\n', '\u{..}', '\''); otherwise a lifetime or a label
        ('\'', Some('\\')) => {
            let from = i + 3;
            chars[from..]
                .iter()
                .position(|&c| c == '\'')
                .map(|n| from + n + 1)
        }
        ('\'', Some(_)) => (at(i + 2) == Some('\'')).then_some(i + 3),
        _ => None,
    }
}

/// `source` with every comment, string literal and character literal blanked to spaces
/// (newlines kept, so line numbers still match), leaving only code. Enough of Rust's lexical
/// grammar for this crate's sources: line and nested block comments, plain, byte, C and raw
/// strings, and character literals told apart from lifetimes.
fn code_only(source: &str) -> String {
    let chars: Vec<char> = source.chars().collect();
    let mut out = String::with_capacity(source.len());
    let mut i = 0;
    while i < chars.len() {
        if let Some(end) = literal_or_comment_end(&chars, i) {
            out.extend(
                chars[i..end]
                    .iter()
                    .map(|&c| if c == '\n' { c } else { ' ' }),
            );
            i = end;
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

/// The 1-based lines of `code` where the keyword `unsafe` appears as a whole identifier.
fn unsafe_lines(code: &str) -> Vec<usize> {
    code.lines()
        .enumerate()
        .filter(|(_, line)| {
            line.match_indices("unsafe").any(|(at, word)| {
                let before = line[..at].chars().next_back();
                let after = line[at + word.len()..].chars().next();
                !before.is_some_and(is_ident) && !after.is_some_and(is_ident)
            })
        })
        .map(|(n, _)| n + 1)
        .collect()
}

/// The trimmed lines that open a file before its first item: inner doc comments, comments,
/// blank lines and inner attributes, including a multi-line attribute's continuation lines.
fn preamble(source: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut open_attribute = false;
    for line in source.lines().map(str::trim) {
        if open_attribute || line.starts_with("#![") {
            open_attribute = !line.ends_with(']');
        } else if !(line.is_empty() || line.starts_with("//")) {
            break;
        }
        lines.push(line);
    }
    lines
}

#[test]
fn the_scanner_sees_code_and_ignores_comments_and_strings() {
    let probe = r##"
        // unsafe in a line comment
        /* unsafe in a /* nested */ block comment */
        /// unsafe in a doc comment
        let a = "unsafe in a string with an \" escaped quote";
        let b = r#"unsafe in a raw string with a " quote"#;
        let c = (b"unsafe", br"unsafe", c"unsafe");
        let d = ('"', '\'', '\u{22}');
        fn e<'a>(f: &'a str) -> &'a str { 'outer: loop { break 'outer f; } }
        unsafe_code(); not_unsafe(); unsafe_ops; very_unsafe;
        let g = unsafe { core::hint::unreachable_unchecked() };
        let h = "unsafe";
    "##;
    let code = code_only(probe);
    assert_eq!(code.lines().count(), probe.lines().count(), "{code}");
    assert_eq!(unsafe_lines(&code), [11], "{code}");
    assert!(code.contains("fn e<'a>(f: &'a str)"), "{code}");
    let attributes = "//! docs\n\n#![forbid(unsafe_code)]\n#![allow(\n    a,\n    b\n)]\n\nuse x;";
    assert_eq!(
        preamble(attributes),
        [
            "//! docs",
            "",
            "#![forbid(unsafe_code)]",
            "#![allow(",
            "a,",
            "b",
            ")]",
            ""
        ]
    );
}

#[test]
fn unsafe_appears_in_code_only_inside_src_native() {
    let mut outside = Vec::new();
    let mut inside = 0;
    for file in rust_files("src") {
        let lines = unsafe_lines(&code_only(&read(&file)));
        if file.starts_with("src/native") {
            inside += lines.len();
        } else {
            outside.extend(lines.iter().map(|n| format!("{}:{n}", file.display())));
        }
    }
    assert!(
        outside.is_empty(),
        "`unsafe` outside src/native/: {outside:?}"
    );
    // the scanner is not blind: the bindings are where the FFI calls are
    assert!(
        inside > 50,
        "only {inside} lines with `unsafe` found in src/native/"
    );
}

#[test]
fn every_module_outside_native_forbids_unsafe_code() {
    let mut missing = Vec::new();
    let mut checked = 0;
    for file in rust_files("src") {
        if file.starts_with("src/native") || file == Path::new("src/lib.rs") {
            continue;
        }
        if !preamble(&read(&file)).contains(&"#![forbid(unsafe_code)]") {
            missing.push(file.display().to_string());
        }
        checked += 1;
    }
    assert!(
        missing.is_empty(),
        "no #![forbid(unsafe_code)] before the first item of: {missing:?}"
    );
    assert!(checked >= 16, "only {checked} module files checked");
}

#[test]
fn the_crate_root_denies_unsafe_and_allows_it_for_native_alone() {
    let lib = read(Path::new("src/lib.rs"));
    assert!(preamble(&lib).contains(&"#![deny(unsafe_code)]"));
    let code = code_only(&lib);
    let lines: Vec<&str> = code.lines().map(str::trim).collect();
    let allows: Vec<usize> = (0..lines.len())
        .filter(|&n| lines[n].contains("allow(unsafe_code)"))
        .collect();
    assert_eq!(
        allows.len(),
        1,
        "exactly one allow(unsafe_code) in src/lib.rs"
    );
    // the allow is an outer attribute of the `native` module declaration
    let item = lines[allows[0]..]
        .iter()
        .find(|line| !line.starts_with("#[") && !line.is_empty())
        .expect("an item after the attribute");
    assert_eq!(*item, "pub mod native;");
    for file in rust_files("src") {
        if file == Path::new("src/lib.rs") {
            continue;
        }
        let code = code_only(&read(&file));
        assert!(
            !code.contains("allow(unsafe_code)") && !code.contains("warn(unsafe_code)"),
            "{} relaxes unsafe_code",
            file.display()
        );
    }
    // and the bindings keep the stricter FFI lints they were written under
    let native = read(Path::new("src/native/mod.rs"));
    let native = preamble(&native).join("\n");
    for lint in [
        "unsafe_op_in_unsafe_fn",
        "clippy::undocumented_unsafe_blocks",
        "clippy::multiple_unsafe_ops_per_block",
    ] {
        assert!(
            native.contains(lint),
            "src/native/mod.rs no longer sets {lint}"
        );
    }
}

#[test]
fn the_build_script_has_no_unsafe() {
    // build.rs runs the compiler and the archiver as processes and parses their output; it
    // needs no `unsafe`, and any it gains must be justified here.
    let build = code_only(&read(Path::new("build.rs")));
    assert_eq!(unsafe_lines(&build), Vec::<usize>::new());
}
