//! Builds the native archive: the vendored netcode, reliable and libsodium C plus our shim in
//! `csrc/`, compiled by a compiler this script has verified to be Clang, archived by LLVM's
//! archiver, every external symbol renamed under `dn_native_`.
//!
//! Deterministic and offline: no downloads, no `pkg-config`, no `CMake`, no `bindgen`. `BUILD.md`
//! documents every environment variable read here and the reasons for every flag.

// CI passes -W clippy::pedantic on the command line, overriding the manifest's lint table.
#![allow(clippy::too_many_lines)]

use std::collections::BTreeSet;
use std::env;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The archive's name: `libdream_net_native.a`, or `dream_net_native.lib` on MSVC targets.
const ARCHIVE: &str = "dream_net_native";

/// Oldest LLVM Clang major accepted. 18 is the oldest major still shipped as a distribution
/// default (Ubuntu 24.04) and newer than every flag used here needs; nothing older is tested.
/// CI's MSRV job uses the Clang matching rustc 1.88 (LLVM 20); the test jobs use LLVM 23.
const MIN_CLANG_MAJOR: u32 = 18;

/// Oldest Apple Clang major accepted (Xcode 16). Apple numbers its Clang independently of LLVM.
const MIN_APPLE_CLANG_MAJOR: u32 = 16;

/// Flags the environment (`CFLAGS` and friends) may not add: each would silently change what the
/// vendored code computes or defeat a policy this script enforces.
const FORBIDDEN_FLAGS: &[(&str, &str)] = &[
    ("-ffast-math", "fast-math changes floating-point results"),
    ("-Ofast", "-Ofast implies -ffast-math"),
    (
        "-funsafe-math-optimizations",
        "changes floating-point results",
    ),
    ("-fassociative-math", "changes floating-point results"),
    ("-freciprocal-math", "changes floating-point results"),
    ("-ffinite-math-only", "changes floating-point results"),
    ("-fno-signed-zeros", "changes floating-point results"),
    (
        "-ffp-contract=fast",
        "floating-point contraction must stay off",
    ),
    (
        "-ffp-contract=on",
        "floating-point contraction must stay off",
    ),
    ("-ffp-model=fast", "changes floating-point results"),
    ("-ffp-model=aggressive", "changes floating-point results"),
    (
        "-w",
        "blanket warning suppression hides vendored-code warnings",
    ),
    (
        "-UNDEBUG",
        "assertions stay compiled out (BUILD.md, \"Assertions\")",
    ),
    (
        "-DNETCODE_DEBUG",
        "assertions stay compiled out (BUILD.md, \"Assertions\")",
    ),
    (
        "-DRELIABLE_DEBUG",
        "assertions stay compiled out (BUILD.md, \"Assertions\")",
    ),
    ("-fvisibility=default", "the archive's symbols stay hidden"),
];

fn main() {
    if let Err(message) = run() {
        eprintln!("\nerror: dream-net-native: {message}\n");
        std::process::exit(1);
    }
}

/// What the build is for, read once from Cargo's environment.
struct Target {
    triple: String,
    host: String,
    os: String,
    env: String,
    family: String,
    msvc: bool,
    apple: bool,
}

impl Target {
    fn read() -> Result<Self, String> {
        let triple = var("TARGET")?;
        let os = var("CARGO_CFG_TARGET_OS")?;
        let env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
        let family = env::var("CARGO_CFG_TARGET_FAMILY").unwrap_or_default();
        Ok(Self {
            msvc: env == "msvc",
            apple: matches!(
                os.as_str(),
                "macos" | "ios" | "tvos" | "watchos" | "visionos"
            ),
            host: var("HOST")?,
            triple,
            os,
            env,
            family,
        })
    }

    /// The linker LLD flavour that serves this target's object format.
    fn lld_names(&self) -> &'static [&'static str] {
        if self.msvc {
            &["lld-link"]
        } else if self.apple {
            &["ld64.lld"]
        } else {
            &["ld.lld"]
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Lto {
    Off,
    Thin,
    Full,
}

impl Lto {
    fn name(self) -> &'static str {
        match self {
            Lto::Off => "off",
            Lto::Thin => "thin",
            Lto::Full => "full",
        }
    }
}

/// A verified Clang.
struct Compiler {
    path: PathBuf,
    /// clang-cl, which takes MSVC-style arguments.
    cl_mode: bool,
    major: u32,
    apple: bool,
    banner: String,
}

fn var(name: &str) -> Result<String, String> {
    env::var(name).map_err(|_| format!("Cargo did not set {name}"))
}

/// Reads an environment variable and tells Cargo to rerun when it changes.
fn tracked(name: &str) -> Option<OsString> {
    println!("cargo:rerun-if-env-changed={name}");
    env::var_os(name).filter(|v| !v.is_empty())
}

/// Looks a tool variable up the way the `cc` crate does (`NAME_<target>`, `NAME_<target with
/// underscores>`, `HOST_NAME`/`TARGET_NAME`, `NAME`), so `CC`/`AR` overrides are honoured, never
/// ignored, and then verified like everything else.
fn target_scoped(name: &str, target: &Target) -> Option<(String, OsString)> {
    let kind = if target.triple == target.host {
        "HOST"
    } else {
        "TARGET"
    };
    let candidates = [
        format!("{name}_{}", target.triple),
        format!("{name}_{}", target.triple.replace('-', "_")),
        format!("{kind}_{name}"),
        name.to_owned(),
    ];
    let mut found = None;
    for candidate in candidates {
        let value = tracked(&candidate);
        if found.is_none() {
            found = value.map(|v| (candidate, v));
        }
    }
    found
}

/// Resolves a program name or path to an existing file: a value with a path separator must
/// exist as given; a bare name is searched for on `PATH` (with `.exe` on Windows).
fn which(program: &Path) -> Option<PathBuf> {
    let exe = |p: PathBuf| -> Option<PathBuf> {
        if p.is_file() {
            return Some(p);
        }
        if cfg!(windows) && p.extension().is_none() {
            let with_exe = p.with_extension("exe");
            if with_exe.is_file() {
                return Some(with_exe);
            }
        }
        None
    };
    if program.components().count() > 1 || program.is_absolute() {
        return exe(program.to_path_buf());
    }
    let path = env::var_os("PATH")?;
    env::split_paths(&path).find_map(|dir| exe(dir.join(program)))
}

/// The directories a tool may sit in next to the compiler: the compiler's own directory, and
/// the directory of the file it resolves to (`/usr/bin/clang` -> `/usr/lib/llvm-20/bin/clang`).
fn compiler_dirs(compiler: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(dir) = compiler.parent() {
        dirs.push(dir.to_path_buf());
    }
    if let Ok(real) = fs::canonicalize(compiler)
        && let Some(dir) = real.parent()
        && !dirs.iter().any(|d| d == dir)
    {
        dirs.push(dir.to_path_buf());
    }
    dirs
}

/// Finds an LLVM tool: next to the compiler first (same release), then on `PATH`, then as the
/// Debian-style `name-<major>`.
fn find_llvm_tool(name: &str, compiler: &Compiler) -> Option<PathBuf> {
    for dir in compiler_dirs(&compiler.path) {
        if let Some(found) = which(&dir.join(name)) {
            return Some(found);
        }
    }
    which(Path::new(name)).or_else(|| which(Path::new(&format!("{name}-{}", compiler.major))))
}

fn run_capture(command: &mut Command) -> Result<String, String> {
    let program = command.get_program().to_string_lossy().into_owned();
    let output = command
        .output()
        .map_err(|e| format!("could not run `{program}`: {e}"))?;
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    if output.status.success() {
        Ok(text)
    } else {
        Err(format!(
            "`{program}` failed ({}):\n{}",
            output.status,
            text.trim()
        ))
    }
}

fn first_line(text: &str) -> String {
    text.lines().next().unwrap_or("").trim().to_owned()
}

/// Chooses the compiler: `DREAM_NET_NATIVE_CC`, else `CC_<target>`/`CC` as `cc` reads them,
/// else `clang` (`clang-cl` on MSVC targets). Never anything else.
fn choose_compiler(target: &Target) -> Result<(PathBuf, String), String> {
    let (source, value) = if let Some(value) = tracked("DREAM_NET_NATIVE_CC") {
        ("DREAM_NET_NATIVE_CC".to_owned(), value)
    } else if let Some((name, value)) = target_scoped("CC", target) {
        (name, value)
    } else {
        let default = if target.msvc { "clang-cl" } else { "clang" };
        ("the default".to_owned(), OsString::from(default))
    };
    let shown = value.to_string_lossy().into_owned();
    if let Some(path) = which(Path::new(&value)) {
        return Ok((path, source));
    }
    if shown.split_whitespace().count() > 1 {
        return Err(format!(
            "{source} is `{shown}`, which is not a single program. Compiler wrappers and \
             arguments are not supported here: point DREAM_NET_NATIVE_CC at the clang executable."
        ));
    }
    Err(format!(
        "the C compiler `{shown}` (from {source}) was not found. dream-net-native compiles its C \
         only with Clang >= {MIN_CLANG_MAJOR}. Install Clang (and LLD and the LLVM binutils) and put \
         it on PATH, or set DREAM_NET_NATIVE_CC to its full path."
    ))
}

/// Proves the chosen compiler is Clang by what it predefines, not by its name.
fn verify_compiler(path: PathBuf, source: &str, out_dir: &Path) -> Result<Compiler, String> {
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let cl_mode = stem.ends_with("clang-cl") || stem == "cl";
    let banner = run_capture(Command::new(&path).arg("--version"))
        .map_or_else(|e| first_line(&e), |text| first_line(&text));
    let probe = out_dir.join("dn_native_compiler_probe.c");
    fs::write(
        &probe,
        "#if defined(__clang__)\nDN_CLANG __clang_major__ __clang_minor__ __clang_patchlevel__\n#endif\n\
         #if defined(__apple_build_version__)\nDN_APPLE __apple_build_version__\n#endif\n\
         #if defined(_MSC_VER)\nDN_MSVC _MSC_VER\n#endif\n\
         #if defined(__GNUC__) && !defined(__clang__)\nDN_GCC __GNUC__ __GNUC_MINOR__\n#endif\n\
         #if defined(__MINGW32__)\nDN_MINGW\n#endif\n",
    )
    .map_err(|e| format!("writing {}: {e}", probe.display()))?;
    let mut command = Command::new(&path);
    if cl_mode {
        command.arg("/nologo").arg("/EP").arg(&probe);
    } else {
        command.arg("-E").arg("-P").arg("-x").arg("c").arg(&probe);
    }
    let output = run_capture(&mut command).map_err(|e| {
        format!(
            "the C compiler `{}` (from {source}) could not preprocess a test file, so it cannot be \
             verified as Clang:\n{e}\nSet DREAM_NET_NATIVE_CC to a working Clang >= {MIN_CLANG_MAJOR}.",
            path.display()
        )
    })?;
    let field = |marker: &str| -> Option<Vec<String>> {
        output.lines().find_map(|line| {
            let mut words = line.split_whitespace();
            (words.next() == Some(marker)).then(|| words.map(str::to_owned).collect())
        })
    };
    let Some(version) = field("DN_CLANG") else {
        let what = if let Some(gcc) = field("DN_GCC") {
            let mingw = if field("DN_MINGW").is_some() {
                "MinGW "
            } else {
                ""
            };
            format!("{mingw}GCC {}", gcc.join("."))
        } else if let Some(msvc) = field("DN_MSVC") {
            format!("MSVC cl.exe (_MSC_VER {})", msvc.join(""))
        } else {
            "an unknown compiler".to_owned()
        };
        return Err(format!(
            "the C compiler `{}` (from {source}) is {what}, not Clang. Its banner: `{banner}`.\n\
             dream-net-native compiles only with Clang and never falls back to GCC, MinGW GCC or \
             MSVC cl.exe. Set DREAM_NET_NATIVE_CC to Clang >= {MIN_CLANG_MAJOR} (clang-cl on MSVC \
             targets), or unset {source} if it names another compiler.",
            path.display()
        ));
    };
    let major: u32 = version
        .first()
        .and_then(|m| m.parse().ok())
        .ok_or_else(|| format!("could not read __clang_major__ from `{}`", path.display()))?;
    let apple = field("DN_APPLE").is_some();
    let minimum = if apple {
        MIN_APPLE_CLANG_MAJOR
    } else {
        MIN_CLANG_MAJOR
    };
    if major < minimum {
        let kind = if apple { "Apple Clang" } else { "Clang" };
        return Err(format!(
            "`{}` (from {source}) is {kind} {}, older than the minimum {kind} {minimum}. Its \
             banner: `{banner}`. Install a newer Clang and set DREAM_NET_NATIVE_CC.",
            path.display(),
            version.join(".")
        ));
    }
    Ok(Compiler {
        path,
        cl_mode,
        major,
        apple,
        banner,
    })
}

/// Chooses and verifies the archiver. Auto-detection only ever finds LLVM's `llvm-ar`; a
/// non-LLVM archiver is accepted only when named explicitly, and never in LTO mode, where the
/// members are LLVM bitcode whose symbol table only LLVM's archiver writes.
fn choose_archiver(target: &Target, compiler: &Compiler, lto: Lto) -> Result<PathBuf, String> {
    let explicit = tracked("DREAM_NET_NATIVE_AR")
        .map(|v| ("DREAM_NET_NATIVE_AR".to_owned(), v))
        .or_else(|| target_scoped("AR", target));
    let (path, source) = if let Some((source, value)) = explicit {
        let path = which(Path::new(&value)).ok_or_else(|| {
            format!(
                "the archiver `{}` (from {source}) was not found",
                value.to_string_lossy()
            )
        })?;
        (path, source)
    } else {
        let path = find_llvm_tool("llvm-ar", compiler).ok_or_else(|| {
            format!(
                "llvm-ar was not found next to `{}` or on PATH. Install the LLVM binutils of the \
                 same release as Clang, or set DREAM_NET_NATIVE_AR to llvm-ar.",
                compiler.path.display()
            )
        })?;
        (path, "auto-detection".to_owned())
    };
    let banner = run_capture(Command::new(&path).arg("--version")).unwrap_or_default();
    let is_llvm = banner.contains("LLVM");
    if !is_llvm && lto != Lto::Off {
        return Err(format!(
            "LTO mode needs LLVM's archiver, but `{}` (from {source}) is not llvm-ar: `{}`. \
             Set DREAM_NET_NATIVE_AR to llvm-ar.",
            path.display(),
            first_line(&banner)
        ));
    }
    if !is_llvm && target.msvc {
        return Err(format!(
            "`{}` (from {source}) is not llvm-ar; MSVC targets are archived with `llvm-ar \
             --format=coff`. Set DREAM_NET_NATIVE_AR to llvm-ar.",
            path.display()
        ));
    }
    // Apple's ar (cctools) takes neither `D` nor `--format=darwin`, so it would only fail later
    // with a usage message. Say what to do instead.
    if !is_llvm && target.apple {
        return Err(format!(
            "`{}` (from {source}) is not llvm-ar; Apple targets are archived with `llvm-ar \
             --format=darwin`, whose flags Apple's ar does not take. Install LLVM (an LLVM.org \
             release, or Homebrew's llvm, whose llvm-ar is in `$(brew --prefix llvm)/bin`) and set \
             DREAM_NET_NATIVE_AR to its llvm-ar.",
            path.display()
        ));
    }
    Ok(path)
}

/// Whether the Rust side asked for linker-plugin LTO (`-Clinker-plugin-lto[=yes|path]`).
fn rustflags_request_linker_plugin_lto(rustflags: &[String]) -> bool {
    let mut enabled = false;
    let mut iter = rustflags.iter().peekable();
    while let Some(flag) = iter.next() {
        let value = if let Some(rest) = flag.strip_prefix("-C") {
            if rest.is_empty() {
                iter.next().map(String::as_str)
            } else {
                Some(rest)
            }
        } else if let Some(rest) = flag.strip_prefix("--codegen=") {
            Some(rest)
        } else if flag == "--codegen" {
            iter.next().map(String::as_str)
        } else {
            None
        };
        if let Some(option) = value.and_then(|v| v.strip_prefix("linker-plugin-lto")) {
            enabled = !matches!(option, "=no" | "=n" | "=off" | "=false");
        }
    }
    enabled
}

fn lto_mode(rustflags: &[String]) -> Result<Lto, String> {
    match tracked("DREAM_NET_NATIVE_LTO").map(|v| v.to_string_lossy().to_ascii_lowercase()) {
        None => Ok(if rustflags_request_linker_plugin_lto(rustflags) {
            Lto::Thin
        } else {
            Lto::Off
        }),
        Some(v) if matches!(v.as_str(), "0" | "off" | "no" | "false") => Ok(Lto::Off),
        Some(v) if matches!(v.as_str(), "1" | "on" | "yes" | "true" | "thin") => Ok(Lto::Thin),
        Some(v) if matches!(v.as_str(), "full" | "fat") => Ok(Lto::Full),
        Some(v) => Err(format!(
            "DREAM_NET_NATIVE_LTO={v} is not one of off, thin, full"
        )),
    }
}

/// The LLVM major of the rustc compiling this crate.
fn rustc_llvm_major() -> Result<u32, String> {
    let rustc = env::var_os("RUSTC").unwrap_or_else(|| OsString::from("rustc"));
    let text = run_capture(Command::new(rustc).arg("-vV"))?;
    text.lines()
        .find_map(|line| line.strip_prefix("LLVM version: "))
        .and_then(|v| v.split('.').next())
        .and_then(|m| m.trim().parse().ok())
        .ok_or_else(|| "could not read the LLVM version from `rustc -vV`".to_owned())
}

/// LTO preconditions: same LLVM major in Clang, rustc and LLD, and an LLD that can link it.
fn verify_lto(target: &Target, compiler: &Compiler, lld: Option<&Path>) -> Result<(), String> {
    if compiler.apple {
        return Err(format!(
            "LTO mode was requested, but `{}` is Apple Clang ({}), whose LLVM version cannot be \
             matched to rustc's. Use an LLVM.org Clang of rustc's LLVM major, or set \
             DREAM_NET_NATIVE_LTO=off.",
            compiler.path.display(),
            compiler.banner
        ));
    }
    let rustc_major = rustc_llvm_major()?;
    if compiler.major != rustc_major {
        return Err(format!(
            "LTO mode needs Clang and rustc to share an LLVM major so their bitcode can be linked \
             together, but Clang is {} and rustc uses LLVM {rustc_major}. Point DREAM_NET_NATIVE_CC \
             at Clang {rustc_major}, or set DREAM_NET_NATIVE_LTO=off.",
            compiler.major
        ));
    }
    let names = target.lld_names().join(" or ");
    let lld = lld.ok_or_else(|| {
        format!(
            "LTO mode needs LLD ({names}) to link the bitcode, and none was found next to `{}` or \
             on PATH. Install LLD {rustc_major}, or set DREAM_NET_NATIVE_LTO=off.",
            compiler.path.display()
        )
    })?;
    let banner = run_capture(Command::new(lld).arg("--version"))?;
    let lld_major: Option<u32> = banner
        .split_whitespace()
        .skip_while(|w| *w != "LLD")
        .nth(1)
        .and_then(|v| v.split('.').next())
        .and_then(|m| m.parse().ok());
    if lld_major != Some(rustc_major) {
        return Err(format!(
            "LTO mode needs LLD {rustc_major} (rustc's LLVM major), but `{}` reports `{}`.",
            lld.display(),
            first_line(&banner)
        ));
    }
    Ok(())
}

fn sanitizers() -> Result<Vec<String>, String> {
    let Some(value) = tracked("DREAM_NET_NATIVE_SANITIZE") else {
        return Ok(Vec::new());
    };
    let mut list: Vec<String> = value
        .to_string_lossy()
        .split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    list.sort();
    list.dedup();
    if let Some(bad) = list
        .iter()
        .find(|s| !matches!(s.as_str(), "address" | "undefined"))
    {
        return Err(format!(
            "DREAM_NET_NATIVE_SANITIZE: `{bad}` is not supported; use address, undefined or both"
        ));
    }
    Ok(list)
}

/// Builds the flag lists shared by every translation unit, as gnu-style arguments (translated
/// for clang-cl by `push_flag`).
struct Flags {
    defines: Vec<(&'static str, Option<&'static str>)>,
    common: Vec<String>,
}

fn flags(
    target: &Target,
    opt_level: &str,
    lto: Lto,
    sanitize: &[String],
    native: &Path,
    out_dir: &Path,
) -> Flags {
    // Behaviour-changing defines, every one chosen explicitly (BUILD.md, "Defines").
    let defines = vec![
        // Release assertions in every Cargo profile, debug and test included (director
        // decision, BUILD.md "Assertions"): upstream's debug asserts call exit(1) or trap, which
        // must never happen inside a host, so the Rust wrappers validate every argument an
        // assert guards instead. netcode_assert and sodium's assert() follow NDEBUG,
        // reliable_assert follows RELIABLE_RELEASE; outside test code these names change
        // nothing else in either library.
        ("NDEBUG", None),
        ("NETCODE_RELEASE", None),
        ("RELIABLE_RELEASE", None),
        // The upstream defaults, stated: logging compiled in but silent (level NONE, and the
        // shim installs a discarding printf hook); test code compiled out of the archive.
        ("NETCODE_ENABLE_LOGGING", Some("1")),
        ("RELIABLE_ENABLE_LOGGING", Some("1")),
        ("NETCODE_ENABLE_TESTS", Some("0")),
        ("RELIABLE_ENABLE_TESTS", Some("0")),
        ("NETCODE_ENABLE_NONCE_AUDIT", Some("0")),
        ("NETCODE_CRYPTO_LOGS", Some("0")),
    ];
    let mut common = vec![
        // Floating point exactly as written: no contraction into FMA, no fast-math, the
        // floor Más Bandwidth sets for its network libraries.
        "-ffp-contract=off".to_owned(),
        "-fno-fast-math".to_owned(),
        // libsodium's own build flags, extended to netcode and reliable, whose byte-level
        // serialisation is exactly where aliasing or signed-overflow UB would bite.
        "-fno-strict-aliasing".to_owned(),
        "-fwrapv".to_owned(),
        // Absolute paths become stable names, in __FILE__ (assert messages) and debug info.
        format!("-ffile-prefix-map={}=/dream-net-native", native.display()),
        format!(
            "-ffile-prefix-map={}=/dream-net-native-out",
            out_dir.display()
        ),
    ];
    if !target.msvc {
        // Nothing in the archive is exported from a shared object built on top of it.
        common.push("-fvisibility=hidden".to_owned());
        common.push("-fstack-protector-strong".to_owned());
        if opt_level != "0" && sanitize.is_empty() && target.family == "unix" {
            common.push("-U_FORTIFY_SOURCE".to_owned());
            common.push("-D_FORTIFY_SOURCE=2".to_owned());
        }
    }
    if !sanitize.is_empty() {
        let mut list = sanitize.join(",");
        if list.is_empty() {
            list.push_str("undefined");
        }
        common.push(format!("-fsanitize={list}"));
        if sanitize.iter().any(|s| s == "undefined") {
            // Trap instead of calling the UBSan runtime, which a Rust binary does not link.
            common.push("-fsanitize-trap=undefined".to_owned());
        }
        common.push("-fno-sanitize-recover=all".to_owned());
        common.push("-fno-omit-frame-pointer".to_owned());
    }
    match lto {
        Lto::Off => {}
        Lto::Thin => common.push("-flto=thin".to_owned()),
        Lto::Full => common.push("-flto=full".to_owned()),
    }
    Flags { defines, common }
}

/// Adds a gnu-style flag, wrapped in `/clang:` for clang-cl.
fn push_flag(build: &mut cc::Build, compiler: &Compiler, flag: &str) {
    if compiler.cl_mode && !flag.starts_with("-D") && !flag.starts_with("-U") {
        build.flag(format!("/clang:{flag}"));
    } else {
        build.flag(flag);
    }
}

/// One `cc::Build` with the verified tools and the shared flags; `cc`'s own compiler and
/// archiver detection never runs.
fn new_build(
    compiler: &Compiler,
    archiver: &Path,
    flags: &Flags,
    prefix_header: &Path,
    obj_dir: &Path,
) -> cc::Build {
    let mut build = cc::Build::new();
    build
        .compiler(&compiler.path)
        .archiver(archiver)
        .out_dir(obj_dir)
        .cargo_metadata(false)
        .inherit_rustflags(false)
        .warnings(true)
        .extra_warnings(true)
        .pic(true);
    for (name, value) in &flags.defines {
        build.define(name, *value);
    }
    for flag in &flags.common {
        push_flag(&mut build, compiler, flag);
    }
    if compiler.cl_mode {
        build.flag(format!("/FI{}", prefix_header.display()));
    } else {
        build.flag("-include").flag(prefix_header.as_os_str());
    }
    build
}

/// Checks the final command line, environment flags included, against the policy.
fn verify_build(
    build: &cc::Build,
    compiler: &Compiler,
    lto: Lto,
    label: &str,
) -> Result<Vec<String>, String> {
    let tool = build
        .try_get_compiler()
        .map_err(|e| format!("configuring the {label} build: {e}"))?;
    if tool.path() != compiler.path {
        return Err(format!(
            "the cc crate resolved the compiler to `{}` instead of the verified `{}`",
            tool.path().display(),
            compiler.path.display()
        ));
    }
    if !tool.is_like_clang() && !tool.is_like_clang_cl() {
        return Err(format!(
            "the cc crate does not recognise `{}` as Clang",
            compiler.path.display()
        ));
    }
    let args: Vec<String> = tool
        .args()
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    for arg in &args {
        let bare = arg.strip_prefix("/clang:").unwrap_or(arg);
        if let Some((_, why)) = FORBIDDEN_FLAGS.iter().find(|(flag, _)| bare == *flag) {
            return Err(format!(
                "the {label} compile line contains `{arg}`, which dream-net-native refuses: {why}. \
                 It most likely comes from CFLAGS or CFLAGS_<target>; remove it."
            ));
        }
        if lto == Lto::Off && bare.starts_with("-flto") {
            return Err(format!(
                "the {label} compile line contains `{arg}` but LTO mode is off. Use \
                 DREAM_NET_NATIVE_LTO instead of passing -flto in CFLAGS."
            ));
        }
    }
    Ok(args)
}

fn c_files(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .map_err(|e| format!("reading {}: {e}", dir.display()))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_file() && path.extension().is_some_and(|e| e == "c"))
        .collect();
    files.sort();
    Ok(files)
}

fn run() -> Result<(), String> {
    let native = PathBuf::from(var("CARGO_MANIFEST_DIR")?);
    let out_dir = PathBuf::from(var("OUT_DIR")?);
    let target = Target::read()?;
    let opt_level = var("OPT_LEVEL")?;
    let rustflags: Vec<String> = env::var("CARGO_ENCODED_RUSTFLAGS")
        .unwrap_or_default()
        .split('\u{1f}')
        .filter(|f| !f.is_empty())
        .map(str::to_owned)
        .collect();

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=csrc");
    println!("cargo:rerun-if-changed=vendor");
    for name in ["CRATE_CC_NO_DEFAULTS", "DREAM_NET_NATIVE_NM"] {
        tracked(name);
    }
    // `cargo_metadata(false)` (below) also silences the rerun-if-env-changed lines cc would
    // print for what it reads, so they are declared here: without them a changed CFLAGS reused
    // the cached archive and skipped the forbidden-flag check. CFLAGS as cc reads it, then cc's
    // own switches, then what Clang, clang-cl and xcrun read by themselves (cc's documented list).
    target_scoped("CFLAGS", &target);
    for name in [
        "CC_SHELL_ESCAPED_FLAGS",
        "CC_FORCE_DISABLE",
        "CC_KNOWN_WRAPPER_CUSTOM",
        "CPATH",
        "C_INCLUDE_PATH",
        "COMPILER_PATH",
        "SOURCE_DATE_EPOCH",
        "CCC_OVERRIDE_OPTIONS",
        "CLANG_NO_DEFAULT_CONFIG",
        "INCLUDE",
        "EXTERNAL_INCLUDE",
        "VCToolsInstallDir",
        "VCINSTALLDIR",
        "CL",
        "_CL_",
        "DEVELOPER_DIR",
        "TOOLCHAINS",
        "SDKROOT",
        "MACOSX_DEPLOYMENT_TARGET",
        "IPHONEOS_DEPLOYMENT_TARGET",
        "TVOS_DEPLOYMENT_TARGET",
        "WATCHOS_DEPLOYMENT_TARGET",
        "XROS_DEPLOYMENT_TARGET",
        "RC_DEBUG_OPTIONS",
        "RC_DEBUG_PREFIX_MAP",
    ] {
        tracked(name);
    }

    let lto = lto_mode(&rustflags)?;
    let sanitize = sanitizers()?;
    if sanitize.iter().any(|s| s == "address")
        && !rustflags.iter().any(|f| f.contains("sanitizer=address"))
    {
        return Err(
            "DREAM_NET_NATIVE_SANITIZE includes address, which instruments the archive with ASan, \
             but the Rust side is not built with -Zsanitizer=address, so the ASan runtime would be \
             missing at link time. Use RUSTFLAGS=-Zsanitizer=address with a nightly toolchain and \
             an explicit --target (BUILD.md, \"Sanitizers\"), or sanitize only the upstream C tests \
             with DREAM_NET_NATIVE_TEST_SANITIZE."
                .to_owned(),
        );
    }

    let (compiler_path, source) = choose_compiler(&target)?;
    let compiler = verify_compiler(compiler_path, &source, &out_dir)?;
    let archiver = choose_archiver(&target, &compiler, lto)?;
    let lld = target
        .lld_names()
        .iter()
        .find_map(|name| find_llvm_tool(name, &compiler));
    if lto != Lto::Off {
        verify_lto(&target, &compiler, lld.as_deref())?;
    }
    let nm = tracked("DREAM_NET_NATIVE_NM")
        .and_then(|v| which(Path::new(&v)))
        .or_else(|| find_llvm_tool("llvm-nm", &compiler));

    let vendor = native.join("vendor");
    let csrc = native.join("csrc");
    let prefix_header = csrc.join("dn_native_prefix.h");
    let flags = flags(&target, &opt_level, lto, &sanitize, &native, &out_dir);
    let netcode_dir = vendor.join("netcode");
    let sodium_dir = netcode_dir.join("sodium");
    let reliable_dir = vendor.join("reliable");
    let std_flag = if compiler.cl_mode { "c11" } else { "gnu99" };

    // netcode and reliable: upstream's language (C99 with the GNU extensions CMake enables by
    // default) and warnings, which they compile clean under.
    let mut libs = new_build(
        &compiler,
        &archiver,
        &flags,
        &prefix_header,
        &out_dir.join("obj/libs"),
    );
    libs.std(std_flag)
        .include(&netcode_dir)
        .include(&sodium_dir)
        .include(&reliable_dir)
        .file(netcode_dir.join("netcode.c"))
        .file(reliable_dir.join("reliable.c"));
    let lib_args = verify_build(&libs, &compiler, lto, "netcode and reliable")?;

    // The libsodium subset: one justified suppression. `#pragma GCC target("sse2")` in the
    // verify.c section is GCC-only; Clang ignores it, and it guards code compiled only where SSE2
    // is already the baseline, so ignoring it changes nothing (upstream's CMake suppresses it too).
    let mut sodium = new_build(
        &compiler,
        &archiver,
        &flags,
        &prefix_header,
        &out_dir.join("obj/sodium"),
    );
    sodium
        .std(std_flag)
        .include(&sodium_dir)
        .file(sodium_dir.join("sodium.c"));
    push_flag(&mut sodium, &compiler, "-Wno-unknown-pragmas");
    verify_build(&sodium, &compiler, lto, "libsodium")?;

    // Our shim: every top-level .c in csrc/, warnings as errors.
    let shim_files = c_files(&csrc)?;
    let mut shim = new_build(
        &compiler,
        &archiver,
        &flags,
        &prefix_header,
        &out_dir.join("obj/shim"),
    );
    shim.std(if compiler.cl_mode { "c11" } else { "gnu11" })
        .include(&csrc)
        .include(&netcode_dir)
        .include(&sodium_dir)
        .include(&reliable_dir)
        .warnings_into_errors(true)
        .files(&shim_files);
    verify_build(&shim, &compiler, lto, "shim")?;

    let mut objects = Vec::new();
    for build in [&libs, &sodium, &shim] {
        objects.extend(
            build
                .try_compile_intermediates()
                .map_err(|e| format!("compiling the native C: {e}"))?,
        );
    }
    objects.sort();

    let archive = if target.msvc {
        out_dir.join(format!("{ARCHIVE}.lib"))
    } else {
        out_dir.join(format!("lib{ARCHIVE}.a"))
    };
    if archive.exists() {
        fs::remove_file(&archive).map_err(|e| format!("removing {}: {e}", archive.display()))?;
    }
    let mut ar = Command::new(&archiver);
    // r: insert, c: create silently, s: symbol table, D: zero timestamps, uids and modes.
    ar.arg("rcsD");
    if target.msvc {
        ar.arg("--format=coff");
    } else if target.apple {
        ar.arg("--format=darwin");
    }
    ar.arg(&archive).args(&objects).env("ZERO_AR_DATE", "1");
    run_capture(&mut ar).map_err(|e| format!("archiving: {e}"))?;

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static={ARCHIVE}");
    match target.os.as_str() {
        "windows" => {
            for lib in ["ws2_32", "iphlpapi", "advapi32"] {
                println!("cargo:rustc-link-lib={lib}");
            }
            if target.msvc {
                // netcode's Windows packet tagging uses qWave (MinGW disables it upstream).
                println!("cargo:rustc-link-lib=qwave");
            }
        }
        "macos" | "ios" | "tvos" | "watchos" | "visionos" => {}
        _ if target.family == "unix" => println!("cargo:rustc-link-lib=m"),
        _ => {}
    }

    // For this package's tests and the LTO probe (BUILD.md, "What the tests check").
    let test_cflags: Vec<&String> = lib_args
        .iter()
        .filter(|a| {
            let bare = a.strip_prefix("/clang:").unwrap_or(a);
            !(bare.starts_with("-std")
                || bare.starts_with("-flto")
                || bare.starts_with("-fsanitize")
                || bare == "-Werror")
        })
        .collect();
    let mut joined = String::new();
    for (index, arg) in test_cflags.iter().enumerate() {
        if index > 0 {
            joined.push('\u{1f}');
        }
        joined.push_str(arg);
    }
    let path_or_empty = |p: Option<&Path>| p.map(|p| p.display().to_string()).unwrap_or_default();
    println!("cargo:rustc-env=DN_NATIVE_ARCHIVE={}", archive.display());
    println!("cargo:rustc-env=DN_NATIVE_CC={}", compiler.path.display());
    println!(
        "cargo:rustc-env=DN_NATIVE_CC_CL_MODE={}",
        u8::from(compiler.cl_mode)
    );
    println!("cargo:rustc-env=DN_NATIVE_AR={}", archiver.display());
    println!(
        "cargo:rustc-env=DN_NATIVE_NM={}",
        path_or_empty(nm.as_deref())
    );
    println!(
        "cargo:rustc-env=DN_NATIVE_LLD={}",
        path_or_empty(lld.as_deref())
    );
    println!("cargo:rustc-env=DN_NATIVE_LTO={}", lto.name());
    println!("cargo:rustc-env=DN_NATIVE_SANITIZE={}", sanitize.join(","));
    println!("cargo:rustc-env=DN_NATIVE_TARGET_ENV={}", target.env);
    println!("cargo:rustc-env=DN_NATIVE_TEST_CFLAGS={joined}");
    // Metadata for dependents (DEP_DREAM_NET_NATIVE_*), via the `links` key.
    println!("cargo:include={}", csrc.display());
    println!("cargo:prefix=dn_native_");
    println!("cargo:lto={}", lto.name());

    let mut summary = String::new();
    let _ = write!(
        summary,
        "dream-net-native: {} ({}) | ar {} | lto {} | sanitize [{}] | {} objects",
        compiler.path.display(),
        compiler.banner,
        archiver.display(),
        lto.name(),
        sanitize.join(","),
        objects.len()
    );
    let unique: BTreeSet<_> = objects.iter().filter_map(|o| o.file_name()).collect();
    if unique.len() != objects.len() {
        return Err("two native objects share a file name inside the archive".to_owned());
    }
    // Visible with `cargo build -vv`; never a warning on a successful build.
    println!("{summary}");
    Ok(())
}
