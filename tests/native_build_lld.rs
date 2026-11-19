//! The workspace's own test binaries, this one included, are linked by LLD.
//!
//! A library cannot choose the linker of a downstream binary; this proves what the workspace
//! controls. On Linux, rustc >= 1.90 (the 1.95 MSRV included) links x86_64-unknown-linux-gnu with
//! its bundled rust-lld by default, and the workspace's `.cargo/config.toml` passes
//! `-fuse-ld=lld` on every Linux GNU target regardless. LLD records itself in the ELF `.comment`
//! section ("Linker: LLD <version>"); GNU ld and gold record nothing there. Mach-O and PE carry
//! no comparable marker, so the check exists only for ELF (native/BUILD.md, "Linker").

// CI passes -W clippy::pedantic on the command line, overriding the manifest's lint table.
#![allow(clippy::module_name_repetitions)]

// Links the native archive into this binary, so the proof covers a binary that contains it.
use dream_net as _;

#[test]
#[cfg_attr(
    not(all(target_os = "linux", target_env = "gnu")),
    ignore = "LLD leaves an identifiable marker only in ELF .comment; checked on Linux GNU targets"
)]
fn this_test_binary_was_linked_by_lld() {
    let exe = std::env::current_exe().expect("current_exe");
    let bytes = std::fs::read(&exe).expect("reading the test binary");
    let comment = elf_section(&bytes, b".comment")
        .expect("an ELF64 little-endian binary with a .comment section");
    // Searched for inside .comment only: the marker text also sits in this binary's .rodata.
    let marker = b"Linker: LLD ";
    let at = comment
        .windows(marker.len())
        .position(|w| w == marker)
        .unwrap_or_else(|| {
            panic!(
                "{} has no \"Linker: LLD\" in .comment: it was not linked by LLD. RUSTFLAGS in the \
                 environment replace the workspace's .cargo/config.toml rustflags; add \
                 -Clink-arg=-fuse-ld=lld to them.",
                exe.display()
            )
        });
    let end = comment[at..]
        .iter()
        .position(|&b| b == 0)
        .map_or(comment.len(), |n| at + n);
    println!("{}", String::from_utf8_lossy(&comment[at..end]));
}

/// The contents of the named section of an ELF64 little-endian file.
fn elf_section<'a>(elf: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    let u16_at = |at: usize| Some(u16::from_le_bytes(elf.get(at..at + 2)?.try_into().ok()?));
    let u32_at = |at: usize| Some(u32::from_le_bytes(elf.get(at..at + 4)?.try_into().ok()?));
    let u64_at = |at: usize| Some(u64::from_le_bytes(elf.get(at..at + 8)?.try_into().ok()?));
    if elf.get(0..6)? != b"\x7fELF\x02\x01" {
        return None;
    }
    let shoff = usize::try_from(u64_at(0x28)?).ok()?;
    let shentsize = usize::from(u16_at(0x3A)?);
    let shnum = usize::from(u16_at(0x3C)?);
    let shstrndx = usize::from(u16_at(0x3E)?);
    let header = |index: usize| shoff + index * shentsize;
    let contents = |index: usize| -> Option<&'a [u8]> {
        let offset = usize::try_from(u64_at(header(index) + 0x18)?).ok()?;
        let size = usize::try_from(u64_at(header(index) + 0x20)?).ok()?;
        elf.get(offset..offset + size)
    };
    let names = contents(shstrndx)?;
    (0..shnum).find_map(|index| {
        let start = usize::try_from(u32_at(header(index))?).ok()?;
        let section_name = names.get(start..)?.split(|&b| b == 0).next()?;
        if section_name == name {
            contents(index)
        } else {
            None
        }
    })
}
