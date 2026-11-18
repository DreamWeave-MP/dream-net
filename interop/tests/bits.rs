//! dream-net's private bit stream (`src/bits.rs`, compiled here from its source so the main
//! crate gains no public surface) against serialize 2.4.0's `BitWriter`/`BitReader`, over
//! random operation sequences: the writers must produce the same bytes, and the readers must
//! return the same values wherever serialize's read is within its contract, while dream-net's
//! reader refuses every read serialize leaves to the caller to prevent.

// CI passes -W clippy::pedantic on the command line, overriding the manifest's lint table;
// test code casts freely between widths it controls.
#![allow(
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]

#[path = "../../src/bits.rs"]
#[allow(unused)] // the tests use part of the module
mod bits;

use proptest::prelude::*;

#[derive(Debug, Clone)]
enum Write {
    Bits(u32, u32),
    Align,
    /// Aligns first: serialize requires an aligned stream for byte runs.
    Bytes(Vec<u8>),
}

fn write_op() -> impl Strategy<Value = Write> {
    prop_oneof![
        6 => (1u32..=32, any::<u32>()).prop_map(|(bits, v)| Write::Bits(
            if bits == 32 { v } else { v & ((1 << bits) - 1) },
            bits
        )),
        1 => Just(Write::Align),
        2 => prop::collection::vec(any::<u8>(), 0..40).prop_map(Write::Bytes),
    ]
}

/// Writes `ops` with dream-net's writer into `buffer`, returning (bits, bytes).
fn write_new(ops: &[Write], buffer: &mut [u8]) -> (u64, u64) {
    let mut w = bits::BitWriter::new(buffer);
    for op in ops {
        match op {
            Write::Bits(value, n) => w.write_bits(*value, *n),
            Write::Align => w.write_align(),
            Write::Bytes(bytes) => {
                w.write_align();
                w.write_bytes(bytes);
            }
        }
    }
    let bits = w.bits_written();
    w.flush_bits();
    (bits, w.bytes_written())
}

fn write_old(ops: &[Write], buffer: &mut [u8]) -> (u64, u64) {
    let mut w = serialize::BitWriter::new(buffer);
    for op in ops {
        match op {
            Write::Bits(value, n) => w.write_bits(*value, *n),
            Write::Align => w.write_align(),
            Write::Bytes(bytes) => {
                w.write_align();
                w.write_bytes(bytes);
            }
        }
    }
    let bits = w.bits_written();
    w.flush_bits();
    (bits, w.bytes_written())
}

#[derive(Debug, Clone, Copy)]
enum Read {
    /// Any width, including 0 and widths past 32.
    Bits(u32),
    Align,
    Bytes(usize),
}

fn read_op() -> impl Strategy<Value = Read> {
    prop_oneof![
        6 => (0u32..=40).prop_map(Read::Bits),
        2 => Just(Read::Align),
        2 => (0usize..24).prop_map(Read::Bytes),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    #[test]
    fn writers_produce_identical_bytes(ops in prop::collection::vec(write_op(), 0..80)) {
        // serialize needs a buffer that is a multiple of 8 bytes with room for its last word
        let mut old = vec![0u8; 8 * 1024];
        let (old_bits, old_len) = write_old(&ops, &mut old);
        let mut new = vec![0x5Au8; 8 * 1024];
        let (new_bits, new_len) = write_new(&ops, &mut new);
        prop_assert_eq!(new_bits, old_bits);
        prop_assert_eq!(new_len, old_len);
        prop_assert_eq!(&new[..new_len as usize], &old[..old_len as usize]);
        // dream-net's writer also fits a buffer of exactly the packet's bytes
        let mut exact = vec![0xA5u8; old_len as usize];
        let (_, exact_len) = write_new(&ops, &mut exact);
        prop_assert_eq!(exact_len, old_len);
        prop_assert_eq!(&exact[..], &old[..old_len as usize]);
    }

    #[test]
    fn readers_agree_on_any_bytes(
        data in prop::collection::vec(any::<u8>(), 0..48),
        ops in prop::collection::vec(read_op(), 0..64),
    ) {
        // dream-net built serialize's reader over the packet alone: no slack past the data
        let mut old = serialize::BitReader::new(&data, data.len());
        let mut new = bits::BitReader::new(&data);
        for op in ops {
            prop_assert_eq!(new.bits_read(), old.bits_read());
            prop_assert_eq!(new.bits_remaining(), old.bits_remaining());
            prop_assert_eq!(new.align_bits(), old.align_bits());
            match op {
                Read::Bits(n) => {
                    let got = new.read_bits(n);
                    if n == 0 {
                        prop_assert_eq!(got, Some(0));
                    } else if n > 32 || old.would_read_past_end(n) {
                        prop_assert_eq!(got, None);
                    } else {
                        prop_assert_eq!(got, Some(old.read_bits(n)));
                    }
                }
                Read::Align => {
                    let pad = old.align_bits();
                    if pad == 0 {
                        prop_assert!(old.read_align());
                        prop_assert_eq!(new.read_bits(pad), Some(0));
                    } else if old.would_read_past_end(pad) {
                        prop_assert_eq!(new.read_bits(pad), None);
                    } else {
                        let clean = old.read_align();
                        prop_assert_eq!(new.read_bits(pad).map(|v| v == 0), Some(clean));
                    }
                }
                Read::Bytes(len) => {
                    let got = new.read_byte_slice(len);
                    if old.align_bits() != 0 || len as u64 * 8 > old.bits_remaining() {
                        prop_assert_eq!(got, None);
                    } else {
                        prop_assert_eq!(got, Some(old.read_byte_slice(len)));
                    }
                }
            }
        }
        prop_assert_eq!(new.bits_read(), old.bits_read());
    }

    #[test]
    fn readers_agree_on_written_streams(ops in prop::collection::vec(write_op(), 0..80)) {
        let mut buffer = vec![0u8; 8 * 1024];
        let (_, len) = write_old(&ops, &mut buffer);
        let packet = &buffer[..len as usize];
        let mut old = serialize::BitReader::new(packet, packet.len());
        let mut new = bits::BitReader::new(packet);
        for op in &ops {
            match op {
                Write::Bits(value, n) => {
                    prop_assert_eq!(old.read_bits(*n), *value);
                    prop_assert_eq!(new.read_bits(*n), Some(*value));
                }
                Write::Align => {
                    prop_assert!(old.read_align());
                    prop_assert_eq!(new.read_bits(new.align_bits()), Some(0));
                }
                Write::Bytes(bytes) => {
                    prop_assert!(old.read_align());
                    prop_assert_eq!(new.read_bits(new.align_bits()), Some(0));
                    prop_assert_eq!(old.read_byte_slice(bytes.len()), &bytes[..]);
                    prop_assert_eq!(new.read_byte_slice(bytes.len()), Some(&bytes[..]));
                }
            }
            prop_assert_eq!(new.bits_read(), old.bits_read());
        }
    }

    #[test]
    fn bits_required_matches(min in any::<u32>(), span in any::<u32>()) {
        let max = min.saturating_add(span);
        prop_assert_eq!(bits::bits_required(min, max), serialize::bits_required(min, max));
        prop_assert_eq!(bits::bits_required(min, min), serialize::bits_required(min, min));
        let small = span % 70_000;
        prop_assert_eq!(bits::bits_required(0, small), serialize::bits_required(0, small));
    }
}
