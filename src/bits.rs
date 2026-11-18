//! The bit stream under the connection packet format: a small, safe, total reimplementation of
//! the part of the [serialize](https://github.com/mas-bandwidth/serialize.rs) bitpacker
//! (`serialize-official` 2.4.0) that [`crate::wire`] uses. Wire format v2 is serialize's bit
//! stream format, and this module writes and accepts the same bytes, so dream-net 1.1.1 peers
//! interoperate with this code unchanged.
//!
//! # What serialize did, and what is reproduced here
//!
//! - **Bit order.** A value of `n` bits is packed least significant bit first: its bit `i`
//!   becomes stream bit `p + i`, where `p` is the number of bits written before it. serialize
//!   ORs values into a 64-bit scratch word from the low end and stores full words to memory
//!   little endian, so stream bit `k` is bit `k % 8` of byte `k / 8`, on every platform. The
//!   writer here keeps the same scratch word and little-endian stores (one store per 64 bits
//!   is the fast path); the reader loads a little-endian 64-bit window at byte `k / 8` and
//!   shifts by `k % 8`, exactly as serialize's reader does.
//! - **Widths.** serialize reads and writes 1 to 32 bits per call (a debug assertion, compiled
//!   out in release). dream-net's own wrapper never called it with 0 bits: a zero-width field
//!   (`bits_required(x, x)`) occupies no bits and decodes as its minimum. Here a 0-bit read
//!   returns 0 and consumes nothing, and a read wider than 32 bits is refused, in every build.
//! - **Alignment.** `write_align` pads with zero bits up to the next multiple of 8 bits
//!   counted from the start of the stream (nothing if already aligned). On read, the same pad
//!   width is computed from the bits read, and the pad must be all zeros: serialize's
//!   `read_align` returned `false` for nonzero padding, and [`crate::wire`] refuses it.
//! - **Bytes.** `write_bytes` requires an aligned stream. serialize bitpacks head bytes one at
//!   a time up to a word boundary, copies whole words, then bitpacks the tail; on the wire this
//!   is identical to writing each byte as an 8-bit value, which is what the reader's zero-copy
//!   byte slices assume. The writer here produces the same bytes but ORs the head into the
//!   scratch word, and starts the next scratch word from the tail, with one load each.
//! - **Flush and length.** serialize stores the final partial scratch word whole, so up to 7
//!   bytes past the data are written (as zeros), and reports `bytes_written` as the bits
//!   written rounded up to whole bytes. dream-net always aligns before flushing, so a packet
//!   is exactly `bits / 8` bytes. serialize required the write buffer to be a multiple of 8
//!   bytes and panicked (a slice bounds check) if the final word did not fit; the writer here
//!   stores only the bytes the buffer has, so it never writes out of bounds and needs no slack:
//!   a buffer of `bytes_written` bytes is enough. `Connection`'s write buffer (the maximum
//!   packet size rounded up to whole words, plus one spare word) remains more than sufficient.
//! - **Reader construction.** dream-net built serialize's reader as `BitReader::new(packet,
//!   packet.len())`: the readable length is the whole packet, which need not be a multiple of 8
//!   bytes. Near the end, window loads fell back to a zero-filled copy of the remaining bytes;
//!   bits past the end were never interpreted because dream-net checked `would_read_past_end`
//!   before every read. Here that check is part of every read.
//! - **Reading past the end.** serialize's `read_bits` only debug-asserted against it (returning
//!   zero-filled bits in release) and `read_byte_slice` panicked on its slice bounds check;
//!   dream-net's wrapper guarded both. Here every read returns `None` instead: the reader is
//!   total, with no panic, no out-of-bounds index, no arithmetic overflow and no allocation for
//!   any input and any sequence of calls.
//! - **`bits_required(min, max)`** is 0 when `min == max`, otherwise
//!   `32 - leading_zeros(max - min)` with the subtraction wrapping (dream-net never passes
//!   `min > max`).
//! - **`int_relative`** lives in [`crate::wire`]; its buckets are serialize's.
//!
//! This module has no dependencies on the rest of the crate, so tests outside it can compile
//! the same source against serialize itself.

#![forbid(unsafe_code)]

use core::fmt;

/// Calculates the number of bits needed for an integer in `[min, max]`: zero for a range of
/// one value.
#[inline]
pub(crate) const fn bits_required(min: u32, max: u32) -> u32 {
    if min == max {
        0
    } else {
        32 - max.wrapping_sub(min).leading_zeros()
    }
}

/// The first `n` (at most 8) bytes of `bytes` as a little-endian word, zero filled: one load
/// when 8 bytes are available.
#[inline]
fn le_prefix(bytes: &[u8], n: usize) -> u64 {
    match bytes.first_chunk::<8>() {
        Some(word) if n < 8 => u64::from_le_bytes(*word) & ((1u64 << (n * 8)) - 1),
        Some(word) => u64::from_le_bytes(*word),
        None => le_bytes(&bytes[..n.min(bytes.len())]),
    }
}

/// The last `n` (at most 8) bytes of `bytes` as a little-endian word, zero filled: one load
/// when 8 bytes are available.
#[inline]
fn le_suffix(bytes: &[u8], n: usize) -> u64 {
    match bytes.last_chunk::<8>() {
        Some(word) if n > 0 => u64::from_le_bytes(*word) >> ((8 - n.min(8)) * 8),
        Some(_) => 0,
        None => le_bytes(&bytes[bytes.len() - n.min(bytes.len())..]),
    }
}

#[inline]
fn le_bytes(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .take(8)
        .enumerate()
        .fold(0, |word, (i, &b)| word | u64::from(b) << (8 * i))
}

/// Bitpacks values into a caller-owned buffer. The trusted write path: width and range
/// violations are debug assertions, but nothing is ever written outside the buffer.
pub(crate) struct BitWriter<'a> {
    data: &'a mut [u8],
    scratch: u64,
    bits_written: u64,
    word_index: usize,
    /// Bits held in `scratch`; always below 64.
    scratch_bits: u32,
}

impl fmt::Debug for BitWriter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // counters only, as serialize's writer printed them: the buffer is not log material
        f.debug_struct("BitWriter")
            .field("bits_written", &self.bits_written)
            .field("num_bits", &(self.data.len() as u64).saturating_mul(8))
            .finish_non_exhaustive()
    }
}

impl<'a> BitWriter<'a> {
    /// Starts writing at the beginning of `data`, which may be any length.
    #[inline]
    pub(crate) fn new(data: &'a mut [u8]) -> Self {
        Self {
            data,
            scratch: 0,
            bits_written: 0,
            word_index: 0,
            scratch_bits: 0,
        }
    }

    /// Writes the low `bits` bits of `value`; `bits` is in `[0, 32]` and `value` below
    /// `1 << bits`.
    #[inline]
    pub(crate) fn write_bits(&mut self, value: u32, bits: u32) {
        debug_assert!(bits <= 32, "bits must be in [0, 32] (got {bits})");
        debug_assert!(u64::from(value) < (1u64 << bits.min(32)));
        debug_assert!(
            self.bits_written + u64::from(bits) <= (self.data.len() as u64).saturating_mul(8),
            "write past the end of the buffer"
        );
        // clamped so no shift below can overflow, whatever a release build is handed
        let bits = bits.min(32);
        // scratch_bits < 64
        self.scratch |= u64::from(value) << self.scratch_bits;
        let filled = self.scratch_bits + bits;
        if filled >= 64 {
            self.store_word();
            // filled >= 64 with bits <= 32 means scratch_bits >= 32: the shift is in [1, 32]
            self.scratch = u64::from(value) >> (64 - self.scratch_bits);
            self.scratch_bits = filled - 64;
        } else {
            self.scratch_bits = filled;
        }
        self.bits_written += u64::from(bits);
    }

    /// Stores the scratch word at the next word position: whole when the buffer has room, and
    /// otherwise only the bytes that fit (the rest are the zeros past the data).
    #[inline]
    fn store_word(&mut self) {
        let start = self.word_index.wrapping_mul(8);
        match self
            .data
            .get_mut(start..)
            .and_then(<[u8]>::first_chunk_mut::<8>)
        {
            Some(dst) => *dst = self.scratch.to_le_bytes(),
            None => self.store_partial(start, &self.scratch.to_le_bytes()),
        }
        self.word_index = self.word_index.wrapping_add(1);
    }

    #[cold]
    #[inline(never)]
    fn store_partial(&mut self, start: usize, bytes: &[u8]) {
        if let Some(tail) = self.data.get_mut(start..) {
            let n = tail.len().min(bytes.len());
            tail[..n].copy_from_slice(&bytes[..n]);
        }
    }

    /// Pads with zero bits to a byte boundary.
    #[inline]
    pub(crate) fn write_align(&mut self) {
        let remainder = (self.bits_written % 8) as u32;
        if remainder != 0 {
            self.write_bits(0, 8 - remainder);
        }
    }

    /// Writes `bytes` as 8-bit values; the stream must be byte aligned.
    #[inline]
    pub(crate) fn write_bytes(&mut self, bytes: &[u8]) {
        debug_assert_eq!(
            self.bits_written % 8,
            0,
            "write_bytes on an unaligned stream"
        );
        if !self.scratch_bits.is_multiple_of(8) {
            // only on an unaligned stream (a contract violation): keep the bit semantics
            // rather than tear the stream
            for &byte in bytes {
                self.write_bits(u32::from(byte), 8);
            }
            return;
        }
        let mut rest = bytes;
        // head: complete the partial scratch word with up to 7 bytes, in one OR
        if self.scratch_bits != 0 {
            let room = ((64 - self.scratch_bits) / 8) as usize;
            let (head, after) = rest.split_at(room.min(rest.len()));
            // scratch_bits is in [8, 56] here, so the shift is in range
            self.scratch |= le_prefix(rest, head.len()) << self.scratch_bits;
            self.bits_written += head.len() as u64 * 8;
            if head.len() < room {
                self.scratch_bits += head.len() as u32 * 8;
                return;
            }
            self.store_word();
            self.scratch = 0;
            self.scratch_bits = 0;
            rest = after;
        }
        // whole words: a straight copy, no bitpacking
        let (whole, tail) = rest.split_at(rest.len() / 8 * 8);
        if !whole.is_empty() {
            let start = self.word_index.wrapping_mul(8);
            if let Some(dst) = self.data.get_mut(start..start.wrapping_add(whole.len())) {
                dst.copy_from_slice(whole);
            } else {
                self.store_partial(start, whole);
            }
            self.word_index = self.word_index.wrapping_add(whole.len() / 8);
            self.bits_written += whole.len() as u64 * 8;
        }
        // tail: fewer than 8 bytes start the next scratch word
        if !tail.is_empty() {
            self.scratch = le_suffix(bytes, tail.len());
            self.scratch_bits = tail.len() as u32 * 8;
            self.bits_written += tail.len() as u64 * 8;
        }
    }

    /// Stores any bits still held in the scratch word. Call once, after the last write.
    #[inline]
    pub(crate) fn flush_bits(&mut self) {
        if self.scratch_bits != 0 {
            self.store_word();
            self.scratch = 0;
            self.scratch_bits = 0;
        }
    }

    /// Bits written so far.
    #[inline]
    pub(crate) fn bits_written(&self) -> u64 {
        self.bits_written
    }

    /// Bytes written: the bits rounded up to whole bytes. Call [`Self::flush_bits`] first.
    #[inline]
    pub(crate) fn bytes_written(&self) -> u64 {
        self.bits_written.div_ceil(8)
    }
}

/// Reads bitpacked values from a received packet. Total: every read is checked and returns
/// `None` rather than reading past the end.
#[derive(Clone)]
pub(crate) struct BitReader<'a> {
    data: &'a [u8],
    num_bits: u64,
    /// Never above `num_bits`.
    bits_read: u64,
}

impl fmt::Debug for BitReader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BitReader")
            .field("bits_read", &self.bits_read)
            .field("num_bits", &self.num_bits)
            .finish_non_exhaustive()
    }
}

impl<'a> BitReader<'a> {
    /// Reads all of `data`, whatever its length.
    #[inline]
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            // a slice is at most isize::MAX bytes, so this saturates on no real platform; if it
            // did, the reader would merely refuse the bytes past 2^64 bits
            num_bits: (data.len() as u64).saturating_mul(8),
            bits_read: 0,
        }
    }

    /// The little-endian 64-bit window starting at byte `index`, zero filled past the end.
    #[inline]
    fn window(&self, index: usize) -> u64 {
        match self.data.get(index..index.wrapping_add(8)) {
            Some(window) => match <[u8; 8]>::try_from(window) {
                Ok(window) => u64::from_le_bytes(window),
                Err(_) => self.window_slow(index),
            },
            None => self.window_slow(index),
        }
    }

    #[cold]
    #[inline(never)]
    fn window_slow(&self, index: usize) -> u64 {
        let mut window = [0u8; 8];
        let tail = self.data.get(index..).unwrap_or_default();
        let n = tail.len().min(8);
        window[..n].copy_from_slice(&tail[..n]);
        u64::from_le_bytes(window)
    }

    /// Reads `bits` bits (0 to 32). `None` if that would pass the end of the data or `bits`
    /// is wider than 32; nothing is consumed then.
    #[inline]
    pub(crate) fn read_bits(&mut self, bits: u32) -> Option<u32> {
        if bits > 32 || u64::from(bits) > self.num_bits - self.bits_read {
            return None;
        }
        if bits == 0 {
            return Some(0);
        }
        // bits_read <= num_bits = 8 * data.len(), so the byte index fits a usize
        let offset = self.bits_read;
        let window = self.window((offset >> 3) as usize);
        self.bits_read = offset + u64::from(bits);
        Some(((window >> (offset & 7)) & ((1u64 << bits) - 1)) as u32)
    }

    /// Bits of padding to the next byte boundary, in `[0, 7]`.
    #[inline]
    pub(crate) fn align_bits(&self) -> u32 {
        ((8 - self.bits_read % 8) % 8) as u32
    }

    /// Takes the next `len` bytes as a slice of the data, without copying. `None` if the stream
    /// is not byte aligned or fewer than `len` bytes remain; nothing is consumed then.
    #[inline]
    pub(crate) fn read_byte_slice(&mut self, len: usize) -> Option<&'a [u8]> {
        if !self.bits_read.is_multiple_of(8) || len as u64 > self.bits_remaining() / 8 {
            return None;
        }
        let start = (self.bits_read / 8) as usize;
        let slice = self.data.get(start..start.checked_add(len)?)?;
        self.bits_read += len as u64 * 8;
        Some(slice)
    }

    /// Bits read so far.
    #[inline]
    pub(crate) fn bits_read(&self) -> u64 {
        self.bits_read
    }

    /// Bits left to read.
    #[inline]
    pub(crate) fn bits_remaining(&self) -> u64 {
        self.num_bits - self.bits_read
    }
}

#[cfg(test)]
mod tests {
    use super::{BitReader, BitWriter, bits_required};

    /// The bit stream as a plain list of bits, least significant first: the model both sides
    /// are checked against.
    #[derive(Default)]
    struct Model(Vec<bool>);

    impl Model {
        fn push(&mut self, value: u32, bits: u32) {
            for i in 0..bits {
                self.0.push(value >> i & 1 == 1);
            }
        }

        fn align(&mut self) {
            while !self.0.len().is_multiple_of(8) {
                self.0.push(false);
            }
        }

        fn bytes(&self) -> Vec<u8> {
            self.0
                .chunks(8)
                .map(|c| {
                    c.iter()
                        .enumerate()
                        .fold(0u8, |b, (i, &bit)| b | (u8::from(bit) << i))
                })
                .collect()
        }
    }

    /// A small deterministic generator, so the tests need nothing outside this file.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }

        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    enum Op {
        Bits(u32, u32),
        Align,
        Bytes(Vec<u8>),
    }

    fn random_ops(rng: &mut Rng) -> Vec<Op> {
        let count = rng.below(64);
        let mut ops = Vec::new();
        let mut aligned = true;
        for _ in 0..count {
            match rng.below(4) {
                0 if aligned => {
                    let len = rng.below(40) as usize;
                    ops.push(Op::Bytes((0..len).map(|_| rng.next() as u8).collect()));
                }
                1 => {
                    ops.push(Op::Align);
                    aligned = true;
                }
                _ => {
                    let bits = 1 + rng.below(32) as u32;
                    let value = (rng.next() & ((1u64 << bits) - 1)) as u32;
                    ops.push(Op::Bits(value, bits));
                    aligned = false;
                }
            }
        }
        ops
    }

    fn write(ops: &[Op], buffer: &mut [u8]) -> usize {
        let mut w = BitWriter::new(buffer);
        for op in ops {
            match op {
                Op::Bits(value, bits) => w.write_bits(*value, *bits),
                Op::Align => w.write_align(),
                Op::Bytes(bytes) => w.write_bytes(bytes),
            }
        }
        w.write_align();
        w.flush_bits();
        w.bytes_written() as usize
    }

    fn model(ops: &[Op]) -> Vec<u8> {
        let mut m = Model::default();
        for op in ops {
            match op {
                Op::Bits(value, bits) => m.push(*value, *bits),
                Op::Align => m.align(),
                Op::Bytes(bytes) => bytes.iter().for_each(|&b| m.push(u32::from(b), 8)),
            }
        }
        m.align();
        m.bytes()
    }

    #[test]
    fn bits_required_matches_serialize_definition() {
        assert_eq!(bits_required(0, 0), 0);
        assert_eq!(bits_required(7, 7), 0);
        assert_eq!(bits_required(0, 1), 1);
        assert_eq!(bits_required(1, 2), 1);
        assert_eq!(bits_required(0, 2), 2);
        assert_eq!(bits_required(0, 3), 2);
        assert_eq!(bits_required(0, 4), 3);
        assert_eq!(bits_required(1, 32), 5);
        assert_eq!(bits_required(0, 64), 7);
        assert_eq!(bits_required(0, 1024), 11);
        assert_eq!(bits_required(2, 6), 3);
        assert_eq!(bits_required(7, 23), 5);
        assert_eq!(bits_required(24, 280), 9);
        assert_eq!(bits_required(281, 4377), 13);
        assert_eq!(bits_required(4378, 69914), 17);
        assert_eq!(bits_required(0, u32::MAX), 32);
        // serialize's subtraction wraps: min > max is never passed, but stays defined
        assert_eq!(bits_required(1, 0), 32);
    }

    #[test]
    fn hand_computed_vectors() {
        let mut buffer = [0xFFu8; 16];
        let mut w = BitWriter::new(&mut buffer);
        w.write_bits(0b01, 2);
        w.write_bits(1, 1);
        w.write_bits(0x2A, 6);
        w.write_align();
        w.write_bytes(&[0xDE, 0xAD]);
        w.write_bits(0xBEEF, 16);
        w.flush_bits();
        assert_eq!(w.bits_written(), 48);
        assert_eq!(w.bytes_written(), 6);
        // 0b01 | 1 << 2 | 0x2A << 3 = 0x155: byte 0x55, then bit 8 set and 7 bits of padding
        assert_eq!(&buffer[..6], &[0x55, 0x01, 0xDE, 0xAD, 0xEF, 0xBE]);
        // the flush stores the whole final word: zeros past the data
        assert_eq!(&buffer[6..8], &[0, 0]);
        assert_eq!(&buffer[8..], &[0xFF; 8]);

        let mut r = BitReader::new(&buffer[..6]);
        assert_eq!(r.read_bits(2), Some(0b01));
        assert_eq!(r.read_bits(1), Some(1));
        assert_eq!(r.read_bits(6), Some(0x2A));
        assert_eq!(r.align_bits(), 7);
        assert_eq!(r.read_bits(7), Some(0));
        assert_eq!(r.read_byte_slice(2), Some(&[0xDE, 0xAD][..]));
        assert_eq!(r.read_bits(16), Some(0xBEEF));
        assert_eq!(r.bits_remaining(), 0);
        assert_eq!(r.read_bits(1), None);
        assert_eq!(r.read_bits(0), Some(0));
    }

    #[test]
    fn a_full_word_spills_into_the_next() {
        let mut buffer = [0u8; 16];
        let mut w = BitWriter::new(&mut buffer);
        w.write_bits(0x7FFF_FFFF, 31);
        w.write_bits(0x1234_5678, 32);
        w.write_bits(0b101, 3);
        w.flush_bits();
        assert_eq!(w.bits_written(), 66);
        assert_eq!(w.bytes_written(), 9);
        let mut r = BitReader::new(&buffer[..9]);
        assert_eq!(r.read_bits(31), Some(0x7FFF_FFFF));
        assert_eq!(r.read_bits(32), Some(0x1234_5678));
        assert_eq!(r.read_bits(3), Some(0b101));
        assert_eq!(r.read_bits(6), Some(0));
        assert_eq!(r.read_bits(1), None);
    }

    #[test]
    fn random_streams_match_the_model_and_read_back() {
        let mut rng = Rng(0x00D2_EA11);
        for _ in 0..5_000 {
            let ops = random_ops(&mut rng);
            let expected = model(&ops);
            // a buffer of exactly the packet's bytes is enough: no slack is needed
            let mut exact = vec![0xAAu8; expected.len()];
            let len = write(&ops, &mut exact);
            assert_eq!(len, expected.len());
            assert_eq!(exact, expected);
            // a dirty, oversized buffer is overwritten, not merged with
            let mut roomy = vec![0x5Au8; expected.len() + 24];
            let len = write(&ops, &mut roomy);
            assert_eq!(&roomy[..len], &expected[..]);

            let mut r = BitReader::new(&expected);
            for op in &ops {
                match op {
                    Op::Bits(value, bits) => assert_eq!(r.read_bits(*bits), Some(*value)),
                    Op::Align => assert_eq!(r.read_bits(r.align_bits()), Some(0)),
                    Op::Bytes(bytes) => {
                        assert_eq!(r.read_byte_slice(bytes.len()), Some(&bytes[..]));
                    }
                }
            }
            assert_eq!(r.read_bits(r.align_bits()), Some(0));
            assert_eq!(r.bits_remaining(), 0);
            assert_eq!(r.bits_read(), expected.len() as u64 * 8);
        }
    }

    #[test]
    fn reads_are_total() {
        let mut rng = Rng(7);
        for _ in 0..5_000 {
            let len = rng.below(24) as usize;
            let data: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
            let mut model = Model::default();
            for &b in &data {
                model.push(u32::from(b), 8);
            }
            let mut r = BitReader::new(&data);
            for _ in 0..64 {
                let before = r.bits_read();
                match rng.below(3) {
                    0 => {
                        let bits = rng.below(40) as u32;
                        let got = r.read_bits(bits);
                        let fits = bits <= 32 && before + u64::from(bits) <= len as u64 * 8;
                        if fits {
                            let expected = (0..bits).fold(0u32, |v, i| {
                                v | u32::from(model.0[(before + u64::from(i)) as usize]) << i
                            });
                            assert_eq!(got, Some(expected));
                        } else {
                            assert_eq!(got, None);
                            assert_eq!(r.bits_read(), before);
                        }
                    }
                    1 => {
                        let n = rng.below(12) as usize;
                        let got = r.read_byte_slice(n);
                        if before.is_multiple_of(8) && before / 8 + n as u64 <= len as u64 {
                            let start = (before / 8) as usize;
                            assert_eq!(got, Some(&data[start..start + n]));
                        } else {
                            assert_eq!(got, None);
                            assert_eq!(r.bits_read(), before);
                        }
                    }
                    _ => {
                        let _ = r.read_bits(r.align_bits());
                    }
                }
                assert!(r.bits_read() <= len as u64 * 8);
                assert_eq!(r.bits_remaining(), len as u64 * 8 - r.bits_read());
            }
        }
        let mut empty = BitReader::new(&[]);
        assert_eq!(empty.read_bits(1), None);
        assert_eq!(empty.read_bits(0), Some(0));
        assert_eq!(empty.read_byte_slice(0), Some(&[][..]));
        assert_eq!(empty.read_byte_slice(usize::MAX), None);
        assert_eq!(empty.read_bits(u32::MAX), None);
    }

    #[test]
    fn writes_never_leave_the_buffer() {
        // release builds only: in debug the overrun is an assertion
        if cfg!(debug_assertions) {
            return;
        }
        let mut buffer = [0u8; 3];
        let mut w = BitWriter::new(&mut buffer);
        for _ in 0..4 {
            w.write_bits(u32::MAX, 32);
        }
        w.write_bytes(&[1; 40]);
        w.write_bits(5, 40);
        w.flush_bits();
        assert_eq!(buffer, [0xFF; 3]);
    }

    #[test]
    fn debug_prints_counters_only() {
        let mut buffer = [0u8; 16];
        let mut w = BitWriter::new(&mut buffer);
        w.write_bits(3, 2);
        assert_eq!(
            format!("{w:?}"),
            "BitWriter { bits_written: 2, num_bits: 128, .. }"
        );
        let r = BitReader::new(&buffer[..3]);
        assert_eq!(
            format!("{r:?}"),
            "BitReader { bits_read: 0, num_bits: 24, .. }"
        );
    }
}
