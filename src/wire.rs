//! The connection packet wire format, version 2.
//!
//! A connection packet is the payload dream-net hands `reliable` (which adds its own
//! sequence/ack header and fragments large packets). It is a `serialize` bit stream — little
//! endian 64-bit words, values packed in the fewest bits their range needs:
//!
//! ```text
//! packet   := kind:2                    0 = data; 1..3 reserved and refused
//!             has_hello:1
//!             hello?                    wire_version:u16, fingerprint:u128
//!             section_count:int[0, channels]
//!             section*                  at most one per channel
//! section  := channel:int[0, channels-1]
//!             message_count:int[1, max_messages_per_packet]
//!             reliable only: first_id:u16, then each later id as int_relative from the
//!                            previous one (never its absolute tier), all within one
//!                            channel window
//!             message*
//! message  := event:int[0, events-1]    must be an event of the section's channel
//!             length:int[0, channel_max_payload], at most the event's max payload
//!             align, payload[length]
//! trailer  := align (zero padding); nothing may follow
//! ```
//!
//! The hello precedes everything whose width depends on the schema, so a peer with a different
//! schema is recognized as a mismatch rather than parsed as garbage. The encoding is canonical:
//! [`decode`] refuses nonzero padding and trailing bytes, so every accepted packet re-encodes
//! to itself. `tests/wire_golden.rs` pins the bytes; changing them means bumping
//! [`WIRE_VERSION`].
//!
//! Writing goes through serialize's [`BitWriter`] (the trusted path). Reading goes through
//! serialize's [`BitReader`] behind a checked reader that refuses exactly what serialize's
//! `ReadStream` refuses, but can also hand out payloads as zero-copy slices of the packet:
//! received bytes are copied once, into their destination.

use core::fmt;

use serialize::{BitReader, BitWriter, bits_required};

use crate::id::{ChannelId, EventTypeId};
use crate::schema::{Delivery, Fingerprint, Schema};
use crate::sequence::Seq16;

/// The version of this wire format. Carried in every hello; part of the schema fingerprint.
pub const WIRE_VERSION: u16 = 2;

const KIND_BITS: u32 = 2;
const KIND_DATA: u32 = 0;
const HELLO_BITS: u64 = 16 + 128;

/// `int_relative` buckets after the one-bit fast path: `(threshold, min, max)`, exactly as
/// serialize defines them.
const RELATIVE_BUCKETS: [(u32, u32, u32); 5] = [
    (6, 2, 6),
    (23, 7, 23),
    (280, 24, 280),
    (4377, 281, 4377),
    (69914, 4378, 69914),
];

/// The handshake a packet carries until the remote acknowledges one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hello {
    /// The sender's [`WIRE_VERSION`].
    pub wire_version: u16,
    /// The sender's schema fingerprint.
    pub fingerprint: Fingerprint,
}

/// Per-channel wire facts.
#[derive(Debug, Clone, Copy)]
pub struct ChannelLayout {
    /// Whether the channel is reliable-ordered (and so carries message ids).
    pub reliable: bool,
    /// The channel capacity: for reliable channels, the id window.
    pub window: u16,
    /// Largest payload of any event on the channel.
    pub max_payload: u32,
    /// Bits of the length field.
    pub length_bits: u32,
}

/// Everything the codec needs from a schema, precomputed into flat tables.
#[derive(Debug, Clone)]
pub struct Layout {
    hello: Hello,
    channel_count: u32,
    max_messages: u32,
    event_count: u32,
    channel_bits: u32,
    section_count_bits: u32,
    count_bits: u32,
    event_bits: u32,
    channels: Vec<ChannelLayout>,
    event_channel: Vec<u8>,
    event_max_payload: Vec<u32>,
}

impl Layout {
    /// Precomputes the layout of `schema`.
    pub fn new(schema: &Schema) -> Self {
        let channel_count = schema.channels().len() as u32;
        let event_count = schema.events().len() as u32;
        let max_messages = schema.max_messages_per_packet();
        Self {
            hello: Hello {
                wire_version: WIRE_VERSION,
                fingerprint: schema.fingerprint(),
            },
            channel_count,
            max_messages,
            event_count,
            channel_bits: bits_required(0, channel_count.saturating_sub(1)),
            section_count_bits: bits_required(0, channel_count),
            count_bits: bits_required(1, max_messages),
            event_bits: bits_required(0, event_count.saturating_sub(1)),
            channels: schema
                .channels()
                .iter()
                .map(|c| ChannelLayout {
                    reliable: c.delivery() == Delivery::ReliableOrdered,
                    window: c.config.capacity,
                    max_payload: c.max_payload,
                    length_bits: bits_required(0, c.max_payload),
                })
                .collect(),
            event_channel: schema.events().iter().map(|e| e.channel.0).collect(),
            event_max_payload: schema.events().iter().map(|e| e.max_payload).collect(),
        }
    }

    /// The hello this layout's side sends.
    #[inline]
    pub fn hello(&self) -> Hello {
        self.hello
    }

    /// Per-channel wire facts.
    #[inline]
    pub fn channel(&self, channel: ChannelId) -> &ChannelLayout {
        &self.channels[usize::from(channel.0)]
    }

    /// The most messages one section may carry.
    #[inline]
    pub fn max_messages(&self) -> u32 {
        self.max_messages
    }

    /// Bits of a packet header, before any section.
    #[inline]
    pub fn header_bits(&self, hello: bool) -> u64 {
        u64::from(KIND_BITS + 1 + self.section_count_bits) + if hello { HELLO_BITS } else { 0 }
    }

    /// Bits of a section header, including a reliable section's first id.
    #[inline]
    pub fn section_bits(&self, channel: ChannelId) -> u64 {
        let reliable = self.channel(channel).reliable;
        u64::from(self.channel_bits + self.count_bits + if reliable { 16 } else { 0 })
    }

    /// An upper bound on the bits of one message with a `len`-byte payload on `channel`
    /// (alignment padding counted as its worst case, 7 bits).
    #[inline]
    pub fn message_bits(&self, channel: ChannelId, len: usize) -> u64 {
        u64::from(self.event_bits + self.channel(channel).length_bits + 7) + len as u64 * 8
    }

    /// The worst-case bytes of framing around a single message in its own packet (with a
    /// hello), so `max_packet_size - overhead` is the largest event payload that always fits.
    pub fn worst_case_single_message_overhead(&self) -> usize {
        let section = u64::from(self.channel_bits + self.count_bits + 16);
        let length_bits = self
            .channels
            .iter()
            .map(|c| c.length_bits)
            .max()
            .unwrap_or(0);
        let bits = self.header_bits(true) + section + u64::from(self.event_bits + length_bits + 7);
        bits.div_ceil(8) as usize
    }
}

/// Bits `int_relative` spends on a forward delta of `delta` (at least 1).
#[inline]
pub fn relative_bits(delta: u32) -> u64 {
    if delta == 1 {
        return 1;
    }
    let mut flags = 1;
    for (threshold, min, max) in RELATIVE_BUCKETS {
        flags += 1;
        if delta <= threshold {
            return u64::from(flags + bits_required(min, max));
        }
    }
    u64::from(flags + 32)
}

/// Writes one connection packet. The caller decides the section and message counts first
/// (they precede their contents on the wire) and then writes exactly that many.
///
/// This is the trusted write path: arguments are validated by the caller (the packet builder),
/// and violations are debug assertions.
#[derive(Debug)]
pub struct PacketWriter<'b> {
    w: BitWriter<'b>,
}

impl<'b> PacketWriter<'b> {
    /// Starts a packet in `buffer`, whose length must be a multiple of 8 and large enough for
    /// the packet plus one word.
    #[inline]
    pub fn new(buffer: &'b mut [u8]) -> Self {
        Self {
            w: BitWriter::new(buffer),
        }
    }

    #[inline]
    fn put(&mut self, value: u32, bits: u32) {
        if bits > 0 {
            self.w.write_bits(value, bits);
        }
    }

    /// Writes the packet header.
    #[inline]
    pub fn header(&mut self, layout: &Layout, hello: Option<Hello>, section_count: u32) {
        debug_assert!(section_count <= layout.channel_count);
        self.put(KIND_DATA, KIND_BITS);
        self.put(u32::from(hello.is_some()), 1);
        if let Some(hello) = hello {
            self.put(u32::from(hello.wire_version), 16);
            let fingerprint = hello.fingerprint.0;
            for word in 0..4 {
                self.put((fingerprint >> (32 * word)) as u32, 32);
            }
        }
        self.put(section_count, layout.section_count_bits);
    }

    /// Writes a section header (without a reliable section's first id).
    #[inline]
    pub fn section(&mut self, layout: &Layout, channel: ChannelId, message_count: u32) {
        debug_assert!(u32::from(channel.0) < layout.channel_count);
        debug_assert!((1..=layout.max_messages).contains(&message_count));
        self.put(u32::from(channel.0), layout.channel_bits);
        self.put(message_count - 1, layout.count_bits);
    }

    /// Writes a reliable section's first message id.
    #[inline]
    pub fn first_id(&mut self, id: Seq16) {
        self.put(u32::from(id.0), 16);
    }

    /// Writes a later message id as a forward delta (at least 1) from the previous id.
    #[inline]
    pub fn next_id(&mut self, delta: u32) {
        debug_assert!(delta >= 1);
        if delta == 1 {
            self.put(1, 1);
            return;
        }
        self.put(0, 1);
        for (threshold, min, max) in RELATIVE_BUCKETS {
            if delta <= threshold {
                self.put(1, 1);
                self.put(delta - min, bits_required(min, max));
                return;
            }
            self.put(0, 1);
        }
        // the absolute tier carries the unwrapped current value; the reader reconstructs it
        // against its own previous value, so this path is only for deltas past 69914, which a
        // window of at most 32768 never produces
        unreachable!("message id delta {delta} exceeds every relative bucket");
    }

    /// Writes one message.
    #[inline]
    pub fn message(&mut self, layout: &Layout, event: EventTypeId, payload: &[u8]) {
        let channel = layout.event_channel[event.0 as usize];
        let length_bits = layout.channels[usize::from(channel)].length_bits;
        debug_assert!(
            payload.len() as u64 <= u64::from(layout.event_max_payload[event.0 as usize])
        );
        self.put(event.0, layout.event_bits);
        self.put(payload.len() as u32, length_bits);
        self.w.write_align();
        self.w.write_bytes(payload);
    }

    /// Bits written so far.
    #[inline]
    pub fn bits(&self) -> u64 {
        self.w.bits_written()
    }

    /// Pads to a byte, flushes, and returns the packet length in bytes.
    #[inline]
    pub fn finish(mut self) -> usize {
        self.w.write_align();
        self.w.flush_bits();
        self.w.bytes_written() as usize
    }
}

/// Why a packet was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Malformed {
    /// A read would pass the end of the packet (including an empty packet).
    Truncated,
    /// The packet kind is reserved.
    ReservedKind,
    /// A field decoded outside its range.
    ValueOutOfRange,
    /// Two sections named the same channel.
    DuplicateChannel,
    /// A message's event belongs to a different channel than its section.
    EventOnWrongChannel,
    /// A payload exceeds its event's maximum.
    PayloadTooLarge,
    /// A reliable section's ids span more than the channel window.
    IdSpanExceedsWindow,
    /// Alignment padding held nonzero bits.
    NonzeroPadding,
    /// Bytes followed the last section.
    TrailingBytes,
    /// A value used an encoding dream-net never writes (serialize's absolute `int_relative`
    /// tier for a message id delta).
    NonCanonical,
    /// A packet without a hello arrived before the peer's hello was verified.
    MissingHello,
}

impl fmt::Display for Malformed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "truncated packet",
            Self::ReservedKind => "reserved packet kind",
            Self::ValueOutOfRange => "value out of range",
            Self::DuplicateChannel => "duplicate channel section",
            Self::EventOnWrongChannel => "event on the wrong channel",
            Self::PayloadTooLarge => "payload larger than its event allows",
            Self::IdSpanExceedsWindow => "message ids span more than the channel window",
            Self::NonzeroPadding => "nonzero padding",
            Self::TrailingBytes => "trailing bytes",
            Self::NonCanonical => "non-canonical encoding",
            Self::MissingHello => "data before the handshake",
        })
    }
}

/// Decoding stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// The packet is not valid wire format v2 for this schema.
    Malformed(Malformed),
    /// The packet carries a hello that does not match this side's wire version or schema.
    Mismatch(Hello),
}

impl From<Malformed> for DecodeError {
    #[inline]
    fn from(m: Malformed) -> Self {
        Self::Malformed(m)
    }
}

/// A decoded section: a run of `count` messages starting at `first` in
/// [`Decoded::messages`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Section {
    /// The channel.
    pub channel: ChannelId,
    /// Index of the section's first message.
    pub first: u32,
    /// Number of messages.
    pub count: u32,
}

/// A decoded message. The payload stays in the packet: see [`Message::payload`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Message {
    /// The event.
    pub event: EventTypeId,
    /// The message id (reliable sections only; zero otherwise).
    pub id: Seq16,
    /// Payload offset in the packet.
    pub offset: u32,
    /// Payload length.
    pub len: u32,
}

impl Message {
    /// The payload bytes, borrowed from the decoded packet.
    #[inline]
    pub fn payload<'p>(&self, packet: &'p [u8]) -> &'p [u8] {
        &packet[self.offset as usize..(self.offset + self.len) as usize]
    }
}

/// The result of [`decode`]. Reused across packets so decoding does not allocate once warm.
#[derive(Debug, Clone, Default)]
pub struct Decoded {
    /// The packet's hello, if it carried one.
    pub hello: Option<Hello>,
    /// Sections in wire order.
    pub sections: Vec<Section>,
    /// Messages of all sections, in wire order.
    pub messages: Vec<Message>,
}

impl Decoded {
    /// Clears the result for reuse.
    #[inline]
    pub fn clear(&mut self) {
        self.hello = None;
        self.sections.clear();
        self.messages.clear();
    }
}

struct Reader<'a> {
    r: BitReader<'a>,
}

impl Reader<'_> {
    #[inline]
    fn bits(&mut self, bits: u32) -> Result<u32, Malformed> {
        if bits == 0 {
            return Ok(0);
        }
        if self.r.would_read_past_end(bits) {
            return Err(Malformed::Truncated);
        }
        Ok(self.r.read_bits(bits))
    }

    #[inline]
    fn int(&mut self, min: u32, max: u32) -> Result<u32, Malformed> {
        let value = self.bits(bits_required(min, max))?;
        if value > max - min {
            return Err(Malformed::ValueOutOfRange);
        }
        Ok(value + min)
    }

    #[inline]
    fn align(&mut self) -> Result<(), Malformed> {
        let pad = self.r.align_bits();
        if pad != 0 {
            if self.r.would_read_past_end(pad) {
                return Err(Malformed::Truncated);
            }
            if !self.r.read_align() {
                return Err(Malformed::NonzeroPadding);
            }
        }
        Ok(())
    }

    #[inline]
    fn skip_bytes(&mut self, len: u32) -> Result<u32, Malformed> {
        if u64::from(len) * 8 > self.r.bits_remaining() {
            return Err(Malformed::Truncated);
        }
        let offset = (self.r.bits_read() / 8) as u32;
        let _ = self.r.read_byte_slice(len as usize);
        Ok(offset)
    }

    /// Mirrors serialize's `int_relative` read: the reconstructed value must be in
    /// `[0, i32::MAX]` and greater than `previous`.
    #[inline]
    fn relative(&mut self, previous: i32) -> Result<i32, Malformed> {
        let reconstructed = if self.bits(1)? == 1 {
            i64::from(previous) + 1
        } else {
            let mut value = None;
            for (_, min, max) in RELATIVE_BUCKETS {
                if self.bits(1)? == 1 {
                    value = Some(i64::from(previous) + i64::from(self.int(min, max)?));
                    break;
                }
            }
            // serialize's absolute tier (32 raw bits) can re-encode any delta a bucket already
            // covers. Ids in one section span less than a window (at most 32768), so a
            // canonical writer never reaches it: refusing it keeps every accepted packet
            // byte-identical to what dream-net would write
            match value {
                Some(value) => value,
                None => return Err(Malformed::NonCanonical),
            }
        };
        if !(0..=i64::from(i32::MAX)).contains(&reconstructed)
            || reconstructed <= i64::from(previous)
        {
            return Err(Malformed::ValueOutOfRange);
        }
        Ok(reconstructed as i32)
    }
}

/// Decodes `packet` against `layout` into `out` (cleared first).
///
/// A hello that does not match `layout` stops decoding with [`DecodeError::Mismatch`] before
/// anything schema-dependent is read. The whole packet is validated before this returns
/// `Ok`: a caller never acts on part of a malformed packet.
///
/// # Errors
///
/// [`DecodeError::Malformed`] for anything that is not canonical wire format v2 for this
/// schema, [`DecodeError::Mismatch`] for a foreign hello.
pub fn decode(layout: &Layout, packet: &[u8], out: &mut Decoded) -> Result<(), DecodeError> {
    out.clear();
    let mut r = Reader {
        r: BitReader::new(packet, packet.len()),
    };
    if r.bits(KIND_BITS)? != KIND_DATA {
        return Err(Malformed::ReservedKind.into());
    }
    if r.bits(1)? == 1 {
        let wire_version = r.bits(16)? as u16;
        let mut fingerprint = 0u128;
        for word in 0..4 {
            fingerprint |= u128::from(r.bits(32)?) << (32 * word);
        }
        let hello = Hello {
            wire_version,
            fingerprint: Fingerprint(fingerprint),
        };
        if hello != layout.hello {
            return Err(DecodeError::Mismatch(hello));
        }
        out.hello = Some(hello);
    }

    let section_count = r.int(0, layout.channel_count)?;
    let mut seen: u64 = 0;
    for _ in 0..section_count {
        let channel = r.int(0, layout.channel_count - 1)?;
        if seen & (1 << channel) != 0 {
            return Err(Malformed::DuplicateChannel.into());
        }
        seen |= 1 << channel;
        let count = r.int(1, layout.max_messages)?;
        let info = layout.channels[channel as usize];
        let first = out.messages.len() as u32;

        let mut first_id = 0i32;
        let mut previous = 0i32;
        if info.reliable {
            first_id = r.bits(16)? as i32;
            previous = first_id;
        }
        for index in 0..count {
            let mut id = Seq16::ZERO;
            if info.reliable {
                if index > 0 {
                    previous = r.relative(previous)?;
                    if previous - first_id >= i32::from(info.window) {
                        return Err(Malformed::IdSpanExceedsWindow.into());
                    }
                }
                id = Seq16(previous as u16);
            }
            if layout.event_count == 0 {
                return Err(Malformed::ValueOutOfRange.into());
            }
            let event = r.int(0, layout.event_count - 1)?;
            if u32::from(layout.event_channel[event as usize]) != channel {
                return Err(Malformed::EventOnWrongChannel.into());
            }
            let len = r.int(0, info.max_payload)?;
            if len > layout.event_max_payload[event as usize] {
                return Err(Malformed::PayloadTooLarge.into());
            }
            r.align()?;
            let offset = r.skip_bytes(len)?;
            out.messages.push(Message {
                event: EventTypeId(event),
                id,
                offset,
                len,
            });
        }
        out.sections.push(Section {
            channel: ChannelId(channel as u8),
            first,
            count,
        });
    }

    r.align()?;
    if r.r.bits_remaining() != 0 {
        return Err(Malformed::TrailingBytes.into());
    }
    Ok(())
}
