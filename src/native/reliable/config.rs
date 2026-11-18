//! [`Config`] and its validation.

use core::ffi::c_int;
use core::fmt;

use super::{FRAGMENT_HEADER_BYTES, MAX_PACKET_HEADER_BYTES};
use crate::native::sys::reliable::Params;

/// Largest `sent_packets_buffer_size`, `received_packets_buffer_size` and
/// `fragment_reassembly_buffer_size` the C library accepts (`RELIABLE_MAX_SEQUENCE_BUFFER_SIZE`).
pub const MAX_SEQUENCE_BUFFER_SIZE: usize = 16384;

/// Largest [`Config::max_fragments`] (fragment ids are one byte on the wire).
pub const MAX_FRAGMENTS: usize = 256;

/// Longest [`Config::name`] in bytes: the C config stores it in `char[256]` with a terminator.
pub const MAX_NAME_BYTES: usize = 255;

/// `INT_MAX` as a `usize`.
const INT_MAX: usize = c_int::MAX as usize;

/// Largest [`Config::max_packet_size`] this wrapper accepts: one below what C accepts
/// (`INT_MAX - 14`), so that "one byte more than the receive limit" is always an `int` the
/// wrapper can hand C to have an oversized datagram counted (see
/// [`Endpoint::receive_packet`](super::Endpoint::receive_packet)).
pub const MAX_PACKET_SIZE: usize = INT_MAX - MAX_PACKET_HEADER_BYTES - FRAGMENT_HEADER_BYTES - 1;

/// Configuration for an [`Endpoint`](super::Endpoint).
///
/// The same public fields and defaults as the `reliable` 1.3.4 Rust port (and the C library's
/// `reliable_default_config`). [`Config::default`] returns sensible defaults for a
/// client/server game exchanging packets at 60 Hz. [`Config::validate`] says whether the C
/// library will accept it.
#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    /// Name of the endpoint, at most [`MAX_NAME_BYTES`] bytes and without NUL. Only used in
    /// the C library's log output, which dream-net keeps silent.
    pub name: String,
    /// Maximum packet size that can be sent or received (bytes).
    pub max_packet_size: usize,
    /// Packets larger than this many bytes are sent as fragments.
    pub fragment_above: usize,
    /// Maximum number of fragments per-packet, at most [`MAX_FRAGMENTS`]. Must cover
    /// `max_packet_size / fragment_size`.
    pub max_fragments: usize,
    /// Size of each fragment (bytes).
    pub fragment_size: usize,
    /// Maximum number of acks buffered between calls to [`Endpoint::clear_acks`](super::Endpoint::clear_acks).
    pub ack_buffer_size: usize,
    /// Number of sent packets tracked for acks, packet loss and bandwidth stats. At most
    /// [`MAX_SEQUENCE_BUFFER_SIZE`]; rounded up to a power of two by C.
    pub sent_packets_buffer_size: usize,
    /// Number of received packets tracked. Also the window for stale and duplicate packet
    /// rejection. At most [`MAX_SEQUENCE_BUFFER_SIZE`]; rounded up to a power of two by C.
    pub received_packets_buffer_size: usize,
    /// Number of packets that can be under reassembly from fragments at the same time. At
    /// most [`MAX_SEQUENCE_BUFFER_SIZE`]; rounded up to a power of two by C, which can double
    /// the reassembly memory bound ([`Endpoint::memory_usage`](super::Endpoint::memory_usage)).
    pub fragment_reassembly_buffer_size: usize,
    /// Exponential smoothing factor for the rtt moving average, in `[0, 1]`.
    pub rtt_smoothing_factor: f32,
    /// Number of rtt samples kept for min/max/avg rtt and jitter.
    pub rtt_history_size: usize,
    /// Exponential smoothing factor for packet loss, in `[0, 1]`.
    pub packet_loss_smoothing_factor: f32,
    /// Exponential smoothing factor for bandwidth, in `[0, 1]`.
    pub bandwidth_smoothing_factor: f32,
    /// Assumed network header overhead per-packet, used only for bandwidth stats. 28 = IPv4 + UDP.
    pub packet_header_size: usize,
}

impl Default for Config {
    /// `reliable_default_config` and the Rust port's `Config::default`.
    fn default() -> Self {
        Self {
            name: "endpoint".to_owned(),
            max_packet_size: 16 * 1024,
            fragment_above: 1024,
            max_fragments: 16,
            fragment_size: 1024,
            ack_buffer_size: 256,
            sent_packets_buffer_size: 256,
            received_packets_buffer_size: 256,
            fragment_reassembly_buffer_size: 64,
            rtt_smoothing_factor: 0.0025,
            rtt_history_size: 512,
            packet_loss_smoothing_factor: 0.1,
            bandwidth_smoothing_factor: 0.1,
            packet_header_size: 28,
        }
    }
}

/// Why a [`Config`] was refused, or why an [`Endpoint`](super::Endpoint) could not be created.
///
/// Every refusal of the C library's `reliable_config_valid` and `reliable_endpoint_create` has a
/// variant here, checked in the same order, plus the wrapper's own limits (the name, `int`
/// ranges, and [`MAX_PACKET_SIZE`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigError {
    /// `name` is longer than [`MAX_NAME_BYTES`] bytes. Refused rather than truncated, so that
    /// [`Endpoint::config`](super::Endpoint::config) is exactly what C holds.
    NameTooLong,
    /// `name` contains a NUL byte, which C would read as its end.
    NameContainsNul,
    /// The named field does not fit a C `int`.
    NotAnInt(&'static str),
    /// The named size is zero; it must be positive.
    Zero(&'static str),
    /// `max_fragments` is above [`MAX_FRAGMENTS`].
    TooManyFragments,
    /// The named window is above [`MAX_SEQUENCE_BUFFER_SIZE`].
    WindowTooLarge(&'static str),
    /// `fragment_above` is above `max_packet_size`.
    FragmentAboveExceedsMaxPacketSize,
    /// `max_fragments * fragment_size` does not cover `max_packet_size`.
    FragmentsDoNotCoverMaxPacketSize,
    /// `max_fragments * fragment_size` plus a packet header does not fit a C `int`.
    ReassemblyTooLarge,
    /// `max_packet_size` is above [`MAX_PACKET_SIZE`].
    MaxPacketSizeTooLarge,
    /// `fragment_size` plus both headers does not fit a C `int`.
    FragmentSizeTooLarge,
    /// `packet_header_size + max_packet_size` plus both headers does not fit a C `int`.
    PacketHeaderSizeTooLarge,
    /// A buffer of the named size cannot be allocated: its byte size overflows.
    BufferTooLarge(&'static str),
    /// The named smoothing factor is NaN or outside `[0, 1]`.
    SmoothingFactorOutOfRange(&'static str),
    /// The C library refused a config [`Config::validate`] accepted, or could not allocate the
    /// endpoint. With a valid config this means the allocator returned null.
    CreateFailed,
    /// The native libraries failed to initialise for this process.
    InitFailed,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NameTooLong => write!(f, "reliable name is longer than {MAX_NAME_BYTES} bytes"),
            Self::NameContainsNul => f.write_str("reliable name contains a NUL byte"),
            Self::NotAnInt(field) => write!(f, "reliable {field} does not fit a C int"),
            Self::Zero(field) => write!(f, "reliable {field} must be positive"),
            Self::TooManyFragments => {
                write!(f, "reliable max_fragments must be at most {MAX_FRAGMENTS}")
            }
            Self::WindowTooLarge(field) => {
                write!(f, "reliable {field} must be at most {MAX_SEQUENCE_BUFFER_SIZE}")
            }
            Self::FragmentAboveExceedsMaxPacketSize => {
                f.write_str("reliable fragment_above is above max_packet_size")
            }
            Self::FragmentsDoNotCoverMaxPacketSize => {
                f.write_str("reliable max_fragments * fragment_size does not cover max_packet_size")
            }
            Self::ReassemblyTooLarge => {
                f.write_str("reliable max_fragments * fragment_size does not fit a packet length")
            }
            Self::MaxPacketSizeTooLarge => {
                write!(f, "reliable max_packet_size must be at most {MAX_PACKET_SIZE}")
            }
            Self::FragmentSizeTooLarge => {
                f.write_str("reliable fragment_size plus headers does not fit a C int")
            }
            Self::PacketHeaderSizeTooLarge => f.write_str(
                "reliable packet_header_size plus max_packet_size does not fit a received packet length",
            ),
            Self::BufferTooLarge(field) => {
                write!(f, "reliable {field} is too large to allocate")
            }
            Self::SmoothingFactorOutOfRange(field) => {
                write!(f, "reliable {field} must be between 0 and 1")
            }
            Self::CreateFailed => f.write_str("reliable endpoint could not be created"),
            Self::InitFailed => f.write_str("the native libraries failed to initialise"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Bytes an allocation of `count` elements of `element` bytes costs, header included, if it is
/// representable as a Rust allocation.
fn allocation_fits(count: usize, element: usize) -> bool {
    count
        .checked_mul(element)
        .and_then(|bytes| bytes.checked_add(super::endpoint::ALLOCATION_HEADER))
        .is_some_and(|bytes| bytes <= isize::MAX.cast_unsigned())
}

fn int(value: usize, field: &'static str) -> Result<c_int, ConfigError> {
    c_int::try_from(value).map_err(|_| ConfigError::NotAnInt(field))
}

fn smoothing(value: f32, field: &'static str) -> Result<(), ConfigError> {
    // written so that NaN is refused, as C's negated range test does
    if (0.0..=1.0).contains(&value) {
        Ok(())
    } else {
        Err(ConfigError::SmoothingFactorOutOfRange(field))
    }
}

impl Config {
    /// Checks that the C library will accept this config, without creating anything.
    ///
    /// Refuses everything `reliable_config_valid` and `reliable_endpoint_create` refuse, in the
    /// same order, so the error names the first problem C would have found: zero sizes,
    /// `max_fragments` above 256, windows above [`MAX_SEQUENCE_BUFFER_SIZE`], `fragment_above`
    /// above `max_packet_size`, fragments that do not cover `max_packet_size`, sizes whose sums
    /// overflow a C `int`, and smoothing factors that are NaN or outside `[0, 1]`. Additionally
    /// refuses a name C could not hold, any size that does not fit a C `int`, and
    /// `max_packet_size == INT_MAX - 14` (see [`MAX_PACKET_SIZE`]). Every config this accepts is
    /// accepted by the C library (a property the crate's tests check against it).
    ///
    /// # Errors
    ///
    /// The first problem found, as a [`ConfigError`].
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.params().map(|_| ())
    }

    /// Validates and converts the scalar fields for the shim.
    #[allow(clippy::too_many_lines)] // one flat list of C's checks, in C's order
    pub(crate) fn params(&self) -> Result<Params, ConfigError> {
        if self.name.len() > MAX_NAME_BYTES {
            return Err(ConfigError::NameTooLong);
        }
        if self.name.as_bytes().contains(&0) {
            return Err(ConfigError::NameContainsNul);
        }
        let params = Params {
            max_packet_size: int(self.max_packet_size, "max_packet_size")?,
            fragment_above: int(self.fragment_above, "fragment_above")?,
            max_fragments: int(self.max_fragments, "max_fragments")?,
            fragment_size: int(self.fragment_size, "fragment_size")?,
            ack_buffer_size: int(self.ack_buffer_size, "ack_buffer_size")?,
            sent_packets_buffer_size: int(
                self.sent_packets_buffer_size,
                "sent_packets_buffer_size",
            )?,
            received_packets_buffer_size: int(
                self.received_packets_buffer_size,
                "received_packets_buffer_size",
            )?,
            fragment_reassembly_buffer_size: int(
                self.fragment_reassembly_buffer_size,
                "fragment_reassembly_buffer_size",
            )?,
            rtt_history_size: int(self.rtt_history_size, "rtt_history_size")?,
            packet_header_size: int(self.packet_header_size, "packet_header_size")?,
            rtt_smoothing_factor: self.rtt_smoothing_factor,
            packet_loss_smoothing_factor: self.packet_loss_smoothing_factor,
            bandwidth_smoothing_factor: self.bandwidth_smoothing_factor,
        };

        // reliable_config_valid, in its order (reliable.c:588-722)
        for (value, field) in [
            (self.max_packet_size, "max_packet_size"),
            (self.fragment_above, "fragment_above"),
            (self.fragment_size, "fragment_size"),
            (self.max_fragments, "max_fragments"),
        ] {
            if value == 0 {
                return Err(ConfigError::Zero(field));
            }
        }
        if self.max_fragments > MAX_FRAGMENTS {
            return Err(ConfigError::TooManyFragments);
        }
        for (value, field) in [
            (self.ack_buffer_size, "ack_buffer_size"),
            (self.sent_packets_buffer_size, "sent_packets_buffer_size"),
            (
                self.received_packets_buffer_size,
                "received_packets_buffer_size",
            ),
            (
                self.fragment_reassembly_buffer_size,
                "fragment_reassembly_buffer_size",
            ),
            (self.rtt_history_size, "rtt_history_size"),
        ] {
            if value == 0 {
                return Err(ConfigError::Zero(field));
            }
        }
        for (value, field) in [
            (self.sent_packets_buffer_size, "sent_packets_buffer_size"),
            (
                self.received_packets_buffer_size,
                "received_packets_buffer_size",
            ),
            (
                self.fragment_reassembly_buffer_size,
                "fragment_reassembly_buffer_size",
            ),
        ] {
            if value > MAX_SEQUENCE_BUFFER_SIZE {
                return Err(ConfigError::WindowTooLarge(field));
            }
        }
        if self.fragment_above > self.max_packet_size {
            return Err(ConfigError::FragmentAboveExceedsMaxPacketSize);
        }
        if self.max_fragments <= (self.max_packet_size - 1) / self.fragment_size {
            return Err(ConfigError::FragmentsDoNotCoverMaxPacketSize);
        }
        // both at most INT_MAX, so the product fits a u64 on every target
        if self.max_fragments as u64 * self.fragment_size as u64
            > (INT_MAX - MAX_PACKET_HEADER_BYTES) as u64
        {
            return Err(ConfigError::ReassemblyTooLarge);
        }
        if self.max_packet_size > MAX_PACKET_SIZE {
            return Err(ConfigError::MaxPacketSizeTooLarge);
        }
        if self.packet_header_size as u64
            + self.max_packet_size as u64
            + (MAX_PACKET_HEADER_BYTES + FRAGMENT_HEADER_BYTES) as u64
            > INT_MAX as u64
        {
            return Err(ConfigError::PacketHeaderSizeTooLarge);
        }
        smoothing(self.rtt_smoothing_factor, "rtt_smoothing_factor")?;
        smoothing(
            self.packet_loss_smoothing_factor,
            "packet_loss_smoothing_factor",
        )?;
        smoothing(
            self.bandwidth_smoothing_factor,
            "bandwidth_smoothing_factor",
        )?;

        // reliable_endpoint_create's own refusals (reliable.c:724-767): the acks and rtt history
        // allocations, and the fragment transmit buffer size
        if !allocation_fits(self.ack_buffer_size, size_of::<u16>()) {
            return Err(ConfigError::BufferTooLarge("ack_buffer_size"));
        }
        if !allocation_fits(self.rtt_history_size, size_of::<f32>()) {
            return Err(ConfigError::BufferTooLarge("rtt_history_size"));
        }
        if self.fragment_size > INT_MAX - FRAGMENT_HEADER_BYTES - MAX_PACKET_HEADER_BYTES {
            return Err(ConfigError::FragmentSizeTooLarge);
        }
        Ok(params)
    }
}
