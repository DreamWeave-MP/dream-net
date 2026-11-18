//! Packet acknowledgement, fragmentation and link statistics: a safe wrapper over the vendored
//! C [reliable](https://github.com/mas-bandwidth/reliable) (v1.4.6).
//!
//! The API mirrors the subset of the `reliable` 1.3.4 Rust port that dream-net calls, with the
//! same names and, wherever the C allows, the same signatures, so moving dream-net over is a
//! change of import. reliable handles packet-level mechanics only; message reliability,
//! ordering and channels stay in dream-net.
//!
//! ```
//! use dream_net_native::reliable::{Config, Endpoint};
//!
//! let mut a = Endpoint::new(Config::default(), 0.0).unwrap();
//! let mut b = Endpoint::new(Config::default(), 0.0).unwrap();
//! let mut delivered = Vec::new();
//! a.send_packet(&[1, 2, 3], |_sequence, datagram| {
//!     b.receive_packet(datagram, |_sequence, packet| {
//!         delivered.extend_from_slice(packet);
//!         true
//!     });
//! });
//! assert_eq!(delivered, [1, 2, 3]);
//! ```
//!
//! # Differences from the `reliable` 1.3.4 Rust port
//!
//! None of these changes a byte on the wire (the crate's interop tests compare both
//! implementations datagram for datagram).
//!
//! - [`Endpoint::new`] returns `Result<Endpoint, ConfigError>` instead of panicking, and the C
//!   refuses more configs than the port asserted on: windows above [`MAX_SEQUENCE_BUFFER_SIZE`]
//!   (16384), `fragment_above > max_packet_size`, fragments that do not cover
//!   `max_packet_size`, sizes that do not fit a C `int`, smoothing factors outside `[0, 1]`.
//!   [`Config::validate`] checks all of it up front. Names longer than 255 bytes or containing
//!   NUL are refused.
//! - Sequence windows (`sent_packets_buffer_size`, `received_packets_buffer_size`,
//!   `fragment_reassembly_buffer_size`) are rounded up to a power of two by C. The port used
//!   them as given. Identical for powers of two.
//! - [`Endpoint::send_packet`] with an empty packet is a no-op (the port panicked).
//!   [`Endpoint::receive_packet`] with an empty datagram counts it `num_packets_invalid` (the
//!   port panicked).
//! - [`Endpoint::update`] ignores a non-finite or backwards time (keeps the last one). The port
//!   stored any time. [`Endpoint::new`] treats a non-finite start time as `0.0`.
//! - [`Endpoint::reset`] also clears the rtt, jitter, packet loss and bandwidth statistics.
//! - [`Endpoint::rtt_min`] reports the true minimum on links slower than 10 s (the port's
//!   sentinel reported 0); a negative rtt sample (impossible with non-decreasing time) is
//!   clamped to 0 instead of a debug assertion.
//! - A fragment that cannot be stored is counted `num_fragments_invalid`, not received
//!   (unreachable after header validation in both).
//! - [`Endpoint::drain_acks`] returns a named iterator, [`DrainAcks`], that clears the acks when
//!   dropped. [`Counters`] is also `Copy` and `Hash`.
//! - Added: [`Endpoint::memory_usage`] (an upper bound of the endpoint's heap),
//!   [`Endpoint::allocated_bytes`] (what it holds now) and the limit constants.
//! - Logging: C's log level is NONE and its printf hook discards (process-wide, set once by
//!   this crate); the port logged through the `log` facade.
//!
//! # Callbacks
//!
//! C calls `transmit_packet_function` and `process_packet_function` synchronously inside
//! `reliable_endpoint_send_packet` (once per regular packet, once per fragment) and
//! `reliable_endpoint_receive_packet` (at most once: for a regular packet, or for the packet a
//! fragment completes). C keeps neither packet pointer after the callback returns. The wrapper:
//!
//! - stores a pointer to the caller's closure (on the caller's stack) in the endpoint's
//!   context immediately before the C call and clears it immediately after, so a callback
//!   reaches a closure only during the call that owns it, the context never dangles, and a
//!   callback arriving at any other time (or of the other kind) is a no-op that rejects;
//! - hands the closure a slice valid only for that callback (the closure is higher-ranked, so
//!   it cannot keep it);
//! - holds `&mut self` for the whole call, so the closure cannot re-enter the same endpoint
//!   (C's "must not send packets on the same endpoint"); it may drive other endpoints;
//! - catches a panic in the closure inside the callback (never unwinding through C), rejects
//!   the packet (process) or skips the rest of the send's callbacks (transmit), lets the C call
//!   finish, clears the context, and then resumes the panic. The endpoint stays consistent and
//!   usable: see the `# Panics` sections of [`Endpoint::send_packet`] and
//!   [`Endpoint::receive_packet`].
//!
//! No allocation, boxing or dynamic dispatch happens per call. Compared with the Rust port the
//! FFI adds no copy: C frames the packet into its transmit buffer (one copy, as the port did)
//! and hands unfragmented received payloads to `process` in place.
//!
//! # Memory
//!
//! C allocates through hooks that call Rust's global allocator (a counting global allocator
//! sees reliable's memory) and count this endpoint's bytes. After creation only fragment
//! reassembly allocates: at most one buffer of `9 + num_fragments * fragment_size + 8` bytes
//! per reassembly slot, freed when completed, superseded, reset or dropped.
//! [`Endpoint::memory_usage`] is the resulting bound.
//!
//! # C preconditions and where they are enforced
//!
//! The C is compiled with `NDEBUG`/`RELIABLE_RELEASE`, so `reliable_assert` is a no-op; every
//! assertion of a function called here is either guaranteed by the wrapper or followed by a real
//! check in C. `reliable.c` lines at the v1.4.6 pin.
//!
//! | C function | Assertion | Enforcement |
//! | --- | --- | --- |
//! | `reliable_endpoint_create` | `reliable_config_valid` (real checks, :588) | [`Config::validate`] first, then C; NULL is [`ConfigError::CreateFailed`] |
//! | `reliable_sequence_buffer_create` | `num_entries > 0`, `entry_stride > 0` (:189-190) | validated non-zero; strides are C constants |
//! | `reliable_endpoint_send_packet` | `endpoint`, `packet_data` non-null, `packet_bytes > 0` (:979-981) | handle is always live; slice pointers are never null; empty sends return before C |
//! | (same) | `packet_bytes <= max_packet_size` | a real check (:983): counted too large; the wrapper passes `max_packet_size + 1` for any longer slice |
//! | (same) | `sent_packet_data` non-null (:1001) | `endpoint->sequence` and the sent window's sequence advance together, so the insert is never stale |
//! | (same) | `1 <= num_fragments <= max_fragments` (:1035-1036) | validated: `max_fragments * fragment_size` covers `max_packet_size` |
//! | (same) | header bytes `<= 9` (:972) | by construction of the header writer |
//! | `reliable_endpoint_receive_packet` | `endpoint`, `packet_data` non-null (:1325-1326) | live handle, non-null slice pointer (not read when the length is 0) |
//! | (same) | `packet_header_bytes <= packet_bytes` (:1362) | established by the explicit length checks of `reliable_read_packet_header` (:1084-1135) |
//! | (same) | `received_packet_data` non-null (:1403) | the stale check just before (:1374) and nothing between can move the window (`&mut self`) |
//! | (same) | `packet_bytes` fits `int` | the wrapper passes at most `max_packet_size + 15 <= INT_MAX` (validated), which C counts too large before reading |
//! | `reliable_endpoint_get_acks`, `_clear_acks`, `_reset`, `_update`, getters, `_destroy` | `endpoint` (and out-pointers) non-null | live handle; out-pointers are Rust locals |
//! | `reliable_sequence_buffer_at_index` | `0 <= index < num_entries` | loops bounded by `num_entries` in C |
//!
//! Remote input reaches only real checks. Every hostile case is refused by an explicit `if`
//! and counted: a datagram longer than `max_packet_size + 14` (:1334), a short or truncated
//! header (:1084-1135, fragments :1178), a fragment header with `num_fragments > max_fragments` (:1197) or
//! `fragment_id >= num_fragments` (:1203), a fragment-0 packet header with the wrong sequence
//! (:1230) or not canonical (:1241), a fragment larger than `fragment_size` (:1253) or a
//! non-final fragment of another size (:1259), a count mismatch with the reassembly in
//! progress (:1547), a duplicate fragment (:1555), a write past the reassembly buffer (:1307),
//! a stale reassembly (:1506-1513), a failed allocation (:1525), a stale packet (:1374), a duplicate
//! packet (:1381), and acks for sequences never sent or already acked (:1418), at most 32
//! per packet and at most `ack_buffer_size` buffered (:1420). Sequence comparisons are
//! half-space and wrap-correct. No bound on remote input was found to rest on an assertion
//! alone.
//!
//! # Threads
//!
//! [`Endpoint`] is `Send + Sync + Unpin + UnwindSafe + RefUnwindSafe`. The C endpoint has no
//! thread affinity or thread-local state, every `&self` method is a pure read, and all
//! mutation goes through `&mut self` (the justification is at the `unsafe impl`s).

mod config;
mod endpoint;

pub use config::{
    Config, ConfigError, MAX_FRAGMENTS, MAX_NAME_BYTES, MAX_PACKET_SIZE, MAX_SEQUENCE_BUFFER_SIZE,
};
pub use endpoint::{Bandwidth, Counters, DrainAcks, Endpoint};

/// The maximum size of a packet header in bytes (`RELIABLE_MAX_PACKET_HEADER_BYTES`).
pub const MAX_PACKET_HEADER_BYTES: usize = 9;

/// The size of a fragment header in bytes (`RELIABLE_FRAGMENT_HEADER_BYTES`).
pub const FRAGMENT_HEADER_BYTES: usize = 5;

/// Returns true if sequence number `s1` is greater than `s2`, taking wrap-around into account:
/// `s1` is ahead of `s2` by 1 to 32768 steps. The same half-space comparison as the C library
/// and the Rust port.
#[inline]
pub const fn sequence_greater_than(s1: u16, s2: u16) -> bool {
    ((s1 > s2) && (s1 - s2 <= 32768)) || ((s1 < s2) && (s2 - s1 > 32768))
}

/// Returns true if sequence number `s1` is less than `s2`, taking wrap-around into account.
#[inline]
pub const fn sequence_less_than(s1: u16, s2: u16) -> bool {
    sequence_greater_than(s2, s1)
}
