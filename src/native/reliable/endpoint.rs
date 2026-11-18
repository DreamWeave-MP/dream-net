//! [`Endpoint`]: one C `reliable_endpoint_t` behind a safe, owning handle.

use core::ffi::{c_int, c_void};
use core::fmt;
use core::mem::{align_of, offset_of, size_of};
use core::ptr::{self, NonNull};
use std::alloc::{Layout, alloc, dealloc};
use std::any::Any;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

use super::config::{Config, ConfigError};
use super::{FRAGMENT_HEADER_BYTES, MAX_PACKET_HEADER_BYTES};
use crate::native::sys::reliable as sys;
use crate::native::sys::reliable::RawEndpoint;

/// Bytes the allocator hook puts in front of every block it hands C, to remember the block's
/// size for `free`. 16 keeps the block as aligned as `malloc`'s.
pub(crate) const ALLOCATION_HEADER: usize = 16;
const ALLOCATION_ALIGN: usize = 16;

/// Extra bytes `reliable_endpoint_receive_packet` adds to every reassembly buffer
/// (`reliable.c:1517`: `RELIABLE_MAX_PACKET_HEADER_BYTES + num_fragments * fragment_size + 8`).
const REASSEMBLY_SLACK: usize = 8;

/// Counters tracked by an [`Endpoint`], in the C library's `RELIABLE_ENDPOINT_COUNTER_*` order.
///
/// The same 11 fields as the `reliable` 1.3.4 Rust port. [`Endpoint::counters`] returns a
/// reference straight into the C endpoint's `uint64_t[11]` array, which this `repr(C)` struct
/// matches field for field (pinned by `const` assertions here and `_Static_assert`s in the shim).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Counters {
    /// Packets sent through the endpoint (a fragmented packet counts once).
    pub num_packets_sent: u64,
    /// Regular packets received, including invalid, stale and duplicate ones, and each
    /// completed reassembly.
    pub num_packets_received: u64,
    /// Sent packets acked by the other side.
    pub num_packets_acked: u64,
    /// Received packets dropped because they fell outside the receive window.
    pub num_packets_stale: u64,
    /// Received packets dropped because they were empty or their header could not be read.
    pub num_packets_invalid: u64,
    /// Packets refused by [`Endpoint::send_packet`] for exceeding [`Config::max_packet_size`].
    pub num_packets_too_large_to_send: u64,
    /// Received packets dropped for exceeding [`Config::max_packet_size`].
    pub num_packets_too_large_to_receive: u64,
    /// Fragments sent.
    pub num_fragments_sent: u64,
    /// Fragments received and stored for reassembly.
    pub num_fragments_received: u64,
    /// Fragments dropped: invalid header, count mismatch, unstorable, stale, or no memory.
    pub num_fragments_invalid: u64,
    /// Received packets dropped because a packet with the same sequence number was already
    /// received.
    pub num_packets_duplicate: u64,
}

const _: () = {
    assert!(size_of::<Counters>() == 11 * size_of::<u64>());
    assert!(align_of::<Counters>() == align_of::<u64>());
    assert!(offset_of!(Counters, num_packets_sent) == 0);
    assert!(offset_of!(Counters, num_packets_received) == 8);
    assert!(offset_of!(Counters, num_packets_acked) == 2 * 8);
    assert!(offset_of!(Counters, num_packets_stale) == 3 * 8);
    assert!(offset_of!(Counters, num_packets_invalid) == 4 * 8);
    assert!(offset_of!(Counters, num_packets_too_large_to_send) == 5 * 8);
    assert!(offset_of!(Counters, num_packets_too_large_to_receive) == 6 * 8);
    assert!(offset_of!(Counters, num_fragments_sent) == 7 * 8);
    assert!(offset_of!(Counters, num_fragments_received) == 8 * 8);
    assert!(offset_of!(Counters, num_fragments_invalid) == 9 * 8);
    assert!(offset_of!(Counters, num_packets_duplicate) == 10 * 8);
};

/// Bandwidth statistics, in kilobits per second.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Bandwidth {
    /// Outgoing bandwidth over the sent packet window.
    pub sent_kbps: f32,
    /// Incoming bandwidth over the received packet window.
    pub received_kbps: f32,
    /// Outgoing bandwidth restricted to packets that were acked.
    pub acked_kbps: f32,
}

/// Which callback a [`Call`] serves. A callback of the other kind is a no-op.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Transmit,
    Process,
}

/// Monomorphised entry into the closure of the call in progress.
type Invoke = unsafe fn(*mut c_void, u16, &[u8]) -> bool;

/// The closure of the one C call in progress, type-erased.
#[derive(Clone, Copy)]
struct Call {
    kind: Kind,
    /// A `*mut Frame<F>` on the stack of `send_packet` or `receive_packet`.
    frame: *mut c_void,
    /// `invoke_transmit::<F>` or `invoke_process::<F>` for that `F`.
    invoke: Invoke,
}

/// The per-endpoint state C hands back to the callbacks and allocator hooks as their context.
///
/// Heap-allocated so its address is stable for the endpoint's life (C stores it at create).
/// Only ever accessed through raw pointers (never a long-lived reference), and only written
/// during a C call made under `&mut Endpoint` (or create and destroy), so a `&Endpoint` read of
/// `live_bytes` never races a write.
struct Context {
    /// Bytes (headers included) currently allocated through [`allocate`] for this endpoint.
    live_bytes: usize,
    /// Set immediately before a send or receive call and cleared immediately after it, so a
    /// callback can reach a closure only during the call that owns it, and never dangles.
    call: Option<Call>,
}

/// The stack frame a [`Call`] points at: the caller's closure, and the panic it raised, if any.
struct Frame<F> {
    closure: F,
    panic: Option<Box<dyn Any + Send>>,
}

/// A reliable endpoint: packet acknowledgement, fragmentation and reassembly, and link
/// statistics for one connection, over the vendored C `reliable`.
///
/// One endpoint per connection: a client has one, a server has one per client slot. Every
/// mutating operation takes `&mut self`, so the borrow checker enforces the C library's rules
/// that an endpoint is not used concurrently and that a callback never re-enters its own
/// endpoint. See the [module documentation](super) for the differences from the `reliable`
/// 1.3.4 Rust port.
pub struct Endpoint {
    raw: NonNull<RawEndpoint>,
    context: NonNull<Context>,
    config: Config,
    /// The time last handed to C (create or update): finite and non-decreasing.
    time: f64,
    /// Bytes C allocated in `reliable_endpoint_create`; nothing but reassembly allocates later.
    created_bytes: usize,
    /// Most bytes all reassembly buffers can hold at once.
    reassembly_bound: usize,
}

// SAFETY: (justified against reliable.c at the pin, read in full for the functions called here)
// - The C endpoint has no thread affinity: no thread-local storage, no thread ids, no locks.
//   The only process-global state its functions touch is the log level, printf hook and
//   assert hook, read by reliable_printf and written only by dn_native_hooks_install, once,
//   inside `sys::ensure_init`'s OnceLock before any endpoint exists (so every later read
//   happens-after the write, on any thread).
// - Its memory comes from `allocate`/`free` below, which call Rust's global allocator (thread
//   agnostic by `GlobalAlloc`'s contract) and update this endpoint's own `Context`.
// - The callbacks run synchronously on the calling thread, inside the C call, and reach only
//   the closure of that call.
// So moving the handle to another thread and using it there is the same as using it here.
unsafe impl Send for Endpoint {}

// SAFETY: every `&self` method is a pure read: the getters `reliable_endpoint_rtt`,
// `_rtt_min`, `_rtt_max`, `_rtt_avg`, `_jitter_*`, `_packet_loss`, `_bandwidth`,
// `_next_packet_sequence`, `_get_acks` and `_counters` only load fields of the endpoint
// (reliable.c, getters section) and write nothing but their out-parameters, which are Rust
// locals; `memory_usage`/`allocated_bytes`/`config` read Rust state. C writes the endpoint, its
// buffers and the `Context` only inside calls made through `&mut self` (send, receive, update,
// clear_acks, reset) or in `new`/`drop`, which the borrow checker keeps from overlapping any
// `&self` access. So shared references on several threads only ever read concurrently.
unsafe impl Sync for Endpoint {}

impl Endpoint {
    /// Creates an endpoint with the given config, starting at `time` (seconds).
    ///
    /// Fallible where the Rust port asserted: the C library refuses more configs than the port
    /// did (see [`Config::validate`]), and returns NULL rather than panicking. A non-finite
    /// `time` is treated as `0.0`.
    ///
    /// # Errors
    ///
    /// The [`ConfigError`] of [`Config::validate`]; [`ConfigError::CreateFailed`] if the
    /// allocator returned null; [`ConfigError::InitFailed`] if the native libraries could not
    /// be initialised.
    pub fn new(config: Config, time: f64) -> Result<Self, ConfigError> {
        let params = config.params()?;
        if !crate::native::sys::ensure_init() {
            return Err(ConfigError::InitFailed);
        }
        let time = if time.is_finite() { time } else { 0.0 };
        let context = NonNull::from(Box::leak(Box::new(Context {
            live_bytes: 0,
            call: None,
        })));
        // SAFETY: `params` is a valid `Params` for the duration of the call; the name pointer
        // and length describe `config.name`'s bytes (validated: at most 255, no NUL); `context`
        // is a live heap allocation that outlives the endpoint (freed in `drop`, after
        // `reliable_endpoint_destroy`); the four hooks have exactly the C signatures. The shim
        // copies everything it needs before returning.
        let raw = unsafe {
            sys::dn_native_shim_reliable_create(
                &raw const params,
                config.name.as_ptr().cast(),
                config.name.len(),
                time,
                context.as_ptr().cast(),
                Some(transmit_trampoline),
                Some(process_trampoline),
                Some(allocate),
                Some(free),
            )
        };
        let Some(raw) = NonNull::new(raw) else {
            // reliable.h: on failure create hands every allocation back before returning, so
            // nothing refers to the context any more
            // SAFETY: `context` came from `Box::leak` above and C holds no copy of it.
            drop(unsafe { Box::from_raw(context.as_ptr()) });
            return Err(ConfigError::CreateFailed);
        };
        // SAFETY: C is not running; nothing else writes the context now.
        let created_bytes = unsafe { (*context.as_ptr()).live_bytes };
        let slots = config.fragment_reassembly_buffer_size.next_power_of_two();
        // validated: max_fragments * fragment_size <= INT_MAX - 9, so none of this overflows
        let buffer = ALLOCATION_HEADER
            + MAX_PACKET_HEADER_BYTES
            + config.max_fragments * config.fragment_size
            + REASSEMBLY_SLACK;
        Ok(Self {
            raw,
            context,
            reassembly_bound: slots.saturating_mul(buffer),
            created_bytes,
            config,
            time,
        })
    }

    /// The endpoint's configuration.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// The sequence number the next sent packet will have. Use it to map acked sequence
    /// numbers back to the contents of packets you sent.
    pub fn next_packet_sequence(&self) -> u16 {
        // SAFETY: `raw` is a live endpoint; the function only reads `endpoint->sequence`.
        unsafe { sys::reliable_endpoint_next_packet_sequence(self.raw.as_ptr()) }
    }

    /// Sends a packet: hands it to `transmit` as `(sequence, datagram)`, split into fragments
    /// first (one `transmit` call per fragment) if larger than [`Config::fragment_above`].
    ///
    /// `transmit` runs synchronously, before this returns, and the slice it gets is valid only
    /// for that call. It cannot reach this endpoint (it is mutably borrowed), which upholds the
    /// C library's rule that it must not send on the same endpoint.
    ///
    /// - An empty `packet_data` is a no-op: nothing is sent, no sequence is used, no counter
    ///   moves. (The Rust port panicked; C would send a header-only packet.)
    /// - A packet over [`Config::max_packet_size`] is not sent: `transmit` is not called and
    ///   `num_packets_too_large_to_send` counts it, as in the Rust port.
    ///
    /// # Panics
    ///
    /// Only if `transmit` panics. The panic is caught before it reaches C, every later
    /// `transmit` call of this send is skipped, C finishes the send, and the panic resumes
    /// here. The endpoint stays consistent: the packet counts as sent (its sequence is used and
    /// recorded, so it will show as lost unless the peer received a fragment set that was
    /// complete), and the endpoint is fully usable.
    pub fn send_packet(&mut self, packet_data: &[u8], transmit: impl FnMut(u16, &[u8])) {
        if packet_data.is_empty() {
            return;
        }
        // C counts and drops anything over max_packet_size before reading it, so an oversized
        // slice is described to C as one byte over the limit (an int, as validated)
        let bytes = packet_data.len().min(self.config.max_packet_size + 1);
        let mut frame = Frame {
            closure: transmit,
            panic: None,
        };
        let invoke = transmit_invoker(&frame);
        let call = Call {
            kind: Kind::Transmit,
            frame: (&raw mut frame).cast(),
            invoke,
        };
        let (raw, data, bytes) = (
            self.raw.as_ptr(),
            packet_data.as_ptr().cast_mut(),
            int(bytes),
        );
        self.during(call, || {
            // SAFETY: `raw` is live; `data` is valid for `bytes` reads (bytes <= len,
            // or bytes > max_packet_size, in which case C returns before reading); C only reads
            // through the pointer (memcpy source, reliable.c:1017, 1066), so casting away const
            // is sound; `bytes` is in 1..=INT_MAX by validation; the callbacks it fires find
            // `call` in the context.
            unsafe { sys::reliable_endpoint_send_packet(raw, data, bytes) };
        });
        if let Some(payload) = frame.panic {
            resume_unwind(payload);
        }
    }

    /// Processes a datagram received from the socket. A valid new packet is passed to
    /// `process` as `(sequence, payload)`; return `true` to accept and ack it, `false` to
    /// reject it (a rejected packet is not acked, its piggy-backed acks are discarded, and it
    /// may be processed again if it arrives again). Stale, duplicate, invalid and oversized
    /// datagrams never reach `process`. A fragment that completes a reassembly calls `process`
    /// once with the whole packet.
    ///
    /// `process` runs synchronously, at most once, and its slice is valid only for that call.
    ///
    /// - Any bytes are safe input: arbitrary, truncated or hostile datagrams are refused and
    ///   counted, never panic, and allocate at most what [`memory_usage`](Self::memory_usage)
    ///   bounds.
    /// - An empty datagram counts as `num_packets_invalid` (C's behaviour; the Rust port
    ///   panicked).
    /// - A datagram over `max_packet_size` plus both headers counts as
    ///   `num_packets_too_large_to_receive`, whatever its length.
    ///
    /// # Panics
    ///
    /// Only if `process` panics. The panic is caught before it reaches C, the packet is
    /// rejected (not acked, not recorded, its acks discarded), C finishes, and the panic
    /// resumes here with the endpoint consistent and usable.
    pub fn receive_packet(&mut self, packet_data: &[u8], process: impl FnMut(u16, &[u8]) -> bool) {
        let limit = self.config.max_packet_size + MAX_PACKET_HEADER_BYTES + FRAGMENT_HEADER_BYTES;
        // limit + 1 <= INT_MAX by validation (MAX_PACKET_SIZE)
        let bytes = packet_data.len().min(limit + 1);
        let mut frame = Frame {
            closure: process,
            panic: None,
        };
        let invoke = process_invoker(&frame);
        let call = Call {
            kind: Kind::Process,
            frame: (&raw mut frame).cast(),
            invoke,
        };
        let (raw, data, bytes) = (
            self.raw.as_ptr(),
            packet_data.as_ptr().cast_mut(),
            int(bytes),
        );
        self.during(call, || {
            // SAFETY: `raw` is live; `data` is valid for `bytes` reads, except that
            // `bytes == 0` (C counts it invalid before any read, reliable.c:1328) and
            // `bytes == limit + 1` (C counts it too large before any read, :1334) read nothing;
            // the body only reads the input (header parsing and memcpy source, :1323-1593), so
            // casting away const is sound, and it keeps no pointer to it after returning.
            unsafe { sys::reliable_endpoint_receive_packet(raw, data, bytes) };
        });
        if let Some(payload) = frame.panic {
            resume_unwind(payload);
        }
    }

    /// Makes `call` reachable from the callbacks for exactly the duration of `c`.
    fn during(&mut self, call: Call, c: impl FnOnce()) {
        /// Clears the slot even if `c` unwinds (it cannot: the trampolines catch every panic,
        /// and C does not unwind), so the context never keeps a dangling frame.
        struct Clear(*mut Context);
        impl Drop for Clear {
            fn drop(&mut self) {
                // SAFETY: the context is live for the endpoint's life; no reference to it
                // exists.
                unsafe { (*self.0).call = None };
            }
        }
        let context = self.context.as_ptr();
        // SAFETY: as above; C is not running.
        unsafe { (*context).call = Some(call) };
        let _clear = Clear(context);
        c();
    }

    /// The sequence numbers of sent packets acked since the last [`clear_acks`](Self::clear_acks)
    /// or [`drain_acks`](Self::drain_acks), in the order they were acked. At most
    /// [`Config::ack_buffer_size`]: later acks are dropped until the buffer is cleared.
    pub fn acks(&self) -> &[u16] {
        let mut num_acks: c_int = 0;
        // SAFETY: `raw` is live; the function only reads the endpoint and writes `num_acks`.
        let acks = unsafe { sys::reliable_endpoint_get_acks(self.raw.as_ptr(), &raw mut num_acks) };
        match usize::try_from(num_acks) {
            Ok(len) if len > 0 && !acks.is_null() => {
                // SAFETY: `acks` is the endpoint's array of `ack_buffer_size` u16 (16-byte
                // aligned by `allocate`), of which the first `num_acks <= ack_buffer_size` are
                // set (reliable.c:1420-1423). reliable.h: it stays valid until the next receive,
                // clear_acks, reset or destroy, each of which needs `&mut self`, so it outlives
                // this borrow of `self`.
                unsafe { core::slice::from_raw_parts(acks, len) }
            }
            _ => &[],
        }
    }

    /// Clears the acks. Call once per frame after processing them, or use
    /// [`drain_acks`](Self::drain_acks): an uncleared buffer fills up and drops new acks.
    pub fn clear_acks(&mut self) {
        // SAFETY: `raw` is live; the function sets `num_acks = 0`.
        unsafe { sys::reliable_endpoint_clear_acks(self.raw.as_ptr()) };
    }

    /// Yields the acked sequence numbers (as [`acks`](Self::acks)) and clears them when the
    /// iterator is dropped, consumed or not. (Leaking the iterator with `mem::forget` leaves
    /// the acks in place.)
    pub fn drain_acks(&mut self) -> DrainAcks<'_> {
        DrainAcks {
            endpoint: self,
            next: 0,
        }
    }

    /// Resets the endpoint to its state at creation: acks, counters, the sequence number, all
    /// tracking and reassembly buffers (reassembly memory is freed), the rtt history and every
    /// rtt, jitter, packet loss and bandwidth statistic. The config and time are kept.
    ///
    /// The Rust port kept the statistics (rtt, jitter, loss, bandwidth); C clears them.
    pub fn reset(&mut self) {
        // SAFETY: `raw` is live; reset frees reassembly buffers through `free` with this
        // endpoint's context and calls no packet callback.
        unsafe { sys::reliable_endpoint_reset(self.raw.as_ptr()) };
    }

    /// Updates rtt, jitter, packet loss and bandwidth statistics. Call once per frame with the
    /// current time in seconds.
    ///
    /// Time never runs backwards inside the endpoint: a `time` earlier than the last one, or
    /// not finite, is replaced by the last one (the statistics are still recomputed). This is
    /// the clamp dream-net applies before calling; C requires non-decreasing time.
    pub fn update(&mut self, time: f64) {
        if time.is_finite() && time > self.time {
            self.time = time;
        }
        // SAFETY: `raw` is live; update reads and writes only the endpoint and calls no
        // callback or allocator.
        unsafe { sys::reliable_endpoint_update(self.raw.as_ptr(), self.time) };
    }

    /// Round trip time, exponentially smoothed moving average, in milliseconds.
    pub fn rtt(&self) -> f32 {
        // SAFETY: `raw` is live; a pure field read.
        unsafe { sys::reliable_endpoint_rtt(self.raw.as_ptr()) }
    }

    /// Minimum round trip time over the rtt history, in milliseconds (0 with no samples).
    pub fn rtt_min(&self) -> f32 {
        // SAFETY: `raw` is live; a pure field read.
        unsafe { sys::reliable_endpoint_rtt_min(self.raw.as_ptr()) }
    }

    /// Maximum round trip time over the rtt history, in milliseconds.
    pub fn rtt_max(&self) -> f32 {
        // SAFETY: `raw` is live; a pure field read.
        unsafe { sys::reliable_endpoint_rtt_max(self.raw.as_ptr()) }
    }

    /// Average round trip time over the rtt history, in milliseconds.
    pub fn rtt_avg(&self) -> f32 {
        // SAFETY: `raw` is live; a pure field read.
        unsafe { sys::reliable_endpoint_rtt_avg(self.raw.as_ptr()) }
    }

    /// Average jitter relative to the minimum rtt, in milliseconds.
    pub fn jitter_avg_vs_min_rtt(&self) -> f32 {
        // SAFETY: `raw` is live; a pure field read.
        unsafe { sys::reliable_endpoint_jitter_avg_vs_min_rtt(self.raw.as_ptr()) }
    }

    /// Maximum jitter relative to the minimum rtt, in milliseconds.
    pub fn jitter_max_vs_min_rtt(&self) -> f32 {
        // SAFETY: `raw` is live; a pure field read.
        unsafe { sys::reliable_endpoint_jitter_max_vs_min_rtt(self.raw.as_ptr()) }
    }

    /// Standard deviation of the rtt from the average rtt, in milliseconds.
    pub fn jitter_stddev_vs_avg_rtt(&self) -> f32 {
        // SAFETY: `raw` is live; a pure field read.
        unsafe { sys::reliable_endpoint_jitter_stddev_vs_avg_rtt(self.raw.as_ptr()) }
    }

    /// Packet loss, as a percentage.
    pub fn packet_loss(&self) -> f32 {
        // SAFETY: `raw` is live; a pure field read.
        unsafe { sys::reliable_endpoint_packet_loss(self.raw.as_ptr()) }
    }

    /// Sent, received and acked bandwidth, in kilobits per second.
    pub fn bandwidth(&self) -> Bandwidth {
        let mut bandwidth = Bandwidth::default();
        // SAFETY: `raw` is live; the function reads three fields and writes them to the three
        // out-parameters, which point at distinct `f32` fields of a local.
        unsafe {
            sys::reliable_endpoint_bandwidth(
                self.raw.as_ptr(),
                &raw mut bandwidth.sent_kbps,
                &raw mut bandwidth.received_kbps,
                &raw mut bandwidth.acked_kbps,
            );
        }
        bandwidth
    }

    /// The endpoint's counters, read in place from the C endpoint.
    pub fn counters(&self) -> &Counters {
        // SAFETY: `raw` is live. The function returns `endpoint->counters`, a `uint64_t[11]`
        // inside the endpoint allocation (16-byte aligned by `allocate`, the array 8-aligned in
        // it), which `Counters` matches exactly (repr(C), 11 u64, pinned on both sides); every
        // bit pattern is a valid u64. C writes it only inside `&mut self` calls (send, receive,
        // reset), so it does not change for the life of this borrow, and it is freed only by
        // destroy in `drop`.
        let counters = unsafe { sys::reliable_endpoint_counters(self.raw.as_ptr()) };
        // SAFETY: as above.
        unsafe { &*counters.cast::<Counters>() }
    }

    /// An upper bound, in bytes, of the heap memory this endpoint can hold: everything C
    /// allocated at creation (measured through the allocator hook, so it includes the power of
    /// two rounding of the windows and the hook's 16-byte block header), plus the worst case of
    /// fragment reassembly (every one of the `fragment_reassembly_buffer_size` slots, rounded
    /// up to a power of two, holding a buffer for `max_fragments` fragments), plus the callback
    /// context. The [`Config`] handed to [`new`](Self::new) is not counted.
    ///
    /// Constant for the endpoint's life, and never below [`allocated_bytes`](Self::allocated_bytes).
    pub fn memory_usage(&self) -> usize {
        self.created_bytes + self.reassembly_bound + size_of::<Context>()
    }

    /// The heap memory this endpoint holds right now, in bytes, counted as
    /// [`memory_usage`](Self::memory_usage) counts it. Every C allocation goes through Rust's
    /// global allocator, so a counting global allocator sees the same bytes.
    pub fn allocated_bytes(&self) -> usize {
        // SAFETY: the context is live; it is written only during `&mut self` calls, which
        // cannot overlap this `&self` read.
        unsafe { (*self.context.as_ptr()).live_bytes + size_of::<Context>() }
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        // SAFETY: `raw` is live and not used again; destroy frees every allocation through
        // `free` with the context, which is still live, and calls no packet callback.
        unsafe { sys::reliable_endpoint_destroy(self.raw.as_ptr()) };
        // SAFETY: `context` came from `Box::leak` in `new`; the endpoint that held a copy of
        // the pointer is gone.
        drop(unsafe { Box::from_raw(self.context.as_ptr()) });
    }
}

impl fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Endpoint")
            .field("name", &self.config.name)
            .field("time", &self.time)
            .field("next_packet_sequence", &self.next_packet_sequence())
            .field("num_acks", &self.acks().len())
            .field("counters", self.counters())
            .field("allocated_bytes", &self.allocated_bytes())
            .finish_non_exhaustive()
    }
}

/// The iterator of [`Endpoint::drain_acks`]: yields the acked sequence numbers, then clears
/// them when dropped.
pub struct DrainAcks<'a> {
    endpoint: &'a mut Endpoint,
    next: usize,
}

impl Iterator for DrainAcks<'_> {
    type Item = u16;

    fn next(&mut self) -> Option<u16> {
        let ack = *self.endpoint.acks().get(self.next)?;
        self.next += 1;
        Some(ack)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let left = self.endpoint.acks().len() - self.next;
        (left, Some(left))
    }
}

impl ExactSizeIterator for DrainAcks<'_> {}
impl core::iter::FusedIterator for DrainAcks<'_> {}

impl Drop for DrainAcks<'_> {
    fn drop(&mut self) {
        self.endpoint.clear_acks();
    }
}

impl fmt::Debug for DrainAcks<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DrainAcks")
            .field("remaining", &&self.endpoint.acks()[self.next..])
            .finish()
    }
}

/// A size C takes as `int`. Every caller passes a value validation keeps within `INT_MAX`;
/// saturating keeps the conversion total regardless.
fn int(bytes: usize) -> c_int {
    c_int::try_from(bytes).unwrap_or(c_int::MAX)
}

fn transmit_invoker<F: FnMut(u16, &[u8])>(_: &Frame<F>) -> Invoke {
    invoke_transmit::<F>
}

fn process_invoker<F: FnMut(u16, &[u8]) -> bool>(_: &Frame<F>) -> Invoke {
    invoke_process::<F>
}

/// Runs the transmit closure of the call in progress, catching its panic.
///
/// # Safety
///
/// `frame` is the `*mut Frame<F>` of the call in progress, with no other reference to it live.
unsafe fn invoke_transmit<F: FnMut(u16, &[u8])>(
    frame: *mut c_void,
    sequence: u16,
    data: &[u8],
) -> bool {
    // SAFETY: the caller's contract.
    let frame = unsafe { &mut *frame.cast::<Frame<F>>() };
    if frame.panic.is_some() {
        // the closure already panicked during this call: never run it again
        return false;
    }
    let closure = &mut frame.closure;
    match catch_unwind(AssertUnwindSafe(|| closure(sequence, data))) {
        Ok(()) => true,
        Err(payload) => {
            frame.panic = Some(payload);
            false
        }
    }
}

/// Runs the process closure of the call in progress, catching its panic: a panic rejects the
/// packet.
///
/// # Safety
///
/// As [`invoke_transmit`].
unsafe fn invoke_process<F: FnMut(u16, &[u8]) -> bool>(
    frame: *mut c_void,
    sequence: u16,
    data: &[u8],
) -> bool {
    // SAFETY: the caller's contract.
    let frame = unsafe { &mut *frame.cast::<Frame<F>>() };
    if frame.panic.is_some() {
        return false;
    }
    let closure = &mut frame.closure;
    match catch_unwind(AssertUnwindSafe(|| closure(sequence, data))) {
        Ok(accept) => accept,
        Err(payload) => {
            frame.panic = Some(payload);
            false
        }
    }
}

/// The call in progress on the endpoint whose context this is, if it is of `kind`.
///
/// # Safety
///
/// `context` is null or the live `Context` of an endpoint, with no reference to it live.
unsafe fn active_call(context: *mut c_void, kind: Kind) -> Option<Call> {
    let context = NonNull::new(context.cast::<Context>())?;
    // SAFETY: the caller's contract; a copy is read, no reference is kept.
    let call = unsafe { (*context.as_ptr()).call }?;
    (call.kind == kind).then_some(call)
}

/// Borrows a packet C hands a callback.
///
/// # Safety
///
/// If `bytes > 0` and `data` is not null, `data` is valid for `bytes` reads and not written
/// for `'a`.
unsafe fn borrowed<'a>(data: *const u8, bytes: c_int) -> &'a [u8] {
    match usize::try_from(bytes) {
        // SAFETY: the caller's contract.
        Ok(len) if len > 0 && !data.is_null() => unsafe { core::slice::from_raw_parts(data, len) },
        _ => &[],
    }
}

/// `transmit_packet_function`. C calls it only inside `reliable_endpoint_send_packet`, once
/// per regular packet or once per fragment (reliable.c:1019, 1073), with `packet_data` in the
/// endpoint's transmit buffer, valid until it returns; C keeps no pointer the callback could
/// see. Outside a transmit call it does nothing.
unsafe extern "C" fn transmit_trampoline(
    context: *mut c_void,
    _id: u64,
    sequence: u16,
    packet_data: *mut u8,
    packet_bytes: c_int,
) {
    // SAFETY: C passes back the context given at create: a live `Context`, accessed by no
    // reference while C runs.
    let Some(call) = (unsafe { active_call(context, Kind::Transmit) }) else {
        return;
    };
    // SAFETY: C's transmit buffer holds `packet_bytes` bytes and is not written until the next
    // fragment, after this returns; the slice does not escape the higher-ranked closure.
    let data = unsafe { borrowed(packet_data, packet_bytes) };
    // SAFETY: `call` was set by `Endpoint::during` for the send in progress, whose frame lives
    // on its stack until after C returns, and is otherwise untouched while C runs.
    unsafe { (call.invoke)(call.frame, sequence, data) };
}

/// `process_packet_function`. C calls it only inside `reliable_endpoint_receive_packet`, at
/// most once per call: for a regular packet, or for the packet a fragment completes
/// (reliable.c:1390, reached for a reassembly by the recursive call at :1584). `packet_data` points into the caller's
/// datagram or into the reassembly buffer, which C frees right after this returns. Outside a
/// receive call it rejects (returns 0) and does nothing.
unsafe extern "C" fn process_trampoline(
    context: *mut c_void,
    _id: u64,
    sequence: u16,
    packet_data: *mut u8,
    packet_bytes: c_int,
) -> c_int {
    // SAFETY: as in `transmit_trampoline`.
    let Some(call) = (unsafe { active_call(context, Kind::Process) }) else {
        return 0;
    };
    // SAFETY: the packet is valid and unwritten until this returns; the slice does not escape.
    let data = unsafe { borrowed(packet_data, packet_bytes) };
    // SAFETY: as in `transmit_trampoline`, for the receive in progress.
    c_int::from(unsafe { (call.invoke)(call.frame, sequence, data) })
}

/// `allocate_function`: Rust's global allocator, with a header recording the block size, and
/// this endpoint's byte count. Returns null on failure, which C handles everywhere (create
/// fails cleanly; a reassembly buffer's fragment is dropped and counted invalid).
#[allow(clippy::cast_ptr_alignment)] // the block is 16-aligned
unsafe extern "C" fn allocate(context: *mut c_void, bytes: usize) -> *mut c_void {
    let Some(total) = bytes.checked_add(ALLOCATION_HEADER) else {
        return ptr::null_mut();
    };
    let Ok(layout) = Layout::from_size_align(total, ALLOCATION_ALIGN) else {
        return ptr::null_mut();
    };
    // SAFETY: `layout` has a non-zero size (at least the header).
    let base = unsafe { alloc(layout) };
    if base.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `base` is valid for `total >= 16` bytes and 16-aligned, so usize-aligned.
    unsafe { base.cast::<usize>().write(total) };
    if let Some(context) = NonNull::new(context.cast::<Context>()) {
        // SAFETY: C passes back the live `Context` given at create; no reference to it is live.
        let live = unsafe { &mut (*context.as_ptr()).live_bytes };
        *live = live.wrapping_add(total);
    }
    // SAFETY: `ALLOCATION_HEADER <= total`, so the result is inside the block, 16-aligned.
    unsafe { base.add(ALLOCATION_HEADER) }.cast()
}

/// `free_function`: undoes [`allocate`].
#[allow(clippy::cast_ptr_alignment)] // the block is 16-aligned
unsafe extern "C" fn free(context: *mut c_void, pointer: *mut c_void) {
    if pointer.is_null() {
        return;
    }
    // SAFETY: C frees only pointers `allocate` returned for this endpoint, so the header is
    // `ALLOCATION_HEADER` bytes before it, inside the same block.
    let base = unsafe { pointer.cast::<u8>().sub(ALLOCATION_HEADER) };
    // SAFETY: `allocate` wrote the block's total size there.
    let total = unsafe { base.cast::<usize>().read() };
    if let Some(context) = NonNull::new(context.cast::<Context>()) {
        // SAFETY: as in `allocate`.
        let live = unsafe { &mut (*context.as_ptr()).live_bytes };
        *live = live.wrapping_sub(total);
    }
    // SAFETY: `Layout::from_size_align` accepted exactly this size and alignment in `allocate`.
    let layout = unsafe { Layout::from_size_align_unchecked(total, ALLOCATION_ALIGN) };
    // SAFETY: `base` was allocated by `alloc` with this layout and is freed once.
    unsafe { dealloc(base, layout) };
}

#[cfg(test)]
mod tests {
    use super::{
        ALLOCATION_HEADER, Call, Context, Kind, allocate, free, process_trampoline,
        transmit_trampoline,
    };
    use core::ffi::c_void;
    use core::ptr;

    /// A callback outside any call, or of the other kind, reaches no closure and rejects.
    #[test]
    fn callbacks_outside_a_call_are_inert() {
        unsafe fn never(_: *mut c_void, _: u16, _: &[u8]) -> bool {
            panic!("reached a closure outside its call")
        }
        let mut data = [1u8, 2, 3];
        let mut context = Context {
            live_bytes: 0,
            call: None,
        };
        let context_ptr: *mut c_void = (&raw mut context).cast();
        // SAFETY: a live context with no call, and a valid 3-byte packet.
        unsafe { transmit_trampoline(context_ptr, 0, 7, data.as_mut_ptr(), 3) };
        // SAFETY: as above.
        let accepted = unsafe { process_trampoline(context_ptr, 0, 7, data.as_mut_ptr(), 3) };
        assert_eq!(accepted, 0);
        // SAFETY: a null context is handled.
        let accepted = unsafe { process_trampoline(ptr::null_mut(), 0, 7, data.as_mut_ptr(), 3) };
        assert_eq!(accepted, 0);
        // SAFETY: as above.
        unsafe { transmit_trampoline(ptr::null_mut(), 0, 7, data.as_mut_ptr(), 3) };

        // a transmit call in progress is not reachable from the process callback, and the
        // other way round
        for (kind, other) in [
            (Kind::Transmit, Kind::Process),
            (Kind::Process, Kind::Transmit),
        ] {
            context.call = Some(Call {
                kind,
                frame: ptr::null_mut(),
                invoke: never,
            });
            let context_ptr: *mut c_void = (&raw mut context).cast();
            if other == Kind::Process {
                // SAFETY: a live context whose call is of the other kind.
                let accepted =
                    unsafe { process_trampoline(context_ptr, 0, 7, data.as_mut_ptr(), 3) };
                assert_eq!(accepted, 0);
            } else {
                // SAFETY: as above.
                unsafe { transmit_trampoline(context_ptr, 0, 7, data.as_mut_ptr(), 3) };
            }
        }
    }

    #[test]
    fn allocator_hooks_count_align_and_refuse() {
        let mut context = Context {
            live_bytes: 0,
            call: None,
        };
        let context_ptr: *mut c_void = (&raw mut context).cast();
        let mut blocks = Vec::new();
        for bytes in [1usize, 2, 15, 16, 17, 1000, 65536] {
            // SAFETY: a live context.
            let block = unsafe { allocate(context_ptr, bytes) };
            assert!(!block.is_null());
            assert_eq!(block.addr() % 16, 0);
            // SAFETY: the block is writable for `bytes` bytes.
            unsafe { block.cast::<u8>().write_bytes(0xA5, bytes) };
            blocks.push((block, bytes));
        }
        let expected: usize = blocks.iter().map(|(_, b)| b + ALLOCATION_HEADER).sum();
        // SAFETY: no reference to the context is live.
        let live = unsafe { (*context_ptr.cast::<Context>()).live_bytes };
        assert_eq!(live, expected);
        for (block, _) in blocks {
            // SAFETY: each block came from `allocate` with this context.
            unsafe { free(context_ptr, block) };
        }
        // SAFETY: null is ignored.
        unsafe { free(context_ptr, ptr::null_mut()) };
        // SAFETY: as above.
        let live = unsafe { (*context_ptr.cast::<Context>()).live_bytes };
        assert_eq!(live, 0);
        // sizes that cannot be a Rust allocation are refused with null, never aborted on
        for bytes in [usize::MAX - 8, isize::MAX as usize] {
            // SAFETY: a live context.
            assert!(unsafe { allocate(context_ptr, bytes) }.is_null());
        }
    }
}
