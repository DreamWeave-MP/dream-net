//! Raw declarations of the prefixed reliable C API and of the reliable shim
//! (`csrc/dn_native_reliable.{c,h}`).
//!
//! Every function here takes the endpoint as an opaque pointer. The only struct Rust builds for
//! C is [`Params`], whose layout is pinned three ways: `_Static_assert`s in the shim, the `const`
//! assertions below, and a run-time comparison with the C `offsetof`s in this module's tests.
//! The counter array C exposes is read in place as [`crate::reliable::Counters`], pinned the
//! same way (`RELIABLE_ENDPOINT_NUM_COUNTERS == 11` and every index in the shim, the size and
//! field offsets in `reliable::endpoint`).

use core::ffi::{c_char, c_int, c_void};
use core::marker::{PhantomData, PhantomPinned};
use core::mem::{align_of, offset_of, size_of};

/// `struct reliable_endpoint_t`, defined privately in `reliable.c`. Never constructed or read
/// in Rust; only handled behind a pointer. The marker makes it `!Send`, `!Sync` and `!Unpin`
/// on its own, so only the wrapper's justified impls decide those traits.
#[repr(C)]
pub(crate) struct RawEndpoint {
    _opaque: [u8; 0],
    _marker: PhantomData<(*mut u8, PhantomPinned)>,
}

/// `struct dn_native_reliable_params` (`csrc/dn_native_reliable.h`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct Params {
    pub max_packet_size: c_int,
    pub fragment_above: c_int,
    pub max_fragments: c_int,
    pub fragment_size: c_int,
    pub ack_buffer_size: c_int,
    pub sent_packets_buffer_size: c_int,
    pub received_packets_buffer_size: c_int,
    pub fragment_reassembly_buffer_size: c_int,
    pub rtt_history_size: c_int,
    pub packet_header_size: c_int,
    pub rtt_smoothing_factor: f32,
    pub packet_loss_smoothing_factor: f32,
    pub bandwidth_smoothing_factor: f32,
}

// The same literals as the shim's _Static_asserts.
const _: () = {
    assert!(size_of::<c_int>() == 4);
    assert!(size_of::<Params>() == 52);
    assert!(align_of::<Params>() == 4);
    assert!(offset_of!(Params, max_packet_size) == 0);
    assert!(offset_of!(Params, fragment_above) == 4);
    assert!(offset_of!(Params, max_fragments) == 8);
    assert!(offset_of!(Params, fragment_size) == 12);
    assert!(offset_of!(Params, ack_buffer_size) == 16);
    assert!(offset_of!(Params, sent_packets_buffer_size) == 20);
    assert!(offset_of!(Params, received_packets_buffer_size) == 24);
    assert!(offset_of!(Params, fragment_reassembly_buffer_size) == 28);
    assert!(offset_of!(Params, rtt_history_size) == 32);
    assert!(offset_of!(Params, packet_header_size) == 36);
    assert!(offset_of!(Params, rtt_smoothing_factor) == 40);
    assert!(offset_of!(Params, packet_loss_smoothing_factor) == 44);
    assert!(offset_of!(Params, bandwidth_smoothing_factor) == 48);
};

/// `DN_NATIVE_RELIABLE_PARAMS_LAYOUT_LEN`.
#[cfg(test)]
pub(crate) const PARAMS_LAYOUT_LEN: usize = 14;

/// `void (*)(void*, uint64_t, uint16_t, uint8_t*, int)`.
pub(crate) type TransmitFn = unsafe extern "C" fn(*mut c_void, u64, u16, *mut u8, c_int);
/// `int (*)(void*, uint64_t, uint16_t, uint8_t*, int)`.
pub(crate) type ProcessFn = unsafe extern "C" fn(*mut c_void, u64, u16, *mut u8, c_int) -> c_int;
/// `void * (*)(void*, size_t)`.
pub(crate) type AllocateFn = unsafe extern "C" fn(*mut c_void, usize) -> *mut c_void;
/// `void (*)(void*, void*)`.
pub(crate) type FreeFn = unsafe extern "C" fn(*mut c_void, *mut c_void);

// SAFETY: every declaration matches `csrc/dn_native_reliable.h` or `vendor/reliable/reliable.h`
// at the pinned commit, with `int` as `c_int`, `size_t` as `usize`, `float` as `f32`, `double` as
// `f64`, and `struct reliable_endpoint_t *` as `*mut RawEndpoint`. The reliable functions link
// under their `dn_native_` names (`csrc/dn_native_prefix.h`).
unsafe extern "C" {
    pub(crate) fn dn_native_shim_reliable_create(
        params: *const Params,
        name: *const c_char,
        name_bytes: usize,
        time: f64,
        context: *mut c_void,
        transmit_packet_function: Option<TransmitFn>,
        process_packet_function: Option<ProcessFn>,
        allocate_function: Option<AllocateFn>,
        free_function: Option<FreeFn>,
    ) -> *mut RawEndpoint;

    #[cfg(test)]
    pub(crate) fn dn_native_shim_reliable_params_layout(out: *mut usize);

    #[link_name = "dn_native_reliable_endpoint_destroy"]
    pub(crate) fn reliable_endpoint_destroy(endpoint: *mut RawEndpoint);

    #[link_name = "dn_native_reliable_endpoint_next_packet_sequence"]
    pub(crate) fn reliable_endpoint_next_packet_sequence(endpoint: *mut RawEndpoint) -> u16;

    #[link_name = "dn_native_reliable_endpoint_send_packet"]
    pub(crate) fn reliable_endpoint_send_packet(
        endpoint: *mut RawEndpoint,
        packet_data: *mut u8,
        packet_bytes: c_int,
    );

    #[link_name = "dn_native_reliable_endpoint_receive_packet"]
    pub(crate) fn reliable_endpoint_receive_packet(
        endpoint: *mut RawEndpoint,
        packet_data: *mut u8,
        packet_bytes: c_int,
    );

    #[link_name = "dn_native_reliable_endpoint_get_acks"]
    pub(crate) fn reliable_endpoint_get_acks(
        endpoint: *mut RawEndpoint,
        num_acks: *mut c_int,
    ) -> *const u16;

    #[link_name = "dn_native_reliable_endpoint_clear_acks"]
    pub(crate) fn reliable_endpoint_clear_acks(endpoint: *mut RawEndpoint);

    #[link_name = "dn_native_reliable_endpoint_reset"]
    pub(crate) fn reliable_endpoint_reset(endpoint: *mut RawEndpoint);

    #[link_name = "dn_native_reliable_endpoint_update"]
    pub(crate) fn reliable_endpoint_update(endpoint: *mut RawEndpoint, time: f64);

    #[link_name = "dn_native_reliable_endpoint_rtt"]
    pub(crate) fn reliable_endpoint_rtt(endpoint: *mut RawEndpoint) -> f32;

    #[link_name = "dn_native_reliable_endpoint_rtt_min"]
    pub(crate) fn reliable_endpoint_rtt_min(endpoint: *mut RawEndpoint) -> f32;

    #[link_name = "dn_native_reliable_endpoint_rtt_max"]
    pub(crate) fn reliable_endpoint_rtt_max(endpoint: *mut RawEndpoint) -> f32;

    #[link_name = "dn_native_reliable_endpoint_rtt_avg"]
    pub(crate) fn reliable_endpoint_rtt_avg(endpoint: *mut RawEndpoint) -> f32;

    #[link_name = "dn_native_reliable_endpoint_jitter_avg_vs_min_rtt"]
    pub(crate) fn reliable_endpoint_jitter_avg_vs_min_rtt(endpoint: *mut RawEndpoint) -> f32;

    #[link_name = "dn_native_reliable_endpoint_jitter_max_vs_min_rtt"]
    pub(crate) fn reliable_endpoint_jitter_max_vs_min_rtt(endpoint: *mut RawEndpoint) -> f32;

    #[link_name = "dn_native_reliable_endpoint_jitter_stddev_vs_avg_rtt"]
    pub(crate) fn reliable_endpoint_jitter_stddev_vs_avg_rtt(endpoint: *mut RawEndpoint) -> f32;

    #[link_name = "dn_native_reliable_endpoint_packet_loss"]
    pub(crate) fn reliable_endpoint_packet_loss(endpoint: *mut RawEndpoint) -> f32;

    #[link_name = "dn_native_reliable_endpoint_bandwidth"]
    pub(crate) fn reliable_endpoint_bandwidth(
        endpoint: *mut RawEndpoint,
        sent_bandwidth_kbps: *mut f32,
        received_bandwidth_kbps: *mut f32,
        acked_bandwidth_kbps: *mut f32,
    );

    #[link_name = "dn_native_reliable_endpoint_counters"]
    pub(crate) fn reliable_endpoint_counters(endpoint: *mut RawEndpoint) -> *const u64;
}

#[cfg(test)]
mod tests {
    use super::{PARAMS_LAYOUT_LEN, Params, dn_native_shim_reliable_params_layout};
    use core::mem::{offset_of, size_of};

    #[test]
    fn params_layout_matches_c() {
        let mut c = [0usize; PARAMS_LAYOUT_LEN];
        // SAFETY: the shim writes exactly PARAMS_LAYOUT_LEN size_t values to `out`, and `c` is
        // that many `usize` (size_t on every supported target).
        unsafe { dn_native_shim_reliable_params_layout(c.as_mut_ptr()) };
        let rust = [
            size_of::<Params>(),
            offset_of!(Params, max_packet_size),
            offset_of!(Params, fragment_above),
            offset_of!(Params, max_fragments),
            offset_of!(Params, fragment_size),
            offset_of!(Params, ack_buffer_size),
            offset_of!(Params, sent_packets_buffer_size),
            offset_of!(Params, received_packets_buffer_size),
            offset_of!(Params, fragment_reassembly_buffer_size),
            offset_of!(Params, rtt_history_size),
            offset_of!(Params, packet_header_size),
            offset_of!(Params, rtt_smoothing_factor),
            offset_of!(Params, packet_loss_smoothing_factor),
            offset_of!(Params, bandwidth_smoothing_factor),
        ];
        assert_eq!(c, rust);
    }
}
