/*
    dream-net reliable shim. SPDX-License-Identifier: MIT OR Apache-2.0

    The only C the reliable binding (src/reliable/, src/sys/reliable.rs) adds. Shared decision 6:
    Rust never builds or reads a struct reliable_config_t (256-byte name, pointers, callbacks,
    allocator hooks). It hands this shim the scalar settings in one small struct whose layout is
    pinned on both sides (_Static_assert here, const assertions in src/sys/reliable.rs, and a
    run-time comparison in the crate's unit tests), and the shim builds the config from
    reliable_default_config() and installs the callbacks and allocator hooks.

    Everything else the binding calls is the plain reliable API from vendor/reliable/reliable.h,
    linked under the dn_native_ prefix.
*/

#ifndef DN_NATIVE_RELIABLE_H
#define DN_NATIVE_RELIABLE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct reliable_endpoint_t;

/*
    The scalar half of struct reliable_config_t, in the same units. Every int is already range
    checked by the Rust Config::validate; reliable_endpoint_create checks them again.
*/
struct dn_native_reliable_params
{
    int max_packet_size;
    int fragment_above;
    int max_fragments;
    int fragment_size;
    int ack_buffer_size;
    int sent_packets_buffer_size;
    int received_packets_buffer_size;
    int fragment_reassembly_buffer_size;
    int rtt_history_size;
    int packet_header_size;
    float rtt_smoothing_factor;
    float packet_loss_smoothing_factor;
    float bandwidth_smoothing_factor;
};

/* Number of size_t values dn_native_shim_reliable_params_layout writes. */
#define DN_NATIVE_RELIABLE_PARAMS_LAYOUT_LEN 14

/*
    Creates an endpoint from reliable_default_config() overwritten with params, the name (name_bytes
    bytes, no NUL needed, at most 255 and without an interior NUL), and the four hooks. context is
    both the callback context and the allocator context: the endpoint stores it and hands it back
    unchanged, so it must outlive the endpoint. Returns NULL if params or name are refused (by this
    shim or by reliable_endpoint_create) or an allocation fails; nothing is retained then.
*/
struct reliable_endpoint_t * dn_native_shim_reliable_create( const struct dn_native_reliable_params * params,
                                                             const char * name,
                                                             size_t name_bytes,
                                                             double time,
                                                             void * context,
                                                             void (*transmit_packet_function)(void*,uint64_t,uint16_t,uint8_t*,int),
                                                             int (*process_packet_function)(void*,uint64_t,uint16_t,uint8_t*,int),
                                                             void * (*allocate_function)(void*,size_t),
                                                             void (*free_function)(void*,void*) );

/*
    Writes sizeof(struct dn_native_reliable_params) then the offset of each of its 13 fields, in
    declaration order, so a Rust test can compare them with its own repr(C) mirror at run time.
*/
void dn_native_shim_reliable_params_layout( size_t out[DN_NATIVE_RELIABLE_PARAMS_LAYOUT_LEN] );

#ifdef __cplusplus
}
#endif

#endif /* DN_NATIVE_RELIABLE_H */
