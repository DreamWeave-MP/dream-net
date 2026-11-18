/*
    dream-net reliable shim. SPDX-License-Identifier: MIT OR Apache-2.0
*/

#include "dn_native_reliable.h"

#include "reliable.h"

#include <stddef.h>
#include <string.h>

/* The values the Rust binding hard-codes as literals (src/reliable.rs, src/sys/reliable.rs). */
_Static_assert( RELIABLE_MAX_PACKET_HEADER_BYTES == 9, "MAX_PACKET_HEADER_BYTES" );
_Static_assert( RELIABLE_FRAGMENT_HEADER_BYTES == 5, "FRAGMENT_HEADER_BYTES" );
_Static_assert( RELIABLE_OK == 1, "RELIABLE_OK" );

/* Counters is a repr(C) struct of 11 u64 that the binding reads in place over the array
   reliable_endpoint_counters returns: the order of its fields is the order of these indices. */
_Static_assert( RELIABLE_ENDPOINT_NUM_COUNTERS == 11, "counter count" );
_Static_assert( RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_SENT == 0, "counter index" );
_Static_assert( RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_RECEIVED == 1, "counter index" );
_Static_assert( RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_ACKED == 2, "counter index" );
_Static_assert( RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_STALE == 3, "counter index" );
_Static_assert( RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_INVALID == 4, "counter index" );
_Static_assert( RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_TOO_LARGE_TO_SEND == 5, "counter index" );
_Static_assert( RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_TOO_LARGE_TO_RECEIVE == 6, "counter index" );
_Static_assert( RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_SENT == 7, "counter index" );
_Static_assert( RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_RECEIVED == 8, "counter index" );
_Static_assert( RELIABLE_ENDPOINT_COUNTER_NUM_FRAGMENTS_INVALID == 9, "counter index" );
_Static_assert( RELIABLE_ENDPOINT_COUNTER_NUM_PACKETS_DUPLICATE == 10, "counter index" );
_Static_assert( sizeof( uint64_t ) * RELIABLE_ENDPOINT_NUM_COUNTERS == 88, "counter array bytes" );

/* The Rust side declares c_int as i32 and f32 for float. */
_Static_assert( sizeof( int ) == 4, "int is 32 bits" );
_Static_assert( sizeof( float ) == 4, "float is 32 bits" );

/* The params layout, mirrored by a repr(C) struct in src/sys/reliable.rs. */
_Static_assert( sizeof( struct dn_native_reliable_params ) == 52, "params size" );
_Static_assert( _Alignof( struct dn_native_reliable_params ) == 4, "params alignment" );
_Static_assert( offsetof( struct dn_native_reliable_params, max_packet_size ) == 0, "params layout" );
_Static_assert( offsetof( struct dn_native_reliable_params, fragment_above ) == 4, "params layout" );
_Static_assert( offsetof( struct dn_native_reliable_params, max_fragments ) == 8, "params layout" );
_Static_assert( offsetof( struct dn_native_reliable_params, fragment_size ) == 12, "params layout" );
_Static_assert( offsetof( struct dn_native_reliable_params, ack_buffer_size ) == 16, "params layout" );
_Static_assert( offsetof( struct dn_native_reliable_params, sent_packets_buffer_size ) == 20, "params layout" );
_Static_assert( offsetof( struct dn_native_reliable_params, received_packets_buffer_size ) == 24, "params layout" );
_Static_assert( offsetof( struct dn_native_reliable_params, fragment_reassembly_buffer_size ) == 28, "params layout" );
_Static_assert( offsetof( struct dn_native_reliable_params, rtt_history_size ) == 32, "params layout" );
_Static_assert( offsetof( struct dn_native_reliable_params, packet_header_size ) == 36, "params layout" );
_Static_assert( offsetof( struct dn_native_reliable_params, rtt_smoothing_factor ) == 40, "params layout" );
_Static_assert( offsetof( struct dn_native_reliable_params, packet_loss_smoothing_factor ) == 44, "params layout" );
_Static_assert( offsetof( struct dn_native_reliable_params, bandwidth_smoothing_factor ) == 48, "params layout" );

/* The name buffer the shim copies into: 255 bytes and the terminator. */
_Static_assert( sizeof( ( (struct reliable_config_t *) NULL )->name ) == 256, "config name bytes" );

struct reliable_endpoint_t * dn_native_shim_reliable_create( const struct dn_native_reliable_params * params,
                                                             const char * name,
                                                             size_t name_bytes,
                                                             double time,
                                                             void * context,
                                                             void (*transmit_packet_function)(void*,uint64_t,uint16_t,uint8_t*,int),
                                                             int (*process_packet_function)(void*,uint64_t,uint16_t,uint8_t*,int),
                                                             void * (*allocate_function)(void*,size_t),
                                                             void (*free_function)(void*,void*) )
{
    struct reliable_config_t config;

    if ( params == NULL || ( name == NULL && name_bytes != 0 ) )
    {
        return NULL;
    }

    /* refuse rather than truncate, matching Config::validate */
    if ( name_bytes > sizeof( config.name ) - 1 || ( name_bytes != 0 && memchr( name, '\0', name_bytes ) != NULL ) )
    {
        return NULL;
    }

    reliable_default_config( &config );

    memset( config.name, 0, sizeof( config.name ) );
    if ( name_bytes != 0 )
    {
        memcpy( config.name, name, name_bytes );
    }

    config.context = context;
    config.id = 0;
    config.max_packet_size = params->max_packet_size;
    config.fragment_above = params->fragment_above;
    config.max_fragments = params->max_fragments;
    config.fragment_size = params->fragment_size;
    config.ack_buffer_size = params->ack_buffer_size;
    config.sent_packets_buffer_size = params->sent_packets_buffer_size;
    config.received_packets_buffer_size = params->received_packets_buffer_size;
    config.fragment_reassembly_buffer_size = params->fragment_reassembly_buffer_size;
    config.rtt_smoothing_factor = params->rtt_smoothing_factor;
    config.rtt_history_size = params->rtt_history_size;
    config.packet_loss_smoothing_factor = params->packet_loss_smoothing_factor;
    config.bandwidth_smoothing_factor = params->bandwidth_smoothing_factor;
    config.packet_header_size = params->packet_header_size;
    config.transmit_packet_function = transmit_packet_function;
    config.process_packet_function = process_packet_function;
    config.allocator_context = context;
    config.allocate_function = allocate_function;
    config.free_function = free_function;

    /* create validates the config (reliable_config_valid) and copies it: nothing here is
       referenced after it returns */
    return reliable_endpoint_create( &config, time );
}

void dn_native_shim_reliable_params_layout( size_t out[DN_NATIVE_RELIABLE_PARAMS_LAYOUT_LEN] )
{
    out[0] = sizeof( struct dn_native_reliable_params );
    out[1] = offsetof( struct dn_native_reliable_params, max_packet_size );
    out[2] = offsetof( struct dn_native_reliable_params, fragment_above );
    out[3] = offsetof( struct dn_native_reliable_params, max_fragments );
    out[4] = offsetof( struct dn_native_reliable_params, fragment_size );
    out[5] = offsetof( struct dn_native_reliable_params, ack_buffer_size );
    out[6] = offsetof( struct dn_native_reliable_params, sent_packets_buffer_size );
    out[7] = offsetof( struct dn_native_reliable_params, received_packets_buffer_size );
    out[8] = offsetof( struct dn_native_reliable_params, fragment_reassembly_buffer_size );
    out[9] = offsetof( struct dn_native_reliable_params, rtt_history_size );
    out[10] = offsetof( struct dn_native_reliable_params, packet_header_size );
    out[11] = offsetof( struct dn_native_reliable_params, rtt_smoothing_factor );
    out[12] = offsetof( struct dn_native_reliable_params, packet_loss_smoothing_factor );
    out[13] = offsetof( struct dn_native_reliable_params, bandwidth_smoothing_factor );
}
