/*
    dream-net: fuzz reliable's receive path with an honest peer supplying real context.
    SPDX-License-Identifier: MIT OR Apache-2.0

    A unity build over the vendored reliable.c (see fuzz_support.h). Two endpoints with
    dream-net's default configuration (TransportConfig::default().reliable_config(): 32 KiB
    packets, fragments above 1191 bytes, 1186-byte fragments, 28 fragments, windows of 256,
    16 reassembly slots) talk through a wire the fuzzer controls. The sender is honest: the
    fuzzer only chooses what it sends (sizes from one byte to past max_packet_size, so whole
    fragment sets) and then what happens to each datagram on the wire: delivered, dropped,
    duplicated, held back and reordered, or mutated with structure: a flipped byte, the
    fragment header's sequence, id or count rewritten, truncated, extended, or spliced from
    another datagram. Raw noise and acks flowing back are mixed in.

    Oracles (abort on violation), on top of ASan/UBSan and, asserts live, every reliable_assert:

    1. Every packet the receiver processes was sent by the sender with that sequence and is
       byte-identical to it, unless a mutated datagram of that sequence reached the receiver
       (reliable has no authentication: netcode's AEAD is what stops forgeries in dream-net).
    2. With only honest (if lost, duplicated and reordered) traffic, a sequence is processed
       at most once (the receive window).
    3. The receiver never holds more heap than the bound Endpoint::memory_usage reports:
       everything allocated at create plus every reassembly slot (rounded up to a power of
       two) holding a buffer for max_fragments fragments. Counted through the allocator hooks,
       exactly as the Rust binding counts.
    4. Nothing processed is longer than max_packet_size.
*/

#include "reliable.c"

#define DN_FUZZ_NAME "fuzz_reliable_pair"
#include "fuzz_support.h"

#define DN_MAX_PACKET 32768
#define DN_FRAGMENT_ABOVE 1191
#define DN_FRAGMENT_SIZE 1186
#define DN_MAX_FRAGMENTS 28
#define DN_REASSEMBLY 16
#define DN_MAX_OPS 160
#define DN_WIRE 96
#define DN_DATAGRAM ( DN_FRAGMENT_SIZE + RELIABLE_FRAGMENT_HEADER_BYTES + RELIABLE_MAX_PACKET_HEADER_BYTES )

struct dn_side
{
    struct reliable_endpoint_t * endpoint;
    size_t live;
    size_t created;
};

static struct dn_side dn_a;   /* sender */
static struct dn_side dn_b;   /* receiver */

struct dn_wire_datagram
{
    int to_b;
    int bytes;
    uint16_t sequence;
    uint8_t data[DN_DATAGRAM + 64];
};

static struct dn_wire_datagram dn_wire[DN_WIRE];
static int dn_wire_count;

/* what A sent, by sequence: hash and length of the whole packet */
static uint64_t dn_sent_hash[65536];
static int dn_sent_valid[65536];
static uint8_t dn_tainted[65536];
static uint8_t dn_processed[65536];
static int dn_any_taint;

static void * dn_allocate( void * context, size_t bytes )
{
    struct dn_side * side = (struct dn_side*) context;
    size_t total = bytes + 16;
    uint8_t * block = (uint8_t*) malloc( total );
    if ( !block )
        return NULL;
    memcpy( block, &total, sizeof( total ) );
    side->live += total;
    return block + 16;
}

static void dn_free( void * context, void * pointer )
{
    struct dn_side * side = (struct dn_side*) context;
    if ( !pointer )
        return;
    uint8_t * block = (uint8_t*) pointer - 16;
    size_t total;
    memcpy( &total, block, sizeof( total ) );
    side->live -= total;
    free( block );
}

static void dn_transmit( void * context, uint64_t id, uint16_t sequence, uint8_t * data, int bytes )
{
    (void) context;
    DN_CHECK( bytes > 0 && bytes <= DN_DATAGRAM );
    if ( dn_wire_count == DN_WIRE )
        return;   /* the wire is full: dropped */
    struct dn_wire_datagram * d = &dn_wire[dn_wire_count++];
    d->to_b = ( id == 0 );
    d->bytes = bytes;
    d->sequence = sequence;
    memcpy( d->data, data, (size_t) bytes );
}

static int dn_process( void * context, uint64_t id, uint16_t sequence, uint8_t * data, int bytes )
{
    (void) context;
    if ( id != 1 )
        return 1;   /* A processing B's ack-only packets */
#ifdef DN_TRACE
    fprintf( stderr, "process seq %u bytes %d valid %d tainted %d match %d\n", sequence, bytes, dn_sent_valid[sequence], dn_tainted[sequence], dn_sent_hash[sequence] == dn_hash( data, (size_t) bytes ) );
#endif
    /* oracle 4 */
    DN_CHECK( bytes >= 0 && bytes <= DN_MAX_PACKET );
    /* oracle 2 (forged datagrams can move the window anywhere in the 16-bit space, after
       which an old sequence is new again: only honest traffic promises once) */
    DN_CHECK( dn_any_taint || !dn_processed[sequence] );
    dn_processed[sequence] = 1;
    /* oracle 1 */
    if ( !dn_tainted[sequence] )
    {
        DN_CHECK( dn_sent_valid[sequence] );
        DN_CHECK( dn_sent_hash[sequence] == dn_hash( data, (size_t) bytes ) );
    }
    dn_stat( 0, bytes > DN_FRAGMENT_ABOVE ? "reassembled packets processed" : "packets processed" );
    return 1;
}

static struct reliable_endpoint_t * dn_create( struct dn_side * side, uint64_t id, const char * name )
{
    struct reliable_config_t config;
    reliable_default_config( &config );
    snprintf( config.name, sizeof( config.name ), "%s", name );
    config.context = NULL;
    config.id = id;
    config.max_packet_size = DN_MAX_PACKET;
    config.fragment_above = DN_FRAGMENT_ABOVE;
    config.max_fragments = DN_MAX_FRAGMENTS;
    config.fragment_size = DN_FRAGMENT_SIZE;
    config.ack_buffer_size = 64;
    config.sent_packets_buffer_size = 256;
    config.received_packets_buffer_size = 256;
    config.fragment_reassembly_buffer_size = DN_REASSEMBLY;
    config.rtt_smoothing_factor = 0.0025f;
    config.rtt_history_size = 128;
    config.packet_loss_smoothing_factor = 0.1f;
    config.bandwidth_smoothing_factor = 0.1f;
    config.packet_header_size = 28;
    config.transmit_packet_function = dn_transmit;
    config.process_packet_function = dn_process;
    config.allocator_context = side;
    config.allocate_function = dn_allocate;
    config.free_function = dn_free;
    side->live = 0;
    struct reliable_endpoint_t * endpoint = reliable_endpoint_create( &config, 0.0 );
    DN_CHECK( endpoint );
    side->created = side->live;
    return endpoint;
}

static void dn_check_memory( void )
{
    /* oracle 3: the bound Endpoint::memory_usage reports (without the Rust context) */
    size_t slots = DN_REASSEMBLY;   /* already a power of two */
    size_t buffer = 16 + RELIABLE_MAX_PACKET_HEADER_BYTES + (size_t) DN_MAX_FRAGMENTS * DN_FRAGMENT_SIZE + 8;
    DN_CHECK( dn_b.live <= dn_b.created + slots * buffer );
    if ( dn_b.live > dn_b.created )
        dn_stat( 1, "inputs holding reassembly memory" );
}

static void dn_deliver( struct dn_wire_datagram * d, int tainted )
{
#ifdef DN_TRACE
    fprintf( stderr, "deliver to_b %d seq %u bytes %d tainted %d head %02x %02x %02x %02x %02x\n", d->to_b, d->sequence, d->bytes, tainted, d->data[0], d->data[1], d->data[2], d->data[3], d->data[4] );
#endif
    if ( d->to_b )
    {
        if ( tainted )
            dn_any_taint = 1;
        if ( tainted && d->bytes >= 3 )
        {
            /* whichever sequence the datagram now claims may carry altered data */
            uint16_t claimed = (uint16_t) ( d->data[1] | ( d->data[2] << 8 ) );
            dn_tainted[claimed] = 1;
            dn_tainted[d->sequence] = 1;
        }
        reliable_endpoint_receive_packet( dn_b.endpoint, d->data, d->bytes );
        dn_check_memory();
        /* B acks: its acks go to A on the next send from B */
    }
    else
    {
        reliable_endpoint_receive_packet( dn_a.endpoint, d->data, d->bytes );
    }
}

static void dn_take( int index )
{
    int i;
    for ( i = index; i + 1 < dn_wire_count; i++ )
        dn_wire[i] = dn_wire[i + 1];
    dn_wire_count--;
}

int LLVMFuzzerTestOneInput( const uint8_t * data, size_t size )
{
#ifndef NDEBUG
    reliable_set_assert_function( dn_fuzz_assert_trip );
#endif
    reliable_set_printf_function( dn_fuzz_discard_printf );
    reliable_log_level( RELIABLE_LOG_LEVEL_NONE );

    struct dn_in in = { data, size, 0 };
    dn_wire_count = 0;
    dn_any_taint = 0;
    memset( dn_sent_valid, 0, sizeof( dn_sent_valid ) );
    memset( dn_tainted, 0, sizeof( dn_tainted ) );
    memset( dn_processed, 0, sizeof( dn_processed ) );

    dn_a.endpoint = dn_create( &dn_a, 0, "a" );
    dn_b.endpoint = dn_create( &dn_b, 1, "b" );

    static uint8_t packet[DN_MAX_PACKET + 64];
    double time = 0.0;
    int ops = 0;
    while ( dn_more( &in ) && ops++ < DN_MAX_OPS )
    {
        uint8_t op = dn_u8( &in );
        switch ( op % 10 )
        {
            case 0:
            case 1:
            {
                /* A sends: small, around the fragment threshold, or a whole fragment set */
                int bytes;
                uint8_t shape = dn_u8( &in ) % 6;
                if ( shape == 0 )
                    bytes = 1 + dn_u8( &in );
                else if ( shape == 1 )
                    bytes = DN_FRAGMENT_ABOVE - 2 + dn_u8( &in ) % 5;
                else if ( shape == 2 )
                    bytes = DN_MAX_PACKET - 2 + dn_u8( &in ) % 5;   /* across the maximum */
                else
                    bytes = 1 + (int) ( dn_u16( &in ) % ( DN_MAX_PACKET + 8 ) );
                uint8_t fill = dn_u8( &in );
                int i;
                for ( i = 0; i < bytes; i++ )
                    packet[i] = (uint8_t) ( fill + i * 7 );
                uint16_t sequence = reliable_endpoint_next_packet_sequence( dn_a.endpoint );
#ifdef DN_TRACE
                fprintf( stderr, "send seq %u bytes %d\n", sequence, bytes );
#endif
                if ( bytes <= DN_MAX_PACKET )
                {
                    dn_sent_valid[sequence] = 1;
                    dn_sent_hash[sequence] = dn_hash( packet, (size_t) bytes );
                    /* a taint stays: a forged fragment may have claimed this sequence before
                       it was sent, and reassembly keeps the first copy of each fragment */
                    dn_processed[sequence] = 0;
                }
                /* exact-size heap copy, so ASan sees any read past the end */
                uint8_t * copy = (uint8_t*) malloc( (size_t) bytes );
                memcpy( copy, packet, (size_t) bytes );
                reliable_endpoint_send_packet( dn_a.endpoint, copy, bytes );
                free( copy );
                break;
            }

            case 2:
            case 3:
            {
                /* deliver everything in order, the oldest, or a chosen datagram, as it is */
                if ( dn_wire_count == 0 )
                    break;
                if ( op % 10 == 2 && ( dn_u8( &in ) & 1 ) )
                {
                    while ( dn_wire_count > 0 )
                    {
                        struct dn_wire_datagram d = dn_wire[0];
                        dn_take( 0 );
                        dn_deliver( &d, 0 );
                    }
                    break;
                }
                int index = ( op % 10 == 2 ) ? 0 : dn_u8( &in ) % dn_wire_count;
                struct dn_wire_datagram d = dn_wire[index];
                dn_take( index );
                dn_deliver( &d, 0 );
                break;
            }

            case 4:
            {
                /* drop, or duplicate */
                if ( dn_wire_count == 0 )
                    break;
                int index = dn_u8( &in ) % dn_wire_count;
                if ( dn_u8( &in ) & 1 )
                {
                    struct dn_wire_datagram d = dn_wire[index];
                    dn_deliver( &d, 0 );
                }
                else
                {
                    dn_take( index );
                }
                break;
            }

            case 5:
            case 6:
            {
                /* deliver a mutated copy */
                if ( dn_wire_count == 0 )
                    break;
                int index = dn_u8( &in ) % dn_wire_count;
                struct dn_wire_datagram d = dn_wire[index];
                uint8_t how = dn_u8( &in ) % 8;
                switch ( how )
                {
                    case 0: d.data[dn_u16( &in ) % d.bytes] ^= (uint8_t) ( 1 + dn_u8( &in ) % 255 ); break;
                    case 1: if ( d.bytes >= 3 ) { uint16_t s = dn_u16( &in ); d.data[1] = (uint8_t) s; d.data[2] = (uint8_t) ( s >> 8 ); } break;
                    case 2: if ( d.bytes >= 4 ) d.data[3] = dn_u8( &in ); break;   /* fragment id */
                    case 3: if ( d.bytes >= 5 ) d.data[4] = dn_u8( &in ); break;   /* fragment count */
                    case 4: d.bytes = dn_u16( &in ) % ( d.bytes + 1 ); break;
                    case 5:
                    {
                        int extra = 1 + dn_u8( &in ) % 64;
                        int i;
                        for ( i = 0; i < extra; i++ )
                            d.data[d.bytes + i] = dn_u8( &in );
                        d.bytes += extra;
                        break;
                    }
                    case 6:
                    {
                        /* splice: the head of this datagram on the tail of another */
                        struct dn_wire_datagram * other = &dn_wire[dn_u8( &in ) % dn_wire_count];
                        int cut = d.bytes > 0 ? dn_u16( &in ) % d.bytes : 0;
                        int tail = other->bytes - cut;
                        if ( tail > 0 && cut + tail <= (int) sizeof( d.data ) )
                        {
                            memcpy( d.data + cut, other->data + cut, (size_t) tail );
                            d.bytes = cut + tail;
                        }
                        break;
                    }
                    default: d.data[0] ^= (uint8_t) ( 1u << ( dn_u8( &in ) % 8 ) ); break;
                }
                if ( d.bytes > DN_DATAGRAM + 64 )
                    d.bytes = DN_DATAGRAM + 64;
                if ( d.to_b )
                    dn_deliver( &d, 1 );
                break;
            }

            case 7:
            {
                /* raw noise into B */
                uint8_t raw[DN_DATAGRAM + 16];
                int bytes = dn_u16( &in ) % ( DN_DATAGRAM + 17 );
                dn_bytes( &in, raw, (size_t) bytes );
                dn_any_taint = 1;
                if ( bytes >= 3 )
                {
                    dn_tainted[(uint16_t) ( raw[1] | ( raw[2] << 8 ) )] = 1;
                    if ( bytes >= 9 )
                        dn_tainted[(uint16_t) ( raw[6] | ( raw[7] << 8 ) )] = 1;
                }
                if ( bytes == 0 )
                    reliable_endpoint_receive_packet( dn_b.endpoint, raw, 0 );
                else
                {
                    uint8_t * copy = (uint8_t*) malloc( (size_t) bytes );
                    memcpy( copy, raw, (size_t) bytes );
                    reliable_endpoint_receive_packet( dn_b.endpoint, copy, bytes );
                    free( copy );
                }
                dn_check_memory();
                break;
            }

            case 8:
            {
                /* B sends a small packet (carrying acks) back to A */
                uint8_t ack_payload[4] = { 1, 2, 3, 4 };
                reliable_endpoint_send_packet( dn_b.endpoint, ack_payload, 1 + dn_u8( &in ) % 4 );
                break;
            }

            case 9:
            {
                time += ( dn_u8( &in ) % 8 ) * 0.05;
                reliable_endpoint_update( dn_a.endpoint, time );
                reliable_endpoint_update( dn_b.endpoint, time );
                reliable_endpoint_clear_acks( dn_a.endpoint );
                reliable_endpoint_clear_acks( dn_b.endpoint );
                break;
            }
        }
    }

    reliable_endpoint_destroy( dn_a.endpoint );
    reliable_endpoint_destroy( dn_b.endpoint );
    DN_CHECK( dn_a.live == 0 && dn_b.live == 0 );   /* destroy hands back everything */
    return 0;
}
