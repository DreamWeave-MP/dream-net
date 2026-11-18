/*
    dream-net-native: fuzz the netcode client's whole datagram entry point, with the session keys
    known to the fuzzer, which plays every server. SPDX-License-Identifier: MIT OR Apache-2.0

    A unity build over the vendored netcode.c (see fuzz_support.h). The client runs exactly as
    dream-net runs it, through netcode_client_connect and netcode_client_update, over netcode's
    send/receive override: the fuzzer decides every datagram the client "receives" and sees every
    one it sends. The connect token lists two servers (A, then B), so the multi-address paths run.

    Operations: honest server behaviour (a challenge, keep-alives, payloads, a disconnect, a
    denied packet) from A or B; authenticated packets of every type with hostile contents,
    sequences (window edges, far jumps, UINT64_MAX and neighbours, reuse) and sequence-byte
    counts; the same from a stranger's address; replays of any datagram so far, flipped or
    truncated; raw noise; time steps; application sends, receives, disconnects and reconnects.

    Oracles (abort on violation), on top of ASan/UBSan and, asserts live, every netcode_assert:

    1. Within one connect attempt the client never encrypts two datagrams under one
       (client-to-server key, sequence) pair.
    2. Every payload the application receives was sealed by the fuzzer under the
       server-to-client key at that sequence, byte for byte, and is received at most once per
       attempt; nothing under another key is ever received.
    3. The client only ever sends to the server it is connecting to, and only datagrams of at
       most NETCODE_MAX_PACKET_BYTES.
    4. A disconnect from the server while connected leaves the client disconnected: it never
       moves on to the next listed server (audit S4).
*/

#include "netcode.c"

#define DN_FUZZ_NAME "fuzz_netcode_client"
#include "fuzz_support.h"

#include <time.h>

#define DN_PROTOCOL_ID 0x1122334455667788ULL
#define DN_MAX_OPS 96
#define DN_QUEUE 64
#define DN_HISTORY 64
#define DN_LOG 1024

static struct netcode_address_t dn_server_a;
static struct netcode_address_t dn_server_b;
static struct netcode_address_t dn_stranger;
static uint8_t dn_c2s[NETCODE_KEY_BYTES];
static uint8_t dn_s2c[NETCODE_KEY_BYTES];
static uint8_t dn_token[NETCODE_CONNECT_TOKEN_BYTES];
static int dn_ready;

struct dn_datagram
{
    struct netcode_address_t address;
    int bytes;
    uint8_t data[NETCODE_MAX_PACKET_BYTES];
};

static struct dn_datagram dn_inbound[DN_QUEUE];
static int dn_inbound_count;
static int dn_inbound_next;

static struct dn_datagram dn_history[DN_HISTORY];
static int dn_history_count;

/* oracle 1: client-to-server sequences of the current attempt */
static uint64_t dn_client_sequences[DN_LOG];
static int dn_client_sequence_count;

/* oracle 2: what the fuzzer sealed this attempt, under the server-to-client key */
struct dn_sealed
{
    uint64_t sequence;
    uint64_t hash;
    int received;      /* in the current attempt */
};
static struct dn_sealed dn_sealed[DN_LOG];
static int dn_sealed_count;

static uint64_t dn_server_sequence;
static struct netcode_client_t * dn_client;

static void dn_new_attempt( void )
{
    dn_client_sequence_count = 0;
    int n;
    for ( n = 0; n < dn_sealed_count; n++ )
        dn_sealed[n].received = 0;
}

static void dn_send_override( void * context, struct netcode_address_t * to, NETCODE_CONST uint8_t * data, int bytes )
{
    (void) context;
    /* oracle 3 */
    DN_CHECK( bytes > 0 && bytes <= NETCODE_MAX_PACKET_BYTES );
    DN_CHECK( netcode_address_equal( to, &dn_client->server_address ) );
    if ( data[0] == NETCODE_CONNECTION_REQUEST_PACKET )
        return;
    int sequence_bytes = data[0] >> 4;
    DN_CHECK( sequence_bytes >= 1 && sequence_bytes <= 8 && bytes >= 1 + sequence_bytes + NETCODE_MAC_BYTES );
    uint64_t sequence = 0;
    int b;
    for ( b = 0; b < sequence_bytes; b++ )
        sequence |= ( (uint64_t) data[1 + b] ) << ( 8 * b );
    int n;
    for ( n = 0; n < dn_client_sequence_count; n++ )
        DN_CHECK( dn_client_sequences[n] != sequence );   /* oracle 1 */
    if ( dn_client_sequence_count < DN_LOG )
        dn_client_sequences[dn_client_sequence_count++] = sequence;
    dn_stat( 0, "client datagrams" );
}

static int dn_receive_override( void * context, struct netcode_address_t * from, uint8_t * data, int bytes )
{
    (void) context;
    if ( dn_inbound_next >= dn_inbound_count )
        return 0;
    struct dn_datagram * d = &dn_inbound[dn_inbound_next++];
    int n = d->bytes < bytes ? d->bytes : bytes;
    *from = d->address;
    memcpy( data, d->data, (size_t) n );
    return n;
}

static void dn_queue( const struct netcode_address_t * from, const uint8_t * data, int bytes )
{
    if ( bytes < 0 )
        return;
    if ( bytes > NETCODE_MAX_PACKET_BYTES )
        bytes = NETCODE_MAX_PACKET_BYTES;
    if ( dn_inbound_count < DN_QUEUE )
    {
        struct dn_datagram * d = &dn_inbound[dn_inbound_count++];
        d->address = *from;
        d->bytes = bytes;
        memcpy( d->data, data, (size_t) bytes );
    }
    struct dn_datagram * h = &dn_history[dn_history_count % DN_HISTORY];
    dn_history_count++;
    h->address = *from;
    h->bytes = bytes;
    memcpy( h->data, data, (size_t) bytes );
}

static int dn_seal( uint8_t * out, int type, int sequence_bytes, uint64_t sequence, const uint8_t * plaintext, int plaintext_bytes, const uint8_t * key )
{
    uint8_t prefix = (uint8_t) ( ( type & 0xF ) | ( sequence_bytes << 4 ) );
    uint8_t * p = out;
    *p++ = prefix;
    int i;
    for ( i = 0; i < sequence_bytes; i++ )
        *p++ = (uint8_t) ( sequence >> ( 8 * i ) );
    memcpy( p, plaintext, (size_t) plaintext_bytes );
    uint8_t additional[NETCODE_VERSION_INFO_BYTES + 8 + 1];
    {
        uint8_t * q = additional;
        netcode_write_bytes( &q, NETCODE_VERSION_INFO, NETCODE_VERSION_INFO_BYTES );
        netcode_write_uint64( &q, DN_PROTOCOL_ID );
        netcode_write_uint8( &q, prefix );
    }
    uint8_t nonce[12];
    {
        uint8_t * q = nonce;
        netcode_write_uint32( &q, 0 );
        netcode_write_uint64( &q, sequence );
    }
    DN_CHECK( netcode_encrypt_aead( p, (uint64_t) plaintext_bytes, additional, sizeof( additional ), nonce, key ) == NETCODE_OK );
    return (int) ( p - out ) + plaintext_bytes + NETCODE_MAC_BYTES;
}

static void dn_setup( void )
{
    if ( dn_ready )
        return;
    DN_CHECK( netcode_init() == NETCODE_OK );
#ifndef NDEBUG
    netcode_set_assert_function( dn_fuzz_assert_trip );
#endif
    netcode_set_printf_function( dn_fuzz_discard_printf );
    netcode_log_level( NETCODE_LOG_LEVEL_NONE );
    DN_CHECK( netcode_parse_address( "10.0.0.1:40000", &dn_server_a ) == NETCODE_OK );
    DN_CHECK( netcode_parse_address( "[fd00::2]:40001", &dn_server_b ) == NETCODE_OK );
    DN_CHECK( netcode_parse_address( "10.9.9.9:666", &dn_stranger ) == NETCODE_OK );
    memset( dn_c2s, 0x21, sizeof( dn_c2s ) );
    memset( dn_s2c, 0x43, sizeof( dn_s2c ) );

    struct netcode_connect_token_t token;
    memset( &token, 0, sizeof( token ) );
    memcpy( token.version_info, NETCODE_VERSION_INFO, NETCODE_VERSION_INFO_BYTES );
    token.protocol_id = DN_PROTOCOL_ID;
    token.create_timestamp = (uint64_t) time( NULL );
    token.expire_timestamp = token.create_timestamp + 30;
    memset( token.nonce, 0x11, NETCODE_CONNECT_TOKEN_NONCE_BYTES );
    memset( token.private_data, 0x99, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );
    token.timeout_seconds = 5;
    token.num_server_addresses = 2;
    token.server_addresses[0] = dn_server_a;
    token.server_addresses[1] = dn_server_b;
    memcpy( token.client_to_server_key, dn_c2s, NETCODE_KEY_BYTES );
    memcpy( token.server_to_client_key, dn_s2c, NETCODE_KEY_BYTES );
    netcode_write_connect_token( &token, dn_token, NETCODE_CONNECT_TOKEN_BYTES );
    dn_ready = 1;
}

static uint64_t dn_pick_sequence( struct dn_in * in )
{
    uint64_t base = dn_server_sequence;
    switch ( dn_u8( in ) % 11 )
    {
        case 0: return dn_server_sequence++;
        case 1: return 0;
        case 2: return base > 0 ? base - 1 : 0;
        case 3: return base >= NETCODE_REPLAY_PROTECTION_BUFFER_SIZE ? base - NETCODE_REPLAY_PROTECTION_BUFFER_SIZE : 0;
        case 4: return base >= NETCODE_REPLAY_PROTECTION_BUFFER_SIZE - 1 ? base - ( NETCODE_REPLAY_PROTECTION_BUFFER_SIZE - 1 ) : 0;
        case 5: return base + NETCODE_REPLAY_PROTECTION_BUFFER_SIZE + dn_u8( in );
        case 6: return UINT64_MAX;
        case 7: return UINT64_MAX - 1 - ( dn_u8( in ) % 4 );
        case 8: return ( 1ULL << 63 ) + dn_u8( in );
        case 9: return dn_u64( in );
        default: { uint64_t s = base + dn_u16( in ); dn_server_sequence = s + 1; return s; }
    }
}

static struct netcode_address_t * dn_pick_from( struct dn_in * in )
{
    uint8_t which = dn_u8( in ) % 8;
    if ( which == 0 )
        return &dn_stranger;
    if ( which == 1 )
        return &dn_server_b;
    return &dn_server_a;
}

static void dn_send_sealed( struct dn_in * in, int type, const uint8_t * plaintext, int bytes, int record )
{
    uint64_t sequence = dn_pick_sequence( in );
    int sequence_bytes = netcode_sequence_number_bytes_required( sequence );
    if ( dn_u8( in ) % 4 == 0 )
        sequence_bytes = 1 + dn_u8( in ) % 8;
    if ( sequence_bytes < 8 )
        sequence &= ( 1ULL << ( 8 * sequence_bytes ) ) - 1;
    const uint8_t * key = ( dn_u8( in ) % 16 == 0 ) ? dn_c2s : dn_s2c;   /* sometimes the wrong key */
    uint8_t packet[NETCODE_MAX_PACKET_BYTES + 64];
    int n = dn_seal( packet, type, sequence_bytes, sequence, plaintext, bytes, key );
    if ( n > NETCODE_MAX_PACKET_BYTES )
        return;
    struct netcode_address_t * from = dn_pick_from( in );
    /* anything sealed under the server-to-client key may come back as a replay from the right
       address, so all of it is authentic; nothing else is */
    if ( record && key == dn_s2c && dn_sealed_count < DN_LOG )
    {
        dn_sealed[dn_sealed_count].sequence = sequence;
        dn_sealed[dn_sealed_count].hash = dn_hash( plaintext, (size_t) bytes );
        dn_sealed[dn_sealed_count].received = 0;
        dn_sealed_count++;
    }
    dn_queue( from, packet, n );
}

static void dn_receive_all( void )
{
    while ( 1 )
    {
        int bytes = 0;
        uint64_t sequence = 0;
        uint8_t * payload = netcode_client_receive_packet( dn_client, &bytes, &sequence );
        if ( !payload )
            break;
        DN_CHECK( bytes >= 1 && bytes <= NETCODE_MAX_PAYLOAD_BYTES );
        uint64_t hash = dn_hash( payload, (size_t) bytes );
        int found = 0;
        int n;
        for ( n = 0; n < dn_sealed_count; n++ )
        {
            if ( dn_sealed[n].sequence != sequence )
                continue;
            DN_CHECK( !dn_sealed[n].received );   /* oracle 2: at most once */
            if ( dn_sealed[n].hash == hash )
                found = 1;
        }
        DN_CHECK( found || dn_sealed_count == DN_LOG );   /* oracle 2: sealed by the server */
        for ( n = 0; n < dn_sealed_count; n++ )
        {
            if ( dn_sealed[n].sequence == sequence )
                dn_sealed[n].received = 1;
        }
        dn_stat( 1, "payloads received" );
        netcode_client_free_packet( dn_client, payload );
    }
}

static void dn_update( double * time, double step )
{
    int before = netcode_client_state( dn_client );
    struct netcode_address_t before_address = dn_client->server_address;
    *time += step;
    netcode_client_update( dn_client, *time );
    dn_inbound_count = 0;
    dn_inbound_next = 0;
    int after = netcode_client_state( dn_client );
    if ( before == NETCODE_CLIENT_STATE_CONNECTED && after != NETCODE_CLIENT_STATE_CONNECTED )
    {
        /* oracle 4: a connected client that lost its server never moves on to the next one */
        DN_CHECK( after <= NETCODE_CLIENT_STATE_DISCONNECTED );
        dn_stat( 2, "connected sessions ended" );
    }
    if ( after == NETCODE_CLIENT_STATE_CONNECTED && before != NETCODE_CLIENT_STATE_CONNECTED )
        dn_stat( 3, "connected" );
    if ( before > NETCODE_CLIENT_STATE_DISCONNECTED && after > NETCODE_CLIENT_STATE_DISCONNECTED &&
         !netcode_address_equal( &before_address, &dn_client->server_address ) )
        dn_stat( 4, "moved to the next server" );
}

int LLVMFuzzerTestOneInput( const uint8_t * data, size_t size )
{
    dn_setup();
    struct dn_in in = { data, size, 0 };
    dn_inbound_count = dn_inbound_next = 0;
    dn_history_count = 0;
    dn_server_sequence = 0;
    dn_sealed_count = 0;
    dn_new_attempt();

    struct netcode_client_config_t config;
    netcode_default_client_config( &config );
    config.override_send_and_receive = 1;
    config.send_packet_override = dn_send_override;
    config.receive_packet_override = dn_receive_override;
    dn_client = netcode_client_create( "10.0.1.1:5000", &config, 0.0 );
    DN_CHECK( dn_client );
    netcode_client_connect( dn_client, dn_token );
    DN_CHECK( netcode_client_state( dn_client ) == NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST );

    double time = 0.0;
    int ops = 0;
    while ( dn_more( &in ) && ops++ < DN_MAX_OPS )
    {
        uint8_t op = dn_u8( &in );
        switch ( op % 13 )
        {
            case 0:
            case 1:
            {
                uint8_t plaintext[8 + NETCODE_CHALLENGE_TOKEN_BYTES];
                uint8_t * p = plaintext;
                netcode_write_uint64( &p, dn_u64( &in ) );
                memset( p, dn_u8( &in ), NETCODE_CHALLENGE_TOKEN_BYTES );
                dn_send_sealed( &in, NETCODE_CONNECTION_CHALLENGE_PACKET, plaintext, (int) sizeof( plaintext ), 0 );
                break;
            }
            case 2:
            case 3:
            {
                uint8_t plaintext[8];
                uint8_t * p = plaintext;
                uint8_t how = dn_u8( &in );
                netcode_write_uint32( &p, ( how & 1 ) ? dn_u32( &in ) : 0 );
                netcode_write_uint32( &p, ( how & 2 ) ? dn_u32( &in ) : 4 );
                dn_send_sealed( &in, NETCODE_CONNECTION_KEEP_ALIVE_PACKET, plaintext, 8, 0 );
                break;
            }
            case 4:
            case 5:
            {
                int bytes = 1 + dn_u16( &in ) % NETCODE_MAX_PAYLOAD_BYTES;
                uint8_t plaintext[NETCODE_MAX_PAYLOAD_BYTES];
                memset( plaintext, dn_u8( &in ), (size_t) bytes );
                plaintext[0] = (uint8_t) ops;
                dn_send_sealed( &in, NETCODE_CONNECTION_PAYLOAD_PACKET, plaintext, bytes, 1 );
                break;
            }
            case 6:
            {
                uint8_t empty[1] = { 0 };
                dn_send_sealed( &in, ( dn_u8( &in ) & 1 ) ? NETCODE_CONNECTION_DISCONNECT_PACKET : NETCODE_CONNECTION_DENIED_PACKET, empty, 0, 0 );
                break;
            }
            case 7:
            {
                int type = dn_u8( &in ) & 0xF;
                int bytes = dn_u16( &in ) % ( NETCODE_MAX_PAYLOAD_BYTES + 64 );
                uint8_t plaintext[NETCODE_MAX_PAYLOAD_BYTES + 64];
                dn_bytes( &in, plaintext, (size_t) ( bytes < 32 ? bytes : 32 ) );
                if ( bytes > 32 )
                    memset( plaintext + 32, 0x55, (size_t) ( bytes - 32 ) );
                dn_send_sealed( &in, type, plaintext, bytes, type == NETCODE_CONNECTION_PAYLOAD_PACKET );
                break;
            }
            case 8:
            {
                if ( dn_history_count == 0 )
                    break;
                int limit = dn_history_count < DN_HISTORY ? dn_history_count : DN_HISTORY;
                struct dn_datagram copy = dn_history[dn_u8( &in ) % limit];
                uint8_t how = dn_u8( &in );
                if ( ( how & 1 ) && copy.bytes > 0 )
                    copy.data[dn_u16( &in ) % copy.bytes] ^= (uint8_t) ( 1 + dn_u8( &in ) % 255 );
                if ( how & 2 )
                    copy.bytes = dn_u16( &in ) % ( copy.bytes + 1 );
                dn_queue( ( how & 4 ) ? dn_pick_from( &in ) : &copy.address, copy.data, copy.bytes );
                break;
            }
            case 9:
            {
                uint8_t raw[NETCODE_MAX_PACKET_BYTES];
                int bytes = dn_u16( &in ) % ( NETCODE_MAX_PACKET_BYTES + 1 );
                dn_bytes( &in, raw, (size_t) bytes );
                dn_queue( dn_pick_from( &in ), raw, bytes );
                break;
            }
            case 10:
            {
                static const double steps[8] = { 0.0, 0.01, 0.1, 0.5, 1.0, 2.0, 6.0, 40.0 };
                dn_update( &time, steps[dn_u8( &in ) % 8] );
                break;
            }
            case 11:
            {
                uint8_t what = dn_u8( &in ) % 4;
                if ( what == 0 )
                {
                    uint8_t payload[64];
                    memset( payload, 0x3C, sizeof( payload ) );
                    netcode_client_send_packet( dn_client, payload, 1 + dn_u8( &in ) % 64 );
                }
                else if ( what == 1 )
                {
                    dn_receive_all();
                }
                else if ( what == 2 )
                {
                    netcode_client_disconnect( dn_client );
                }
                else
                {
                    /* a new attempt: oracles 1 and 2 hold per attempt */
                    netcode_client_connect( dn_client, dn_token );
                    dn_new_attempt();
                    dn_server_sequence = 0;
                }
                break;
            }
            case 12:
                dn_receive_all();
                break;
        }
    }

    dn_update( &time, 0.01 );
    dn_receive_all();
    netcode_client_destroy( dn_client );
    dn_client = NULL;
    return 0;
}
