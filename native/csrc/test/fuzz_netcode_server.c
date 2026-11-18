/*
    dream-net: fuzz the netcode server's whole datagram entry point, with the session keys
    of every client known to the fuzzer. SPDX-License-Identifier: MIT OR Apache-2.0

    A unity build over the vendored netcode.c (see fuzz_support.h). The server runs exactly as
    dream-net runs it, through netcode_server_update, except that its socket is netcode's own
    send/receive override: datagrams the fuzzer chooses are what the override "receives", and
    everything the server sends is captured. No socket, no sleep, one process.

    The fuzz input is a script of operations by up to DN_TOKENS honest-but-hostile clients, each
    holding a valid connect token for this server (so its keys are known), and by off-path
    strangers:

    - the handshake, honestly (request, response to the captured challenge), from the token's
      own address or another one;
    - authenticated packets of every type (0..15) under the client's real key with hostile
      contents: wrong decrypted sizes, any sequence (0, the replay window's edges, far-future
      jumps, the reserved UINT64_MAX and its neighbours, reuse of a sequence already used),
      non-minimal sequence-byte counts;
    - replays of any datagram sent so far, from any address, with or without one flipped byte,
      and raw noise;
    - server time steps (timeouts, keep-alives), payload sends to slots, slot disconnects, and
      an in-process restart.

    Oracles (abort on violation), on top of ASan/UBSan and, in the asserts-live configuration,
    every netcode_assert:

    1. AEAD nonce uniqueness: no (server-to-client key, sequence) pair ever encrypts two
       datagrams, across sessions, reconnect attempts and restarts. A token's keys are used for
       exactly one session (C >= 1.4.5); a restart refuses tokens minted before it (the start
       floor, modelled by setting the floor as a real clock would).
    2. Replay: for each token, the server delivers each sequence number at most once, ever.
    3. Integrity: every delivered payload is byte-identical to one the fuzzer sealed under that
       client's key at that sequence; nothing reaches a slot that the client did not encrypt.
    4. Bounds: connected clients <= max_clients; encryption mappings and token history inside
       their fixed arrays; every datagram the server sends is at most NETCODE_MAX_PACKET_BYTES;
       a slot's identity (client id, user data) is the one of the token whose keys it uses.
*/

#include "netcode.c"

#define DN_FUZZ_NAME "fuzz_netcode_server"
#include "fuzz_support.h"

#include <time.h>

#define DN_PROTOCOL_ID 0x1122334455667788ULL
#define DN_TOKENS 6
#define DN_MAX_OPS 96
#define DN_QUEUE 64
#define DN_HISTORY 64
#define DN_NONCE_LOG 4096
#define DN_SENT_LOG 512

static uint8_t dn_private_key[NETCODE_KEY_BYTES];
static struct netcode_address_t dn_server_address;
static struct netcode_address_t dn_stranger;

struct dn_token
{
    uint64_t client_id;
    uint64_t expire_timestamp;
    int timeout_seconds;
    struct netcode_address_t address;
    uint8_t c2s[NETCODE_KEY_BYTES];
    uint8_t s2c[NETCODE_KEY_BYTES];
    uint8_t user_data[NETCODE_USER_DATA_BYTES];
    uint8_t request[NETCODE_MAX_PACKET_BYTES + 1];
    int request_bytes;
};

static struct dn_token dn_tokens[DN_TOKENS];
static int dn_ready;

/* per input */

struct dn_datagram
{
    struct netcode_address_t address;
    int bytes;
    uint8_t data[NETCODE_MAX_PACKET_BYTES];
};

static struct dn_datagram dn_inbound[DN_QUEUE];
static int dn_inbound_count;
static int dn_inbound_next;

static struct dn_datagram dn_outbound[DN_QUEUE * 4];
static int dn_outbound_count;

static struct dn_datagram dn_history[DN_HISTORY];
static int dn_history_count;

struct dn_peer
{
    uint64_t next_sequence;
    int have_challenge;
    uint64_t challenge_sequence;
    uint8_t challenge[NETCODE_CHALLENGE_TOKEN_BYTES];
};

static struct dn_peer dn_peers[DN_TOKENS];

/* (token, sequence) -> hash, for the server-to-client nonce oracle */
struct dn_nonce
{
    int token;
    uint64_t sequence;
    uint64_t hash;
    int epoch;
};
static struct dn_nonce dn_nonces[DN_NONCE_LOG];
static int dn_nonce_count;

/* payloads the fuzzer sealed, and the sequences the server delivered */
struct dn_sent
{
    int token;
    uint64_t sequence;
    uint64_t hash;
    int delivered;
    int epoch;
};
static struct dn_sent dn_sent[DN_SENT_LOG];
static int dn_sent_count;

static struct netcode_server_t * dn_server;
static int dn_restarts;

static void dn_send_override( void * context, struct netcode_address_t * to, NETCODE_CONST uint8_t * data, int bytes )
{
    (void) context;
    DN_CHECK( bytes > 0 && bytes <= NETCODE_MAX_PACKET_BYTES );
    if ( dn_outbound_count == (int) ( sizeof( dn_outbound ) / sizeof( dn_outbound[0] ) ) )
        return;
    struct dn_datagram * d = &dn_outbound[dn_outbound_count++];
    d->address = *to;
    d->bytes = bytes;
    memcpy( d->data, data, (size_t) bytes );
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

static void dn_connect_callback( void * context, int client_index, int connected )
{
    (void) context;
    DN_CHECK( client_index >= 0 && client_index < NETCODE_MAX_CLIENTS );
    dn_stat( connected ? 0 : 1, connected ? "connects" : "disconnects" );
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

/* Seals an encrypted netcode packet exactly as netcode_write_packet frames one, but with any
   type nibble, any count of sequence bytes and any plaintext. Returns its length. */
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

static void dn_setup_tokens( void )
{
    if ( dn_ready )
        return;
    DN_CHECK( netcode_init() == NETCODE_OK );
#ifndef NDEBUG
    netcode_set_assert_function( dn_fuzz_assert_trip );
#endif
    netcode_set_printf_function( dn_fuzz_discard_printf );
    netcode_log_level( NETCODE_LOG_LEVEL_NONE );

    memset( dn_private_key, 0x5A, sizeof( dn_private_key ) );
    DN_CHECK( netcode_parse_address( "10.0.0.1:40000", &dn_server_address ) == NETCODE_OK );
    DN_CHECK( netcode_parse_address( "10.9.9.9:666", &dn_stranger ) == NETCODE_OK );

    uint64_t now = (uint64_t) time( NULL );
    int t;
    for ( t = 0; t < DN_TOKENS; t++ )
    {
        struct dn_token * k = &dn_tokens[t];
        char address[64];
        snprintf( address, sizeof( address ), "10.0.1.%d:%d", t + 1, 5000 + t );
        DN_CHECK( netcode_parse_address( address, &k->address ) == NETCODE_OK );
        k->client_id = 1000 + (uint64_t) t;
        k->expire_timestamp = ( t == DN_TOKENS - 1 ) ? UINT64_MAX : now + 3600;
        k->timeout_seconds = ( t % 3 == 2 ) ? -1 : 5;
        memset( k->c2s, 0x10 + t, sizeof( k->c2s ) );
        memset( k->s2c, 0x60 + t, sizeof( k->s2c ) );
        memset( k->user_data, 0xA0 + t, sizeof( k->user_data ) );

        struct netcode_connect_token_private_t private_part;
        memset( &private_part, 0, sizeof( private_part ) );
        private_part.client_id = k->client_id;
        private_part.timeout_seconds = k->timeout_seconds;
        private_part.num_server_addresses = 1;
        private_part.server_addresses[0] = dn_server_address;
        memcpy( private_part.client_to_server_key, k->c2s, NETCODE_KEY_BYTES );
        memcpy( private_part.server_to_client_key, k->s2c, NETCODE_KEY_BYTES );
        memcpy( private_part.user_data, k->user_data, NETCODE_USER_DATA_BYTES );

        struct netcode_connection_request_packet_t request;
        memset( &request, 0, sizeof( request ) );
        request.packet_type = NETCODE_CONNECTION_REQUEST_PACKET;
        memcpy( request.version_info, NETCODE_VERSION_INFO, NETCODE_VERSION_INFO_BYTES );
        request.protocol_id = DN_PROTOCOL_ID;
        request.connect_token_expire_timestamp = k->expire_timestamp;
        memset( request.connect_token_nonce, 0x30 + t, NETCODE_CONNECT_TOKEN_NONCE_BYTES );
        netcode_write_connect_token_private( &private_part, request.connect_token_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );
        DN_CHECK( netcode_encrypt_connect_token_private( request.connect_token_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES, NETCODE_VERSION_INFO,
                                                         DN_PROTOCOL_ID, k->expire_timestamp, request.connect_token_nonce, dn_private_key ) == NETCODE_OK );
        uint8_t ignored_key[NETCODE_KEY_BYTES];
        memset( ignored_key, 0, sizeof( ignored_key ) );
        k->request_bytes = netcode_write_packet( &request, k->request, (int) sizeof( k->request ), 0, ignored_key, DN_PROTOCOL_ID );
        DN_CHECK( k->request_bytes == 1078 );
    }
    dn_ready = 1;
}

/* The floor a real clock would set: tokens are minted one second after the start. */
static void dn_start_floor( uint64_t floor )
{
    dn_server->min_connect_token_expire_timestamp = floor;
}

static int dn_token_of_client_id( uint64_t client_id )
{
    if ( client_id < 1000 || client_id >= 1000 + DN_TOKENS )
        return -1;
    return (int) ( client_id - 1000 );
}

static void dn_check_bounds( void )
{
    struct netcode_server_t * s = dn_server;
    DN_CHECK( s->num_connected_clients >= 0 && s->num_connected_clients <= s->max_clients );
    DN_CHECK( s->encryption_manager.num_encryption_mappings >= 0 && s->encryption_manager.num_encryption_mappings <= NETCODE_MAX_ENCRYPTION_MAPPINGS );
    int connected = 0;
    int i;
    for ( i = 0; i < s->max_clients; i++ )
    {
        if ( !s->client_connected[i] )
            continue;
        connected++;
        int t = dn_token_of_client_id( s->client_id[i] );
        DN_CHECK( t >= 0 );
        int e = s->client_encryption_index[i];
        DN_CHECK( e >= 0 && e < s->encryption_manager.num_encryption_mappings );
        DN_CHECK( s->encryption_manager.client_index[e] == i );
        /* the slot's identity is the one of the token whose keys it uses */
        DN_CHECK( memcmp( s->encryption_manager.receive_key + e * NETCODE_KEY_BYTES, dn_tokens[t].c2s, NETCODE_KEY_BYTES ) == 0 );
        DN_CHECK( memcmp( s->encryption_manager.send_key + e * NETCODE_KEY_BYTES, dn_tokens[t].s2c, NETCODE_KEY_BYTES ) == 0 );
        DN_CHECK( memcmp( s->client_user_data[i], dn_tokens[t].user_data, NETCODE_USER_DATA_BYTES ) == 0 );
        /* (the address is whichever one the token's holder completed the handshake from) */
    }
    DN_CHECK( connected == s->num_connected_clients );
}

/* Reads what the server sent: the nonce oracle, then the client side of the handshake. */
static void dn_take_outbound( void )
{
    int i;
    for ( i = 0; i < dn_outbound_count; i++ )
    {
        struct dn_datagram * d = &dn_outbound[i];
        DN_CHECK( d->bytes >= 1 + 1 + NETCODE_MAC_BYTES );

        /* every packet the server sends is encrypted under the server-to-client key of exactly
           one token: find it by decrypting (the destination may be a thief's address) */
        uint8_t allowed[NETCODE_CONNECTION_NUM_PACKETS];
        memset( allowed, 0, sizeof( allowed ) );
        allowed[NETCODE_CONNECTION_DENIED_PACKET] = 1;
        allowed[NETCODE_CONNECTION_CHALLENGE_PACKET] = 1;
        allowed[NETCODE_CONNECTION_KEEP_ALIVE_PACKET] = 1;
        allowed[NETCODE_CONNECTION_PAYLOAD_PACKET] = 1;
        allowed[NETCODE_CONNECTION_DISCONNECT_PACKET] = 1;
        void * packet = NULL;
        uint64_t sequence = 0;
        int t;
        for ( t = 0; t < DN_TOKENS && !packet; t++ )
        {
            uint8_t copy[NETCODE_MAX_PACKET_BYTES];
            memcpy( copy, d->data, (size_t) d->bytes );
            packet = netcode_read_packet( copy, d->bytes, &sequence, dn_tokens[t].s2c, DN_PROTOCOL_ID, 0, 0, NULL, allowed,
                                          NULL, NULL, NULL );
        }
        t--;
        DN_CHECK( packet != NULL );

        /* oracle 1: a (key, nonce) pair is never used twice, not even for the same bytes */
        uint64_t hash = dn_hash( d->data, (size_t) d->bytes );
        int n;
        for ( n = 0; n < dn_nonce_count; n++ )
        {
            /* the documented residual: a token that never expires passes the start floor, so
               a restart on the same key reopens it (netcode.h, netcode_generate_connect_token;
               dream-net's Server docs). Only within one run is it checked. */
            if ( dn_tokens[t].expire_timestamp == UINT64_MAX && dn_nonces[n].epoch != dn_restarts )
                continue;
            if ( dn_nonces[n].token == t && dn_nonces[n].sequence == sequence )
                fprintf( stderr, "nonce reuse: token %d sequence %llx type %d restarts %d same bytes %d\n", t,
                         (unsigned long long) sequence, ( (uint8_t*) packet )[0], dn_restarts, dn_nonces[n].hash == hash );
            DN_CHECK( !( dn_nonces[n].token == t && dn_nonces[n].sequence == sequence ) );
        }
        if ( dn_nonce_count < DN_NONCE_LOG )
        {
            dn_nonces[dn_nonce_count].token = t;
            dn_nonces[dn_nonce_count].sequence = sequence;
            dn_nonces[dn_nonce_count].hash = hash;
            dn_nonces[dn_nonce_count].epoch = dn_restarts;
            dn_nonce_count++;
        }

        /* the token's holder reads it */
        uint8_t type = ( (uint8_t*) packet )[0];
        if ( type == NETCODE_CONNECTION_CHALLENGE_PACKET )
        {
            dn_stat( 3, "challenges" );
            struct netcode_connection_challenge_packet_t * c = (struct netcode_connection_challenge_packet_t*) packet;
            dn_peers[t].have_challenge = 1;
            dn_peers[t].challenge_sequence = c->challenge_token_sequence;
            memcpy( dn_peers[t].challenge, c->challenge_token_data, NETCODE_CHALLENGE_TOKEN_BYTES );
        }
        free( packet );
    }
    dn_outbound_count = 0;
}

static void dn_update( double * time, double step )
{
    *time += step;
    netcode_server_update( dn_server, *time );
    dn_inbound_count = 0;
    dn_inbound_next = 0;
    dn_take_outbound();
    dn_check_bounds();
}

/* Drains every slot: the replay and integrity oracles. */
static void dn_drain( void )
{
    int i;
    for ( i = 0; i < dn_server->max_clients; i++ )
    {
        while ( 1 )
        {
            int bytes = 0;
            uint64_t sequence = 0;
            uint8_t * payload = netcode_server_receive_packet( dn_server, i, &bytes, &sequence );
            if ( !payload )
                break;
            DN_CHECK( bytes >= 1 && bytes <= NETCODE_MAX_PAYLOAD_BYTES );
            int t = dn_token_of_client_id( dn_server->client_id[i] );
            DN_CHECK( t >= 0 );
            uint64_t hash = dn_hash( payload, (size_t) bytes );
            int found = 0;
            int n;
            for ( n = 0; n < dn_sent_count; n++ )
            {
                struct dn_sent * s = &dn_sent[n];
                if ( s->token != t || s->sequence != sequence )
                    continue;
                /* the never-expiring token's documented residual, as in the nonce oracle */
                if ( dn_tokens[t].expire_timestamp == UINT64_MAX && s->delivered && s->epoch != dn_restarts )
                    continue;
                /* oracle 2: one delivery per sequence per token, ever */
                DN_CHECK( !s->delivered );
                if ( s->hash == hash )
                    found = 1;
            }
            /* oracle 3: the payload is one the token's holder sealed at that sequence */
            DN_CHECK( found || dn_sent_count == DN_SENT_LOG );
            for ( n = 0; n < dn_sent_count; n++ )
            {
                if ( dn_sent[n].token == t && dn_sent[n].sequence == sequence )
                {
                    dn_sent[n].delivered = 1;
                    dn_sent[n].epoch = dn_restarts;
                }
            }
            dn_stat( 2, "payloads delivered" );
            netcode_server_free_packet( dn_server, payload );
        }
    }
}

static uint64_t dn_pick_sequence( struct dn_in * in, struct dn_peer * peer )
{
    uint8_t mode = dn_u8( in );
    uint64_t base = peer->next_sequence;
    switch ( mode % 12 )
    {
        case 0: return peer->next_sequence++;
        case 1: return 0;
        case 2: return base > 0 ? base - 1 : 0;                                         /* reuse */
        case 3: return base >= NETCODE_REPLAY_PROTECTION_BUFFER_SIZE ? base - NETCODE_REPLAY_PROTECTION_BUFFER_SIZE : 0;
        case 4: return base >= NETCODE_REPLAY_PROTECTION_BUFFER_SIZE - 1 ? base - ( NETCODE_REPLAY_PROTECTION_BUFFER_SIZE - 1 ) : 0;
        case 5: return base + NETCODE_REPLAY_PROTECTION_BUFFER_SIZE + ( dn_u8( in ) );   /* far ahead */
        case 6: return UINT64_MAX;                                                         /* reserved */
        case 7: return UINT64_MAX - 1 - ( dn_u8( in ) % 4 );                               /* near the top */
        case 8: return ( 1ULL << 63 ) + dn_u8( in );                                       /* the global range */
        case 9: return dn_u64( in );
        case 10: { uint64_t s = base + dn_u16( in ); peer->next_sequence = s + 1; return s; }
        default: return peer->next_sequence++;
    }
}

static int dn_sequence_bytes( struct dn_in * in, uint64_t sequence )
{
    int minimal = netcode_sequence_number_bytes_required( sequence );
    if ( dn_u8( in ) % 4 == 0 )
    {
        int n = 1 + dn_u8( in ) % 8;
        /* fewer bytes than needed would change the sequence: still a valid frame */
        return n;
    }
    return minimal;
}

static struct netcode_address_t * dn_pick_from( struct dn_in * in, int t )
{
    uint8_t which = dn_u8( in ) % 8;
    if ( which == 0 )
        return &dn_stranger;
    if ( which == 1 )
        return &dn_tokens[( t + 1 ) % DN_TOKENS].address;
    return &dn_tokens[t].address;
}

static void dn_send_sealed( struct dn_in * in, int t, int type, const uint8_t * plaintext, int bytes, int record_payload )
{
    struct dn_peer * peer = &dn_peers[t];
    uint64_t sequence = dn_pick_sequence( in, peer );
    int sequence_bytes = dn_sequence_bytes( in, sequence );
    uint64_t on_wire = sequence;
    if ( sequence_bytes < 8 )
        on_wire &= ( 1ULL << ( 8 * sequence_bytes ) ) - 1;
    uint8_t packet[NETCODE_MAX_PACKET_BYTES + 64];
    int n = dn_seal( packet, type, sequence_bytes, on_wire, plaintext, bytes, dn_tokens[t].c2s );
    if ( n > NETCODE_MAX_PACKET_BYTES )
        return;
    if ( record_payload && dn_sent_count < DN_SENT_LOG )
    {
        dn_sent[dn_sent_count].token = t;
        dn_sent[dn_sent_count].sequence = on_wire;
        dn_sent[dn_sent_count].hash = dn_hash( plaintext, (size_t) bytes );
        dn_sent[dn_sent_count].delivered = 0;
        dn_sent[dn_sent_count].epoch = dn_restarts;
        /* a sequence already delivered stays delivered: copy the flag */
        int k;
        for ( k = 0; k < dn_sent_count; k++ )
        {
            if ( dn_sent[k].token == t && dn_sent[k].sequence == on_wire && dn_sent[k].delivered )
            {
                dn_sent[dn_sent_count].delivered = 1;
                dn_sent[dn_sent_count].epoch = dn_sent[k].epoch;
            }
        }
        dn_sent_count++;
    }
    dn_queue( dn_pick_from( in, t ), packet, n );
}

int LLVMFuzzerTestOneInput( const uint8_t * data, size_t size )
{
    dn_setup_tokens();

    struct dn_in in = { data, size, 0 };

    dn_inbound_count = dn_inbound_next = dn_outbound_count = 0;
    dn_history_count = 0;
    dn_nonce_count = 0;
    dn_sent_count = 0;
    dn_restarts = 0;
    memset( dn_peers, 0, sizeof( dn_peers ) );
    int t;

    struct netcode_server_config_t config;
    netcode_default_server_config( &config );
    config.protocol_id = DN_PROTOCOL_ID;
    memcpy( config.private_key, dn_private_key, NETCODE_KEY_BYTES );
    config.override_send_and_receive = 1;
    config.send_packet_override = dn_send_override;
    config.receive_packet_override = dn_receive_override;
    config.connect_disconnect_callback = dn_connect_callback;
    config.max_connect_token_lifetime = 3600;

    dn_server = netcode_server_create( "10.0.0.1:40000", &config, 0.0 );
    DN_CHECK( dn_server );
    int max_clients = 1 + dn_u8( &in ) % 4;
    netcode_server_start( dn_server, max_clients );
    /* every token here was minted after this start */
    dn_start_floor( dn_tokens[0].expire_timestamp - 1 );

    double time = 0.0;
    int ops = 0;
    while ( dn_more( &in ) && ops++ < DN_MAX_OPS )
    {
        uint8_t op = dn_u8( &in );
        t = dn_u8( &in ) % DN_TOKENS;
        struct dn_peer * peer = &dn_peers[t];
        switch ( op % 14 )
        {
            case 0:
            case 1:
                /* the connection request, as the token's holder (or a thief replaying it) */
                dn_queue( dn_pick_from( &in, t ), dn_tokens[t].request, dn_tokens[t].request_bytes );
                break;

            case 2:
            case 3:
                /* the response to the captured challenge, honestly framed */
                if ( peer->have_challenge )
                {
                    uint8_t plaintext[8 + NETCODE_CHALLENGE_TOKEN_BYTES];
                    uint8_t * p = plaintext;
                    netcode_write_uint64( &p, peer->challenge_sequence );
                    memcpy( p, peer->challenge, NETCODE_CHALLENGE_TOKEN_BYTES );
                    dn_send_sealed( &in, t, NETCODE_CONNECTION_RESPONSE_PACKET, plaintext, (int) sizeof( plaintext ), 0 );
                }
                break;

            case 4:
            case 5:
            {
                /* a payload, any sequence */
                int bytes = 1 + dn_u16( &in ) % NETCODE_MAX_PAYLOAD_BYTES;
                uint8_t plaintext[NETCODE_MAX_PAYLOAD_BYTES];
                memset( plaintext, dn_u8( &in ), (size_t) bytes );
                plaintext[0] = (uint8_t) ops;
                dn_send_sealed( &in, t, NETCODE_CONNECTION_PAYLOAD_PACKET, plaintext, bytes, 1 );
                break;
            }

            case 6:
            {
                /* keep-alive or disconnect */
                uint8_t plaintext[8];
                memset( plaintext, 0, sizeof( plaintext ) );
                if ( dn_u8( &in ) & 1 )
                    dn_send_sealed( &in, t, NETCODE_CONNECTION_KEEP_ALIVE_PACKET, plaintext, 8, 0 );
                else
                    dn_send_sealed( &in, t, NETCODE_CONNECTION_DISCONNECT_PACKET, plaintext, 0, 0 );
                break;
            }

            case 7:
            {
                /* authenticated and malformed: any type nibble, any decrypted size */
                int type = dn_u8( &in ) & 0xF;
                int bytes = dn_u16( &in ) % ( NETCODE_MAX_PAYLOAD_BYTES + 64 );
                uint8_t plaintext[NETCODE_MAX_PAYLOAD_BYTES + 64];
                dn_bytes( &in, plaintext, (size_t) ( bytes < 32 ? bytes : 32 ) );
                if ( bytes > 32 )
                    memset( plaintext + 32, 0x77, (size_t) ( bytes - 32 ) );
                dn_send_sealed( &in, t, type, plaintext, bytes, type == NETCODE_CONNECTION_PAYLOAD_PACKET );
                break;
            }

            case 8:
            {
                /* replay any datagram sent so far, maybe from elsewhere, maybe with a flip */
                if ( dn_history_count == 0 )
                    break;
                int limit = dn_history_count < DN_HISTORY ? dn_history_count : DN_HISTORY;
                struct dn_datagram copy = dn_history[dn_u8( &in ) % limit];
                uint8_t how = dn_u8( &in );
                if ( ( how & 1 ) && copy.bytes > 0 )
                    copy.data[dn_u16( &in ) % copy.bytes] ^= (uint8_t) ( 1 + dn_u8( &in ) % 255 );
                if ( how & 2 )
                    copy.bytes = dn_u16( &in ) % ( copy.bytes + 1 );
                const struct netcode_address_t * from = ( how & 4 ) ? dn_pick_from( &in, t ) : &copy.address;
                dn_queue( from, copy.data, copy.bytes );
                break;
            }

            case 9:
            {
                /* raw noise from anyone */
                uint8_t raw[NETCODE_MAX_PACKET_BYTES];
                int bytes = dn_u16( &in ) % ( NETCODE_MAX_PACKET_BYTES + 1 );
                dn_bytes( &in, raw, (size_t) bytes );
                dn_queue( dn_pick_from( &in, t ), raw, bytes );
                break;
            }

            case 10:
            {
                static const double steps[8] = { 0.0, 0.01, 0.1, 0.5, 1.0, 2.0, 6.0, 40.0 };
                dn_update( &time, steps[dn_u8( &in ) % 8] );
                break;
            }

            case 11:
                dn_drain();
                break;

            case 12:
            {
                /* the server's own actions */
                int slot = dn_u8( &in ) % NETCODE_MAX_CLIENTS;
                uint8_t what = dn_u8( &in ) % 4;
                if ( what == 0 )
                {
                    uint8_t payload[64];
                    memset( payload, (int) slot, sizeof( payload ) );
                    if ( slot < dn_server->max_clients )
                        netcode_server_send_packet( dn_server, slot, payload, 1 + dn_u8( &in ) % 64 );
                }
                else if ( what == 1 )
                {
                    if ( slot < dn_server->max_clients )
                        netcode_server_disconnect_client( dn_server, slot );
                }
                else if ( what == 2 )
                {
                    netcode_server_disconnect_all_clients( dn_server );
                }
                dn_take_outbound();
                dn_check_bounds();
                break;
            }

            case 13:
            {
                /* restart in-process: every token here was minted before it, so all are
                   refused from now on (the floor a real clock one hour later would set) */
                if ( dn_u8( &in ) % 4 != 0 )
                    break;
                netcode_server_stop( dn_server );
                dn_take_outbound();
                dn_restarts++;
                netcode_server_start( dn_server, 1 + dn_u8( &in ) % 4 );
                dn_stat( 4, "restarts" );
                dn_start_floor( UINT64_MAX - 1 );
                dn_take_outbound();
                int k;
                for ( k = 0; k < DN_TOKENS; k++ )
                    dn_peers[k].have_challenge = 0;
                dn_check_bounds();
                break;
            }
        }
    }

    dn_update( &time, 0.01 );
    dn_drain();
    netcode_server_destroy( dn_server );
    dn_server = NULL;
    dn_take_outbound();
    return 0;
}
