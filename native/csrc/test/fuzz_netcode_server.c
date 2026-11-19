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

    - the handshake, honestly (request with the attempt's client salt, response to the captured
      challenge under the per-connection key derived from that salt and the challenge's server
      nonce), from the token's own address or another one, and new attempts with the same
      token under a fresh client salt (the retried handshake of GHSA-8mrq-q9c6-h23v);
    - authenticated packets of every type (0..15) under the client's derived key (or, before a
      challenge, the token's root key) with hostile contents: wrong decrypted sizes, any
      sequence (0, the replay window's edges, far-future jumps, the reserved UINT64_MAX and its
      neighbours, reuse of a sequence already used), non-minimal sequence-byte counts;
    - packets sealed directly under the token's root key, as NETCODE 1.02 framed them;
    - replays of any datagram sent so far, from any address, with or without one flipped byte,
      and raw noise;
    - server time steps (timeouts, keep-alives), payload sends to slots, slot disconnects, and
      an in-process restart.

    Oracles (abort on violation), on top of ASan/UBSan and, in the asserts-live configuration,
    every netcode_assert:

    1. AEAD nonce uniqueness: no (server-to-client packet key, sequence) pair ever encrypts two
       datagrams, across sessions, retried attempts with one token, and restarts. Under NETCODE
       1.03 every packet key is derived per attempt (HChaCha20 over the token key, the client
       salt and a fresh server nonce), so this holds even for a token that never expires and
       is presented again after a restart, which NETCODE 1.02 could not promise.
    2. Replay: for each token, the server delivers each sequence number at most once in a run.
    3. Integrity: every delivered payload is byte-identical to one the fuzzer sealed under that
       client's derived key at that sequence; nothing reaches a slot that the client did not
       encrypt, and nothing sealed under a token's root key is ever delivered.
    4. Bounds: connected clients <= max_clients; encryption mappings and token history inside
       their fixed arrays; every datagram the server sends is at most NETCODE_MAX_PACKET_BYTES;
       a slot's identity (client id, user data) is the one of the token whose keys it uses.
    5. Key derivation: every connected slot's keys are exactly HChaCha20 of its token's root
       keys over the mapping's client salt and server nonce, and no encryption mapping ever
       holds a token's root key.
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
    uint8_t token_nonce[NETCODE_CONNECT_TOKEN_NONCE_BYTES];
    uint8_t private_data[NETCODE_CONNECT_TOKEN_PRIVATE_BYTES];
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

#define DN_SALTS 16
#define DN_PAIRS 192

struct dn_peer
{
    uint64_t next_sequence;
    /* the current attempt: its client salt and, once a challenge for it arrived, the server
       nonce and the packet keys derived from both */
    uint8_t salt[NETCODE_CONNECT_SALT_BYTES];
    int have_challenge;
    uint8_t server_nonce[NETCODE_SERVER_NONCE_BYTES];
    uint8_t c2s[NETCODE_KEY_BYTES];
    uint8_t s2c[NETCODE_KEY_BYTES];
    uint64_t challenge_sequence;
    uint8_t challenge[NETCODE_CHALLENGE_TOKEN_BYTES];
    /* every client salt this token's holder used in this input, the current one last */
    uint8_t salts[DN_SALTS][NETCODE_CONNECT_SALT_BYTES];
    int salt_count;
};

static struct dn_peer dn_peers[DN_TOKENS];

/* every (client salt, server nonce) pair the server answered a token's holder under, with the
   server-to-client packet key derived from it: how the fuzzer reads what the server sends */
struct dn_pair
{
    uint8_t salt[NETCODE_CONNECT_SALT_BYTES];
    uint8_t server_nonce[NETCODE_SERVER_NONCE_BYTES];
    uint8_t s2c[NETCODE_KEY_BYTES];
};
static struct dn_pair dn_pairs[DN_TOKENS][DN_PAIRS];
static int dn_pair_count[DN_TOKENS];

/* (packet key, sequence) -> hash, for the server-to-client nonce oracle */
struct dn_nonce
{
    int token;
    uint64_t key;
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

        memset( k->token_nonce, 0x30 + t, NETCODE_CONNECT_TOKEN_NONCE_BYTES );
        netcode_write_connect_token_private( &private_part, k->private_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );
        DN_CHECK( netcode_encrypt_connect_token_private( k->private_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES, NETCODE_VERSION_INFO,
                                                         DN_PROTOCOL_ID, k->expire_timestamp, k->token_nonce, dn_private_key ) == NETCODE_OK );
    }
    dn_ready = 1;
}

/* Starts a new attempt for token t's holder: a fresh client salt, no challenge yet. Returns 0
   once the holder has used DN_SALTS salts in this input (the attempt then keeps its salt). */
static int dn_new_attempt( int t )
{
    struct dn_peer * peer = &dn_peers[t];
    if ( peer->salt_count == DN_SALTS )
        return 0;
    int i;
    for ( i = 0; i < NETCODE_CONNECT_SALT_BYTES; i++ )
        peer->salt[i] = (uint8_t) ( 0xC0 ^ ( t << 4 ) ^ peer->salt_count ^ ( i * 37 ) );
    memcpy( peer->salts[peer->salt_count++], peer->salt, NETCODE_CONNECT_SALT_BYTES );
    peer->have_challenge = 0;
    return 1;
}

/* The connection request of token t's holder for its current attempt. Returns its length. */
static int dn_request( int t, uint8_t * out, int out_bytes )
{
    struct dn_token * k = &dn_tokens[t];
    struct netcode_connection_request_packet_t request;
    memset( &request, 0, sizeof( request ) );
    request.packet_type = NETCODE_CONNECTION_REQUEST_PACKET;
    memcpy( request.version_info, NETCODE_VERSION_INFO, NETCODE_VERSION_INFO_BYTES );
    request.protocol_id = DN_PROTOCOL_ID;
    request.connect_token_expire_timestamp = k->expire_timestamp;
    memcpy( request.connect_token_nonce, k->token_nonce, NETCODE_CONNECT_TOKEN_NONCE_BYTES );
    memcpy( request.connect_token_data, k->private_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );
    memcpy( request.client_salt, dn_peers[t].salt, NETCODE_CONNECT_SALT_BYTES );
    uint8_t ignored_key[NETCODE_KEY_BYTES];
    memset( ignored_key, 0, sizeof( ignored_key ) );
    int bytes = netcode_write_packet( &request, out, out_bytes, 0, ignored_key, DN_PROTOCOL_ID );
    DN_CHECK( bytes == 1086 );
    return bytes;
}

/* Records that the server answered token t's holder under (salt, server nonce); returns the
   pair's index, or -1 when the log is full. */
static int dn_log_pair( int t, const uint8_t * salt, const uint8_t * server_nonce, const uint8_t * s2c )
{
    int i;
    for ( i = 0; i < dn_pair_count[t]; i++ )
    {
        if ( memcmp( dn_pairs[t][i].salt, salt, NETCODE_CONNECT_SALT_BYTES ) == 0 &&
             memcmp( dn_pairs[t][i].server_nonce, server_nonce, NETCODE_SERVER_NONCE_BYTES ) == 0 )
            return i;
    }
    if ( dn_pair_count[t] == DN_PAIRS )
        return -1;
    struct dn_pair * p = &dn_pairs[t][dn_pair_count[t]];
    memcpy( p->salt, salt, NETCODE_CONNECT_SALT_BYTES );
    memcpy( p->server_nonce, server_nonce, NETCODE_SERVER_NONCE_BYTES );
    memcpy( p->s2c, s2c, NETCODE_KEY_BYTES );
    return dn_pair_count[t]++;
}

static int dn_pairs_full( void )
{
    int t;
    for ( t = 0; t < DN_TOKENS; t++ )
        if ( dn_pair_count[t] == DN_PAIRS )
            return 1;
    return 0;
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
        /* the slot's identity is the one of the token whose keys it uses, and its keys are
           derived from that token's root keys over the mapping's salt and nonce (oracle 5) */
        uint8_t c2s[NETCODE_KEY_BYTES], s2c[NETCODE_KEY_BYTES];
        netcode_derive_packet_key( c2s, dn_tokens[t].c2s, s->encryption_manager.client_salt + e * NETCODE_CONNECT_SALT_BYTES,
                                   s->encryption_manager.server_nonce + e * NETCODE_SERVER_NONCE_BYTES );
        netcode_derive_packet_key( s2c, dn_tokens[t].s2c, s->encryption_manager.client_salt + e * NETCODE_CONNECT_SALT_BYTES,
                                   s->encryption_manager.server_nonce + e * NETCODE_SERVER_NONCE_BYTES );
        DN_CHECK( memcmp( s->encryption_manager.receive_key + e * NETCODE_KEY_BYTES, c2s, NETCODE_KEY_BYTES ) == 0 );
        DN_CHECK( memcmp( s->encryption_manager.send_key + e * NETCODE_KEY_BYTES, s2c, NETCODE_KEY_BYTES ) == 0 );
        DN_CHECK( memcmp( s->client_user_data[i], dn_tokens[t].user_data, NETCODE_USER_DATA_BYTES ) == 0 );
        /* (the address is whichever one the token's holder completed the handshake from) */
    }
    DN_CHECK( connected == s->num_connected_clients );
    /* oracle 5: no mapping, connected or half open, ever keys packets with a root key */
    int e;
    for ( e = 0; e < s->encryption_manager.num_encryption_mappings; e++ )
    {
        int t;
        for ( t = 0; t < DN_TOKENS; t++ )
        {
            DN_CHECK( memcmp( s->encryption_manager.receive_key + e * NETCODE_KEY_BYTES, dn_tokens[t].c2s, NETCODE_KEY_BYTES ) != 0 );
            DN_CHECK( memcmp( s->encryption_manager.send_key + e * NETCODE_KEY_BYTES, dn_tokens[t].s2c, NETCODE_KEY_BYTES ) != 0 );
        }
    }
}

/* Reads what the server sent: the nonce oracle, then the client side of the handshake. */
static void dn_take_outbound( void )
{
    int i;
    for ( i = 0; i < dn_outbound_count; i++ )
    {
        struct dn_datagram * d = &dn_outbound[i];
        DN_CHECK( d->bytes >= 1 + 1 + NETCODE_MAC_BYTES );

        /* every packet the server sends is encrypted under a packet key derived from exactly
           one token's server-to-client key: find it by decrypting (the destination may be a
           thief's address). A denied or challenge packet names its server nonce in clear, and
           its key is derived from one of the client salts the token's holder sent; any other
           packet is keyed by a (salt, nonce) pair a challenge already established. */
        uint8_t allowed[NETCODE_CONNECTION_NUM_PACKETS];
        memset( allowed, 0, sizeof( allowed ) );
        allowed[NETCODE_CONNECTION_DENIED_PACKET] = 1;
        allowed[NETCODE_CONNECTION_CHALLENGE_PACKET] = 1;
        allowed[NETCODE_CONNECTION_KEEP_ALIVE_PACKET] = 1;
        allowed[NETCODE_CONNECTION_PAYLOAD_PACKET] = 1;
        allowed[NETCODE_CONNECTION_DISCONNECT_PACKET] = 1;
        void * packet = NULL;
        uint64_t sequence = 0;
        uint8_t key[NETCODE_KEY_BYTES];
        int t = 0;
        int salt_index = -1;
        int prefix_type = d->data[0] & 0xF;
        int sequence_bytes = d->data[0] >> 4;
        if ( prefix_type == NETCODE_CONNECTION_DENIED_PACKET || prefix_type == NETCODE_CONNECTION_CHALLENGE_PACKET )
        {
            DN_CHECK( sequence_bytes >= 1 && sequence_bytes <= 8 );
            DN_CHECK( d->bytes >= 1 + sequence_bytes + NETCODE_SERVER_NONCE_BYTES + NETCODE_MAC_BYTES );
            const uint8_t * server_nonce = d->data + 1 + sequence_bytes;
            for ( t = 0; t < DN_TOKENS && !packet; t++ )
            {
                for ( salt_index = dn_peers[t].salt_count - 1; salt_index >= 0 && !packet; salt_index-- )
                {
                    netcode_derive_packet_key( key, dn_tokens[t].s2c, dn_peers[t].salts[salt_index], server_nonce );
                    uint8_t copy[NETCODE_MAX_PACKET_BYTES];
                    memcpy( copy, d->data, (size_t) d->bytes );
                    packet = netcode_read_packet( copy, d->bytes, &sequence, key, DN_PROTOCOL_ID, 0, 0, NULL, allowed, NULL, NULL, NULL );
                }
            }
            salt_index++;
            t--;
            DN_CHECK( packet != NULL );
            if ( dn_log_pair( t, dn_peers[t].salts[salt_index], server_nonce, key ) < 0 )
                dn_stat( 8, "pair log full" );
            /* the packet's nonce, read back, is the header's */
            if ( prefix_type == NETCODE_CONNECTION_CHALLENGE_PACKET )
                DN_CHECK( memcmp( ( (struct netcode_connection_challenge_packet_t*) packet )->server_nonce, server_nonce, NETCODE_SERVER_NONCE_BYTES ) == 0 );
            else
                DN_CHECK( memcmp( ( (struct netcode_connection_denied_packet_t*) packet )->server_nonce, server_nonce, NETCODE_SERVER_NONCE_BYTES ) == 0 );
            /* the derived key is neither root key (the 1.02 key) of any token */
            int k;
            for ( k = 0; k < DN_TOKENS; k++ )
                DN_CHECK( memcmp( key, dn_tokens[k].s2c, NETCODE_KEY_BYTES ) != 0 && memcmp( key, dn_tokens[k].c2s, NETCODE_KEY_BYTES ) != 0 );
        }
        else
        {
            for ( t = 0; t < DN_TOKENS && !packet; t++ )
            {
                int p;
                for ( p = dn_pair_count[t] - 1; p >= 0 && !packet; p-- )
                {
                    uint8_t copy[NETCODE_MAX_PACKET_BYTES];
                    memcpy( copy, d->data, (size_t) d->bytes );
                    packet = netcode_read_packet( copy, d->bytes, &sequence, dn_pairs[t][p].s2c, DN_PROTOCOL_ID, 0, 0, NULL, allowed,
                                                  NULL, NULL, NULL );
                    if ( packet )
                        memcpy( key, dn_pairs[t][p].s2c, NETCODE_KEY_BYTES );
                }
            }
            t--;
            /* a key the fuzzer cannot know only when its pair log overflowed */
            if ( !packet && dn_pairs_full() )
                continue;
            DN_CHECK( packet != NULL );
        }

        /* oracle 1: a (key, nonce) pair is never used twice, not even for the same bytes, in a
           run or across restarts, whatever the token's expiry */
        uint64_t hash = dn_hash( d->data, (size_t) d->bytes );
        uint64_t key_id = dn_hash( key, NETCODE_KEY_BYTES );
        int n;
        for ( n = 0; n < dn_nonce_count; n++ )
        {
            int reused = dn_nonces[n].key == key_id && dn_nonces[n].sequence == sequence;
            if ( reused )
                fprintf( stderr, "nonce reuse: token %d sequence %llx type %d restarts %d (then %d) same bytes %d\n", t,
                         (unsigned long long) sequence, ( (uint8_t*) packet )[0], dn_restarts, dn_nonces[n].epoch, dn_nonces[n].hash == hash );
            DN_CHECK( !reused );
        }
        if ( dn_nonce_count < DN_NONCE_LOG )
        {
            dn_nonces[dn_nonce_count].token = t;
            dn_nonces[dn_nonce_count].key = key_id;
            dn_nonces[dn_nonce_count].sequence = sequence;
            dn_nonces[dn_nonce_count].hash = hash;
            dn_nonces[dn_nonce_count].epoch = dn_restarts;
            dn_nonce_count++;
        }

        /* the token's holder reads it: a challenge for its current attempt installs that
           attempt's packet keys */
        uint8_t type = ( (uint8_t*) packet )[0];
        if ( type == NETCODE_CONNECTION_CHALLENGE_PACKET )
        {
            dn_stat( 3, "challenges" );
            struct netcode_connection_challenge_packet_t * c = (struct netcode_connection_challenge_packet_t*) packet;
            struct dn_peer * peer = &dn_peers[t];
            if ( memcmp( peer->salt, peer->salts[salt_index], NETCODE_CONNECT_SALT_BYTES ) == 0 )
            {
                peer->have_challenge = 1;
                memcpy( peer->server_nonce, c->server_nonce, NETCODE_SERVER_NONCE_BYTES );
                netcode_derive_packet_key( peer->c2s, dn_tokens[t].c2s, peer->salt, c->server_nonce );
                memcpy( peer->s2c, key, NETCODE_KEY_BYTES );
                peer->challenge_sequence = c->challenge_token_sequence;
                memcpy( peer->challenge, c->challenge_token_data, NETCODE_CHALLENGE_TOKEN_BYTES );
                /* the two directions never share a key */
                DN_CHECK( memcmp( peer->c2s, peer->s2c, NETCODE_KEY_BYTES ) != 0 );
            }
            else
            {
                dn_stat( 6, "challenges for an earlier attempt" );
            }
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

/* Seals a packet from token t's holder under its current attempt's derived key, or, before a
   challenge for that attempt arrived or when `root` is set, under the token's root key, as
   NETCODE 1.02 did. Only derived-key payloads are recorded: the server must never deliver a
   payload sealed under a root key, so one that is delivered fails the integrity oracle. */
static void dn_send_sealed_with( struct dn_in * in, int t, int type, const uint8_t * plaintext, int bytes, int record_payload, int root )
{
    struct dn_peer * peer = &dn_peers[t];
    uint64_t sequence = dn_pick_sequence( in, peer );
    int sequence_bytes = dn_sequence_bytes( in, sequence );
    uint64_t on_wire = sequence;
    if ( sequence_bytes < 8 )
        on_wire &= ( 1ULL << ( 8 * sequence_bytes ) ) - 1;
    int derived = peer->have_challenge && !root;
    uint8_t packet[NETCODE_MAX_PACKET_BYTES + 64];
    int n = dn_seal( packet, type, sequence_bytes, on_wire, plaintext, bytes, derived ? peer->c2s : dn_tokens[t].c2s );
    if ( n > NETCODE_MAX_PACKET_BYTES )
        return;
    if ( !derived )
        dn_stat( 7, "packets sealed under a root key" );
    if ( record_payload && derived && dn_sent_count < DN_SENT_LOG )
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

static void dn_send_sealed( struct dn_in * in, int t, int type, const uint8_t * plaintext, int bytes, int record_payload )
{
    dn_send_sealed_with( in, t, type, plaintext, bytes, record_payload, 0 );
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
    memset( dn_pair_count, 0, sizeof( dn_pair_count ) );
    int t;
    for ( t = 0; t < DN_TOKENS; t++ )
        DN_CHECK( dn_new_attempt( t ) );

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
        switch ( op % 15 )
        {
            case 0:
            case 1:
            {
                /* the connection request, as the token's holder (or a thief replaying it); op 1
                   first starts a new attempt with the same token under a fresh client salt, as
                   a client does when it connects again or after a failed handshake */
                if ( op % 15 == 1 && dn_new_attempt( t ) )
                    dn_stat( 5, "attempts retried with one token" );
                uint8_t request[NETCODE_MAX_PACKET_BYTES];
                int bytes = dn_request( t, request, (int) sizeof( request ) );
                dn_queue( dn_pick_from( &in, t ), request, bytes );
                break;
            }

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

            case 14:
            {
                /* a session packet under the token's root key, as NETCODE 1.02 sealed it: the
                   payload is never recorded, so delivering it fails oracle 3 */
                int type = ( dn_u8( &in ) & 1 ) ? NETCODE_CONNECTION_PAYLOAD_PACKET : NETCODE_CONNECTION_RESPONSE_PACKET;
                uint8_t plaintext[8 + NETCODE_CHALLENGE_TOKEN_BYTES];
                int bytes = 1 + dn_u8( &in ) % 64;
                memset( plaintext, 0xEE, sizeof( plaintext ) );
                if ( type == NETCODE_CONNECTION_RESPONSE_PACKET && dn_peers[t].have_challenge )
                {
                    uint8_t * p = plaintext;
                    netcode_write_uint64( &p, dn_peers[t].challenge_sequence );
                    memcpy( p, dn_peers[t].challenge, NETCODE_CHALLENGE_TOKEN_BYTES );
                    bytes = (int) sizeof( plaintext );
                }
                dn_send_sealed_with( &in, t, type, plaintext, bytes, 0, 1 );
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
