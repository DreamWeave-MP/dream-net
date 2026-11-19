/*
    dream-net: netcode known-answer vectors. SPDX-License-Identifier: MIT OR Apache-2.0

    Reproduces the eleven vectors netcode-official 1.2.0 (NETCODE 1.03) ships in tests/vectors/
    from the same fixed inputs (its src/wire_compat.rs), with the vendored C, as the program in
    docs/maintenance/NATIVE_TRANSPORT_AUDIT.md Appendix A did for 1.0.0, plus the per-connection
    HChaCha20 key derivation known answer of netcode-official 1.2.0's src/crypto.rs
    (test_derive_packet_keys_kat, identical to upstream C's). Prints one line per vector,
    "<name> <length> <hex>", which tests/native_netcode_kat.rs hashes and compares.

    A unity build over netcode.c, because the token and packet writers are internal to it.
    Built and run at test time by tests/native_netcode_kat.rs with the archive's own flags; never
    compiled into the archive (build.rs takes only top-level csrc/*.c).
*/

#include "netcode.c"

static void out( const char * name, const uint8_t * bytes, int length )
{
    printf( "%s %d ", name, length );
    for ( int i = 0; i < length; i++ )
        printf( "%02x", bytes[i] );
    printf( "\n" );
}

int main( void )
{
    if ( netcode_init() != NETCODE_OK )
        return 1;

    uint64_t protocol_id = 0x1122334455667788ULL;
    uint64_t client_id = 0x0102030405060708ULL;
    uint64_t create = 1720000000ULL;
    uint64_t expire = 1720000100ULL;
    uint64_t challenge_sequence = 1000;
    uint64_t packet_sequence = 0x1122334455ULL;
    uint8_t private_key[32] = { 0x60, 0x6a, 0xbe, 0x6e, 0xc9, 0x19, 0x10, 0xea, 0x9a, 0x65, 0x62, 0xf6, 0x6f, 0x2b, 0x30, 0xe4,
                                0x43, 0x71, 0xd6, 0x2c, 0xd1, 0x99, 0x27, 0x26, 0x6b, 0x3c, 0x60, 0xf4, 0xb7, 0x15, 0xab, 0xa1 };
    uint8_t client_to_server[32], server_to_client[32], challenge_key[32], packet_key[32], user_data[256], nonce[24];
    for ( int i = 0; i < 32; i++ )
    {
        client_to_server[i] = (uint8_t) i;
        server_to_client[i] = (uint8_t) ( 255 - i );
        challenge_key[i] = (uint8_t) ( i * 2 );
        packet_key[i] = (uint8_t) ( i + 17 );
    }
    for ( int i = 0; i < 256; i++ )
        user_data[i] = (uint8_t) i;
    for ( int i = 0; i < 24; i++ )
        nonce[i] = (uint8_t) ( 100 + i );

    struct netcode_address_t addresses[2];
    if ( netcode_parse_address( "127.0.0.1:40000", &addresses[0] ) != NETCODE_OK ||
         netcode_parse_address( "[::1]:50000", &addresses[1] ) != NETCODE_OK )
        return 2;

    struct netcode_connect_token_private_t private_token;
    memset( &private_token, 0, sizeof( private_token ) );
    private_token.client_id = client_id;
    private_token.timeout_seconds = 15;
    private_token.num_server_addresses = 2;
    memcpy( private_token.server_addresses, addresses, sizeof( addresses ) );
    memcpy( private_token.client_to_server_key, client_to_server, 32 );
    memcpy( private_token.server_to_client_key, server_to_client, 32 );
    memcpy( private_token.user_data, user_data, 256 );
    uint8_t private_plain[1024];
    memset( private_plain, 0, sizeof( private_plain ) );
    netcode_write_connect_token_private( &private_token, private_plain, 1024 );
    out( "private_connect_token_plaintext.bin", private_plain, 1024 );

    uint8_t private_encrypted[1024];
    memcpy( private_encrypted, private_plain, 1024 );
    if ( netcode_encrypt_connect_token_private( private_encrypted, 1024, NETCODE_VERSION_INFO, protocol_id, expire, nonce, private_key ) != NETCODE_OK )
        return 3;
    out( "private_connect_token_encrypted.bin", private_encrypted, 1024 );

    struct netcode_connect_token_t token;
    memset( &token, 0, sizeof( token ) );
    memcpy( token.version_info, NETCODE_VERSION_INFO, 13 );
    token.protocol_id = protocol_id;
    token.create_timestamp = create;
    token.expire_timestamp = expire;
    memcpy( token.nonce, nonce, 24 );
    memcpy( token.private_data, private_encrypted, 1024 );
    token.timeout_seconds = 15;
    token.num_server_addresses = 2;
    memcpy( token.server_addresses, addresses, sizeof( addresses ) );
    memcpy( token.client_to_server_key, client_to_server, 32 );
    memcpy( token.server_to_client_key, server_to_client, 32 );
    uint8_t token_bytes[2048];
    memset( token_bytes, 0, sizeof( token_bytes ) );
    netcode_write_connect_token( &token, token_bytes, 2048 );
    out( "connect_token.bin", token_bytes, 2048 );

    struct netcode_challenge_token_t challenge;
    challenge.client_id = client_id;
    memcpy( challenge.user_data, user_data, 256 );
    uint8_t challenge_bytes[300];
    memset( challenge_bytes, 0, sizeof( challenge_bytes ) );
    netcode_write_challenge_token( &challenge, challenge_bytes, 300 );
    if ( netcode_encrypt_challenge_token( challenge_bytes, 300, challenge_sequence, challenge_key ) != NETCODE_OK )
        return 4;
    out( "challenge_token_encrypted.bin", challenge_bytes, 300 );

    uint8_t buffer[2048];
    int n;

    struct netcode_connection_request_packet_t request;
    memset( &request, 0, sizeof( request ) );
    request.packet_type = 0;
    memcpy( request.version_info, NETCODE_VERSION_INFO, 13 );
    request.protocol_id = protocol_id;
    request.connect_token_expire_timestamp = expire;
    memcpy( request.connect_token_nonce, nonce, 24 );
    memcpy( request.connect_token_data, private_encrypted, 1024 );
    for ( int i = 0; i < NETCODE_CONNECT_SALT_BYTES; i++ )
        request.client_salt[i] = (uint8_t) ( 50 + i );
    n = netcode_write_packet( &request, buffer, sizeof( buffer ), packet_sequence, packet_key, protocol_id );
    out( "packet_request.bin", buffer, n );

    uint8_t server_nonce[NETCODE_SERVER_NONCE_BYTES];
    for ( int i = 0; i < NETCODE_SERVER_NONCE_BYTES; i++ )
        server_nonce[i] = (uint8_t) ( 80 + i );

    struct netcode_connection_denied_packet_t denied;
    memset( &denied, 0, sizeof( denied ) );
    denied.packet_type = 1;
    memcpy( denied.server_nonce, server_nonce, NETCODE_SERVER_NONCE_BYTES );
    n = netcode_write_packet( &denied, buffer, sizeof( buffer ), packet_sequence, packet_key, protocol_id );
    out( "packet_denied.bin", buffer, n );

    struct netcode_connection_challenge_packet_t challenge_packet;
    memset( &challenge_packet, 0, sizeof( challenge_packet ) );
    challenge_packet.packet_type = 2;
    memcpy( challenge_packet.server_nonce, server_nonce, NETCODE_SERVER_NONCE_BYTES );
    challenge_packet.challenge_token_sequence = challenge_sequence;
    memcpy( challenge_packet.challenge_token_data, challenge_bytes, 300 );
    n = netcode_write_packet( &challenge_packet, buffer, sizeof( buffer ), packet_sequence, packet_key, protocol_id );
    out( "packet_challenge.bin", buffer, n );

    struct netcode_connection_response_packet_t response;
    response.packet_type = 3;
    response.challenge_token_sequence = challenge_sequence;
    memcpy( response.challenge_token_data, challenge_bytes, 300 );
    n = netcode_write_packet( &response, buffer, sizeof( buffer ), packet_sequence, packet_key, protocol_id );
    out( "packet_response.bin", buffer, n );

    struct netcode_connection_keep_alive_packet_t keep_alive;
    keep_alive.packet_type = 4;
    keep_alive.client_index = 7;
    keep_alive.max_clients = 32;
    n = netcode_write_packet( &keep_alive, buffer, sizeof( buffer ), packet_sequence, packet_key, protocol_id );
    out( "packet_keep_alive.bin", buffer, n );

    struct netcode_connection_payload_packet_t * payload = netcode_create_payload_packet( 1200, NULL, NULL );
    if ( !payload )
        return 5;
    for ( int i = 0; i < 1200; i++ )
        payload->payload_data[i] = (uint8_t) i;
    n = netcode_write_packet( payload, buffer, sizeof( buffer ), packet_sequence, packet_key, protocol_id );
    out( "packet_payload.bin", buffer, n );
    free( payload );

    struct netcode_connection_disconnect_packet_t disconnect = { 6 };
    n = netcode_write_packet( &disconnect, buffer, sizeof( buffer ), packet_sequence, packet_key, protocol_id );
    out( "packet_disconnect.bin", buffer, n );

    /* The NETCODE 1.03 per-connection key derivation: token keys i*3+1 (client to server) and
       i*5+2 (server to client), client salt i*19+21, server nonce i*23+29. Printed as the
       derived client-to-server key followed by the derived server-to-client key. */
    {
        uint8_t c2s[32], s2c[32], salt[NETCODE_CONNECT_SALT_BYTES], snonce[NETCODE_SERVER_NONCE_BYTES], derived[64];
        for ( int i = 0; i < 32; i++ )
        {
            c2s[i] = (uint8_t) ( i * 3 + 1 );
            s2c[i] = (uint8_t) ( i * 5 + 2 );
        }
        for ( int i = 0; i < NETCODE_CONNECT_SALT_BYTES; i++ )
            salt[i] = (uint8_t) ( i * 19 + 21 );
        for ( int i = 0; i < NETCODE_SERVER_NONCE_BYTES; i++ )
            snonce[i] = (uint8_t) ( i * 23 + 29 );
        netcode_derive_packet_key( derived, c2s, salt, snonce );
        netcode_derive_packet_key( derived + 32, s2c, salt, snonce );
        out( "derived_packet_keys.kat", derived, 64 );
    }

    printf( "netcode_kat: OK %s\n", NETCODE_VERSION_FULL );
    return 0;
}
