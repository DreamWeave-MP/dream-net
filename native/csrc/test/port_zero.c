/*
    dream-net: proves patches/0001 over real loopback sockets.
    SPDX-License-Identifier: MIT OR Apache-2.0

    A server created on 127.0.0.1:0 must report the port its socket was bound to, and a client
    holding a connect token minted for 127.0.0.1:<that port> must connect. Unpatched netcode keeps
    port 0 as the server's public address and ignores every such token, so the client times out.

    Built and run by tests/native_build_upstream.rs against the vendored sources with the archive's own
    flags. Not compiled into the archive (build.rs takes only top-level csrc/*.c).
*/

#include "netcode.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#define PROTOCOL_ID 0x1122334455667788ULL
#define CLIENT_ID 0x0102030405060708ULL

static int fail( const char * what )
{
    printf( "port_zero: FAILED: %s\n", what );
    return 1;
}

int main( void )
{
    if ( netcode_init() != NETCODE_OK )
        return fail( "netcode_init" );
    netcode_log_level( NETCODE_LOG_LEVEL_NONE );

    uint8_t private_key[NETCODE_KEY_BYTES];
    netcode_random_bytes( private_key, NETCODE_KEY_BYTES );

    double time = netcode_time();

    struct netcode_server_config_t server_config;
    netcode_default_server_config( &server_config );
    server_config.protocol_id = PROTOCOL_ID;
    memcpy( server_config.private_key, private_key, NETCODE_KEY_BYTES );
    // tokens below expire 30 seconds out; the start floor admits them once expiry minus this
    // lifetime is after the server's start second
    server_config.max_connect_token_lifetime = 10;

    struct netcode_server_t * server = netcode_server_create( "127.0.0.1:0", &server_config, time );
    if ( !server )
        return fail( "netcode_server_create on port 0" );
    netcode_server_start( server, 1 );

    uint16_t port = netcode_server_get_port( server );
    if ( port == 0 )
        return fail( "netcode_server_get_port reported 0" );

    char server_address[64];
    snprintf( server_address, sizeof( server_address ), "127.0.0.1:%u", (unsigned) port );
    NETCODE_CONST char * addresses[] = { server_address };

    uint8_t user_data[NETCODE_USER_DATA_BYTES];
    memset( user_data, 0, sizeof( user_data ) );
    uint8_t connect_token[NETCODE_CONNECT_TOKEN_BYTES];
    if ( netcode_generate_connect_token( 1, addresses, addresses, 30, 5, CLIENT_ID, PROTOCOL_ID, private_key, user_data, connect_token ) != NETCODE_OK )
        return fail( "netcode_generate_connect_token" );

    struct netcode_client_config_t client_config;
    netcode_default_client_config( &client_config );
    struct netcode_client_t * client = netcode_client_create( "127.0.0.1:0", &client_config, time );
    if ( !client )
        return fail( "netcode_client_create on port 0" );
    if ( netcode_client_get_port( client ) == 0 )
        return fail( "netcode_client_get_port reported 0" );

    netcode_client_connect( client, connect_token );

    int connected = 0;
    double deadline = time + 5.0;
    while ( netcode_time() < deadline )
    {
        time = netcode_time();
        netcode_client_update( client, time );
        netcode_server_update( server, time );
        if ( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED && netcode_server_client_connected( server, 0 ) )
        {
            connected = 1;
            break;
        }
        if ( netcode_client_state( client ) <= NETCODE_CLIENT_STATE_DISCONNECTED )
            break;
        netcode_sleep( 0.01 );
    }

    int state = netcode_client_state( client );
    if ( !connected )
    {
        printf( "port_zero: client state %d\n", state );
        return fail( "the client did not connect to the port-0 server with a token for its bound port" );
    }
    if ( netcode_server_client_id( server, 0 ) != CLIENT_ID )
        return fail( "the server slot holds the wrong client id" );

    printf( "port_zero: server bound port %u, client connected (client id %" PRIx64 ")\n", (unsigned) port, (uint64_t) CLIENT_ID );

    netcode_client_destroy( client );
    netcode_server_destroy( server );
    netcode_term();
    printf( "port_zero: OK\n" );
    return 0;
}
