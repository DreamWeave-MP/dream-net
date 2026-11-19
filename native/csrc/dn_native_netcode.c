/*
    dream-net netcode shim. SPDX-License-Identifier: MIT OR Apache-2.0

    See dn_native_netcode.h. Compiled into the archive with -Werror -Wall -Wextra (build.rs).
*/

#include "dn_native_netcode.h"

#include "netcode.h"
#include "sodium.h"

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* The layouts Rust mirrors (src/sys/netcode.rs repeats these as const assertions). */

_Static_assert( sizeof( dn_native_nc_address_t ) == 20, "dn_native_nc_address_t size" );
_Static_assert( _Alignof( dn_native_nc_address_t ) == 2, "dn_native_nc_address_t alignment" );
_Static_assert( offsetof( dn_native_nc_address_t, family ) == 0, "family offset" );
_Static_assert( offsetof( dn_native_nc_address_t, reserved ) == 1, "reserved offset" );
_Static_assert( offsetof( dn_native_nc_address_t, port ) == 2, "port offset" );
_Static_assert( offsetof( dn_native_nc_address_t, bytes ) == 4, "bytes offset" );

_Static_assert( sizeof( dn_native_nc_slot_events_t ) == 24, "dn_native_nc_slot_events_t size" );
_Static_assert( _Alignof( dn_native_nc_slot_events_t ) == _Alignof( uint64_t ), "slot events alignment" );
_Static_assert( offsetof( dn_native_nc_slot_events_t, connects ) == 0, "connects offset" );
_Static_assert( offsetof( dn_native_nc_slot_events_t, disconnects ) == 8, "disconnects offset" );
_Static_assert( offsetof( dn_native_nc_slot_events_t, first_disconnect_reason ) == 16, "reason offset" );
_Static_assert( offsetof( dn_native_nc_slot_events_t, connected ) == 20, "connected offset" );

/* The constants the Rust side hard-codes. */

_Static_assert( NETCODE_MAX_CLIENTS == 256, "NETCODE_MAX_CLIENTS" );
_Static_assert( NETCODE_KEY_BYTES == 32, "NETCODE_KEY_BYTES" );
_Static_assert( NETCODE_USER_DATA_BYTES == 256, "NETCODE_USER_DATA_BYTES" );
_Static_assert( NETCODE_CONNECT_TOKEN_BYTES == 2048, "NETCODE_CONNECT_TOKEN_BYTES" );
_Static_assert( NETCODE_MAX_PACKET_SIZE == 1200, "NETCODE_MAX_PACKET_SIZE" );
_Static_assert( NETCODE_MAX_SERVERS_PER_CONNECT == 32, "NETCODE_MAX_SERVERS_PER_CONNECT" );
_Static_assert( NETCODE_MAC_BYTES == 16, "NETCODE_MAC_BYTES" );
_Static_assert( NETCODE_ADDRESS_NONE == 0 && NETCODE_ADDRESS_IPV4 == 1 && NETCODE_ADDRESS_IPV6 == 2, "NETCODE_ADDRESS_*" );
_Static_assert( NETCODE_DEFAULT_MAX_CONNECT_TOKEN_LIFETIME == 30, "NETCODE_DEFAULT_MAX_CONNECT_TOKEN_LIFETIME" );

static int dn_native_os_error( void )
{
#if defined( _WIN32 )
    return 0;
#else
    return errno;
#endif
}

static void dn_native_export_address( const struct netcode_address_t * in, dn_native_nc_address_t * out )
{
    memset( out, 0, sizeof( *out ) );
    if ( !in )
        return;
    if ( in->type == NETCODE_ADDRESS_IPV4 )
    {
        out->family = NETCODE_ADDRESS_IPV4;
        memcpy( out->bytes, in->data.ipv4, 4 );
    }
    else if ( in->type == NETCODE_ADDRESS_IPV6 )
    {
        int i;
        out->family = NETCODE_ADDRESS_IPV6;
        for ( i = 0; i < 8; i++ )
        {
            out->bytes[i * 2] = (uint8_t) ( in->data.ipv6[i] >> 8 );
            out->bytes[i * 2 + 1] = (uint8_t) ( in->data.ipv6[i] & 0xFF );
        }
    }
    else
    {
        return;
    }
    out->port = in->port;
}

/* ---------------------------------------------------------------- client */

struct netcode_client_t * dn_native_nc_client_create( const char * address, double time, int * error, int * os_error )
{
    *error = NETCODE_CLIENT_CREATE_ERROR_NONE;
    *os_error = 0;
    struct netcode_client_config_t config;
    netcode_default_client_config( &config );
    /* NETCODE_CONST is empty under clang-cl (no __STDC__); netcode only reads the address */
    struct netcode_client_t * client = netcode_client_create( ( NETCODE_CONST char * ) address, &config, time );
    if ( !client )
    {
        *os_error = dn_native_os_error();
        *error = netcode_client_create_error();
    }
    return client;
}

int dn_native_nc_client_server_address( struct netcode_client_t * client, dn_native_nc_address_t * out )
{
    dn_native_export_address( netcode_client_server_address( client ), out );
    return out->family != NETCODE_ADDRESS_NONE;
}

/* ---------------------------------------------------------------- server */

struct dn_native_nc_slot_t
{
    /* the window since the last take */
    uint64_t connects;
    uint64_t disconnects;
    int first_disconnect_reason;
    /* the state now, and the identity captured by the latest connect */
    int connected;
    uint64_t client_id;
    dn_native_nc_address_t address;
    uint8_t user_data[NETCODE_USER_DATA_BYTES];
};

struct dn_native_nc_server_t
{
    struct netcode_server_t * server;
    int dirty;
    struct dn_native_nc_slot_t slots[NETCODE_MAX_CLIENTS];
};

/*
    connect_disconnect_callback. Fires inside netcode_server_update, disconnect_client,
    disconnect_all_clients, stop and destroy. netcode guarantees the slot's id, address and user
    data are readable here for both kinds of call (netcode.c: the slot is reset after the
    disconnect callback returns), and records the disconnect reason before it calls. Only
    copies into the fixed slot record: no allocation, no call out of C.
*/
static void dn_native_nc_server_callback( void * context, int client_index, int connected )
{
    struct dn_native_nc_server_t * s = (struct dn_native_nc_server_t *) context;
    if ( !s || !s->server || client_index < 0 || client_index >= NETCODE_MAX_CLIENTS )
        return;
    struct dn_native_nc_slot_t * slot = &s->slots[client_index];
    s->dirty = 1;
    if ( connected )
    {
        slot->connects++;
        slot->connected = 1;
        slot->client_id = netcode_server_client_id( s->server, client_index );
        dn_native_export_address( netcode_server_client_address( s->server, client_index ), &slot->address );
        const void * user_data = netcode_server_client_user_data( s->server, client_index );
        if ( user_data )
            memcpy( slot->user_data, user_data, NETCODE_USER_DATA_BYTES );
        else
            memset( slot->user_data, 0, NETCODE_USER_DATA_BYTES );
    }
    else
    {
        if ( slot->disconnects == 0 )
            slot->first_disconnect_reason = netcode_server_client_disconnect_reason( s->server, client_index );
        slot->disconnects++;
        slot->connected = 0;
    }
}

dn_native_nc_server_t * dn_native_nc_server_create( const char * address,
                                                    uint64_t protocol_id,
                                                    const uint8_t * private_key,
                                                    int max_connect_token_lifetime,
                                                    double time,
                                                    int * error,
                                                    int * os_error )
{
    *error = NETCODE_SERVER_CREATE_ERROR_NONE;
    *os_error = 0;

    struct dn_native_nc_server_t * s = (struct dn_native_nc_server_t *) calloc( 1, sizeof( struct dn_native_nc_server_t ) );
    if ( !s )
    {
        *error = NETCODE_SERVER_CREATE_ERROR_ALLOCATE_SERVER_FAILED;
        return NULL;
    }

    struct netcode_server_config_t config;
    netcode_default_server_config( &config );
    config.protocol_id = protocol_id;
    memcpy( config.private_key, private_key, NETCODE_KEY_BYTES );
    config.max_connect_token_lifetime = max_connect_token_lifetime;
    config.callback_context = s;
    config.connect_disconnect_callback = dn_native_nc_server_callback;

    /* no callback can fire inside create: there are no clients yet */
    /* NETCODE_CONST is empty under clang-cl (no __STDC__); netcode only reads the address */
    s->server = netcode_server_create( ( NETCODE_CONST char * ) address, &config, time );
    if ( !s->server )
    {
        *os_error = dn_native_os_error();
        *error = netcode_server_create_error();
    }

    sodium_memzero( &config, sizeof( config ) );

    if ( !s->server )
    {
        free( s );
        return NULL;
    }
    return s;
}

struct netcode_server_t * dn_native_nc_server_inner( dn_native_nc_server_t * server )
{
    return server->server;
}

void dn_native_nc_server_destroy( dn_native_nc_server_t * server )
{
    if ( !server )
        return;
    /* destroy stops the server, which calls back into server->slots: free only afterwards */
    netcode_server_destroy( server->server );
    server->server = NULL;
    sodium_memzero( server, sizeof( *server ) );
    free( server );
}

int dn_native_nc_server_take_events( dn_native_nc_server_t * server, dn_native_nc_slot_events_t * out )
{
    if ( !server->dirty )
        return 0;
    server->dirty = 0;
    int i;
    for ( i = 0; i < NETCODE_MAX_CLIENTS; i++ )
    {
        struct dn_native_nc_slot_t * slot = &server->slots[i];
        out[i].connects = slot->connects;
        out[i].disconnects = slot->disconnects;
        out[i].first_disconnect_reason = slot->first_disconnect_reason;
        out[i].connected = slot->connected;
        slot->connects = 0;
        slot->disconnects = 0;
        slot->first_disconnect_reason = NETCODE_SERVER_CLIENT_DISCONNECT_REASON_NONE;
    }
    return 1;
}

static struct dn_native_nc_slot_t * dn_native_connected_slot( dn_native_nc_server_t * server, int index )
{
    /* netcode_server_client_connected checks running and the index against max_clients */
    if ( index < 0 || index >= NETCODE_MAX_CLIENTS || !netcode_server_client_connected( server->server, index ) )
        return NULL;
    struct dn_native_nc_slot_t * slot = &server->slots[index];
    return slot->connected ? slot : NULL;
}

int dn_native_nc_server_client_identity( dn_native_nc_server_t * server, int index, uint64_t * client_id, dn_native_nc_address_t * address )
{
    struct dn_native_nc_slot_t * slot = dn_native_connected_slot( server, index );
    if ( !slot )
        return 0;
    *client_id = slot->client_id;
    *address = slot->address;
    return 1;
}

const uint8_t * dn_native_nc_server_client_user_data( dn_native_nc_server_t * server, int index )
{
    struct dn_native_nc_slot_t * slot = dn_native_connected_slot( server, index );
    return slot ? slot->user_data : NULL;
}

int dn_native_nc_address_size( void )
{
    return (int) sizeof( dn_native_nc_address_t );
}

int dn_native_nc_slot_events_size( void )
{
    return (int) sizeof( dn_native_nc_slot_events_t );
}
