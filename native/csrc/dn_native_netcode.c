/*
    dream-net-native netcode shim. SPDX-License-Identifier: MIT OR Apache-2.0

    See dn_native_netcode.h. Compiled into the archive with -Werror -Wall -Wextra (build.rs).
*/

#include "dn_native_netcode.h"

#include "netcode.h"

#include <errno.h>
#include <stddef.h>
#include <string.h>

/* The layouts Rust mirrors (src/sys/netcode.rs repeats these as const assertions). */

_Static_assert( sizeof( dn_native_nc_address_t ) == 20, "dn_native_nc_address_t size" );
_Static_assert( _Alignof( dn_native_nc_address_t ) == 2, "dn_native_nc_address_t alignment" );
_Static_assert( offsetof( dn_native_nc_address_t, family ) == 0, "family offset" );
_Static_assert( offsetof( dn_native_nc_address_t, reserved ) == 1, "reserved offset" );
_Static_assert( offsetof( dn_native_nc_address_t, port ) == 2, "port offset" );
_Static_assert( offsetof( dn_native_nc_address_t, bytes ) == 4, "bytes offset" );

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
    struct netcode_client_t * client = netcode_client_create( address, &config, time );
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
