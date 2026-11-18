/*
    dream-net-native netcode shim. SPDX-License-Identifier: MIT OR Apache-2.0

    The only C the safe Rust netcode binding (src/netcode.rs) calls besides plain netcode
    functions that take scalars and byte pointers. It exists because of shared decision 6:

    - netcode's config structs are never laid out from Rust: the create functions here start
      from netcode_default_*_config and set fields from scalar arguments.
    - netcode_address_t is never read from Rust: addresses cross the boundary in the flat,
      layout-pinned dn_native_nc_address_t below (or as strings going in).

    Every struct Rust reads or writes is pinned by _Static_assert in dn_native_netcode.c and by
    const assertions in src/sys/netcode.rs.
*/

#ifndef DN_NATIVE_NETCODE_H
#define DN_NATIVE_NETCODE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct netcode_client_t;

/* An address in flat form. family: 0 none, 1 IPv4 (bytes[0..4]), 2 IPv6 (bytes[0..16]), the
   values of NETCODE_ADDRESS_*. Bytes are in network order; port is in host order. */
typedef struct dn_native_nc_address_t
{
    uint8_t family;
    uint8_t reserved;
    uint16_t port;
    uint8_t bytes[16];
} dn_native_nc_address_t;

/*
    Creates a netcode client bound to address (a netcode address string) with the default
    client config. On failure returns NULL, stores netcode_client_create_error() in *error and
    the OS error code seen right after the failure (errno; 0 on Windows) in *os_error. Reads the
    process-global create error, so callers serialise every create (src/netcode.rs does).
*/
struct netcode_client_t * dn_native_nc_client_create( const char * address, double time, int * error, int * os_error );

/* Writes the client's current server address; returns 1 when it has one, else 0. */
int dn_native_nc_client_server_address( struct netcode_client_t * client, dn_native_nc_address_t * out );

#ifdef __cplusplus
}
#endif

#endif /* DN_NATIVE_NETCODE_H */
