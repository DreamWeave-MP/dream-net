/*
    dream-net netcode shim. SPDX-License-Identifier: MIT OR Apache-2.0

    The only C the safe Rust netcode binding (src/netcode.rs) calls besides plain netcode
    functions that take scalars and byte pointers. It exists for three reasons (shared decision
    6 and 7):

    - netcode's config structs are never laid out from Rust: the create functions here start
      from netcode_default_*_config and set fields from scalar arguments.
    - netcode_address_t is never read from Rust: addresses cross the boundary in the flat,
      layout-pinned dn_native_nc_address_t below (or as strings going in).
    - the server's connect_disconnect_callback lands in C, here, and only counts transitions
      into fixed per-slot storage owned by the server handle. No Rust code ever runs inside a
      netcode call, so nothing can unwind through C, and a callback never allocates.

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
struct netcode_server_t;

/* An address in flat form. family: 0 none, 1 IPv4 (bytes[0..4]), 2 IPv6 (bytes[0..16]), the
   values of NETCODE_ADDRESS_*. Bytes are in network order; port is in host order. */
typedef struct dn_native_nc_address_t
{
    uint8_t family;
    uint8_t reserved;
    uint16_t port;
    uint8_t bytes[16];
} dn_native_nc_address_t;

/* What happened in one server slot since the previous dn_native_nc_server_take_events.
   connects/disconnects count connect_disconnect_callback calls for the slot;
   first_disconnect_reason is the NETCODE_SERVER_CLIENT_DISCONNECT_REASON_* of the first
   disconnect in that window (NONE when there was none); connected is the slot's state now. */
typedef struct dn_native_nc_slot_events_t
{
    uint64_t connects;
    uint64_t disconnects;
    int32_t first_disconnect_reason;
    int32_t connected;
} dn_native_nc_slot_events_t;

/* The server handle: the netcode server plus the callback's per-slot storage. Opaque. */
typedef struct dn_native_nc_server_t dn_native_nc_server_t;

/*
    Creates a netcode client bound to address (a netcode address string) with the default
    client config. On failure returns NULL, stores netcode_client_create_error() in *error and
    the OS error code seen right after the failure (errno; 0 on Windows) in *os_error. Reads the
    process-global create error, so callers serialise every create (src/netcode.rs does).
*/
struct netcode_client_t * dn_native_nc_client_create( const char * address, double time, int * error, int * os_error );

/* Writes the client's current server address; returns 1 when it has one, else 0. */
int dn_native_nc_client_server_address( struct netcode_client_t * client, dn_native_nc_address_t * out );

/*
    Creates a netcode server whose public address is address, with the given protocol id,
    private key (NETCODE_KEY_BYTES) and max_connect_token_lifetime (seconds, > 0), and the
    shim's connect/disconnect callback. The key is copied into netcode's config and the local
    copy is zeroed. Errors as dn_native_nc_client_create, with netcode_server_create_error.
*/
dn_native_nc_server_t * dn_native_nc_server_create( const char * address,
                                                    uint64_t protocol_id,
                                                    const uint8_t * private_key,
                                                    int max_connect_token_lifetime,
                                                    double time,
                                                    int * error,
                                                    int * os_error );

/* The netcode server inside the handle, for direct netcode_server_* calls. Never NULL. */
struct netcode_server_t * dn_native_nc_server_inner( dn_native_nc_server_t * server );

/*
    Destroys the netcode server first (which stops it and fires the callback for every connected
    slot, into storage that is still alive), then frees the handle. Exactly once per handle.
*/
void dn_native_nc_server_destroy( dn_native_nc_server_t * server );

/*
    If any callback fired since the previous call, copies every slot's window into
    out[0..NETCODE_MAX_CLIENTS], starts a new window for every slot, and returns 1. Otherwise
    leaves out untouched and returns 0.
*/
int dn_native_nc_server_take_events( dn_native_nc_server_t * server, dn_native_nc_slot_events_t * out );

/*
    The identity the connect callback captured for the client in slot index: returns 1 and
    writes its client id and address when netcode reports the slot connected, else returns 0.
*/
int dn_native_nc_server_client_identity( dn_native_nc_server_t * server, int index, uint64_t * client_id, dn_native_nc_address_t * address );

/*
    The user data the connect callback captured for slot index (NETCODE_USER_DATA_BYTES, owned
    by the handle and stable until the next call that can fire the callback), or NULL when
    netcode does not report the slot connected.
*/
const uint8_t * dn_native_nc_server_client_user_data( dn_native_nc_server_t * server, int index );

/* sizeof of the two shared structs, for the Rust side's layout checks at run time. */
int dn_native_nc_address_size( void );
int dn_native_nc_slot_events_size( void );

#ifdef __cplusplus
}
#endif

#endif /* DN_NATIVE_NETCODE_H */
