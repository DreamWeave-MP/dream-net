//! Raw declarations of the prefixed netcode C API and of the netcode shim
//! (`csrc/dn_native_netcode.{c,h}`).
//!
//! Only functions whose arguments are scalars, byte pointers, NUL-terminated strings and opaque
//! handles are declared. netcode's config and address structs are never mirrored: the shim
//! builds configs from scalars and exports addresses in the flat [`Address`] form, whose layout
//! is pinned by `_Static_assert`s in the shim and by the const assertions
//! below. Nothing here is public; [`crate::netcode`] is the only caller.

use core::ffi::{c_char, c_int};

/// `struct netcode_client_t`: opaque, only ever behind a pointer.
#[repr(C)]
pub(crate) struct NetcodeClient {
    _private: [u8; 0],
}

/// `dn_native_nc_address_t`. Family 0 is netcode's "no address".
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct Address {
    /// 0 none, 1 IPv4, 2 IPv6.
    pub(crate) family: u8,
    pub(crate) reserved: u8,
    /// Host order.
    pub(crate) port: u16,
    /// Network order; IPv4 in the first four bytes.
    pub(crate) bytes: [u8; 16],
}

// The same layout the shim pins with _Static_assert.
const _: () = {
    assert!(size_of::<Address>() == 20);
    assert!(align_of::<Address>() == 2);
    assert!(core::mem::offset_of!(Address, family) == 0);
    assert!(core::mem::offset_of!(Address, reserved) == 1);
    assert!(core::mem::offset_of!(Address, port) == 2);
    assert!(core::mem::offset_of!(Address, bytes) == 4);
};

pub(crate) const ADDRESS_IPV4: u8 = 1;
pub(crate) const ADDRESS_IPV6: u8 = 2;

pub(crate) const OK: c_int = 1;

pub(crate) const CLIENT_STATE_CONNECT_TOKEN_EXPIRED: c_int = -6;
pub(crate) const CLIENT_STATE_INVALID_CONNECT_TOKEN: c_int = -5;
pub(crate) const CLIENT_STATE_CONNECTION_TIMED_OUT: c_int = -4;
pub(crate) const CLIENT_STATE_CONNECTION_RESPONSE_TIMED_OUT: c_int = -3;
pub(crate) const CLIENT_STATE_CONNECTION_REQUEST_TIMED_OUT: c_int = -2;
pub(crate) const CLIENT_STATE_CONNECTION_DENIED: c_int = -1;
pub(crate) const CLIENT_STATE_SENDING_CONNECTION_REQUEST: c_int = 1;
pub(crate) const CLIENT_STATE_SENDING_CONNECTION_RESPONSE: c_int = 2;
pub(crate) const CLIENT_STATE_CONNECTED: c_int = 3;

pub(crate) const CLIENT_CREATE_ERROR_PARSE_ADDRESS_FAILED: c_int = 1;
pub(crate) const CLIENT_CREATE_ERROR_CREATE_SOCKET_IPV4_FAILED: c_int = 4;
pub(crate) const CLIENT_CREATE_ERROR_CREATE_SOCKET_IPV6_FAILED: c_int = 5;
pub(crate) const CLIENT_CREATE_ERROR_ALLOCATE_CLIENT_FAILED: c_int = 6;

// SAFETY: every declaration below matches its prototype in `vendor/netcode/netcode.h` (v1.4.10
// plus patch 0001) or `csrc/dn_native_netcode.h`, with C `int` as `c_int`, `uint8_t`/`uint16_t`/
// `uint64_t` as `u8`/`u16`/`u64`, `double` as `f64`, `char *` as `c_char` pointers, and struct
// pointers as pointers to the opaque or layout-pinned types above. Each is linked under its
// `dn_native_` name (`csrc/dn_native_prefix.h`). The preconditions of each call are listed and
// enforced in `crate::netcode` (module docs, "Preconditions").
unsafe extern "C" {
    // ---- shim
    pub(crate) fn dn_native_nc_client_create(
        address: *const c_char,
        time: f64,
        error: *mut c_int,
        os_error: *mut c_int,
    ) -> *mut NetcodeClient;
    pub(crate) fn dn_native_nc_client_server_address(
        client: *mut NetcodeClient,
        out: *mut Address,
    ) -> c_int;

    // ---- netcode: keys and tokens
    #[link_name = "dn_native_netcode_random_bytes"]
    pub(crate) fn netcode_random_bytes(data: *mut u8, bytes: c_int);
    #[link_name = "dn_native_netcode_generate_connect_token"]
    pub(crate) fn netcode_generate_connect_token(
        num_server_addresses: c_int,
        public_server_addresses: *const *const c_char,
        internal_server_addresses: *const *const c_char,
        expire_seconds: c_int,
        timeout_seconds: c_int,
        client_id: u64,
        protocol_id: u64,
        private_key: *const u8,
        user_data: *mut u8,
        connect_token: *mut u8,
    ) -> c_int;

    // ---- netcode: client
    #[link_name = "dn_native_netcode_client_destroy"]
    pub(crate) fn netcode_client_destroy(client: *mut NetcodeClient);
    #[link_name = "dn_native_netcode_client_connect"]
    pub(crate) fn netcode_client_connect(client: *mut NetcodeClient, connect_token: *mut u8);
    #[link_name = "dn_native_netcode_client_update"]
    pub(crate) fn netcode_client_update(client: *mut NetcodeClient, time: f64);
    #[link_name = "dn_native_netcode_client_next_packet_sequence"]
    pub(crate) fn netcode_client_next_packet_sequence(client: *mut NetcodeClient) -> u64;
    #[link_name = "dn_native_netcode_client_send_packet"]
    pub(crate) fn netcode_client_send_packet(
        client: *mut NetcodeClient,
        packet_data: *const u8,
        packet_bytes: c_int,
    );
    #[link_name = "dn_native_netcode_client_receive_packet"]
    pub(crate) fn netcode_client_receive_packet(
        client: *mut NetcodeClient,
        packet_bytes: *mut c_int,
        packet_sequence: *mut u64,
    ) -> *mut u8;
    #[link_name = "dn_native_netcode_client_free_packet"]
    pub(crate) fn netcode_client_free_packet(client: *mut NetcodeClient, packet: *mut u8);
    #[link_name = "dn_native_netcode_client_disconnect"]
    pub(crate) fn netcode_client_disconnect(client: *mut NetcodeClient);
    #[link_name = "dn_native_netcode_client_state"]
    pub(crate) fn netcode_client_state(client: *mut NetcodeClient) -> c_int;
    #[link_name = "dn_native_netcode_client_index"]
    pub(crate) fn netcode_client_index(client: *mut NetcodeClient) -> c_int;
    #[link_name = "dn_native_netcode_client_max_clients"]
    pub(crate) fn netcode_client_max_clients(client: *mut NetcodeClient) -> c_int;
    #[link_name = "dn_native_netcode_client_get_port"]
    pub(crate) fn netcode_client_get_port(client: *mut NetcodeClient) -> u16;

}
