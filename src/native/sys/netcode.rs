//! Raw declarations of the prefixed netcode C API and of the netcode shim
//! (`native/csrc/dn_native_netcode.{c,h}`).
//!
//! Only functions whose arguments are scalars, byte pointers, NUL-terminated strings and opaque
//! handles are declared. netcode's config and address structs are never mirrored: the shim
//! builds configs from scalars and exports addresses in the flat [`Address`] form, whose layout
//! (like [`SlotEvents`]) is pinned by `_Static_assert`s in the shim and by the const assertions
//! below. Nothing here is public; [`crate::native::netcode`] is the only caller.

use core::ffi::{c_char, c_int};

/// `struct netcode_client_t`: opaque, only ever behind a pointer.
#[repr(C)]
pub(crate) struct NetcodeClient {
    _private: [u8; 0],
}

/// `struct netcode_server_t`: opaque, only ever behind a pointer.
#[repr(C)]
pub(crate) struct NetcodeServer {
    _private: [u8; 0],
}

/// `dn_native_nc_server_t`: the shim's server handle (the netcode server plus the
/// callback's per-slot storage). Opaque.
#[repr(C)]
pub(crate) struct ShimServer {
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

/// `dn_native_nc_slot_events_t`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct SlotEvents {
    pub(crate) connects: u64,
    pub(crate) disconnects: u64,
    pub(crate) first_disconnect_reason: i32,
    pub(crate) connected: i32,
}

// The same layout the shim pins with _Static_assert.
const _: () = {
    assert!(size_of::<Address>() == 20);
    assert!(align_of::<Address>() == 2);
    assert!(core::mem::offset_of!(Address, family) == 0);
    assert!(core::mem::offset_of!(Address, reserved) == 1);
    assert!(core::mem::offset_of!(Address, port) == 2);
    assert!(core::mem::offset_of!(Address, bytes) == 4);
    assert!(size_of::<SlotEvents>() == 24);
    assert!(align_of::<SlotEvents>() == align_of::<u64>());
    assert!(core::mem::offset_of!(SlotEvents, connects) == 0);
    assert!(core::mem::offset_of!(SlotEvents, disconnects) == 8);
    assert!(core::mem::offset_of!(SlotEvents, first_disconnect_reason) == 16);
    assert!(core::mem::offset_of!(SlotEvents, connected) == 20);
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

pub(crate) const DISCONNECT_REASON_TIMED_OUT: i32 = 1;
pub(crate) const DISCONNECT_REASON_CLIENT_DISCONNECT: i32 = 2;

pub(crate) const CLIENT_CREATE_ERROR_PARSE_ADDRESS_FAILED: c_int = 1;
pub(crate) const CLIENT_CREATE_ERROR_CREATE_SOCKET_IPV4_FAILED: c_int = 4;
pub(crate) const CLIENT_CREATE_ERROR_CREATE_SOCKET_IPV6_FAILED: c_int = 5;
pub(crate) const CLIENT_CREATE_ERROR_ALLOCATE_CLIENT_FAILED: c_int = 6;

pub(crate) const SERVER_CREATE_ERROR_PARSE_ADDRESS_FAILED: c_int = 1;
pub(crate) const SERVER_CREATE_ERROR_CREATE_SOCKET_IPV4_FAILED: c_int = 3;
pub(crate) const SERVER_CREATE_ERROR_CREATE_SOCKET_IPV6_FAILED: c_int = 4;
pub(crate) const SERVER_CREATE_ERROR_BIND_SOCKET_IPV4_FAILED: c_int = 5;
pub(crate) const SERVER_CREATE_ERROR_BIND_SOCKET_IPV6_FAILED: c_int = 6;
pub(crate) const SERVER_CREATE_ERROR_ALLOCATE_SERVER_FAILED: c_int = 7;

// SAFETY: every declaration below matches its prototype in `native/vendor/netcode/netcode.h` (v1.5.0
// plus native/patches/) or `native/csrc/dn_native_netcode.h`, with C `int` as `c_int`, `uint8_t`/`uint16_t`/
// `uint64_t` as `u8`/`u16`/`u64`, `double` as `f64`, `char *` as `c_char` pointers, and struct
// pointers as pointers to the opaque or layout-pinned types above. Each is linked under its
// `dn_native_` name (`native/csrc/dn_native_prefix.h`). The preconditions of each call are listed and
// enforced in `crate::native::netcode` (module docs, "Preconditions").
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
    pub(crate) fn dn_native_nc_server_create(
        address: *const c_char,
        protocol_id: u64,
        private_key: *const u8,
        max_connect_token_lifetime: c_int,
        time: f64,
        error: *mut c_int,
        os_error: *mut c_int,
    ) -> *mut ShimServer;
    pub(crate) fn dn_native_nc_server_inner(server: *mut ShimServer) -> *mut NetcodeServer;
    pub(crate) fn dn_native_nc_server_destroy(server: *mut ShimServer);
    pub(crate) fn dn_native_nc_server_take_events(
        server: *mut ShimServer,
        out: *mut SlotEvents,
    ) -> c_int;
    pub(crate) fn dn_native_nc_server_client_identity(
        server: *mut ShimServer,
        index: c_int,
        client_id: *mut u64,
        address: *mut Address,
    ) -> c_int;
    pub(crate) fn dn_native_nc_server_client_user_data(
        server: *mut ShimServer,
        index: c_int,
    ) -> *const u8;

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

    // ---- netcode: server
    #[link_name = "dn_native_netcode_server_start"]
    pub(crate) fn netcode_server_start(server: *mut NetcodeServer, max_clients: c_int);
    #[link_name = "dn_native_netcode_server_stop"]
    pub(crate) fn netcode_server_stop(server: *mut NetcodeServer);
    #[link_name = "dn_native_netcode_server_running"]
    pub(crate) fn netcode_server_running(server: *mut NetcodeServer) -> c_int;
    #[link_name = "dn_native_netcode_server_max_clients"]
    pub(crate) fn netcode_server_max_clients(server: *mut NetcodeServer) -> c_int;
    #[link_name = "dn_native_netcode_server_update"]
    pub(crate) fn netcode_server_update(server: *mut NetcodeServer, time: f64);
    #[link_name = "dn_native_netcode_server_client_connected"]
    pub(crate) fn netcode_server_client_connected(
        server: *mut NetcodeServer,
        client_index: c_int,
    ) -> c_int;
    #[link_name = "dn_native_netcode_server_disconnect_client"]
    pub(crate) fn netcode_server_disconnect_client(server: *mut NetcodeServer, client_index: c_int);
    #[link_name = "dn_native_netcode_server_disconnect_all_clients"]
    pub(crate) fn netcode_server_disconnect_all_clients(server: *mut NetcodeServer);
    #[link_name = "dn_native_netcode_server_next_packet_sequence"]
    pub(crate) fn netcode_server_next_packet_sequence(
        server: *mut NetcodeServer,
        client_index: c_int,
    ) -> u64;
    #[link_name = "dn_native_netcode_server_send_packet"]
    pub(crate) fn netcode_server_send_packet(
        server: *mut NetcodeServer,
        client_index: c_int,
        packet_data: *const u8,
        packet_bytes: c_int,
    );
    #[link_name = "dn_native_netcode_server_receive_packet"]
    pub(crate) fn netcode_server_receive_packet(
        server: *mut NetcodeServer,
        client_index: c_int,
        packet_bytes: *mut c_int,
        packet_sequence: *mut u64,
    ) -> *mut u8;
    #[link_name = "dn_native_netcode_server_free_packet"]
    pub(crate) fn netcode_server_free_packet(server: *mut NetcodeServer, packet: *mut u8);
    #[link_name = "dn_native_netcode_server_num_connected_clients"]
    pub(crate) fn netcode_server_num_connected_clients(server: *mut NetcodeServer) -> c_int;
    #[link_name = "dn_native_netcode_server_get_port"]
    pub(crate) fn netcode_server_get_port(server: *mut NetcodeServer) -> u16;
}

#[cfg(test)]
// SAFETY: as above, for the two size probes in `native/csrc/dn_native_netcode.h`.
unsafe extern "C" {
    fn dn_native_nc_address_size() -> c_int;
    fn dn_native_nc_slot_events_size() -> c_int;
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_shim_agrees_on_the_shared_struct_sizes() {
        // SAFETY: both functions take no arguments and return a constant.
        let address = unsafe { super::dn_native_nc_address_size() };
        // SAFETY: as above.
        let events = unsafe { super::dn_native_nc_slot_events_size() };
        assert_eq!(
            usize::try_from(address).ok(),
            Some(size_of::<super::Address>())
        );
        assert_eq!(
            usize::try_from(events).ok(),
            Some(size_of::<super::SlotEvents>())
        );
    }
}
