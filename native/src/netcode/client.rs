//! The netcode client.

use core::ffi::c_int;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::ptr::NonNull;

use super::address::{self, CAddress};
use super::{CONNECT_TOKEN_BYTES, Error, MAX_PAYLOAD_BYTES, Time, copy_payload, create_lock};
use crate::sys;
use crate::sys::netcode as ffi;

/// The state of a [`Client`], as netcode's `NETCODE_CLIENT_STATE_*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClientState {
    /// The token expired before the connection completed.
    ConnectTokenExpired,
    /// The token could not be read, or lists no server of the client's address family.
    InvalidConnectToken,
    /// An established connection stopped hearing from the server.
    ConnectionTimedOut,
    /// The server stopped answering the connection response.
    ConnectionResponseTimedOut,
    /// No server answered the connection request.
    ConnectionRequestTimedOut,
    /// The server was full.
    ConnectionDenied,
    /// Not connected, and not in an error state.
    Disconnected,
    /// Sending connection requests.
    SendingConnectionRequest,
    /// Sending connection responses to a challenge.
    SendingConnectionResponse,
    /// Connected: payloads flow.
    Connected,
}

impl ClientState {
    /// Whether this is one of the six failure states.
    pub fn is_error(self) -> bool {
        matches!(
            self,
            ClientState::ConnectTokenExpired
                | ClientState::InvalidConnectToken
                | ClientState::ConnectionTimedOut
                | ClientState::ConnectionResponseTimedOut
                | ClientState::ConnectionRequestTimedOut
                | ClientState::ConnectionDenied
        )
    }

    /// Whether the client is in the middle of a handshake.
    pub fn is_connecting(self) -> bool {
        matches!(
            self,
            ClientState::SendingConnectionRequest | ClientState::SendingConnectionResponse
        )
    }

    /// Whether the client is not connected and not connecting.
    pub fn is_disconnected(self) -> bool {
        self == ClientState::Disconnected || self.is_error()
    }

    fn from_c(state: c_int) -> Self {
        match state {
            ffi::CLIENT_STATE_CONNECT_TOKEN_EXPIRED => ClientState::ConnectTokenExpired,
            ffi::CLIENT_STATE_INVALID_CONNECT_TOKEN => ClientState::InvalidConnectToken,
            ffi::CLIENT_STATE_CONNECTION_TIMED_OUT => ClientState::ConnectionTimedOut,
            ffi::CLIENT_STATE_CONNECTION_RESPONSE_TIMED_OUT => {
                ClientState::ConnectionResponseTimedOut
            }
            ffi::CLIENT_STATE_CONNECTION_REQUEST_TIMED_OUT => {
                ClientState::ConnectionRequestTimedOut
            }
            ffi::CLIENT_STATE_CONNECTION_DENIED => ClientState::ConnectionDenied,
            ffi::CLIENT_STATE_SENDING_CONNECTION_REQUEST => ClientState::SendingConnectionRequest,
            ffi::CLIENT_STATE_SENDING_CONNECTION_RESPONSE => ClientState::SendingConnectionResponse,
            ffi::CLIENT_STATE_CONNECTED => ClientState::Connected,
            // NETCODE_CLIENT_STATE_DISCONNECTED (0), and any value netcode never produces
            _ => ClientState::Disconnected,
        }
    }
}

impl fmt::Display for ClientState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            ClientState::ConnectTokenExpired => "connect token expired",
            ClientState::InvalidConnectToken => "invalid connect token",
            ClientState::ConnectionTimedOut => "connection timed out",
            ClientState::ConnectionResponseTimedOut => "connection response timed out",
            ClientState::ConnectionRequestTimedOut => "connection request timed out",
            ClientState::ConnectionDenied => "connection denied",
            ClientState::Disconnected => "disconnected",
            ClientState::SendingConnectionRequest => "sending connection request",
            ClientState::SendingConnectionResponse => "sending connection response",
            ClientState::Connected => "connected",
        };
        f.write_str(name)
    }
}

/// A netcode client: one UDP socket and at most one connection.
///
/// Owns a C `netcode_client_t`. Neither `Send` nor `Sync` (it holds a raw pointer, and nothing
/// needs to move it between threads); see the module docs.
pub struct Client {
    raw: NonNull<ffi::NetcodeClient>,
    time: Time,
}

impl Client {
    /// Binds a client socket to `bind_address` (IPv4 or IPv6; port 0 for an ephemeral port).
    ///
    /// `time` is the caller's clock in seconds, which [`update`](Self::update) continues.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when the socket cannot be created or bound, when `bind_address` is an IPv6
    /// address with a non-zero scope id (netcode cannot bind one: refused rather than bound
    /// without it), or when the native library cannot be initialised.
    pub fn new(bind_address: SocketAddr, time: f64) -> Result<Self, Error> {
        if let SocketAddr::V6(v6) = bind_address
            && v6.scope_id() != 0
        {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "netcode cannot bind an IPv6 address with a scope id",
            )));
        }
        if !sys::ensure_init() {
            return Err(super::error::init_failed());
        }
        let text = CAddress::new(bind_address);
        let time = Time::new(time);
        let mut error: c_int = 0;
        let mut os_error: c_int = 0;
        let raw = {
            let _guard = create_lock();
            // SAFETY: the library is initialised; `text` is a NUL-terminated string that
            // outlives the call; `error` and `os_error` are writable ints. The shim builds the
            // config from netcode_default_client_config (no simulator, no overrides), which is
            // every assert of netcode_client_create. The process-global create error it reads is
            // only written by creates, which the lock serialises.
            unsafe {
                ffi::dn_native_nc_client_create(
                    text.as_ptr(),
                    time.now(),
                    &raw mut error,
                    &raw mut os_error,
                )
            }
        };
        match NonNull::new(raw) {
            Some(raw) => Ok(Self { raw, time }),
            None => Err(super::error::client_create(error, os_error)),
        }
    }

    /// Starts connecting with `connect_token`, after ending any connection or attempt in
    /// progress (which sends disconnect packets if it was connected).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConnectToken`] when netcode cannot read the token, or when the token
    /// lists no server address of the family this client is bound to. The client is then in
    /// [`ClientState::InvalidConnectToken`].
    pub fn connect(&mut self, connect_token: &[u8; CONNECT_TOKEN_BYTES]) -> Result<(), Error> {
        // SAFETY: `raw` is a live client (owned, destroyed only in Drop); the token pointer is
        // non-null and points at CONNECT_TOKEN_BYTES bytes, the length netcode reads. netcode
        // declares the parameter non-const but only reads through it (netcode_client_connect
        // passes it to netcode_read_connect_token, which copies out with netcode_read_*), so a
        // pointer derived from a shared reference is never written through.
        unsafe {
            ffi::netcode_client_connect(self.raw.as_ptr(), connect_token.as_ptr().cast_mut());
        }
        if self.state() == ClientState::InvalidConnectToken {
            Err(Error::InvalidConnectToken)
        } else {
            Ok(())
        }
    }

    /// Advances the client to `time` (seconds): receives, sends keep-alives and requests, and
    /// handles timeouts and token expiry.
    ///
    /// netcode requires non-decreasing time; a `time` earlier than the latest one, or not
    /// finite, is replaced by the latest one.
    pub fn update(&mut self, time: f64) {
        let now = self.time.advance(time);
        // SAFETY: `raw` is a live client, never in loopback mode.
        unsafe { ffi::netcode_client_update(self.raw.as_ptr(), now) };
    }

    /// Sends `payload` to the server if connected; otherwise does nothing and returns `Ok`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidPayloadSize`] for an empty payload or one over `MAX_PAYLOAD_BYTES`,
    /// whatever the state.
    pub fn send_packet(&mut self, payload: &[u8]) -> Result<(), Error> {
        let Some(bytes) = payload_len(payload) else {
            return Err(Error::InvalidPayloadSize(payload.len()));
        };
        // SAFETY: `raw` is a live client; `payload` is `bytes` readable bytes with bytes in
        // 1..=NETCODE_MAX_PACKET_SIZE (checked above), which are the asserts of
        // netcode_client_send_packet. netcode ignores the call unless connected.
        unsafe { ffi::netcode_client_send_packet(self.raw.as_ptr(), payload.as_ptr(), bytes) };
        Ok(())
    }

    /// Takes the next received payload and its sequence number, if any.
    pub fn receive_packet(&mut self) -> Option<(Vec<u8>, u64)> {
        let mut payload = Vec::new();
        let sequence = self.receive_packet_into(&mut payload)?;
        Some((payload, sequence))
    }

    /// Takes the next received payload into `buffer` (cleared first, then filled with exactly
    /// the payload) and returns its sequence number, or returns `None` and leaves `buffer`
    /// empty. Reusing one buffer makes receiving allocation-free once it has grown to the
    /// largest payload; the C packet is freed before this returns.
    pub fn receive_packet_into(&mut self, buffer: &mut Vec<u8>) -> Option<u64> {
        buffer.clear();
        loop {
            let mut bytes: c_int = 0;
            let mut sequence: u64 = 0;
            // SAFETY: `raw` is a live client; both out-pointers are writable.
            let packet = unsafe {
                ffi::netcode_client_receive_packet(
                    self.raw.as_ptr(),
                    &raw mut bytes,
                    &raw mut sequence,
                )
            };
            if packet.is_null() {
                return None;
            }
            // SAFETY: netcode returned a non-null payload pointer with `bytes` readable bytes
            // behind it, owned by us until netcode_client_free_packet below.
            let copied = unsafe { copy_payload(packet, bytes, buffer) };
            // SAFETY: `packet` came from netcode_client_receive_packet on this client and is
            // freed exactly once, after the last read of it above.
            unsafe { ffi::netcode_client_free_packet(self.raw.as_ptr(), packet) };
            if copied {
                return Some(sequence);
            }
            // a size netcode never queues (it asserts 0..=1200): dropped, take the next one
        }
    }

    /// Disconnects, sending disconnect packets if connected. Does nothing when already
    /// disconnected (or in an error state, which it keeps).
    pub fn disconnect(&mut self) {
        // SAFETY: `raw` is a live client, never in loopback mode.
        unsafe { ffi::netcode_client_disconnect(self.raw.as_ptr()) };
    }

    /// The client's state.
    pub fn state(&self) -> ClientState {
        // SAFETY: `raw` is a live client; the call only reads.
        ClientState::from_c(unsafe { ffi::netcode_client_state(self.raw.as_ptr()) })
    }

    /// The slot the server gave this client (0 until connected).
    pub fn client_index(&self) -> usize {
        // SAFETY: `raw` is a live client; the call only reads.
        let index = unsafe { ffi::netcode_client_index(self.raw.as_ptr()) };
        usize::try_from(index).unwrap_or(0)
    }

    /// The server's slot count, as its keep-alive said (0 until connected).
    pub fn max_clients(&self) -> usize {
        // SAFETY: `raw` is a live client; the call only reads.
        let max = unsafe { ffi::netcode_client_max_clients(self.raw.as_ptr()) };
        usize::try_from(max).unwrap_or(0)
    }

    /// The sequence number the next packet to the server will carry.
    pub fn next_packet_sequence(&self) -> u64 {
        // SAFETY: `raw` is a live client; the call only reads.
        unsafe { ffi::netcode_client_next_packet_sequence(self.raw.as_ptr()) }
    }

    /// The local port the client's socket is bound to.
    pub fn port(&self) -> u16 {
        // SAFETY: `raw` is a live client; the call only reads.
        unsafe { ffi::netcode_client_get_port(self.raw.as_ptr()) }
    }

    /// The server being connected to or connected to; `None` when disconnected.
    pub fn server_address(&self) -> Option<SocketAddr> {
        let mut flat = ffi::Address::default();
        // SAFETY: `raw` is a live client; `flat` is a writable, layout-pinned address.
        let some =
            unsafe { ffi::dn_native_nc_client_server_address(self.raw.as_ptr(), &raw mut flat) };
        if some == 0 {
            None
        } else {
            address::from_flat(&flat)
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        // SAFETY: `raw` is a live client and this is the only place it is destroyed; it is
        // never used again. netcode_client_destroy disconnects first (sending disconnect packets
        // if connected), closes the sockets and frees the client.
        unsafe { ffi::netcode_client_destroy(self.raw.as_ptr()) };
    }
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // never the token or its keys
        f.debug_struct("Client")
            .field("state", &self.state())
            .field("port", &self.port())
            .field("server_address", &self.server_address())
            .field("client_index", &self.client_index())
            .finish_non_exhaustive()
    }
}

/// The payload length as netcode's `int`, if it is in `1..=MAX_PAYLOAD_BYTES`.
pub(super) fn payload_len(payload: &[u8]) -> Option<c_int> {
    if payload.is_empty() || payload.len() > MAX_PAYLOAD_BYTES {
        return None;
    }
    c_int::try_from(payload.len()).ok()
}
