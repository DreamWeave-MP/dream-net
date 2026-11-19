//! The netcode server.

use core::ffi::c_int;
use std::collections::VecDeque;
use std::fmt;
use std::net::SocketAddr;
use std::ptr::NonNull;

use super::address::{self, CAddress};
use super::client::payload_len;
use super::{Error, Key, MAX_CLIENTS, Time, UserData, copy_payload, create_lock};
use crate::native::sys;
use crate::native::sys::netcode as ffi;

/// Why a client left a server slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DisconnectReason {
    /// The server stopped hearing from the client for the token's timeout.
    TimedOut,
    /// The client sent disconnect packets.
    ClientDisconnect,
    /// The server disconnected it: [`Server::disconnect_client`],
    /// [`Server::disconnect_all_clients`], [`Server::stop`], or a restart through
    /// [`Server::start`].
    ServerDisconnect,
}

/// A change in a server slot, from [`Server::next_event`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServerEvent {
    /// A client now occupies `client_index`.
    ClientConnected {
        /// The slot.
        client_index: usize,
    },
    /// The client in `client_index` left.
    ClientDisconnected {
        /// The slot.
        client_index: usize,
        /// Why.
        reason: DisconnectReason,
    },
}

/// Server construction options that `netcode-official` 1.0.0 did not have.
///
/// `#[non_exhaustive]`: start from [`ServerOptions::default`] and set fields, or use the
/// `with_*` methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ServerOptions {
    /// The longest lifetime, in seconds, of the connect tokens this server's backend issues:
    /// netcode's `max_connect_token_lifetime`. Default 30 (netcode's default). Must be in
    /// `1..=i32::MAX`. See "Token lifetime and the start floor" in the module docs for exactly
    /// what it refuses.
    pub max_connect_token_lifetime: u32,
}

impl ServerOptions {
    /// netcode's default maximum connect-token lifetime, in seconds.
    pub const DEFAULT_MAX_CONNECT_TOKEN_LIFETIME: u32 = 30;

    /// These options with `max_connect_token_lifetime` set to `seconds`.
    #[must_use]
    pub fn with_max_connect_token_lifetime(mut self, seconds: u32) -> Self {
        self.max_connect_token_lifetime = seconds;
        self
    }
}

impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            max_connect_token_lifetime: Self::DEFAULT_MAX_CONNECT_TOKEN_LIFETIME,
        }
    }
}

/// A netcode server: one UDP socket and up to [`MAX_CLIENTS`] client slots.
///
/// Owns the shim's server handle (the C `netcode_server_t` plus the fixed per-slot storage its
/// connect/disconnect callback writes). Neither `Send` nor `Sync`; see the module docs.
pub struct Server {
    shim: NonNull<ffi::ShimServer>,
    raw: NonNull<ffi::NetcodeServer>,
    address: SocketAddr,
    options: ServerOptions,
    time: Time,
    /// Per slot: whether the last event reported for it was `ClientConnected`.
    reported: Box<[bool; MAX_CLIENTS]>,
    /// At most two events per slot, refilled only when empty: never grows past its initial
    /// capacity.
    events: VecDeque<ServerEvent>,
    scratch: Box<[ffi::SlotEvents; MAX_CLIENTS]>,
}

impl Server {
    /// Creates a server for `public_address` with the default [`ServerOptions`]. It is not
    /// running until [`start`](Self::start).
    ///
    /// # Errors
    ///
    /// As [`with_options`](Self::with_options).
    pub fn new(
        public_address: SocketAddr,
        protocol_id: u64,
        private_key: &Key,
        time: f64,
    ) -> Result<Self, Error> {
        Self::with_options(
            public_address,
            protocol_id,
            private_key,
            time,
            ServerOptions::default(),
        )
    }

    /// Creates a server for `public_address`.
    ///
    /// netcode binds `0.0.0.0:<port>` (IPv4) or `[::]:<port>` (IPv6, v6-only) and accepts
    /// only connect tokens whose server list contains `public_address` exactly (IP and port).
    /// Port 0 binds an ephemeral port, which [`address`](Self::address) and
    /// [`port`](Self::port) then report and which tokens must name (patch 0001). An IPv6
    /// scope id or flow label is ignored: netcode compares only IP and port. The private key
    /// is copied into netcode (which zeroes it on destruction) and never kept in Rust.
    ///
    /// The port is held exclusively on every platform: the bind fails with `AddrInUse` when
    /// another socket holds the port on any address, and no other socket can bind it
    /// afterwards. Windows allows both by default; patch 0002 sets `SO_EXCLUSIVEADDRUSE`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConnectTokenLifetime`] for a lifetime outside `1..=i32::MAX`;
    /// [`Error::Io`] when the socket cannot be created or bound (a port in use is
    /// `ErrorKind::AddrInUse`), or when the native library cannot be initialised.
    pub fn with_options(
        public_address: SocketAddr,
        protocol_id: u64,
        private_key: &Key,
        time: f64,
        options: ServerOptions,
    ) -> Result<Self, Error> {
        let lifetime = c_int::try_from(options.max_connect_token_lifetime)
            .ok()
            .filter(|l| *l > 0)
            .ok_or(Error::InvalidConnectTokenLifetime(
                options.max_connect_token_lifetime,
            ))?;
        if !sys::ensure_init() {
            return Err(super::error::init_failed());
        }
        let public_address = address::strip_v6_extras(public_address);
        let text = CAddress::new(public_address);
        let time = Time::new(time);
        let mut error: c_int = 0;
        let mut os_error: c_int = 0;
        let shim = {
            let _guard = create_lock();
            // SAFETY: the library is initialised; `text` is a NUL-terminated string and
            // `private_key` KEY_BYTES readable bytes, both outliving the call; `error` and
            // `os_error` are writable ints; `lifetime` > 0. The shim builds the config from
            // netcode_default_server_config (no simulator, no overrides), which is every assert
            // of netcode_server_create. The process-global create error it reads is only
            // written by creates, which the lock serialises.
            unsafe {
                ffi::dn_native_nc_server_create(
                    text.as_ptr(),
                    protocol_id,
                    private_key.as_ptr(),
                    lifetime,
                    time.now(),
                    &raw mut error,
                    &raw mut os_error,
                )
            }
        };
        let Some(shim) = NonNull::new(shim) else {
            return Err(super::error::server_create(error, os_error));
        };
        // SAFETY: `shim` is a live handle just returned by the shim's create.
        let raw = unsafe { ffi::dn_native_nc_server_inner(shim.as_ptr()) };
        let Some(raw) = NonNull::new(raw) else {
            // SAFETY: `shim` is live and destroyed exactly once, here. Unreachable: a handle is
            // only returned with its server.
            unsafe { ffi::dn_native_nc_server_destroy(shim.as_ptr()) };
            return Err(super::error::server_create(-1, 0));
        };
        // SAFETY: `raw` is the live server inside `shim`; the call only reads the bound port.
        let port = unsafe { ffi::netcode_server_get_port(raw.as_ptr()) };
        let mut address = public_address;
        address.set_port(port);
        Ok(Self {
            shim,
            raw,
            address,
            options,
            time,
            reported: Box::new([false; MAX_CLIENTS]),
            events: VecDeque::with_capacity(2 * MAX_CLIENTS),
            scratch: Box::new([ffi::SlotEvents::default(); MAX_CLIENTS]),
        })
    }

    /// Starts accepting clients into `max_clients` slots, stopping first if running (which
    /// disconnects everyone). Each start draws a new challenge key and sets the start floor
    /// for connect tokens (module docs) from the wall clock now.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidMaxClients`] outside `1..=MAX_CLIENTS`; the server is then unchanged.
    pub fn start(&mut self, max_clients: usize) -> Result<(), Error> {
        if max_clients == 0 || max_clients > MAX_CLIENTS {
            return Err(Error::InvalidMaxClients(max_clients));
        }
        let Ok(max) = c_int::try_from(max_clients) else {
            return Err(Error::InvalidMaxClients(max_clients));
        };
        // SAFETY: `raw` is live; `max` is in 1..=NETCODE_MAX_CLIENTS (checked above), the
        // asserts of netcode_server_start. Callbacks it fires (through its stop) land in the
        // shim's storage, which lives as long as `raw`.
        unsafe { ffi::netcode_server_start(self.raw.as_ptr(), max) };
        Ok(())
    }

    /// Disconnects every client (each gets [`DisconnectReason::ServerDisconnect`]) and stops.
    /// Does nothing when not running. The server can be started again.
    pub fn stop(&mut self) {
        // SAFETY: `raw` is live; netcode_server_stop returns at once when not running.
        unsafe { ffi::netcode_server_stop(self.raw.as_ptr()) };
    }

    /// Advances the server to `time` (seconds): receives every pending datagram, sends
    /// keep-alives, and times out silent clients. Slot changes become [`next_event`]s.
    ///
    /// netcode requires non-decreasing time; a `time` earlier than the latest one, or not
    /// finite, is replaced by the latest one.
    ///
    /// [`next_event`]: Self::next_event
    pub fn update(&mut self, time: f64) {
        let now = self.time.advance(time);
        // SAFETY: `raw` is live. Callbacks land in the shim's storage, which lives as long as
        // `raw`; they only copy into it.
        unsafe { ffi::netcode_server_update(self.raw.as_ptr(), now) };
    }

    /// The next slot change, or `None`.
    ///
    /// Events are synthesised from the shim's per-slot record of every connect/disconnect
    /// callback since the previous batch, when the queue runs empty: first every
    /// `ClientDisconnected` in slot order, then every `ClientConnected` in slot order. A slot
    /// that changed hands since the previous batch always yields `ClientDisconnected` (for the
    /// client last reported) before `ClientConnected` (for the client there now). A session
    /// that both began and ended between two batches is not reported. See the module docs.
    pub fn next_event(&mut self) -> Option<ServerEvent> {
        if self.events.is_empty() {
            self.collect_events();
        }
        self.events.pop_front()
    }

    fn collect_events(&mut self) {
        // SAFETY: `shim` is live; `scratch` is MAX_CLIENTS writable, layout-pinned records, the
        // length the shim writes.
        let taken = unsafe {
            ffi::dn_native_nc_server_take_events(self.shim.as_ptr(), self.scratch.as_mut_ptr())
        };
        if taken == 0 {
            return;
        }
        for (client_index, slot) in self.scratch.iter().enumerate() {
            if self.reported[client_index] && (slot.disconnects > 0 || slot.connects > 0) {
                self.events.push_back(ServerEvent::ClientDisconnected {
                    client_index,
                    reason: reason_from_c(slot.first_disconnect_reason),
                });
                self.reported[client_index] = false;
            }
        }
        for (client_index, slot) in self.scratch.iter().enumerate() {
            let connected = slot.connected != 0;
            if connected && !self.reported[client_index] {
                self.events
                    .push_back(ServerEvent::ClientConnected { client_index });
            }
            self.reported[client_index] = connected;
        }
    }

    /// Sends `payload` to the client in `client_index`. Does nothing (and returns `Ok`) when
    /// not running, the index is out of range, or the slot is empty.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidPayloadSize`] for an empty payload or one over `MAX_PAYLOAD_BYTES`,
    /// whatever the state.
    pub fn send_packet(&mut self, client_index: usize, payload: &[u8]) -> Result<(), Error> {
        let Some(bytes) = payload_len(payload) else {
            return Err(Error::InvalidPayloadSize(payload.len()));
        };
        let Some(index) = self.connected_index(client_index) else {
            return Ok(());
        };
        // SAFETY: `raw` is live and running, `index` is a connected slot below max_clients,
        // and `payload` is `bytes` readable bytes with bytes in 1..=NETCODE_MAX_PACKET_SIZE:
        // every assert of netcode_server_send_packet.
        unsafe {
            ffi::netcode_server_send_packet(self.raw.as_ptr(), index, payload.as_ptr(), bytes);
        }
        Ok(())
    }

    /// Takes the next payload received from the client in `client_index`, with its sequence
    /// number. `None` when there is none, when not running, or for an empty or out-of-range
    /// slot.
    pub fn receive_packet(&mut self, client_index: usize) -> Option<(Vec<u8>, u64)> {
        let mut payload = Vec::new();
        let sequence = self.receive_packet_into(client_index, &mut payload)?;
        Some((payload, sequence))
    }

    /// Takes the next payload from the client in `client_index` into `buffer` (cleared first,
    /// then filled with exactly the payload) and returns its sequence number; `None` (with
    /// `buffer` empty) as [`receive_packet`](Self::receive_packet). Reusing one buffer makes
    /// receiving allocation-free once it has grown to the largest payload; the C packet is
    /// freed before this returns.
    pub fn receive_packet_into(
        &mut self,
        client_index: usize,
        buffer: &mut Vec<u8>,
    ) -> Option<u64> {
        buffer.clear();
        let index = self.connected_index(client_index)?;
        loop {
            let mut bytes: c_int = 0;
            let mut sequence: u64 = 0;
            // SAFETY: `raw` is live and running, `index` is a connected slot below max_clients
            // (netcode_server_receive_packet's asserts), and both out-pointers are writable.
            let packet = unsafe {
                ffi::netcode_server_receive_packet(
                    self.raw.as_ptr(),
                    index,
                    &raw mut bytes,
                    &raw mut sequence,
                )
            };
            if packet.is_null() {
                return None;
            }
            // SAFETY: netcode returned a non-null payload pointer with `bytes` readable bytes
            // behind it, owned by us until netcode_server_free_packet below.
            let copied = unsafe { copy_payload(packet, bytes, buffer) };
            // SAFETY: `packet` came from netcode_server_receive_packet on this server and is
            // freed exactly once, after the last read of it above.
            unsafe { ffi::netcode_server_free_packet(self.raw.as_ptr(), packet) };
            if copied {
                return Some(sequence);
            }
        }
    }

    /// Disconnects the client in `client_index`, sending it disconnect packets; it is reported
    /// as [`DisconnectReason::ServerDisconnect`]. Does nothing for an empty or out-of-range
    /// slot, or when not running.
    pub fn disconnect_client(&mut self, client_index: usize) {
        if let Some(index) = self.connected_index(client_index) {
            // SAFETY: `raw` is live and running; `index` is a connected slot below
            // max_clients, the asserts of netcode_server_disconnect_client.
            unsafe { ffi::netcode_server_disconnect_client(self.raw.as_ptr(), index) };
        }
    }

    /// Disconnects every client, as [`disconnect_client`](Self::disconnect_client). Does
    /// nothing when not running.
    pub fn disconnect_all_clients(&mut self) {
        // SAFETY: `raw` is live; the call returns at once when not running.
        unsafe { ffi::netcode_server_disconnect_all_clients(self.raw.as_ptr()) };
    }

    /// Whether the server is started.
    pub fn running(&self) -> bool {
        // SAFETY: `raw` is live; the call only reads.
        unsafe { ffi::netcode_server_running(self.raw.as_ptr()) != 0 }
    }

    /// The slot count given to [`start`](Self::start); 0 when not running.
    pub fn max_clients(&self) -> usize {
        // SAFETY: `raw` is live; the call only reads.
        let max = unsafe { ffi::netcode_server_max_clients(self.raw.as_ptr()) };
        usize::try_from(max).unwrap_or(0)
    }

    /// How many slots are occupied.
    pub fn num_connected_clients(&self) -> usize {
        // SAFETY: `raw` is live; the call only reads.
        let n = unsafe { ffi::netcode_server_num_connected_clients(self.raw.as_ptr()) };
        usize::try_from(n).unwrap_or(0)
    }

    /// Whether a client occupies `client_index` (false when not running or out of range).
    pub fn client_connected(&self, client_index: usize) -> bool {
        self.connected_index(client_index).is_some()
    }

    /// The client id of the client in `client_index`, captured when it connected; 0 for an
    /// empty or out-of-range slot.
    pub fn client_id(&self, client_index: usize) -> u64 {
        self.identity(client_index).map_or(0, |(id, _)| id)
    }

    /// The address of the client in `client_index`, captured when it connected.
    pub fn client_address(&self, client_index: usize) -> Option<SocketAddr> {
        self.identity(client_index).and_then(|(_, a)| a)
    }

    /// The user data of the client in `client_index` (from its connect token), captured when
    /// it connected.
    pub fn client_user_data(&self, client_index: usize) -> Option<&UserData> {
        let index = c_int::try_from(client_index).ok()?;
        // SAFETY: `shim` is live; any index is accepted (the shim range-checks it).
        let data = unsafe { ffi::dn_native_nc_server_client_user_data(self.shim.as_ptr(), index) };
        // SAFETY: a non-null result points at USER_DATA_BYTES bytes inside the shim handle,
        // which lives as long as `self`. They are written only by the connect callback, which
        // fires only inside calls that take `&mut self`, so they cannot change while the
        // returned borrow of `self` lives. `UserData` is a byte array: no alignment or validity
        // requirement beyond that.
        unsafe { data.cast::<UserData>().as_ref() }
    }

    /// The sequence number of the next packet to the client in `client_index`; 0 for an empty
    /// or out-of-range slot.
    pub fn next_packet_sequence(&self, client_index: usize) -> u64 {
        match self.connected_index(client_index) {
            // SAFETY: `raw` is live and running; `index` is a connected slot below max_clients,
            // the asserts of netcode_server_next_packet_sequence. The call only reads.
            Some(index) => unsafe {
                ffi::netcode_server_next_packet_sequence(self.raw.as_ptr(), index)
            },
            None => 0,
        }
    }

    /// The port the server's socket is bound to (the real one when created with port 0).
    pub fn port(&self) -> u16 {
        self.address.port()
    }

    /// The public address, with the bound port.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// The options the server was created with.
    pub fn options(&self) -> ServerOptions {
        self.options
    }

    /// `client_index` as a C int when it is an occupied slot of a running server.
    fn connected_index(&self, client_index: usize) -> Option<c_int> {
        if client_index >= MAX_CLIENTS {
            return None;
        }
        let index = c_int::try_from(client_index).ok()?;
        // SAFETY: `raw` is live; netcode_server_client_connected checks running and the range
        // itself and only reads.
        let connected = unsafe { ffi::netcode_server_client_connected(self.raw.as_ptr(), index) };
        (connected != 0).then_some(index)
    }

    fn identity(&self, client_index: usize) -> Option<(u64, Option<SocketAddr>)> {
        let index = c_int::try_from(client_index).ok()?;
        let mut id = 0u64;
        let mut flat = ffi::Address::default();
        // SAFETY: `shim` is live; any index is accepted (the shim range-checks it); both
        // out-pointers are writable.
        let found = unsafe {
            ffi::dn_native_nc_server_client_identity(
                self.shim.as_ptr(),
                index,
                &raw mut id,
                &raw mut flat,
            )
        };
        (found != 0).then(|| (id, address::from_flat(&flat)))
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        // SAFETY: `shim` is live and this is the only place it is destroyed; neither it nor
        // `raw` is used again. The shim destroys the netcode server first (its stop fires the
        // callback into the handle's storage, which is still allocated) and frees the handle
        // after. Events from that final stop are discarded with the server.
        unsafe { ffi::dn_native_nc_server_destroy(self.shim.as_ptr()) };
    }
}

impl fmt::Debug for Server {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // never the private key (which Rust does not hold anyway)
        f.debug_struct("Server")
            .field("address", &self.address)
            .field("running", &self.running())
            .field("max_clients", &self.max_clients())
            .field("num_connected_clients", &self.num_connected_clients())
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

fn reason_from_c(reason: i32) -> DisconnectReason {
    match reason {
        ffi::DISCONNECT_REASON_TIMED_OUT => DisconnectReason::TimedOut,
        ffi::DISCONNECT_REASON_CLIENT_DISCONNECT => DisconnectReason::ClientDisconnect,
        // SERVER_DISCONNECT (3), and NONE (0), which netcode never records for a disconnect
        _ => DisconnectReason::ServerDisconnect,
    }
}
