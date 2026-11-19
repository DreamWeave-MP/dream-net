//! A dream-net server over netcode.
//!
//! The server owns a netcode server (upstream C netcode 1.5.0 through the safe binding in
//! dream-net's `native` module), which holds the socket and the private key, and one [`Connection`] per
//! client slot. It is driven by the host in one explicit network phase per frame:
//!
//! ```text
//! server.update(time)        receive, decrypt, decode, ack, handshake, timers
//! while let Some(event) = server.poll() { ... }     lifecycle and events, in arrival order
//! server.send(peer, event, &payload)                 queue (copied before returning)
//! server.flush()             aggregate, packetize, encrypt, send
//! ```
//!
//! Nothing calls back into the host. A peer is announced with [`ServerEvent::Connected`] only
//! after its schema fingerprint matched; a peer that fails the handshake is reported as
//! [`ServerEvent::Rejected`] and never becomes addressable.
//!
//! # Connect tokens
//!
//! A server admits a client only with a connect token minted for it by
//! [`generate_connect_token`](crate::generate_connect_token) under the server's private key,
//! naming the server's [`address`](Server::address) and protocol id.
//!
//! A connect token admits one connection attempt: mint a new token for every attempt. The
//! server enforces these rules of netcode's:
//!
//! - **Single use.** Once a session has been established with a token, the token admits
//!   nothing again on this server, from any address, even after that session ended. A client
//!   that reconnects needs a fresh token. Until then, a token is held for the attempt that
//!   first presented it (its address and the client salt it drew in `connect`) for the token's
//!   `timeout_seconds`, so a handshake that loses a packet can still complete, while another
//!   attempt with the same token, from another address or from a later `connect` on the same
//!   socket, is refused.
//! - **Expiry.** A token whose expire timestamp is not later than the server's wall clock is
//!   refused.
//! - **The start floor.** When the server starts it records
//!   `floor = wall-clock second at start + max_connect_token_lifetime`
//!   ([`DEFAULT_MAX_CONNECT_TOKEN_LIFETIME`], 30 seconds, with [`Server::new`]; any other value
//!   with [`Server::with_max_token_lifetime`]). A token whose expire timestamp is not later
//!   than the floor is refused. A token no longer-lived than the maximum is therefore accepted
//!   only if it was minted in a wall-clock second after the server's start second, and a token
//!   minted before the start never is. This is the restart protection: the single-use history
//!   lives in memory and does not survive a restart (of this process, or of another one on the
//!   same key and address), and without the floor a token used before the restart would open
//!   a second session.
//!
//! The floor only covers tokens whose lifetime does not exceed the server's maximum. A token
//! that lives longer, or never expires (a negative `expire_seconds`), passes the floor and can
//! be presented again to a restarted server for the rest of its life. A host that keeps its
//! private key across server starts must therefore mint tokens no longer-lived than the
//! maximum it gives the server. A host that generates a fresh key for every server start (as
//! l3i does) is not exposed to replay across restarts at all: a token minted under the old key
//! does not decrypt under the new one.
//!
//! A refused token is never answered: netcode ignores the request, so the client keeps asking
//! until its attempt runs out and reports
//! [`ClientEvent::ConnectFailed`](crate::ClientEvent::ConnectFailed) with
//! [`DisconnectReason::TimedOut`] (after the token's `timeout_seconds` for each server address
//! it lists, on the client's clock), or with [`DisconnectReason::Authentication`] if the
//! token's lifetime, counted from `connect`, runs out first.
//!
//! Two clocks are involved. Token timestamps, expiry and the floor use the **wall clock**
//! (whole Unix seconds, read inside netcode when a token is minted, when a server starts, and
//! when it checks a request). Everything else (keep-alives, connection timeouts, the client's
//! own token countdown from `connect`, dream-net's handshake timeout and mismatch linger) uses
//! the **host's clock**: the `time` given to `new` and `update`.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use crate::capture::{CaptureKind, CaptureRecord, CaptureSink};
use crate::config::TransportConfig;
use crate::connection::{Connection, ConnectionEvent, Shared};
use crate::error::{BufferTooSmall, Error, SendError};
use crate::id::{ChannelId, EventTypeId, PeerId};
use crate::inbox::{Inbox, Record};
use crate::lifecycle::{DisconnectReason, Failure};
use crate::native::netcode;
use crate::schema::Schema;
use crate::stats::{ConnectionStats, Counters, MemoryUsage};

/// The maximum connect-token lifetime, in seconds, that [`Server::new`] gives netcode: netcode's
/// own default. See [Connect tokens](self#connect-tokens).
pub const DEFAULT_MAX_CONNECT_TOKEN_LIFETIME: u32 =
    netcode::ServerOptions::DEFAULT_MAX_CONNECT_TOKEN_LIFETIME;

/// Server settings.
#[derive(Debug, Clone, PartialEq)]
pub struct ServerConfig {
    /// The address clients connect to (it goes into connect tokens). Port 0 binds an ephemeral
    /// port and advertises it.
    pub public_address: SocketAddr,
    /// netcode's protocol id: the host's protocol family. Schema compatibility is checked
    /// separately, by fingerprint.
    pub protocol_id: u64,
    /// Client slots, in `[1, 256]`.
    pub max_clients: usize,
    /// Transport limits.
    pub transport: TransportConfig,
}

/// A server lifecycle or message record. `P` is the payload: a borrowed slice from
/// [`Server::poll`], its length from [`Server::poll_into`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerEvent<P> {
    /// A client completed the handshake and can be sent events.
    Connected {
        /// Its handle.
        peer: PeerId,
        /// Its authenticated id from the connect token.
        client_id: u64,
    },
    /// A connected client left. Every `Connected` is followed by exactly one of these.
    Disconnected {
        /// Its handle, now invalid.
        peer: PeerId,
        /// Why.
        reason: DisconnectReason,
    },
    /// A client authenticated with netcode but failed dream-net's handshake. It was never
    /// announced and has been disconnected.
    Rejected {
        /// The handle it would have had.
        peer: PeerId,
        /// Its authenticated id from the connect token.
        client_id: u64,
        /// What failed; a schema mismatch carries both fingerprints.
        failure: Failure,
    },
    /// An event from a connected client.
    Message {
        /// The authenticated sender.
        peer: PeerId,
        /// The event type.
        event: EventTypeId,
        /// The channel it arrived on.
        channel: ChannelId,
        /// The payload.
        payload: P,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lifecycle {
    Connected(PeerId, u64),
    Disconnected(PeerId, DisconnectReason),
    Rejected(PeerId, u64, Failure),
}

impl Lifecycle {
    fn event<P>(self) -> ServerEvent<P> {
        match self {
            Self::Connected(peer, client_id) => ServerEvent::Connected { peer, client_id },
            Self::Disconnected(peer, reason) => ServerEvent::Disconnected { peer, reason },
            Self::Rejected(peer, client_id, failure) => ServerEvent::Rejected {
                peer,
                client_id,
                failure,
            },
        }
    }
}

#[derive(Debug)]
struct Slot {
    peer: PeerId,
    client_id: u64,
    established: bool,
    /// Set while a mismatched client lingers: the time its slot is released.
    closing_until: Option<f64>,
    connection: Option<Connection>,
}

/// A dream-net server. See the [module docs](self).
pub struct Server {
    netcode: netcode::Server,
    /// Each received datagram is copied here, so receiving allocates nothing once this has
    /// grown to the largest datagram.
    datagram: Vec<u8>,
    shared: Arc<Shared>,
    slots: Vec<Slot>,
    inbox: Inbox<Lifecycle>,
    generation: u64,
    time: f64,
    capture: Option<Box<dyn CaptureSink>>,
}

impl<P: Copy> ServerEvent<P> {
    fn capture<'p>(&self, time: f64, payload: &'p [u8]) -> CaptureRecord<&'p [u8]> {
        let (peer, kind) = match *self {
            Self::Connected { peer, client_id } => (peer, CaptureKind::Connected { client_id }),
            Self::Disconnected { peer, reason } => (peer, CaptureKind::Disconnected { reason }),
            Self::Rejected {
                peer,
                client_id,
                failure,
            } => (
                peer,
                CaptureKind::Rejected {
                    client_id,
                    reason: failure.reason(),
                },
            ),
            Self::Message {
                peer,
                event,
                channel,
                ..
            } => (
                peer,
                CaptureKind::Received {
                    event,
                    channel,
                    len: payload.len(),
                    payload,
                },
            ),
        };
        CaptureRecord { time, peer, kind }
    }
}

impl Server {
    /// Binds the socket and starts accepting clients, with netcode's default maximum
    /// connect-token lifetime, [`DEFAULT_MAX_CONNECT_TOKEN_LIFETIME`] (30 seconds).
    ///
    /// The same as [`with_max_token_lifetime`](Self::with_max_token_lifetime) with that maximum.
    /// Connect tokens are single use, and a token whose expire timestamp is not later than the
    /// server's start second plus 30 seconds (wall clock) is refused: a 30-second token is
    /// accepted from the wall-clock second after the server started, and a token minted before
    /// the start (before a restart on the same key, say) only if it lives longer than 30
    /// seconds, which is why a host that keeps its key must not mint longer-lived tokens. See
    /// [Connect tokens](self#connect-tokens) for every rule and the clock each one uses.
    ///
    /// The socket binds `0.0.0.0` (or `[::]`, IPv6 only) on the public address's port. Port 0
    /// binds an ephemeral port, which [`address`](Self::address) then reports and which tokens
    /// must name. Tokens must name the public address exactly (IP and port), so give the
    /// address clients will reach the server at: an unspecified public address (`0.0.0.0`,
    /// `[::]`) binds, but no client can complete a connection to it. A `time` that is not
    /// finite is taken as 0.
    ///
    /// # Errors
    ///
    /// [`Error::Config`] for an invalid schema/transport pairing; [`Error::Netcode`] for a
    /// `max_clients` outside `[1, 256]` or a socket that cannot be bound (a port in use is an
    /// `Io` error of kind `AddrInUse`).
    pub fn new(
        config: ServerConfig,
        private_key: &netcode::Key,
        schema: Schema,
        time: f64,
    ) -> Result<Self, Error> {
        Self::with_max_token_lifetime(
            config,
            private_key,
            schema,
            time,
            DEFAULT_MAX_CONNECT_TOKEN_LIFETIME,
        )
    }

    /// As [`new`](Self::new), with `max_connect_token_lifetime_seconds` as the longest lifetime
    /// of the connect tokens this server's backend issues.
    ///
    /// The server records `floor = wall-clock second at start + max_connect_token_lifetime_seconds`
    /// and refuses every token whose expire timestamp is not later than the floor. With a
    /// maximum `M` and a token lifetime `L <= M`, a token is accepted only if it was minted at
    /// least `M - L + 1` wall-clock seconds after the start second, and a token minted before
    /// the start never is: that is the restart protection. A token with `L > M`, or one that
    /// never expires, passes the floor, so the protection only covers tokens no longer-lived
    /// than `M`: a host that keeps its private key across server starts must mint every token
    /// with `expire_seconds <= M`. A host that generates a fresh key for each start (as l3i
    /// does) is not exposed to restart replay whatever `M` is. Tokens are single use in every
    /// case. The floor and token timestamps use the wall clock; `time` is the host's clock.
    /// See [Connect tokens](self#connect-tokens).
    ///
    /// # Errors
    ///
    /// As [`new`](Self::new), and [`Error::Netcode`] with
    /// [`NetcodeError::InvalidConnectTokenLifetime`](crate::NetcodeError::InvalidConnectTokenLifetime)
    /// for a maximum of 0 or above `i32::MAX`.
    pub fn with_max_token_lifetime(
        config: ServerConfig,
        private_key: &netcode::Key,
        schema: Schema,
        time: f64,
        max_connect_token_lifetime_seconds: u32,
    ) -> Result<Self, Error> {
        let shared = Shared::new(schema, config.transport)?;
        let time = if time.is_finite() { time } else { 0.0 };
        let mut netcode = netcode::Server::with_options(
            config.public_address,
            config.protocol_id,
            private_key,
            time,
            netcode::ServerOptions::default()
                .with_max_connect_token_lifetime(max_connect_token_lifetime_seconds),
        )?;
        netcode.start(config.max_clients)?;
        let slots = (0..config.max_clients)
            .map(|slot| Slot {
                peer: PeerId::new(slot as u16, 0),
                client_id: 0,
                established: false,
                closing_until: None,
                connection: None,
            })
            .collect();
        Ok(Self {
            netcode,
            datagram: Vec::with_capacity(netcode::MAX_PAYLOAD_BYTES),
            shared,
            slots,
            inbox: Inbox::new(config.max_clients),
            generation: 0,
            time,
            capture: None,
        })
    }

    /// Installs (or with `None`, removes) a capture sink that records every event this
    /// server sends and every record it polls. See [`capture`](crate::capture).
    pub fn set_capture(&mut self, sink: Option<Box<dyn CaptureSink>>) {
        self.capture = sink;
    }

    /// The schema.
    pub fn schema(&self) -> &Schema {
        self.shared.schema()
    }

    /// The address clients connect to.
    pub fn address(&self) -> SocketAddr {
        self.netcode.address()
    }

    /// Client slots.
    pub fn max_clients(&self) -> usize {
        self.slots.len()
    }

    /// Connected (announced) clients.
    pub fn num_connected(&self) -> usize {
        self.slots.iter().filter(|s| s.established).count()
    }

    /// Handles of every connected client, in slot order.
    pub fn peers(&self) -> impl Iterator<Item = PeerId> + '_ {
        self.slots.iter().filter(|s| s.established).map(|s| s.peer)
    }

    /// Receives and processes everything that arrived, then advances timers. Call once per
    /// frame with the host's monotonic time; a time earlier than the latest one, or not finite,
    /// is replaced by the latest one.
    pub fn update(&mut self, time: f64) {
        if time.is_finite() && time > self.time {
            self.time = time;
        }
        let time = self.time;
        self.inbox.compact();
        self.netcode.update(time);

        // Why no stale PeerId can reach a new occupant, and lifecycle stays as documented.
        //
        // netcode reports slot changes per batch, drained here in full right after its update
        // and before anything reads a slot: every ClientDisconnected, then every
        // ClientConnected, each in slot order. A slot vacated and refilled since the last
        // batch yields both; a session that began and ended between two batches yields
        // nothing. netcode changes slots only inside its update (drained here),
        // disconnect_client (dream-net forgets the slot before calling it) and stop (Drop), so
        // between calls `slots` and netcode agree on who is connected.
        //
        // - A PeerId is (slot, generation). The generation is a server-wide counter bumped on
        //   every ClientConnected and never reused, and every handle-taking method compares
        //   the whole PeerId with an established slot's, so a handle never matches a later
        //   occupant, whichever way the slot changed hands. When one batch both vacates and
        //   refills a slot, the Disconnected for the old occupant is handled first (under its
        //   own PeerId) and only then is the new one given a fresh generation.
        // - Each Connected is followed by exactly one Disconnected: it is pushed for the
        //   announced PeerId when the slot's Connection is taken, here, or in `disconnect` or
        //   `close_slot`, whichever comes first; the others find no Connection. An occupant
        //   never announced is Rejected (close_slot) or, if it never got that far, not
        //   reported at all.
        // - The client id is read at ClientConnected, which netcode synthesises from the
        //   slot's current state, so it is the current occupant's. client_address and
        //   client_user_data are answered by netcode for the occupant it reports connected,
        //   captured when that occupant connected, and asked only after the whole PeerId
        //   matched an established slot, which by the agreement above is that occupant's.
        // - netcode clears a slot's packet queue when its occupant leaves, before the slot can
        //   be reused, and queues packets only under the current occupant's address and keys.
        //   Everything received below for a slot therefore belongs to the occupant whose
        //   Connection exists now; a session that produced no events produced no Connection
        //   and its packets were discarded with it.
        while let Some(event) = self.netcode.next_event() {
            match event {
                netcode::ServerEvent::ClientConnected { client_index } => {
                    self.generation += 1;
                    let peer = PeerId::new(client_index as u16, self.generation);
                    let slot = &mut self.slots[client_index];
                    debug_assert!(
                        slot.connection.is_none(),
                        "netcode reported a connect for a slot dream-net still holds"
                    );
                    slot.peer = peer;
                    slot.client_id = self.netcode.client_id(client_index);
                    slot.established = false;
                    slot.closing_until = None;
                    slot.connection = Some(Connection::new(self.shared.clone(), peer, time));
                    self.inbox.open_slot(peer);
                }
                netcode::ServerEvent::ClientDisconnected {
                    client_index,
                    reason,
                } => {
                    let slot = &mut self.slots[client_index];
                    if slot.connection.take().is_some() && slot.established {
                        let reason = match reason {
                            netcode::DisconnectReason::TimedOut => DisconnectReason::TimedOut,
                            netcode::DisconnectReason::ClientDisconnect => DisconnectReason::Remote,
                            netcode::DisconnectReason::ServerDisconnect => {
                                DisconnectReason::Requested
                            }
                        };
                        self.inbox
                            .push_lifecycle(Lifecycle::Disconnected(slot.peer, reason));
                    }
                    slot.established = false;
                    slot.closing_until = None;
                }
            }
        }

        for index in 0..self.slots.len() {
            let slot = &mut self.slots[index];
            let Some(connection) = slot.connection.as_mut() else {
                continue;
            };
            if let Some(until) = slot.closing_until {
                // a lingering mismatched client: its data is ignored until it leaves or the
                // linger runs out
                while self
                    .netcode
                    .receive_packet_into(index, &mut self.datagram)
                    .is_some()
                {}
                if time >= until {
                    slot.closing_until = None;
                    slot.connection = None;
                    self.netcode.disconnect_client(index);
                }
                continue;
            }
            connection.update(time);
            // a handshaking connection delivers nothing, so everything this peer queues below
            // follows the packet that completed its handshake, and its Connected goes first
            let announce_at = self.inbox.len();
            let mut rejected = false;
            while self
                .netcode
                .receive_packet_into(index, &mut self.datagram)
                .is_some()
            {
                let netcode = &mut self.netcode;
                connection.receive(&self.datagram, &mut self.inbox, |ack| {
                    rejected |= netcode.send_packet(index, ack).is_err();
                });
            }
            let mut failed = rejected.then_some(Failure::TransportError);
            while let Some(event) = connection.take_event() {
                match event {
                    ConnectionEvent::Established => {
                        slot.established = true;
                        self.inbox.insert_lifecycle(
                            announce_at,
                            Lifecycle::Connected(slot.peer, slot.client_id),
                        );
                    }
                    ConnectionEvent::Failed(failure) => {
                        failed = Some(failure);
                        break;
                    }
                }
            }
            if let Some(failure) = failed {
                self.close_slot(index, failure);
            }
        }
    }

    /// Ends a slot's connection after `failure`: reports it, then either lingers (a
    /// mismatched client, so it can see our hello) or disconnects at once.
    fn close_slot(&mut self, index: usize, failure: Failure) {
        let slot = &mut self.slots[index];
        if slot.connection.is_none() || slot.closing_until.is_some() {
            return;
        }
        self.inbox.push_lifecycle(if slot.established {
            Lifecycle::Disconnected(slot.peer, failure.reason())
        } else {
            Lifecycle::Rejected(slot.peer, slot.client_id, failure)
        });
        slot.established = false;
        let mismatch = matches!(
            failure,
            Failure::SchemaMismatch { .. } | Failure::ProtocolMismatch { .. }
        );
        let linger = self.shared.config().mismatch_linger;
        if mismatch && linger > 0.0 {
            slot.closing_until = Some(self.time + linger);
        } else {
            slot.connection = None;
            self.netcode.disconnect_client(index);
        }
    }

    /// Pops the next lifecycle record or event. The payload is borrowed until the next call.
    #[inline]
    pub fn poll(&mut self) -> Option<ServerEvent<&[u8]>> {
        let (record, payload) = self.inbox.pop()?;
        let event = match record {
            Record::Lifecycle(lifecycle) => lifecycle.event(),
            Record::Message(info) => ServerEvent::Message {
                peer: info.peer,
                event: info.event,
                channel: info.channel,
                payload,
            },
        };
        if let Some(sink) = self.capture.as_mut() {
            sink.record(&event.capture(self.time, payload));
        }
        Some(event)
    }

    /// Pops the next record, copying an event's payload into `buffer` and reporting its
    /// length. Nothing is consumed if the payload does not fit.
    ///
    /// # Errors
    ///
    /// [`BufferTooSmall`] with the needed length.
    #[inline]
    pub fn poll_into(
        &mut self,
        buffer: &mut [u8],
    ) -> Result<Option<ServerEvent<usize>>, BufferTooSmall> {
        let Some(record) = self.inbox.pop_into(buffer)? else {
            return Ok(None);
        };
        let event = match record {
            Record::Lifecycle(lifecycle) => lifecycle.event(),
            Record::Message(info) => ServerEvent::Message {
                peer: info.peer,
                event: info.event,
                channel: info.channel,
                payload: info.len,
            },
        };
        if let Some(sink) = self.capture.as_mut() {
            let len = match event {
                ServerEvent::Message { payload, .. } => payload,
                _ => 0,
            };
            sink.record(&event.capture(self.time, &buffer[..len]));
        }
        Ok(Some(event))
    }

    #[inline]
    fn connection_mut(&mut self, peer: PeerId) -> Result<&mut Connection, SendError> {
        match self.slots.get_mut(peer.slot()) {
            Some(slot) if slot.peer == peer && slot.established => {
                slot.connection.as_mut().ok_or(SendError::UnknownPeer(peer))
            }
            _ => Err(SendError::UnknownPeer(peer)),
        }
    }

    fn connection(&self, peer: PeerId) -> Option<&Connection> {
        match self.slots.get(peer.slot()) {
            Some(slot) if slot.peer == peer && slot.established => slot.connection.as_ref(),
            _ => None,
        }
    }

    /// Queues an event to one client. The payload is copied before this returns.
    ///
    /// # Errors
    ///
    /// [`SendError::UnknownPeer`] for a handle that is not connected, or anything
    /// [`Connection::send`] refuses.
    #[inline]
    pub fn send(
        &mut self,
        peer: PeerId,
        event: EventTypeId,
        payload: &[u8],
    ) -> Result<(), SendError> {
        self.connection_mut(peer)?.send(event, payload)?;
        if let Some(sink) = self.capture.as_mut()
            && let Some(def) = self.shared.schema().event(event)
        {
            sink.record(&CaptureRecord {
                time: self.time,
                peer,
                kind: CaptureKind::Sent {
                    event,
                    channel: def.channel,
                    len: payload.len(),
                    payload,
                },
            });
        }
        Ok(())
    }

    /// Queues an event to every connected client except `except`. Returns how many clients'
    /// queues refused it (reliable channels refuse when a client's window is full); use
    /// [`send`](Self::send) per peer when that needs handling peer by peer.
    ///
    /// # Errors
    ///
    /// [`SendError::UnknownEvent`] or [`SendError::PayloadTooLarge`], before anything is
    /// queued.
    pub fn broadcast_except(
        &mut self,
        except: Option<PeerId>,
        event: EventTypeId,
        payload: &[u8],
    ) -> Result<usize, SendError> {
        let def = self
            .shared
            .schema()
            .event(event)
            .ok_or(SendError::UnknownEvent(event))?;
        if payload.len() > def.max_payload as usize {
            return Err(SendError::PayloadTooLarge {
                event,
                len: payload.len(),
                max: def.max_payload,
            });
        }
        let mut refused = 0;
        for slot in &mut self.slots {
            if !slot.established || Some(slot.peer) == except {
                continue;
            }
            if let Some(connection) = slot.connection.as_mut() {
                if connection.send(event, payload).is_err() {
                    refused += 1;
                } else if let Some(sink) = self.capture.as_mut() {
                    sink.record(&CaptureRecord {
                        time: self.time,
                        peer: slot.peer,
                        kind: CaptureKind::Sent {
                            event,
                            channel: def.channel,
                            len: payload.len(),
                            payload,
                        },
                    });
                }
            }
        }
        Ok(refused)
    }

    /// Queues an event to every connected client. See
    /// [`broadcast_except`](Self::broadcast_except).
    ///
    /// # Errors
    ///
    /// As [`broadcast_except`](Self::broadcast_except).
    pub fn broadcast(&mut self, event: EventTypeId, payload: &[u8]) -> Result<usize, SendError> {
        self.broadcast_except(None, event, payload)
    }

    /// Packs and sends everything queued, plus any owed acks and idle packets.
    ///
    /// netcode's `send_packet` refuses only payloads outside `[1, 1200]` bytes, which
    /// [`TransportConfig::validate`] rules out for every datagram dream-net produces; socket
    /// errors never surface here (netcode drops them, and they show up as loss and, in the
    /// end, a timeout). A refusal would therefore be a dream-net bug: the peer is failed with
    /// [`Failure::TransportError`] rather than silently losing its traffic.
    pub fn flush(&mut self) {
        for index in 0..self.slots.len() {
            let slot = &mut self.slots[index];
            let Some(connection) = slot.connection.as_mut() else {
                continue;
            };
            let netcode = &mut self.netcode;
            let mut refused = false;
            connection.write_packets(|datagram| {
                refused |= netcode.send_packet(index, datagram).is_err();
            });
            debug_assert!(!refused, "netcode refused a datagram dream-net sized");
            if refused {
                self.close_slot(index, Failure::TransportError);
            }
        }
    }

    /// Disconnects a client. Queues its `Disconnected { reason: Requested }` record.
    pub fn disconnect(&mut self, peer: PeerId) {
        let Some(slot) = self.slots.get_mut(peer.slot()) else {
            return;
        };
        if slot.peer != peer || slot.connection.is_none() {
            return;
        }
        if slot.established {
            self.inbox
                .push_lifecycle(Lifecycle::Disconnected(peer, DisconnectReason::Requested));
        }
        slot.established = false;
        slot.closing_until = None;
        slot.connection = None;
        self.netcode.disconnect_client(peer.slot());
    }

    /// Disconnects every client.
    pub fn disconnect_all(&mut self) {
        let peers: Vec<PeerId> = self
            .slots
            .iter()
            .filter(|s| s.connection.is_some())
            .map(|s| s.peer)
            .collect();
        for peer in peers {
            self.disconnect(peer);
        }
    }

    /// A connected client's authenticated id (from its connect token).
    pub fn client_id(&self, peer: PeerId) -> Option<u64> {
        self.connection(peer)
            .map(|_| self.slots[peer.slot()].client_id)
    }

    /// A connected client's address.
    pub fn client_address(&self, peer: PeerId) -> Option<SocketAddr> {
        self.connection(peer)?;
        self.netcode.client_address(peer.slot())
    }

    /// The opaque user data from a connected client's connect token.
    pub fn client_user_data(&self, peer: PeerId) -> Option<&netcode::UserData> {
        self.connection(peer)?;
        self.netcode.client_user_data(peer.slot())
    }

    /// Link estimates for a connected client.
    pub fn stats(&self, peer: PeerId) -> Option<ConnectionStats> {
        self.connection(peer).map(Connection::stats)
    }

    /// Counters for a connected client.
    pub fn counters(&self, peer: PeerId) -> Option<Counters> {
        self.connection(peer).map(Connection::counters)
    }

    /// The underlying connection of a connected client, for diagnostics.
    pub fn peer_connection(&self, peer: PeerId) -> Option<&Connection> {
        self.connection(peer)
    }

    /// Approximate native memory: every connection plus the inbox (counted as `receive`).
    pub fn memory_usage(&self) -> MemoryUsage {
        let mut total = MemoryUsage {
            receive: self.inbox.memory_usage(),
            ..MemoryUsage::default()
        };
        for connection in self.slots.iter().filter_map(|s| s.connection.as_ref()) {
            let m = connection.memory_usage();
            total.connection += m.connection;
            total.reliable += m.reliable;
            total.send += m.send;
            total.receive += m.receive;
        }
        total
    }
}

impl std::fmt::Debug for Server {
    // hand written: netcode's server holds the private key, which must never reach a log
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("address", &self.netcode.address())
            .field("max_clients", &self.slots.len())
            .field("connected", &self.num_connected())
            .field("fingerprint", &self.shared.schema().fingerprint())
            .field("time", &self.time)
            .finish_non_exhaustive()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        // tell clients now rather than letting them time out: netcode sends each connected
        // client its disconnect packets (dropping the netcode server would as well, but this
        // keeps the order explicit: clients are told before any dream-net state goes away)
        self.netcode.stop();
    }
}
