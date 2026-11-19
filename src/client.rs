//! A dream-net client over netcode.
//!
//! The client connects with an opaque connect token minted by a trusted backend (it never sees
//! the server's key), then runs the same frame phases as the server: `update`, `poll`, `send`,
//! `flush`. Every connect attempt ends in exactly one of [`ClientEvent::Disconnected`] (after
//! `Connected`) or [`ClientEvent::ConnectFailed`] (before it).
//!
//! The secure connection underneath is upstream C netcode 1.4.10, through the safe binding in
//! dream-net's `native` module. How each netcode outcome surfaces:
//!
//! | netcode | dream-net |
//! | --- | --- |
//! | the token cannot be read, or lists no server of the bound address family | `connect` returns `Err`, and `ConnectFailed { reason: Authentication }` |
//! | (dream-net, before netcode) the token was already passed to `connect` in this process | `connect` returns `Err`, and `ConnectFailed { reason: Authentication }`; nothing is sent |
//! | the token's lifetime, counted from `connect` on the host's clock, ran out while connecting | `ConnectFailed { reason: Authentication }` |
//! | no answer within the token's `timeout_seconds` for each listed server address, which is also what a refused token looks like (a used token, one under the start floor, a wrong key or protocol: the server never answers those) | `ConnectFailed { reason: TimedOut }` |
//! | the server is full | `ConnectFailed { reason: Denied }` |
//! | an established connection stopped hearing from the server | `Disconnected { reason: TimedOut }` |
//! | the server disconnected the client (or stopped) | `Disconnected { reason: Remote }`, and the client stays disconnected even when the token lists other servers |
//!
//! A connect token admits one connection attempt: once passed to `connect` it is refused if
//! passed again in the same process, and a host must never store a token and present it again
//! after a restart; mint a new token for every attempt. See
//! [Connect tokens](crate::server#connect-tokens).

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

/// Client settings.
#[derive(Debug, Clone, PartialEq)]
pub struct ClientConfig {
    /// Local address to bind; port 0 lets the OS choose. The address family must match the
    /// server addresses in connect tokens.
    pub bind_address: SocketAddr,
    /// Transport limits.
    pub transport: TransportConfig,
}

/// A client lifecycle or message record. `P` is the payload: a borrowed slice from
/// [`Client::poll`], its length from [`Client::poll_into`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientEvent<P> {
    /// The handshake completed: events can be sent.
    Connected,
    /// The connection ended after `Connected`.
    Disconnected {
        /// Why.
        reason: DisconnectReason,
    },
    /// The attempt ended before `Connected`.
    ConnectFailed {
        /// Why.
        reason: DisconnectReason,
        /// dream-net's handshake failure, when that was the cause; a schema mismatch carries
        /// both fingerprints.
        failure: Option<Failure>,
    },
    /// An event from the server.
    Message {
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
    Connected,
    Disconnected(DisconnectReason),
    ConnectFailed(DisconnectReason, Option<Failure>),
}

impl Lifecycle {
    fn event<P>(self) -> ClientEvent<P> {
        match self {
            Self::Connected => ClientEvent::Connected,
            Self::Disconnected(reason) => ClientEvent::Disconnected { reason },
            Self::ConnectFailed(reason, failure) => ClientEvent::ConnectFailed { reason, failure },
        }
    }
}

/// Where a client stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientStatus {
    /// Idle.
    Disconnected,
    /// netcode is exchanging connection requests and responses.
    Connecting,
    /// netcode connected; waiting for the server's hello.
    Handshaking,
    /// Events flow.
    Connected,
}

/// A dream-net client. See the [module docs](self).
pub struct Client {
    netcode: netcode::Client,
    /// Each received datagram is copied here, so receiving allocates nothing once this has
    /// grown to the largest datagram.
    datagram: Vec<u8>,
    shared: Arc<Shared>,
    connection: Option<Connection>,
    established: bool,
    attempting: bool,
    inbox: Inbox<Lifecycle>,
    generation: u64,
    time: f64,
    capture: Option<Box<dyn CaptureSink>>,
}

impl<P: Copy> ClientEvent<P> {
    fn capture<'p>(&self, time: f64, peer: PeerId, payload: &'p [u8]) -> CaptureRecord<&'p [u8]> {
        let kind = match *self {
            Self::Connected => CaptureKind::Connected { client_id: 0 },
            Self::Disconnected { reason } => CaptureKind::Disconnected { reason },
            Self::ConnectFailed { reason, .. } => CaptureKind::Rejected {
                client_id: 0,
                reason,
            },
            Self::Message { event, channel, .. } => CaptureKind::Received {
                event,
                channel,
                len: payload.len(),
                payload,
            },
        };
        CaptureRecord { time, peer, kind }
    }
}

/// The peer id a client's inbox uses for the server.
const SERVER: u16 = 0;

impl Client {
    /// Binds the socket. A `time` that is not finite is taken as 0.
    ///
    /// # Errors
    ///
    /// An invalid schema/transport pairing, or a socket error (including an IPv6 bind address
    /// with a scope id, which netcode cannot bind).
    pub fn new(config: ClientConfig, schema: Schema, time: f64) -> Result<Self, Error> {
        let shared = Shared::new(schema, config.transport)?;
        let time = if time.is_finite() { time } else { 0.0 };
        let netcode = netcode::Client::new(config.bind_address, time)?;
        Ok(Self {
            netcode,
            datagram: Vec::with_capacity(netcode::MAX_PAYLOAD_BYTES),
            shared,
            connection: None,
            established: false,
            attempting: false,
            inbox: Inbox::new(1),
            generation: 0,
            time,
            capture: None,
        })
    }

    /// Installs (or with `None`, removes) a capture sink that records every event this
    /// client sends and every record it polls. See [`capture`](crate::capture).
    pub fn set_capture(&mut self, sink: Option<Box<dyn CaptureSink>>) {
        self.capture = sink;
    }

    fn server_peer(&self) -> PeerId {
        PeerId::new(SERVER, self.generation)
    }

    /// The schema.
    pub fn schema(&self) -> &Schema {
        self.shared.schema()
    }

    /// Starts connecting with a connect token. An attempt or connection in progress is ended
    /// first.
    ///
    /// A connect token admits one connection attempt: once passed to `connect` it is refused
    /// if passed again in the same process, by this client or any other, and a host must never
    /// store a token and present it again after a restart; mint a new token for every attempt.
    /// A token that lists several servers is still tried against each of them within the one
    /// attempt. The server refuses a token that already established a session there, and one
    /// under its start floor (see [Connect tokens](crate::server#connect-tokens)); it does not
    /// answer a refused token, so the attempt ends with `ConnectFailed { reason: TimedOut }`
    /// once the token's timeout has passed for every server it lists.
    ///
    /// # Errors
    ///
    /// [`Error::Netcode`] with `InvalidConnectToken` for a token netcode cannot parse, one that
    /// lists no server address of the family the client is bound to, or one already passed to
    /// `connect` in this process (refused before anything is sent). The attempt then ends with
    /// `ConnectFailed { reason: Authentication }` as well.
    pub fn connect(&mut self, token: &[u8; netcode::CONNECT_TOKEN_BYTES]) -> Result<(), Error> {
        if self.attempting {
            self.disconnect();
        }
        self.attempting = true;
        if let Err(error) = self.netcode.connect(token) {
            self.end(DisconnectReason::Authentication, None);
            return Err(error.into());
        }
        Ok(())
    }

    fn end(&mut self, reason: DisconnectReason, failure: Option<Failure>) {
        if !self.attempting {
            return;
        }
        self.inbox.push_lifecycle(if self.established {
            Lifecycle::Disconnected(reason)
        } else {
            Lifecycle::ConnectFailed(reason, failure)
        });
        self.attempting = false;
        self.established = false;
        self.connection = None;
    }

    /// Ends the connection or attempt, telling the server.
    pub fn disconnect(&mut self) {
        self.netcode.disconnect();
        self.end(DisconnectReason::Requested, None);
    }

    /// Where the client stands.
    pub fn status(&self) -> ClientStatus {
        if self.established {
            ClientStatus::Connected
        } else if self.connection.is_some() {
            ClientStatus::Handshaking
        } else if self.attempting {
            ClientStatus::Connecting
        } else {
            ClientStatus::Disconnected
        }
    }

    /// Receives and processes everything that arrived, then advances timers. A time earlier
    /// than the latest one, or not finite, is replaced by the latest one.
    pub fn update(&mut self, time: f64) {
        if time.is_finite() && time > self.time {
            self.time = time;
        }
        let time = self.time;
        self.inbox.compact();
        self.netcode.update(time);
        let state = self.netcode.state();

        if state == netcode::ClientState::Connected && self.connection.is_none() && self.attempting
        {
            self.generation += 1;
            let peer = PeerId::new(SERVER, self.generation);
            self.inbox.open_slot(peer);
            self.connection = Some(Connection::new(self.shared.clone(), peer, time));
        }

        if let Some(connection) = self.connection.as_mut() {
            connection.update(time);
            // a handshaking connection delivers nothing, so everything queued below follows
            // the packet that completed the handshake, and Connected goes first
            let announce_at = self.inbox.len();
            let mut refused = false;
            while self
                .netcode
                .receive_packet_into(&mut self.datagram)
                .is_some()
            {
                let netcode = &mut self.netcode;
                connection.receive(&self.datagram, &mut self.inbox, |ack| {
                    refused |= netcode.send_packet(ack).is_err();
                });
            }
            if refused {
                self.netcode.disconnect();
                self.end(
                    DisconnectReason::TransportError,
                    Some(Failure::TransportError),
                );
                return;
            }
            while let Some(event) = connection.take_event() {
                match event {
                    ConnectionEvent::Established => {
                        self.established = true;
                        self.inbox
                            .insert_lifecycle(announce_at, Lifecycle::Connected);
                    }
                    ConnectionEvent::Failed(failure) => {
                        self.netcode.disconnect();
                        self.end(failure.reason(), Some(failure));
                        return;
                    }
                }
            }
        }

        if self.attempting && state.is_disconnected() {
            let reason = match state {
                netcode::ClientState::ConnectTokenExpired
                | netcode::ClientState::InvalidConnectToken => DisconnectReason::Authentication,
                netcode::ClientState::ConnectionTimedOut
                | netcode::ClientState::ConnectionResponseTimedOut
                | netcode::ClientState::ConnectionRequestTimedOut => DisconnectReason::TimedOut,
                netcode::ClientState::ConnectionDenied => DisconnectReason::Denied,
                _ => DisconnectReason::Remote,
            };
            self.end(reason, None);
        }
    }

    /// Pops the next lifecycle record or event. The payload is borrowed until the next call.
    #[inline]
    pub fn poll(&mut self) -> Option<ClientEvent<&[u8]>> {
        let peer = self.server_peer();
        let (record, payload) = self.inbox.pop()?;
        let event = match record {
            Record::Lifecycle(lifecycle) => lifecycle.event(),
            Record::Message(info) => ClientEvent::Message {
                event: info.event,
                channel: info.channel,
                payload,
            },
        };
        if let Some(sink) = self.capture.as_mut() {
            sink.record(&event.capture(self.time, peer, payload));
        }
        Some(event)
    }

    /// Pops the next record, copying an event's payload into `buffer`. Nothing is consumed if
    /// the payload does not fit.
    ///
    /// # Errors
    ///
    /// [`BufferTooSmall`] with the needed length.
    #[inline]
    pub fn poll_into(
        &mut self,
        buffer: &mut [u8],
    ) -> Result<Option<ClientEvent<usize>>, BufferTooSmall> {
        let peer = self.server_peer();
        let Some(record) = self.inbox.pop_into(buffer)? else {
            return Ok(None);
        };
        let event = match record {
            Record::Lifecycle(lifecycle) => lifecycle.event(),
            Record::Message(info) => ClientEvent::Message {
                event: info.event,
                channel: info.channel,
                payload: info.len,
            },
        };
        if let Some(sink) = self.capture.as_mut() {
            let len = match event {
                ClientEvent::Message { payload, .. } => payload,
                _ => 0,
            };
            sink.record(&event.capture(self.time, peer, &buffer[..len]));
        }
        Ok(Some(event))
    }

    /// Queues an event to the server. The payload is copied before this returns.
    ///
    /// # Errors
    ///
    /// [`SendError::NotConnected`] before `Connected`, or anything [`Connection::send`]
    /// refuses.
    #[inline]
    pub fn send(&mut self, event: EventTypeId, payload: &[u8]) -> Result<(), SendError> {
        match self.connection.as_mut() {
            Some(connection) if self.established => connection.send(event, payload)?,
            _ => return Err(SendError::NotConnected),
        }
        if let Some(sink) = self.capture.as_mut()
            && let Some(def) = self.shared.schema().event(event)
        {
            sink.record(&CaptureRecord {
                time: self.time,
                peer: PeerId::new(SERVER, self.generation),
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

    /// Packs and sends everything queued, plus any owed acks and idle packets.
    ///
    /// As on the server, netcode can only refuse a datagram dream-net sized wrongly, which
    /// the transport configuration rules out; if it ever happens the connection ends with
    /// [`DisconnectReason::TransportError`] instead of losing traffic silently.
    pub fn flush(&mut self) {
        let Some(connection) = self.connection.as_mut() else {
            return;
        };
        let netcode = &mut self.netcode;
        let mut refused = false;
        connection.write_packets(|datagram| {
            refused |= netcode.send_packet(datagram).is_err();
        });
        debug_assert!(!refused, "netcode refused a datagram dream-net sized");
        if refused {
            self.netcode.disconnect();
            self.end(
                DisconnectReason::TransportError,
                Some(Failure::TransportError),
            );
        }
    }

    /// The server address, while connecting or connected.
    pub fn server_address(&self) -> Option<SocketAddr> {
        self.netcode.server_address()
    }

    /// The local port.
    pub fn port(&self) -> u16 {
        self.netcode.port()
    }

    /// Link estimates, from the moment netcode connects, through the handshake
    /// ([`ClientStatus::Handshaking`]), until the connection ends. `None` while netcode is
    /// still connecting, and when idle.
    pub fn stats(&self) -> Option<ConnectionStats> {
        self.connection.as_ref().map(Connection::stats)
    }

    /// Counters, from the moment netcode connects, through the handshake
    /// ([`ClientStatus::Handshaking`]), until the connection ends. `None` while netcode is
    /// still connecting, and when idle.
    pub fn counters(&self) -> Option<Counters> {
        self.connection.as_ref().map(Connection::counters)
    }

    /// Approximate native memory.
    pub fn memory_usage(&self) -> MemoryUsage {
        let mut usage = self
            .connection
            .as_ref()
            .map(Connection::memory_usage)
            .unwrap_or_default();
        usage.receive += self.inbox.memory_usage();
        usage
    }
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("status", &self.status())
            .field("server", &self.netcode.server_address())
            .field("fingerprint", &self.shared.schema().fingerprint())
            .field("time", &self.time)
            .finish_non_exhaustive()
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.netcode.disconnect();
    }
}
