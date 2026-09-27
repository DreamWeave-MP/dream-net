//! A dream-net server over netcode.
//!
//! The server owns netcode's socket, its private key, and one [`Connection`] per client slot.
//! It is driven by the host in one explicit network phase per frame:
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

use std::net::SocketAddr;
use std::sync::Arc;

use crate::capture::{CaptureKind, CaptureRecord, CaptureSink};
use crate::config::TransportConfig;
use crate::connection::{Connection, ConnectionEvent, Shared};
use crate::error::{BufferTooSmall, Error, SendError};
use crate::id::{ChannelId, EventTypeId, PeerId};
use crate::inbox::{Inbox, Record};
use crate::lifecycle::{DisconnectReason, Failure};
use crate::schema::Schema;
use crate::stats::{ConnectionStats, Counters, MemoryUsage};

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
    /// Binds the socket and starts accepting clients.
    ///
    /// # Errors
    ///
    /// An invalid schema/transport pairing, an out-of-range `max_clients`, or a socket error.
    pub fn new(
        config: ServerConfig,
        private_key: &netcode::Key,
        schema: Schema,
        time: f64,
    ) -> Result<Self, Error> {
        let shared = Shared::new(schema, config.transport)?;
        let mut netcode =
            netcode::Server::new(config.public_address, config.protocol_id, private_key, time)?;
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
    /// frame with the host's monotonic time.
    pub fn update(&mut self, time: f64) {
        self.time = self.time.max(time);
        let time = self.time;
        self.inbox.compact();
        self.netcode.update(time);

        while let Some(event) = self.netcode.next_event() {
            match event {
                netcode::ServerEvent::ClientConnected { client_index } => {
                    self.generation += 1;
                    let peer = PeerId::new(client_index as u16, self.generation);
                    let slot = &mut self.slots[client_index];
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
                while self.netcode.receive_packet(index).is_some() {}
                if time >= until {
                    slot.closing_until = None;
                    slot.connection = None;
                    self.netcode.disconnect_client(index);
                }
                continue;
            }
            connection.update(time, &mut self.inbox);
            while let Some((payload, _sequence)) = self.netcode.receive_packet(index) {
                let netcode = &mut self.netcode;
                connection.receive(&payload, &mut self.inbox, |ack| {
                    let result = netcode.send_packet(index, ack);
                    debug_assert!(result.is_ok(), "{result:?}");
                });
            }
            while let Some(event) = connection.take_event() {
                match event {
                    ConnectionEvent::Established => {
                        slot.established = true;
                        self.inbox
                            .push_lifecycle(Lifecycle::Connected(slot.peer, slot.client_id));
                    }
                    ConnectionEvent::Failed(failure) => {
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
                            slot.closing_until = Some(time + linger);
                        } else {
                            slot.connection = None;
                            self.netcode.disconnect_client(index);
                        }
                        break;
                    }
                }
            }
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
    pub fn flush(&mut self) {
        for (index, slot) in self.slots.iter_mut().enumerate() {
            if let Some(connection) = slot.connection.as_mut() {
                let netcode = &mut self.netcode;
                connection.write_packets(|datagram| {
                    // cannot fail: the transport config keeps datagrams in [1, 1200] bytes
                    let result = netcode.send_packet(index, datagram);
                    debug_assert!(result.is_ok(), "{result:?}");
                });
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
        // tell clients now rather than letting them time out
        self.netcode.stop();
    }
}
