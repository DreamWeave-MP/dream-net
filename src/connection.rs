//! One end of a dream-net connection, independent of any socket.
//!
//! A [`Connection`] turns queued events into reliable-framed datagrams ([`write_packets`])
//! and received datagrams into inbox records ([`receive`]). It owns the `reliable::Endpoint`,
//! the channels, the packet builder, and the schema handshake. [`Server`](crate::Server) and
//! [`Client`](crate::Client) drive one per peer over netcode; tests and benchmarks drive two
//! over a [`sim::Link`](crate::sim::Link).
//!
//! This is the low-level engine room. It accepts [`send`](Connection::send) before its
//! handshake completes (the handshake tests rely on it), exposes raw datagram I/O, and trusts
//! its caller with time. Hosts, and any scripting facade, should use `Server` and `Client`,
//! which only let events through once a peer is announced; `Connection` is never meant to be
//! bound to ordinary Luau.
//!
//! [`write_packets`]: Connection::write_packets
//! [`receive`]: Connection::receive

use std::sync::Arc;

use crate::channel::{Arrival, Channel, QueueOutcome};
use crate::config::TransportConfig;
use crate::error::{ConfigError, SendError};
use crate::id::{ChannelId, EventTypeId, PeerId};
use crate::inbox::Inbox;
use crate::lifecycle::{ConnectionState, Failure};
use crate::schema::Schema;
use crate::sequence::Seq16;
use crate::stats::{ConnectionStats, Counters, MemoryUsage};
use crate::wire::{self, DecodeError, Decoded, Layout, Malformed, PacketWriter, relative_bits};

/// Received packets after which [`Connection::receive`] acknowledges immediately instead of
/// waiting for the next flush: half of reliable's 33-packet ack window, leaving room for
/// reordering.
pub const ACK_EVERY: u32 = 16;

/// A state change the host must act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionEvent {
    /// The peer's hello matched: announce the peer.
    Established,
    /// The connection failed: disconnect the peer.
    Failed(Failure),
}

/// Configuration and schema tables shared by every connection of a host.
#[derive(Debug)]
pub struct Shared {
    schema: Schema,
    layout: Layout,
    config: TransportConfig,
}

impl Shared {
    /// Validates `config` against `schema` and precomputes the wire layout.
    ///
    /// # Errors
    ///
    /// Anything [`TransportConfig::validate_for`] rejects.
    pub fn new(schema: Schema, config: TransportConfig) -> Result<Arc<Self>, ConfigError> {
        config.validate_for(&schema)?;
        let layout = Layout::new(&schema);
        Ok(Arc::new(Self {
            schema,
            layout,
            config,
        }))
    }

    /// The schema.
    pub fn schema(&self) -> &Schema {
        &self.schema
    }

    /// The transport configuration.
    pub fn config(&self) -> &TransportConfig {
        &self.config
    }
}

#[derive(Debug, Default)]
struct SentEntry {
    sequence: u16,
    live: bool,
    hello: bool,
    time: f64,
    messages: Vec<(u8, Seq16, u32)>,
}

/// Maps sent packet sequences to the reliable messages they carried, and counts packets in
/// flight.
///
/// reliable can only match an ack to a packet still in its sent-packet window, so a sender
/// that runs more than a window of packets ahead of its acks forgets what it sent and
/// resends it all. [`Connection::write_packets`] therefore stops adding events once half
/// the window is in flight. A packet stops counting when it is acked, when its slot is
/// reused, or when it is older than twice the worst recent round trip (it was lost).
#[derive(Debug)]
struct SentPackets {
    entries: Vec<SentEntry>,
    mask: usize,
    in_flight: usize,
}

impl SentPackets {
    fn new(size: usize) -> Self {
        debug_assert!(size.is_power_of_two());
        Self {
            entries: (0..size).map(|_| SentEntry::default()).collect(),
            mask: size - 1,
            in_flight: 0,
        }
    }

    #[inline]
    fn record(&mut self, sequence: u16, hello: bool, time: f64) -> &mut Vec<(u8, Seq16, u32)> {
        let entry = &mut self.entries[usize::from(sequence) & self.mask];
        if entry.live {
            // never acked and now out of reliable's window: it was lost
            self.in_flight -= 1;
        }
        entry.sequence = sequence;
        entry.live = true;
        entry.hello = hello;
        entry.time = time;
        entry.messages.clear();
        self.in_flight += 1;
        &mut entry.messages
    }

    #[inline]
    fn take(&mut self, sequence: u16) -> Option<&SentEntry> {
        let entry = &mut self.entries[usize::from(sequence) & self.mask];
        if entry.live && entry.sequence == sequence {
            entry.live = false;
            self.in_flight -= 1;
            Some(entry)
        } else {
            None
        }
    }

    /// Whether another packet with events may go out: fewer than half the window in flight,
    /// after writing off packets older than `expiry` seconds.
    #[inline]
    fn has_room(&mut self, now: f64, expiry: f64) -> bool {
        let cap = self.entries.len() / 2;
        if self.in_flight < cap {
            return true;
        }
        for entry in &mut self.entries {
            if entry.live && now - entry.time > expiry {
                entry.live = false;
                self.in_flight -= 1;
            }
        }
        self.in_flight < cap
    }

    fn memory(&self) -> usize {
        self.entries.capacity() * size_of::<SentEntry>()
            + self
                .entries
                .iter()
                .map(|e| e.messages.capacity() * size_of::<(u8, Seq16, u32)>())
                .sum::<usize>()
    }
}

/// The bit budget of the packet being built.
#[derive(Debug)]
struct Fill {
    bits: u64,
    limit: u64,
    max_bits: u64,
    /// Set when a lone oversize event took the packet: nothing else goes in.
    full: bool,
}

impl Fill {
    /// Admits a message of `cost` bits if it fits the packet and its channel's budget. An
    /// event too large for an ordinary packet is admitted alone into an empty one, up to the
    /// largest packet reliable can fragment.
    #[inline]
    fn admit(&mut self, cost: u64, channel_used: u64, channel_budget: u64, empty: bool) -> bool {
        if self.bits + cost <= self.limit && channel_used + cost <= channel_budget {
            self.bits += cost;
            return true;
        }
        if empty && self.bits + cost <= self.max_bits {
            self.bits += cost;
            self.limit = self.bits;
            self.full = true;
            return true;
        }
        false
    }
}

#[derive(Debug, Clone, Copy)]
struct Pick {
    channel: u8,
    /// Reliable: message id. Unreliable: queue index.
    id: Seq16,
    index: u32,
    serial: u32,
}

/// Everything but the endpoint, so the endpoint's receive closure can borrow it.
#[derive(Debug)]
#[allow(clippy::struct_excessive_bools)] // four independent flags, not a state machine
struct Core {
    shared: Arc<Shared>,
    peer: PeerId,
    channels: Vec<Channel>,
    sent: SentPackets,
    state: ConnectionState,
    established_event: bool,
    failed_event: bool,
    hello_acked: bool,
    created: f64,
    time: f64,
    last_send: f64,
    ack_pending: bool,
    /// Packets with content received since this end last sent a packet.
    unacked_received: u32,
    /// Payload bytes of reliable events parked outside the inbox.
    parked_bytes: usize,
    malformed: u32,
    rotation: usize,
    counters: Counters,
    decoded: Decoded,
    picks: Vec<Pick>,
    sections: Vec<(u8, u32, u32)>,
    write_buffer: Vec<u8>,
}

/// One end of a connection. See the [module docs](self).
#[derive(Debug)]
pub struct Connection {
    endpoint: reliable::Endpoint,
    core: Core,
}

impl Connection {
    /// Creates a connection that delivers into its inbox as `peer`, starting at `time`.
    pub fn new(shared: Arc<Shared>, peer: PeerId, time: f64) -> Self {
        let config = &shared.config;
        let endpoint = reliable::Endpoint::new(config.reliable_config("dream-net"), time);
        let channels = shared
            .schema
            .channels()
            .iter()
            .map(|def| Channel::new(def, config.max_pooled_bytes))
            .collect();
        // one spare word for the writer's final flush, rounded to whole words
        let write_buffer = vec![0u8; config.max_packet_size.div_ceil(8) * 8 + 8];
        let sent = SentPackets::new(config.sent_packets_buffer_size);
        Self {
            endpoint,
            core: Core {
                shared,
                peer,
                channels,
                sent,
                state: ConnectionState::Handshaking,
                established_event: false,
                failed_event: false,
                hello_acked: false,
                created: time,
                time,
                last_send: f64::NEG_INFINITY,
                ack_pending: false,
                unacked_received: 0,
                parked_bytes: 0,
                malformed: 0,
                rotation: 0,
                counters: Counters::default(),
                decoded: Decoded::default(),
                picks: Vec::new(),
                sections: Vec::new(),
                write_buffer,
            },
        }
    }

    /// The peer this connection delivers as.
    #[inline]
    pub fn peer(&self) -> PeerId {
        self.core.peer
    }

    /// The handshake state.
    #[inline]
    pub fn state(&self) -> ConnectionState {
        self.core.state
    }

    /// Takes the next state change the host has not seen yet.
    #[inline]
    pub fn take_event(&mut self) -> Option<ConnectionEvent> {
        if self.core.established_event {
            self.core.established_event = false;
            return Some(ConnectionEvent::Established);
        }
        if self.core.failed_event {
            self.core.failed_event = false;
            if let ConnectionState::Failed(failure) = self.core.state {
                return Some(ConnectionEvent::Failed(failure));
            }
        }
        None
    }

    /// Queues an event. The payload is copied before this returns.
    ///
    /// # Errors
    ///
    /// [`SendError::UnknownEvent`], [`SendError::PayloadTooLarge`], or
    /// [`SendError::QueueFull`]. Nothing is queued on error.
    #[inline]
    pub fn send(&mut self, event: EventTypeId, payload: &[u8]) -> Result<(), SendError> {
        let core = &mut self.core;
        let Some(def) = core.shared.schema.event(event) else {
            return Err(SendError::UnknownEvent(event));
        };
        if payload.len() > def.max_payload as usize {
            return Err(SendError::PayloadTooLarge {
                event,
                len: payload.len(),
                max: def.max_payload,
            });
        }
        let channel = def.channel;
        match core.channels[usize::from(channel.0)].queue(event, payload) {
            QueueOutcome::Accepted => {}
            QueueOutcome::DroppedOldest | QueueOutcome::DroppedNew => {
                core.counters.events_dropped_on_send += 1;
            }
            QueueOutcome::Refused => return Err(SendError::QueueFull(channel)),
        }
        core.counters.events_queued += 1;
        Ok(())
    }

    /// Processes one received datagram, delivering events into `inbox`.
    ///
    /// reliable acknowledges the latest received packet and the 32 before it, in the header
    /// of each packet this end sends. When the peer bursts more packets than that between two
    /// of our flushes, the oldest would never be acknowledged and would be resent for
    /// nothing, so after every [`ACK_EVERY`] received packets this sends a small control
    /// packet (no events) through `transmit` right away.
    #[inline]
    pub fn receive<L: Copy>(
        &mut self,
        datagram: &[u8],
        inbox: &mut Inbox<L>,
        transmit: impl FnMut(&[u8]),
    ) {
        // reliable panics on empty input; netcode never yields one, but a sim link might
        if datagram.is_empty() || matches!(self.core.state, ConnectionState::Failed(_)) {
            return;
        }
        let core = &mut self.core;
        core.counters.datagrams_received += 1;
        core.counters.bytes_received += datagram.len() as u64;
        self.endpoint
            .receive_packet(datagram, |_sequence, packet| core.process(packet, inbox));
        for sequence in self.endpoint.drain_acks() {
            core.acked(sequence);
        }
        if core.unacked_received >= ACK_EVERY && !matches!(core.state, ConnectionState::Failed(_)) {
            self.send_control(transmit);
        }
    }

    /// Sends a packet with no events: the ack header, plus the hello while it is unacked.
    fn send_control(&mut self, mut transmit: impl FnMut(&[u8])) {
        let core = &mut self.core;
        let layout = &core.shared.layout;
        let hello = (!core.hello_acked).then(|| layout.hello());
        let mut w = PacketWriter::new(&mut core.write_buffer);
        w.header(layout, hello, 0);
        let len = w.finish();
        let sequence = self.endpoint.next_packet_sequence();
        core.sent.record(sequence, hello.is_some(), core.time);
        let counters = &mut core.counters;
        self.endpoint
            .send_packet(&core.write_buffer[..len], |_, datagram| {
                counters.datagrams_sent += 1;
                counters.bytes_sent += datagram.len() as u64;
                transmit(datagram);
            });
        core.counters.packets_sent += 1;
        core.ack_pending = false;
        core.unacked_received = 0;
        core.last_send = core.time;
    }

    /// Advances time: refreshes link statistics and enforces the handshake timeout. Call it
    /// at the start of a frame, before that frame's [`receive`](Self::receive) calls, so acks
    /// are timestamped with the current time.
    #[inline]
    pub fn update(&mut self, time: f64) {
        let core = &mut self.core;
        // time is host supplied and must not run backwards
        core.time = core.time.max(time);
        self.endpoint.update(core.time);
        if core.state == ConnectionState::Handshaking
            && core.time - core.created >= core.shared.config.handshake_timeout
        {
            core.fail(Failure::HandshakeTimeout);
        }
    }

    /// Packs queued events into as many packets as needed (up to the configured cap) and
    /// hands each resulting datagram to `transmit`. Sends a small packet anyway when acks are
    /// owed, the handshake is pending, or the idle interval has passed.
    ///
    /// A connection that failed on a schema or protocol mismatch sends only its hello, so the
    /// peer can diagnose the mismatch too; any other failed connection sends nothing.
    #[inline]
    pub fn write_packets(&mut self, mut transmit: impl FnMut(&[u8])) {
        let core = &mut self.core;
        if let ConnectionState::Failed(failure) = core.state {
            if matches!(
                failure,
                Failure::SchemaMismatch { .. } | Failure::ProtocolMismatch { .. }
            ) {
                let layout = &core.shared.layout;
                let mut w = PacketWriter::new(&mut core.write_buffer);
                w.header(layout, Some(layout.hello()), 0);
                let len = w.finish();
                self.endpoint
                    .send_packet(&core.write_buffer[..len], |_, datagram| transmit(datagram));
            }
            return;
        }
        for channel in &mut core.channels {
            if let Channel::Reliable(c) = channel {
                c.begin_flush();
            }
        }
        let config = &core.shared.config;
        let (max_packets, idle_interval) =
            (config.max_packets_per_flush, config.idle_packet_interval);
        // a packet unacked after twice the worst recent round trip was lost
        let rtt_max = f64::from(self.endpoint.rtt_max()) / 1000.0;
        let expiry = if rtt_max > 0.0 {
            (rtt_max * 2.0).clamp(0.05, 1.0)
        } else {
            0.25
        };
        for _ in 0..max_packets {
            let with_events = core.sent.has_room(core.time, expiry);
            let (len, messages) = core.build_packet(with_events);
            let owed = core.ack_pending
                || !core.hello_acked
                || core.time - core.last_send >= idle_interval;
            if messages == 0 && !owed {
                break;
            }
            let sequence = self.endpoint.next_packet_sequence();
            let hello = !core.hello_acked;
            let entry = core.sent.record(sequence, hello, core.time);
            entry.extend(
                core.picks
                    .iter()
                    .filter(|p| {
                        matches!(core.channels[usize::from(p.channel)], Channel::Reliable(_))
                    })
                    .map(|p| (p.channel, p.id, p.serial)),
            );
            debug_assert!(len >= 1 && len <= core.shared.config.max_packet_size);
            let counters = &mut core.counters;
            self.endpoint
                .send_packet(&core.write_buffer[..len], |_sequence, datagram| {
                    counters.datagrams_sent += 1;
                    counters.bytes_sent += datagram.len() as u64;
                    transmit(datagram);
                });
            core.counters.packets_sent += 1;
            core.ack_pending = false;
            core.unacked_received = 0;
            core.last_send = core.time;
            if messages == 0 {
                break;
            }
        }
    }

    /// Link estimates.
    #[inline]
    pub fn stats(&self) -> ConnectionStats {
        ConnectionStats::from_endpoint(&self.endpoint)
    }

    /// Counters.
    #[inline]
    pub fn counters(&self) -> Counters {
        self.core.counters
    }

    /// reliable's own counters (fragments, stale and duplicate packets).
    pub fn reliable_counters(&self) -> &reliable::Counters {
        self.endpoint.counters()
    }

    /// Events queued on a channel and not yet sent (unreliable) or acked (reliable).
    pub fn queued(&self, channel: ChannelId) -> usize {
        self.core
            .channels
            .get(usize::from(channel.0))
            .map_or(0, Channel::queued_messages)
    }

    /// Payload bytes of received reliable events parked outside the inbox (bounded by
    /// `max_parked_bytes`).
    pub fn parked_bytes(&self) -> usize {
        self.core.parked_bytes
    }

    /// Payload bytes queued across all channels.
    pub fn queued_bytes(&self) -> usize {
        self.core.channels.iter().map(Channel::queued_bytes).sum()
    }

    /// Approximate native memory held.
    pub fn memory_usage(&self) -> MemoryUsage {
        let config = &self.core.shared.config;
        let (send, receive) = self
            .core
            .channels
            .iter()
            .map(Channel::memory)
            .fold((0, 0), |a, b| (a.0 + b.0, a.1 + b.1));
        // reliable's buffers: per-packet tracking, 512 RTT samples, the transmit scratch
        // buffer, and whatever reassembly buffers are live (bounded by the reassembly window)
        let reliable = (config.sent_packets_buffer_size + config.received_packets_buffer_size) * 24
            + config.fragment_reassembly_buffer_size * 300
            + 512 * 4
            + config.max_packet_size
            + 64 * 2;
        let core = &self.core;
        let connection = size_of::<Self>()
            + core.write_buffer.capacity()
            + core.sent.memory()
            + core.picks.capacity() * size_of::<Pick>()
            + core.sections.capacity() * size_of::<(u8, u32, u32)>()
            + core.decoded.messages.capacity() * size_of::<wire::Message>()
            + core.decoded.sections.capacity() * size_of::<wire::Section>();
        MemoryUsage {
            connection,
            reliable,
            send,
            receive,
        }
    }
}

impl Core {
    fn fail(&mut self, failure: Failure) {
        if !matches!(self.state, ConnectionState::Failed(_)) {
            self.state = ConnectionState::Failed(failure);
            self.failed_event = true;
        }
    }

    fn malformed(&mut self, _why: Malformed) -> bool {
        self.malformed += 1;
        self.counters.malformed_packets += 1;
        if self.malformed >= self.shared.config.malformed_limit {
            self.fail(Failure::MalformedData);
        }
        false
    }

    /// reliable's `process` callback: returns whether to ack the packet.
    fn process<L: Copy>(&mut self, packet: &[u8], inbox: &mut Inbox<L>) -> bool {
        if matches!(self.state, ConnectionState::Failed(_)) {
            return false;
        }
        match wire::decode(&self.shared.layout, packet, &mut self.decoded) {
            Ok(()) => {}
            Err(DecodeError::Malformed(why)) => return self.malformed(why),
            Err(DecodeError::Mismatch(hello)) => {
                let local = self.shared.layout.hello();
                self.fail(if hello.wire_version == local.wire_version {
                    Failure::SchemaMismatch {
                        local: local.fingerprint,
                        remote: hello.fingerprint,
                    }
                } else {
                    Failure::ProtocolMismatch {
                        local: local.wire_version,
                        remote: hello.wire_version,
                    }
                });
                return false;
            }
        }

        if self.state == ConnectionState::Handshaking {
            if self.decoded.hello.is_none() {
                // a correct peer repeats its hello until one is acked, and we ack nothing
                // before verifying one
                return self.malformed(Malformed::MissingHello);
            }
            self.state = ConnectionState::Established;
            self.established_event = true;
        }

        // validate every reliable id before applying anything: all or nothing
        let invalid = self.decoded.sections.iter().any(|section| {
            let messages = &self.decoded.messages
                [section.first as usize..(section.first + section.count) as usize];
            match &self.channels[usize::from(section.channel.0)] {
                Channel::Reliable(c) => {
                    messages.iter().any(|m| c.arrival(m.id) == Arrival::Invalid)
                }
                Channel::Unreliable(_) => false,
            }
        });
        if invalid {
            return self.malformed(Malformed::IdSpanExceedsWindow);
        }

        if !self.apply_reliable(packet, inbox) {
            // unreliable events ride only in acked packets, so a duplicate of this datagram
            // arriving later cannot deliver them twice
            for section in &self.decoded.sections {
                if matches!(
                    self.channels[usize::from(section.channel.0)],
                    Channel::Unreliable(_)
                ) {
                    self.counters.events_dropped_on_receive += u64::from(section.count);
                }
            }
            self.counters.packets_refused += 1;
            return false;
        }
        self.apply_unreliable(packet, inbox);

        self.counters.packets_received += 1;
        if self.decoded.hello.is_some() || !self.decoded.messages.is_empty() {
            self.ack_pending = true;
            self.unacked_received += 1;
        }
        true
    }

    /// Applies the reliable sections of a decoded packet. Returns false if an event could
    /// be neither delivered nor parked, so the packet must stay unacked.
    ///
    /// The invariant that keeps a sender inside this end's receive window: an event is acked
    /// only once delivered, or parked behind a gap. The next in-order event is therefore
    /// delivered or refused, never parked, and when it fills a gap the whole contiguous run
    /// behind it moves into the inbox at once. Events applied before a refusal come back as
    /// duplicates and are ignored.
    fn apply_reliable<L: Copy>(&mut self, packet: &[u8], inbox: &mut Inbox<L>) -> bool {
        let config = &self.shared.config;
        let (max_events, max_bytes) = (config.max_pending_events, config.max_pending_bytes);
        let max_parked = config.max_parked_bytes;
        let peer = self.peer;
        for section in &self.decoded.sections {
            let channel_id = section.channel;
            let Channel::Reliable(c) = &mut self.channels[usize::from(channel_id.0)] else {
                continue;
            };
            let messages = &self.decoded.messages
                [section.first as usize..(section.first + section.count) as usize];
            for m in messages {
                let payload = m.payload(packet);
                match c.arrival(m.id) {
                    Arrival::Old => self.counters.duplicate_events += 1,
                    Arrival::Invalid => unreachable!("validated before applying"),
                    Arrival::New if c.is_parked(m.id) => self.counters.duplicate_events += 1,
                    Arrival::New if c.is_next(m.id) => {
                        if !inbox.has_room(peer, payload.len(), max_events, max_bytes) {
                            return false;
                        }
                        inbox.push_message(peer, m.event, channel_id, payload);
                        self.counters.events_received += 1;
                        c.delivered_next();
                        // the gap is filled: everything parked behind it is in order now
                        while let Some((event, parked)) = c.ready() {
                            inbox.push_message(peer, event, channel_id, parked);
                            self.counters.events_received += 1;
                            self.parked_bytes -= c.consume_ready();
                        }
                    }
                    Arrival::New => {
                        if self.parked_bytes + payload.len() > max_parked {
                            return false;
                        }
                        c.park(m.id, m.event, payload);
                        self.parked_bytes += payload.len();
                    }
                }
            }
        }
        true
    }

    /// Applies the unreliable sections of an accepted packet, dropping what the inbox has no
    /// room for.
    fn apply_unreliable<L: Copy>(&mut self, packet: &[u8], inbox: &mut Inbox<L>) {
        let config = &self.shared.config;
        let (max_events, max_bytes) = (config.max_pending_events, config.max_pending_bytes);
        for section in &self.decoded.sections {
            if !matches!(
                self.channels[usize::from(section.channel.0)],
                Channel::Unreliable(_)
            ) {
                continue;
            }
            let messages = &self.decoded.messages
                [section.first as usize..(section.first + section.count) as usize];
            for m in messages {
                let payload = m.payload(packet);
                if inbox.has_room(self.peer, payload.len(), max_events, max_bytes) {
                    inbox.push_message(self.peer, m.event, section.channel, payload);
                    self.counters.events_received += 1;
                } else {
                    self.counters.events_dropped_on_receive += 1;
                }
            }
        }
    }

    fn acked(&mut self, sequence: u16) {
        let Some(entry) = self.sent.take(sequence) else {
            return;
        };
        if entry.hello {
            self.hello_acked = true;
        }
        for &(channel, id, serial) in &entry.messages {
            if let Channel::Reliable(c) = &mut self.channels[usize::from(channel)] {
                c.ack(id, serial);
            }
        }
    }

    /// Selects and writes one packet into `write_buffer`. Returns its length and how many
    /// events it carries.
    fn build_packet(&mut self, with_events: bool) -> (usize, u32) {
        let hello = (!self.hello_acked).then(|| self.shared.layout.hello());
        let config = &self.shared.config;
        let mut fill = Fill {
            bits: self.shared.layout.header_bits(hello.is_some()),
            limit: config.packet_budget as u64 * 8,
            max_bits: config.max_packet_size as u64 * 8,
            full: false,
        };
        self.picks.clear();
        self.sections.clear();

        let count = if with_events { self.channels.len() } else { 0 };
        let start = if count == 0 { 0 } else { self.rotation % count };
        let mut blocked = None;
        for k in 0..count {
            if fill.full {
                break;
            }
            let index = (start + k) % count;
            let first = self.picks.len() as u32;
            let (taken, stalled) = self.select(index, &mut fill);
            if stalled {
                blocked.get_or_insert(index);
            }
            if taken > 0 {
                self.sections.push((index as u8, first, taken));
            }
        }
        // a blocked channel leads the next packet, so a large event is never starved by
        // smaller ones filling every packet ahead of it
        if count > 0 {
            self.rotation = blocked.unwrap_or(start + 1);
        }

        let len = self.write_selected(hello, fill.limit);
        (len, self.picks.len() as u32)
    }

    /// Picks messages from one channel into the packet. Returns how many it took and whether
    /// it stopped because the next one did not fit.
    fn select(&mut self, index: usize, fill: &mut Fill) -> (u32, bool) {
        let shared = &*self.shared;
        let layout = &shared.layout;
        let channel_id = ChannelId(index as u8);
        let budget = shared.schema.channels()[index]
            .config
            .packet_budget
            .map_or(u64::MAX, |b| u64::from(b) * 8);
        let max_messages = layout.max_messages();
        let mut used = 0u64;
        let mut taken = 0u32;
        match &mut self.channels[index] {
            Channel::Reliable(c) => {
                let mut previous: Option<Seq16> = None;
                while taken < max_messages && !fill.full {
                    let Some(candidate) = c.peek_due(self.time) else {
                        break;
                    };
                    let (id, serial, resend) = (candidate.id, candidate.serial, candidate.resend);
                    let cost = layout.message_bits(channel_id, candidate.payload.len())
                        + previous.map_or_else(
                            || layout.section_bits(channel_id),
                            |p| relative_bits(u32::from(id.since(p))),
                        );
                    if !fill.admit(cost, used, budget, self.picks.is_empty()) {
                        return (taken, true);
                    }
                    c.take_due(self.time);
                    if resend {
                        self.counters.events_resent += 1;
                    } else {
                        self.counters.events_sent += 1;
                    }
                    self.picks.push(Pick {
                        channel: index as u8,
                        id,
                        index: 0,
                        serial,
                    });
                    used += cost;
                    taken += 1;
                    previous = Some(id);
                }
            }
            Channel::Unreliable(c) => {
                while taken < max_messages && !fill.full {
                    let Some((_, payload)) = c.get(taken as usize) else {
                        break;
                    };
                    let section = if taken == 0 {
                        layout.section_bits(channel_id)
                    } else {
                        0
                    };
                    let cost = layout.message_bits(channel_id, payload.len()) + section;
                    if !fill.admit(cost, used, budget, self.picks.is_empty()) {
                        return (taken, true);
                    }
                    self.counters.events_sent += 1;
                    self.picks.push(Pick {
                        channel: index as u8,
                        id: Seq16::ZERO,
                        index: taken,
                        serial: 0,
                    });
                    used += cost;
                    taken += 1;
                }
            }
        }
        (taken, false)
    }

    /// Writes the selected sections into `write_buffer`, returning the packet length.
    fn write_selected(&mut self, hello: Option<wire::Hello>, limit: u64) -> usize {
        let layout = &self.shared.layout;
        let mut w = PacketWriter::new(&mut self.write_buffer);
        w.header(layout, hello, self.sections.len() as u32);
        for &(index, first, taken) in &self.sections {
            w.section(layout, ChannelId(index), taken);
            let picks = &self.picks[first as usize..(first + taken) as usize];
            match &mut self.channels[usize::from(index)] {
                Channel::Reliable(c) => {
                    let mut previous = None;
                    for pick in picks {
                        match previous {
                            None => w.first_id(pick.id),
                            Some(p) => w.next_id(u32::from(pick.id.since(p))),
                        }
                        previous = Some(pick.id);
                        let (event, payload) = c.payload(pick.id);
                        w.message(layout, event, payload);
                    }
                }
                Channel::Unreliable(c) => {
                    for pick in picks {
                        if let Some((event, payload)) = c.get(pick.index as usize) {
                            w.message(layout, event, payload);
                        }
                    }
                    c.pop_sent(taken as usize);
                }
            }
        }
        debug_assert!(w.bits() <= limit);
        w.finish()
    }
}
