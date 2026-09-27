//! Transport configuration: packet sizing, limits, and timers.
//!
//! This is the runtime network profile (§82 of the design). It is host-validated because it
//! bounds memory and shapes what reaches netcode. Unlike the [`Schema`], it
//! need not match between peers.

use crate::error::ConfigError;
use crate::schema::Schema;

/// The largest datagram netcode carries.
pub const DATAGRAM_BYTES: usize = netcode::MAX_PAYLOAD_BYTES;
/// The largest reliable fragment payload whose datagram still fits netcode:
/// fragment header + packet header + fragment ≤ 1200.
pub const MAX_FRAGMENT_SIZE: usize =
    DATAGRAM_BYTES - reliable::FRAGMENT_HEADER_BYTES - reliable::MAX_PACKET_HEADER_BYTES;
/// The largest unfragmented connection packet whose datagram still fits netcode:
/// packet header + packet ≤ 1200.
pub const MAX_UNFRAGMENTED_PACKET: usize = DATAGRAM_BYTES - reliable::MAX_PACKET_HEADER_BYTES;

/// Transport configuration shared by [`Connection`](crate::Connection),
/// [`Server`](crate::Server), and [`Client`](crate::Client).
///
/// Build one with struct update syntax over [`Default`]:
/// `TransportConfig { max_pending_events: 256, ..TransportConfig::default() }`.
#[derive(Debug, Clone, PartialEq)]
pub struct TransportConfig {
    /// Largest connection packet, in bytes. Packets above `fragment_above` are fragmented by
    /// reliable; this bounds the largest single event a channel can carry.
    pub max_packet_size: usize,
    /// Packets larger than this are fragmented. At most [`MAX_UNFRAGMENTED_PACKET`].
    pub fragment_above: usize,
    /// Fragment payload size. At most [`MAX_FRAGMENT_SIZE`].
    pub fragment_size: usize,
    /// Target size of an aggregated packet. Events are packed until the next would exceed it;
    /// an event larger than the budget gets a packet of its own. Defaults to `fragment_above`
    /// so ordinary packets are never fragmented.
    pub packet_budget: usize,
    /// Most packets one connection writes per flush.
    pub max_packets_per_flush: usize,
    /// Seconds a new connection may take to complete the schema handshake.
    pub handshake_timeout: f64,
    /// Seconds a server keeps a client that failed the handshake with a schema or protocol
    /// mismatch, sending only its own hello, so the client can report the mismatch itself
    /// instead of seeing a bare disconnect. The client ends it early by disconnecting.
    pub mismatch_linger: f64,
    /// Longest gap, in seconds, between packets a connection sends. Acks and link statistics
    /// only travel in packets, so an idle connection still sends a small packet this often.
    /// 0 sends one every flush.
    pub idle_packet_interval: f64,
    /// Most received events waiting in the inbox to be polled, per connection. Past it,
    /// unreliable events are dropped (and counted), and a reliable event that is next in
    /// order is refused: its packet goes unacknowledged and the sender resends it once the
    /// host has polled. See `max_parked_bytes` for the one way the inbox can exceed this.
    pub max_pending_events: usize,
    /// Most received payload bytes waiting in the inbox to be polled, per connection. Same
    /// policy as `max_pending_events`.
    pub max_pending_bytes: usize,
    /// Most bytes of reliable events a connection holds outside the inbox: events that
    /// arrived behind a gap (an earlier event still missing) and wait for it. Each is charged
    /// its payload plus [`PARK_OVERHEAD`](crate::connection::PARK_OVERHEAD) for its slot, and
    /// an event is parked only if the reorder slots up to it fit the budget too, so this
    /// bounds the reorder buffer's structure as well as its payloads.
    ///
    /// A connection acknowledges a reliable event only once it is delivered to the inbox or
    /// parked behind a gap. That invariant keeps the sender inside this end's receive window,
    /// and it means an event that is next in order is never parked: it is delivered, or its
    /// packet is refused. When the missing event arrives, the whole parked run behind it
    /// moves into the inbox at once (already in memory, so no new bytes), which is the one
    /// case the inbox may exceed the pending limits, by at most this budget. What a peer can
    /// make a connection hold on receive is therefore at most
    /// `max_pending_bytes + 2 * max_parked_bytes`, whatever the schema's windows allow.
    ///
    /// An event that would overflow the budget leaves its packet unacknowledged, so the
    /// sender resends it after the gap fills. The event that fills a gap never needs
    /// parking, so the budget can slow a connection but not stall it.
    pub max_parked_bytes: usize,
    /// Most bytes of recycled payload buffers each channel keeps for reuse. Warm connections
    /// allocate nothing while their events fit; a burst of larger events is freed afterwards
    /// rather than held for the life of the connection.
    pub max_pooled_bytes: usize,
    /// Malformed packets tolerated before the peer is disconnected. netcode authenticates
    /// every datagram, so malformed framing comes from a buggy or hostile peer, never from
    /// line noise: the default is 1.
    pub malformed_limit: u32,
    /// Sent packets tracked for acks, loss, and bandwidth. A power of two, at most 32768.
    pub sent_packets_buffer_size: usize,
    /// Received packets tracked; also reliable's duplicate/stale window. A power of two, at
    /// most 32768.
    pub received_packets_buffer_size: usize,
    /// Packets that may be under fragment reassembly at once.
    pub fragment_reassembly_buffer_size: usize,
    /// Exponential smoothing factor for RTT.
    pub rtt_smoothing_factor: f32,
    /// Exponential smoothing factor for packet loss.
    pub packet_loss_smoothing_factor: f32,
    /// Exponential smoothing factor for bandwidth.
    pub bandwidth_smoothing_factor: f32,
    /// Assumed IP + UDP header bytes per packet, for bandwidth statistics only.
    pub packet_header_size: usize,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            max_packet_size: 32 * 1024,
            fragment_above: MAX_UNFRAGMENTED_PACKET,
            fragment_size: MAX_FRAGMENT_SIZE,
            packet_budget: MAX_UNFRAGMENTED_PACKET,
            max_packets_per_flush: 64,
            handshake_timeout: 5.0,
            mismatch_linger: 1.0,
            idle_packet_interval: 0.1,
            max_pending_events: 4096,
            max_pending_bytes: 4 * 1024 * 1024,
            max_parked_bytes: 1024 * 1024,
            max_pooled_bytes: 64 * 1024,
            malformed_limit: 1,
            sent_packets_buffer_size: 256,
            received_packets_buffer_size: 256,
            fragment_reassembly_buffer_size: 16,
            rtt_smoothing_factor: 0.0025,
            packet_loss_smoothing_factor: 0.1,
            bandwidth_smoothing_factor: 0.1,
            packet_header_size: 28,
        }
    }
}

impl TransportConfig {
    /// The number of fragments the largest packet needs.
    pub fn max_fragments(&self) -> usize {
        self.max_packet_size.div_ceil(self.fragment_size.max(1))
    }

    /// Checks every limit. After this succeeds, no packet dream-net hands reliable can trip
    /// one of its assertions, and every datagram fits netcode.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Transport`] naming the first bad value.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let check = |ok: bool, what: &'static str| {
            if ok {
                Ok(())
            } else {
                Err(ConfigError::Transport(what))
            }
        };
        check(
            (1..=MAX_FRAGMENT_SIZE).contains(&self.fragment_size),
            "fragment_size must be in [1, MAX_FRAGMENT_SIZE]",
        )?;
        check(
            (1..=MAX_UNFRAGMENTED_PACKET).contains(&self.fragment_above),
            "fragment_above must be in [1, MAX_UNFRAGMENTED_PACKET]",
        )?;
        check(
            self.max_packet_size >= self.fragment_above,
            "max_packet_size must be at least fragment_above",
        )?;
        check(
            self.max_fragments() <= 256,
            "max_packet_size needs more than 256 fragments",
        )?;
        check(
            (1..=self.max_packet_size).contains(&self.packet_budget),
            "packet_budget must be in [1, max_packet_size]",
        )?;
        check(
            self.max_packets_per_flush >= 1,
            "max_packets_per_flush must be at least 1",
        )?;
        check(
            self.handshake_timeout.is_finite() && self.handshake_timeout > 0.0,
            "handshake_timeout must be a positive number of seconds",
        )?;
        check(
            self.mismatch_linger.is_finite() && self.mismatch_linger >= 0.0,
            "mismatch_linger must be a non-negative number of seconds",
        )?;
        check(
            self.idle_packet_interval.is_finite() && self.idle_packet_interval >= 0.0,
            "idle_packet_interval must be a non-negative number of seconds",
        )?;
        check(
            self.max_pending_events >= 1,
            "max_pending_events must be at least 1",
        )?;
        check(
            self.malformed_limit >= 1,
            "malformed_limit must be at least 1",
        )?;
        let window = |n: usize| n.is_power_of_two() && n <= 32768;
        check(
            window(self.sent_packets_buffer_size),
            "sent_packets_buffer_size must be a power of two <= 32768",
        )?;
        check(
            window(self.received_packets_buffer_size),
            "received_packets_buffer_size must be a power of two <= 32768",
        )?;
        check(
            self.fragment_reassembly_buffer_size >= 1,
            "fragment_reassembly_buffer_size must be at least 1",
        )?;
        let factor = |f: f32| f.is_finite() && f > 0.0 && f <= 1.0;
        check(
            factor(self.rtt_smoothing_factor)
                && factor(self.packet_loss_smoothing_factor)
                && factor(self.bandwidth_smoothing_factor),
            "smoothing factors must be in (0, 1]",
        )?;
        Ok(())
    }

    /// Checks this configuration and that every event in `schema` fits in one packet.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Transport`] or [`ConfigError::EventTooLarge`].
    pub fn validate_for(&self, schema: &Schema) -> Result<(), ConfigError> {
        self.validate()?;
        let layout = crate::wire::Layout::new(schema);
        let overhead = layout.worst_case_single_message_overhead();
        let limit = self.max_packet_size.saturating_sub(overhead);
        let limit = u32::try_from(limit).unwrap_or(u32::MAX);
        if let Some(event) = schema.events().iter().find(|e| e.max_payload > limit) {
            return Err(ConfigError::EventTooLarge {
                event: event.name.clone(),
                max_payload: event.max_payload,
                limit,
            });
        }
        // A reliable id can arrive long after it was sent: reliable accepts any packet within
        // its received-packet window, so an id can lag the receiver by up to that many packets
        // of events plus a window. It must never wrap all the way round into the window ahead,
        // where it would be taken for a new event.
        let window = schema
            .channels()
            .iter()
            .filter(|c| c.delivery() == crate::schema::Delivery::ReliableOrdered)
            .map(|c| usize::from(c.config.capacity))
            .max()
            .unwrap_or(0);
        let stale = self.received_packets_buffer_size * schema.max_messages_per_packet() as usize;
        if stale + 2 * window > 1 << 16 {
            return Err(ConfigError::Transport(
                "received_packets_buffer_size * max_messages_per_packet + 2 * the largest \
                 reliable window must not exceed 65536",
            ));
        }
        let largest = |reliable_only: bool| {
            schema
                .channels()
                .iter()
                .filter(|c| {
                    !reliable_only || c.delivery() == crate::schema::Delivery::ReliableOrdered
                })
                .map(|c| c.max_payload as usize)
                .max()
                .unwrap_or(0)
        };
        if self.max_pending_bytes < largest(false) {
            return Err(ConfigError::Transport(
                "max_pending_bytes is smaller than the largest event payload",
            ));
        }
        if self.max_parked_bytes < largest(true) + 2 * crate::connection::PARK_OVERHEAD {
            return Err(ConfigError::Transport(
                "max_parked_bytes cannot hold the largest reliable event payload",
            ));
        }
        Ok(())
    }

    /// The reliable endpoint configuration this transport configuration implies.
    pub fn reliable_config(&self, name: &str) -> reliable::Config {
        reliable::Config {
            name: name.to_owned(),
            max_packet_size: self.max_packet_size,
            fragment_above: self.fragment_above,
            max_fragments: self.max_fragments(),
            fragment_size: self.fragment_size,
            // acks are drained after every received datagram, which carries at most 32
            ack_buffer_size: 64,
            sent_packets_buffer_size: self.sent_packets_buffer_size,
            received_packets_buffer_size: self.received_packets_buffer_size,
            fragment_reassembly_buffer_size: self.fragment_reassembly_buffer_size,
            rtt_smoothing_factor: self.rtt_smoothing_factor,
            rtt_history_size: 512,
            packet_loss_smoothing_factor: self.packet_loss_smoothing_factor,
            bandwidth_smoothing_factor: self.bandwidth_smoothing_factor,
            packet_header_size: self.packet_header_size,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_datagrams_fit_netcode() {
        let config = TransportConfig::default();
        config.validate().unwrap();
        assert_eq!(MAX_FRAGMENT_SIZE, 1186);
        assert_eq!(MAX_UNFRAGMENTED_PACKET, 1191);
        assert!(
            reliable::FRAGMENT_HEADER_BYTES
                + reliable::MAX_PACKET_HEADER_BYTES
                + config.fragment_size
                <= DATAGRAM_BYTES
        );
        assert!(reliable::MAX_PACKET_HEADER_BYTES + config.fragment_above <= DATAGRAM_BYTES);
    }

    #[test]
    fn rejects_configs_that_would_trip_reliable() {
        let bad = [
            TransportConfig {
                fragment_size: MAX_FRAGMENT_SIZE + 1,
                ..TransportConfig::default()
            },
            TransportConfig {
                fragment_above: 0,
                ..TransportConfig::default()
            },
            TransportConfig {
                max_packet_size: 257 * MAX_FRAGMENT_SIZE,
                ..TransportConfig::default()
            },
            TransportConfig {
                sent_packets_buffer_size: 300,
                ..TransportConfig::default()
            },
            TransportConfig {
                packet_budget: 0,
                ..TransportConfig::default()
            },
            TransportConfig {
                handshake_timeout: f64::INFINITY,
                ..TransportConfig::default()
            },
            TransportConfig {
                rtt_smoothing_factor: 0.0,
                ..TransportConfig::default()
            },
        ];
        for config in bad {
            assert!(config.validate().is_err(), "{config:?}");
        }
    }
}
