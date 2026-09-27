//! The frozen wire schema: channels, events, and the fingerprint peers compare.
//!
//! The engine's event system owns what events mean. Before networking starts it hands
//! dream-net the transport view of its wire-capable events: a name, a channel, and a maximum
//! payload per event. [`SchemaBuilder::build`] sorts events by name, assigns dense
//! [`EventTypeId`]s, freezes the result, and computes a [`Fingerprint`] over everything both
//! ends must agree on. Registration order never affects ids or the fingerprint.

use core::fmt;
use std::sync::Arc;

use crate::error::ConfigError;
use crate::id::{ChannelId, EventTypeId};

/// The most channels a schema may declare.
pub const MAX_CHANNELS: usize = 64;
/// The most events a schema may declare.
pub const MAX_EVENT_TYPES: usize = 1 << 20;
/// The longest channel or event name, in bytes.
pub const MAX_NAME_BYTES: usize = 255;
/// The largest reliable window: half the 16-bit message id space, so wrap-safe comparisons
/// stay unambiguous.
pub const MAX_RELIABLE_WINDOW: u16 = 32768;
/// The largest per-event payload a schema accepts. Transport limits usually bind first.
pub const MAX_EVENT_PAYLOAD: u32 = 1 << 24;
/// The largest `max_messages_per_packet`.
pub const MAX_MESSAGES_PER_PACKET: u32 = 4096;

/// How a channel delivers events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Delivery {
    /// Delivered exactly once, in send order, resent until acknowledged.
    ReliableOrdered,
    /// Delivered at most once, in any order, never resent.
    UnreliableUnordered,
}

/// What an unreliable channel does when its send queue is full.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum OverflowPolicy {
    /// Refuse the new event with [`SendError::QueueFull`](crate::SendError::QueueFull).
    #[default]
    Fail,
    /// Drop the oldest queued event to make room.
    DropOldest,
    /// Drop the new event, reporting success.
    DropNewest,
}

/// A channel to declare with [`SchemaBuilder::channel`].
///
/// `name`, `delivery`, and `capacity` are part of the fingerprint: both ends must agree on
/// them. `overflow`, `packet_budget`, and `resend_interval` are local sending policy.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct ChannelConfig {
    /// Diagnostic name, unique in the schema.
    pub name: String,
    /// Delivery class.
    pub delivery: Delivery,
    /// Reliable: the send window and receive window, in messages (at most 32768).
    /// Unreliable: the send queue capacity.
    pub capacity: u16,
    /// Unreliable overflow policy. Reliable channels must use [`OverflowPolicy::Fail`].
    pub overflow: OverflowPolicy,
    /// The most payload-and-framing bytes this channel may put in one packet, or `None` for
    /// no per-channel cap. A single event larger than the budget still gets sent.
    pub packet_budget: Option<u32>,
    /// Reliable: seconds before an unacknowledged message is sent again.
    pub resend_interval: f64,
}

impl ChannelConfig {
    /// A reliable-ordered channel with a 1024-message window and a 100 ms resend interval.
    pub fn reliable_ordered(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            delivery: Delivery::ReliableOrdered,
            capacity: 1024,
            overflow: OverflowPolicy::Fail,
            packet_budget: None,
            resend_interval: 0.1,
        }
    }

    /// An unreliable-unordered channel with a 1024-event queue that refuses when full.
    pub fn unreliable_unordered(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            delivery: Delivery::UnreliableUnordered,
            capacity: 1024,
            overflow: OverflowPolicy::Fail,
            packet_budget: None,
            resend_interval: 0.0,
        }
    }

    /// Sets `capacity`.
    #[must_use]
    pub fn with_capacity(mut self, capacity: u16) -> Self {
        self.capacity = capacity;
        self
    }

    /// Sets `overflow`.
    #[must_use]
    pub fn with_overflow(mut self, overflow: OverflowPolicy) -> Self {
        self.overflow = overflow;
        self
    }

    /// Sets `packet_budget`.
    #[must_use]
    pub fn with_packet_budget(mut self, budget: u32) -> Self {
        self.packet_budget = Some(budget);
        self
    }

    /// Sets `resend_interval`.
    #[must_use]
    pub fn with_resend_interval(mut self, seconds: f64) -> Self {
        self.resend_interval = seconds;
        self
    }
}

/// A channel in a built [`Schema`].
#[derive(Debug, Clone, PartialEq)]
pub struct ChannelDef {
    /// The channel's id: its position in the catalogue.
    pub id: ChannelId,
    /// The channel's configuration.
    pub config: ChannelConfig,
    /// The largest payload of any event on the channel (0 if it has none).
    pub max_payload: u32,
    /// The events on this channel, in id order.
    pub events: Vec<EventTypeId>,
}

impl ChannelDef {
    /// The channel's diagnostic name.
    pub fn name(&self) -> &str {
        &self.config.name
    }

    /// The channel's delivery class.
    pub fn delivery(&self) -> Delivery {
        self.config.delivery
    }
}

/// An event in a built [`Schema`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventDef {
    /// The event's id.
    pub id: EventTypeId,
    /// The event's canonical name, kept for diagnostics.
    pub name: String,
    /// The channel that carries it.
    pub channel: ChannelId,
    /// The largest payload it may carry, in bytes.
    pub max_payload: u32,
    /// A version tag for the event's payload codec. Changing it changes the fingerprint.
    pub codec_version: u32,
}

/// A 128-bit schema fingerprint: SHA-256 over a canonical encoding of the schema, truncated.
///
/// It detects incompatible registries; it does not authenticate anything (netcode does
/// that). A cryptographic digest rather than a fast checksum makes it impractical for an
/// authenticated but hostile peer to craft a different schema with the same fingerprint.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Fingerprint(pub u128);

impl Fingerprint {
    /// The high and low 64-bit halves, for hosts (such as Luau) without 128-bit integers.
    pub const fn halves(self) -> (u64, u64) {
        ((self.0 >> 64) as u64, self.0 as u64)
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({:032x})", self.0)
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:032x}", self.0)
    }
}

/// The canonical-encoding hasher behind [`Fingerprint`].
struct Hasher(sha2::Sha256);

impl Hasher {
    fn new() -> Self {
        use sha2::Digest;
        Self(sha2::Sha256::new())
    }

    fn bytes(&mut self, bytes: &[u8]) {
        use sha2::Digest;
        self.0.update(bytes);
    }

    fn name(&mut self, name: &str) {
        // names are at most 255 bytes, so the length prefix is one byte and unambiguous
        self.bytes(&[name.len() as u8]);
        self.bytes(name.as_bytes());
    }

    /// The first 128 bits of the digest.
    fn finish(self) -> Fingerprint {
        use sha2::Digest;
        let digest = self.0.finalize();
        let mut first = [0u8; 16];
        first.copy_from_slice(&digest[..16]);
        Fingerprint(u128::from_le_bytes(first))
    }
}

/// Declares channels and events, then freezes them into a [`Schema`].
#[derive(Debug, Clone)]
pub struct SchemaBuilder {
    schema_version: u32,
    max_messages_per_packet: u32,
    channels: Vec<ChannelConfig>,
    events: Vec<(String, ChannelId, u32, u32)>,
}

impl SchemaBuilder {
    /// Starts a schema. `schema_version` is the host's catalogue version; it is part of the
    /// fingerprint.
    pub fn new(schema_version: u32) -> Self {
        Self {
            schema_version,
            max_messages_per_packet: 64,
            channels: Vec::new(),
            events: Vec::new(),
        }
    }

    /// Sets the most events one connection packet may carry per channel section (default
    /// 64). It shapes the wire format, so it is part of the fingerprint, and together with
    /// the reliable windows it must satisfy
    /// [`TransportConfig::validate_for`](crate::TransportConfig::validate_for).
    #[must_use]
    pub fn max_messages_per_packet(mut self, n: u32) -> Self {
        self.max_messages_per_packet = n;
        self
    }

    /// Declares a channel. Channel ids follow declaration order: the catalogue is
    /// deterministic because the host declares it in one place.
    ///
    /// # Errors
    ///
    /// Invalid or duplicate names, too many channels, or invalid capacity/policy.
    pub fn channel(&mut self, config: ChannelConfig) -> Result<ChannelId, ConfigError> {
        validate_name(&config.name)?;
        if self.channels.iter().any(|c| c.name == config.name) {
            return Err(ConfigError::DuplicateChannel(config.name));
        }
        if self.channels.len() >= MAX_CHANNELS {
            return Err(ConfigError::TooManyChannels);
        }
        let reliable = config.delivery == Delivery::ReliableOrdered;
        if config.capacity == 0 || (reliable && config.capacity > MAX_RELIABLE_WINDOW) {
            return Err(ConfigError::InvalidCapacity {
                channel: config.name,
                capacity: config.capacity,
            });
        }
        if reliable && config.overflow != OverflowPolicy::Fail {
            return Err(ConfigError::ReliableOverflowPolicy(config.name));
        }
        if !config.resend_interval.is_finite() || config.resend_interval < 0.0 {
            return Err(ConfigError::InvalidResendInterval(config.name));
        }
        let id = ChannelId(self.channels.len() as u8);
        self.channels.push(config);
        Ok(id)
    }

    /// Declares an event with codec version 0.
    ///
    /// # Errors
    ///
    /// See [`event_with_codec`](Self::event_with_codec).
    pub fn event(
        &mut self,
        name: impl Into<String>,
        channel: ChannelId,
        max_payload: u32,
    ) -> Result<(), ConfigError> {
        self.event_with_codec(name, channel, max_payload, 0)
    }

    /// Declares an event. Its id is assigned by [`build`](Self::build) from the sorted names.
    ///
    /// # Errors
    ///
    /// Invalid or duplicate names, an unknown channel, too many events, or a payload limit
    /// above [`MAX_EVENT_PAYLOAD`].
    pub fn event_with_codec(
        &mut self,
        name: impl Into<String>,
        channel: ChannelId,
        max_payload: u32,
        codec_version: u32,
    ) -> Result<(), ConfigError> {
        let name = name.into();
        validate_name(&name)?;
        if usize::from(channel.0) >= self.channels.len() {
            return Err(ConfigError::UnknownChannel(channel));
        }
        if self.events.len() >= MAX_EVENT_TYPES {
            return Err(ConfigError::TooManyEvents);
        }
        if max_payload > MAX_EVENT_PAYLOAD {
            return Err(ConfigError::EventTooLarge {
                event: name,
                max_payload,
                limit: MAX_EVENT_PAYLOAD,
            });
        }
        if self.events.iter().any(|(n, ..)| *n == name) {
            return Err(ConfigError::DuplicateEvent(name));
        }
        self.events
            .push((name, channel, max_payload, codec_version));
        Ok(())
    }

    /// Sorts, assigns ids, freezes, and fingerprints.
    ///
    /// # Errors
    ///
    /// An out-of-range `max_messages_per_packet`.
    pub fn build(mut self) -> Result<Schema, ConfigError> {
        if !(1..=MAX_MESSAGES_PER_PACKET).contains(&self.max_messages_per_packet) {
            return Err(ConfigError::InvalidMaxMessagesPerPacket(
                self.max_messages_per_packet,
            ));
        }
        self.events
            .sort_unstable_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));

        let mut channels: Vec<ChannelDef> = self
            .channels
            .into_iter()
            .enumerate()
            .map(|(index, config)| ChannelDef {
                id: ChannelId(index as u8),
                config,
                max_payload: 0,
                events: Vec::new(),
            })
            .collect();

        let events: Vec<EventDef> = self
            .events
            .into_iter()
            .enumerate()
            .map(|(index, (name, channel, max_payload, codec_version))| {
                let id = EventTypeId(index as u32);
                let def = &mut channels[usize::from(channel.0)];
                def.max_payload = def.max_payload.max(max_payload);
                def.events.push(id);
                EventDef {
                    id,
                    name,
                    channel,
                    max_payload,
                    codec_version,
                }
            })
            .collect();

        let mut hash = Hasher::new();
        hash.bytes(b"dream-net schema\0");
        hash.bytes(&crate::wire::WIRE_VERSION.to_le_bytes());
        hash.bytes(&self.schema_version.to_le_bytes());
        hash.bytes(&self.max_messages_per_packet.to_le_bytes());
        hash.bytes(&[channels.len() as u8]);
        for channel in &channels {
            hash.name(channel.name());
            hash.bytes(&[match channel.delivery() {
                Delivery::ReliableOrdered => 0,
                Delivery::UnreliableUnordered => 1,
            }]);
            hash.bytes(&channel.config.capacity.to_le_bytes());
            hash.bytes(&channel.max_payload.to_le_bytes());
        }
        hash.bytes(&(events.len() as u32).to_le_bytes());
        for event in &events {
            hash.bytes(&event.id.0.to_le_bytes());
            hash.name(&event.name);
            hash.bytes(&[event.channel.0]);
            hash.bytes(&event.max_payload.to_le_bytes());
            hash.bytes(&event.codec_version.to_le_bytes());
        }

        Ok(Schema(Arc::new(SchemaInner {
            schema_version: self.schema_version,
            max_messages_per_packet: self.max_messages_per_packet,
            fingerprint: hash.finish(),
            channels,
            events,
        })))
    }
}

#[derive(Debug)]
struct SchemaInner {
    schema_version: u32,
    max_messages_per_packet: u32,
    fingerprint: Fingerprint,
    channels: Vec<ChannelDef>,
    events: Vec<EventDef>,
}

/// A frozen wire schema. Cheap to clone (shared).
#[derive(Debug, Clone)]
pub struct Schema(Arc<SchemaInner>);

impl Schema {
    /// Starts a [`SchemaBuilder`].
    pub fn builder(schema_version: u32) -> SchemaBuilder {
        SchemaBuilder::new(schema_version)
    }

    /// The host's catalogue version.
    pub fn schema_version(&self) -> u32 {
        self.0.schema_version
    }

    /// The fingerprint peers compare during the handshake.
    pub fn fingerprint(&self) -> Fingerprint {
        self.0.fingerprint
    }

    /// The most events one packet section may carry.
    pub fn max_messages_per_packet(&self) -> u32 {
        self.0.max_messages_per_packet
    }

    /// The channel catalogue, indexed by [`ChannelId`].
    pub fn channels(&self) -> &[ChannelDef] {
        &self.0.channels
    }

    /// The events, indexed by [`EventTypeId`] (and sorted by name).
    pub fn events(&self) -> &[EventDef] {
        &self.0.events
    }

    /// Looks up a channel.
    #[inline]
    pub fn channel(&self, id: ChannelId) -> Option<&ChannelDef> {
        self.0.channels.get(usize::from(id.0))
    }

    /// Looks up an event.
    #[inline]
    pub fn event(&self, id: EventTypeId) -> Option<&EventDef> {
        self.0.events.get(id.0 as usize)
    }

    /// Finds an event by name (binary search: events are sorted by name).
    pub fn event_id(&self, name: &str) -> Option<EventTypeId> {
        self.0
            .events
            .binary_search_by(|e| e.name.as_bytes().cmp(name.as_bytes()))
            .ok()
            .map(|index| EventTypeId(index as u32))
    }

    /// Finds a channel by name.
    pub fn channel_id(&self, name: &str) -> Option<ChannelId> {
        self.0
            .channels
            .iter()
            .find(|c| c.name() == name)
            .map(|c| c.id)
    }

    /// Whether two handles share one frozen schema (identity, not structural equality).
    pub fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

fn validate_name(name: &str) -> Result<(), ConfigError> {
    let valid = !name.is_empty()
        && name.len() <= MAX_NAME_BYTES
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'/' | b'-'));
    if valid {
        Ok(())
    } else {
        Err(ConfigError::InvalidName(name.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(order: &[&str]) -> Schema {
        let mut b = Schema::builder(7);
        let reliable = b
            .channel(ChannelConfig::reliable_ordered("reliable"))
            .unwrap();
        let state = b
            .channel(ChannelConfig::unreliable_unordered("state"))
            .unwrap();
        for &name in order {
            let channel = if name.starts_with('R') {
                reliable
            } else {
                state
            };
            b.event(name, channel, 64).unwrap();
        }
        b.build().unwrap()
    }

    #[test]
    fn ids_follow_sorted_names_not_registration_order() {
        let a = build(&["SpellCast", "ActorPosition", "RChat", "Inventory"]);
        let b = build(&["RChat", "Inventory", "SpellCast", "ActorPosition"]);
        assert_eq!(a.fingerprint(), b.fingerprint());
        for event in a.events() {
            assert_eq!(b.event_id(&event.name), Some(event.id));
        }
        assert_eq!(a.event_id("ActorPosition"), Some(EventTypeId(0)));
        assert_eq!(a.event_id("SpellCast"), Some(EventTypeId(3)));
        assert_eq!(a.event_id("Missing"), None);
        assert_eq!(
            a.channel(ChannelId(0)).unwrap().events,
            vec![EventTypeId(2)]
        );
    }

    #[test]
    fn fingerprint_covers_every_input() {
        let base = build(&["A", "B"]).fingerprint();
        // each variant declares A like the base, then a B that differs in exactly one input
        let variants: [fn(&mut SchemaBuilder); 4] = [
            |b| b.event("C", ChannelId(1), 64).unwrap(),
            |b| b.event("B", ChannelId(0), 64).unwrap(),
            |b| b.event("B", ChannelId(1), 65).unwrap(),
            |b| b.event_with_codec("B", ChannelId(1), 64, 1).unwrap(),
        ];
        for (index, variant) in variants.iter().enumerate() {
            let mut b = Schema::builder(7);
            b.channel(ChannelConfig::reliable_ordered("reliable"))
                .unwrap();
            b.channel(ChannelConfig::unreliable_unordered("state"))
                .unwrap();
            b.event("A", ChannelId(1), 64).unwrap();
            variant(&mut b);
            assert_ne!(b.build().unwrap().fingerprint(), base, "variant {index}");
        }

        let mut version = Schema::builder(8);
        version
            .channel(ChannelConfig::reliable_ordered("reliable"))
            .unwrap();
        version
            .channel(ChannelConfig::unreliable_unordered("state"))
            .unwrap();
        version.event("A", ChannelId(1), 64).unwrap();
        version.event("B", ChannelId(1), 64).unwrap();
        assert_ne!(version.build().unwrap().fingerprint(), base);

        let mut window = Schema::builder(7);
        window
            .channel(ChannelConfig::reliable_ordered("reliable").with_capacity(512))
            .unwrap();
        window
            .channel(ChannelConfig::unreliable_unordered("state"))
            .unwrap();
        window.event("A", ChannelId(1), 64).unwrap();
        window.event("B", ChannelId(1), 64).unwrap();
        assert_ne!(window.build().unwrap().fingerprint(), base);

        let per_packet = build(&["A", "B"]);
        let mut b = Schema::builder(7).max_messages_per_packet(8);
        b.channel(ChannelConfig::reliable_ordered("reliable"))
            .unwrap();
        b.channel(ChannelConfig::unreliable_unordered("state"))
            .unwrap();
        b.event("A", ChannelId(1), 64).unwrap();
        b.event("B", ChannelId(1), 64).unwrap();
        assert_ne!(b.build().unwrap().fingerprint(), per_packet.fingerprint());
    }

    #[test]
    fn local_policy_is_not_fingerprinted() {
        let mut b = Schema::builder(7);
        b.channel(
            ChannelConfig::reliable_ordered("reliable")
                .with_resend_interval(0.5)
                .with_packet_budget(100),
        )
        .unwrap();
        b.channel(
            ChannelConfig::unreliable_unordered("state").with_overflow(OverflowPolicy::DropOldest),
        )
        .unwrap();
        b.event("A", ChannelId(1), 64).unwrap();
        b.event("B", ChannelId(1), 64).unwrap();
        assert_eq!(
            b.build().unwrap().fingerprint(),
            build(&["A", "B"]).fingerprint()
        );
    }

    #[test]
    fn rejects_bad_declarations() {
        let mut b = Schema::builder(0);
        assert!(matches!(
            b.channel(ChannelConfig::reliable_ordered("")),
            Err(ConfigError::InvalidName(_))
        ));
        assert!(matches!(
            b.channel(ChannelConfig::reliable_ordered("has space")),
            Err(ConfigError::InvalidName(_))
        ));
        let c = b.channel(ChannelConfig::reliable_ordered("r")).unwrap();
        assert!(matches!(
            b.channel(ChannelConfig::reliable_ordered("r")),
            Err(ConfigError::DuplicateChannel(_))
        ));
        assert!(matches!(
            b.channel(ChannelConfig::reliable_ordered("w").with_capacity(40000)),
            Err(ConfigError::InvalidCapacity { .. })
        ));
        assert!(matches!(
            b.channel(ChannelConfig::unreliable_unordered("z").with_capacity(0)),
            Err(ConfigError::InvalidCapacity { .. })
        ));
        assert!(matches!(
            b.channel(
                ChannelConfig::reliable_ordered("d").with_overflow(OverflowPolicy::DropOldest)
            ),
            Err(ConfigError::ReliableOverflowPolicy(_))
        ));
        assert!(matches!(
            b.channel(ChannelConfig::reliable_ordered("n").with_resend_interval(f64::NAN)),
            Err(ConfigError::InvalidResendInterval(_))
        ));
        assert!(matches!(
            b.event("E", ChannelId(9), 1),
            Err(ConfigError::UnknownChannel(_))
        ));
        b.event("E", c, 1).unwrap();
        assert!(matches!(
            b.event("E", c, 1),
            Err(ConfigError::DuplicateEvent(_))
        ));
        assert!(matches!(
            b.event("Big", c, MAX_EVENT_PAYLOAD + 1),
            Err(ConfigError::EventTooLarge { .. })
        ));
        assert!(matches!(
            b.clone().max_messages_per_packet(0).build(),
            Err(ConfigError::InvalidMaxMessagesPerPacket(0))
        ));
        let name = "x".repeat(MAX_NAME_BYTES + 1);
        assert!(matches!(
            b.event(name, c, 1),
            Err(ConfigError::InvalidName(_))
        ));
        b.event("x".repeat(MAX_NAME_BYTES), c, 1).unwrap();
        b.build().unwrap();
    }
}
