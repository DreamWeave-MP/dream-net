//! Compact identifiers: events, channels, and peers.

use core::fmt;

/// A wire event type, assigned densely from the sorted canonical event names when a
/// [`Schema`](crate::Schema) is built. Never depends on registration order.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct EventTypeId(pub u32);

/// A channel, numbered by its position in the schema's channel catalogue.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ChannelId(pub u8);

/// A connection-scoped handle to a remote client on a server.
///
/// The low 16 bits are the netcode slot, the high 48 bits a generation that increases every
/// time any slot is filled. A handle to a peer that has left never reaches the slot's next
/// occupant: it fails as unknown. Fits a Luau integer.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerId(pub u64);

impl PeerId {
    /// The largest generation a `PeerId` can hold.
    pub const MAX_GENERATION: u64 = (1 << 48) - 1;

    /// Builds a handle from a slot and a generation (masked to 48 bits).
    #[inline]
    #[must_use]
    pub const fn new(slot: u16, generation: u64) -> Self {
        Self(((generation & Self::MAX_GENERATION) << 16) | slot as u64)
    }

    /// The netcode client slot.
    #[inline]
    #[must_use]
    pub const fn slot(self) -> usize {
        (self.0 & 0xFFFF) as usize
    }

    /// The generation the slot had when this peer connected.
    #[inline]
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.0 >> 16
    }
}

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PeerId(slot {}, generation {})",
            self.slot(),
            self.generation()
        )
    }
}

impl fmt::Display for EventTypeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "event {}", self.0)
    }
}

impl fmt::Display for ChannelId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "channel {}", self.0)
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "peer {}:{}", self.slot(), self.generation())
    }
}

#[cfg(test)]
mod tests {
    use super::PeerId;

    #[test]
    fn peer_id_packs_slot_and_generation() {
        let peer = PeerId::new(255, 123_456_789);
        assert_eq!(peer.slot(), 255);
        assert_eq!(peer.generation(), 123_456_789);
        assert_ne!(PeerId::new(3, 1), PeerId::new(3, 2));
        let top = PeerId::new(u16::MAX, PeerId::MAX_GENERATION);
        assert_eq!(top.slot(), usize::from(u16::MAX));
        assert_eq!(top.generation(), PeerId::MAX_GENERATION);
    }
}
