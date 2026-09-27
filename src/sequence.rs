//! Wrap-safe 16-bit sequence numbers.
//!
//! Reliable message ids wrap at 16 bits. Comparing two of them with `<` is wrong as soon as
//! the counter wraps, so every comparison in dream-net goes through [`Seq16`], whose ordering
//! is exactly `reliable`'s packet sequence ordering (half the space ahead is newer).

use core::fmt;

/// A 16-bit sequence number that wraps.
///
/// Ordering is circular: `a` is newer than `b` when it is at most half the space (32768)
/// ahead of it. Distances are forward distances modulo 2^16.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Seq16(pub u16);

impl Seq16 {
    /// Sequence number zero.
    pub const ZERO: Self = Self(0);

    /// The next sequence number, wrapping from 65535 to 0.
    #[inline]
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0.wrapping_add(1))
    }

    /// This sequence number advanced by `n`, wrapping.
    #[inline]
    #[must_use]
    pub const fn add(self, n: u16) -> Self {
        Self(self.0.wrapping_add(n))
    }

    /// The forward distance from `base` to `self`, modulo 2^16. A window of `w` messages
    /// starting at `base` contains `self` exactly when `self.since(base) < w`.
    #[inline]
    #[must_use]
    pub const fn since(self, base: Self) -> u16 {
        self.0.wrapping_sub(base.0)
    }

    /// Whether `self` is newer than `other` (at most 32768 ahead of it).
    #[inline]
    #[must_use]
    pub fn is_newer_than(self, other: Self) -> bool {
        reliable::sequence_greater_than(self.0, other.0)
    }

    /// Whether `self` is older than `other`.
    #[inline]
    #[must_use]
    pub fn is_older_than(self, other: Self) -> bool {
        reliable::sequence_less_than(self.0, other.0)
    }
}

impl fmt::Debug for Seq16 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Seq16({})", self.0)
    }
}

impl fmt::Display for Seq16 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

#[cfg(test)]
mod tests {
    use super::Seq16;
    use proptest::prelude::*;

    #[test]
    fn wraps() {
        assert_eq!(Seq16(u16::MAX).next(), Seq16(0));
        assert!(Seq16(0).is_newer_than(Seq16(u16::MAX)));
        assert!(Seq16(u16::MAX).is_older_than(Seq16(0)));
        assert_eq!(Seq16(3).since(Seq16(u16::MAX - 1)), 5);
        assert!(!Seq16(7).is_newer_than(Seq16(7)));
    }

    proptest! {
        #[test]
        fn newer_matches_forward_distance(a: u16, d in 1u16..=32767) {
            let base = Seq16(a);
            let ahead = base.add(d);
            prop_assert!(ahead.is_newer_than(base));
            prop_assert!(base.is_older_than(ahead));
            prop_assert_eq!(ahead.since(base), d);
        }

        #[test]
        fn ordering_is_antisymmetric(a: u16, b: u16) {
            let (a, b) = (Seq16(a), Seq16(b));
            prop_assert!(!(a.is_newer_than(b) && b.is_newer_than(a)));
            prop_assert_eq!(a.is_newer_than(b), b.is_older_than(a));
        }
    }
}
