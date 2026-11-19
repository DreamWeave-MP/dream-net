//! The connect tokens this process has already passed to [`Client::connect`]: a connect token
//! admits one connection attempt, and a second `connect` with the same token is refused before
//! anything reaches netcode.
//!
//! The record is process-wide, bounded and fixed in size: a ring of the SHA-256 digests (the
//! first [`DIGEST_BYTES`] bytes) of the most recent [`CONNECT_TOKEN_RECORD_CAPACITY`] tokens.
//! Neither a token nor its keys is kept, only the digest. When the ring is full the oldest
//! digest is forgotten, so the guarantee covers the most recent
//! [`CONNECT_TOKEN_RECORD_CAPACITY`] tokens. That is acceptable because a token is minted for
//! one attempt and stops being usable when it expires (seconds to minutes in practice): a host
//! would have to start thousands of other attempts within one token's lifetime, and still
//! hold on to that token, for the bound to matter. The record does not outlive the process: a
//! host must never store a token and present it again after a restart.
//!
//! [`Client::connect`]: super::Client::connect

use std::sync::{Mutex, MutexGuard, PoisonError};

use sha2::{Digest, Sha256};

use super::CONNECT_TOKEN_BYTES;

/// How many of the most recently used connect tokens the process remembers.
pub const CONNECT_TOKEN_RECORD_CAPACITY: usize = 4096;

/// Bytes of each token's SHA-256 kept: 128 bits, far beyond any chance of two different
/// tokens colliding.
const DIGEST_BYTES: usize = 16;

type TokenDigest = [u8; DIGEST_BYTES];

/// The digests of the most recently used tokens, oldest overwritten first. Fixed size: 64 KiB
/// in static memory, never allocated.
pub(super) struct UsedTokens {
    digests: [TokenDigest; CONNECT_TOKEN_RECORD_CAPACITY],
    /// How many entries of `digests` are filled.
    len: usize,
    /// Where the next digest goes once the ring is full: the oldest entry.
    next: usize,
}

impl UsedTokens {
    // Evaluated at compile time for the static record; only the unit tests below build one at
    // run time, 64 KiB on a test thread's stack.
    #[allow(clippy::large_stack_arrays)]
    const fn new() -> Self {
        Self {
            digests: [[0; DIGEST_BYTES]; CONNECT_TOKEN_RECORD_CAPACITY],
            len: 0,
            next: 0,
        }
    }

    /// The process-wide record, locked. A poisoned lock is recovered: every update of the
    /// record is a single slot write and two counters, so a panic elsewhere never leaves it
    /// half written.
    pub(super) fn lock() -> MutexGuard<'static, UsedTokens> {
        static USED: Mutex<UsedTokens> = Mutex::new(UsedTokens::new());
        USED.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether `digest` is recorded.
    pub(super) fn contains(&self, digest: &TokenDigest) -> bool {
        self.digests[..self.len].contains(digest)
    }

    /// Records `digest`, forgetting the oldest digest when the record is full.
    pub(super) fn insert(&mut self, digest: TokenDigest) {
        if self.len < CONNECT_TOKEN_RECORD_CAPACITY {
            self.digests[self.len] = digest;
            self.len += 1;
        } else {
            self.digests[self.next] = digest;
            self.next = (self.next + 1) % CONNECT_TOKEN_RECORD_CAPACITY;
        }
    }
}

/// The digest a token is recorded under.
pub(super) fn digest(token: &[u8; CONNECT_TOKEN_BYTES]) -> TokenDigest {
    let full = Sha256::digest(token);
    let mut digest = [0; DIGEST_BYTES];
    digest.copy_from_slice(&full[..DIGEST_BYTES]);
    digest
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(n: u32) -> [u8; CONNECT_TOKEN_BYTES] {
        let mut token = [0; CONNECT_TOKEN_BYTES];
        token[..4].copy_from_slice(&n.to_le_bytes());
        token
    }

    #[test]
    fn the_record_remembers_the_latest_tokens_and_forgets_the_oldest() {
        let mut record = UsedTokens::new();
        let extra = 5;
        let total = u32::try_from(CONNECT_TOKEN_RECORD_CAPACITY).unwrap() + extra;
        for n in 0..total {
            assert!(!record.contains(&digest(&token(n))));
            record.insert(digest(&token(n)));
            assert!(record.contains(&digest(&token(n))));
        }
        assert_eq!(record.len, CONNECT_TOKEN_RECORD_CAPACITY);
        for n in 0..extra {
            assert!(
                !record.contains(&digest(&token(n))),
                "token {n} still recorded"
            );
        }
        for n in extra..total {
            assert!(record.contains(&digest(&token(n))), "token {n} forgotten");
        }
        assert!(!record.contains(&digest(&token(total))));
    }

    #[test]
    fn different_tokens_have_different_digests_and_the_zero_digest_is_not_preset() {
        assert_ne!(digest(&token(0)), digest(&token(1)));
        let record = UsedTokens::new();
        assert!(!record.contains(&[0; DIGEST_BYTES]));
    }
}
