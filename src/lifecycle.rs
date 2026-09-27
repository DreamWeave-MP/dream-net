//! Connection lifecycle: why connections end.

use core::fmt;

use crate::schema::Fingerprint;

/// Why a connection ended. Stable: hosts map these to player-facing messages.
///
/// These do not promise a one-to-one mapping onto netcode's internal states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DisconnectReason {
    /// This side asked to disconnect.
    Requested,
    /// The other side closed the connection.
    Remote,
    /// Nothing was heard from the other side within netcode's timeout.
    TimedOut,
    /// The server refused the connection (full, or the client id is already connected).
    Denied,
    /// The connect token was invalid or expired.
    Authentication,
    /// The peer speaks a different dream-net wire version.
    ProtocolMismatch,
    /// The peer's schema fingerprint differs.
    SchemaMismatch,
    /// The peer sent malformed dream-net framing.
    MalformedData,
    /// The peer never completed the schema handshake.
    HandshakeTimeout,
    /// The transport failed (socket error, or the server stopped).
    TransportError,
}

impl DisconnectReason {
    /// A stable camelCase name, for scripts and logs.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Remote => "remote",
            Self::TimedOut => "timeout",
            Self::Denied => "denied",
            Self::Authentication => "authentication",
            Self::ProtocolMismatch => "protocolMismatch",
            Self::SchemaMismatch => "schemaMismatch",
            Self::MalformedData => "malformedData",
            Self::HandshakeTimeout => "handshakeTimeout",
            Self::TransportError => "transportError",
        }
    }
}

impl fmt::Display for DisconnectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Where a [`Connection`](crate::Connection) stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Waiting for the peer's hello.
    Handshaking,
    /// The peer's hello matched: events flow.
    Established,
    /// The connection failed and must be torn down.
    Failed(Failure),
}

/// Why a [`Connection`](crate::Connection) failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// The peer's wire version differs.
    ProtocolMismatch {
        /// Our wire version.
        local: u16,
        /// Theirs.
        remote: u16,
    },
    /// The peer's schema fingerprint differs.
    SchemaMismatch {
        /// Our fingerprint.
        local: Fingerprint,
        /// Theirs.
        remote: Fingerprint,
    },
    /// The peer sent more malformed packets than the configured limit.
    MalformedData,
    /// The peer did not complete the handshake in time.
    HandshakeTimeout,
    /// The transport refused a datagram. dream-net sizes every datagram so this cannot
    /// happen; it is reported instead of silently dropping traffic if it ever does.
    TransportError,
}

impl Failure {
    /// The matching disconnect reason.
    pub const fn reason(self) -> DisconnectReason {
        match self {
            Self::ProtocolMismatch { .. } => DisconnectReason::ProtocolMismatch,
            Self::SchemaMismatch { .. } => DisconnectReason::SchemaMismatch,
            Self::MalformedData => DisconnectReason::MalformedData,
            Self::HandshakeTimeout => DisconnectReason::HandshakeTimeout,
            Self::TransportError => DisconnectReason::TransportError,
        }
    }
}
