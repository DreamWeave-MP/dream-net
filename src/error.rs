//! Error types.
//!
//! dream-net separates three kinds of failure (§103 of the design): API misuse is a typed
//! `Err`, ordinary network conditions are not errors at all (a poll returns `None`, a lost
//! packet is silent), and malformed remote input is refused, counted, and eventually
//! disconnects the peer — it never reaches the host as an error or a panic.

use core::fmt;

use crate::id::{ChannelId, EventTypeId, PeerId};

/// A schema or transport configuration was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigError {
    /// A channel or event name is empty, longer than 255 bytes, or contains a character
    /// outside `[A-Za-z0-9_.:/-]`.
    InvalidName(String),
    /// Two channels share a name.
    DuplicateChannel(String),
    /// Two events share a name.
    DuplicateEvent(String),
    /// More than [`MAX_CHANNELS`](crate::schema::MAX_CHANNELS) channels.
    TooManyChannels,
    /// More than [`MAX_EVENT_TYPES`](crate::schema::MAX_EVENT_TYPES) events.
    TooManyEvents,
    /// An event names a channel the schema does not have.
    UnknownChannel(ChannelId),
    /// A channel capacity is zero, or a reliable window exceeds 32768 messages.
    InvalidCapacity {
        /// The channel.
        channel: String,
        /// The rejected capacity.
        capacity: u16,
    },
    /// A reliable channel was given an overflow policy other than `Fail`. Durable events are
    /// never dropped silently.
    ReliableOverflowPolicy(String),
    /// A channel's resend interval is not a finite, non-negative number of seconds.
    InvalidResendInterval(String),
    /// `max_messages_per_packet` is outside `[1, 4096]`.
    InvalidMaxMessagesPerPacket(u32),
    /// An event's maximum payload exceeds what the schema or transport can carry.
    EventTooLarge {
        /// The event's name.
        event: String,
        /// Its declared maximum payload.
        max_payload: u32,
        /// The largest payload that fits.
        limit: u32,
    },
    /// A transport configuration value is out of range; the message names it.
    Transport(&'static str),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName(name) => write!(
                f,
                "invalid name {name:?}: names are 1-255 bytes of [A-Za-z0-9_.:/-]"
            ),
            Self::DuplicateChannel(name) => write!(f, "duplicate channel {name:?}"),
            Self::DuplicateEvent(name) => write!(f, "duplicate event {name:?}"),
            Self::TooManyChannels => write!(f, "too many channels"),
            Self::TooManyEvents => write!(f, "too many events"),
            Self::UnknownChannel(channel) => write!(f, "unknown {channel}"),
            Self::InvalidCapacity { channel, capacity } => {
                write!(f, "channel {channel:?} has invalid capacity {capacity}")
            }
            Self::ReliableOverflowPolicy(channel) => write!(
                f,
                "reliable channel {channel:?} must refuse on overflow, not drop"
            ),
            Self::InvalidResendInterval(channel) => {
                write!(f, "channel {channel:?} has an invalid resend interval")
            }
            Self::InvalidMaxMessagesPerPacket(n) => {
                write!(f, "max messages per packet {n} is outside [1, 4096]")
            }
            Self::EventTooLarge {
                event,
                max_payload,
                limit,
            } => write!(
                f,
                "event {event:?} allows {max_payload} byte payloads, but at most {limit} fit"
            ),
            Self::Transport(what) => write!(f, "invalid transport configuration: {what}"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Queueing an outgoing event failed. Nothing was queued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SendError {
    /// The peer is not connected: it never existed, has left, or has not finished its
    /// handshake.
    UnknownPeer(PeerId),
    /// The client is not connected (or has not finished its handshake).
    NotConnected,
    /// The schema has no event with this id.
    UnknownEvent(EventTypeId),
    /// The payload is larger than the event's declared maximum.
    PayloadTooLarge {
        /// The event.
        event: EventTypeId,
        /// The payload length.
        len: usize,
        /// The event's maximum payload.
        max: u32,
    },
    /// The channel's queue is full. Reliable channels always refuse rather than drop;
    /// unreliable channels refuse under `OverflowPolicy::Fail`.
    QueueFull(ChannelId),
}

impl fmt::Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownPeer(peer) => write!(f, "{peer} is not connected"),
            Self::NotConnected => write!(f, "not connected"),
            Self::UnknownEvent(event) => write!(f, "unknown {event}"),
            Self::PayloadTooLarge { event, len, max } => {
                write!(
                    f,
                    "{len} byte payload exceeds the {max} byte maximum of {event}"
                )
            }
            Self::QueueFull(channel) => write!(f, "{channel} send queue is full"),
        }
    }
}

impl std::error::Error for SendError {}

/// A caller-provided buffer was too small for the next polled payload. The event was not
/// consumed; grow the buffer to `needed` bytes and poll again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufferTooSmall {
    /// The payload length.
    pub needed: usize,
}

impl fmt::Display for BufferTooSmall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "buffer too small: the next payload is {} bytes",
            self.needed
        )
    }
}

impl std::error::Error for BufferTooSmall {}

/// Creating or starting a server or client failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The schema or transport configuration was rejected.
    Config(ConfigError),
    /// netcode refused (socket, token, or slot count).
    Netcode(netcode::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(error) => fmt::Display::fmt(error, f),
            Self::Netcode(error) => write!(f, "netcode: {error}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Config(error) => Some(error),
            Self::Netcode(error) => Some(error),
        }
    }
}

impl From<ConfigError> for Error {
    fn from(error: ConfigError) -> Self {
        Self::Config(error)
    }
}

impl From<netcode::Error> for Error {
    fn from(error: netcode::Error) -> Self {
        Self::Netcode(error)
    }
}
