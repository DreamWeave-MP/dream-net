//! **dream-net** is the networking substrate of the DreamWeave engine.
//!
//! It moves opaque event payloads between authenticated peers and stops there:
//!
//! - [netcode] owns secure connections: connect tokens, encryption, replay protection, slots;
//! - [reliable] owns packet acknowledgement, fragmentation, and RTT/jitter/loss/bandwidth
//!   estimates;
//! - [serialize] owns the bit-packing of dream-net's own framing;
//! - dream-net adds the event layer those crates leave out: reliable-ordered and
//!   unreliable-unordered channels with packet aggregation, a frozen event schema with a
//!   fingerprint handshake, polled lifecycle and wire events, and bounded memory everywhere.
//!
//! dream-net knows event IDs, channel IDs, peers, and bytes. What an event means, who may send
//! it, and where it goes next are decided above it, in Luau.
//!
//! [netcode]: https://github.com/mas-bandwidth/netcode.rs
//! [reliable]: https://github.com/mas-bandwidth/reliable.rs
//! [serialize]: https://github.com/mas-bandwidth/serialize.rs

#![forbid(unsafe_code)]

mod channel;
pub mod config;
pub mod connection;
pub mod error;
pub mod id;
pub mod inbox;
pub mod lifecycle;
pub mod schema;
pub mod sequence;
pub mod sim;
pub mod stats;
pub mod wire;

pub use config::TransportConfig;
pub use connection::{Connection, ConnectionEvent, Shared};
pub use error::{BufferTooSmall, ConfigError, Error, SendError};
pub use id::{ChannelId, EventTypeId, PeerId};
pub use inbox::{Inbox, MessageInfo, Record};
pub use lifecycle::{ConnectionState, DisconnectReason, Failure};
pub use schema::{
    ChannelConfig, ChannelDef, Delivery, EventDef, Fingerprint, OverflowPolicy, Schema,
    SchemaBuilder,
};
pub use sequence::Seq16;
pub use stats::{ConnectionStats, Counters, MemoryUsage};
