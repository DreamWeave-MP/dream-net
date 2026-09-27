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
// Source attributes, not just the manifest's [lints] table: CI passes -W clippy::pedantic on
// the command line, which overrides manifest lint levels but not these.
//
// Bit-packing and table indexing cast between widths whose bounds the schema and transport
// validation already enforce, the same policy serialize itself uses.
#![allow(
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::module_name_repetitions,
    clippy::must_use_candidate
)]

pub mod capture;
mod channel;
pub mod client;
pub mod config;
pub mod connection;
pub mod error;
pub mod id;
pub mod inbox;
pub mod lifecycle;
pub mod schema;
pub mod sequence;
pub mod server;
pub mod sim;
pub mod stats;
pub mod wire;

pub use client::{Client, ClientConfig, ClientEvent, ClientStatus};
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

/// netcode's public items dream-net's API mentions: keys, connect tokens, and the backend's
/// token generator (§76 of the design keeps token minting in trusted Rust tooling).
pub use netcode::{
    CONNECT_TOKEN_BYTES, KEY_BYTES, Key, USER_DATA_BYTES, UserData, generate_connect_token,
    generate_key,
};
pub use server::{Server, ServerConfig, ServerEvent};
pub use stats::{ConnectionStats, Counters, MemoryUsage};
