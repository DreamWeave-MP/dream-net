//! The public surface of `Server`, `Client`, their configuration and events, `Error`, and the
//! connect-token re-exports, pinned as dream-net 1.1.1 has it.
//!
//! Mostly a compile test: every signature is coerced to an explicit function-pointer type,
//! every exhaustive struct is built as a literal and every exhaustive enum matched without a
//! wildcard, and the auto traits are asserted both ways (a type that is not `Send` in 1.1.1
//! must not quietly become `Send` either, because hosts such as l3i reason from it). A change
//! of transport backend must leave this file compiling unchanged; the few runtime checks pin
//! values (constant sizes, `Display` texts) that a type cannot.

// CI passes -W clippy::pedantic on the command line, overriding the manifest's lint table.
// `clone` on Copy types is deliberate: it pins that `Clone` is implemented.
#![allow(clippy::type_complexity, clippy::clone_on_copy, dead_code)]

use std::net::SocketAddr;
use std::panic::{RefUnwindSafe, UnwindSafe};
use std::sync::Arc;

use dream_net::capture::CaptureSink;
use dream_net::sim::Pair;
use dream_net::{
    BufferTooSmall, CONNECT_TOKEN_BYTES, ChannelId, Client, ClientConfig, ClientEvent,
    ClientStatus, ConfigError, Connection, ConnectionStats, Counters, DisconnectReason, Error,
    EventTypeId, Failure, Inbox, KEY_BYTES, Key, MemoryUsage, PeerId, Schema, SendError, Server,
    ServerConfig, ServerEvent, Shared, TransportConfig, USER_DATA_BYTES, UserData,
};

// ---------------------------------------------------------------- auto traits (audit 4.10)

/// Asserts at compile time that `$t` does NOT implement `$trait`: if it did, the two blanket
/// impls below would make the method lookup ambiguous and the crate would not compile.
macro_rules! assert_not_impl {
    ($t:ty: $trait:path) => {
        const _: fn() = || {
            trait AmbiguousIfImpl<A> {
                fn some_item() {}
            }
            impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
            struct Invalid;
            impl<T: ?Sized + $trait> AmbiguousIfImpl<Invalid> for T {}
            let _ = <$t as AmbiguousIfImpl<_>>::some_item;
        };
    };
}

/// Asserts at compile time that `$t` implements every one of the five auto traits.
macro_rules! assert_all_auto {
    ($($t:ty),* $(,)?) => {
        $(const _: fn() = || {
            fn all<T: Send + Sync + Unpin + UnwindSafe + RefUnwindSafe>() {}
            all::<$t>();
        };)*
    };
}

// Server and Client: neither Send nor Sync (the capture sink is a `Box<dyn CaptureSink>`),
// Unpin, and neither UnwindSafe nor RefUnwindSafe.
const _: fn() = || {
    fn unpin<T: Unpin>() {}
    unpin::<Server>();
    unpin::<Client>();
};
assert_not_impl!(Server: Send);
assert_not_impl!(Server: Sync);
assert_not_impl!(Server: UnwindSafe);
assert_not_impl!(Server: RefUnwindSafe);
assert_not_impl!(Client: Send);
assert_not_impl!(Client: Sync);
assert_not_impl!(Client: UnwindSafe);
assert_not_impl!(Client: RefUnwindSafe);

// Error: Send, Sync and Unpin, not UnwindSafe or RefUnwindSafe (it can carry an io::Error).
const _: fn() = || {
    fn plain<T: Send + Sync + Unpin + 'static>() {}
    plain::<Error>();
};
assert_not_impl!(Error: UnwindSafe);
assert_not_impl!(Error: RefUnwindSafe);

// Everything else in the audit's table has all five.
assert_all_auto!(
    Connection,
    Shared,
    Arc<Shared>,
    Schema,
    Inbox<()>,
    ConfigError,
    SendError,
    ServerConfig,
    ClientConfig,
    TransportConfig,
    ConnectionStats,
    Counters,
    PeerId,
    Key,
    UserData,
    Pair,
);

// Plain data around the lifecycle, as in 1.1.1.
assert_all_auto!(
    ClientStatus,
    DisconnectReason,
    Failure,
    BufferTooSmall,
    MemoryUsage,
    ServerEvent<usize>,
    ServerEvent<&'static [u8]>,
    ClientEvent<usize>,
    ClientEvent<&'static [u8]>,
);

// ---------------------------------------------------------------- re-exports and constants

const _: () = assert!(CONNECT_TOKEN_BYTES == 2048);
const _: () = assert!(KEY_BYTES == 32);
const _: () = assert!(USER_DATA_BYTES == 256);
const _: usize = CONNECT_TOKEN_BYTES;
const _: usize = KEY_BYTES;
const _: usize = USER_DATA_BYTES;
const _: fn(Key) -> [u8; 32] = |k| k;
const _: fn([u8; 32]) -> Key = |k| k;
const _: fn(UserData) -> [u8; 256] = |u| u;
const _: fn([u8; 256]) -> UserData = |u| u;
const _: fn() -> Key = dream_net::generate_key;

/// `generate_connect_token` keeps its eight parameters, and its error is exactly the payload of
/// `Error::Netcode`, which converts into `Error` with `?`.
fn token_error_is_the_netcode_payload<E>(
    _: fn(
        &[SocketAddr],
        &[SocketAddr],
        i32,
        i32,
        u64,
        u64,
        &Key,
        &UserData,
    ) -> Result<[u8; CONNECT_TOKEN_BYTES], E>,
    _: fn(E) -> Error,
) where
    E: std::error::Error + Send + Sync + 'static,
    Error: From<E>,
{
}

const _: fn() = || {
    token_error_is_the_netcode_payload(dream_net::generate_connect_token, Error::Netcode);
};

// ---------------------------------------------------------------- Error

const _: fn(ConfigError) -> Error = Error::Config;
const _: fn(ConfigError) -> Error = <Error as From<ConfigError>>::from;

/// `Error` is an error with a source, printable and debuggable.
fn error_traits<T: std::error::Error + std::fmt::Debug + std::fmt::Display + 'static>() {}
const _: fn() = || error_traits::<Error>();

// ---------------------------------------------------------------- additive since 1.1.1

// The Netcode payload has a name of dream-net's own, with netcode-official 1.0.0's variants.
const _: fn(dream_net::NetcodeError) -> Error = Error::Netcode;
const _: fn(dream_net::NetcodeError) -> Error = <Error as From<dream_net::NetcodeError>>::from;
const _: fn(dream_net::error::NetcodeError) -> dream_net::NetcodeError = |e| e;
const _: fn() = || error_traits::<dream_net::NetcodeError>();
const _: fn() = || {
    fn plain<T: Send + Sync + Unpin + 'static>() {}
    plain::<dream_net::NetcodeError>();
};

/// Every variant `netcode-official` 1.0.0's error had, under the same name and payload.
fn netcode_error(error: &dream_net::NetcodeError) -> u8 {
    use dream_net::NetcodeError as E;
    match error {
        E::InvalidConnectToken => 0,
        E::EncryptFailed => 1,
        E::DecryptFailed => 2,
        E::InvalidPayloadSize(size) => {
            let _: usize = *size;
            3
        }
        E::InvalidServerAddresses => 4,
        E::InvalidMaxClients(n) => {
            let _: usize = *n;
            5
        }
        E::Io(error) => {
            let _: &std::io::Error = error;
            6
        }
        E::InvalidConnectTokenLifetime(n) => {
            let _: u32 = *n;
            7
        }
        _ => 8,
    }
}

// A maximum connect-token lifetime other than netcode's default.
const _: fn(ServerConfig, &Key, Schema, f64, u32) -> Result<Server, Error> =
    Server::with_max_token_lifetime;
const _: () = assert!(dream_net::DEFAULT_MAX_CONNECT_TOKEN_LIFETIME == 30);
const _: u32 = dream_net::server::DEFAULT_MAX_CONNECT_TOKEN_LIFETIME;

// ---------------------------------------------------------------- ServerConfig and Server

/// `ServerConfig` is an exhaustive struct with exactly these four fields: hosts build it as a
/// literal (l3i does), so a new field would break them.
fn server_config(address: SocketAddr) -> ServerConfig {
    let config = ServerConfig {
        public_address: address,
        protocol_id: 1,
        max_clients: 4,
        transport: TransportConfig::default(),
    };
    let ServerConfig {
        public_address,
        protocol_id,
        max_clients,
        transport,
    } = config.clone();
    let _: (SocketAddr, u64, usize, TransportConfig) =
        (public_address, protocol_id, max_clients, transport);
    let _: bool = config == config.clone();
    let _ = format!("{config:?}");
    config
}

const _: fn(ServerConfig, &Key, Schema, f64) -> Result<Server, Error> = Server::new;
const _: fn(&mut Server, Option<Box<dyn CaptureSink>>) = Server::set_capture;
const _: for<'a> fn(&'a Server) -> &'a Schema = Server::schema;
const _: fn(&Server) -> SocketAddr = Server::address;
const _: fn(&Server) -> usize = Server::max_clients;
const _: fn(&Server) -> usize = Server::num_connected;
const _: fn(&mut Server, f64) = Server::update;
const _: for<'a> fn(&'a mut Server) -> Option<ServerEvent<&'a [u8]>> = Server::poll;
const _: fn(&mut Server, &mut [u8]) -> Result<Option<ServerEvent<usize>>, BufferTooSmall> =
    Server::poll_into;
const _: fn(&mut Server, PeerId, EventTypeId, &[u8]) -> Result<(), SendError> = Server::send;
const _: fn(&mut Server, Option<PeerId>, EventTypeId, &[u8]) -> Result<usize, SendError> =
    Server::broadcast_except;
const _: fn(&mut Server, EventTypeId, &[u8]) -> Result<usize, SendError> = Server::broadcast;
const _: fn(&mut Server) = Server::flush;
const _: fn(&mut Server, PeerId) = Server::disconnect;
const _: fn(&mut Server) = Server::disconnect_all;
const _: fn(&Server, PeerId) -> Option<u64> = Server::client_id;
const _: fn(&Server, PeerId) -> Option<SocketAddr> = Server::client_address;
const _: for<'a> fn(&'a Server, PeerId) -> Option<&'a UserData> = Server::client_user_data;
const _: for<'a> fn(&'a Server, PeerId) -> Option<&'a [u8; USER_DATA_BYTES]> =
    Server::client_user_data;
const _: fn(&Server, PeerId) -> Option<ConnectionStats> = Server::stats;
const _: fn(&Server, PeerId) -> Option<Counters> = Server::counters;
const _: for<'a> fn(&'a Server, PeerId) -> Option<&'a Connection> = Server::peer_connection;
const _: fn(&Server) -> MemoryUsage = Server::memory_usage;

/// `peers` returns an iterator of handles borrowed from the server; `Server` is `Debug`
/// (hand-written, never the key).
fn server_uses(server: &Server) {
    let _: Vec<PeerId> = server.peers().collect();
    let _ = format!("{server:?}");
}

/// `ServerEvent` keeps exactly its four variants and their fields, generic over the payload,
/// with `Debug + Clone + Copy + PartialEq + Eq`.
fn server_event<P: Copy + PartialEq + Eq + std::fmt::Debug>(event: ServerEvent<P>) -> PeerId {
    let copy = event;
    let _: bool = copy == event.clone();
    let _ = format!("{event:?}");
    match event {
        ServerEvent::Connected { peer, client_id } => {
            let _: u64 = client_id;
            peer
        }
        ServerEvent::Disconnected { peer, reason } => {
            let _: DisconnectReason = reason;
            peer
        }
        ServerEvent::Rejected {
            peer,
            client_id,
            failure,
        } => {
            let _: (u64, Failure) = (client_id, failure);
            peer
        }
        ServerEvent::Message {
            peer,
            event,
            channel,
            payload,
        } => {
            let _: (EventTypeId, ChannelId, P) = (event, channel, payload);
            peer
        }
    }
}

// the module paths name the same items
const _: fn(dream_net::server::ServerConfig) -> ServerConfig = |c| c;
const _: fn(dream_net::server::ServerEvent<usize>) -> ServerEvent<usize> = |e| e;
const _: fn(dream_net::server::Server) -> Server = |s| s;
const _: fn(dream_net::error::Error) -> Error = |e| e;

// ---------------------------------------------------------------- ClientConfig and Client

/// `ClientConfig` is an exhaustive struct with exactly these two fields.
fn client_config(address: SocketAddr) -> ClientConfig {
    let config = ClientConfig {
        bind_address: address,
        transport: TransportConfig::default(),
    };
    let ClientConfig {
        bind_address,
        transport,
    } = config.clone();
    let _: (SocketAddr, TransportConfig) = (bind_address, transport);
    let _: bool = config == config.clone();
    let _ = format!("{config:?}");
    config
}

const _: fn(ClientConfig, Schema, f64) -> Result<Client, Error> = Client::new;
const _: fn(&mut Client, Option<Box<dyn CaptureSink>>) = Client::set_capture;
const _: for<'a> fn(&'a Client) -> &'a Schema = Client::schema;
const _: fn(&mut Client, &[u8; CONNECT_TOKEN_BYTES]) -> Result<(), Error> = Client::connect;
const _: fn(&mut Client, &[u8; 2048]) -> Result<(), Error> = Client::connect;
const _: fn(&mut Client) = Client::disconnect;
const _: fn(&Client) -> ClientStatus = Client::status;
const _: fn(&mut Client, f64) = Client::update;
const _: for<'a> fn(&'a mut Client) -> Option<ClientEvent<&'a [u8]>> = Client::poll;
const _: fn(&mut Client, &mut [u8]) -> Result<Option<ClientEvent<usize>>, BufferTooSmall> =
    Client::poll_into;
const _: fn(&mut Client, EventTypeId, &[u8]) -> Result<(), SendError> = Client::send;
const _: fn(&mut Client) = Client::flush;
const _: fn(&Client) -> Option<SocketAddr> = Client::server_address;
const _: fn(&Client) -> u16 = Client::port;
const _: fn(&Client) -> Option<ConnectionStats> = Client::stats;
const _: fn(&Client) -> Option<Counters> = Client::counters;
const _: fn(&Client) -> MemoryUsage = Client::memory_usage;

fn client_uses(client: &Client) {
    let _ = format!("{client:?}");
}

/// `ClientEvent` keeps exactly its four variants and their fields.
fn client_event<P: Copy + PartialEq + Eq + std::fmt::Debug>(event: ClientEvent<P>) -> u8 {
    let copy = event;
    let _: bool = copy == event.clone();
    let _ = format!("{event:?}");
    match event {
        ClientEvent::Connected => 0,
        ClientEvent::Disconnected { reason } => {
            let _: DisconnectReason = reason;
            1
        }
        ClientEvent::ConnectFailed { reason, failure } => {
            let _: (DisconnectReason, Option<Failure>) = (reason, failure);
            2
        }
        ClientEvent::Message {
            event,
            channel,
            payload,
        } => {
            let _: (EventTypeId, ChannelId, P) = (event, channel, payload);
            3
        }
    }
}

/// `ClientStatus` keeps exactly its four variants.
fn client_status(status: ClientStatus) -> u8 {
    let _: bool = status == status.clone();
    match status {
        ClientStatus::Disconnected => 0,
        ClientStatus::Connecting => 1,
        ClientStatus::Handshaking => 2,
        ClientStatus::Connected => 3,
    }
}

/// `DisconnectReason` keeps exactly its ten variants.
fn disconnect_reason(reason: DisconnectReason) -> u8 {
    match reason {
        DisconnectReason::Requested => 0,
        DisconnectReason::Remote => 1,
        DisconnectReason::TimedOut => 2,
        DisconnectReason::Denied => 3,
        DisconnectReason::Authentication => 4,
        DisconnectReason::ProtocolMismatch => 5,
        DisconnectReason::SchemaMismatch => 6,
        DisconnectReason::MalformedData => 7,
        DisconnectReason::HandshakeTimeout => 8,
        DisconnectReason::TransportError => 9,
    }
}

const _: fn(dream_net::client::ClientConfig) -> ClientConfig = |c| c;
const _: fn(dream_net::client::ClientEvent<usize>) -> ClientEvent<usize> = |e| e;
const _: fn(dream_net::client::ClientStatus) -> ClientStatus = |s| s;
const _: fn(dream_net::client::Client) -> Client = |c| c;

// ---------------------------------------------------------------- runtime: values and texts

#[test]
fn the_surface_is_reachable_and_its_values_hold() {
    let address: SocketAddr = "127.0.0.1:0".parse().unwrap();
    assert_eq!(server_config(address).max_clients, 4);
    assert_eq!(client_config(address).bind_address, address);
    let peer = PeerId::new(3, 9);
    assert_eq!(
        server_event(ServerEvent::<usize>::Disconnected {
            peer,
            reason: DisconnectReason::Remote
        }),
        peer
    );
    assert_eq!(client_event(ClientEvent::<usize>::Connected), 0);
    assert_eq!(client_status(ClientStatus::Handshaking), 2);
    assert_eq!(disconnect_reason(DisconnectReason::TransportError), 9);
    // fn items above are referenced so they are type-checked, not just declared
    let _: fn(&Server) = server_uses;
    let _: fn(&Client) = client_uses;

    let key: Key = dream_net::generate_key();
    assert_eq!(key.len(), KEY_BYTES);
    let user_data: UserData = [7; USER_DATA_BYTES];
    let token: [u8; CONNECT_TOKEN_BYTES] =
        dream_net::generate_connect_token(&[address], &[address], 30, 5, 1, 2, &key, &user_data)
            .unwrap();
    assert_eq!(token.len(), CONNECT_TOKEN_BYTES);
    // the version string netcode 1.03 tokens start with
    assert_eq!(&token[..13], b"NETCODE 1.03\0");

    // an empty address list is refused, and the error reaches `Error` through `?` with the
    // "netcode: " prefix l3i shows to scripts
    let refused =
        dream_net::generate_connect_token(&[], &[], 30, 5, 1, 2, &key, &user_data).unwrap_err();
    let error: Error = refused.into();
    assert!(matches!(error, Error::Netcode(_)));
    assert_eq!(
        error.to_string(),
        "netcode: number of server addresses is out of range [1,32] or public and internal \
         address lists differ in length"
    );
    assert!(std::error::Error::source(&error).is_some());
}

#[test]
fn server_and_client_creation_errors_keep_their_shape() {
    let schema = Schema::builder(1).build().unwrap();
    let key = dream_net::generate_key();
    let refused = Server::new(
        ServerConfig {
            public_address: "127.0.0.1:0".parse().unwrap(),
            protocol_id: 1,
            max_clients: 0,
            transport: TransportConfig::default(),
        },
        &key,
        schema.clone(),
        0.0,
    )
    .unwrap_err();
    assert!(matches!(refused, Error::Netcode(_)), "{refused:?}");
    assert_eq!(
        refused.to_string(),
        "netcode: max clients 0 is out of range [1,256]"
    );
    let refused = Server::new(
        ServerConfig {
            public_address: "127.0.0.1:0".parse().unwrap(),
            protocol_id: 1,
            max_clients: 257,
            transport: TransportConfig::default(),
        },
        &key,
        schema.clone(),
        0.0,
    )
    .unwrap_err();
    assert_eq!(
        refused.to_string(),
        "netcode: max clients 257 is out of range [1,256]"
    );

    let mut client = Client::new(
        ClientConfig {
            bind_address: "127.0.0.1:0".parse().unwrap(),
            transport: TransportConfig::default(),
        },
        schema,
        0.0,
    )
    .unwrap();
    let refused = client.connect(&[0; CONNECT_TOKEN_BYTES]).unwrap_err();
    assert!(matches!(refused, Error::Netcode(_)), "{refused:?}");
    assert_eq!(refused.to_string(), "netcode: invalid connect token");
    assert!(std::error::Error::source(&refused).is_some());
}

#[test]
fn the_additions_map_onto_the_same_error() {
    let schema = Schema::builder(1).build().unwrap();
    let key = dream_net::generate_key();
    let config = ServerConfig {
        public_address: "127.0.0.1:0".parse().unwrap(),
        protocol_id: 1,
        max_clients: 1,
        transport: TransportConfig::default(),
    };
    for lifetime in [0, u32::MAX] {
        let refused =
            Server::with_max_token_lifetime(config.clone(), &key, schema.clone(), 0.0, lifetime)
                .unwrap_err();
        let Error::Netcode(inner) = &refused else {
            panic!("{refused:?}")
        };
        assert_eq!(netcode_error(inner), 7);
        assert!(
            refused
                .to_string()
                .starts_with(&format!("netcode: max connect token lifetime {lifetime} ")),
            "{refused}"
        );
    }
    let server = Server::with_max_token_lifetime(config, &key, schema, 0.0, 1).unwrap();
    assert_ne!(server.address().port(), 0);
}
