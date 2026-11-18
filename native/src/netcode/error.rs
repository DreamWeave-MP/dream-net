//! The binding's error type: `netcode-official` 1.0.0's variants and `Display` texts.

use core::ffi::c_int;
use std::fmt;
use std::io;

use super::{MAX_CLIENTS, MAX_PAYLOAD_BYTES, MAX_SERVERS_PER_CONNECT};
use crate::sys::netcode as sys;

/// Everything that can go wrong in the netcode binding.
///
/// The variants and their `Display` texts are `netcode-official` 1.0.0's. Plain data:
/// `Send + Sync + 'static`. No variant carries a key, a token, or a C pointer.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// [`Client::connect`](super::Client::connect) was given a token netcode cannot read, or
    /// one that lists no server address of the family the client is bound to.
    InvalidConnectToken,
    /// [`generate_connect_token`](super::generate_connect_token) could not encrypt the token.
    EncryptFailed,
    /// Kept for `netcode-official` compatibility. The binding never returns it: undecryptable
    /// packets are dropped silently, as in both implementations.
    DecryptFailed,
    /// A payload of this many bytes was refused: payloads are `1..=MAX_PAYLOAD_BYTES`.
    InvalidPayloadSize(usize),
    /// A token's address lists were empty, longer than `MAX_SERVERS_PER_CONNECT`, or of
    /// different lengths.
    InvalidServerAddresses,
    /// A server was given a slot count outside `1..=MAX_CLIENTS`.
    InvalidMaxClients(usize),
    /// A socket could not be created or bound, an address was refused, or the native library
    /// could not be initialised.
    Io(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidConnectToken => write!(f, "invalid connect token"),
            Error::EncryptFailed => write!(f, "encryption failed"),
            Error::DecryptFailed => write!(f, "decryption failed"),
            Error::InvalidPayloadSize(size) => {
                write!(
                    f,
                    "payload size {size} is out of range [1,{MAX_PAYLOAD_BYTES}]"
                )
            }
            Error::InvalidServerAddresses => write!(
                f,
                "number of server addresses is out of range [1,{MAX_SERVERS_PER_CONNECT}] \
                 or public and internal address lists differ in length"
            ),
            Error::InvalidMaxClients(n) => {
                write!(f, "max clients {n} is out of range [1,{MAX_CLIENTS}]")
            }
            Error::Io(error) => write!(f, "socket error: {error}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::Io(error)
    }
}

/// The error for a failed `ensure_init`.
pub(crate) fn init_failed() -> Error {
    Error::Io(io::Error::other(
        "the native netcode library could not be initialised",
    ))
}

/// The OS error the shim saw right after a failed create, if it saw one.
fn os_error(code: c_int) -> Option<io::Error> {
    (code != 0).then(|| io::Error::from_raw_os_error(code))
}

/// An `Io` error saying `what`, with the OS error's kind and text when the shim saw one, else
/// `fallback`.
fn with_os(fallback: io::ErrorKind, what: &str, os: c_int) -> Error {
    match os_error(os) {
        Some(os) => {
            let kind = if os.kind() == io::ErrorKind::Other {
                fallback
            } else {
                os.kind()
            };
            Error::Io(io::Error::new(kind, format!("{what}: {os}")))
        }
        None => Error::Io(io::Error::new(fallback, what.to_owned())),
    }
}

/// Maps `netcode_client_create_error()` (read under the create lock, right after the failure)
/// and the OS error code to an [`Error`].
pub(crate) fn client_create(code: c_int, os: c_int) -> Error {
    match code {
        sys::CLIENT_CREATE_ERROR_PARSE_ADDRESS_FAILED => Error::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "netcode could not parse the client bind address",
        )),
        sys::CLIENT_CREATE_ERROR_CREATE_SOCKET_IPV4_FAILED => with_os(
            io::ErrorKind::Other,
            "netcode could not create or bind the client's IPv4 socket",
            os,
        ),
        sys::CLIENT_CREATE_ERROR_CREATE_SOCKET_IPV6_FAILED => with_os(
            io::ErrorKind::Other,
            "netcode could not create or bind the client's IPv6 socket",
            os,
        ),
        sys::CLIENT_CREATE_ERROR_ALLOCATE_CLIENT_FAILED => Error::Io(io::Error::new(
            io::ErrorKind::OutOfMemory,
            "netcode could not allocate the client",
        )),
        other => Error::Io(io::Error::other(format!(
            "netcode could not create the client (client create error {other})"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_are_plain_data_and_keep_the_port_texts() {
        fn plain<T: Send + Sync + 'static + std::error::Error>() {}
        plain::<Error>();
        assert_eq!(
            Error::InvalidPayloadSize(0).to_string(),
            "payload size 0 is out of range [1,1200]"
        );
        assert_eq!(
            Error::InvalidMaxClients(257).to_string(),
            "max clients 257 is out of range [1,256]"
        );
        assert_eq!(
            Error::InvalidConnectToken.to_string(),
            "invalid connect token"
        );
        assert_eq!(
            Error::InvalidServerAddresses.to_string(),
            "number of server addresses is out of range [1,32] or public and internal address \
             lists differ in length"
        );
    }

    #[test]
    fn create_errors_map_to_io_kinds() {
        let Error::Io(e) = client_create(sys::CLIENT_CREATE_ERROR_PARSE_ADDRESS_FAILED, 0) else {
            panic!()
        };
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput);
        let Error::Io(e) = client_create(sys::CLIENT_CREATE_ERROR_ALLOCATE_CLIENT_FAILED, 0) else {
            panic!()
        };
        assert_eq!(e.kind(), io::ErrorKind::OutOfMemory);
    }
}
