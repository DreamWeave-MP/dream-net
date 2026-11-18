//! `SocketAddr` to netcode's address strings, and the shim's flat address back to `SocketAddr`.

use core::ffi::c_char;
use std::io::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::sys::netcode as sys;

/// Room for the longest form, `[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535` (47 bytes),
/// plus the NUL. netcode copies at most `NETCODE_MAX_ADDRESS_STRING_LENGTH - 1` (255) bytes.
const CAPACITY: usize = 64;

/// A `SocketAddr` as the NUL-terminated string netcode parses: `a.b.c.d:port` or `[v6]:port`.
///
/// Only the IP and port are written. An IPv6 scope id and flow label cannot be represented in
/// netcode's address type or on its wire; callers decide whether to refuse or ignore them.
pub(crate) struct CAddress {
    bytes: [u8; CAPACITY],
}

impl CAddress {
    pub(crate) fn new(address: SocketAddr) -> Self {
        let mut bytes = [0u8; CAPACITY];
        let mut cursor: &mut [u8] = &mut bytes[..CAPACITY - 1];
        // Cannot fail: the longest form is 47 bytes and the cursor holds 63.
        let written = match address.ip() {
            IpAddr::V4(ip) => write!(cursor, "{ip}:{}", address.port()),
            IpAddr::V6(ip) => write!(cursor, "[{ip}]:{}", address.port()),
        };
        debug_assert!(written.is_ok());
        // The last byte is never part of the cursor, so the string is always terminated.
        Self { bytes }
    }

    /// A pointer to the NUL-terminated string, valid as long as `self`.
    pub(crate) fn as_ptr(&self) -> *const c_char {
        self.bytes.as_ptr().cast()
    }
}

/// The shim's flat address as a `SocketAddr`; `None` for netcode's "no address".
pub(crate) fn from_flat(address: &sys::Address) -> Option<SocketAddr> {
    match address.family {
        sys::ADDRESS_IPV4 => {
            let [a, b, c, d, ..] = address.bytes;
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(a, b, c, d)),
                address.port,
            ))
        }
        sys::ADDRESS_IPV6 => Some(SocketAddr::new(
            IpAddr::V6(Ipv6Addr::from(address.bytes)),
            address.port,
        )),
        // 0: netcode's "no address"
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;
    use std::net::SocketAddrV6;

    fn text(address: SocketAddr) -> String {
        let c = CAddress::new(address);
        // SAFETY: `as_ptr` points at a NUL-terminated buffer that lives as long as `c`.
        unsafe { CStr::from_ptr(c.as_ptr()) }
            .to_str()
            .unwrap()
            .to_owned()
    }

    #[test]
    fn addresses_format_as_netcode_parses_them() {
        assert_eq!(text("127.0.0.1:0".parse().unwrap()), "127.0.0.1:0");
        assert_eq!(text("[::1]:40000".parse().unwrap()), "[::1]:40000");
        assert_eq!(
            text(
                "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535"
                    .parse()
                    .unwrap()
            ),
            "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535"
        );
        // the scope id and flow label are not written
        let scoped = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 7, 9, 3));
        assert_eq!(text(scoped), "[::1]:7");
        assert_eq!(
            text("[::ffff:1.2.3.4]:5".parse().unwrap()),
            "[::ffff:1.2.3.4]:5"
        );
    }

    #[test]
    fn flat_addresses_convert_back() {
        let mut flat = sys::Address::default();
        assert_eq!(from_flat(&flat), None);
        flat.family = sys::ADDRESS_IPV4;
        flat.port = 1234;
        flat.bytes[..4].copy_from_slice(&[10, 0, 0, 7]);
        assert_eq!(from_flat(&flat), Some("10.0.0.7:1234".parse().unwrap()));
        flat.family = sys::ADDRESS_IPV6;
        flat.bytes = Ipv6Addr::LOCALHOST.octets();
        assert_eq!(from_flat(&flat), Some("[::1]:1234".parse().unwrap()));
        flat.family = 9;
        assert_eq!(from_flat(&flat), None);
    }
}
