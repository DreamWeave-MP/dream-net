//! The error texts a host or script can see, dream-net 1.1.1 against this tree, for every
//! `Error` path of `Server::new`, `Client::new`, `Client::connect` and
//! `generate_connect_token`, and the transport limits `TransportConfig::validate` tightened.
//! l3i formats every one of these through `Display` into a Luau error (`dream.udp: <text>`),
//! so a changed text is a change a script that matches on error strings would see. Each pair
//! is asserted exactly: the unchanged ones stay unchanged, and the changed ones are listed in
//! `docs/maintenance/NATIVE_TRANSPORT_L3I.md`.

// CI passes -W clippy::pedantic on the command line, overriding the manifest's lint table.
#![allow(clippy::too_many_lines)]

use std::net::{SocketAddr, UdpSocket};

macro_rules! errors {
    ($side:ident, $dn:ident) => {
        mod $side {
            use std::net::SocketAddr;

            pub fn schema() -> $dn::Schema {
                let mut b = $dn::Schema::builder(1);
                let c = b
                    .channel($dn::ChannelConfig::reliable_ordered("reliable"))
                    .unwrap();
                b.event("Chat", c, 16).unwrap();
                b.build().unwrap()
            }

            pub fn server(address: SocketAddr, max_clients: usize) -> String {
                $dn::Server::new(
                    $dn::ServerConfig {
                        public_address: address,
                        protocol_id: 1,
                        max_clients,
                        transport: $dn::TransportConfig::default(),
                    },
                    &[7; 32],
                    schema(),
                    0.0,
                )
                .err()
                .map_or_else(|| "Ok".to_owned(), |e| e.to_string())
            }

            pub fn client(bind: SocketAddr) -> String {
                $dn::Client::new(
                    $dn::ClientConfig {
                        bind_address: bind,
                        transport: $dn::TransportConfig::default(),
                    },
                    schema(),
                    0.0,
                )
                .err()
                .map_or_else(|| "Ok".to_owned(), |e| e.to_string())
            }

            /// `connect` with `token`: the error text and the client's first record.
            pub fn connect(bind: SocketAddr, token: &[u8; 2048]) -> (String, String) {
                let mut client = $dn::Client::new(
                    $dn::ClientConfig {
                        bind_address: bind,
                        transport: $dn::TransportConfig::default(),
                    },
                    schema(),
                    0.0,
                )
                .unwrap();
                let error = client
                    .connect(token)
                    .err()
                    .map_or_else(|| "Ok".to_owned(), |e| e.to_string());
                client.update(0.1);
                let record = client.poll().map(|e| match e {
                    $dn::ClientEvent::ConnectFailed { reason, .. } => {
                        format!("ConnectFailed({})", reason.name())
                    }
                    other => format!("{other:?}"),
                });
                (error, record.unwrap_or_else(|| "None".to_owned()))
            }

            pub fn token(addresses: &[SocketAddr], expire: i32, timeout: i32) -> String {
                $dn::generate_connect_token(
                    addresses, addresses, expire, timeout, 1, 1, &[7; 32], &[0; 256],
                )
                .err()
                .map_or_else(|| "Ok".to_owned(), |e| e.to_string())
            }

            pub fn mint(addresses: &[SocketAddr]) -> [u8; 2048] {
                $dn::generate_connect_token(addresses, addresses, 30, 5, 1, 1, &[7; 32], &[0; 256])
                    .unwrap()
            }

            /// `TransportConfig::validate` with one field changed.
            pub fn validate(field: &str, value: usize) -> String {
                let mut config = $dn::TransportConfig::default();
                match field {
                    "sent" => config.sent_packets_buffer_size = value,
                    "received" => config.received_packets_buffer_size = value,
                    "reassembly" => config.fragment_reassembly_buffer_size = value,
                    _ => unreachable!(),
                }
                config
                    .validate()
                    .err()
                    .map_or_else(|| "Ok".to_owned(), |e| e.to_string())
            }
        }
    };
}

errors!(old, dream_net_old);
errors!(new, dream_net);

fn v4() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

/// (what, 1.1.1's text, this tree's text)
fn texts() -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    let mut add = |what: &str, old: String, new: String| out.push((what.to_owned(), old, new));

    let taken = UdpSocket::bind("0.0.0.0:0").unwrap();
    let port = taken.local_addr().unwrap().port();
    let busy: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    add(
        "Server::new on a port in use",
        old::server(busy, 4),
        new::server(busy, 4),
    );
    add(
        "Server::new with max_clients 0",
        old::server(v4(), 0),
        new::server(v4(), 0),
    );
    add(
        "Server::new with max_clients 257",
        old::server(v4(), 257),
        new::server(v4(), 257),
    );
    let client_taken = UdpSocket::bind("127.0.0.1:0").unwrap();
    let busy_client = client_taken.local_addr().unwrap();
    add(
        "Client::new on an address in use",
        old::client(busy_client),
        new::client(busy_client),
    );
    let unbindable: SocketAddr = "192.0.2.1:0".parse().unwrap();
    add(
        "Client::new on an address not on this host",
        old::client(unbindable),
        new::client(unbindable),
    );
    let zeros = [0u8; 2048];
    let (o, n) = (old::connect(v4(), &zeros), new::connect(v4(), &zeros));
    add("Client::connect with a zeroed token", o.0, n.0);
    add("  then the client's first record", o.1, n.1);
    let v6_server: SocketAddr = "[::1]:40000".parse().unwrap();
    let (o, n) = (
        old::connect(v4(), &old::mint(&[v6_server])),
        new::connect(v4(), &new::mint(&[v6_server])),
    );
    add(
        "Client::connect (IPv4 client) with a token naming only an IPv6 server",
        o.0,
        n.0,
    );
    add("  then the client's first record", o.1, n.1);
    add(
        "generate_connect_token with no address",
        old::token(&[], 30, 5),
        new::token(&[], 30, 5),
    );
    let many: Vec<SocketAddr> = (0..33)
        .map(|i| format!("127.0.0.1:{}", 1000 + i).parse().unwrap())
        .collect();
    add(
        "generate_connect_token with 33 addresses",
        old::token(&many, 30, 5),
        new::token(&many, 30, 5),
    );
    add(
        "generate_connect_token that never expires",
        old::token(&[busy], -1, 5),
        new::token(&[busy], -1, 5),
    );
    for (field, value) in [
        ("sent", 32768),
        ("received", 32768),
        ("reassembly", 32768),
        ("reassembly", 16385),
    ] {
        add(
            &format!("TransportConfig::validate with {field} buffer size {value}"),
            old::validate(field, value),
            new::validate(field, value),
        );
    }
    drop((taken, client_taken));
    out
}

#[test]
fn error_texts_old_and_new() {
    let texts = texts();
    for (what, old, new) in &texts {
        println!("{what}\n    1.1.1: {old}\n    new:   {new}");
    }
    let expected: Vec<(&str, &str, &str)> = EXPECTED.to_vec();
    let found: Vec<(&str, &str, &str)> = texts
        .iter()
        .map(|(w, o, n)| (w.as_str(), o.as_str(), n.as_str()))
        .collect();
    assert_eq!(found, expected);
}

/// (what, 1.1.1, this tree) on Linux: the OS error texts in parentheses are the platform's.
/// Changed: every socket error gains netcode's description of the failed step (the `io::Error`
/// kind is unchanged); a client refuses at `connect` a token that names no server of its
/// address family (1.1.1 accepted it and then never connected); and the three buffer sizes
/// above 16384 are refused.
const EXPECTED: [(&str, &str, &str); 16] = [
    (
        "Server::new on a port in use",
        "netcode: socket error: Address already in use (os error 98)",
        "netcode: socket error: netcode could not bind the server's IPv4 socket: Address already in use (os error 98)",
    ),
    (
        "Server::new with max_clients 0",
        "netcode: max clients 0 is out of range [1,256]",
        "netcode: max clients 0 is out of range [1,256]",
    ),
    (
        "Server::new with max_clients 257",
        "netcode: max clients 257 is out of range [1,256]",
        "netcode: max clients 257 is out of range [1,256]",
    ),
    (
        "Client::new on an address in use",
        "netcode: socket error: Address already in use (os error 98)",
        "netcode: socket error: netcode could not create or bind the client's IPv4 socket: Address already in use (os error 98)",
    ),
    (
        "Client::new on an address not on this host",
        "netcode: socket error: Cannot assign requested address (os error 99)",
        "netcode: socket error: netcode could not create or bind the client's IPv4 socket: Cannot assign requested address (os error 99)",
    ),
    (
        "Client::connect with a zeroed token",
        "netcode: invalid connect token",
        "netcode: invalid connect token",
    ),
    (
        "  then the client's first record",
        "ConnectFailed(authentication)",
        "ConnectFailed(authentication)",
    ),
    (
        "Client::connect (IPv4 client) with a token naming only an IPv6 server",
        "Ok",
        "netcode: invalid connect token",
    ),
    (
        "  then the client's first record",
        "None",
        "ConnectFailed(authentication)",
    ),
    (
        "generate_connect_token with no address",
        "number of server addresses is out of range [1,32] or public and internal address lists differ in length",
        "number of server addresses is out of range [1,32] or public and internal address lists differ in length",
    ),
    (
        "generate_connect_token with 33 addresses",
        "number of server addresses is out of range [1,32] or public and internal address lists differ in length",
        "number of server addresses is out of range [1,32] or public and internal address lists differ in length",
    ),
    ("generate_connect_token that never expires", "Ok", "Ok"),
    (
        "TransportConfig::validate with sent buffer size 32768",
        "Ok",
        "invalid transport configuration: sent_packets_buffer_size must be a power of two <= 16384",
    ),
    (
        "TransportConfig::validate with received buffer size 32768",
        "Ok",
        "invalid transport configuration: received_packets_buffer_size must be a power of two <= 16384",
    ),
    (
        "TransportConfig::validate with reassembly buffer size 32768",
        "Ok",
        "invalid transport configuration: fragment_reassembly_buffer_size must be in [1, 16384]",
    ),
    (
        "TransportConfig::validate with reassembly buffer size 16385",
        "Ok",
        "invalid transport configuration: fragment_reassembly_buffer_size must be in [1, 16384]",
    ),
];
