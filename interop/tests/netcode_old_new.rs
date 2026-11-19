//! The C netcode binding (`dream_net::native::netcode`, netcode 1.4.10) against the Rust port it
//! replaces (`netcode-official` 1.0.0) over loopback: each side's client with the other side's
//! server, tokens minted by either generator accepted by either server, payloads both ways.
//! The deliberate differences (campaign decision 12: single-use tokens, the start floor, a
//! server disconnect ending a multi-address session) are asserted as the new side's refusals,
//! next to the old side's acceptance.

// CI passes -W clippy::pedantic on the command line, overriding the manifest's lint table;
// test code casts freely between widths it controls, and the old client is simply large.
#![allow(
    clippy::cast_possible_truncation,
    clippy::large_enum_variant,
    clippy::too_many_lines
)]

use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dream_net::native::netcode as new;
use netcode_old as old;

const PROTOCOL: u64 = 0x0DDB_A11C_AFE0_0001;
const DT: f64 = 0.01;
const STEPS: usize = 3000;

fn localhost() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn user_data(id: u64) -> [u8; 256] {
    let mut data = [0u8; 256];
    data[..8].copy_from_slice(&id.to_le_bytes());
    data[200] = 0xEE;
    data
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Minter {
    Old,
    New,
}

fn mint(
    minter: Minter,
    addresses: &[SocketAddr],
    key: &[u8; 32],
    id: u64,
    expire: i32,
    timeout: i32,
) -> [u8; 2048] {
    match minter {
        Minter::Old => old::generate_connect_token(
            addresses,
            addresses,
            expire,
            timeout,
            id,
            PROTOCOL,
            key,
            &user_data(id),
        )
        .unwrap(),
        Minter::New => new::generate_connect_token(
            addresses,
            addresses,
            expire,
            timeout,
            id,
            PROTOCOL,
            key,
            &user_data(id),
        )
        .unwrap(),
    }
}

/// Either implementation's server, behind one interface.
enum AnyServer {
    Old(old::Server),
    New(new::Server),
}

impl AnyServer {
    fn start(kind: Minter, key: &[u8; 32], slots: usize) -> Self {
        match kind {
            Minter::Old => {
                let mut s = old::Server::new(localhost(), PROTOCOL, key, 0.0).unwrap();
                s.start(slots).unwrap();
                AnyServer::Old(s)
            }
            Minter::New => {
                let mut s = new::Server::new(localhost(), PROTOCOL, key, 0.0).unwrap();
                s.start(slots).unwrap();
                AnyServer::New(s)
            }
        }
    }

    fn address(&self) -> SocketAddr {
        match self {
            AnyServer::Old(s) => s.address(),
            AnyServer::New(s) => s.address(),
        }
    }

    fn update(&mut self, time: f64) {
        match self {
            AnyServer::Old(s) => s.update(time),
            AnyServer::New(s) => s.update(time),
        }
    }

    /// Connected slots reported by events since the last call (true = connected).
    fn events(&mut self) -> Vec<(usize, bool)> {
        let mut out = Vec::new();
        match self {
            AnyServer::Old(s) => {
                while let Some(e) = s.next_event() {
                    out.push(match e {
                        old::ServerEvent::ClientConnected { client_index } => (client_index, true),
                        old::ServerEvent::ClientDisconnected { client_index, .. } => {
                            (client_index, false)
                        }
                    });
                }
            }
            AnyServer::New(s) => {
                while let Some(e) = s.next_event() {
                    out.push(match e {
                        new::ServerEvent::ClientConnected { client_index } => (client_index, true),
                        new::ServerEvent::ClientDisconnected { client_index, .. } => {
                            (client_index, false)
                        }
                    });
                }
            }
        }
        out
    }

    fn identity(&self, slot: usize) -> (u64, Option<[u8; 256]>) {
        match self {
            AnyServer::Old(s) => (s.client_id(slot), s.client_user_data(slot).copied()),
            AnyServer::New(s) => (s.client_id(slot), s.client_user_data(slot).copied()),
        }
    }

    fn send(&mut self, slot: usize, payload: &[u8]) {
        match self {
            AnyServer::Old(s) => s.send_packet(slot, payload).unwrap(),
            AnyServer::New(s) => s.send_packet(slot, payload).unwrap(),
        }
    }

    fn receive(&mut self, slot: usize) -> Option<Vec<u8>> {
        match self {
            AnyServer::Old(s) => s.receive_packet(slot).map(|(p, _)| p),
            AnyServer::New(s) => s.receive_packet(slot).map(|(p, _)| p),
        }
    }

    fn disconnect(&mut self, slot: usize) {
        match self {
            AnyServer::Old(s) => s.disconnect_client(slot),
            AnyServer::New(s) => s.disconnect_client(slot),
        }
    }
}

/// Either implementation's client.
enum AnyClient {
    Old(old::Client),
    New(new::Client),
}

impl AnyClient {
    fn connect(kind: Minter, token: &[u8; 2048], time: f64) -> Self {
        match kind {
            Minter::Old => {
                let mut c = old::Client::new(localhost(), time).unwrap();
                c.connect(token).unwrap();
                AnyClient::Old(c)
            }
            Minter::New => {
                let mut c = new::Client::new(localhost(), time).unwrap();
                c.connect(token).unwrap();
                AnyClient::New(c)
            }
        }
    }

    fn update(&mut self, time: f64) {
        match self {
            AnyClient::Old(c) => c.update(time),
            AnyClient::New(c) => c.update(time),
        }
    }

    /// The state's `Display` text, which both implementations share.
    fn state(&self) -> String {
        match self {
            AnyClient::Old(c) => c.state().to_string(),
            AnyClient::New(c) => c.state().to_string(),
        }
    }

    fn connecting(&self) -> bool {
        match self {
            AnyClient::Old(c) => c.state().is_connecting(),
            AnyClient::New(c) => c.state().is_connecting(),
        }
    }

    fn send(&mut self, payload: &[u8]) {
        match self {
            AnyClient::Old(c) => c.send_packet(payload).unwrap(),
            AnyClient::New(c) => c.send_packet(payload).unwrap(),
        }
    }

    fn receive(&mut self) -> Option<Vec<u8>> {
        match self {
            AnyClient::Old(c) => c.receive_packet().map(|(p, _)| p),
            AnyClient::New(c) => c.receive_packet().map(|(p, _)| p),
        }
    }

    /// Disconnects and connects again with `token`; returns what `connect` refused, as text.
    fn reconnect(&mut self, token: &[u8; 2048]) -> Result<(), String> {
        match self {
            AnyClient::Old(c) => {
                c.disconnect();
                c.connect(token).map_err(|e| e.to_string())
            }
            AnyClient::New(c) => {
                c.disconnect();
                c.connect(token).map_err(|e| e.to_string())
            }
        }
    }
}

/// Steps both until the client leaves the connecting states; returns its state's text.
fn settle(server: &mut AnyServer, client: &mut AnyClient, time: &mut f64) -> String {
    for _ in 0..STEPS {
        *time += DT;
        client.update(*time);
        server.update(*time);
        if !client.connecting() {
            break;
        }
    }
    client.state()
}

fn exchange(server: &mut AnyServer, client: &mut AnyClient, slot: usize, time: &mut f64) {
    for (len, seed) in [(1usize, 3u8), (1200, 4), (77, 5)] {
        let up: Vec<u8> = (0..len).map(|i| (i as u8) ^ seed).collect();
        let down: Vec<u8> = (0..len).map(|i| (i as u8) ^ !seed).collect();
        client.send(&up);
        server.send(slot, &down);
        let (mut got_up, mut got_down) = (None, None);
        for _ in 0..100 {
            *time += DT;
            client.update(*time);
            server.update(*time);
            got_up = got_up.or_else(|| server.receive(slot));
            got_down = got_down.or_else(|| client.receive());
            if got_up.is_some() && got_down.is_some() {
                break;
            }
        }
        assert_eq!(got_up.as_deref(), Some(&up[..]));
        assert_eq!(got_down.as_deref(), Some(&down[..]));
    }
}

/// Every combination of server, client and token minter connects and exchanges payloads.
#[test]
fn every_mix_of_old_and_new_connects_and_carries_payloads() {
    for server_kind in [Minter::Old, Minter::New] {
        for client_kind in [Minter::Old, Minter::New] {
            for minter in [Minter::Old, Minter::New] {
                let what =
                    format!("server {server_kind:?}, client {client_kind:?}, token {minter:?}");
                let key = new::generate_key();
                let mut server = AnyServer::start(server_kind, &key, 4);
                let token = mint(minter, &[server.address()], &key, 4242, 3600, 5);
                let mut time = 0.0;
                let mut client = AnyClient::connect(client_kind, &token, time);
                assert_eq!(
                    settle(&mut server, &mut client, &mut time),
                    "connected",
                    "{what}"
                );
                // the server reports it once the keep-alive confirms
                for _ in 0..5 {
                    time += DT;
                    client.update(time);
                    server.update(time);
                }
                assert_eq!(server.events(), vec![(0, true)], "{what}");
                assert_eq!(server.identity(0), (4242, Some(user_data(4242))), "{what}");
                exchange(&mut server, &mut client, 0, &mut time);
            }
        }
    }
}

/// D1, S1: the old server lets a token connect again after a disconnect; the new one does not.
/// The new client refuses the used token itself, before sending anything, so the servers'
/// answers are shown with the old client, which keeps no record of used tokens.
#[test]
fn a_reused_token_is_refused_by_the_new_server_only() {
    for (server_kind, expected) in [
        (Minter::Old, "connected"),
        (Minter::New, "connection request timed out"),
    ] {
        for client_kind in [Minter::Old, Minter::New] {
            let key = new::generate_key();
            let mut server = AnyServer::start(server_kind, &key, 4);
            let token = mint(Minter::New, &[server.address()], &key, 9, 3600, 1);
            let mut time = 0.0;
            let mut client = AnyClient::connect(client_kind, &token, time);
            assert_eq!(settle(&mut server, &mut client, &mut time), "connected");
            let reconnected = client.reconnect(&token);
            if client_kind == Minter::New {
                assert_eq!(
                    reconnected,
                    Err(new::Error::InvalidConnectToken.to_string()),
                    "server {server_kind:?}"
                );
                assert_eq!(client.state(), "disconnected", "server {server_kind:?}");
                continue;
            }
            assert_eq!(reconnected, Ok(()));
            assert_eq!(
                settle(&mut server, &mut client, &mut time),
                expected,
                "server {server_kind:?}, client {client_kind:?}"
            );
        }
    }
}

fn second() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Waits until the current second is at least 60 ms old (C's `time(NULL)` can lag a few ms
/// behind `SystemTime` at a boundary) and has at least half a second left.
fn settled_second() -> u64 {
    loop {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        if (60_000_000..=500_000_000).contains(&nanos) {
            return second();
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// D2, S5: a 30-second token minted in the server's start second passes the old server and
/// hits the new server's start floor (default maximum lifetime 30 s).
#[test]
fn a_token_minted_in_the_start_second_is_refused_by_the_new_server_only() {
    for (server_kind, expected) in [
        (Minter::Old, "connected"),
        (Minter::New, "connection request timed out"),
    ] {
        for minter in [Minter::Old, Minter::New] {
            let mut done = false;
            for _ in 0..5 {
                let key = new::generate_key();
                let start = settled_second();
                let mut server = AnyServer::start(server_kind, &key, 4);
                let token = mint(minter, &[server.address()], &key, 1, 30, 1);
                if second() != start {
                    continue;
                }
                let mut time = 0.0;
                let mut client = AnyClient::connect(Minter::New, &token, time);
                assert_eq!(
                    settle(&mut server, &mut client, &mut time),
                    expected,
                    "server {server_kind:?}, token {minter:?}"
                );
                done = true;
                break;
            }
            assert!(done, "could not mint inside the start second");
        }
    }
}

/// D8, S4: with a two-address token, a server disconnect sends the old client to the next
/// address, and leaves the new client disconnected.
#[test]
fn a_server_disconnect_ends_a_multi_address_session_only_for_the_new_client() {
    for (client_kind, expected) in [
        (Minter::Old, "sending connection request"),
        (Minter::New, "disconnected"),
    ] {
        let key = new::generate_key();
        let mut server = AnyServer::start(Minter::New, &key, 4);
        let spare = std::net::UdpSocket::bind(localhost()).unwrap();
        let token = mint(
            Minter::New,
            &[server.address(), spare.local_addr().unwrap()],
            &key,
            5,
            3600,
            5,
        );
        let mut time = 0.0;
        let mut client = AnyClient::connect(client_kind, &token, time);
        assert_eq!(settle(&mut server, &mut client, &mut time), "connected");
        server.disconnect(0);
        let mut state = client.state();
        for _ in 0..20 {
            time += DT;
            client.update(time);
            server.update(time);
            state = client.state();
            if state != "connected" {
                break;
            }
        }
        assert_eq!(state, expected, "client {client_kind:?}");
    }
}
