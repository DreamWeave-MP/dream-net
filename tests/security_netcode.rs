//! Security regressions of issue #12 for the secure transport, over real sockets on localhost:
//! AEAD nonce uniqueness measured at the byte level, the residuals the start floor leaves,
//! multi-address tokens, refused token replays, the handshake's amplification factor, and what
//! the pre-authentication state costs. `tests/lifecycle_security.rs` holds the S1 to S5
//! regressions these build on; `docs/maintenance/NATIVE_TRANSPORT_SECURITY.md` indexes both.
//!
//! netcode frames every encrypted packet as a prefix byte (type in the low nibble, sequence
//! length in the high one), the little-endian sequence, then ciphertext and tag. The AEAD
//! nonce is the sequence. Under NETCODE 1.03 the key is derived for each connection attempt
//! from the token's key, the client salt the attempt drew (the last 8 bytes of its connection
//! request) and the nonce the server drew for it (8 cleartext bytes after the sequence of a
//! challenge or denial), so two attempts share keys only if they share both. The ledger below
//! records every encrypted datagram the relay sees by token, direction and sequence, which is
//! stricter than the protocol needs: it counts a sequence used twice under one token as a
//! repeat even when the keys differ, and the tests that expect sequences to repeat check the
//! salts and nonces as well.

// CI passes -W clippy::pedantic on the command line, overriding the manifest's lint table;
// test code casts freely between widths it controls.
#![allow(
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]

mod common;
mod lifecycle;

use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use common::{REQUEST_TOKEN_BYTES, connection_request, fresh_salt};
use dream_net::native::netcode;
use dream_net::{ClientEvent, ClientStatus, DisconnectReason};
use lifecycle::{
    DEADLINE, Net, PROTOCOL, Token, chat, localhost, packet_type, unix_second, user_data,
    wait_past_second,
};

/// The sequence of a session-encrypted datagram; `None` for a connection request, the one
/// packet netcode sends without a session key.
fn sequence_of(datagram: &[u8]) -> Option<u64> {
    if packet_type(datagram) == 0 {
        return None;
    }
    let bytes = usize::from(datagram[0] >> 4);
    assert!((1..=8).contains(&bytes) && datagram.len() > bytes);
    let mut sequence = 0u64;
    for (i, b) in datagram[1..=bytes].iter().enumerate() {
        sequence |= u64::from(*b) << (8 * i);
    }
    Some(sequence)
}

/// Every session-encrypted datagram seen, by (token, direction, sequence).
#[derive(Default)]
struct Ledger {
    by_nonce: HashMap<(u64, bool, u64), Vec<Vec<u8>>>,
}

impl Ledger {
    /// Records what the relay saw since `marks` under `token`'s keys, returning the new marks.
    fn record(&mut self, net: &Net, token: u64, marks: (usize, usize)) -> (usize, usize) {
        let relay = net.relay.as_ref().unwrap();
        for (to_client, datagrams) in [
            (true, &relay.to_client[marks.0..]),
            (false, &relay.to_server[marks.1..]),
        ] {
            for datagram in datagrams {
                if let Some(sequence) = sequence_of(datagram) {
                    self.by_nonce
                        .entry((token, to_client, sequence))
                        .or_default()
                        .push(datagram.clone());
                }
            }
        }
        (relay.to_client.len(), relay.to_server.len())
    }

    /// Every (token, direction, sequence) used for more than one datagram.
    fn reused(&self) -> Vec<(u64, bool, u64)> {
        let mut reused: Vec<_> = self
            .by_nonce
            .iter()
            .filter(|(_, datagrams)| datagrams.len() > 1)
            .map(|(key, _)| *key)
            .collect();
        reused.sort_unstable();
        reused
    }

    fn encrypted(&self) -> usize {
        self.by_nonce.values().map(Vec::len).sum()
    }
}

fn marks(net: &Net) -> (usize, usize) {
    let relay = net.relay.as_ref().unwrap();
    (relay.to_client.len(), relay.to_server.len())
}

/// A client connects with `token` through the relay and events go both ways, so the session
/// has payloads and keep-alives in both directions. Returns the client.
fn session(net: &mut Net, token: &Token) -> usize {
    let c = net.add_client(token);
    let before = net.connected_peers().len();
    assert!(
        net.run_until(|n| n.connected_peers().len() > before
            && n.clients[c].status() == ClientStatus::Connected),
        "{:?}",
        net.client_events[c]
    );
    let peer = *net.connected_peers().last().unwrap();
    net.clients[c].send(chat(), b"up").unwrap();
    net.server.send(peer, chat(), b"down").unwrap();
    assert!(net.run_until(|n| !n.messages_from(peer).is_empty() && n.client_got(c, b"down")));
    net.run_for(0.3);
    c
}

/// A token used before is refused by the server when a new client presents it again.
fn refused_again(net: &mut Net, token: &Token) {
    net.assert_refused(None, token);
}

/// The client salts of the connection requests and the server nonces of the challenges and
/// denials the relay saw since `marks`: what the attempts in that span derived their packet
/// keys from.
fn key_inputs(net: &Net, marks: (usize, usize)) -> (HashSet<Vec<u8>>, HashSet<Vec<u8>>) {
    let relay = net.relay.as_ref().unwrap();
    let salts = relay.to_server[marks.1..]
        .iter()
        .filter(|d| packet_type(d) == 0)
        .map(|d| d[REQUEST_TOKEN_BYTES..].to_vec())
        .collect();
    let nonces = relay.to_client[marks.0..]
        .iter()
        .filter(|d| matches!(packet_type(d), 1 | 2))
        .map(|d| {
            let at = 1 + usize::from(d[0] >> 4);
            d[at..at + 8].to_vec()
        })
        .collect();
    (salts, nonces)
}

/// A client tries `token` and fails: the server never answers it.
fn refused(net: &mut Net, token: &Token) {
    let c = net.add_client(token);
    assert!(net.run_until(|n| n.ended(c).is_some()));
    assert_eq!(
        net.ended(c),
        Some(ClientEvent::ConnectFailed {
            reason: DisconnectReason::TimedOut,
            failure: None
        })
    );
}

/// No (key, nonce) pair encrypts two datagrams, and no ciphertext recurs, across everything one
/// token can be put through with a server that keeps its key: a session with events both ways
/// and a clean disconnect, a second attempt with the used token, a restart of the server on the
/// same key and address, the used token and a token minted before the restart presented to the
/// restarted server, and a fresh session afterwards. The tokens live exactly the server's
/// maximum (30 s), the longest lifetime the start floor protects.
#[test]
fn aead_nonces_never_repeat_across_sessions_attempts_and_restarts() {
    let mut net = Net::new(2).with_relay();
    wait_past_second(net.server_started);
    let mut ledger = Ledger::default();
    let mut at = marks(&net);

    let used = net.token_with(1, 30, 1, true);
    let c = session(&mut net, &used);
    net.clients[c].disconnect();
    assert!(net.run_until(|n| n.server.num_connected() == 0));
    net.run_for(0.2);
    at = ledger.record(&net, 1, at);

    refused_again(&mut net, &used);
    at = ledger.record(&net, 1, at);

    let unused = net.token_with(2, 30, 1, true);
    net.restart();
    refused_again(&mut net, &used);
    at = ledger.record(&net, 1, at);
    refused(&mut net, &unused);
    at = ledger.record(&net, 2, at);

    wait_past_second(net.server_started);
    let fresh = net.token_with(3, 30, 1, true);
    session(&mut net, &fresh);
    ledger.record(&net, 3, at);

    assert!(ledger.encrypted() > 20, "too little traffic to judge");
    assert_eq!(
        ledger.reused(),
        vec![],
        "a (key, nonce) pair was used twice"
    );
    let relay = net.relay.as_ref().unwrap();
    let mut seen = HashSet::new();
    for datagram in relay.to_client.iter().chain(&relay.to_server) {
        if sequence_of(datagram).is_some() {
            assert!(seen.insert(datagram.clone()), "a ciphertext recurred");
        }
    }
}

/// The documented residual of the start floor (audit S2; `Server` docs, "Connect tokens"): a
/// token that lives `L` seconds, longer than the server's maximum `M`, passes the floor of a
/// restart that happens less than `L - M` seconds after it was minted, and one that never
/// expires passes every floor. A server restarted on the same key then admits it again after
/// it was used, a replayed session, which is why the guidance is to keep tokens within the
/// maximum or use a fresh key per start (pinned here with l3i's default lifetime of 300
/// seconds against the default maximum of 30). Both sessions count their sequences from 0.
/// Under NETCODE 1.02 that made the second session repeat the first one's (key, nonce) pairs
/// (GHSA-8mrq-q9c6-h23v and its restart form); under 1.03 the second session draws a new
/// client salt and gets a new server nonce, so its keys are fresh.
#[test]
fn tokens_beyond_the_maximum_lifetime_survive_a_restart_under_fresh_keys() {
    for (client_id, lifetime) in [(1u64, 300i32), (2, -1)] {
        let mut net = Net::new(2).with_relay();
        let mut ledger = Ledger::default();
        let start = marks(&net);
        // minted in the start second: only a lifetime above the maximum is accepted then
        let token = net.token_with(client_id, lifetime, 5, true);
        let c = session(&mut net, &token);
        net.clients[c].disconnect();
        assert!(net.run_until(|n| n.server.num_connected() == 0));
        net.run_for(0.2);
        let first = key_inputs(&net, start);
        let at = ledger.record(&net, client_id, start);

        net.restart();
        // the restarted server admits the used token again
        let c = session(&mut net, &token);
        net.clients[c].disconnect();
        net.run_for(0.2);
        let second = key_inputs(&net, at);
        ledger.record(&net, client_id, at);

        let reused = ledger.reused();
        assert!(
            reused.iter().any(|(_, to_client, s)| *to_client && *s < 4)
                && reused.iter().any(|(_, to_client, _)| !*to_client),
            "lifetime {lifetime}: expected the second session to count both directions' \
             sequences from 0 again, saw {reused:?}"
        );
        for (what, a, b) in [
            ("client salt", &first.0, &second.0),
            ("server nonce", &first.1, &second.1),
        ] {
            assert!(
                !a.is_empty() && !b.is_empty(),
                "lifetime {lifetime}: no {what} seen"
            );
            assert!(
                a.is_disjoint(b),
                "lifetime {lifetime}: the second session reused a {what} of the first"
            );
        }
    }
}

fn pump(clients: &mut [netcode::Client], servers: &mut [&mut netcode::Server], time: f64) {
    for server in servers.iter_mut() {
        server.update(time);
        while server.next_event().is_some() {}
    }
    for client in clients.iter_mut() {
        client.update(time);
    }
}

/// Audit S2, related HYPOTHESIS, CONFIRMED against C 1.4.10 and still so on 1.5.0: single use
/// is per server. Two servers that share a private key each keep their own token history, so
/// one token that lists both opens one session on each. Under NETCODE 1.02 both sessions ran
/// under the token's keys from sequence 0; under 1.03 the client draws a new salt when it moves
/// to the next server and each server draws its own nonce, so the keys differ (GHSA-8mrq-q9c6-h23v;
/// upstream pins it in its nonce-audit tests). (dream-net and l3i mint single-address tokens by
/// default; this is reachable only by listing several addresses in `generate_connect_token`.)
#[test]
fn a_multi_address_token_opens_one_session_per_listed_server() {
    let key = netcode::generate_key();
    let mut first = netcode::Server::new(localhost(), PROTOCOL, &key, 0.0).unwrap();
    let mut second = netcode::Server::new(localhost(), PROTOCOL, &key, 0.0).unwrap();
    first.start(4).unwrap();
    second.start(4).unwrap();
    wait_past_second(unix_second());
    let addresses = [first.address(), second.address()];
    let token = netcode::generate_connect_token(
        &addresses,
        &addresses,
        30,
        1,
        7,
        PROTOCOL,
        &key,
        &user_data(7),
    )
    .unwrap();

    let mut clients = vec![
        netcode::Client::new(localhost(), 0.0).unwrap(),
        netcode::Client::new(localhost(), 0.0).unwrap(),
    ];
    clients[0].connect(&token).unwrap();
    let started = Instant::now();
    let time = |s: Instant| s.elapsed().as_secs_f64();
    while clients[0].state() != netcode::ClientState::Connected {
        assert!(started.elapsed() < DEADLINE);
        pump(&mut clients, &mut [&mut first, &mut second], time(started));
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(clients[0].server_address(), Some(first.address()));

    // the same token on a second client: the first server ignores it (used), the client times
    // out there after the token's 1-second timeout and moves on to the second server, which
    // admits it
    clients[1].connect(&token).unwrap();
    while clients[1].state().is_connecting() {
        assert!(started.elapsed() < DEADLINE + DEADLINE);
        pump(&mut clients, &mut [&mut first, &mut second], time(started));
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(clients[1].state(), netcode::ClientState::Connected);
    assert_eq!(clients[1].server_address(), Some(second.address()));
    let mut both_held = false;
    let until = Instant::now() + Duration::from_millis(300);
    while Instant::now() < until {
        pump(&mut clients, &mut [&mut first, &mut second], time(started));
        both_held |= first.num_connected_clients() == 1
            && second.num_connected_clients() == 1
            && first.client_id(0) == 7
            && second.client_id(0) == 7;
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(both_held, "the two sessions were never up at once");
}

/// The public part of a connect token, as netcode writes it.
const VERSION: std::ops::Range<usize> = 0..13;
const PROTOCOL_ID: std::ops::Range<usize> = 13..21;
const EXPIRE: std::ops::Range<usize> = 29..37;
const NONCE: std::ops::Range<usize> = 37..61;
const PRIVATE: std::ops::Range<usize> = 61..1085;
/// With exactly one IPv4 address: the type byte, four address bytes and the port follow the
/// timeout and the address count, then the two session keys.
const CLIENT_TO_SERVER_KEY: std::ops::Range<usize> = 1100..1132;
const SERVER_TO_CLIENT_KEY: std::ops::Range<usize> = 1132..1164;

/// The connection request a client sends for `token` in an attempt that drew a fresh client
/// salt: everything the server sees of it.
fn request_for(token: &Token) -> Vec<u8> {
    let request = connection_request(token, fresh_salt());
    assert_eq!(request[1..14], token[VERSION]);
    assert_eq!(request[14..22], token[PROTOCOL_ID]);
    assert_eq!(request[22..30], token[EXPIRE]);
    assert_eq!(request[30..54], token[NONCE]);
    assert_eq!(request[54..1078], token[PRIVATE]);
    request
}

fn token_for(server: &netcode::Server, key: &netcode::Key, client_id: u64) -> Token {
    netcode::generate_connect_token(
        &[server.address()],
        &[server.address()],
        30,
        1,
        client_id,
        PROTOCOL,
        key,
        &user_data(client_id),
    )
    .unwrap()
}

/// Runs `clients` against `server` until each has left the connecting states, and returns
/// whether any connected.
fn any_connects(server: &mut netcode::Server, clients: &mut [netcode::Client]) -> bool {
    let started = Instant::now();
    loop {
        let time = started.elapsed().as_secs_f64();
        server.update(time);
        while server.next_event().is_some() {}
        for client in clients.iter_mut() {
            client.update(time);
        }
        if clients
            .iter()
            .any(|c| c.state() == netcode::ClientState::Connected)
        {
            return true;
        }
        if clients.iter().all(|c| !c.state().is_connecting()) {
            return false;
        }
        assert!(started.elapsed() < DEADLINE);
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// A token is refused by a server it does not name, even one with the same key and protocol,
/// and refused by the server it names when any field the server authenticates was altered in
/// its public part: version, protocol id, expire timestamp, nonce, the encrypted private part
/// and its tag, or either session key. (The create timestamp, timeout and address list are read
/// by the client only; the server takes its own copies from the encrypted part.)
#[test]
fn a_token_is_refused_elsewhere_and_with_any_authenticated_field_altered() {
    let key = netcode::generate_key();
    let mut named = netcode::Server::new(localhost(), PROTOCOL, &key, 0.0).unwrap();
    let mut other = netcode::Server::new(localhost(), PROTOCOL, &key, 0.0).unwrap();
    named.start(16).unwrap();
    other.start(16).unwrap();
    wait_past_second(unix_second());

    // the other server, same key and protocol, is not in the token's list
    let token = token_for(&named, &key, 1);
    let mut client = netcode::Client::new(localhost(), 0.0).unwrap();
    let mut patched = token;
    // the address bytes and port follow the type byte at 1093
    patched[1094..1100].copy_from_slice(&{
        let SocketAddr::V4(other_address) = other.address() else {
            unreachable!()
        };
        let mut bytes = [0u8; 6];
        bytes[..4].copy_from_slice(&other_address.ip().octets());
        bytes[4..].copy_from_slice(&other_address.port().to_le_bytes());
        bytes
    });
    client.connect(&patched).unwrap();
    assert!(!any_connects(&mut other, std::slice::from_mut(&mut client)));
    assert_eq!(other.num_connected_clients(), 0);

    let fields = [
        ("version", VERSION.start + 8),
        ("protocol id", PROTOCOL_ID.start),
        ("expire timestamp", EXPIRE.start),
        ("nonce", NONCE.start + 3),
        ("private part", PRIVATE.start + 100),
        ("private tag", PRIVATE.end - 1),
        ("client-to-server key", CLIENT_TO_SERVER_KEY.start + 5),
        ("server-to-client key", SERVER_TO_CLIENT_KEY.start + 5),
    ];
    let mut clients = Vec::new();
    for (index, (_, offset)) in fields.iter().enumerate() {
        let mut altered = token_for(&named, &key, 10 + index as u64);
        altered[*offset] ^= 0x01;
        let mut client = netcode::Client::new(localhost(), 0.0).unwrap();
        // a client may refuse a token it cannot read (the version) before sending anything
        if client.connect(&altered).is_ok() {
            clients.push(client);
        }
    }
    assert!(clients.len() >= fields.len() - 1);
    assert!(!any_connects(&mut named, &mut clients));
    assert_eq!(named.num_connected_clients(), 0);

    // the same tokens unaltered connect: the refusals above were the alterations
    let mut honest = netcode::Client::new(localhost(), 0.0).unwrap();
    honest.connect(&token_for(&named, &key, 99)).unwrap();
    assert!(any_connects(&mut named, std::slice::from_mut(&mut honest)));
}

/// Bytes the server sends to `socket` in response to `datagram` sent `count` times, with an
/// update after each.
fn answer_bytes(
    server: &mut netcode::Server,
    socket: &UdpSocket,
    datagram: &[u8],
    count: usize,
) -> (usize, usize) {
    let mut buffer = [0u8; 2048];
    let mut answers = 0;
    let mut bytes = 0;
    let started = Instant::now();
    for _ in 0..count {
        socket.send_to(datagram, server.address()).unwrap();
        server.update(started.elapsed().as_secs_f64());
        while server.next_event().is_some() {}
    }
    let until = Instant::now() + Duration::from_millis(200);
    while Instant::now() < until {
        server.update(started.elapsed().as_secs_f64());
        while let Ok((len, _)) = socket.recv_from(&mut buffer) {
            answers += 1;
            bytes += len;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    (answers, bytes)
}

/// The handshake never amplifies: each valid connection request (1086 bytes) is answered by at
/// most one challenge of 341 bytes (333 before NETCODE 1.03 added the server nonce), a ratio
/// below one third, and only to the address that first presented the token. The same request replayed from any other address, which is what a
/// reflection through a spoofed source would be, is answered with nothing; so is a request
/// whose token does not decrypt, whatever its source.
#[test]
fn the_handshake_answers_less_than_it_receives_and_never_a_stranger() {
    let key = netcode::generate_key();
    let mut server = netcode::Server::new(localhost(), PROTOCOL, &key, 0.0).unwrap();
    server.start(4).unwrap();
    wait_past_second(unix_second());
    let token = token_for(&server, &key, 1);
    let request = request_for(&token);

    let holder = UdpSocket::bind(localhost()).unwrap();
    holder.set_nonblocking(true).unwrap();
    let (answers, bytes) = answer_bytes(&mut server, &holder, &request, 20);
    assert!(answers >= 1, "the token holder got no challenge");
    assert!(answers <= 20);
    assert!(
        bytes / answers == 341,
        "challenge of {} bytes",
        bytes / answers
    );
    assert!(
        bytes * 3 < request.len() * 20,
        "{bytes} bytes out for {} in",
        request.len() * 20
    );

    let stranger = UdpSocket::bind(localhost()).unwrap();
    stranger.set_nonblocking(true).unwrap();
    assert_eq!(answer_bytes(&mut server, &stranger, &request, 20), (0, 0));

    let mut forged = request_for(&token_for(&server, &key, 2));
    forged[500] ^= 0x80;
    assert_eq!(answer_bytes(&mut server, &stranger, &forged, 20), (0, 0));
    assert_eq!(server.num_connected_clients(), 0);
}

/// Audit S10, HYPOTHESIS, now CONFIRMED and bounded: the token history holds 2048 entries
/// (`NETCODE_MAX_CLIENTS * 8`), an entry lives until its token expires, and a full history
/// refuses new tokens rather than evicting (eviction is what would let a used token back in).
/// So 2048 distinct valid, unexpired tokens, presented from a single address, lock every new
/// token out until the first of them expires: at most one token lifetime. Only the backend can
/// mint valid tokens, so an attacker needs that many from it; random or forged requests never
/// create an entry (they fail to decrypt first), and one token creates at most one entry.
#[test]
fn a_full_token_history_refuses_new_tokens_until_entries_expire() {
    const HISTORY: u64 = 2048;
    let key = netcode::generate_key();
    let mut server = netcode::Server::new(localhost(), PROTOCOL, &key, 0.0).unwrap();
    server.start(4).unwrap();
    wait_past_second(unix_second());
    let flooder = UdpSocket::bind(localhost()).unwrap();
    flooder.set_nonblocking(true).unwrap();
    let mut buffer = [0u8; 2048];
    let started = Instant::now();
    let mut challenges = 0u64;
    for client_id in 0..HISTORY {
        let request = request_for(&token_for(&server, &key, 1000 + client_id));
        flooder.send_to(&request, server.address()).unwrap();
        if client_id % 32 == 31 {
            server.update(started.elapsed().as_secs_f64());
            while flooder.recv_from(&mut buffer).is_ok() {
                challenges += 1;
            }
        }
    }
    for _ in 0..50 {
        server.update(started.elapsed().as_secs_f64());
        while flooder.recv_from(&mut buffer).is_ok() {
            challenges += 1;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    // every one of the 2048 distinct tokens took an entry and was answered
    assert_eq!(challenges, HISTORY);

    // the history is full: a legitimate client with a fresh token is not answered
    let mut late = netcode::Client::new(localhost(), 0.0).unwrap();
    late.connect(&token_for(&server, &key, 1)).unwrap();
    assert!(!any_connects(&mut server, std::slice::from_mut(&mut late)));
    assert_eq!(
        late.state(),
        netcode::ClientState::ConnectionRequestTimedOut
    );
}
