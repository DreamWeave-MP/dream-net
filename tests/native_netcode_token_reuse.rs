//! Passing one connect token to `connect` more than once, under NETCODE 1.03 (netcode 1.5.0,
//! GHSA-8mrq-q9c6-h23v). Every attempt draws a fresh 8-byte client salt, carried at the end of
//! its connection requests, and its packet keys are derived from that salt and the server's
//! nonce, so a token used twice never repeats a key: the client half. The server holds an
//! unfinished token for the attempt that first presented it (its address and salt) for the
//! token's timeout, and for nothing else: the server half. Raw UDP sockets stand in for one
//! side or the other, so every datagram is seen.

// CI passes -W clippy::pedantic on the command line, overriding the manifest's lint table.
#![allow(clippy::cast_possible_truncation)]

mod native_netcode_support;

use std::net::{SocketAddr, UdpSocket};

use dream_net::native::netcode::{
    CONNECT_TOKEN_BYTES, Client, ClientState, Error, Key, generate_connect_token, generate_key,
};
use native_netcode_support::{
    DT, LONG_LIFETIME, PROTOCOL, World, await_loopback, localhost, pace, token_with, user_data_for,
};

type Token = [u8; CONNECT_TOKEN_BYTES];

/// Bytes of a connection request; the last 8 are the attempt's client salt.
const REQUEST_BYTES: usize = 1086;
const SALT: std::ops::Range<usize> = REQUEST_BYTES - 8..REQUEST_BYTES;

/// A socket that receives and never answers. Non-blocking: loopback delivers a datagram into
/// its queue during the sender's `sendto`.
fn listener() -> UdpSocket {
    let socket = UdpSocket::bind(localhost()).unwrap();
    socket.set_nonblocking(true).unwrap();
    socket
}

fn token_for(servers: &[SocketAddr], key: &Key, client_id: u64, timeout: i32) -> Token {
    generate_connect_token(
        servers,
        servers,
        30,
        timeout,
        client_id,
        PROTOCOL,
        key,
        &user_data_for(client_id),
    )
    .unwrap()
}

/// Every datagram `socket` receives while `client` is updated `steps` times.
fn sent_while_updating(
    client: &mut Client,
    socket: &UdpSocket,
    time: &mut f64,
    steps: usize,
) -> Vec<Vec<u8>> {
    let mut received = Vec::new();
    let mut buffer = [0u8; 2048];
    for _ in 0..steps {
        *time += DT;
        client.update(*time);
        pace();
        while let Ok((len, _)) = socket.recv_from(&mut buffer) {
            received.push(buffer[..len].to_vec());
        }
    }
    // the last step's datagrams too
    await_loopback();
    while let Ok((len, _)) = socket.recv_from(&mut buffer) {
        received.push(buffer[..len].to_vec());
    }
    received
}

/// The one client salt every connection request of an attempt carries, after checking that
/// they are all connection requests for `token`.
fn salt_of(attempt: &[Vec<u8>], token: &Token) -> [u8; 8] {
    assert!(!attempt.is_empty(), "the attempt sent nothing");
    let salt: [u8; 8] = attempt[0][SALT].try_into().unwrap();
    for datagram in attempt {
        assert_eq!(datagram.len(), REQUEST_BYTES, "not a connection request");
        assert_eq!(datagram[0], 0);
        assert_eq!(datagram[1..14], token[..13], "not this token's request");
        assert_eq!(datagram[SALT], salt, "the salt changed within one attempt");
    }
    salt
}

#[test]
fn every_connect_with_one_token_draws_a_new_client_salt() {
    let server = listener();
    let token = token_for(&[server.local_addr().unwrap()], &generate_key(), 1, 5);
    let mut time = 0.0;
    let mut client = Client::new(localhost(), time).unwrap();
    let mut salts = Vec::new();
    for _ in 0..3 {
        client.connect(&token).unwrap();
        let attempt = sent_while_updating(&mut client, &server, &mut time, 30);
        salts.push(salt_of(&attempt, &token));
    }
    // another client with the same token
    let mut other = Client::new(localhost(), time).unwrap();
    other.connect(&token).unwrap();
    let attempt = sent_while_updating(&mut other, &server, &mut time, 30);
    salts.push(salt_of(&attempt, &token));

    for (i, a) in salts.iter().enumerate() {
        for b in &salts[i + 1..] {
            assert_ne!(a, b, "two attempts drew one salt: {salts:?}");
        }
    }
}

#[test]
fn a_multi_address_token_draws_a_new_salt_for_each_server() {
    let servers = [listener(), listener()];
    let addresses: Vec<SocketAddr> = servers.iter().map(|s| s.local_addr().unwrap()).collect();
    let token = token_for(&addresses, &generate_key(), 2, 1);
    let mut time = 0.0;
    let mut client = Client::new(localhost(), time).unwrap();
    client.connect(&token).unwrap();
    let mut seen: [Vec<Vec<u8>>; 2] = [Vec::new(), Vec::new()];
    let mut buffer = [0u8; 2048];
    // three simulated seconds: the first server's one-second timeout passes, and netcode
    // moves on to the second
    for step in 0..=300 {
        let done = step == 300 || !client.state().is_connecting();
        if done {
            // a last read, for what the final update sent
            await_loopback();
        } else {
            time += DT;
            client.update(time);
            pace();
        }
        for (n, server) in servers.iter().enumerate() {
            while let Ok((len, _)) = server.recv_from(&mut buffer) {
                seen[n].push(buffer[..len].to_vec());
            }
        }
        if done {
            break;
        }
    }
    assert_eq!(client.state(), ClientState::ConnectionRequestTimedOut);
    assert_ne!(salt_of(&seen[0], &token), salt_of(&seen[1], &token));
}

/// The connection request an attempt that drew `salt` sends for `token`.
fn request(token: &Token, salt: [u8; 8]) -> Vec<u8> {
    let mut request = vec![0u8];
    request.extend_from_slice(&token[0..21]);
    request.extend_from_slice(&token[29..1085]);
    request.extend_from_slice(&salt);
    assert_eq!(request.len(), REQUEST_BYTES);
    request
}

/// The packet types the server answers `request` with, sent from `socket` three times over
/// ten steps of `world`'s clock.
fn answers(world: &mut World, socket: &UdpSocket, request: &[u8]) -> Vec<u8> {
    let mut types = Vec::new();
    let mut buffer = [0u8; 2048];
    for step in 0..10 {
        if step % 4 == 0 {
            socket.send_to(request, world.server.address()).unwrap();
            pace();
        }
        world.step();
        await_loopback();
        while let Ok((len, _)) = socket.recv_from(&mut buffer) {
            assert!(len > 0);
            types.push(buffer[0] & 0x0F);
        }
    }
    types
}

/// The server half of GHSA-8mrq-q9c6-h23v. A token whose handshake was never finished is held
/// for the attempt that first presented it: that attempt's retransmissions are answered with
/// challenges until the token's timeout has passed, and nothing else is: not a second attempt
/// from the same socket (a new salt), and not the first attempt's own request replayed from
/// another socket. Under 1.4.10 a second attempt from the same address was admitted, and
/// reused the first attempt's keys.
#[test]
fn an_unfinished_token_is_held_for_the_attempt_that_presented_it() {
    let mut world = World::new(4);
    let token = token_with(world.server.address(), &world.key, 3, LONG_LIFETIME, 1);
    let first = request(&token, [1, 2, 3, 4, 5, 6, 7, 8]);
    let second = request(&token, [8, 7, 6, 5, 4, 3, 2, 1]);
    let holder = listener();
    let stranger = listener();

    let answered = answers(&mut world, &holder, &first);
    assert!(!answered.is_empty(), "no challenge for a fresh token");
    assert!(answered.iter().all(|&t| t == 2), "{answered:?}");

    assert_eq!(answers(&mut world, &holder, &second), Vec::<u8>::new());
    assert_eq!(answers(&mut world, &stranger, &first), Vec::<u8>::new());
    assert_eq!(answers(&mut world, &stranger, &second), Vec::<u8>::new());

    // the first attempt is still answered within the token's one-second timeout...
    let again = answers(&mut world, &holder, &first);
    assert!(
        !again.is_empty() && again.iter().all(|&t| t == 2),
        "{again:?}"
    );
    // ...and not after it, counted from when the server first saw the token
    world.time += 1.5;
    assert_eq!(answers(&mut world, &holder, &first), Vec::<u8>::new());
    assert_eq!(world.server.num_connected_clients(), 0);
}

#[test]
fn a_malformed_token_is_refused_by_netcode_every_time() {
    let key = generate_key();
    let mut garbage = token_for(&[localhost()], &key, 4, 1);
    garbage[..13].copy_from_slice(b"NOT A TOKEN\0\0");
    let mut client = Client::new(localhost(), 0.0).unwrap();
    for _ in 0..2 {
        assert!(matches!(
            client.connect(&garbage),
            Err(Error::InvalidConnectToken)
        ));
        assert_eq!(client.state(), ClientState::InvalidConnectToken);
    }
}
