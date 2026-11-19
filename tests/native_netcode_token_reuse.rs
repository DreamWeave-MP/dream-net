//! A connect token admits one connection attempt, on the client as well as the server: once a
//! process has passed a token to `Client::connect`, it refuses that token again, on the same
//! client or any other, before anything is sent. A raw UDP socket stands in for the server, so
//! every datagram a client sends is seen; nothing answers.

// CI passes -W clippy::pedantic on the command line, overriding the manifest's lint table.
#![allow(clippy::cast_possible_truncation)]

mod native_netcode_support;

use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Barrier};

use dream_net::native::netcode::{
    CONNECT_TOKEN_BYTES, Client, ClientState, Error, Key, generate_connect_token, generate_key,
};
use native_netcode_support::{DT, PROTOCOL, await_loopback, localhost, pace, user_data_for};

type Token = [u8; CONNECT_TOKEN_BYTES];

/// A socket standing in for a server: it receives and never answers. Non-blocking: loopback
/// delivers a datagram into its queue during the sender's `sendto`.
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

/// Every datagram `socket` receives while `client` is updated `steps` times, with its sender.
fn sent_while_updating(
    client: &mut Client,
    socket: &UdpSocket,
    time: &mut f64,
    steps: usize,
) -> Vec<(SocketAddr, Vec<u8>)> {
    let mut received = Vec::new();
    let mut buffer = [0u8; 2048];
    for _ in 0..steps {
        *time += DT;
        client.update(*time);
        pace();
        while let Ok((len, from)) = socket.recv_from(&mut buffer) {
            received.push((from, buffer[..len].to_vec()));
        }
    }
    // the last step's datagrams too
    await_loopback();
    while let Ok((len, from)) = socket.recv_from(&mut buffer) {
        received.push((from, buffer[..len].to_vec()));
    }
    received
}

#[test]
fn a_used_token_is_refused_on_the_same_client_and_sends_nothing() {
    let server = listener();
    let key = generate_key();
    let token = token_for(&[server.local_addr().unwrap()], &key, 1, 5);
    let mut time = 0.0;
    let mut client = Client::new(localhost(), time).unwrap();
    client.connect(&token).unwrap();
    let first = sent_while_updating(&mut client, &server, &mut time, 30);
    assert!(
        !first.is_empty() && first.iter().all(|(_, d)| d[0] == 0),
        "the first attempt sends connection requests"
    );

    client.disconnect();
    assert_eq!(client.state(), ClientState::Disconnected);
    sent_while_updating(&mut client, &server, &mut time, 5);
    assert!(matches!(
        client.connect(&token),
        Err(Error::InvalidConnectToken)
    ));
    // left exactly as it was, and silent
    assert_eq!(client.state(), ClientState::Disconnected);
    assert_eq!(
        sent_while_updating(&mut client, &server, &mut time, 60),
        vec![]
    );

    // while the first attempt is still running, a second connect with its token changes
    // nothing either: the first attempt goes on, unchanged
    let other = token_for(&[server.local_addr().unwrap()], &key, 2, 5);
    client.connect(&other).unwrap();
    sent_while_updating(&mut client, &server, &mut time, 5);
    assert!(matches!(
        client.connect(&other),
        Err(Error::InvalidConnectToken)
    ));
    assert_eq!(client.state(), ClientState::SendingConnectionRequest);
}

#[test]
fn a_used_token_is_refused_on_a_fresh_client_and_sends_nothing() {
    let server = listener();
    let key = generate_key();
    let token = token_for(&[server.local_addr().unwrap()], &key, 3, 5);
    let mut time = 0.0;
    let mut first = Client::new(localhost(), time).unwrap();
    first.connect(&token).unwrap();
    drop(first);

    let mut fresh = Client::new(localhost(), time).unwrap();
    let fresh_port = fresh.port();
    assert!(matches!(
        fresh.connect(&token),
        Err(Error::InvalidConnectToken)
    ));
    assert_eq!(fresh.state(), ClientState::Disconnected);
    let sent = sent_while_updating(&mut fresh, &server, &mut time, 60);
    assert!(
        sent.iter().all(|(from, _)| from.port() != fresh_port),
        "the refused client sent {} datagrams",
        sent.len()
    );

    // a new token works on the same client, as before
    let new = token_for(&[server.local_addr().unwrap()], &key, 4, 5);
    fresh.connect(&new).unwrap();
    assert_eq!(fresh.state(), ClientState::SendingConnectionRequest);
    let sent = sent_while_updating(&mut fresh, &server, &mut time, 30);
    assert!(
        sent.iter()
            .any(|(from, d)| from.port() == fresh_port && d[0] == 0)
    );
}

#[test]
fn a_new_token_connects_after_a_failed_attempt() {
    let server = listener();
    let key = generate_key();
    let token = token_for(&[server.local_addr().unwrap()], &key, 5, 1);
    let mut time = 0.0;
    let mut client = Client::new(localhost(), time).unwrap();
    client.connect(&token).unwrap();
    // nothing answers: the attempt times out after the token's one second
    // two simulated seconds
    sent_while_updating(&mut client, &server, &mut time, 200);
    assert_eq!(client.state(), ClientState::ConnectionRequestTimedOut);
    assert!(matches!(
        client.connect(&token),
        Err(Error::InvalidConnectToken)
    ));
    let new = token_for(&[server.local_addr().unwrap()], &key, 6, 1);
    client.connect(&new).unwrap();
    assert_eq!(client.state(), ClientState::SendingConnectionRequest);
}

#[test]
fn a_malformed_token_is_not_remembered() {
    let key = generate_key();
    let mut garbage = token_for(&[localhost()], &key, 7, 1);
    garbage[..13].copy_from_slice(b"NOT A TOKEN\0\0");
    let mut client = Client::new(localhost(), 0.0).unwrap();
    for _ in 0..2 {
        assert!(matches!(
            client.connect(&garbage),
            Err(Error::InvalidConnectToken)
        ));
        // refused by netcode itself each time (which leaves this state), not by the record
        assert_eq!(client.state(), ClientState::InvalidConnectToken);
    }
}

#[test]
fn of_concurrent_connects_with_one_token_exactly_one_proceeds() {
    const THREADS: usize = 8;
    let server = listener();
    let token = token_for(&[server.local_addr().unwrap()], &generate_key(), 8, 5);
    let start = Arc::new(Barrier::new(THREADS));
    let outcomes: Vec<bool> = (0..THREADS)
        .map(|_| {
            let start = Arc::clone(&start);
            std::thread::spawn(move || {
                let mut client = Client::new(localhost(), 0.0).unwrap();
                start.wait();
                match client.connect(&token) {
                    Ok(()) => true,
                    Err(Error::InvalidConnectToken) => false,
                    Err(other) => panic!("unexpected {other:?}"),
                }
            })
        })
        .collect::<Vec<_>>()
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(outcomes.iter().filter(|&&ok| ok).count(), 1, "{outcomes:?}");
}

#[test]
fn a_multi_address_token_still_walks_its_addresses_in_one_attempt() {
    let servers = [listener(), listener()];
    let addresses: Vec<SocketAddr> = servers.iter().map(|s| s.local_addr().unwrap()).collect();
    let token = token_for(&addresses, &generate_key(), 9, 1);
    let mut time = 0.0;
    let mut client = Client::new(localhost(), time).unwrap();
    client.connect(&token).unwrap();
    let mut seen = [0usize; 2];
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
            while server.recv_from(&mut buffer).is_ok() {
                seen[n] += 1;
            }
        }
        if done {
            break;
        }
    }
    assert!(seen[0] > 0 && seen[1] > 0, "requests per server: {seen:?}");
    assert_eq!(client.state(), ClientState::ConnectionRequestTimedOut);
    // and the attempt, over both addresses, was the token's one
    assert!(matches!(
        client.connect(&token),
        Err(Error::InvalidConnectToken)
    ));
}
