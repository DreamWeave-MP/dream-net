//! The server's start floor (audit S5, D2) and restart protection (S2), which use the wall
//! clock: a connection request is ignored when its token's expire timestamp is at or below
//! `wall clock at start + max_connect_token_lifetime`. Each test waits for at most one or two
//! wall-clock second boundaries.

// CI passes -W clippy::pedantic on the command line, overriding the manifest's lint table.
#![allow(clippy::cast_possible_wrap)]

mod native_netcode_support;

use std::net::SocketAddr;

use dream_net::native::netcode::{
    Client, ClientState, Error, Key, Server, ServerOptions, generate_key,
};
use native_netcode_support::{
    DT, MAX_STEPS, PROTOCOL, localhost, pace, present_raw, settled_second, token_with,
    wait_for_next_second, wall_second,
};

/// Drives one client with `token` against `server` until it connects or fails.
fn attempt(server: &mut Server, token: &[u8; 2048], time: &mut f64) -> ClientState {
    let mut client = Client::new(localhost(), *time).unwrap();
    client.connect(token).unwrap();
    for _ in 0..MAX_STEPS {
        *time += DT;
        client.update(*time);
        server.update(*time);
        pace();
        if !client.state().is_connecting() {
            break;
        }
    }
    let state = client.state();
    drop(client);
    // let the server see the disconnect and drop its events
    *time += DT;
    server.update(*time);
    while server.next_event().is_some() {}
    state
}

fn server(key: &Key, address: SocketAddr, max_lifetime: u32) -> Server {
    let options = ServerOptions::default().with_max_connect_token_lifetime(max_lifetime);
    let mut server = Server::with_options(address, PROTOCOL, key, 0.0, options).unwrap();
    server.start(4).unwrap();
    server
}

/// Mints tokens of `refused_lifetime` and `refused_lifetime + 1` seconds in the start second of
/// a server with the given maximum lifetime (default when `None`), and checks that only the
/// longer one connects.
fn tokens_minted_in_the_start_second(max_lifetime: Option<u32>, refused_lifetime: i32) {
    let key = generate_key();
    for _ in 0..5 {
        let second = settled_second();
        let mut server = if let Some(m) = max_lifetime {
            server(&key, localhost(), m)
        } else {
            let mut s = Server::new(localhost(), PROTOCOL, &key, 0.0).unwrap();
            s.start(4).unwrap();
            s
        };
        let address = server.address();
        let at_floor = token_with(address, &key, 1, refused_lifetime, 1);
        let above_floor = token_with(address, &key, 2, refused_lifetime + 1, 1);
        if wall_second() != second {
            continue; // a second boundary fell between start and minting: try again
        }
        let mut time = 0.0;
        assert_eq!(
            attempt(&mut server, &at_floor, &mut time),
            ClientState::ConnectionRequestTimedOut,
            "a {refused_lifetime} s token minted in the start second is refused"
        );
        assert_eq!(
            attempt(&mut server, &above_floor, &mut time),
            ClientState::Connected,
            "a {} s token minted in the start second is accepted",
            refused_lifetime + 1
        );
        return;
    }
    panic!("could not mint inside the start second in five tries");
}

#[test]
fn with_the_default_maximum_a_30_second_token_from_the_start_second_is_refused() {
    tokens_minted_in_the_start_second(None, 30);
}

#[test]
fn with_a_custom_maximum_the_floor_moves_with_it() {
    tokens_minted_in_the_start_second(Some(5), 5);
    tokens_minted_in_the_start_second(Some(300), 300);
}

#[test]
fn a_30_second_token_minted_a_second_after_the_start_is_accepted() {
    let key = generate_key();
    let mut server = Server::new(localhost(), PROTOCOL, &key, 0.0).unwrap();
    server.start(1).unwrap();
    wait_for_next_second();
    let token = token_with(server.address(), &key, 1, 30, 1);
    let mut time = 0.0;
    assert_eq!(
        attempt(&mut server, &token, &mut time),
        ClientState::Connected
    );
}

/// Restart protection, for a restart of the same `Server` (`stop` + `start`) and for a new
/// `Server` on the same key and port.
fn restart(new_server: bool) {
    const MAX: u32 = 10;
    let key = generate_key();
    let mut first = server(&key, localhost(), MAX);
    let address = first.address();
    // a token minted a second after the start, no longer-lived than the maximum, passes the
    // first run's floor
    wait_for_next_second();
    let used = token_with(address, &key, 1, MAX as i32, 1);
    let unused = token_with(address, &key, 2, MAX as i32, 1);
    let long_lived = token_with(address, &key, 3, 3600, 1);
    let mut time = 0.0;
    assert_eq!(
        attempt(&mut first, &used, &mut time),
        ClientState::Connected
    );

    let mut second = if new_server {
        drop(first);
        server(&key, address, MAX)
    } else {
        first.stop();
        first.start(4).unwrap();
        first
    };
    assert_eq!(second.address(), address);
    // within the floor: both tokens from before the restart are refused, used or not. This
    // process refuses the used one itself, before sending anything, so the server's refusal is
    // shown by presenting it as a second client would (its connection request, from a raw
    // socket): no answer within the token's 1-second timeout
    let mut client = Client::new(localhost(), time).unwrap();
    assert!(matches!(
        client.connect(&used),
        Err(Error::InvalidConnectToken)
    ));
    drop(client);
    assert_eq!(
        present_raw(&mut second, &mut time, &used, 1, localhost()),
        Vec::<Vec<u8>>::new()
    );
    assert_eq!(
        attempt(&mut second, &unused, &mut time),
        ClientState::ConnectionRequestTimedOut
    );
    // documented residual (S2): a token longer-lived than the maximum, minted before the
    // restart, is still accepted
    assert_eq!(
        attempt(&mut second, &long_lived, &mut time),
        ClientState::Connected
    );
    // above the floor: a token minted after the restart is accepted
    let fresh = token_with(address, &key, 4, MAX as i32 + 1, 1);
    assert_eq!(
        attempt(&mut second, &fresh, &mut time),
        ClientState::Connected
    );
}

#[test]
fn a_token_from_before_a_stop_and_start_is_refused() {
    restart(false);
}

#[test]
fn a_token_from_before_a_new_server_on_the_same_key_and_port_is_refused() {
    restart(true);
}
