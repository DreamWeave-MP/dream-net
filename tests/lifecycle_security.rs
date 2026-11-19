//! Security regressions for the move to C netcode (audit S1 to S5, campaign decision 12). Each
//! asserts the secure behaviour, which dream-net 1.1.1 on `netcode-official` 1.0.0 did not
//! have:
//!
//! - S1: a connect token is single use. Reconnecting with it, after a clean disconnect or after
//!   the first session timed out, is refused, and no datagram of the second attempt carries an
//!   encrypted packet at all, so nothing can repeat a (key, nonce) pair of the first session.
//!   A process refuses a token it already passed to `connect` itself, before sending anything
//!   (asserted first), so the server's own refusal is tested by presenting the token again as
//!   a second client would, from a raw socket sending its exact connection request
//!   (`Net::present_raw`), from the same socket address where the first attempt's client is
//!   the one reconnecting.
//! - S2: a token used before a server restart (same key, same address) is refused after it,
//!   while a token minted after the restart is accepted.
//! - S5: the start floor, with the default maximum token lifetime and with another one.
//! - S3: zero-length datagrams no longer stall the receive loop of a server or a client.
//! - S4: a server disconnect leaves a client with a multi-address token disconnected; it does
//!   not move on to the next address.
//!
//! A refused token is not answered by the server, so the client reports
//! `ConnectFailed { reason: TimedOut }` once the token's timeout has passed. Tokens that are
//! refused here use a short timeout to keep the file fast.

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

use std::net::{SocketAddr, UdpSocket};
use std::time::Instant;

use dream_net::{ClientEvent, ClientStatus, DisconnectReason, ServerEvent};
use lifecycle::{
    DEADLINE, Net, PROTOCOL, Token, chat, connection_request, localhost, packet_type, server,
    settled_second, token_servers, unix_second, user_data, wait_past_second,
};

const TIMED_OUT: ClientEvent<Vec<u8>> = ClientEvent::ConnectFailed {
    reason: DisconnectReason::TimedOut,
    failure: None,
};

/// What a raw presenter received when the server ignored it: nothing.
const UNANSWERED: Vec<Vec<u8>> = Vec::new();

/// A session through the relay that exchanges events both ways, so the first session's
/// encrypted traffic holds keep-alives and payloads in both directions.
fn establish_and_talk(net: &mut Net, token: &Token) -> usize {
    let c = net.add_client(token);
    assert!(
        net.run_until(
            |n| !n.connected_peers().is_empty() && n.clients[c].status() == ClientStatus::Connected
        ),
        "{:?}",
        net.client_events[c]
    );
    let peer = *net.connected_peers().last().unwrap();
    net.clients[c].send(chat(), b"up").unwrap();
    net.server.send(peer, chat(), b"down").unwrap();
    assert!(net.run_until(|n| !n.messages_from(peer).is_empty() && n.client_got(c, b"down")));
    c
}

/// What the relay saw from `from_server`/`from_client` on: the server sent nothing at all, and
/// the client sent only connection requests (the token's own, unchanged), never an encrypted
/// packet. So no ciphertext of the second attempt can repeat one of the first, and no session
/// key was used twice.
fn assert_second_attempt_encrypted_nothing(net: &Net, from_server: usize, from_client: usize) {
    let relay = net.relay.as_ref().unwrap();
    assert!(
        relay.to_client[from_server..].is_empty(),
        "the server answered a used token: {:?}",
        relay.to_client[from_server..]
            .iter()
            .map(|d| packet_type(d))
            .collect::<Vec<_>>()
    );
    let second = &relay.to_server[from_client..];
    assert!(
        !second.is_empty(),
        "the second attempt never reached the relay"
    );
    assert!(
        second.iter().all(|d| packet_type(d) == 0),
        "the client sent encrypted packets in the second attempt"
    );
    let first = &relay.to_server[..from_client];
    let first_encrypted: Vec<&Vec<u8>> = first
        .iter()
        .chain(&relay.to_client[..from_server])
        .filter(|d| packet_type(d) != 0)
        .collect();
    assert!(
        !first_encrypted.is_empty(),
        "the first session carried no encrypted traffic to compare with"
    );
    for datagram in second {
        assert!(!first_encrypted.contains(&datagram));
    }
}

/// S1: reconnecting with a token after a clean disconnect, from the same client socket (the
/// case 1.0.0 admitted, reusing every (key, nonce) pair of the first session).
#[test]
fn a_used_token_is_refused_after_a_disconnect() {
    let mut net = Net::new(2).with_relay();
    wait_past_second(net.server_started);
    let token = net.token_with(1, 30, 1, true);
    let c = establish_and_talk(&mut net, &token);
    let peer = net.connected_peers()[0];
    // what `present_raw` sends below is exactly what the client sent
    let requests: Vec<&Vec<u8>> = net
        .relay
        .as_ref()
        .unwrap()
        .to_server
        .iter()
        .filter(|d| packet_type(d) == 0)
        .collect();
    assert_ne!(requests.len(), 0, "no connection requests");
    assert!(requests.iter().all(|d| **d == connection_request(&token)));
    net.clients[c].disconnect();
    assert!(net.run_until(|n| n.server.num_connected() == 0));
    assert!(net.server_events.contains(&ServerEvent::Disconnected {
        peer,
        reason: DisconnectReason::Remote
    }));
    net.run_for(0.1);

    // the client refuses the token itself, and sends nothing
    net.assert_refused_in_process(Some(c), &token);
    // the server refuses it too, presented from the same socket address
    let relay = net.relay.as_ref().unwrap();
    let (from_server, from_client) = (relay.to_client.len(), relay.to_server.len());
    assert_eq!(net.present_raw(&token, Some(c)), UNANSWERED);
    assert_eq!(net.connected_peers(), vec![peer]);
    assert_eq!(net.server.num_connected(), 0);
    assert_second_attempt_encrypted_nothing(&net, from_server, from_client);
}

/// `present_raw` is a faithful stand-in for a second client: for a token the server has not
/// seen it lists the relay and then the server, and the server answers its request with a
/// challenge, through the relay.
#[test]
fn the_raw_presenter_is_answered_for_a_fresh_token() {
    let mut net = Net::new(2).with_relay();
    wait_past_second(net.server_started);
    let token = net.token_with(1, 30, 1, true);
    let relay = net.relay.as_ref().unwrap().address();
    assert_eq!(
        token_servers(&token),
        (1, vec![relay, net.server.address()])
    );
    let answers = net.present_raw(&token, None);
    assert_ne!(answers.len(), 0, "no answer");
    assert!(answers.iter().all(|d| packet_type(d) == 2), "{answers:?}");
}

/// S1, second form: the first session timed out (the relay went silent) rather than ending
/// cleanly; a new client with the same token is still refused.
#[test]
fn a_used_token_is_refused_after_its_session_timed_out() {
    let mut net = Net::new(2).with_relay();
    wait_past_second(net.server_started);
    let token = net.token_with(1, 30, 1, true);
    let c = establish_and_talk(&mut net, &token);
    let peer = net.connected_peers()[0];
    net.relay.as_mut().unwrap().blocked = true;
    assert!(net.run_until(|n| n.server.num_connected() == 0 && n.ended(c).is_some()));
    assert!(net.server_events.contains(&ServerEvent::Disconnected {
        peer,
        reason: DisconnectReason::TimedOut
    }));
    assert_eq!(
        net.ended(c),
        Some(ClientEvent::Disconnected {
            reason: DisconnectReason::TimedOut
        })
    );
    net.relay.as_mut().unwrap().blocked = false;
    net.run_for(0.1);

    // a new client of this process refuses the token itself, and sends nothing
    net.assert_refused_in_process(None, &token);
    // the server refuses it from a new socket
    let relay = net.relay.as_ref().unwrap();
    let (from_server, from_client) = (relay.to_client.len(), relay.to_server.len());
    assert_eq!(net.present_raw(&token, None), UNANSWERED);
    assert_eq!(net.connected_peers(), vec![peer]);
    assert_second_attempt_encrypted_nothing(&net, from_server, from_client);
}

/// S2: a server restarted on the same key and address refuses a token used before the restart,
/// and one minted before it but never used; a token minted after the restart connects.
#[test]
fn a_restart_refuses_tokens_from_before_it() {
    let mut net = Net::new(2).with_relay();
    wait_past_second(net.server_started);
    let token = net.token_with(1, 30, 1, true);
    let unused = net.token_with(2, 30, 1, true);
    let c = establish_and_talk(&mut net, &token);
    net.clients[c].disconnect();
    assert!(net.run_until(|n| n.server.num_connected() == 0));
    net.run_for(0.1);
    let address = net.server.address();

    net.restart();
    assert_eq!(net.server.address(), address);
    net.server_events.clear();
    // the client refuses the used token itself, and sends nothing
    net.assert_refused_in_process(Some(c), &token);
    // the restarted server refuses it, presented from the same socket address
    let relay = net.relay.as_ref().unwrap();
    let (from_server, from_client) = (relay.to_client.len(), relay.to_server.len());
    assert_eq!(net.present_raw(&token, Some(c)), UNANSWERED);
    assert!(net.server_events.is_empty(), "{:?}", net.server_events);
    assert_second_attempt_encrypted_nothing(&net, from_server, from_client);

    let never_used = net.add_client(&unused);
    assert!(net.run_until(|n| n.ended(never_used).is_some()));
    assert_eq!(net.client_events[never_used], [TIMED_OUT]);
    assert!(net.server_events.is_empty(), "{:?}", net.server_events);

    // the restarted server itself is fine: a token minted after its start second connects
    let (_, peer) = net.connect_one(3);
    assert_eq!(net.server.client_id(peer), Some(3));
}

/// S5 and D2: the start floor. With the default maximum (30 s), a 30-second token minted in the
/// server's start second is refused and one minted a second later accepted. A token longer-lived
/// than the maximum passes even in the start second (which is why only tokens within the
/// maximum are protected across restarts, and a host that keeps its key must not mint longer
/// ones). With another maximum the floor moves with it.
#[test]
fn the_start_floor_refuses_tokens_that_could_predate_the_server() {
    for max_lifetime in [dream_net::DEFAULT_MAX_CONNECT_TOKEN_LIFETIME, 5] {
        let lifetime = i32::try_from(max_lifetime).unwrap();
        let mut done = false;
        for _ in 0..5 {
            let key = dream_net::generate_key();
            let start = settled_second();
            let mut net = Net::on(key, server(&key, localhost(), 4, max_lifetime), 4);
            let at_max = net.token_with(1, lifetime, 1, false);
            let above_max = net.token_with(2, lifetime + 1, 1, false);
            if unix_second() != start {
                continue;
            }
            let refused = net.add_client(&at_max);
            let accepted = net.add_client(&above_max);
            assert!(net.run_until(|n| n.ended(refused).is_some()
                && n.clients[accepted].status() == ClientStatus::Connected));
            assert_eq!(
                net.client_events[refused],
                [TIMED_OUT],
                "maximum {max_lifetime}"
            );
            assert!(
                net.server_events
                    .iter()
                    .all(|e| !matches!(e, ServerEvent::Connected { client_id: 1, .. }))
            );

            wait_past_second(start);
            let later = net.add_client(&net.token_with(3, lifetime, 1, false));
            assert!(
                net.run_until(|n| n.clients[later].status() == ClientStatus::Connected),
                "maximum {max_lifetime}: {:?}",
                net.client_events[later]
            );
            done = true;
            break;
        }
        assert!(done, "could not mint inside the start second");
    }
}

/// S3: thousands of zero-length datagrams queued at a server and at a client before the
/// handshake, and more every step during it, cost nothing: the handshake and an event round
/// trip complete within a few hundred steps. 1.0.0 stopped each receive loop at the first empty
/// datagram, one per update, and under a sustained flood never completed.
#[test]
fn zero_length_datagrams_do_not_stall_a_server_or_a_client() {
    const BURST: usize = 2000;
    const PER_STEP: usize = 50;
    const MAX_STEPS: usize = 1000;
    let mut net = Net::new(1);
    let token = net.token(1);
    let c = net.new_client();
    let flood = UdpSocket::bind(localhost()).unwrap();
    let client_address = SocketAddr::new(localhost().ip(), net.clients[c].port());
    let targets = [net.server.address(), client_address];
    let spray = |n: usize| {
        for target in targets {
            for _ in 0..n {
                let _ = flood.send_to(&[], target);
            }
        }
    };
    spray(BURST);
    net.clients[c].connect(&token).unwrap();
    let mut steps = 0;
    let mut echoed = false;
    let deadline = Instant::now() + DEADLINE;
    while Instant::now() < deadline && steps < MAX_STEPS {
        spray(PER_STEP);
        net.step();
        steps += 1;
        if net.clients[c].status() == ClientStatus::Connected
            && !echoed
            && let Some(&peer) = net.connected_peers().first()
        {
            net.server.send(peer, chat(), b"through the flood").unwrap();
            echoed = true;
        }
        if net.client_got(c, b"through the flood") {
            break;
        }
    }
    assert!(
        net.client_got(c, b"through the flood"),
        "no round trip in {steps} steps: {:?} {:?}",
        net.server_events,
        net.client_events[c]
    );
    assert!(steps < MAX_STEPS);
}

/// S4: with a token listing two servers, a disconnect from the first leaves the client
/// disconnected (`Disconnected { Remote }`), and it never tries the second.
#[test]
fn a_server_disconnect_does_not_send_the_client_to_the_next_address() {
    let mut net = Net::new(2);
    let spare = UdpSocket::bind(localhost()).unwrap();
    spare.set_nonblocking(true).unwrap();
    wait_past_second(net.server_started);
    let addresses = [net.server.address(), spare.local_addr().unwrap()];
    let token = dream_net::generate_connect_token(
        &addresses,
        &addresses,
        30,
        5,
        1,
        PROTOCOL,
        &net.key,
        &user_data(1),
    )
    .unwrap();
    let c = net.add_client(&token);
    assert!(net.run_until(
        |n| n.clients[c].status() == ClientStatus::Connected && !n.connected_peers().is_empty()
    ));
    let peer = net.connected_peers()[0];
    net.server.disconnect(peer);
    assert!(net.run_until(|n| n.ended(c).is_some()));
    net.run_for(1.0);
    assert_eq!(
        net.client_events[c],
        [
            ClientEvent::Connected,
            ClientEvent::Disconnected {
                reason: DisconnectReason::Remote
            }
        ]
    );
    assert_eq!(net.clients[c].status(), ClientStatus::Disconnected);
    assert_eq!(net.clients[c].server_address(), None);
    let mut buffer = [0u8; 2048];
    assert!(
        spare.recv_from(&mut buffer).is_err(),
        "the client went on to the second address"
    );
}
