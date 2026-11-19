//! Peer handles and the server/client lifecycle over C netcode on localhost: slot churn and
//! generations, a slot vacated and refilled inside one update, stale handles, teardown order,
//! clocks, addresses and creation errors.
//!
//! netcode reports slot changes to dream-net per batch (every disconnect, then every connect),
//! so these pin what a host sees through that model: a `PeerId` is never reused, every
//! `Connected` is followed by exactly one `Disconnected`, and nothing of one session (events,
//! id, address, user data) is ever attributed to another.

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

use std::collections::HashSet;
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use common::test_schema;
use dream_net::{
    Client, ClientConfig, ClientEvent, ClientStatus, DisconnectReason, Error, NetcodeError, PeerId,
    SendError, ServerConfig, ServerEvent, TransportConfig,
};
use lifecycle::{
    Net, PROTOCOL, chat, localhost, moved, packet_type, server, user_data, wait_past_second,
};

/// Everything a handle can reach, refused for `old`; `new` (same slot) answers as itself.
fn assert_stale(net: &mut Net, old: PeerId, new: Option<(PeerId, u64)>) {
    assert_eq!(
        net.server.send(old, chat(), b"stale"),
        Err(SendError::UnknownPeer(old))
    );
    assert_eq!(net.server.client_id(old), None);
    assert_eq!(net.server.client_address(old), None);
    assert!(net.server.client_user_data(old).is_none());
    assert!(net.server.stats(old).is_none());
    assert!(net.server.counters(old).is_none());
    assert!(net.server.peer_connection(old).is_none());
    assert!(!net.server.peers().any(|p| p == old));
    if let Some((new, id)) = new {
        assert_eq!(old.slot(), new.slot());
        assert_ne!(old, new);
        assert_eq!(net.server.client_id(new), Some(id));
        assert_eq!(net.server.client_user_data(new), Some(&user_data(id)));
        assert!(net.server.client_address(new).is_some());
        assert!(net.server.stats(new).is_some());
        // disconnecting the stale handle leaves the occupant alone, and reports nothing
        let before = net.server_events.len();
        net.server.disconnect(old);
        net.step();
        assert!(
            !net.server_events[before..]
                .iter()
                .any(|e| matches!(e, ServerEvent::Disconnected { .. })),
            "{:?}",
            net.server_events
        );
        assert_eq!(net.server.client_id(new), Some(id));
    } else {
        net.server.disconnect(old);
    }
}

/// Every `Connected` peer is followed by exactly one `Disconnected` for it, and nothing for a
/// peer after its `Disconnected`.
fn assert_lifecycle_pairs(events: &[ServerEvent<Vec<u8>>]) {
    let mut open = HashSet::new();
    let mut closed = HashSet::new();
    for event in events {
        match event {
            ServerEvent::Connected { peer, .. } => {
                assert!(
                    !open.contains(peer) && !closed.contains(peer),
                    "{peer:?} announced twice: {events:?}"
                );
                open.insert(*peer);
            }
            ServerEvent::Disconnected { peer, .. } => {
                assert!(open.remove(peer), "{peer:?} left without being announced");
                closed.insert(*peer);
            }
            ServerEvent::Message { peer, .. } => {
                assert!(open.contains(peer), "{peer:?} spoke outside its session");
            }
            ServerEvent::Rejected { peer, .. } => {
                assert!(!open.contains(peer) && !closed.contains(peer));
                closed.insert(*peer);
            }
        }
    }
}

#[test]
fn churn_through_every_slot_never_reuses_a_handle() {
    const SLOTS: usize = 4;
    let mut net = Net::new(SLOTS);
    let mut seen = HashSet::new();
    let mut last_generation = 0;
    let mut previous: Vec<PeerId> = Vec::new();
    for round in 0..3u64 {
        let mut peers = Vec::new();
        let mut clients = Vec::new();
        for i in 0..SLOTS as u64 {
            let id = round * 100 + i + 1;
            let (c, peer) = net.connect_one(id);
            // generations only grow, across every slot
            assert!(peer.generation() > last_generation, "{peer:?}");
            last_generation = peer.generation();
            assert!(seen.insert(peer), "{peer:?} handed out twice");
            assert_eq!(net.server.client_id(peer), Some(id));
            peers.push(peer);
            clients.push(c);
        }
        let slots: HashSet<usize> = peers.iter().map(|p| p.slot()).collect();
        assert_eq!(slots, (0..SLOTS).collect(), "every slot is used each round");
        for old in &previous {
            let new = peers.iter().find(|p| p.slot() == old.slot()).unwrap();
            let id = net.server.client_id(*new).unwrap();
            assert_stale(&mut net, *old, Some((*new, id)));
        }
        // each client says something, and it is attributed to it alone
        for (i, &c) in clients.iter().enumerate() {
            net.clients[c].send(chat(), &[i as u8; 3]).unwrap();
        }
        assert!(net.run_until(|n| peers.iter().all(|p| !n.messages_from(*p).is_empty())));
        for (i, peer) in peers.iter().enumerate() {
            assert_eq!(net.messages_from(*peer), vec![vec![i as u8; 3]]);
        }
        for &c in &clients {
            net.clients[c].disconnect();
        }
        assert!(net.run_until(|n| {
            peers.iter().all(|p| {
                n.server_events.contains(&ServerEvent::Disconnected {
                    peer: *p,
                    reason: DisconnectReason::Remote,
                })
            }) && n.server.num_connected() == 0
        }));
        previous = peers;
    }
    for old in &previous {
        assert_stale(&mut net, *old, None);
    }
    assert_lifecycle_pairs(&net.server_events);
}

/// One server update both removes a slot's occupant and installs the next one there: the
/// leaver's disconnect packets and the joiner's connection response sit in the server's socket
/// together. The joiner's response is held back by a relay until then (the server answers a
/// response with "denied" while it is full), and the joiner got its challenge before the slot
/// filled.
#[test]
fn a_slot_vacated_and_refilled_in_one_update_keeps_the_sessions_apart() {
    let mut net = Net::new(1).with_relay();
    wait_past_second(net.server_started);
    // the joiner asks first and gets a challenge while the slot is free; its responses wait in
    // the relay
    let joiner_token = net.token_with(2, 30, 10, true);
    net.relay.as_mut().unwrap().hold = Some(3);
    let joiner = net.add_client(&joiner_token);
    assert!(net.run_until(|n| !n.relay.as_ref().unwrap().held.is_empty()));
    // now the leaver takes the slot, directly
    let leaver_token = net.token_with(1, 30, 10, false);
    let leaver = net.add_client(&leaver_token);
    assert!(net.run_until(|n| !n.connected_peers().is_empty()
        && n.clients[leaver].status() == ClientStatus::Connected));
    let old = net.connected_peers()[0];
    assert_eq!(net.server.client_id(old), Some(1));
    assert_eq!(net.clients[joiner].status(), ClientStatus::Connecting);

    // the leaver's last events and its disconnect, then the joiner's response, all queued at
    // the server before it next updates
    net.clients[leaver]
        .send(chat(), b"from the leaver")
        .unwrap();
    net.clients[leaver].send(moved(), b"leaver state").unwrap();
    net.clients[leaver].flush();
    net.clients[leaver].disconnect();
    net.relay.as_mut().unwrap().release_last_held();
    std::thread::sleep(Duration::from_millis(20));

    let before = net.server_events.len();
    net.update_server();
    let batch: Vec<_> = net.server_events[before..].to_vec();
    assert_eq!(
        batch,
        vec![ServerEvent::Disconnected {
            peer: old,
            reason: DisconnectReason::Remote
        }],
        "the leaver's session ends in this update, its events gone with it"
    );
    // the joiner was installed in the same update: the server's keep-alive is already on its
    // way, and netcode connects the joiner on it (given a moment to reach the relay: macOS and
    // Windows deliver loopback after sendto returns)
    std::thread::sleep(Duration::from_millis(20));
    net.pump_relay();
    assert!(
        net.relay
            .as_ref()
            .unwrap()
            .to_client
            .iter()
            .any(|d| packet_type(d) == 4),
        "the joiner was not installed in the update that removed the leaver"
    );
    assert_stale(&mut net, old, None);

    assert!(
        net.run_until(|n| n.connected_peers().len() == 2
            && n.clients[joiner].status() == ClientStatus::Connected)
    );
    let new = net.connected_peers()[1];
    assert_eq!(new.slot(), old.slot());
    assert_ne!(new, old);
    assert!(new.generation() > old.generation());
    assert_eq!(net.server.client_id(new), Some(2));
    assert_eq!(net.server.client_user_data(new), Some(&user_data(2)));
    assert_eq!(
        net.server.client_address(new),
        Some(net.relay.as_ref().unwrap().address())
    );
    // nothing the leaver sent is ever attributed to the joiner
    net.clients[joiner]
        .send(chat(), b"from the joiner")
        .unwrap();
    assert!(net.run_until(|n| !n.messages_from(new).is_empty()));
    net.run_for(0.2);
    assert_eq!(net.messages_from(new), vec![b"from the joiner".to_vec()]);
    // and the leaver's last events, in flight when it left, went with its session
    assert_eq!(net.messages_from(old), Vec::<Vec<u8>>::new());
    assert_stale(&mut net, old, Some((new, 2)));
    assert_lifecycle_pairs(&net.server_events);
}

#[test]
fn disconnect_all_then_drop_tell_every_client_once() {
    let mut net = Net::new(3);
    let (a, pa) = net.connect_one(1);
    let (b, pb) = net.connect_one(2);
    net.server.disconnect_all();
    // the handles are dead at once, before the records are polled
    assert_stale(&mut net, pa, None);
    assert_stale(&mut net, pb, None);
    net.step();
    for peer in [pa, pb] {
        let reports: Vec<_> = net
            .server_events
            .iter()
            .filter(|e| matches!(e, ServerEvent::Disconnected { peer: p, .. } if *p == peer))
            .collect();
        assert_eq!(
            reports,
            vec![&ServerEvent::Disconnected {
                peer,
                reason: DisconnectReason::Requested
            }]
        );
    }
    assert_eq!(net.server.num_connected(), 0);
    assert!(net.run_until(|n| [a, b].iter().all(|&c| n.ended(c).is_some())));
    for c in [a, b] {
        assert_eq!(
            net.ended(c),
            Some(ClientEvent::Disconnected {
                reason: DisconnectReason::Remote
            })
        );
        assert_eq!(net.clients[c].status(), ClientStatus::Disconnected);
    }
    // nothing more is reported for them
    net.run_for(0.3);
    assert_lifecycle_pairs(&net.server_events);

    // dropping a server with a live peer tells the client at once, not after its timeout
    let (c, _) = net.connect_one(3);
    let key = net.key;
    let placeholder = server(&key, localhost(), 1, 30);
    let dropped_at = Instant::now();
    drop(std::mem::replace(&mut net.server, placeholder));
    assert!(net.run_until(|n| n.ended(c).is_some()));
    assert_eq!(
        net.ended(c),
        Some(ClientEvent::Disconnected {
            reason: DisconnectReason::Remote
        })
    );
    assert!(
        dropped_at.elapsed() < Duration::from_secs(4),
        "it timed out"
    );
}

#[test]
fn dropping_a_connected_client_tells_the_server() {
    let mut net = Net::new(2);
    let (c, peer) = net.connect_one(1);
    let client = net.clients.remove(c);
    net.client_events.remove(c);
    let dropped_at = Instant::now();
    drop(client);
    assert!(net.run_until(|n| n.server.num_connected() == 0));
    assert!(
        dropped_at.elapsed() < Duration::from_secs(4),
        "it timed out"
    );
    assert!(net.server_events.contains(&ServerEvent::Disconnected {
        peer,
        reason: DisconnectReason::Remote
    }));
    assert_stale(&mut net, peer, None);
}

#[test]
fn time_that_goes_backwards_or_is_not_finite_is_ignored() {
    let mut net = Net::new(1);
    let (c, peer) = net.connect_one(1);
    let now = net.time();
    for time in [
        f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
        now - 100.0,
        -1.0,
    ] {
        net.server.update(time);
        net.clients[c].update(time);
    }
    net.server.flush();
    net.clients[c].flush();
    // both still keep time, so the session neither timed out nor stalled
    net.clients[c].send(chat(), b"still here").unwrap();
    net.server.send(peer, chat(), b"so am I").unwrap();
    assert!(net.run_until(|n| !n.messages_from(peer).is_empty() && n.client_got(c, b"so am I")));
    assert_eq!(net.clients[c].status(), ClientStatus::Connected);
    assert!(net.server_events.iter().all(|e| !matches!(
        e,
        ServerEvent::Disconnected { .. } | ServerEvent::Rejected { .. }
    )));

    // a server and a client created at a non-finite time start at 0
    let key = dream_net::generate_key();
    let mut odd = dream_net::Server::new(
        ServerConfig {
            public_address: localhost(),
            protocol_id: PROTOCOL,
            max_clients: 1,
            transport: TransportConfig::default(),
        },
        &key,
        test_schema(),
        f64::NAN,
    )
    .unwrap();
    odd.update(0.5);
    let mut client = Client::new(
        ClientConfig {
            bind_address: localhost(),
            transport: TransportConfig::default(),
        },
        test_schema(),
        f64::INFINITY,
    )
    .unwrap();
    client.update(0.5);
}

fn ipv6_available() -> bool {
    UdpSocket::bind("[::1]:0").is_ok()
}

#[test]
fn port_zero_and_ipv6_servers_advertise_what_they_bound() {
    let net = Net::new(1);
    assert_eq!(net.server.address().ip(), localhost().ip());
    assert_ne!(net.server.address().port(), 0);
    drop(net);

    if !ipv6_available() {
        eprintln!("no IPv6 loopback here: the IPv6 half of this test did not run");
        return;
    }
    let key = dream_net::generate_key();
    let v6: SocketAddr = "[::1]:0".parse().unwrap();
    let mut net = Net::on(key, server(&key, v6, 2, 30), 2);
    assert_eq!(net.server.address().ip(), v6.ip());
    assert_ne!(net.server.address().port(), 0);
    wait_past_second(net.server_started);
    let token = net.token_with(6, 30, 5, false);
    let c = net.clients.len();
    let mut client = Client::new(
        ClientConfig {
            bind_address: v6,
            transport: TransportConfig::default(),
        },
        test_schema(),
        0.0,
    )
    .unwrap();
    client.connect(&token).unwrap();
    net.clients.push(client);
    net.client_events.push(Vec::new());
    assert!(net.run_until(
        |n| !n.connected_peers().is_empty() && n.clients[c].status() == ClientStatus::Connected
    ));
    let peer = net.connected_peers()[0];
    assert_eq!(net.server.client_address(peer).unwrap().ip(), v6.ip());
    assert_eq!(net.clients[c].server_address(), Some(net.server.address()));
    net.server.send(peer, chat(), b"over v6").unwrap();
    assert!(net.run_until(|n| n.client_got(c, b"over v6")));

    // an IPv4 client cannot use a token that lists only IPv6 servers: refused at connect
    let mut v4 = Client::new(
        ClientConfig {
            bind_address: localhost(),
            transport: TransportConfig::default(),
        },
        test_schema(),
        0.0,
    )
    .unwrap();
    let refused = v4.connect(&net.token_with(7, 30, 5, false)).unwrap_err();
    assert!(
        matches!(refused, Error::Netcode(NetcodeError::InvalidConnectToken)),
        "{refused:?}"
    );
    assert_eq!(
        v4.poll(),
        Some(ClientEvent::ConnectFailed {
            reason: DisconnectReason::Authentication,
            failure: None
        })
    );
    assert_eq!(v4.status(), ClientStatus::Disconnected);
}

#[test]
fn creation_errors_are_netcode_errors() {
    let key = dream_net::generate_key();
    let config = |address: SocketAddr, max_clients| ServerConfig {
        public_address: address,
        protocol_id: PROTOCOL,
        max_clients,
        transport: TransportConfig::default(),
    };
    // a port in use
    let first = dream_net::Server::new(config(localhost(), 1), &key, test_schema(), 0.0).unwrap();
    let taken = first.address();
    let refused = dream_net::Server::new(config(taken, 1), &key, test_schema(), 0.0).unwrap_err();
    match &refused {
        Error::Netcode(NetcodeError::Io(io)) => assert_eq!(io.kind(), ErrorKind::AddrInUse),
        other => panic!("{other:?}"),
    }
    assert!(
        refused.to_string().starts_with("netcode: socket error: "),
        "{refused}"
    );
    // a socket some other program holds on that port
    let other = UdpSocket::bind("0.0.0.0:0").unwrap();
    let port = other.local_addr().unwrap().port();
    let refused = dream_net::Server::new(
        config(SocketAddr::new(localhost().ip(), port), 1),
        &key,
        test_schema(),
        0.0,
    )
    .unwrap_err();
    assert!(
        matches!(&refused, Error::Netcode(NetcodeError::Io(io)) if io.kind() == ErrorKind::AddrInUse),
        "{refused:?}"
    );
    // slot counts
    for max_clients in [0, 257, usize::MAX] {
        let refused =
            dream_net::Server::new(config(localhost(), max_clients), &key, test_schema(), 0.0)
                .unwrap_err();
        assert!(
            matches!(refused, Error::Netcode(NetcodeError::InvalidMaxClients(n)) if n == max_clients),
            "{refused:?}"
        );
    }
    for max_clients in [1, 256] {
        let server =
            dream_net::Server::new(config(localhost(), max_clients), &key, test_schema(), 0.0)
                .unwrap();
        assert_eq!(server.max_clients(), max_clients);
    }
    // a client bind address in use
    let refused = Client::new(
        ClientConfig {
            bind_address: other.local_addr().unwrap(),
            transport: TransportConfig::default(),
        },
        test_schema(),
        0.0,
    )
    .unwrap_err();
    assert!(
        matches!(&refused, Error::Netcode(NetcodeError::Io(_))),
        "{refused:?}"
    );
}

/// netcode checks a token against the server's public address byte for byte. An unspecified
/// public address binds, but a token naming it sends the client to an address replies cannot
/// come from, and a token naming a concrete address does not match the server's own: nobody
/// can connect. Each attempt times out (the token's timeout), and the server sees nothing.
#[test]
fn an_unspecified_public_address_binds_but_admits_nobody() {
    let key = dream_net::generate_key();
    let unspecified: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let mut net = Net::on(key, server(&key, unspecified, 2, 30), 2);
    let bound = net.server.address();
    assert!(bound.ip().is_unspecified());
    assert_ne!(bound.port(), 0);
    wait_past_second(net.server_started);
    let concrete = SocketAddr::new(localhost().ip(), bound.port());
    let mut attempts = Vec::new();
    for (id, address) in [(1, bound), (2, concrete)] {
        let token = dream_net::generate_connect_token(
            &[address],
            &[address],
            30,
            1,
            id,
            PROTOCOL,
            &key,
            &user_data(id),
        )
        .unwrap();
        attempts.push(net.add_client(&token));
    }
    assert!(net.run_until(|n| attempts.iter().all(|&c| n.ended(c).is_some())));
    for c in attempts {
        assert_eq!(
            net.ended(c),
            Some(ClientEvent::ConnectFailed {
                reason: DisconnectReason::TimedOut,
                failure: None
            })
        );
    }
    assert!(net.server_events.is_empty(), "{:?}", net.server_events);
}
