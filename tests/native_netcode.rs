//! The netcode binding over real loopback sockets: connection, payloads, every client state,
//! every disconnect reason, slot bookkeeping and lifecycle. Every server binds port 0.

// CI passes -W clippy::pedantic on the command line, overriding the manifest's lint table;
// test code casts freely between widths it controls.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::too_many_lines
)]

mod native_netcode_support;

use std::io;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket};

use dream_net::native::netcode::{
    Client, ClientState, DisconnectReason, Error, MAX_CLIENTS, MAX_PAYLOAD_BYTES, Server,
    ServerEvent, ServerOptions, generate_connect_token, generate_key,
};
use native_netcode_support::{
    LONG_LIFETIME, PROTOCOL, World, await_loopback, ipv6_available, localhost, localhost_v6, token,
    token_with, user_data_for, wait_until,
};

fn connected(client_index: usize) -> ServerEvent {
    ServerEvent::ClientConnected { client_index }
}

fn disconnected(client_index: usize, reason: DisconnectReason) -> ServerEvent {
    ServerEvent::ClientDisconnected {
        client_index,
        reason,
    }
}

fn payload(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31) ^ seed)
        .collect()
}

/// Connects one client and exchanges payloads of 1 and 1200 bytes both ways.
fn connect_and_exchange(address: SocketAddr) {
    let mut world = World::on(address, 4);
    assert_eq!(world.server.address().ip(), address.ip());
    assert_ne!(world.server.port(), 0, "port 0 reports the bound port");
    assert_eq!(world.server.port(), world.server.address().port());
    assert!(world.server.running());
    assert_eq!(world.server.max_clients(), 4);

    let c = world.add_client(0x00C0_FFEE);
    assert_eq!(
        world.clients[c].state(),
        ClientState::SendingConnectionRequest
    );
    assert_eq!(
        world.clients[c].server_address(),
        Some(world.server.address())
    );
    world.connect_all();
    assert_eq!(world.take_events(), vec![connected(0)]);

    let client_address = SocketAddr::new(address.ip(), world.clients[c].port());
    assert_eq!(world.server.client_id(0), 0x00C0_FFEE);
    assert_eq!(world.server.client_address(0), Some(client_address));
    assert_eq!(
        world.server.client_user_data(0),
        Some(&user_data_for(0x00C0_FFEE))
    );
    assert!(world.server.client_connected(0));
    assert_eq!(world.server.num_connected_clients(), 1);
    assert_eq!(world.clients[c].client_index(), 0);
    assert_eq!(world.clients[c].max_clients(), 4);

    for (len, seed) in [(1usize, 1u8), (MAX_PAYLOAD_BYTES, 2), (500, 3)] {
        let to_server = payload(len, seed);
        let to_client = payload(len, !seed);
        let client_sequence = world.clients[c].next_packet_sequence();
        let server_sequence = world.server.next_packet_sequence(0);
        world.clients[c].send_packet(&to_server).unwrap();
        world.server.send_packet(0, &to_client).unwrap();
        assert!(world.clients[c].next_packet_sequence() > client_sequence);
        assert!(world.server.next_packet_sequence(0) > server_sequence);
        let mut got_server = None;
        let mut got_client = None;
        for _ in 0..100 {
            world.step();
            if got_server.is_none() {
                got_server = world.server.receive_packet(0);
            }
            if got_client.is_none() {
                got_client = world.clients[c].receive_packet();
            }
            if got_server.is_some() && got_client.is_some() {
                break;
            }
        }
        let (data, sequence) = got_server.expect("the server received the payload");
        assert_eq!(data, to_server);
        assert_eq!(sequence, client_sequence);
        let (data, _) = got_client.expect("the client received the payload");
        assert_eq!(data, to_client);
    }
}

#[test]
fn an_encrypted_ipv4_connection_carries_payloads_both_ways() {
    connect_and_exchange(localhost());
}

#[test]
fn an_encrypted_ipv6_connection_carries_payloads_both_ways() {
    if !ipv6_available() {
        return;
    }
    connect_and_exchange(localhost_v6());
}

#[test]
fn payloads_of_zero_and_over_1200_bytes_are_refused_in_every_state() {
    let mut world = World::new(2);
    let c = world.add_client(1);
    let too_big = vec![0u8; MAX_PAYLOAD_BYTES + 1];
    // connecting
    assert!(matches!(
        world.clients[c].send_packet(&[]),
        Err(Error::InvalidPayloadSize(0))
    ));
    assert!(matches!(
        world.clients[c].send_packet(&too_big),
        Err(Error::InvalidPayloadSize(1201))
    ));
    // a valid size while not connected is a quiet no-op
    world.clients[c].send_packet(&[1]).unwrap();
    // empty slot
    assert!(matches!(
        world.server.send_packet(1, &[]),
        Err(Error::InvalidPayloadSize(0))
    ));
    world.server.send_packet(1, &[1]).unwrap();
    world.server.send_packet(MAX_CLIENTS + 7, &[1]).unwrap();
    world.connect_all();
    assert!(matches!(
        world.server.send_packet(0, &too_big),
        Err(Error::InvalidPayloadSize(1201))
    ));
    assert!(matches!(
        world.server.send_packet(0, &[]),
        Err(Error::InvalidPayloadSize(0))
    ));
    assert!(matches!(
        world.clients[c].send_packet(&[]),
        Err(Error::InvalidPayloadSize(0))
    ));
    // nothing was delivered by any of the refusals
    for _ in 0..10 {
        world.step();
    }
    assert_eq!(world.server.receive_packet(0), None);
    assert_eq!(world.clients[c].receive_packet(), None);
}

#[test]
fn receive_into_reuses_one_buffer() {
    let mut world = World::new(1);
    let c = world.add_client(5);
    world.connect_all();
    let mut buffer = Vec::with_capacity(MAX_PAYLOAD_BYTES);
    let capacity = buffer.capacity();
    let pointer = buffer.as_ptr();
    let sizes = [1usize, 1200, 7, 300, 1200, 2];
    for (i, len) in sizes.iter().enumerate() {
        world.clients[c]
            .send_packet(&payload(*len, i as u8))
            .unwrap();
        world
            .server
            .send_packet(0, &payload(*len, !(i as u8)))
            .unwrap();
    }
    world.step();
    world.step();
    for (i, len) in sizes.iter().enumerate() {
        let sequence = world.server.receive_packet_into(0, &mut buffer);
        assert!(sequence.is_some());
        assert_eq!(buffer, payload(*len, i as u8));
        assert_eq!(buffer.capacity(), capacity);
        assert_eq!(buffer.as_ptr(), pointer, "no reallocation");
    }
    assert_eq!(world.server.receive_packet_into(0, &mut buffer), None);
    assert!(buffer.is_empty(), "None leaves the buffer empty");
    for (i, len) in sizes.iter().enumerate() {
        assert!(world.clients[c].receive_packet_into(&mut buffer).is_some());
        assert_eq!(buffer, payload(*len, !(i as u8)));
        assert_eq!(buffer.as_ptr(), pointer, "no reallocation");
    }
    assert_eq!(world.clients[c].receive_packet_into(&mut buffer), None);
    assert_eq!(buffer, Vec::<u8>::new());
    // out of range and empty slots
    assert_eq!(world.server.receive_packet_into(1, &mut buffer), None);
    assert_eq!(
        world.server.receive_packet_into(usize::MAX, &mut buffer),
        None
    );
}

/// A client with `token` against a running one-slot server; returns the state it settles in.
fn settle_with(world: &mut World, token: &[u8; 2048]) -> ClientState {
    let mut client = Client::new(localhost(), world.time).unwrap();
    client.connect(token).unwrap();
    world.clients.push(client);
    let index = world.clients.len() - 1;
    world.settle(index)
}

#[test]
fn bad_tokens_end_in_the_matching_client_state_and_connect_nobody() {
    let mut world = World::new(2);
    let address = world.server.address();
    let user_data = user_data_for(1);

    // wrong protocol id: the server never answers
    let wrong_protocol = generate_connect_token(
        &[address],
        &[address],
        LONG_LIFETIME,
        1,
        1,
        PROTOCOL ^ 1,
        &world.key,
        &user_data,
    )
    .unwrap();
    assert_eq!(
        settle_with(&mut world, &wrong_protocol),
        ClientState::ConnectionRequestTimedOut
    );

    // wrong key: the private part does not decrypt
    let wrong_key = generate_connect_token(
        &[address],
        &[address],
        LONG_LIFETIME,
        1,
        2,
        PROTOCOL,
        &generate_key(),
        &user_data,
    )
    .unwrap();
    assert_eq!(
        settle_with(&mut world, &wrong_key),
        ClientState::ConnectionRequestTimedOut
    );

    // a token for another server: the client reaches this server (public address), but the
    // encrypted list (internal address) names another one
    let elsewhere: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let other_server = generate_connect_token(
        &[address],
        &[elsewhere],
        LONG_LIFETIME,
        1,
        3,
        PROTOCOL,
        &world.key,
        &user_data,
    )
    .unwrap();
    assert_eq!(
        settle_with(&mut world, &other_server),
        ClientState::ConnectionRequestTimedOut
    );

    // expired: a zero lifetime expires on the client's first update, and the server would
    // refuse it as expired too (expire <= now)
    let expired = token_with(address, &world.key, 4, 0, 1);
    assert_eq!(
        settle_with(&mut world, &expired),
        ClientState::ConnectTokenExpired
    );

    // garbage: refused by connect itself
    let mut client = Client::new(localhost(), 0.0).unwrap();
    let garbage = [0xA5u8; 2048];
    assert!(matches!(
        client.connect(&garbage),
        Err(Error::InvalidConnectToken)
    ));
    assert_eq!(client.state(), ClientState::InvalidConnectToken);
    assert!(client.state().is_error() && client.state().is_disconnected());
    // a valid token whose version string is damaged
    let mut damaged = token(&world.server, &world.key, 5);
    damaged[0] = b'X';
    assert!(matches!(
        client.connect(&damaged),
        Err(Error::InvalidConnectToken)
    ));

    world.drain();
    assert!(world.events.is_empty(), "{:?}", world.events);
    assert_eq!(world.server.num_connected_clients(), 0);
}

#[test]
fn a_token_with_no_address_of_the_clients_family_is_invalid() {
    if !ipv6_available() {
        return;
    }
    let key = generate_key();
    let v6: SocketAddr = "[::1]:40000".parse().unwrap();
    let token = token_with(v6, &key, 1, LONG_LIFETIME, 5);
    let mut client = Client::new(localhost(), 0.0).unwrap();
    assert!(matches!(
        client.connect(&token),
        Err(Error::InvalidConnectToken)
    ));
    assert_eq!(client.state(), ClientState::InvalidConnectToken);
}

#[test]
fn a_used_token_is_refused_on_reconnect_from_any_address() {
    let mut world = World::new(4);
    let token = token(&world.server, &world.key, 77);
    let mut first = Client::new(localhost(), 0.0).unwrap();
    first.connect(&token).unwrap();
    world.clients.push(first);
    world.connect_all();
    assert_eq!(world.take_events(), vec![connected(0)]);

    // same socket, same token, after a clean disconnect
    world.clients[0].disconnect();
    world.clients[0].disconnect(); // twice is harmless
    assert_eq!(world.clients[0].state(), ClientState::Disconnected);
    for _ in 0..5 {
        world.step();
    }
    assert_eq!(
        world.take_events(),
        vec![disconnected(0, DisconnectReason::ClientDisconnect)]
    );
    // the same client connects with the token again: the server never answers, and the
    // attempt times out after the token's 5-second timeout
    world.clients[0].connect(&token).unwrap();
    assert_eq!(world.settle(0), ClientState::ConnectionRequestTimedOut);

    // another socket, same token: refused too
    assert_eq!(
        settle_with(&mut world, &token),
        ClientState::ConnectionRequestTimedOut
    );

    assert_eq!(world.take_events(), Vec::new());
    assert_eq!(world.server.num_connected_clients(), 0);
}

#[test]
fn a_full_server_denies_the_next_client() {
    let mut world = World::new(1);
    world.add_client(1);
    world.connect_all();
    world.add_client(2);
    assert_eq!(world.settle(1), ClientState::ConnectionDenied);
    assert!(world.clients[1].state().is_error());
    assert_eq!(world.take_events(), vec![connected(0)]);
    assert_eq!(world.server.client_id(0), 1);
}

#[test]
fn every_disconnect_reason_is_reported() {
    let mut world = World::new(3);
    world.add_client(10);
    world.add_client(11);
    world.add_client(12);
    world.connect_all();
    let mut by_slot = [0u64; 3];
    for (slot, id) in by_slot.iter_mut().enumerate() {
        *id = world.server.client_id(slot);
    }
    let slot_of = |id: u64| by_slot.iter().position(|s| *s == id).unwrap();
    world.take_events();

    // the client leaves
    world.clients[0].disconnect();
    await_loopback();
    world.step();
    assert_eq!(
        world.take_events(),
        vec![disconnected(
            slot_of(10),
            DisconnectReason::ClientDisconnect
        )]
    );

    // the server disconnects it: the client ends Disconnected (C: no next server, D8)
    world.server.disconnect_client(slot_of(11));
    assert_eq!(
        world.take_events(),
        vec![disconnected(
            slot_of(11),
            DisconnectReason::ServerDisconnect
        )]
    );
    world.pump_until("client 11 sees the disconnect", |w| {
        w.clients[1].state() == ClientState::Disconnected
    });

    // the client goes silent: the server times it out after the token's 5 s
    let silent = world.clients.remove(2);
    world.pump_until("client 12 times out", |w| !w.events.is_empty());
    assert_eq!(
        world.take_events(),
        vec![disconnected(slot_of(12), DisconnectReason::TimedOut)]
    );
    assert_eq!(silent.state(), ClientState::Connected, "it never noticed");
    assert_eq!(world.server.num_connected_clients(), 0);
}

#[test]
fn a_client_times_out_when_the_server_goes_silent() {
    let mut world = World::new(1);
    world.add_client(1);
    world.connect_all();
    let mut time = world.time;
    for _ in 0..1000 {
        time += 0.01;
        world.clients[0].update(time);
        if world.clients[0].state() != ClientState::Connected {
            break;
        }
    }
    assert_eq!(world.clients[0].state(), ClientState::ConnectionTimedOut);
}

#[test]
fn disconnect_all_clients_reports_every_slot() {
    let mut world = World::new(4);
    for id in 1..=3 {
        world.add_client(id);
    }
    world.connect_all();
    world.take_events();
    world.server.disconnect_all_clients();
    let mut events = world.take_events();
    events.sort_by_key(|e| match e {
        ServerEvent::ClientConnected { client_index }
        | ServerEvent::ClientDisconnected { client_index, .. } => *client_index,
    });
    assert_eq!(
        events,
        (0..3)
            .map(|i| disconnected(i, DisconnectReason::ServerDisconnect))
            .collect::<Vec<_>>()
    );
    world.pump_until("clients see it", |w| {
        w.clients
            .iter()
            .all(|c| c.state() == ClientState::Disconnected)
    });
    // nothing more, and again is a no-op
    world.server.disconnect_all_clients();
    world.server.disconnect_client(0);
    world.server.disconnect_client(MAX_CLIENTS);
    world.server.disconnect_client(usize::MAX);
    assert_eq!(world.take_events(), Vec::new());
}

#[test]
fn churn_across_every_slot_reports_each_session_in_order_with_its_identity() {
    const SLOTS: usize = 6;
    let mut world = World::new(SLOTS);
    let mut next_id = 1000u64;
    // per slot: the identity the last Connected reported, and whether it is open
    let mut open: Vec<Option<(u64, SocketAddr)>> = vec![None; SLOTS];
    for round in 0..4 {
        let first = world.clients.len();
        for _ in 0..SLOTS {
            world.add_client(next_id);
            next_id += 1;
        }
        world.pump_until("round connected", |w| {
            w.clients[first..]
                .iter()
                .all(|c| c.state() == ClientState::Connected)
        });
        for event in world.take_events() {
            let ServerEvent::ClientConnected { client_index } = event else {
                panic!("round {round}: unexpected {event:?}");
            };
            assert!(open[client_index].is_none(), "Connected twice in a row");
            let id = world.server.client_id(client_index);
            let address = world.server.client_address(client_index).unwrap();
            assert_eq!(
                world.server.client_user_data(client_index),
                Some(&user_data_for(id))
            );
            let owner = world.clients[first..]
                .iter()
                .find(|c| c.client_index() == client_index)
                .unwrap();
            assert_eq!(address.port(), owner.port());
            open[client_index] = Some((id, address));
        }
        assert!(open.iter().all(Option::is_some), "round {round}: {open:?}");
        // half leave by themselves, half are kicked
        for (i, client) in world.clients[first..].iter_mut().enumerate() {
            if i % 2 == 0 {
                client.disconnect();
            }
        }
        for slot in 0..SLOTS {
            if slot % 2 == 1 {
                world.server.disconnect_client(slot);
            }
        }
        world.pump_until("round emptied", |w| w.server.num_connected_clients() == 0);
        for event in world.take_events() {
            let ServerEvent::ClientDisconnected { client_index, .. } = event else {
                panic!("round {round}: unexpected {event:?}");
            };
            assert!(open[client_index].take().is_some(), "Disconnected twice");
            assert_eq!(world.server.client_id(client_index), 0);
            assert_eq!(world.server.client_address(client_index), None);
            assert_eq!(world.server.client_user_data(client_index), None);
        }
        assert!(open.iter().all(Option::is_none));
        world.clients.drain(first..);
    }
}

#[test]
fn a_slot_reused_inside_one_update_reports_both_transitions() {
    let mut world = World::new(1);
    let key = world.key;
    // B gets its challenge first, then holds its response: a client only sends once its last
    // send is more than 0.1 s old.
    let mut b = Client::new(localhost(), 0.0).unwrap();
    b.connect(&token(&world.server, &key, 2)).unwrap();
    let t0 = 1.0;
    b.update(t0); // sends the request
    world.time = t0;
    // the server answers with a challenge, and B takes it, too soon to send the response; the
    // clock stands still while the datagrams cross loopback (see native_netcode_support)
    wait_until("B takes the challenge", || {
        world.server.update(t0);
        b.update(t0);
        b.state() != ClientState::SendingConnectionRequest
    });
    assert_eq!(b.state(), ClientState::SendingConnectionResponse);

    // A connects into the only slot
    world.add_client(1);
    world.connect_all();
    assert_eq!(world.take_events(), vec![connected(0)]);
    assert_eq!(world.server.client_id(0), 1);

    // A's disconnect packets, then B's response, all in the socket before one server update
    world.clients[0].disconnect();
    b.update(world.time + 0.2);
    world.time += 0.2;
    await_loopback();
    world.server.update(world.time);
    assert_eq!(world.server.num_connected_clients(), 1);
    assert_eq!(
        world.take_events(),
        vec![
            disconnected(0, DisconnectReason::ClientDisconnect),
            connected(0)
        ]
    );
    assert_eq!(world.server.client_id(0), 2, "the identity is B's");
    assert_eq!(world.server.client_user_data(0), Some(&user_data_for(2)));
    assert_eq!(
        world.server.client_address(0).map(|a| a.port()),
        Some(b.port())
    );
}

#[test]
fn stop_disconnects_everyone_and_the_server_can_start_again() {
    let mut world = World::new(2);
    world.add_client(1);
    world.add_client(2);
    world.connect_all();
    world.take_events();

    world.server.stop();
    assert!(!world.server.running());
    assert_eq!(world.server.max_clients(), 0);
    assert_eq!(world.server.num_connected_clients(), 0);
    let mut events = world.take_events();
    events.sort_by_key(|e| format!("{e:?}"));
    assert_eq!(
        events,
        vec![
            disconnected(0, DisconnectReason::ServerDisconnect),
            disconnected(1, DisconnectReason::ServerDisconnect)
        ]
    );
    // every operation after stop is a quiet no-op
    world.server.stop();
    world.server.update(world.time + 1.0);
    world.server.send_packet(0, &[1]).unwrap();
    assert!(world.server.receive_packet(0).is_none());
    world.server.disconnect_client(0);
    world.server.disconnect_all_clients();
    assert_eq!(world.server.client_id(0), 0);
    assert!(!world.server.client_connected(0));
    assert_eq!(world.server.next_packet_sequence(0), 0);
    assert_eq!(world.take_events(), Vec::new());
    world.pump_until("clients disconnected", |w| {
        w.clients
            .iter()
            .all(|c| c.state() == ClientState::Disconnected)
    });

    // refused restarts leave it stopped
    assert!(matches!(
        world.server.start(0),
        Err(Error::InvalidMaxClients(0))
    ));
    assert!(matches!(
        world.server.start(MAX_CLIENTS + 1),
        Err(Error::InvalidMaxClients(257))
    ));
    assert!(!world.server.running());

    world.server.start(3).unwrap();
    assert_eq!(world.server.max_clients(), 3);
    world.clients.clear();
    world.add_client(3);
    world.connect_all();
    assert_eq!(world.take_events(), vec![connected(0)]);

    // start while running restarts: everyone is disconnected first
    world.server.start(2).unwrap();
    assert_eq!(
        world.take_events(),
        vec![disconnected(0, DisconnectReason::ServerDisconnect)]
    );
    assert_eq!(world.server.max_clients(), 2);
}

#[test]
fn dropping_either_side_first_is_clean() {
    // the server first, with clients connected: they hear its disconnect packets
    let mut world = World::new(2);
    world.add_client(1);
    world.add_client(2);
    world.connect_all();
    let World {
        server,
        mut clients,
        mut time,
        ..
    } = world;
    drop(server);
    for _ in 0..10 {
        time += 0.01;
        for c in &mut clients {
            c.update(time);
        }
    }
    assert!(
        clients
            .iter()
            .all(|c| c.state() == ClientState::Disconnected)
    );
    drop(clients);

    // the clients first: the server hears theirs
    let mut world = World::new(2);
    world.add_client(1);
    world.add_client(2);
    world.connect_all();
    world.take_events();
    world.clients.clear();
    await_loopback();
    world.step();
    assert_eq!(
        world.take_events(),
        vec![
            disconnected(0, DisconnectReason::ClientDisconnect),
            disconnected(1, DisconnectReason::ClientDisconnect)
        ]
    );
    drop(world);

    // a connecting client, an idle server, a never-started server
    let key = generate_key();
    let server = Server::new(localhost(), PROTOCOL, &key, 0.0).unwrap();
    let mut client = Client::new(localhost(), 0.0).unwrap();
    client
        .connect(&token_with(server.address(), &key, 1, LONG_LIFETIME, 5))
        .unwrap();
    client.update(0.5);
    drop(client);
    drop(server);
}

#[test]
fn client_lifecycle_calls_are_safe_in_any_order() {
    let mut world = World::new(2);
    let c = world.add_client(1);
    world.connect_all();
    assert_eq!(world.take_events(), vec![connected(0)]);
    // connect while connected ends the session first
    let again = token(&world.server, &world.key, 2);
    world.clients[c].connect(&again).unwrap();
    assert_eq!(
        world.clients[c].state(),
        ClientState::SendingConnectionRequest
    );
    world.connect_all();
    let events = world.take_events();
    assert_eq!(
        events[0],
        disconnected(0, DisconnectReason::ClientDisconnect)
    );
    assert_eq!(events.len(), 2);
    let ServerEvent::ClientConnected { client_index } = events[1] else {
        panic!("{events:?}")
    };
    assert_eq!(world.server.client_id(client_index), 2);

    world.clients[c].disconnect();
    world.clients[c].disconnect();
    world.clients[c].update(world.time); // time unchanged
    world.clients[c].update(world.time - 5.0); // time going backwards is clamped
    world.clients[c].update(f64::NAN);
    assert_eq!(world.clients[c].state(), ClientState::Disconnected);
    assert_eq!(world.clients[c].server_address(), None);
    assert_eq!(world.clients[c].client_index(), 0);
    assert!(world.clients[c].receive_packet().is_none());
    world.clients[c].send_packet(&[1, 2, 3]).unwrap();
}

/// No other socket can take the datagrams sent to a running server's or client's address. Linux
/// and macOS refuse any later bind on the port by default. Windows allows one unless the first
/// socket claimed the port with `SO_EXCLUSIVEADDRUSE` (patch 0002), and even then still lets a
/// wildcard socket share the port of a socket bound to one address; that socket only receives
/// what is sent to the machine's other addresses, never what netcode's socket was bound for.
#[test]
fn a_bound_port_cannot_be_taken_afterwards() {
    let server = Server::new(localhost(), PROTOCOL, &generate_key(), 0.0).unwrap();
    let client = Client::new(localhost(), 0.0).unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    // the server holds 0.0.0.0:<port>, the client 127.0.0.1:<port>
    for (port, bound_to_one_address) in [(server.port(), false), (client.port(), true)] {
        for address in ["127.0.0.1", "0.0.0.0"] {
            match UdpSocket::bind((address, port)) {
                Err(error) => {
                    // Windows refuses with WSAEACCES or WSAEADDRINUSE, depending on the
                    // addresses involved; elsewhere it is EADDRINUSE
                    let refused = if cfg!(windows) {
                        matches!(
                            error.kind(),
                            io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied
                        )
                    } else {
                        error.kind() == io::ErrorKind::AddrInUse
                    };
                    assert!(refused, "{address}:{port}: {error}");
                }
                Ok(intruder) => {
                    assert!(
                        cfg!(windows) && bound_to_one_address && address == "0.0.0.0",
                        "a second socket bound {address}:{port}, which netcode holds"
                    );
                    // and it receives nothing sent to the address netcode's socket holds
                    intruder.set_nonblocking(true).unwrap();
                    sender.send_to(b"for netcode", ("127.0.0.1", port)).unwrap();
                    await_loopback();
                    let mut buffer = [0u8; 64];
                    assert_eq!(
                        intruder.recv_from(&mut buffer).map_err(|e| e.kind()).err(),
                        Some(io::ErrorKind::WouldBlock),
                        "a wildcard socket took a datagram sent to netcode's address"
                    );
                }
            }
        }
    }
}

#[test]
fn creation_errors_are_reported() {
    let key = generate_key();
    // a port already taken: by a wildcard socket, or by one bound to a single address (the
    // server binds 0.0.0.0:<port> whatever address it is given; on Windows only patch 0002's
    // SO_EXCLUSIVEADDRUSE refuses the second case)
    for holder in ["0.0.0.0:0", "127.0.0.1:0"] {
        let taken = UdpSocket::bind(holder).unwrap();
        let port = taken.local_addr().unwrap().port();
        let Err(Error::Io(error)) = Server::new(
            SocketAddr::from(([127, 0, 0, 1], port)),
            PROTOCOL,
            &key,
            0.0,
        ) else {
            panic!("binding a port taken on {holder} must fail");
        };
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse, "{holder}: {error}");
    }
    // the client binds exactly the address it is given
    let taken = UdpSocket::bind("127.0.0.1:0").unwrap();
    let Err(Error::Io(error)) = Client::new(taken.local_addr().unwrap(), 0.0) else {
        panic!("binding a taken port must fail");
    };
    assert_eq!(error.kind(), io::ErrorKind::AddrInUse, "{error}");

    // a scope id cannot be bound by netcode
    let scoped = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 1));
    let Err(Error::Io(error)) = Client::new(scoped, 0.0) else {
        panic!("a scoped bind address must be refused");
    };
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);

    // lifetimes outside 1..=i32::MAX
    for bad in [0u32, u32::MAX, i32::MAX as u32 + 1] {
        let options = ServerOptions::default().with_max_connect_token_lifetime(bad);
        assert!(matches!(
            Server::with_options(localhost(), PROTOCOL, &key, 0.0, options),
            Err(Error::InvalidConnectTokenLifetime(n)) if n == bad
        ));
    }
    let options = ServerOptions::default().with_max_connect_token_lifetime(i32::MAX as u32);
    let server = Server::with_options(localhost(), PROTOCOL, &key, 0.0, options).unwrap();
    assert_eq!(server.options(), options);
    assert_eq!(
        Server::new(localhost(), PROTOCOL, &key, 0.0)
            .unwrap()
            .options(),
        ServerOptions::default()
    );
    assert_eq!(ServerOptions::default().max_connect_token_lifetime, 30);

    // token address lists
    let one = [localhost()];
    let data = user_data_for(1);
    for (public, internal) in [
        (&[][..], &[][..]),
        (&one[..], &[][..]),
        (&[localhost(); 33][..], &[localhost(); 33][..]),
    ] {
        assert!(matches!(
            generate_connect_token(public, internal, 10, 5, 1, PROTOCOL, &key, &data),
            Err(Error::InvalidServerAddresses)
        ));
    }
    generate_connect_token(
        &[localhost(); 32],
        &[localhost(); 32],
        10,
        5,
        1,
        PROTOCOL,
        &key,
        &data,
    )
    .unwrap();
}

#[test]
fn an_ipv6_server_reports_a_scope_free_address() {
    if !ipv6_available() {
        return;
    }
    let key = generate_key();
    let scoped = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 5, 0));
    let server = Server::new(scoped, PROTOCOL, &key, 0.0).unwrap();
    let SocketAddr::V6(address) = server.address() else {
        panic!()
    };
    assert_eq!(address.scope_id(), 0);
    assert_eq!(address.flowinfo(), 0);
    assert_ne!(address.port(), 0);
}

#[test]
fn keys_tokens_and_endpoints_work_from_many_threads_at_once() {
    let threads: Vec<_> = (0..8u64)
        .map(|n| {
            std::thread::spawn(move || {
                let mut keys = Vec::new();
                for _ in 0..50 {
                    keys.push(generate_key());
                }
                let mut world = World::new(1);
                world.add_client(n);
                world.connect_all();
                assert_eq!(world.server.client_id(0), n);
                keys
            })
        })
        .collect();
    let mut all = std::collections::HashSet::new();
    for thread in threads {
        for key in thread.join().unwrap() {
            assert!(all.insert(key), "a key repeated");
        }
    }
}
