//! The netcode binding's auto traits, pinned at compile time, and `Debug` output that never
//! shows key material.
//!
//! `Server` and `Client` own raw C objects and are deliberately neither `Send` nor `Sync`
//! (dream-net's own `Server` and `Client` never were); the data types are `Send + Sync`. If a
//! change gives the handles `Send` or `Sync`, or takes them from the data types, this file stops
//! compiling.

mod native_netcode_support;

use dream_net::native::netcode::{
    Client, ClientState, DisconnectReason, Error, Server, ServerEvent, ServerOptions,
};
use native_netcode_support::World;
use std::fmt::Write as _;

/// Implemented for every type through the first impl; the second applies only to `Send` types.
/// Naming `<T as NotSend<_>>::CHECK` is ambiguous, and fails to compile, exactly when `T: Send`.
trait NotSend<A> {
    const CHECK: () = ();
}
impl<T: ?Sized> NotSend<()> for T {}
impl<T: ?Sized + Send> NotSend<u8> for T {}

/// The same for `Sync`.
#[allow(dead_code)] // as above
trait NotSync<A> {
    const CHECK: () = ();
}
impl<T: ?Sized> NotSync<()> for T {}
impl<T: ?Sized + Sync> NotSync<u8> for T {}

const _: () = <Server as NotSend<_>>::CHECK;
const _: () = <Server as NotSync<_>>::CHECK;
const _: () = <Client as NotSend<_>>::CHECK;
const _: () = <Client as NotSync<_>>::CHECK;

fn send_sync<T: Send + Sync + 'static>() {}
fn unpin<T: Unpin>() {}

#[test]
fn data_types_are_send_and_sync_and_handles_are_unpin() {
    send_sync::<Error>();
    send_sync::<ClientState>();
    send_sync::<ServerEvent>();
    send_sync::<DisconnectReason>();
    send_sync::<ServerOptions>();
    unpin::<Server>();
    unpin::<Client>();
    unpin::<Error>();
}

#[test]
fn debug_output_shows_no_key_or_token_bytes() {
    let mut world = World::new(2);
    world.add_client(9);
    world.connect_all();
    let key = world.key;
    let shown = format!(
        "{:?} {:#?} {:?} {:#?}",
        world.server, world.server, world.clients[0], world.clients[0]
    );
    // the key formatted as Rust would print an array, or any 4-byte window of it in decimal or
    // hex, must not appear
    assert!(!shown.contains(&format!("{key:?}")));
    for window in key.windows(4) {
        let decimal = format!("{}, {}, {}, {}", window[0], window[1], window[2], window[3]);
        let hex = window.iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        });
        assert!(!shown.contains(&decimal), "{shown}");
        assert!(!shown.contains(&hex), "{shown}");
    }
    assert!(shown.contains("Server") && shown.contains("Client"));
    // a creation error carries no key either
    let taken = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let error = Server::new(taken.local_addr().unwrap(), 1, &key, 0.0).unwrap_err();
    let shown = format!("{error:?} {error}");
    assert!(!shown.contains(&format!("{key:?}")), "{shown}");
}
