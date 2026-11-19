//! The process-wide record of used connect tokens is bounded and fixed in size: it remembers the
//! most recent `CONNECT_TOKEN_RECORD_CAPACITY` tokens, forgets the oldest first, and never
//! allocates (beyond the one allocation std makes for its lock on macOS). Its own binary, because the test fills the record for the whole process and would
//! push out the tokens other tests rely on being remembered.

// CI passes -W clippy::pedantic on the command line, overriding the manifest's lint table.
#![allow(clippy::cast_possible_truncation)]

mod native_netcode_support;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::net::SocketAddr;

use dream_net::native::netcode::{
    CONNECT_TOKEN_BYTES, CONNECT_TOKEN_RECORD_CAPACITY, Client, ClientState, Error,
    generate_connect_token, generate_key,
};
use native_netcode_support::{PROTOCOL, localhost, user_data_for};

/// Counts this thread's allocations, so the test harness's own threads do not disturb it.
struct Counting;

thread_local! {
    static ALLOCATIONS: Cell<u64> = const { Cell::new(0) };
}

// SAFETY: forwards to the system allocator unchanged; only counts, in a const-initialised
// thread-local without a destructor (which never allocates).
#[allow(unsafe_code)]
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.with(|n| n.set(n.get() + 1));
        // SAFETY: the caller upholds `GlobalAlloc::alloc`'s contract, passed on unchanged.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` came from `System` through `alloc` or `realloc` above.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.with(|n| n.set(n.get() + 1));
        // SAFETY: as for `dealloc`, and the caller upholds `realloc`'s contract.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

fn allocations() -> u64 {
    ALLOCATIONS.with(Cell::get)
}

#[test]
fn the_record_keeps_the_latest_tokens_in_fixed_memory_and_forgets_the_oldest() {
    const EXTRA: usize = 5;
    assert_eq!(CONNECT_TOKEN_RECORD_CAPACITY, 4096);
    let key = generate_key();
    // nothing is ever sent there: the client is never updated
    let server: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let tokens: Vec<[u8; CONNECT_TOKEN_BYTES]> = (0..CONNECT_TOKEN_RECORD_CAPACITY + EXTRA)
        .map(|n| {
            generate_connect_token(
                &[server],
                &[server],
                30,
                5,
                n as u64,
                PROTOCOL,
                &key,
                &user_data_for(n as u64),
            )
            .unwrap()
        })
        .collect();
    let mut client = Client::new(localhost(), 0.0).unwrap();
    // The record is static, but the Mutex around it is std's: on macOS a pthread mutex, which
    // std allocates on its first lock, once per process. An unparseable token takes that lock
    // and is refused unrecorded, so the count below starts after it.
    assert!(matches!(
        client.connect(&[0; CONNECT_TOKEN_BYTES]),
        Err(Error::InvalidConnectToken)
    ));

    let before = allocations();
    for token in &tokens {
        client.connect(token).unwrap();
        assert_eq!(client.state(), ClientState::SendingConnectionRequest);
    }
    // the newest and the oldest still remembered are refused
    let newest = tokens.last().unwrap();
    assert!(matches!(
        client.connect(newest),
        Err(Error::InvalidConnectToken)
    ));
    assert!(matches!(
        client.connect(&tokens[EXTRA]),
        Err(Error::InvalidConnectToken)
    ));
    // the first EXTRA were pushed out
    for token in &tokens[..EXTRA] {
        client.connect(token).unwrap();
    }
    assert_eq!(
        allocations(),
        before,
        "connecting {} tokens allocated",
        tokens.len() + EXTRA + 2
    );
    // remembering them again pushed out the next oldest, one each, and nothing newer
    for token in &tokens[2 * EXTRA..] {
        assert!(matches!(
            client.connect(token),
            Err(Error::InvalidConnectToken)
        ));
    }
    for token in &tokens[EXTRA..2 * EXTRA] {
        client.connect(token).unwrap();
    }
}
