//! Per-connection memory, like for like: the `reliable` 1.3.4 Rust endpoint that dream-net
//! 1.1.1 used and the C endpoint this tree uses, both with dream-net's default
//! `TransportConfig`, measured by a counting global allocator (the C allocates through Rust's),
//! at creation and under the worst case a peer can force (every reassembly slot holding a
//! never-completed maximum-size packet). Also the whole `Connection` at creation, and what
//! `MemoryUsage::reliable` reports on each side.

// CI passes -W clippy::pedantic on the command line, overriding the manifest's lint table;
// test code casts freely between widths it controls.
#![allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use dream_net as new;
use dream_net_native::reliable as native;
use dream_net_old as old;
use reliable_old as port;

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grew(bytes: usize) {
    let live = LIVE.fetch_add(bytes, Ordering::Relaxed) + bytes;
    PEAK.fetch_max(live, Ordering::Relaxed);
}

// SAFETY: forwards to the system allocator unchanged; only counts bytes
#[allow(unsafe_code)]
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: same contract as the caller's
        let block = unsafe { System.alloc(layout) };
        if !block.is_null() {
            grew(layout.size());
        }
        block
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        // SAFETY: same contract as the caller's
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: same contract as the caller's
        let block = unsafe { System.realloc(ptr, layout, new_size) };
        if !block.is_null() {
            LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
            grew(new_size);
        }
        block
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// Bytes `f`'s result holds once built, and the peak while building it.
fn measure<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let before = LIVE.load(Ordering::Relaxed);
    let value = f();
    (value, LIVE.load(Ordering::Relaxed) - before)
}

/// Feeds `datagrams` and returns (bytes held afterwards, peak while feeding), above the start.
fn storm(datagrams: &[Vec<u8>], mut receive: impl FnMut(&[u8])) -> (usize, usize) {
    let before = LIVE.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    for d in datagrams {
        receive(d);
    }
    (
        LIVE.load(Ordering::Relaxed) - before,
        PEAK.load(Ordering::Relaxed) - before,
    )
}

fn schema_old() -> old::Schema {
    let mut b = old::Schema::builder(1);
    let c = b
        .channel(old::ChannelConfig::reliable_ordered("reliable"))
        .unwrap();
    b.event("E", c, 256).unwrap();
    b.build().unwrap()
}

fn schema_new() -> new::Schema {
    let mut b = new::Schema::builder(1);
    let c = b
        .channel(new::ChannelConfig::reliable_ordered("reliable"))
        .unwrap();
    b.event("E", c, 256).unwrap();
    b.build().unwrap()
}

#[test]
fn per_connection_memory_old_and_new_like_for_like() {
    let transport_old = old::TransportConfig::default();
    let transport_new = new::TransportConfig::default();
    let slots = transport_new.fragment_reassembly_buffer_size;
    let max = transport_new.max_packet_size;

    // the endpoints alone, at creation
    let (mut port_rx, port_created) =
        measure(|| port::Endpoint::new(transport_old.reliable_config("rx"), 0.0));
    let (mut native_rx, native_created) =
        measure(|| native::Endpoint::new(transport_new.reliable_config("rx"), 0.0).unwrap());
    // the C allocations, as its hook counts them, plus the 2-byte name the config holds
    assert_eq!(native_created, native_rx.allocated_bytes() + "rx".len());
    let native_hook_created = native_rx.allocated_bytes();

    // the worst case: 4 windows of never-completed maximum-size packets
    let mut port_tx = port::Endpoint::new(transport_old.reliable_config("tx"), 0.0);
    let mut native_tx = native::Endpoint::new(transport_new.reliable_config("tx"), 0.0).unwrap();
    let mut port_storm = Vec::new();
    let mut native_storm = Vec::new();
    for _ in 0..4 * slots {
        let mut set = Vec::new();
        port_tx.send_packet(&vec![7; max], |_, d| set.push(d.to_vec()));
        set.pop();
        port_storm.extend(set);
        let mut set = Vec::new();
        native_tx.send_packet(&vec![7; max], |_, d| set.push(d.to_vec()));
        set.pop();
        native_storm.extend(set);
    }
    assert_eq!(
        port_storm, native_storm,
        "the two senders frame identically"
    );
    let (port_held, port_peak) = storm(&port_storm, |d| port_rx.receive_packet(d, |_, _| true));
    let (native_held, native_peak) =
        storm(&native_storm, |d| native_rx.receive_packet(d, |_, _| true));

    // whole connections at creation, and what each reports
    let (conn_old, conn_old_bytes) = measure(|| {
        let shared = old::Shared::new(schema_old(), transport_old.clone()).unwrap();
        old::Connection::new(shared, old::PeerId(1), 0.0)
    });
    let (conn_new, conn_new_bytes) = measure(|| {
        let shared = new::Shared::new(schema_new(), transport_new.clone()).unwrap();
        new::Connection::new(shared, new::PeerId(1), 0.0)
    });
    let report_old = conn_old.memory_usage();
    let report_new = conn_new.memory_usage();

    println!("default TransportConfig, bytes per connection (counting allocator):");
    println!(
        "  reliable endpoint at creation: Rust port {port_created}, C {native_created} \
         (C: {native_hook_created} counted by its allocator hook, the rest is the config's \
         name)"
    );
    println!(
        "  reliable worst case ({slots} slots x {} fragments): Rust port held {} (peak {}), \
         C held {} (peak {})",
        transport_new.max_fragments(),
        port_created + port_held,
        port_created + port_peak,
        native_created + native_held,
        native_created + native_peak
    );
    println!(
        "  C endpoint memory_usage bound {}, Connection at creation: old {conn_old_bytes}, new \
         {conn_new_bytes}",
        native_rx.memory_usage()
    );
    println!(
        "  MemoryUsage old {report_old:?} total {}",
        report_old.total()
    );
    println!(
        "  MemoryUsage new {report_new:?} total {}",
        report_new.total()
    );

    // the reported bound is honest for both backends' real worst case
    // (less the config's name, which the bound does not count)
    assert!(native_created - "rx".len() + native_peak <= native_rx.memory_usage());
    assert!(port_created + port_peak <= report_new.reliable);
    assert_eq!(report_new.reliable, native_rx.memory_usage());
    // and dream-net 1.1.1's estimate was below the real worst case it was meant to bound
    assert!(report_old.reliable < port_created + port_held);
}
