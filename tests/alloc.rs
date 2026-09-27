//! Once warm, dream-net's own send and receive paths allocate nothing.
//!
//! A counting global allocator watches a pair of connections exchanging reliable and
//! unreliable events over the simulator. (reliable itself allocates a buffer per fragmented
//! packet it reassembles, so this uses unfragmented packets; netcode allocates per datagram,
//! which the socket benchmarks measure.)

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

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering};

use common::test_schema;
use dream_net::sim::{LinkConfig, Pair};
use dream_net::{Shared, TransportConfig};

struct Counting;

static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);

// SAFETY: forwards to the system allocator unchanged; only counts calls
#[allow(unsafe_code)]
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: same contract as the caller's
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: same contract as the caller's
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: same contract as the caller's
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

fn warm_pair(link: LinkConfig) -> (Pair, impl FnMut(&mut Pair, u32)) {
    let schema = test_schema();
    let chat = schema.event_id("Chat").unwrap();
    let mv = schema.event_id("Move").unwrap();
    let shared = Shared::new(schema, TransportConfig::default()).unwrap();
    let mut pair = Pair::symmetric(&shared, link, 1);
    assert!(pair.handshake(1.0 / 60.0, 600));
    let mut buffer = [0u8; 2048];
    let frame = move |pair: &mut Pair, n: u32| {
        for i in 0..8u32 {
            let _ = pair.b.send(chat, &(n * 8 + i).to_le_bytes());
            let _ = pair.a.send(mv, &[i as u8; 48]);
        }
        pair.step(1.0 / 60.0);
        while pair.a_inbox.pop_into(&mut buffer).unwrap().is_some() {}
        while pair.b_inbox.pop_into(&mut buffer).unwrap().is_some() {}
        let _ = pair.a.stats();
        let _ = pair.b.counters();
    };
    (pair, frame)
}

/// The counter is process-wide: tests take this lock so they never count each other.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn allocations_during(f: impl FnOnce()) -> u64 {
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    f();
    ALLOCATIONS.load(Ordering::Relaxed) - before
}

#[test]
fn steady_state_allocates_nothing() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for link in [
        LinkConfig::PERFECT,
        LinkConfig::latency(0.05),
        LinkConfig {
            jitter: 0.03,
            duplicate: 0.05,
            ..LinkConfig::latency(0.02)
        },
    ] {
        let (mut pair, mut frame) = warm_pair(link);
        for n in 0..2000 {
            frame(&mut pair, n);
        }
        let allocations = allocations_during(|| {
            for n in 2000..5000 {
                frame(&mut pair, n);
            }
        });
        assert_eq!(
            allocations, 0,
            "{link:?}: {allocations} allocations in 3000 warm frames"
        );
    }
}

/// Under loss, queues and pools grow when a rare long loss burst sets a new high-water
/// mark. Every such growth is bounded by the channel window, so the count decays to zero.
#[test]
fn lossy_growth_converges_to_zero() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let link = LinkConfig {
        loss: 0.05,
        jitter: 0.01,
        ..LinkConfig::latency(0.02)
    };
    let (mut pair, mut frame) = warm_pair(link);
    let windows: Vec<u64> = (0..12u32)
        .map(|w| {
            allocations_during(|| {
                for n in w * 3000..(w + 1) * 3000 {
                    frame(&mut pair, n);
                }
            })
        })
        .collect();
    let total: u64 = windows.iter().sum();
    let tail: u64 = windows[9..].iter().sum();
    assert!(total < 1000, "{windows:?}");
    assert!(tail <= 5, "growth did not converge: {windows:?}");
}
