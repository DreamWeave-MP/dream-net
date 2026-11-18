//! The C endpoint's memory, measured by a counting global allocator (its allocator hooks call
//! Rust's): `memory_usage()` is exact at creation, reached exactly by a worst-case reassembly
//! flood, never exceeded by hostile input, and everything is freed on reset and drop. The send
//! and receive paths allocate nothing except a reassembly buffer per fragmented packet.

// CI passes -W clippy::pedantic on the command line, overriding the manifest's lint table;
// test code casts freely between widths it controls.
#![allow(
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]

mod reliable_support;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use dream_net_native::reliable::{Config, Endpoint, MAX_PACKET_HEADER_BYTES};
use reliable_support::{Rng, dream_net_config, payload};

/// Counts this thread's live bytes and allocations, so parallel tests do not disturb each other.
struct Counting;

thread_local! {
    static LIVE: Cell<isize> = const { Cell::new(0) };
    static ALLOCATIONS: Cell<u64> = const { Cell::new(0) };
}

// SAFETY: forwards to the system allocator unchanged; only counts, in const-initialised
// thread-locals without destructors (which never allocate).
#[allow(unsafe_code)]
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LIVE.with(|l| l.set(l.get() + layout.size() as isize));
        ALLOCATIONS.with(|a| a.set(a.get() + 1));
        // SAFETY: same contract as the caller's
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.with(|l| l.set(l.get() - layout.size() as isize));
        // SAFETY: same contract as the caller's
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        LIVE.with(|l| l.set(l.get() - layout.size() as isize + new_size as isize));
        ALLOCATIONS.with(|a| a.set(a.get() + 1));
        // SAFETY: same contract as the caller's
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

fn live() -> isize {
    LIVE.with(Cell::get)
}

fn allocations() -> u64 {
    ALLOCATIONS.with(Cell::get)
}

fn configs() -> Vec<Config> {
    vec![
        Config::default(),
        dream_net_config("alloc"),
        Config {
            fragment_reassembly_buffer_size: 3, // rounded up to 4 slots by C
            sent_packets_buffer_size: 100,      // rounded up to 128
            ..Config::default()
        },
        Config {
            sent_packets_buffer_size: 16384,
            received_packets_buffer_size: 16384,
            fragment_reassembly_buffer_size: 5,
            max_fragments: 256,
            fragment_size: 64,
            ..Config::default()
        },
    ]
}

/// The worst case of reassembly, from the C allocation (`reliable.c:1517`) and the hook's
/// 16-byte header, independently of the binding.
fn reassembly_bound(config: &Config) -> usize {
    let slots = config.fragment_reassembly_buffer_size.next_power_of_two();
    slots * (16 + MAX_PACKET_HEADER_BYTES + config.max_fragments * config.fragment_size + 8)
}

/// A fragment (not the first) of `sequence` with the most fragments the config allows.
fn widest_fragment(config: &Config, sequence: u16) -> Vec<u8> {
    let count = config.max_fragments;
    let mut d = vec![
        1,
        sequence as u8,
        (sequence >> 8) as u8,
        1,
        (count - 1) as u8,
    ];
    let len = if count == 2 { 1 } else { config.fragment_size };
    d.extend(std::iter::repeat_n(0xEE, len));
    d
}

#[test]
fn memory_usage_is_exact_at_creation_and_tight_under_a_flood() {
    for config in configs() {
        // the config (its name) is the caller's, allocated before the endpoint
        let given = config.clone();
        let baseline = live();
        let mut e = Endpoint::new(given, 0.0).unwrap();
        let created = (live() - baseline) as usize;
        assert_eq!(e.allocated_bytes(), created, "{config:?}");
        assert_eq!(e.memory_usage(), created + reassembly_bound(&config));

        // one reassembly per slot, each as wide as allowed: exactly the bound
        let slots = config.fragment_reassembly_buffer_size.next_power_of_two();
        for s in 0..slots as u16 {
            e.receive_packet(&widest_fragment(&config, s), |_, _| unreachable!());
        }
        assert_eq!(e.counters().num_fragments_received, slots as u64);
        let held = || (live() - baseline) as usize;
        assert_eq!(held(), e.memory_usage(), "{config:?}");
        assert_eq!(e.allocated_bytes(), e.memory_usage());
        // more of them evict and free the oldest: still exactly the bound, never above
        for s in slots as u16..10 * slots as u16 {
            e.receive_packet(&widest_fragment(&config, s), |_, _| unreachable!());
            assert_eq!(held(), e.memory_usage());
        }
        // reset frees every reassembly buffer
        e.reset();
        assert_eq!(held(), created);
        // dropping also frees the config's name, allocated before the baseline
        drop(e);
        assert_eq!(
            live() + config.name.capacity() as isize,
            baseline,
            "{config:?}: leaked"
        );
    }
}

/// dream-net charged 300 bytes per reassembly slot (audit S9); this is the true figure.
#[test]
fn dream_net_reassembly_bound() {
    let config = dream_net_config("alloc");
    let e = Endpoint::new(config.clone(), 0.0).unwrap();
    // 16 slots of 16 + 9 + 28 * 1186 + 8 bytes
    assert_eq!(reassembly_bound(&config), 16 * 33_241);
    println!(
        "dream-net config: created {} B, bound {} B",
        e.allocated_bytes(),
        e.memory_usage()
    );
}

#[test]
fn hostile_input_stays_within_the_bound_and_nothing_leaks() {
    for config in configs() {
        let mut rng = Rng::new(99);
        let mut buffer = Vec::with_capacity(1300);
        let given = config.clone();
        let baseline = live();
        let mut e = Endpoint::new(given, 0.0).unwrap();
        let bound = e.memory_usage();
        for i in 0..20_000u32 {
            buffer.clear();
            let len = rng.below(1300) as usize;
            buffer.extend((0..len).map(|_| rng.next_u64() as u8));
            if let Some(first) = buffer.first_mut() {
                // half fragments, mostly within the configured limits
                if i % 2 == 0 {
                    *first = 1;
                    if buffer.len() >= 5 {
                        buffer[4] = (usize::from(buffer[4]) % config.max_fragments) as u8;
                        buffer[3] %= buffer[4].wrapping_add(1).max(1);
                    }
                }
            }
            e.receive_packet(&buffer, |_, _| true);
            let held = (live() - baseline) as usize;
            assert!(held <= bound, "{held} > {bound}");
            assert_eq!(held, e.allocated_bytes());
        }
        drop(e);
        assert_eq!(live() + config.name.capacity() as isize, baseline, "leaked");
    }
}

/// Once created, an endpoint allocates nothing to send, receive, update or report, except one
/// reassembly buffer per fragmented packet it receives.
#[test]
fn the_packet_path_allocates_only_reassembly_buffers() {
    let config = dream_net_config("alloc");
    let mut a = Endpoint::new(config.clone(), 0.0).unwrap();
    let mut b = Endpoint::new(config.clone(), 0.0).unwrap();
    let small = payload(1, 800);
    let large = payload(2, 9000);
    let before = allocations();
    let mut time = 0.0;
    for i in 0..1000 {
        time += 1.0 / 60.0;
        a.update(time);
        b.update(time);
        let data = if i % 10 == 0 { &large } else { &small };
        a.send_packet(data, |_, d| {
            b.receive_packet(d, |_, p| p.len() == data.len());
        });
        b.send_packet(&small, |_, d| a.receive_packet(d, |_, _| true));
        for _ in a.drain_acks() {}
        b.clear_acks();
        let _ = (
            a.rtt(),
            a.bandwidth(),
            *a.counters(),
            a.acks().len(),
            b.packet_loss(),
        );
    }
    assert_eq!(allocations() - before, 100, "one per reassembled packet");
    assert_eq!(a.counters().num_packets_acked, 1000);
}
