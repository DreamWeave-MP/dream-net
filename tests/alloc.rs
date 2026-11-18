//! Once warm, dream-net's own send and receive paths allocate nothing, and what a hostile
//! peer can make a connection allocate stays within its reported bound.
//!
//! A counting global allocator watches a pair of connections exchanging reliable and
//! unreliable events over the simulator. reliable is the C library, whose allocations go
//! through Rust's global allocator, so it counts them too. (reliable allocates a buffer per
//! fragmented packet it reassembles, so the steady-state tests use unfragmented packets;
//! netcode allocates per datagram, which the socket benchmarks measure.)

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
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use common::{PacketSpec, SectionSpec, encode, test_schema};
use dream_net::sim::{LinkConfig, Pair, Rng};
use dream_net::wire::Layout as WireLayout;
use dream_net::{ChannelId, Connection, ConnectionEvent, Inbox, Record, Shared, TransportConfig};
use dream_net_native::reliable::Endpoint;

struct Counting;

static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
/// Bytes allocated and not yet freed, process-wide.
static LIVE: AtomicUsize = AtomicUsize::new(0);
/// The most `LIVE` has been since the last [`reset_peak`].
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grew(bytes: usize) {
    let live = LIVE.fetch_add(bytes, Ordering::Relaxed) + bytes;
    PEAK.fetch_max(live, Ordering::Relaxed);
}

// SAFETY: forwards to the system allocator unchanged; only counts calls and bytes
#[allow(unsafe_code)]
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
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
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
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

/// Restarts peak tracking from the current live bytes, and returns them.
fn reset_peak() -> usize {
    let live = LIVE.load(Ordering::Relaxed);
    PEAK.store(live, Ordering::Relaxed);
    live
}

/// A payload that names message `n` and checks its own integrity.
fn payload(n: u32, len: usize) -> Vec<u8> {
    let mut p = vec![0u8; len.max(4)];
    p[..4].copy_from_slice(&n.to_le_bytes());
    for (i, b) in p.iter_mut().enumerate().skip(4) {
        *b = (n as usize).wrapping_mul(31).wrapping_add(i) as u8;
    }
    p
}

fn check(p: &[u8]) -> u32 {
    let n = u32::from_le_bytes(p[..4].try_into().unwrap());
    assert_eq!(p, payload(n, p.len()), "payload {n} was never sent");
    n
}

/// A connection established by a scripted native remote endpoint, which frames packets for it.
fn lone(config: TransportConfig) -> (Connection, Inbox<()>, Endpoint, WireLayout) {
    let schema = test_schema();
    let layout = WireLayout::new(&schema);
    let mut remote = Endpoint::new(config.reliable_config("remote"), 0.0).unwrap();
    let shared = Shared::new(schema, config).unwrap();
    let peer = Pair::PEER;
    let mut inbox = Inbox::new(1);
    inbox.open_slot(peer);
    let mut conn = Connection::new(shared, peer, 0.0);
    let hello = encode(
        &layout,
        &PacketSpec {
            hello: Some(layout.hello()),
            sections: Vec::new(),
        },
    );
    remote.send_packet(&hello, |_, d| conn.receive(d, &mut inbox, |_| {}));
    assert_eq!(conn.take_event(), Some(ConnectionEvent::Established));
    (conn, inbox, remote, layout)
}

/// The fragments of one maximum-size packet from `remote`, last fragment withheld: each such
/// set opens a reassembly slot that never completes.
fn open_reassembly(remote: &mut Endpoint, max_packet_size: usize) -> Vec<Vec<u8>> {
    let mut fragments = Vec::new();
    remote.send_packet(&vec![0xA5; max_packet_size], |_, d| {
        fragments.push(d.to_vec());
    });
    fragments.pop();
    fragments
}

/// Fragment reassembly is all a peer can make reliable allocate, and the connection reports
/// its worst case honestly: a storm of never-completed maximum-size packets fills every slot
/// to exactly the bound `MemoryUsage::reliable` charges for reassembly, and no further.
#[test]
fn a_fragment_storm_fills_reassembly_to_the_reported_bound_and_no_further() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let config = TransportConfig::default();
    let slots = config.fragment_reassembly_buffer_size.next_power_of_two();
    let fragments = config.max_fragments();
    let (mut conn, mut inbox, mut remote, _) = lone(config.clone());
    let bound = conn.memory_usage().reliable;
    // each slot: the allocator hook's 16-byte header + 9 + 28 * 1186 + 8 (reliable.c:1517)
    let slot_bytes = 16 + 9 + fragments * config.fragment_size + 8;
    let reassembly = slots * slot_bytes;
    // what the C endpoint holds before any reassembly: everything else in the bound
    let created = bound - reassembly;
    println!(
        "default TransportConfig: reliable bound {bound} B = {created} B at creation + {slots} \
         slots x {slot_bytes} B of reassembly ({reassembly} B)"
    );

    let storm: Vec<Vec<u8>> = (0..4 * slots)
        .flat_map(|_| open_reassembly(&mut remote, config.max_packet_size))
        .collect();
    let before = reset_peak();
    for d in &storm {
        conn.receive(d, &mut inbox, |_| {});
    }
    let peak = PEAK.load(Ordering::Relaxed) - before;
    let held = LIVE.load(Ordering::Relaxed) - before;
    println!("fragment storm: peak {peak} B above the established connection, {held} B held");
    // every slot is full: the storm reached the worst case ...
    assert_eq!(held, reassembly);
    // ... and never went past it: a superseded slot is freed before its new buffer is taken
    assert!(peak <= reassembly, "{peak} > {reassembly}");
    assert_eq!(conn.memory_usage().reliable, bound, "the bound is constant");
    assert!(inbox.is_empty());
    assert_eq!(
        conn.reliable_counters().num_fragments_received,
        storm.len() as u64
    );
    // dropping the connection gives all of it back
    let before_drop = LIVE.load(Ordering::Relaxed);
    drop(conn);
    assert!(before_drop - LIVE.load(Ordering::Relaxed) >= reassembly + created);
}

/// The datagrams of a packet carrying reliable `Chat` event `n`, framed by `remote`.
fn genuine_packet(remote: &mut Endpoint, layout: &WireLayout, rng: &mut Rng, n: u32) -> Vec<u8> {
    let chat = test_schema().event_id("Chat").unwrap();
    let packet = encode(
        layout,
        &PacketSpec {
            hello: None,
            sections: vec![SectionSpec {
                channel: ChannelId(0),
                first_id: n as u16,
                deltas: Vec::new(),
                messages: vec![(chat, payload(n, 4 + rng.below(200) as usize))],
            }],
        },
    );
    let mut datagram = Vec::new();
    remote.send_packet(&packet, |_, d| datagram = d.to_vec());
    datagram
}

/// Feeds `script` to `conn`, polling after every datagram: everything delivered must be a
/// genuine event, in order, once. Returns how many arrived and the peak bytes allocated
/// above the start.
fn feed(conn: &mut Connection, inbox: &mut Inbox<()>, script: &[Vec<u8>]) -> (u32, usize) {
    let chat = test_schema().event_id("Chat").unwrap();
    let mut buffer = vec![0u8; 4096];
    let before = reset_peak();
    let mut delivered = 0u32;
    for d in script {
        conn.receive(d, inbox, |_| {});
        while let Some(record) = inbox.pop_into(&mut buffer).unwrap() {
            if let Record::Message(info) = record {
                assert_eq!(info.event, chat);
                let n = check(&buffer[..info.len]);
                assert_eq!(n, delivered, "out of order or duplicated");
                delivered += 1;
            }
        }
    }
    (delivered, PEAK.load(Ordering::Relaxed) - before)
}

/// Replayed datagrams and storms of real fragments that never complete, interleaved with a
/// genuine stream: every replay is refused as a duplicate or stale, reassembly stays within
/// its bound, and the whole stream still arrives, once, in order.
#[test]
fn replays_and_fragment_storms_do_not_disturb_a_genuine_stream() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let config = TransportConfig::default();
    let (mut conn, mut inbox, mut remote, layout) = lone(config.clone());
    let mut rng = Rng::new(1);
    // the storm: every 10th packet is followed by an incomplete maximum-size packet, and
    // every packet by replays of earlier datagrams, some far behind the window
    let mut genuine: Vec<Vec<u8>> = Vec::new();
    let mut script = Vec::new();
    for i in 0..3000 {
        let d = genuine_packet(&mut remote, &layout, &mut rng, i as u32);
        genuine.push(d.clone());
        script.push(d);
        if i % 10 == 0 {
            script.extend(open_reassembly(&mut remote, config.max_packet_size));
        }
        for _ in 0..rng.below(4) {
            script.push(genuine[rng.below(i as u64 + 1) as usize].clone());
        }
    }
    let (delivered, peak) = feed(&mut conn, &mut inbox, &script);
    let memory = conn.memory_usage();
    let counters = *conn.reliable_counters();
    println!(
        "{} datagrams, {delivered} events, peak {peak} B, reliable bound {} B, {counters:?}",
        script.len(),
        memory.reliable
    );
    assert_eq!(delivered, 3000);
    assert_eq!(
        conn.counters().duplicate_events,
        0,
        "replays never reached dream-net"
    );
    assert!(counters.num_packets_duplicate + counters.num_packets_stale > 1000);
    assert!(peak <= memory.reliable + memory.connection, "{peak}");
}

/// Datagrams straight into `Connection::receive` from a hostile peer: random bytes, real
/// datagrams with their reliable headers mutated, exact replays, real fragments of packets
/// that never complete, and fragments with forged headers. Nothing panics, memory stays within
/// the connection's reported bound, and nothing is delivered that was not sent: reliable
/// events arrive intact, once each, in order.
///
/// Unauthenticated garbage soon ends a connection in practice (a datagram that decodes as a
/// hello of another protocol version fails it, and a forged sequence far ahead makes the
/// genuine stream stale; netcode's encryption is what keeps both out), so this runs many
/// short sessions rather than one long one.
#[test]
fn hostile_datagrams_never_panic_deliver_nothing_unsent_and_stay_bounded() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let config = TransportConfig {
        malformed_limit: u32::MAX,
        ..TransportConfig::default()
    };
    let (mut total, mut failed, mut datagrams, mut peak_max) = (0u32, 0u32, 0usize, 0usize);
    let mut refused = 0u64;
    for seed in 0..200u64 {
        let (mut conn, mut inbox, mut remote, layout) = lone(config.clone());
        let mut rng = Rng::new(seed);
        // every datagram first, so the measurement sees only the connection's own allocations
        let mut genuine: Vec<Vec<u8>> = Vec::new();
        let mut script = Vec::new();
        for i in 0..100 {
            let d = genuine_packet(&mut remote, &layout, &mut rng, i as u32);
            genuine.push(d.clone());
            script.push(d);
            for _ in 0..rng.below(3) {
                let hostile = match rng.below(6) {
                    0 => (0..=rng.below(1300))
                        .map(|_| rng.next_u64() as u8)
                        .collect(),
                    1 => {
                        // a real datagram with bits of its reliable header flipped
                        let mut d = genuine[rng.below(i as u64 + 1) as usize].clone();
                        let header = d.len().min(9) as u64;
                        for _ in 0..=rng.below(2) {
                            let at = rng.below(header) as usize;
                            d[at] ^= 1 << rng.below(8);
                        }
                        d
                    }
                    2 => genuine[rng.below(i as u64 + 1) as usize].clone(),
                    3 => {
                        // a fragment with a forged header: random sequence, id and count
                        let mut d = vec![1u8 | (rng.next_u64() as u8 & 0xFE)];
                        d.extend((0..4).map(|_| rng.next_u64() as u8));
                        d.extend((0..rng.below(1195)).map(|_| rng.next_u64() as u8));
                        d
                    }
                    4 => {
                        script.extend(open_reassembly(&mut remote, config.max_packet_size));
                        continue;
                    }
                    _ => Vec::new(), // ignored before reliable
                };
                script.push(hostile);
            }
        }
        let (delivered, peak) = feed(&mut conn, &mut inbox, &script);
        let memory = conn.memory_usage();
        // reliable within its bound; dream-net's own scratch growth is far below the rest
        assert!(
            peak <= memory.reliable + memory.connection,
            "seed {seed}: {peak}"
        );
        assert!(
            delivered >= 1,
            "seed {seed}: the first genuine packet always arrives"
        );
        let counters = conn.reliable_counters();
        refused += counters.num_packets_invalid
            + counters.num_fragments_invalid
            + counters.num_packets_stale
            + counters.num_packets_duplicate;
        total += delivered;
        failed += u32::from(matches!(
            conn.state(),
            dream_net::ConnectionState::Failed(_)
        ));
        datagrams += script.len();
        peak_max = peak_max.max(peak);
    }
    println!(
        "200 hostile sessions: {datagrams} datagrams, {total} of 20000 genuine events \
         delivered, {failed} sessions failed, {refused} datagrams refused by reliable, peak \
         {peak_max} B"
    );
    assert!(refused > 1000);
    assert!(total > 2000);
}
