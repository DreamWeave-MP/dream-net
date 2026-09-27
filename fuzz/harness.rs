//! Fuzz harnesses for dream-net's own boundary (§64 of the design).
//!
//! Shared by the cargo-fuzz targets in `fuzz_targets/` and by `tests/fuzz_smoke.rs`, which runs
//! them on the stable toolchain over random and hand-picked inputs. Each harness panics only
//! when dream-net breaks an invariant; hostile input itself must never panic.

#![allow(dead_code, clippy::missing_panics_doc)]

use std::sync::Arc;

use dream_net::capture::CaptureReader;
use dream_net::connection::PARK_OVERHEAD;
use dream_net::sim::{LinkConfig, Pair};
use dream_net::wire::{Decoded, Hello, Layout, PacketWriter, WIRE_VERSION, decode};
use dream_net::{
    ChannelConfig, ChannelId, Connection, ConnectionEvent, ConnectionState, EventTypeId, Failure,
    Fingerprint, Inbox, PeerId, Schema, Seq16, Shared, TransportConfig,
};

/// Two reliable channels (one tiny window), one unreliable; small and large events.
pub fn schema() -> Schema {
    let mut b = Schema::builder(3).max_messages_per_packet(16);
    let reliable = b
        .channel(ChannelConfig::reliable_ordered("reliable").with_capacity(32))
        .unwrap();
    let state = b
        .channel(ChannelConfig::unreliable_unordered("state").with_capacity(32))
        .unwrap();
    let tiny = b
        .channel(ChannelConfig::reliable_ordered("tiny").with_capacity(4))
        .unwrap();
    b.event("A", reliable, 64).unwrap();
    b.event("B", reliable, 3000).unwrap();
    b.event("C", state, 32).unwrap();
    b.event("D", state, 0).unwrap();
    b.event("E", tiny, 16).unwrap();
    b.build().unwrap()
}

fn config() -> TransportConfig {
    TransportConfig {
        max_pending_events: 64,
        max_pending_bytes: 16 * 1024,
        max_parked_bytes: 8 * 1024,
        malformed_limit: u32::MAX,
        ..TransportConfig::default()
    }
}

fn shared() -> Arc<Shared> {
    Shared::new(schema(), config()).unwrap()
}

/// Consumes bytes from the fuzz input; runs dry as zeros.
struct Input<'a>(&'a [u8]);

impl Input<'_> {
    fn byte(&mut self) -> u8 {
        match self.0.split_first() {
            Some((&b, rest)) => {
                self.0 = rest;
                b
            }
            None => 0,
        }
    }

    fn take(&mut self, n: usize) -> &[u8] {
        let n = n.min(self.0.len());
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        head
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Re-encodes a decoded packet with dream-net's writer.
fn reencode(layout: &Layout, decoded: &Decoded, packet: &[u8]) -> Vec<u8> {
    let mut buffer = vec![0u8; packet.len().div_ceil(8) * 8 + 64];
    let mut w = PacketWriter::new(&mut buffer);
    w.header(layout, decoded.hello, decoded.sections.len() as u32);
    for section in &decoded.sections {
        w.section(layout, section.channel, section.count);
        let messages =
            &decoded.messages[section.first as usize..(section.first + section.count) as usize];
        let mut previous: Option<Seq16> = None;
        for m in messages {
            if layout.channel(section.channel).reliable {
                match previous {
                    None => w.first_id(m.id),
                    Some(p) => w.next_id(u32::from(m.id.since(p))),
                }
                previous = Some(m.id);
            }
            w.message(layout, m.event, m.payload(packet));
        }
    }
    let len = w.finish();
    buffer.truncate(len);
    buffer
}

/// Decoding never panics, and anything accepted is canonical: it re-encodes to itself.
pub fn wire_decode(data: &[u8]) {
    let schema = schema();
    let layout = Layout::new(&schema);
    let mut decoded = Decoded::default();
    if decode(&layout, data, &mut decoded).is_ok() {
        assert_eq!(
            reencode(&layout, &decoded, data),
            data,
            "accepted packet is not canonical"
        );
        for m in &decoded.messages {
            let event = schema.event(m.event).expect("decoded event exists");
            assert!(m.len <= event.max_payload);
        }
    }
}

/// An established connection, and the remote endpoint that frames packets for it.
fn established() -> (Connection, Inbox<()>, reliable::Endpoint, Layout) {
    let shared = shared();
    let config = shared.config().clone();
    let layout = Layout::new(shared.schema());
    let peer = PeerId::new(0, 1);
    let mut inbox = Inbox::new(1);
    inbox.open_slot(peer);
    let mut connection = Connection::new(shared, peer, 0.0);
    let mut remote = reliable::Endpoint::new(config.reliable_config("remote"), 0.0);
    let mut buffer = [0u8; 64];
    let mut w = PacketWriter::new(&mut buffer);
    w.header(&layout, Some(layout.hello()), 0);
    let len = w.finish();
    remote.send_packet(&buffer[..len], |_, d| {
        connection.receive(d, &mut inbox, |_| {});
    });
    assert_eq!(connection.take_event(), Some(ConnectionEvent::Established));
    (connection, inbox, remote, layout)
}

fn check_bounds(connection: &Connection, inbox: &Inbox<()>) {
    let config = config();
    assert!(connection.parked_bytes() <= config.max_parked_bytes);
    let (events, bytes) = inbox.pending(PeerId::new(0, 1));
    // a filled gap may move up to the park budget into the inbox past its soft limits
    assert!(bytes <= config.max_pending_bytes + config.max_parked_bytes);
    assert!(events <= config.max_pending_events + config.max_parked_bytes / PARK_OVERHEAD);
    let memory = connection.memory_usage();
    assert!(
        memory.receive <= 2 * config.max_parked_bytes + 4 * config.max_pooled_bytes + 64 * 1024
    );
}

/// Arbitrary interleavings of raw datagrams, reliable-framed packets, polling, time, and
/// flushes against an established connection: nothing panics and every bound holds.
pub fn connection_stream(data: &[u8]) {
    let (mut connection, mut inbox, mut remote, _) = established();
    let mut input = Input(data);
    let mut time = 0.0;
    let mut buffer = vec![0u8; 4096];
    while !input.is_empty() {
        match input.byte() % 6 {
            0 => {
                let len = usize::from(input.byte()) * 4;
                let datagram = input.take(len).to_vec();
                connection.receive(&datagram, &mut inbox, |_| {});
            }
            1 | 2 => {
                // reliable framing, so the bytes reach dream-net's decoder
                let len = usize::from(input.byte()) + usize::from(input.byte()) * 16;
                let packet = input.take(len).to_vec();
                if !packet.is_empty() {
                    remote.send_packet(&packet, |_, d| connection.receive(d, &mut inbox, |_| {}));
                }
            }
            3 => {
                time += f64::from(input.byte()) / 100.0;
                connection.update(time);
                remote.update(time);
            }
            4 => {
                connection.write_packets(|d| remote.receive_packet(d, |_, _| true));
                remote.clear_acks();
            }
            _ => {
                for _ in 0..input.byte() {
                    if inbox.pop_into(&mut buffer).expect("buffer fits").is_none() {
                        break;
                    }
                }
                inbox.compact();
            }
        }
        check_bounds(&connection, &inbox);
        assert!(!matches!(connection.state(), ConnectionState::Handshaking));
    }
}

/// Reliable events cross a network whose every decision (deliver, drop, duplicate, delay)
/// comes from the fuzz input; once the network heals, every event arrives exactly once and in
/// order.
pub fn channel_schedule(data: &[u8]) {
    let shared = shared();
    let mut pair = Pair::symmetric(&shared, LinkConfig::PERFECT, 7);
    for _ in 0..4 {
        pair.step(1.0 / 60.0);
    }
    let a_event = EventTypeId(0);
    let e_event = EventTypeId(4);
    let mut input = Input(data);
    let mut sent = [0u32; 2];
    let mut got: [Vec<u32>; 2] = [Vec::new(), Vec::new()];
    let mut held: Vec<(bool, Vec<u8>)> = Vec::new();
    let mut buffer = vec![0u8; 4096];
    let drain = |pair: &mut Pair, got: &mut [Vec<u32>; 2], buffer: &mut [u8]| {
        while let Some(record) = pair.a_inbox.pop_into(buffer).expect("fits") {
            if let dream_net::Record::Message(info) = record {
                let n = u32::from_le_bytes(buffer[..4].try_into().expect("4 bytes"));
                got[usize::from(info.event == e_event)].push(n);
            }
        }
    };
    let mut time = pair.time;
    while !input.is_empty() {
        let op = input.byte();
        for (i, event) in [(0, a_event), (1, e_event)] {
            if op & (1 << i) != 0 && pair.b.send(event, &sent[i].to_le_bytes()).is_ok() {
                sent[i] += 1;
            }
        }
        time += 1.0 / 60.0;
        pair.a.update(time);
        pair.b.update(time);
        // every datagram b sends and a answers passes through the adversary
        let mut out: Vec<(bool, Vec<u8>)> = Vec::new();
        pair.b.write_packets(|d| out.push((true, d.to_vec())));
        pair.a.write_packets(|d| out.push((false, d.to_vec())));
        out.append(&mut held);
        for (to_a, datagram) in out {
            let decision = input.byte();
            let copies = match decision % 5 {
                0 => 0,
                1 => 2,
                2 => {
                    held.push((to_a, datagram));
                    continue;
                }
                _ => 1,
            };
            for _ in 0..copies {
                if to_a {
                    let (a, a_inbox) = (&mut pair.a, &mut pair.a_inbox);
                    a.receive(&datagram, a_inbox, |_| {});
                } else {
                    let (b, b_inbox) = (&mut pair.b, &mut pair.b_inbox);
                    b.receive(&datagram, b_inbox, |_| {});
                }
            }
        }
        if op & 4 != 0 {
            drain(&mut pair, &mut got, &mut buffer);
        }
    }
    // heal the network
    pair.time = time;
    for _ in 0..2000 {
        pair.step(1.0 / 60.0);
        drain(&mut pair, &mut got, &mut buffer);
        if got[0].len() == sent[0] as usize && got[1].len() == sent[1] as usize {
            break;
        }
    }
    for i in 0..2 {
        assert!(
            got[i].iter().copied().eq(0..sent[i]),
            "channel {i}: sent {} got {:?}",
            sent[i],
            got[i]
        );
    }
    assert!(!matches!(pair.a.state(), ConnectionState::Failed(_)));
}

/// A fuzzed hello is classified exactly: protocol mismatch, schema mismatch, or accepted.
pub fn handshake(data: &[u8]) {
    let shared = shared();
    let config = shared.config().clone();
    let layout = Layout::new(shared.schema());
    let mut input = Input(data);
    let wire_version = if input.byte() & 1 == 0 {
        WIRE_VERSION
    } else {
        u16::from_le_bytes([input.byte(), input.byte()])
    };
    let fingerprint = if input.byte() & 1 == 0 {
        shared.schema().fingerprint()
    } else {
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&{
            let mut b = [0u8; 16];
            let taken = input.take(16);
            b[..taken.len()].copy_from_slice(taken);
            b
        });
        Fingerprint(u128::from_le_bytes(bytes))
    };
    let hello = Hello {
        wire_version,
        fingerprint,
    };
    let peer = PeerId::new(0, 1);
    let mut inbox: Inbox<()> = Inbox::new(1);
    inbox.open_slot(peer);
    let mut connection = Connection::new(shared.clone(), peer, 0.0);
    let mut remote = reliable::Endpoint::new(config.reliable_config("remote"), 0.0);
    let mut buffer = [0u8; 64];
    let mut w = PacketWriter::new(&mut buffer);
    w.header(&layout, Some(hello), 0);
    let len = w.finish();
    remote.send_packet(&buffer[..len], |_, d| {
        connection.receive(d, &mut inbox, |_| {});
    });
    let local = layout.hello();
    let expected = if hello.wire_version != local.wire_version {
        ConnectionState::Failed(Failure::ProtocolMismatch {
            local: local.wire_version,
            remote: hello.wire_version,
        })
    } else if hello.fingerprint != local.fingerprint {
        ConnectionState::Failed(Failure::SchemaMismatch {
            local: local.fingerprint,
            remote: hello.fingerprint,
        })
    } else {
        ConnectionState::Established
    };
    assert_eq!(connection.state(), expected);
    // whatever follows, a failed connection stays failed and delivers nothing
    let rest = input.take(usize::MAX).to_vec();
    if !rest.is_empty() {
        remote.send_packet(&rest, |_, d| connection.receive(d, &mut inbox, |_| {}));
    }
    if expected != ConnectionState::Established {
        assert_eq!(connection.state(), expected);
        assert!(inbox.is_empty());
    }
    let _ = ChannelId(0);
}

/// Capture files are untrusted: reading one never panics or allocates past its size. Half
/// the inputs get a real header first, so the fuzzer spends its time on records.
pub fn capture_read(data: &[u8]) {
    let file;
    let data = match data.split_first() {
        Some((&flag, rest)) if flag & 1 == 0 => {
            let writer =
                dream_net::capture::CaptureWriter::new(Vec::new(), &schema(), flag & 2 == 0)
                    .expect("writing to a Vec cannot fail");
            let mut bytes = writer.finish().expect("writing to a Vec cannot fail");
            bytes.extend_from_slice(rest);
            file = bytes;
            &file[..]
        }
        _ => data,
    };
    if let Ok(mut reader) = CaptureReader::new(data) {
        let mut total = 0usize;
        while let Ok(Some(record)) = reader.next_record() {
            if let dream_net::capture::CaptureKind::Received { payload, .. }
            | dream_net::capture::CaptureKind::Sent { payload, .. } = record.kind
            {
                total += payload.len();
            }
        }
        assert!(total <= data.len());
    }
}
