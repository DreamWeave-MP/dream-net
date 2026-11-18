//! The contract l3i's `@dream/udp` bridge (the Luau `sendEvent`/`pollInto` surface) relies on,
//! verified at dream-net's public Rust API over real loopback sockets:
//!
//! - **Buffer ownership.** `send` copies the payload before it returns, and `poll_into` copies
//!   one payload into the caller's buffer and returns only its length (`ServerEvent<usize>`,
//!   `ClientEvent<usize>`: nothing borrowed outlives the call). Thousands of frames with two
//!   peers, a single reused buffer that is shrunk, grown, sized exactly and oversized,
//!   zero-length and maximum-length payloads, and fragmented ones: every payload arrives
//!   intact, reliable ones in order and attributed to the right peer, a too-small buffer
//!   consumes nothing and reports the exact size, and nothing outside the payload's prefix of
//!   the buffer is ever written. The sender's buffer is overwritten right after every send.
//! - **No reentrancy.** `update` and `flush` take no host callback, and the only host code
//!   dream-net ever runs (a capture sink, which l3i never installs) runs from `poll`,
//!   `poll_into` and `send` only: never during `update` or `flush`, the network phase.
//!
//! l3i's own Luau-level versions of these are proposed in
//! `docs/maintenance/NATIVE_TRANSPORT_L3I.md`.

// CI passes -W clippy::pedantic on the command line, overriding the manifest's lint table;
// test code casts freely between widths it controls.
#![allow(
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::too_many_lines
)]

use std::cell::Cell;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dream_net::capture::CaptureRecord;
use dream_net::{
    BufferTooSmall, ChannelConfig, Client, ClientConfig, ClientEvent, EventTypeId, PeerId, Schema,
    SendError, Server, ServerConfig, ServerEvent, TransportConfig, USER_DATA_BYTES,
    generate_connect_token, generate_key,
};

const PROTOCOL: u64 = 0xD4EA_4E70_0000_0015;
// generous: a failure, not the pace, ends a run (sleeps are coarse on some platforms)
const DEADLINE: Duration = Duration::from_secs(120);
const BIG_MAX: usize = 4000;
const SMALL_MAX: usize = 64;
const TICK_MAX: usize = 32;

/// A reliable channel carrying a fragmenting event, a small one and an empty one; an
/// unreliable channel carrying a small event and an empty one.
fn schema() -> Schema {
    let mut b = Schema::builder(15);
    let rel = b
        .channel(ChannelConfig::reliable_ordered("rel").with_capacity(256))
        .unwrap();
    let unrel = b
        .channel(ChannelConfig::unreliable_unordered("unrel").with_capacity(256))
        .unwrap();
    b.event("Big", rel, BIG_MAX as u32).unwrap();
    b.event("Small", rel, SMALL_MAX as u32).unwrap();
    b.event("Zero", rel, 0).unwrap();
    b.event("Tick", unrel, TICK_MAX as u32).unwrap();
    b.event("Nil", unrel, 0).unwrap();
    b.build().unwrap()
}

fn localhost() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn wait_for_the_next_second() {
    let now = || SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let second = now().as_secs();
    while now() < Duration::from_secs(second + 1) + Duration::from_millis(60) {
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// The payload of message `seq` of `stream`: a header naming the stream and sequence, then a
/// pattern derived from both, `len` bytes in all (headers are cut short for tiny lengths).
fn payload(stream: u8, seq: u32, len: usize) -> Vec<u8> {
    let mut header = vec![stream];
    header.extend_from_slice(&seq.to_le_bytes());
    (0..len)
        .map(|i| {
            header
                .get(i)
                .copied()
                .unwrap_or_else(|| (seq as usize * 31 + i * 7 + stream as usize) as u8)
        })
        .collect()
}

/// What one direction of one peer's traffic has sent and not yet seen arrive.
#[derive(Default)]
struct Stream {
    reliable: VecDeque<(EventTypeId, Vec<u8>)>,
    /// Sent and not yet seen, with multiplicity (short payloads repeat).
    unreliable: HashMap<(EventTypeId, Vec<u8>), u32>,
    seq: u32,
    delivered: u64,
}

struct Ids {
    big: EventTypeId,
    small: EventTypeId,
    zero: EventTypeId,
    tick: EventTypeId,
    nil: EventTypeId,
}

impl Ids {
    fn new(schema: &Schema) -> Self {
        let id = |n| schema.event_id(n).unwrap();
        Self {
            big: id("Big"),
            small: id("Small"),
            zero: id("Zero"),
            tick: id("Tick"),
            nil: id("Nil"),
        }
    }

    fn reliable(&self, event: EventTypeId) -> bool {
        event == self.big || event == self.small || event == self.zero
    }
}

/// The events frame `frame` sends on a stream: always a small one and an empty one on each
/// channel, a large one now and then (every eleventh at the maximum).
fn frame_events(ids: &Ids, frame: u32, stream: u8) -> Vec<(EventTypeId, usize)> {
    let mut out = vec![
        (
            ids.small,
            (frame as usize + stream as usize) % (SMALL_MAX + 1),
        ),
        (ids.zero, 0),
        (
            ids.tick,
            (frame as usize * 3 + stream as usize) % (TICK_MAX + 1),
        ),
        (ids.nil, 0),
    ];
    if frame % 25 == stream as u32 % 25 {
        let n = frame / 25;
        let len = if n.is_multiple_of(11) {
            BIG_MAX
        } else {
            (n as usize * 997) % BIG_MAX
        };
        out.push((ids.big, len));
    }
    out
}

/// Sends `frame`'s events on `stream` through `send`, reusing (and scribbling over) one
/// outgoing buffer, as a script reusing a Luau buffer would. Refused reliable events
/// (`QueueFull`) are retried on the next frame.
fn send_frame(
    ids: &Ids,
    frame: u32,
    stream_id: u8,
    stream: &mut Stream,
    backlog: &mut VecDeque<(EventTypeId, usize)>,
    out: &mut Vec<u8>,
    mut send: impl FnMut(EventTypeId, &[u8]) -> Result<(), SendError>,
) {
    backlog.extend(frame_events(ids, frame, stream_id));
    while let Some(&(event, len)) = backlog.front() {
        let bytes = payload(stream_id, stream.seq, len);
        out.clear();
        out.extend_from_slice(&bytes);
        out.resize(BIG_MAX + 16, 0xA5);
        match send(event, &out[..len]) {
            Ok(()) => {}
            Err(SendError::QueueFull(_)) if ids.reliable(event) => break,
            Err(SendError::QueueFull(_)) => {
                backlog.pop_front();
                continue;
            }
            Err(e) => panic!("{e}"),
        }
        // the transport copied the payload: the caller's buffer is free again at once
        out.fill(0x5A);
        backlog.pop_front();
        stream.seq += 1;
        if ids.reliable(event) {
            stream.reliable.push_back((event, bytes));
        } else {
            *stream.unreliable.entry((event, bytes)).or_default() += 1;
        }
    }
}

/// Checks one delivered message against its stream.
fn arrived(ids: &Ids, stream: &mut Stream, event: EventTypeId, bytes: &[u8]) {
    stream.delivered += 1;
    if ids.reliable(event) {
        let (expected_event, expected) = stream.reliable.pop_front().expect("unexpected event");
        assert_eq!(event, expected_event, "reliable order");
        assert_eq!(bytes, expected, "reliable payload");
    } else {
        let left = stream
            .unreliable
            .get_mut(&(event, bytes.to_vec()))
            .filter(|n| **n > 0)
            .unwrap_or_else(|| {
                panic!("unreliable payload unknown or duplicated: {event:?} {bytes:?}")
            });
        *left -= 1;
    }
}

/// The caller-owned receive buffer, resized between polls the way a script might: empty,
/// tiny, exactly the size the last refusal named, or oversized with a sentinel tail.
struct PollBuffer {
    bytes: Vec<u8>,
    round: u32,
    refusals: u64,
}

const SENTINEL: u8 = 0xEE;

impl PollBuffer {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            round: 0,
            refusals: 0,
        }
    }

    fn reshape(&mut self) {
        self.round += 1;
        let len = match self.round % 5 {
            0 => 0,
            1 => 7,
            2 => SMALL_MAX,
            3 => BIG_MAX,
            _ => BIG_MAX + 64,
        };
        self.bytes.clear();
        self.bytes.resize(len, SENTINEL);
    }

    /// Polls through `poll` until it yields, growing the buffer to exactly the refused size.
    /// Returns the event, its payload and the buffer it landed in.
    fn poll<E>(
        &mut self,
        mut poll: impl FnMut(&mut [u8]) -> Result<Option<E>, BufferTooSmall>,
        len_of: impl Fn(&E) -> usize,
    ) -> Option<(E, Vec<u8>)> {
        self.reshape();
        loop {
            match poll(&mut self.bytes) {
                Ok(None) => return None,
                Ok(Some(event)) => {
                    let len = len_of(&event);
                    assert!(len <= self.bytes.len());
                    // nothing past the payload was touched
                    assert!(
                        self.bytes[len..].iter().all(|&b| b == SENTINEL),
                        "poll_into wrote past the payload"
                    );
                    let payload = self.bytes[..len].to_vec();
                    // the caller may scribble over its buffer at once
                    self.bytes.fill(SENTINEL);
                    return Some((event, payload));
                }
                Err(BufferTooSmall { needed }) => {
                    assert!(
                        needed > self.bytes.len(),
                        "{needed} fits {}",
                        self.bytes.len()
                    );
                    assert!(
                        self.bytes.iter().all(|&b| b == SENTINEL),
                        "a refused poll wrote into the buffer"
                    );
                    self.refusals += 1;
                    // exactly what was asked for: nothing was consumed, so the same event
                    // comes back
                    self.bytes.clear();
                    self.bytes.resize(needed, SENTINEL);
                }
            }
        }
    }
}

/// What `poll_into` returns: the event with its payload's length, borrowing nothing.
type ServerPoll = Result<Option<ServerEvent<usize>>, BufferTooSmall>;
type ClientPoll = Result<Option<ClientEvent<usize>>, BufferTooSmall>;

fn server_len(event: &ServerEvent<usize>) -> usize {
    match event {
        ServerEvent::Message { payload, .. } => *payload,
        _ => 0,
    }
}

fn client_len(event: &ClientEvent<usize>) -> usize {
    match event {
        ClientEvent::Message { payload, .. } => *payload,
        _ => 0,
    }
}

#[test]
fn caller_owned_buffers_survive_thousands_of_frames_with_two_peers() {
    let schema = schema();
    let ids = Ids::new(&schema);
    let key = generate_key();
    let mut server = Server::new(
        ServerConfig {
            public_address: localhost(),
            protocol_id: PROTOCOL,
            max_clients: 2,
            transport: TransportConfig::default(),
        },
        &key,
        schema.clone(),
        0.0,
    )
    .unwrap();
    let mut clients: Vec<Client> = (0..2)
        .map(|_| {
            Client::new(
                ClientConfig {
                    bind_address: localhost(),
                    transport: TransportConfig::default(),
                },
                schema.clone(),
                0.0,
            )
            .unwrap()
        })
        .collect();
    wait_for_the_next_second();
    for (i, client) in clients.iter_mut().enumerate() {
        let token = generate_connect_token(
            &[server.address()],
            &[server.address()],
            30,
            5,
            1000 + i as u64,
            PROTOCOL,
            &key,
            &[0; USER_DATA_BYTES],
        )
        .unwrap();
        client.connect(&token).unwrap();
    }

    let started = Instant::now();
    // streams 0, 1: client i to the server; streams 2, 3: the server to client i
    let mut streams: Vec<Stream> = (0..4).map(|_| Stream::default()).collect();
    let mut backlogs: Vec<VecDeque<(EventTypeId, usize)>> = vec![VecDeque::new(); 4];
    let mut out = Vec::new();
    let mut server_buffer = PollBuffer::new();
    let mut client_buffers = [PollBuffer::new(), PollBuffer::new()];
    let mut peers: HashMap<PeerId, usize> = HashMap::new();
    let mut client_connected = [false; 2];
    let frames = 3000u32;
    let mut frame = 0u32;
    let deadline = Instant::now() + DEADLINE;
    loop {
        let time = started.elapsed().as_secs_f64();
        server.update(time);
        for c in &mut clients {
            c.update(time);
        }
        while let Some((event, bytes)) = server_buffer.poll(|b| server.poll_into(b), server_len) {
            match event {
                ServerEvent::Connected { peer, client_id } => {
                    peers.insert(peer, (client_id - 1000) as usize);
                }
                ServerEvent::Message {
                    peer,
                    event,
                    payload,
                    ..
                } => {
                    assert_eq!(payload, bytes.len());
                    // the authenticated slot names the stream, whatever the payload says
                    let from = peers[&peer];
                    if let Some(&stream) = bytes.first() {
                        assert_eq!(stream as usize, from, "attributed to its sender");
                    }
                    arrived(&ids, &mut streams[from], event, &bytes);
                }
                other => panic!("{other:?}"),
            }
        }
        for (i, client) in clients.iter_mut().enumerate() {
            while let Some((event, bytes)) =
                client_buffers[i].poll(|b| client.poll_into(b), client_len)
            {
                match event {
                    ClientEvent::Connected => client_connected[i] = true,
                    ClientEvent::Message { event, payload, .. } => {
                        assert_eq!(payload, bytes.len());
                        arrived(&ids, &mut streams[2 + i], event, &bytes);
                    }
                    other => panic!("{other:?}"),
                }
            }
        }
        let connected = peers.len() == 2 && client_connected == [true; 2];
        if connected && frame < frames {
            for i in 0..2 {
                let peer = *peers.iter().find(|(_, c)| **c == i).unwrap().0;
                let (up, down) = streams.split_at_mut(2);
                let client = &mut clients[i];
                send_frame(
                    &ids,
                    frame,
                    i as u8,
                    &mut up[i],
                    &mut backlogs[i],
                    &mut out,
                    |e, p| client.send(e, p),
                );
                send_frame(
                    &ids,
                    frame,
                    2 + i as u8,
                    &mut down[i],
                    &mut backlogs[2 + i],
                    &mut out,
                    |e, p| server.send(peer, e, p),
                );
            }
            frame += 1;
        }
        server.flush();
        for c in &mut clients {
            c.flush();
        }
        let drained = streams.iter().all(|s| s.reliable.is_empty())
            && backlogs.iter().all(VecDeque::is_empty);
        if frame == frames && drained {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "frame {frame}, outstanding {:?}",
            streams.iter().map(|s| s.reliable.len()).collect::<Vec<_>>()
        );
        std::thread::sleep(Duration::from_micros(500));
    }
    // every stream carried every kind of payload; unreliable ones may (rarely) be lost on
    // loopback, never corrupted or duplicated (checked on arrival)
    for (i, s) in streams.iter().enumerate() {
        assert!(s.seq > frames * 4, "stream {i} sent {}", s.seq);
        assert!(
            s.delivered >= u64::from(frames) * 2,
            "stream {i}: {}",
            s.delivered
        );
    }
    let refusals = server_buffer.refusals + client_buffers.iter().map(|b| b.refusals).sum::<u64>();
    assert!(
        refusals > 1000,
        "too-small buffers were exercised: {refusals}"
    );
}

/// `update` and `flush` take nothing but the time, and no host code runs inside them: a
/// capture sink (the only host code dream-net can be given) fires only from `poll`,
/// `poll_into` and `send`.
#[test]
fn the_network_phase_runs_no_host_code() {
    // the signatures: no closure, no trait object, nothing but `self` and a time
    let _: fn(&mut Server, f64) = Server::update;
    let _: fn(&mut Server) = Server::flush;
    let _: fn(&mut Client, f64) = Client::update;
    let _: fn(&mut Client) = Client::flush;
    // what a poll hands back borrows nothing from the caller's buffer
    let _: fn(&mut Server, &mut [u8]) -> ServerPoll = Server::poll_into;
    let _: fn(&mut Client, &mut [u8]) -> ClientPoll = Client::poll_into;

    let schema = schema();
    let ids = Ids::new(&schema);
    let key = generate_key();
    let mut server = Server::new(
        ServerConfig {
            public_address: localhost(),
            protocol_id: PROTOCOL,
            max_clients: 2,
            transport: TransportConfig::default(),
        },
        &key,
        schema.clone(),
        0.0,
    )
    .unwrap();
    let mut client = Client::new(
        ClientConfig {
            bind_address: localhost(),
            transport: TransportConfig::default(),
        },
        schema,
        0.0,
    )
    .unwrap();
    let in_network_phase = Rc::new(Cell::new(false));
    let calls = Rc::new(Cell::new(0u64));
    let violations = Rc::new(Cell::new(0u64));
    let sink = || {
        let (phase, calls, violations) = (
            Rc::clone(&in_network_phase),
            Rc::clone(&calls),
            Rc::clone(&violations),
        );
        move |_: &CaptureRecord<&[u8]>| {
            calls.set(calls.get() + 1);
            if phase.get() {
                violations.set(violations.get() + 1);
            }
        }
    };
    server.set_capture(Some(Box::new(sink())));
    client.set_capture(Some(Box::new(sink())));
    wait_for_the_next_second();
    let token = generate_connect_token(
        &[server.address()],
        &[server.address()],
        30,
        5,
        7,
        PROTOCOL,
        &key,
        &[0; USER_DATA_BYTES],
    )
    .unwrap();
    client.connect(&token).unwrap();
    let started = Instant::now();
    let mut peer = None;
    let mut received = 0;
    let mut buffer = vec![0u8; BIG_MAX];
    while received < 200 {
        assert!(started.elapsed() < DEADLINE);
        let time = started.elapsed().as_secs_f64();
        in_network_phase.set(true);
        server.update(time);
        client.update(time);
        in_network_phase.set(false);
        while let Some(event) = server.poll_into(&mut buffer).unwrap() {
            match event {
                ServerEvent::Connected { peer: p, .. } => peer = Some(p),
                ServerEvent::Message { .. } => received += 1,
                _ => {}
            }
        }
        while let Some(event) = client.poll_into(&mut buffer).unwrap() {
            if let ClientEvent::Message { .. } = event {
                received += 1;
            }
        }
        if let Some(peer) = peer {
            let _ = client.send(ids.small, b"up");
            let _ = server.send(peer, ids.big, &[9; 2000]);
        }
        in_network_phase.set(true);
        server.flush();
        client.flush();
        in_network_phase.set(false);
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(calls.get() > 200, "the sinks ran from poll and send");
    assert_eq!(violations.get(), 0, "host code ran during update or flush");
}
