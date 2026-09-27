//! Protocol captures: a record of what crossed the host boundary, for tooling.
//!
//! A [`CaptureSink`] installed on a [`Server`](crate::Server) or [`Client`](crate::Client)
//! sees every event the host sends, every event and lifecycle record it polls, with the host's
//! time. [`CaptureWriter`] stores them in a small, versioned binary format that carries the
//! schema's names, so a capture can be inspected (by Jess, for instance) without the engine
//! that produced it. [`CaptureReader`] reads it back. Decoding payloads into engine values is
//! the engine's business; the capture keeps raw bytes.
//!
//! Format (all integers little endian):
//!
//! ```text
//! file    := magic "DNCAP\0" version:u16 flags:u16 fingerprint:u128
//!            channel_count:u16 (name_len:u8 name)*
//!            event_count:u32 (channel:u8 name_len:u8 name)*
//!            record*
//! record  := kind:u8 time:f64 peer:u64 body
//!   1 sent / 2 received  body := event:u32 channel:u8 len:u32 payload[len if flags & 1]
//!   3 connected          body := client_id:u64
//!   4 disconnected       body := reason:u8
//!   5 rejected           body := client_id:u64 reason:u8
//! ```
//!
//! With no sink installed, capturing costs one predictable branch per event.

use std::io::{self, Read, Write};

use crate::id::{ChannelId, EventTypeId, PeerId};
use crate::lifecycle::DisconnectReason;
use crate::schema::{Fingerprint, Schema};

/// The capture format version.
pub const CAPTURE_VERSION: u16 = 1;
const MAGIC: &[u8; 6] = b"DNCAP\0";
const FLAG_PAYLOADS: u16 = 1;

/// What happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureKind<P> {
    /// The host queued an event.
    Sent {
        /// The event.
        event: EventTypeId,
        /// Its channel.
        channel: ChannelId,
        /// Its payload length.
        len: usize,
        /// Its payload (empty when the capture does not keep payloads).
        payload: P,
    },
    /// The host polled an event.
    Received {
        /// The event.
        event: EventTypeId,
        /// Its channel.
        channel: ChannelId,
        /// Its payload length.
        len: usize,
        /// Its payload (empty when the capture does not keep payloads).
        payload: P,
    },
    /// A peer was announced.
    Connected {
        /// Its authenticated id.
        client_id: u64,
    },
    /// A peer left.
    Disconnected {
        /// Why.
        reason: DisconnectReason,
    },
    /// A peer failed the handshake.
    Rejected {
        /// Its authenticated id.
        client_id: u64,
        /// Why.
        reason: DisconnectReason,
    },
}

/// One capture record.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CaptureRecord<P> {
    /// Host time, seconds.
    pub time: f64,
    /// The peer (a client's server is always slot 0).
    pub peer: PeerId,
    /// What happened.
    pub kind: CaptureKind<P>,
}

/// Receives capture records. Called on the host's thread during `send`/`poll`; keep it cheap.
pub trait CaptureSink {
    /// Records one event.
    fn record(&mut self, record: &CaptureRecord<&[u8]>);
}

impl<F: FnMut(&CaptureRecord<&[u8]>)> CaptureSink for F {
    fn record(&mut self, record: &CaptureRecord<&[u8]>) {
        self(record);
    }
}

/// Writes the binary capture format.
#[derive(Debug)]
pub struct CaptureWriter<W: Write> {
    out: W,
    payloads: bool,
    error: Option<io::Error>,
}

impl<W: Write> CaptureWriter<W> {
    /// Writes the header (with `schema`'s names) and returns a writer. With `payloads`
    /// false, only payload lengths are kept.
    ///
    /// # Errors
    ///
    /// Any I/O error writing the header.
    pub fn new(mut out: W, schema: &Schema, payloads: bool) -> io::Result<Self> {
        out.write_all(MAGIC)?;
        out.write_all(&CAPTURE_VERSION.to_le_bytes())?;
        let flags = if payloads { FLAG_PAYLOADS } else { 0 };
        out.write_all(&flags.to_le_bytes())?;
        out.write_all(&schema.fingerprint().0.to_le_bytes())?;
        out.write_all(&(schema.channels().len() as u16).to_le_bytes())?;
        for channel in schema.channels() {
            out.write_all(&[channel.name().len() as u8])?;
            out.write_all(channel.name().as_bytes())?;
        }
        out.write_all(&(schema.events().len() as u32).to_le_bytes())?;
        for event in schema.events() {
            out.write_all(&[event.channel.0, event.name.len() as u8])?;
            out.write_all(event.name.as_bytes())?;
        }
        Ok(Self {
            out,
            payloads,
            error: None,
        })
    }

    /// The first write error, if any. Recording stops after one.
    pub fn error(&self) -> Option<&io::Error> {
        self.error.as_ref()
    }

    /// Flushes and returns the underlying writer.
    ///
    /// # Errors
    ///
    /// The first recording error, or the flush error.
    pub fn finish(mut self) -> io::Result<W> {
        if let Some(error) = self.error.take() {
            return Err(error);
        }
        self.out.flush()?;
        Ok(self.out)
    }

    fn write(&mut self, record: &CaptureRecord<&[u8]>) -> io::Result<()> {
        let (kind, time, peer) = (&record.kind, record.time, record.peer.0);
        let tag = match kind {
            CaptureKind::Sent { .. } => 1u8,
            CaptureKind::Received { .. } => 2,
            CaptureKind::Connected { .. } => 3,
            CaptureKind::Disconnected { .. } => 4,
            CaptureKind::Rejected { .. } => 5,
        };
        let mut head = [0u8; 17];
        head[0] = tag;
        head[1..9].copy_from_slice(&time.to_le_bytes());
        head[9..17].copy_from_slice(&peer.to_le_bytes());
        self.out.write_all(&head)?;
        match *kind {
            CaptureKind::Sent {
                event,
                channel,
                payload,
                ..
            }
            | CaptureKind::Received {
                event,
                channel,
                payload,
                ..
            } => {
                let mut body = [0u8; 9];
                body[..4].copy_from_slice(&event.0.to_le_bytes());
                body[4] = channel.0;
                body[5..9].copy_from_slice(&(payload.len() as u32).to_le_bytes());
                self.out.write_all(&body)?;
                if self.payloads {
                    self.out.write_all(payload)?;
                }
            }
            CaptureKind::Connected { client_id } => self.out.write_all(&client_id.to_le_bytes())?,
            CaptureKind::Disconnected { reason } => self.out.write_all(&[reason_code(reason)])?,
            CaptureKind::Rejected { client_id, reason } => {
                self.out.write_all(&client_id.to_le_bytes())?;
                self.out.write_all(&[reason_code(reason)])?;
            }
        }
        Ok(())
    }
}

impl<W: Write> CaptureSink for CaptureWriter<W> {
    fn record(&mut self, record: &CaptureRecord<&[u8]>) {
        if self.error.is_none()
            && let Err(error) = self.write(record)
        {
            self.error = Some(error);
        }
    }
}

const REASONS: [DisconnectReason; 10] = [
    DisconnectReason::Requested,
    DisconnectReason::Remote,
    DisconnectReason::TimedOut,
    DisconnectReason::Denied,
    DisconnectReason::Authentication,
    DisconnectReason::ProtocolMismatch,
    DisconnectReason::SchemaMismatch,
    DisconnectReason::MalformedData,
    DisconnectReason::HandshakeTimeout,
    DisconnectReason::TransportError,
];

fn reason_code(reason: DisconnectReason) -> u8 {
    REASONS.iter().position(|r| *r == reason).unwrap_or(0) as u8
}

/// The schema names a capture carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureHeader {
    /// The capture format version.
    pub version: u16,
    /// Whether payload bytes were kept.
    pub payloads: bool,
    /// The schema fingerprint.
    pub fingerprint: Fingerprint,
    /// Channel names by id.
    pub channels: Vec<String>,
    /// `(channel, name)` of each event by id.
    pub events: Vec<(ChannelId, String)>,
}

impl CaptureHeader {
    /// An event's name.
    pub fn event_name(&self, event: EventTypeId) -> Option<&str> {
        self.events.get(event.0 as usize).map(|(_, n)| n.as_str())
    }
}

/// Reads the binary capture format. Treats the file as untrusted: every length is checked
/// against what remains, and nothing is allocated beyond the input's size.
#[derive(Debug)]
pub struct CaptureReader<R: Read> {
    input: R,
    header: CaptureHeader,
}

fn invalid(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("capture: {what}"))
}

fn read_array<const N: usize, R: Read>(input: &mut R) -> io::Result<[u8; N]> {
    let mut bytes = [0u8; N];
    input.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn read_name<R: Read>(input: &mut R, len: u8) -> io::Result<String> {
    let mut bytes = vec![0u8; usize::from(len)];
    input.read_exact(&mut bytes)?;
    String::from_utf8(bytes).map_err(|_| invalid("name is not UTF-8"))
}

impl<R: Read> CaptureReader<R> {
    /// Reads and checks the header.
    ///
    /// # Errors
    ///
    /// A bad magic, an unknown version, or truncated input.
    pub fn new(mut input: R) -> io::Result<Self> {
        if &read_array::<6, _>(&mut input)? != MAGIC {
            return Err(invalid("not a dream-net capture"));
        }
        let version = u16::from_le_bytes(read_array(&mut input)?);
        if version != CAPTURE_VERSION {
            return Err(invalid("unknown version"));
        }
        let flags = u16::from_le_bytes(read_array(&mut input)?);
        let fingerprint = Fingerprint(u128::from_le_bytes(read_array(&mut input)?));
        let channel_count = u16::from_le_bytes(read_array(&mut input)?);
        let mut channels = Vec::new();
        for _ in 0..channel_count {
            let [len] = read_array(&mut input)?;
            channels.push(read_name(&mut input, len)?);
        }
        let event_count = u32::from_le_bytes(read_array(&mut input)?);
        let mut events = Vec::new();
        for _ in 0..event_count {
            let [channel, len] = read_array(&mut input)?;
            events.push((ChannelId(channel), read_name(&mut input, len)?));
        }
        Ok(Self {
            input,
            header: CaptureHeader {
                version,
                payloads: flags & FLAG_PAYLOADS != 0,
                fingerprint,
                channels,
                events,
            },
        })
    }

    /// The header.
    pub fn header(&self) -> &CaptureHeader {
        &self.header
    }

    /// Reads the next record; `None` at a clean end of input.
    ///
    /// # Errors
    ///
    /// Truncated or malformed records.
    pub fn next_record(&mut self) -> io::Result<Option<CaptureRecord<Vec<u8>>>> {
        let mut tag = [0u8; 1];
        if self.input.read(&mut tag)? == 0 {
            return Ok(None);
        }
        let time = f64::from_le_bytes(read_array(&mut self.input)?);
        let peer = PeerId(u64::from_le_bytes(read_array(&mut self.input)?));
        let kind = match tag[0] {
            1 | 2 => {
                let body: [u8; 9] = read_array(&mut self.input)?;
                let [e0, e1, e2, e3, channel, l0, l1, l2, l3] = body;
                let event = EventTypeId(u32::from_le_bytes([e0, e1, e2, e3]));
                let channel = ChannelId(channel);
                let len = u32::from_le_bytes([l0, l1, l2, l3]) as usize;
                let payload = if self.header.payloads {
                    // read through `take` so a lying length cannot allocate past the input
                    let mut payload = Vec::new();
                    (&mut self.input)
                        .take(len as u64)
                        .read_to_end(&mut payload)?;
                    if payload.len() != len {
                        return Err(invalid("truncated payload"));
                    }
                    payload
                } else {
                    Vec::new()
                };
                if tag[0] == 1 {
                    CaptureKind::Sent {
                        event,
                        channel,
                        len,
                        payload,
                    }
                } else {
                    CaptureKind::Received {
                        event,
                        channel,
                        len,
                        payload,
                    }
                }
            }
            3 => CaptureKind::Connected {
                client_id: u64::from_le_bytes(read_array(&mut self.input)?),
            },
            4 => {
                let [code] = read_array(&mut self.input)?;
                CaptureKind::Disconnected {
                    reason: *REASONS
                        .get(usize::from(code))
                        .ok_or_else(|| invalid("reason"))?,
                }
            }
            5 => {
                let client_id = u64::from_le_bytes(read_array(&mut self.input)?);
                let [code] = read_array(&mut self.input)?;
                CaptureKind::Rejected {
                    client_id,
                    reason: *REASONS
                        .get(usize::from(code))
                        .ok_or_else(|| invalid("reason"))?,
                }
            }
            _ => return Err(invalid("unknown record kind")),
        };
        Ok(Some(CaptureRecord { time, peer, kind }))
    }
}
