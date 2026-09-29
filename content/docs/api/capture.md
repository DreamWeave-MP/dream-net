+++
title = "Captures"
description = "CaptureSink, CaptureRecord, CaptureKind, CaptureWriter, CaptureReader, CaptureHeader and CAPTURE_VERSION."
weight = 100

[extra]
kind = "api"
+++

Module `dream_net::capture`, not re-exported from the root. [Protocol captures](@/docs/captures.md)
shows it in use and gives the file format.

## CaptureSink

{{ api_signature(value="trait CaptureSink { fn record(&mut self, record: &CaptureRecord<&[u8]>); }") }}

Receives capture records from a `Server` or `Client` it is installed on with `set_capture`. It is
called on the host's thread during `send`, `broadcast` and `poll`, so it should be cheap.

Implemented for every `FnMut(&CaptureRecord<&[u8]>)`, and for `CaptureWriter`.

## CaptureRecord

{{ api_signature(value="struct CaptureRecord<P> { pub time: f64, pub peer: PeerId, pub kind: CaptureKind<P> }") }}

One record: the host's time in seconds, the peer it concerns (a client's server is slot 0), and
what happened. `P` is the payload type: `&[u8]` going into a sink, `Vec<u8>` coming out of a
reader. `Clone`, `Copy` when `P` is, `Debug`, `PartialEq`.

## CaptureKind

{{ api_signature(value="enum CaptureKind<P> { Sent { event, channel, len, payload: P }, Received { event, channel, len, payload: P }, Connected { client_id }, Disconnected { reason }, Rejected { client_id, reason } }") }}

| Variant | Fields | Meaning |
|---|---|---|
| `Sent` | `event: EventTypeId`, `channel: ChannelId`, `len: usize`, `payload: P` | The host queued an event |
| `Received` | the same | The host polled an event |
| `Connected` | `client_id: u64` | A peer was announced |
| `Disconnected` | `reason: DisconnectReason` | A peer left |
| `Rejected` | `client_id: u64`, `reason: DisconnectReason` | A peer failed the handshake, or a client's attempt failed |

`len` is the payload's length; `payload` is empty when the capture does not keep payloads.
`Clone`, `Copy` when `P` is, `Debug`, `Eq`.

## CaptureWriter

{{ api_signature(value="struct CaptureWriter<W: Write>") }}

Writes the binary capture format to `W`. It is a `CaptureSink`, so it can be installed on a host
directly. `Debug`.

{{ api_signature(value="fn new(out: W, schema: &Schema, payloads: bool) -> io::Result<CaptureWriter<W>>") }}

Writes the header, with the schema's fingerprint and its channel and event names, and returns the
writer. With `payloads` false, only payload lengths are kept. Errors: any I/O error writing the
header.

{{ api_signature(value="fn error(&self) -> Option<&io::Error>") }}

The first write error, if any. Recording stops after one.

{{ api_signature(value="fn finish(self) -> io::Result<W>") }}

Flushes and returns the writer's output. Errors: the first recording error, or the flush's.

## CaptureReader

{{ api_signature(value="struct CaptureReader<R: Read>") }}

Reads the binary capture format. It treats the input as untrusted: every length is checked against
what remains, and nothing is allocated beyond the input's size. `Debug`.

{{ api_signature(value="fn new(input: R) -> io::Result<CaptureReader<R>>") }}

Reads and checks the header. Errors: a magic that is not `DNCAP\0`, a version other than
`CAPTURE_VERSION`, a name that is not UTF-8 (`InvalidData`), or truncated input
(`UnexpectedEof`).

{{ api_signature(value="fn header(&self) -> &CaptureHeader") }}

The header.

{{ api_signature(value="fn next_record(&mut self) -> io::Result<Option<CaptureRecord<Vec<u8>>>>") }}

The next record, or `None` at a clean end of input. Errors: a truncated record or payload, an
unknown record kind, or an unknown reason code.

## CaptureHeader

{{ api_signature(value="struct CaptureHeader { pub version: u16, pub payloads: bool, pub fingerprint: Fingerprint, pub channels: Vec<String>, pub events: Vec<(ChannelId, String)> }") }}

What a capture says about itself: its format version, whether it kept payloads, the schema's
fingerprint, the channel names by id, and each event's channel and name by id. `Clone`, `Debug`,
`Eq`.

{{ api_signature(value="fn event_name(&self, event: EventTypeId) -> Option<&str>") }}

An event's name, or `None` for an id the capture's schema does not have.

## CAPTURE_VERSION

{{ api_signature(value="const CAPTURE_VERSION: u16 = 1") }}

The capture format version this crate writes and reads.
