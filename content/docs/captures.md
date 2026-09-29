+++
title = "Protocol captures"
description = "Recording every event a host sends and every record it polls, the binary capture format, and reading a capture back."
weight = 70

[extra]
kind = "guide"
+++

A capture is a record of what crossed the host boundary: every event a `Server` or `Client` was
asked to send, and every event and lifecycle record it handed back from `poll`, with the host's
time. It records the engine's view of the conversation, not packets, so a tool can replay or
inspect a session without the engine that produced it.

## Installing a sink

Anything that implements `CaptureSink` can receive records, including any
`FnMut(&CaptureRecord<&[u8]>)`:

```rust
use dream_net::capture::{CaptureKind, CaptureRecord};
use dream_net::{ChannelConfig, Schema, Server, ServerConfig, TransportConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut schema = Schema::builder(1);
    let reliable = schema.channel(ChannelConfig::reliable_ordered("reliable"))?;
    schema.event("Chat", reliable, 256)?;
    let config = ServerConfig {
        public_address: "127.0.0.1:0".parse()?,
        protocol_id: 0x4452_4541_4d00_0001,
        max_clients: 8,
        transport: TransportConfig::default(),
    };
    let mut server = Server::new(config, &dream_net::generate_key(), schema.build()?, 0.0)?;

    server.set_capture(Some(Box::new(|record: &CaptureRecord<&[u8]>| {
        if let CaptureKind::Received { event, len, .. } = record.kind {
            println!("{:.3}s {} sent {event}, {len} bytes", record.time, record.peer);
        }
    })));
    // ... run frames ...
    server.set_capture(None);
    Ok(())
}
```

A sink is called on the host's thread, inside `send`, `broadcast` and `poll`, so it should be
cheap. With no sink installed, capturing costs one predictable branch per event.

| `CaptureKind` | Recorded when |
|---|---|
| `Sent { event, channel, len, payload }` | `send` or `broadcast` queued an event, once per peer it was queued for |
| `Received { event, channel, len, payload }` | `poll` or `poll_into` returned an event |
| `Connected { client_id }` | `poll` returned `Connected` |
| `Disconnected { reason }` | `poll` returned `Disconnected` |
| `Rejected { client_id, reason }` | `poll` returned `Rejected`, or a client's `ConnectFailed` |

`time` is the host's time as of its last `update`, and `peer` the peer the record concerns. A
client records the server as slot 0 of its current connection, and its own `Connected` and
`ConnectFailed` with client id 0.

## Writing and reading the format

`CaptureWriter` stores records in a small, versioned binary format that carries the schema's
channel and event names, and `CaptureReader` reads it back:

```rust
use dream_net::capture::{CaptureKind, CaptureReader, CaptureRecord, CaptureSink, CaptureWriter};
use dream_net::{ChannelConfig, PeerId, Schema};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut schema = Schema::builder(1);
    let reliable = schema.channel(ChannelConfig::reliable_ordered("reliable"))?;
    schema.event("Chat", reliable, 256)?;
    let schema = schema.build()?;
    let chat = schema.event_id("Chat").expect("declared");

    // payloads: true keeps the bytes; false keeps only their lengths
    let mut writer = CaptureWriter::new(Vec::new(), &schema, true)?;
    writer.record(&CaptureRecord {
        time: 1.5,
        peer: PeerId::new(0, 1),
        kind: CaptureKind::Received { event: chat, channel: reliable, len: 5, payload: b"hello" },
    });
    let bytes = writer.finish()?;

    let mut reader = CaptureReader::new(bytes.as_slice())?;
    assert_eq!(reader.header().fingerprint, schema.fingerprint());
    while let Some(record) = reader.next_record()? {
        if let CaptureKind::Received { event, payload, .. } = &record.kind {
            let name = reader.header().event_name(*event).unwrap_or("?");
            println!("{} at {}s: {name} {:?}", record.peer, record.time, payload);
        }
    }
    Ok(())
}
```

```text
peer 0:1 at 1.5s: Chat [104, 101, 108, 108, 111]
```

A `CaptureWriter` is itself a `CaptureSink`, so it can be installed on a host directly. It stops
recording after its first write error, which `error()` reports and `finish()` returns.

`CaptureReader` treats a capture as untrusted input: every length is checked against what
remains, nothing is allocated beyond the input's size, and a truncated or malformed file is an
`io::Error` of kind `InvalidData` or `UnexpectedEof`, never a panic. It refuses a file whose magic
or version it does not know.

## The format

All integers are little-endian.

```text
file    := magic "DNCAP\0" version:u16 flags:u16 fingerprint:u128
           channel_count:u16 (name_len:u8 name)*
           event_count:u32 (channel:u8 name_len:u8 name)*
           record*
record  := kind:u8 time:f64 peer:u64 body
  1 sent / 2 received  body := event:u32 channel:u8 len:u32 payload[len if flags & 1]
  3 connected          body := client_id:u64
  4 disconnected       body := reason:u8
  5 rejected           body := client_id:u64 reason:u8
```

The version is `CAPTURE_VERSION`, 1. Flag bit 0 says payloads were kept. A reason is a
`DisconnectReason` by its position in the declaration: `Requested` is 0 and `TransportError` is 9.
