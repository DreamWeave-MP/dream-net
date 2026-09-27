//! Capture format round trips, hostile capture files, and a live server capture.

mod common;

use std::cell::RefCell;
use std::io::Write;
use std::rc::Rc;
use std::time::Duration;

use common::test_schema;
use dream_net::capture::{CaptureKind, CaptureReader, CaptureRecord, CaptureSink, CaptureWriter};
use dream_net::{
    ChannelId, Client, ClientConfig, ClientStatus, DisconnectReason, EventTypeId, PeerId, Server,
    ServerConfig, TransportConfig,
};

#[derive(Clone, Default)]
struct Shared(Rc<RefCell<Vec<u8>>>);

impl Write for Shared {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn records() -> Vec<CaptureRecord<&'static [u8]>> {
    let peer = PeerId::new(3, 9);
    vec![
        CaptureRecord {
            time: 0.5,
            peer,
            kind: CaptureKind::Connected { client_id: 77 },
        },
        CaptureRecord {
            time: 0.75,
            peer,
            kind: CaptureKind::Received {
                event: EventTypeId(1),
                channel: ChannelId(0),
                len: 5,
                payload: b"hello",
            },
        },
        CaptureRecord {
            time: 1.0,
            peer,
            kind: CaptureKind::Sent {
                event: EventTypeId(2),
                channel: ChannelId(1),
                len: 0,
                payload: b"",
            },
        },
        CaptureRecord {
            time: 2.0,
            peer,
            kind: CaptureKind::Rejected {
                client_id: 5,
                reason: DisconnectReason::SchemaMismatch,
            },
        },
        CaptureRecord {
            time: 3.0,
            peer,
            kind: CaptureKind::Disconnected {
                reason: DisconnectReason::TimedOut,
            },
        },
    ]
}

fn write(payloads: bool) -> Vec<u8> {
    let mut writer = CaptureWriter::new(Vec::new(), &test_schema(), payloads).unwrap();
    for record in records() {
        writer.record(&record);
    }
    writer.finish().unwrap()
}

#[test]
fn round_trips_with_and_without_payloads() {
    for payloads in [true, false] {
        let bytes = write(payloads);
        let mut reader = CaptureReader::new(bytes.as_slice()).unwrap();
        let header = reader.header().clone();
        assert_eq!(header.fingerprint, test_schema().fingerprint());
        assert_eq!(header.payloads, payloads);
        assert_eq!(header.channels, vec!["reliable", "state", "bulk"]);
        assert_eq!(header.event_name(EventTypeId(1)), Some("Chat"));
        let mut read = Vec::new();
        while let Some(record) = reader.next_record().unwrap() {
            read.push(record);
        }
        assert_eq!(read.len(), records().len());
        for (got, want) in read.iter().zip(records()) {
            assert_eq!(got.time.to_bits(), want.time.to_bits());
            assert_eq!(got.peer, want.peer);
            match (&got.kind, want.kind) {
                (
                    CaptureKind::Received { len, payload, .. }
                    | CaptureKind::Sent { len, payload, .. },
                    CaptureKind::Received {
                        len: want_len,
                        payload: want_payload,
                        ..
                    }
                    | CaptureKind::Sent {
                        len: want_len,
                        payload: want_payload,
                        ..
                    },
                ) => {
                    assert_eq!(*len, want_len);
                    if payloads {
                        assert_eq!(payload.as_slice(), want_payload);
                    } else {
                        assert!(payload.is_empty());
                    }
                }
                (a, b) => assert_eq!(format!("{a:?}"), format!("{b:?}")),
            }
        }
    }
}

#[test]
fn hostile_captures_fail_cleanly() {
    assert!(CaptureReader::new(&b"NOTCAP"[..]).is_err());
    let bytes = write(true);
    // every truncation either fails or ends early; none panics
    for len in 0..bytes.len() {
        if let Ok(mut reader) = CaptureReader::new(&bytes[..len]) {
            while let Ok(Some(_)) = reader.next_record() {}
        }
    }
    // a record claiming a 4 GiB payload in a tiny file must not allocate 4 GiB
    let mut bytes = write(true);
    let header_len = bytes.len() - {
        let mut body = Vec::new();
        let mut w = CaptureWriter::new(&mut body, &test_schema(), true).unwrap();
        for r in records() {
            w.record(&r);
        }
        drop(w);
        body.len()
            - CaptureWriter::new(Vec::new(), &test_schema(), true)
                .unwrap()
                .finish()
                .unwrap()
                .len()
    };
    bytes.truncate(header_len);
    bytes.push(2);
    bytes.extend_from_slice(&1.0f64.to_le_bytes());
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&u32::MAX.to_le_bytes());
    let mut reader = CaptureReader::new(bytes.as_slice()).unwrap();
    assert!(reader.next_record().is_err());
}

#[test]
fn a_server_captures_its_session() {
    let key = dream_net::generate_key();
    let mut server = Server::new(
        ServerConfig {
            public_address: "127.0.0.1:0".parse().unwrap(),
            protocol_id: 1,
            max_clients: 2,
            transport: TransportConfig::default(),
        },
        &key,
        test_schema(),
        0.0,
    )
    .unwrap();
    let out = Shared::default();
    server.set_capture(Some(Box::new(
        CaptureWriter::new(out.clone(), &test_schema(), true).unwrap(),
    )));
    let mut client = Client::new(
        ClientConfig {
            bind_address: "127.0.0.1:0".parse().unwrap(),
            transport: TransportConfig::default(),
        },
        test_schema(),
        0.0,
    )
    .unwrap();
    let address = server.address();
    let token = dream_net::generate_connect_token(
        &[address],
        &[address],
        30,
        5,
        31,
        1,
        &key,
        &[0; dream_net::USER_DATA_BYTES],
    )
    .unwrap();
    client.connect(&token).unwrap();
    let chat = test_schema().event_id("Chat").unwrap();
    let mut time = 0.0;
    let mut peer = None;
    let mut sent = false;
    let mut echoed = false;
    for _ in 0..600 {
        time += 1.0 / 60.0;
        server.update(time);
        client.update(time);
        while let Some(event) = server.poll() {
            match event {
                dream_net::ServerEvent::Connected { peer: p, .. } => peer = Some(p),
                dream_net::ServerEvent::Message { .. } => echoed = true,
                _ => {}
            }
        }
        while client.poll().is_some() {}
        if client.status() == ClientStatus::Connected && !sent {
            client.send(chat, b"captured").unwrap();
            sent = true;
        }
        if echoed {
            server.send(peer.unwrap(), chat, b"reply").unwrap();
            server.disconnect(peer.unwrap());
            while server.poll().is_some() {}
            break;
        }
        server.flush();
        client.flush();
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(echoed);
    drop(server);
    let bytes = out.0.borrow().clone();
    let mut reader = CaptureReader::new(bytes.as_slice()).unwrap();
    let mut kinds = Vec::new();
    while let Some(record) = reader.next_record().unwrap() {
        kinds.push(record.kind);
    }
    assert_eq!(
        kinds,
        vec![
            CaptureKind::Connected { client_id: 31 },
            CaptureKind::Received {
                event: chat,
                channel: ChannelId(0),
                len: 8,
                payload: b"captured".to_vec()
            },
            CaptureKind::Sent {
                event: chat,
                channel: ChannelId(0),
                len: 5,
                payload: b"reply".to_vec()
            },
            CaptureKind::Disconnected {
                reason: DisconnectReason::Requested
            },
        ]
    );
}
