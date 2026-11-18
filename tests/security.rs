//! Security regressions of issue #12 at the connection level, over the deterministic simulator:
//! the configuration limits that guard the packet writer.

// CI passes -W clippy::pedantic on the command line, overriding the manifest's lint table;
// test code casts freely between widths it controls.
#![allow(
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]

use std::sync::Arc;

use dream_net::sim::{LinkConfig, Pair};
use dream_net::{ChannelConfig, ConfigError, Inbox, Record, Schema, Shared, TransportConfig};

const DT: f64 = 1.0 / 60.0;

/// The most channels a schema may have, each with one event.
fn widest_schema() -> Schema {
    let mut b = Schema::builder(1);
    for c in 0..dream_net::schema::MAX_CHANNELS {
        let channel = if c % 2 == 0 {
            b.channel(ChannelConfig::reliable_ordered(format!("r{c}")))
        } else {
            b.channel(ChannelConfig::unreliable_unordered(format!("u{c}")))
        }
        .unwrap();
        b.event(format!("e{c}"), channel, 4).unwrap();
    }
    b.build().unwrap()
}

fn delivered(inbox: &mut Inbox<()>) -> usize {
    let mut n = 0;
    while let Some((record, _)) = inbox.pop() {
        if matches!(record, Record::Message(_)) {
            n += 1;
        }
    }
    n
}

/// A packet budget below the largest packet header passed `validate` in dream-net 1.1.1 and
/// in the native port, and then the header-only packet that carries the handshake was already
/// over budget: a debug assertion in the packet writer fired, and in release a budget (and a
/// `max_packet_size`) below the header produced packets the reliable endpoint refused to send,
/// so the handshake could never complete. `validate` now refuses every budget below the
/// largest header, 20 bytes (2 + 1 + 7 + 144 bits, rounded up).
#[test]
fn a_packet_budget_below_the_largest_header_is_refused() {
    for budget in [0usize, 1, 2, 8, 19] {
        let config = TransportConfig {
            packet_budget: budget,
            ..TransportConfig::default()
        };
        assert_eq!(
            config.validate(),
            Err(ConfigError::Transport(
                "packet_budget must be in [20, max_packet_size]"
            )),
            "budget {budget}"
        );
        assert!(Shared::new(widest_schema(), config).is_err());
    }
    // a max_packet_size below the header cannot hold a budget at all
    let tiny = TransportConfig {
        max_packet_size: 19,
        fragment_above: 19,
        packet_budget: 20,
        ..TransportConfig::default()
    };
    assert!(tiny.validate().is_err());
}

/// The smallest accepted budget works with the widest schema: the handshake completes (its
/// packets are exactly the header plus hello, the largest header there is), events flow on
/// every channel, and no packet the writer produced is over budget, which the writer's debug
/// assertion checks in this (debug) test build.
#[test]
fn the_smallest_packet_budget_carries_the_handshake_and_events_on_every_channel() {
    let schema = widest_schema();
    let config = TransportConfig {
        max_packet_size: 64,
        fragment_above: 64,
        packet_budget: 20,
        ..TransportConfig::default()
    };
    config.validate().unwrap();
    let shared: Arc<Shared> = Shared::new(schema.clone(), config).unwrap();
    let mut pair = Pair::symmetric(&shared, LinkConfig::latency(0.01), 12);
    assert!(
        pair.handshake(DT, 600),
        "no handshake at the smallest budget"
    );
    // one event per channel: with the hello still unacked a header and one event exceed the
    // budget, and such an event goes alone into a packet of up to max_packet_size
    let mut sent = 0;
    for c in 0..dream_net::schema::MAX_CHANNELS {
        let id = schema.event_id(&format!("e{c}")).unwrap();
        pair.b.send(id, &[c as u8; 4]).unwrap();
        sent += 1;
    }
    let mut got = 0;
    for _ in 0..600 {
        pair.step(DT);
        got += delivered(&mut pair.a_inbox);
        if got == sent {
            break;
        }
    }
    // unreliable events may be dropped by the link, never by the writer: the link is perfect
    assert_eq!(got, sent);
}
