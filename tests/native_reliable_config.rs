//! `Config::validate` against the C library: every refusal of `reliable_config_valid` and
//! `reliable_endpoint_create` has its case here, and every config `validate` accepts is
//! accepted by C (`Endpoint::new` succeeds), by property over the space around every limit.

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

use dream_net::native::reliable::{
    Config, ConfigError, Endpoint, MAX_FRAGMENTS, MAX_NAME_BYTES, MAX_PACKET_SIZE,
    MAX_SEQUENCE_BUFFER_SIZE,
};
use proptest::prelude::*;

const INT_MAX: usize = i32::MAX as usize;

fn with(f: impl FnOnce(&mut Config)) -> Config {
    let mut config = Config::default();
    f(&mut config);
    config
}

#[test]
fn every_refusal() {
    use ConfigError as E;
    let cases: Vec<(Config, ConfigError)> = vec![
        (with(|c| c.name = "x".repeat(256)), E::NameTooLong),
        (with(|c| c.name = "a\0b".into()), E::NameContainsNul),
        (
            with(|c| c.max_packet_size = INT_MAX + 1),
            E::NotAnInt("max_packet_size"),
        ),
        (
            with(|c| c.fragment_above = usize::MAX),
            E::NotAnInt("fragment_above"),
        ),
        (
            with(|c| c.max_fragments = INT_MAX + 1),
            E::NotAnInt("max_fragments"),
        ),
        (
            with(|c| c.fragment_size = INT_MAX + 1),
            E::NotAnInt("fragment_size"),
        ),
        (
            with(|c| c.ack_buffer_size = INT_MAX + 1),
            E::NotAnInt("ack_buffer_size"),
        ),
        (
            with(|c| c.sent_packets_buffer_size = INT_MAX + 1),
            E::NotAnInt("sent_packets_buffer_size"),
        ),
        (
            with(|c| c.received_packets_buffer_size = INT_MAX + 1),
            E::NotAnInt("received_packets_buffer_size"),
        ),
        (
            with(|c| c.fragment_reassembly_buffer_size = INT_MAX + 1),
            E::NotAnInt("fragment_reassembly_buffer_size"),
        ),
        (
            with(|c| c.rtt_history_size = INT_MAX + 1),
            E::NotAnInt("rtt_history_size"),
        ),
        (
            with(|c| c.packet_header_size = INT_MAX + 1),
            E::NotAnInt("packet_header_size"),
        ),
        (with(|c| c.max_packet_size = 0), E::Zero("max_packet_size")),
        (with(|c| c.fragment_above = 0), E::Zero("fragment_above")),
        (with(|c| c.fragment_size = 0), E::Zero("fragment_size")),
        (with(|c| c.max_fragments = 0), E::Zero("max_fragments")),
        (with(|c| c.max_fragments = 257), E::TooManyFragments),
        (with(|c| c.ack_buffer_size = 0), E::Zero("ack_buffer_size")),
        (
            with(|c| c.sent_packets_buffer_size = 0),
            E::Zero("sent_packets_buffer_size"),
        ),
        (
            with(|c| c.received_packets_buffer_size = 0),
            E::Zero("received_packets_buffer_size"),
        ),
        (
            with(|c| c.fragment_reassembly_buffer_size = 0),
            E::Zero("fragment_reassembly_buffer_size"),
        ),
        (
            with(|c| c.rtt_history_size = 0),
            E::Zero("rtt_history_size"),
        ),
        (
            with(|c| c.sent_packets_buffer_size = 16385),
            E::WindowTooLarge("sent_packets_buffer_size"),
        ),
        (
            with(|c| c.received_packets_buffer_size = 32768),
            E::WindowTooLarge("received_packets_buffer_size"),
        ),
        (
            with(|c| c.fragment_reassembly_buffer_size = 16385),
            E::WindowTooLarge("fragment_reassembly_buffer_size"),
        ),
        (
            with(|c| c.fragment_above = 16385),
            E::FragmentAboveExceedsMaxPacketSize,
        ),
        // 15 fragments of 1024 cover 15360, not 16384
        (
            with(|c| c.max_fragments = 15),
            E::FragmentsDoNotCoverMaxPacketSize,
        ),
        (
            with(|c| {
                c.max_fragments = 256;
                c.fragment_size = INT_MAX / 256 + 1;
            }),
            E::ReassemblyTooLarge,
        ),
        (
            // INT_MAX - 14: C's config check accepts it; the wrapper keeps one int of headroom
            with(|c| {
                c.max_packet_size = MAX_PACKET_SIZE + 1;
                c.fragment_above = 1;
                c.max_fragments = 1;
                c.fragment_size = MAX_PACKET_SIZE + 1;
            }),
            E::MaxPacketSizeTooLarge,
        ),
        (
            with(|c| c.packet_header_size = INT_MAX - 16384 - 13),
            E::PacketHeaderSizeTooLarge,
        ),
        (
            with(|c| c.rtt_smoothing_factor = -0.001),
            E::SmoothingFactorOutOfRange("rtt_smoothing_factor"),
        ),
        (
            with(|c| c.rtt_smoothing_factor = f32::NAN),
            E::SmoothingFactorOutOfRange("rtt_smoothing_factor"),
        ),
        (
            with(|c| c.packet_loss_smoothing_factor = 1.0001),
            E::SmoothingFactorOutOfRange("packet_loss_smoothing_factor"),
        ),
        (
            with(|c| c.bandwidth_smoothing_factor = f32::INFINITY),
            E::SmoothingFactorOutOfRange("bandwidth_smoothing_factor"),
        ),
        (
            with(|c| {
                c.max_fragments = 1;
                c.fragment_size = INT_MAX - 13;
                c.max_packet_size = 1;
                c.fragment_above = 1;
            }),
            E::FragmentSizeTooLarge,
        ),
    ];
    for (config, expected) in cases {
        assert_eq!(config.validate(), Err(expected), "{config:?}");
        // `new` refuses before anything reaches C
        assert_eq!(Endpoint::new(config, 0.0).err(), Some(expected));
        assert_ne!(expected.to_string(), "");
    }
}

/// The edges that are still accepted, accepted by C too.
#[test]
fn every_edge_that_is_accepted() {
    let accepted = [
        with(|c| c.name = "x".repeat(MAX_NAME_BYTES)),
        with(|c| c.name = String::new()),
        with(|c| c.name = "ünïcödé".into()),
        with(|c| c.max_fragments = MAX_FRAGMENTS),
        with(|c| c.sent_packets_buffer_size = MAX_SEQUENCE_BUFFER_SIZE),
        with(|c| c.received_packets_buffer_size = MAX_SEQUENCE_BUFFER_SIZE),
        with(|c| c.fragment_reassembly_buffer_size = MAX_SEQUENCE_BUFFER_SIZE),
        with(|c| c.fragment_reassembly_buffer_size = 3), // rounded up to 4 by C
        with(|c| c.sent_packets_buffer_size = 1),
        with(|c| c.fragment_above = c.max_packet_size),
        with(|c| {
            c.max_packet_size = 1;
            c.fragment_above = 1;
            c.fragment_size = 1;
            c.max_fragments = 1;
        }),
        // exactly covered: 16 x 1024 = 16384
        with(|c| c.max_fragments = 16),
        with(|c| {
            c.rtt_smoothing_factor = 0.0;
            c.packet_loss_smoothing_factor = 1.0;
            c.bandwidth_smoothing_factor = 0.0;
        }),
        with(|c| c.packet_header_size = 0),
        with(|c| c.ack_buffer_size = 1),
        with(|c| c.rtt_history_size = 1),
    ];
    for config in accepted {
        assert_eq!(config.validate(), Ok(()), "{config:?}");
        let endpoint = Endpoint::new(config.clone(), 0.0).expect("C accepts what validate accepts");
        assert_eq!(endpoint.config(), &config);
    }
}

/// Mostly a value at or within two of a limit, sometimes anything small.
fn size_near(limits: &'static [usize]) -> impl Strategy<Value = usize> {
    prop_oneof![
        3 => proptest::sample::select(limits)
            .prop_flat_map(|l| l.saturating_sub(2)..=l.saturating_add(2)),
        1 => 0usize..5000,
    ]
}

/// Mostly valid factors, sometimes each kind of invalid one.
fn factor() -> impl Strategy<Value = f32> {
    prop_oneof![
        6 => 0.0f32..=1.0,
        1 => Just(0.0f32),
        1 => Just(1.0f32),
        1 => Just(-0.0f32),
        1 => prop_oneof![
            Just(f32::NAN),
            Just(1.000_000_1f32),
            Just(-f32::MIN_POSITIVE),
            Just(f32::INFINITY),
        ],
    ]
}

/// `max_packet_size` against what `max_fragments * fragment_size` covers (inside, exactly,
/// the smallest size that still needs every fragment, or one byte over), and `fragment_above`
/// against `max_packet_size`.
fn packet_geometry() -> impl Strategy<Value = (usize, usize, usize, usize)> {
    (
        size_near(&[1, 1024, 1186, 4096]),
        size_near(&[1, 16, 28, 256]),
    )
        .prop_flat_map(|(fragment_size, max_fragments)| {
            let covered = fragment_size * max_fragments;
            let needs_all = covered.saturating_sub(fragment_size) + 1;
            let max_packet_size = prop_oneof![
                3 => 0..=covered + 1,
                1 => Just(covered),
                1 => Just(needs_all),
                1 => Just(covered + 1),
            ];
            (Just(fragment_size), Just(max_fragments), max_packet_size)
        })
        .prop_flat_map(|(fragment_size, max_fragments, max_packet_size)| {
            let fragment_above = prop_oneof![
                3 => 0..=max_packet_size + 1,
                1 => Just(max_packet_size),
                1 => Just(max_packet_size + 1),
            ];
            (
                Just(max_packet_size),
                fragment_above,
                Just(max_fragments),
                Just(fragment_size),
            )
        })
}

fn config() -> impl Strategy<Value = Config> {
    (
        packet_geometry(),
        (
            size_near(&[1, 64, 256, 4096]),
            size_near(&[1, 2, 256, 16384]),
            size_near(&[1, 3, 256, 16384]),
            size_near(&[1, 16, 64, 16384]),
            size_near(&[1, 128, 512, 4096]),
            size_near(&[0, 28, 48]),
        ),
        (factor(), factor(), factor()),
        prop_oneof![9 => 0usize..=255, 1 => 256usize..=300],
    )
        .prop_map(
            |(
                (max_packet_size, fragment_above, max_fragments, fragment_size),
                (ack, sent, received, reassembly, history, header),
                (rtt, loss, bandwidth),
                name_len,
            )| Config {
                name: "n".repeat(name_len),
                max_packet_size,
                fragment_above,
                max_fragments,
                fragment_size,
                ack_buffer_size: ack,
                sent_packets_buffer_size: sent,
                received_packets_buffer_size: received,
                fragment_reassembly_buffer_size: reassembly,
                rtt_smoothing_factor: rtt,
                rtt_history_size: history,
                packet_loss_smoothing_factor: loss,
                bandwidth_smoothing_factor: bandwidth,
                packet_header_size: header,
            },
        )
}

/// Whatever `validate` accepts, the C library accepts; whatever it refuses never reaches C.
/// The generator is checked to produce both outcomes in quantity.
#[test]
fn validate_agrees_with_c() {
    use std::cell::Cell;
    let cases = 4000;
    let accepted = Cell::new(0u32);
    let mut runner = proptest::test_runner::TestRunner::new(ProptestConfig::with_cases(cases));
    runner
        .run(&config(), |config| {
            let verdict = config.validate();
            match Endpoint::new(config.clone(), 0.0) {
                Ok(endpoint) => {
                    accepted.set(accepted.get() + 1);
                    prop_assert_eq!(verdict, Ok(()));
                    prop_assert!(endpoint.allocated_bytes() <= endpoint.memory_usage());
                }
                Err(error) => {
                    prop_assert_ne!(error, ConfigError::CreateFailed, "C refused {:?}", config);
                    prop_assert_eq!(verdict, Err(error));
                }
            }
            Ok(())
        })
        .unwrap();
    let accepted = accepted.get();
    println!("{accepted} of {cases} generated configs accepted");
    assert!(
        accepted >= cases / 10 && accepted <= cases * 9 / 10,
        "{accepted}"
    );
}
