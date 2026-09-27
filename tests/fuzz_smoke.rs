//! The fuzz harnesses on the stable toolchain: random inputs, plus inputs shaped to reach
//! deep states, so every `cargo test` exercises them. `cargo fuzz` explores far further.

#[path = "../fuzz/harness.rs"]
mod harness;

use dream_net::sim::Rng;

fn inputs(seed: u64, count: usize, max_len: usize) -> impl Iterator<Item = Vec<u8>> {
    let mut rng = Rng::new(seed);
    (0..count).map(move |_| {
        let len = rng.below(max_len as u64) as usize;
        (0..len).map(|_| rng.next_u64() as u8).collect()
    })
}

#[test]
fn wire_decode() {
    for data in inputs(1, 20_000, 96) {
        harness::wire_decode(&data);
    }
    // near-valid packets: a data kind, no hello, and a random body
    for mut data in inputs(2, 20_000, 64) {
        if let Some(first) = data.first_mut() {
            *first &= 0b1111_1000;
        }
        harness::wire_decode(&data);
    }
}

#[test]
fn connection_stream() {
    for data in inputs(3, 2_000, 2048) {
        harness::connection_stream(&data);
    }
}

#[test]
fn channel_schedule() {
    for data in inputs(4, 300, 512) {
        harness::channel_schedule(&data);
    }
    // a hostile schedule: send on both channels every frame, drop or delay two in three
    let hostile: Vec<u8> = (0..600u32)
        .map(|i| if i % 2 == 0 { 3 } else { (i % 3) as u8 })
        .collect();
    harness::channel_schedule(&hostile);
}

#[test]
fn handshake() {
    for data in inputs(5, 5_000, 64) {
        harness::handshake(&data);
    }
    harness::handshake(&[0, 0]);
}

#[test]
fn capture_read() {
    for data in inputs(6, 5_000, 256) {
        harness::capture_read(&data);
    }
    let mut valid = b"DNCAP\0".to_vec();
    valid.extend_from_slice(&1u16.to_le_bytes());
    valid.extend_from_slice(&[1, 0]);
    valid.extend_from_slice(&[0; 16]);
    valid.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    for data in inputs(7, 5_000, 128) {
        let mut file = valid.clone();
        file.extend_from_slice(&data);
        harness::capture_read(&file);
    }
}
