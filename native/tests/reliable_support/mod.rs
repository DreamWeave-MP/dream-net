//! Helpers shared by the `reliable*` test binaries: a seeded RNG, a lossy link, and a parser
//! for reliable's packet and fragment headers.

#![allow(dead_code)] // each test binary uses a different part

use dream_net_native::reliable::Config;

/// `SplitMix64`: small, seeded, reproducible.
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in `0..n` (n > 0).
    pub fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }

    /// True with probability `p`.
    pub fn chance(&mut self, p: f64) -> bool {
        let unit = (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64;
        unit < p
    }
}

/// A one-way link: drops, duplicates and delays datagrams (delay gives reordering).
#[derive(Debug)]
pub struct Link {
    pub rng: Rng,
    pub loss: f64,
    pub duplicate: f64,
    pub latency: f64,
    pub jitter: f64,
    queue: Vec<(f64, u64, Vec<u8>)>,
    order: u64,
}

impl Link {
    pub fn new(seed: u64, loss: f64, duplicate: f64, latency: f64, jitter: f64) -> Self {
        Self {
            rng: Rng::new(seed),
            loss,
            duplicate,
            latency,
            jitter,
            queue: Vec::new(),
            order: 0,
        }
    }

    pub fn perfect() -> Self {
        Self::new(0, 0.0, 0.0, 0.0, 0.0)
    }

    pub fn send(&mut self, now: f64, datagram: &[u8]) {
        if self.rng.chance(self.loss) {
            return;
        }
        let copies = if self.rng.chance(self.duplicate) {
            2
        } else {
            1
        };
        for _ in 0..copies {
            let delay = self.latency + self.jitter * (self.rng.below(1000) as f64 / 1000.0);
            self.queue
                .push((now + delay, self.order, datagram.to_vec()));
            self.order += 1;
        }
    }

    /// Datagrams due by `now`, in arrival order.
    pub fn due(&mut self, now: f64) -> Vec<Vec<u8>> {
        self.queue
            .sort_by(|a, b| a.0.total_cmp(&b.0).then(a.1.cmp(&b.1)));
        let n = self.queue.iter().take_while(|d| d.0 <= now).count();
        self.queue.drain(..n).map(|d| d.2).collect()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

/// A packet of `len` bytes whose content depends on `tag`.
pub fn payload(tag: u64, len: usize) -> Vec<u8> {
    let mut rng = Rng::new(tag ^ (len as u64).rotate_left(32));
    (0..len).map(|_| rng.next_u64() as u8).collect()
}

/// dream-net's transport config, as `TransportConfig::reliable_config` builds it.
pub fn dream_net_config(name: &str) -> Config {
    Config {
        name: name.to_owned(),
        max_packet_size: 32768,
        fragment_above: 1191,
        max_fragments: 28,
        fragment_size: 1186,
        ack_buffer_size: 64,
        sent_packets_buffer_size: 256,
        received_packets_buffer_size: 256,
        fragment_reassembly_buffer_size: 16,
        rtt_smoothing_factor: 0.0025,
        rtt_history_size: 128,
        packet_loss_smoothing_factor: 0.1,
        bandwidth_smoothing_factor: 0.1,
        packet_header_size: 28,
    }
}

/// Length of the regular packet header at the start of `data`, if it is complete.
pub fn packet_header_len(data: &[u8]) -> Option<usize> {
    let prefix = *data.first()?;
    if prefix & 1 != 0 {
        return None;
    }
    let ack_len = if prefix & (1 << 5) != 0 { 1 } else { 2 };
    let ack_bits = (1..=4).filter(|i| prefix & (1 << i) != 0).count();
    let len = 3 + ack_len + ack_bits;
    (data.len() >= len).then_some(len)
}

/// The sequence of a regular packet or a fragment.
pub fn sequence_of(data: &[u8]) -> Option<u16> {
    (data.len() >= 3).then(|| u16::from_le_bytes([data[1], data[2]]))
}

/// A parsed fragment: `(sequence, fragment_id, num_fragments, payload)`. Only the framing is
/// parsed (fragment 0's packet header is skipped by length), not validated.
pub fn parse_fragment(data: &[u8]) -> Option<(u16, usize, usize, &[u8])> {
    if data.len() < 5 || data[0] != 1 {
        return None;
    }
    let sequence = u16::from_le_bytes([data[1], data[2]]);
    let id = usize::from(data[3]);
    let count = usize::from(data[4]) + 1;
    let mut body = &data[5..];
    if id == 0 {
        let header = packet_header_len(body)?;
        body = &body[header..];
    }
    Some((sequence, id, count, body))
}
