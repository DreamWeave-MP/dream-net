//! Connection statistics, counters, and memory accounting.
//!
//! All of these are plain `Copy` values read on demand: nothing allocates, so a script can
//! read them every frame.

/// Link estimates from `reliable`, refreshed by every connection update.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct ConnectionStats {
    /// Smoothed round trip time, milliseconds.
    pub rtt: f32,
    /// Minimum RTT over the history window, milliseconds.
    pub rtt_min: f32,
    /// Maximum RTT over the history window, milliseconds.
    pub rtt_max: f32,
    /// Average RTT over the history window, milliseconds.
    pub rtt_avg: f32,
    /// Average jitter against the minimum RTT, milliseconds.
    pub jitter: f32,
    /// Maximum jitter against the minimum RTT, milliseconds.
    pub jitter_max: f32,
    /// Standard deviation of RTT, milliseconds.
    pub jitter_stddev: f32,
    /// Smoothed packet loss, percent.
    pub packet_loss: f32,
    /// Sent bandwidth, kilobits per second.
    pub sent_kbps: f32,
    /// Received bandwidth, kilobits per second.
    pub received_kbps: f32,
    /// Acknowledged sent bandwidth, kilobits per second.
    pub acked_kbps: f32,
}

impl ConnectionStats {
    pub(crate) fn from_endpoint(endpoint: &reliable::Endpoint) -> Self {
        let bandwidth = endpoint.bandwidth();
        Self {
            rtt: endpoint.rtt(),
            rtt_min: endpoint.rtt_min(),
            rtt_max: endpoint.rtt_max(),
            rtt_avg: endpoint.rtt_avg(),
            jitter: endpoint.jitter_avg_vs_min_rtt(),
            jitter_max: endpoint.jitter_max_vs_min_rtt(),
            jitter_stddev: endpoint.jitter_stddev_vs_avg_rtt(),
            packet_loss: endpoint.packet_loss(),
            sent_kbps: bandwidth.sent_kbps,
            received_kbps: bandwidth.received_kbps,
            acked_kbps: bandwidth.acked_kbps,
        }
    }
}

/// Monotonic per-connection counters for profiling (§100 of the design).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Counters {
    /// Connection packets written.
    pub packets_sent: u64,
    /// Datagrams handed to the transport (fragments count individually).
    pub datagrams_sent: u64,
    /// Datagram bytes handed to the transport.
    pub bytes_sent: u64,
    /// Datagrams received from the transport.
    pub datagrams_received: u64,
    /// Datagram bytes received from the transport.
    pub bytes_received: u64,
    /// Connection packets accepted (after reassembly, duplicate rejection, and decoding).
    pub packets_received: u64,
    /// Events accepted by `send`.
    pub events_queued: u64,
    /// Events written into a packet for the first time.
    pub events_sent: u64,
    /// Reliable events written again because no ack arrived in time.
    pub events_resent: u64,
    /// Events delivered into the inbox.
    pub events_received: u64,
    /// Unreliable events dropped by the send overflow policy.
    pub events_dropped_on_send: u64,
    /// Unreliable events dropped because the inbox was over its limit.
    pub events_dropped_on_receive: u64,
    /// Reliable events received again after delivery (their ack was lost).
    pub duplicate_events: u64,
    /// Packets refused as malformed.
    pub malformed_packets: u64,
    /// Well-formed packets left unacknowledged because a reliable event in them could be
    /// neither delivered nor parked within `max_parked_bytes`. The sender resends them.
    pub packets_refused: u64,
}

/// Approximate native memory held by a connection, by category (§102 of the design).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MemoryUsage {
    /// The connection object and its scratch buffers.
    pub connection: usize,
    /// reliable's endpoint: packet tracking, RTT history, reassembly.
    pub reliable: usize,
    /// Channel send queues and their buffer pools.
    pub send: usize,
    /// Reliable reorder buffers.
    pub receive: usize,
}

impl MemoryUsage {
    /// The sum of all categories.
    pub fn total(&self) -> usize {
        self.connection + self.reliable + self.send + self.receive
    }
}
