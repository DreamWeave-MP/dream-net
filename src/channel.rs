//! Event channels: the message layer `reliable` leaves out (Yojimbo's model, not its code).
//!
//! A reliable-ordered channel keeps every queued event until a packet carrying it is acked,
//! resends unacked events every `resend_interval`, and delivers received events exactly once,
//! in send order. An unreliable-unordered channel sends each event once, in whichever packet it
//! fits, and delivers whatever arrives.
//!
//! Queues grow on demand up to their capacity and recycle payload buffers through a pool, so a
//! warm connection allocates nothing and an idle one holds almost nothing.

use std::collections::VecDeque;

use crate::id::EventTypeId;
use crate::schema::{ChannelDef, Delivery, OverflowPolicy};
use crate::sequence::Seq16;

/// Recycled payload buffers, bounded by count and by retained bytes.
///
/// Recycling keeps a warm connection allocation free; the byte ceiling keeps one burst of
/// large events from pinning its allocations for the life of the connection. A buffer that
/// would push the pool over the ceiling is freed instead.
#[derive(Debug, Default)]
pub(crate) struct Pool {
    spare: Vec<Vec<u8>>,
    limit: usize,
    retained: usize,
    max_bytes: usize,
}

impl Pool {
    fn new(limit: usize, max_bytes: usize) -> Self {
        Self {
            spare: Vec::new(),
            limit,
            retained: 0,
            max_bytes,
        }
    }

    #[inline]
    fn take(&mut self, payload: &[u8]) -> Vec<u8> {
        let mut buffer = match self.spare.pop() {
            Some(buffer) => {
                self.retained -= buffer.capacity();
                buffer
            }
            None => Vec::new(),
        };
        buffer.clear();
        buffer.extend_from_slice(payload);
        buffer
    }

    #[inline]
    fn give(&mut self, buffer: Vec<u8>) {
        let capacity = buffer.capacity();
        if capacity > 0
            && self.spare.len() < self.limit
            && self.retained + capacity <= self.max_bytes
        {
            self.retained += capacity;
            self.spare.push(buffer);
        }
    }

    fn memory(&self) -> usize {
        self.retained + self.spare.capacity() * size_of::<Vec<u8>>()
    }
}

#[derive(Debug)]
struct SendSlot {
    acked: bool,
    serial: u32,
    event: EventTypeId,
    /// `f64::NEG_INFINITY` until first sent.
    last_sent: f64,
    payload: Vec<u8>,
}

#[derive(Debug, Default)]
struct RecvSlot {
    event: Option<EventTypeId>,
    payload: Vec<u8>,
}

/// Where a received reliable id falls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Arrival {
    /// Inside the receive window: store or deliver it.
    New,
    /// Already delivered (a resend whose ack was lost).
    Old,
    /// Neither: a correct peer with the same window cannot send it.
    Invalid,
}

/// Reliable-ordered channel state.
#[derive(Debug)]
pub(crate) struct Reliable {
    window: u16,
    resend_interval: f64,
    // send: slots for ids [oldest_unacked, next_send)
    send: VecDeque<SendSlot>,
    oldest_unacked: Seq16,
    next_serial: u32,
    /// Per-flush scan position, as an offset from `oldest_unacked`.
    cursor: usize,
    // receive: slots for ids [next_receive, next_receive + recv.len())
    recv: VecDeque<RecvSlot>,
    next_receive: Seq16,
    pool: Pool,
}

impl Reliable {
    fn new(def: &ChannelDef, pool_bytes: usize) -> Self {
        Self {
            window: def.config.capacity,
            resend_interval: def.config.resend_interval,
            send: VecDeque::new(),
            oldest_unacked: Seq16::ZERO,
            next_serial: 0,
            cursor: 0,
            recv: VecDeque::new(),
            next_receive: Seq16::ZERO,
            pool: Pool::new(usize::from(def.config.capacity), pool_bytes),
        }
    }

    /// Events queued and not yet acked.
    #[inline]
    pub(crate) fn unacked(&self) -> usize {
        self.send.len()
    }

    #[inline]
    fn queue(&mut self, event: EventTypeId, payload: &[u8]) -> bool {
        if self.send.len() >= usize::from(self.window) {
            return false;
        }
        let payload = self.pool.take(payload);
        self.send.push_back(SendSlot {
            acked: false,
            serial: self.next_serial,
            event,
            last_sent: f64::NEG_INFINITY,
            payload,
        });
        self.next_serial = self.next_serial.wrapping_add(1);
        true
    }

    /// Marks the message with this id acked if it is still the message sent with `serial`.
    #[inline]
    pub(crate) fn ack(&mut self, id: Seq16, serial: u32) {
        let index = usize::from(id.since(self.oldest_unacked));
        if let Some(slot) = self.send.get_mut(index)
            && slot.serial == serial
            && !slot.acked
        {
            slot.acked = true;
            if index == 0 {
                self.advance_acked();
            }
        }
    }

    fn advance_acked(&mut self) {
        while let Some(front) = self.send.front() {
            if !front.acked {
                break;
            }
            let slot = self.send.pop_front().expect("front exists");
            self.pool.give(slot.payload);
            self.oldest_unacked = self.oldest_unacked.next();
            self.cursor = self.cursor.saturating_sub(1);
        }
    }

    /// Classifies a received id against the receive window.
    #[inline]
    pub(crate) fn arrival(&self, id: Seq16) -> Arrival {
        let ahead = id.since(self.next_receive);
        if ahead < self.window {
            Arrival::New
        } else if self.next_receive.since(id) <= self.window {
            Arrival::Old
        } else {
            Arrival::Invalid
        }
    }

    /// Whether `id` can be delivered straight away (it is next and nothing is buffered ahead
    /// of it).
    #[inline]
    pub(crate) fn is_next(&self, id: Seq16) -> bool {
        id == self.next_receive && self.recv.front().is_none_or(|slot| slot.event.is_none())
    }

    /// Records that the next id was delivered directly.
    #[inline]
    pub(crate) fn delivered_next(&mut self) {
        if let Some(slot) = self.recv.pop_front() {
            debug_assert!(slot.event.is_none());
            self.pool.give(slot.payload);
        }
        self.next_receive = self.next_receive.next();
    }

    /// Whether a message with this (new) id is already parked.
    #[inline]
    pub(crate) fn is_parked(&self, id: Seq16) -> bool {
        self.recv
            .get(usize::from(id.since(self.next_receive)))
            .is_some_and(|slot| slot.event.is_some())
    }

    /// Parks an out-of-order (or backpressured) message until it can be delivered. The caller
    /// has checked it is not parked already and accounts its bytes.
    #[inline]
    pub(crate) fn park(&mut self, id: Seq16, event: EventTypeId, payload: &[u8]) {
        let index = usize::from(id.since(self.next_receive));
        while self.recv.len() <= index {
            self.recv.push_back(RecvSlot::default());
        }
        let slot = &mut self.recv[index];
        debug_assert!(slot.event.is_none());
        slot.event = Some(event);
        let buffer = self.pool.take(payload);
        let old = std::mem::replace(&mut slot.payload, buffer);
        self.pool.give(old);
    }

    /// The next buffered message, if it is ready.
    #[inline]
    pub(crate) fn ready(&self) -> Option<(EventTypeId, &[u8])> {
        let slot = self.recv.front()?;
        Some((slot.event?, &slot.payload))
    }

    /// Consumes the message [`ready`](Self::ready) returned, returning the parked bytes it
    /// freed.
    #[inline]
    pub(crate) fn consume_ready(&mut self) -> usize {
        let Some(slot) = self.recv.pop_front() else {
            return 0;
        };
        let len = slot.payload.len();
        self.pool.give(slot.payload);
        self.next_receive = self.next_receive.next();
        len
    }

    fn memory(&self) -> (usize, usize) {
        let send = self
            .send
            .iter()
            .map(|s| s.payload.capacity())
            .sum::<usize>()
            + self.send.capacity() * size_of::<SendSlot>()
            + self.pool.memory();
        let receive = self
            .recv
            .iter()
            .map(|s| s.payload.capacity())
            .sum::<usize>()
            + self.recv.capacity() * size_of::<RecvSlot>();
        (send, receive)
    }

    fn queued_bytes(&self) -> usize {
        self.send.iter().map(|s| s.payload.len()).sum()
    }
}

/// A message the packet builder considers sending.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Candidate<'a> {
    pub(crate) id: Seq16,
    pub(crate) serial: u32,
    pub(crate) payload: &'a [u8],
    pub(crate) resend: bool,
}

impl Reliable {
    /// Starts a flush: the scan restarts at the oldest unacked message.
    #[inline]
    pub(crate) fn begin_flush(&mut self) {
        self.cursor = 0;
    }

    /// The next message due for (re)sending at `time`, from the flush cursor on, without
    /// consuming it.
    #[inline]
    pub(crate) fn peek_due(&mut self, time: f64) -> Option<Candidate<'_>> {
        while let Some(slot) = self.send.get(self.cursor) {
            if !slot.acked && time - slot.last_sent >= self.resend_interval {
                return Some(Candidate {
                    id: self.oldest_unacked.add(self.cursor as u16),
                    serial: slot.serial,
                    payload: &slot.payload,
                    resend: slot.last_sent != f64::NEG_INFINITY,
                });
            }
            self.cursor += 1;
        }
        None
    }

    /// Marks the peeked message sent at `time` and moves past it.
    #[inline]
    pub(crate) fn take_due(&mut self, time: f64) {
        self.send[self.cursor].last_sent = time;
        self.cursor += 1;
    }

    /// The payload of an unacked message by id (for writing a selected message).
    #[inline]
    pub(crate) fn payload(&self, id: Seq16) -> (EventTypeId, &[u8]) {
        let slot = &self.send[usize::from(id.since(self.oldest_unacked))];
        (slot.event, &slot.payload)
    }
}

/// Unreliable-unordered channel state.
#[derive(Debug)]
pub(crate) struct Unreliable {
    capacity: usize,
    overflow: OverflowPolicy,
    queue: VecDeque<(EventTypeId, Vec<u8>)>,
    pool: Pool,
}

/// What queueing on an unreliable channel did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QueueOutcome {
    Accepted,
    DroppedOldest,
    DroppedNew,
    Refused,
}

impl Unreliable {
    fn new(def: &ChannelDef, pool_bytes: usize) -> Self {
        Self {
            capacity: usize::from(def.config.capacity),
            overflow: def.config.overflow,
            queue: VecDeque::new(),
            pool: Pool::new(usize::from(def.config.capacity), pool_bytes),
        }
    }

    #[inline]
    fn queue(&mut self, event: EventTypeId, payload: &[u8]) -> QueueOutcome {
        let mut outcome = QueueOutcome::Accepted;
        if self.queue.len() >= self.capacity {
            match self.overflow {
                OverflowPolicy::Fail => return QueueOutcome::Refused,
                OverflowPolicy::DropNewest => return QueueOutcome::DroppedNew,
                OverflowPolicy::DropOldest => {
                    let (_, old) = self.queue.pop_front().expect("queue is full");
                    self.pool.give(old);
                    outcome = QueueOutcome::DroppedOldest;
                }
            }
        }
        let payload = self.pool.take(payload);
        self.queue.push_back((event, payload));
        outcome
    }

    /// The `index`-th queued message.
    #[inline]
    pub(crate) fn get(&self, index: usize) -> Option<(EventTypeId, &[u8])> {
        self.queue.get(index).map(|(e, p)| (*e, p.as_slice()))
    }

    /// Drops the first `n` messages after they were written into a packet.
    #[inline]
    pub(crate) fn pop_sent(&mut self, n: usize) {
        for _ in 0..n {
            let (_, payload) = self.queue.pop_front().expect("sent message");
            self.pool.give(payload);
        }
    }

    /// Queued messages.
    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.queue.len()
    }

    fn memory(&self) -> usize {
        self.queue.iter().map(|(_, p)| p.capacity()).sum::<usize>()
            + self.queue.capacity() * size_of::<(EventTypeId, Vec<u8>)>()
            + self.pool.memory()
    }

    fn queued_bytes(&self) -> usize {
        self.queue.iter().map(|(_, p)| p.len()).sum()
    }
}

/// A channel: static dispatch over the two delivery classes.
#[derive(Debug)]
pub(crate) enum Channel {
    Reliable(Reliable),
    Unreliable(Unreliable),
}

impl Channel {
    /// A channel whose payload pool retains at most `pool_bytes`.
    pub(crate) fn new(def: &ChannelDef, pool_bytes: usize) -> Self {
        match def.delivery() {
            Delivery::ReliableOrdered => Self::Reliable(Reliable::new(def, pool_bytes)),
            Delivery::UnreliableUnordered => Self::Unreliable(Unreliable::new(def, pool_bytes)),
        }
    }

    /// Queues an outgoing message, returning what happened.
    #[inline]
    pub(crate) fn queue(&mut self, event: EventTypeId, payload: &[u8]) -> QueueOutcome {
        match self {
            Self::Reliable(c) => {
                if c.queue(event, payload) {
                    QueueOutcome::Accepted
                } else {
                    QueueOutcome::Refused
                }
            }
            Self::Unreliable(c) => c.queue(event, payload),
        }
    }

    /// Approximate (send, receive) bytes held.
    pub(crate) fn memory(&self) -> (usize, usize) {
        match self {
            Self::Reliable(c) => c.memory(),
            Self::Unreliable(c) => (c.memory(), 0),
        }
    }

    pub(crate) fn queued_bytes(&self) -> usize {
        match self {
            Self::Reliable(c) => c.queued_bytes(),
            Self::Unreliable(c) => c.queued_bytes(),
        }
    }

    pub(crate) fn queued_messages(&self) -> usize {
        match self {
            Self::Reliable(c) => c.unacked(),
            Self::Unreliable(c) => c.len(),
        }
    }
}
