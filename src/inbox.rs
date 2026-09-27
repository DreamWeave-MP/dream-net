//! The receive queue a host polls: lifecycle and message records in arrival order.
//!
//! Every connection of a host delivers into one [`Inbox`], so a peer's `Connected` record
//! always precedes its messages and its `Disconnected` record follows them. Payload bytes live
//! in one arena: a received payload is copied once into it (straight out of the decoded
//! packet), and once more out of it when polled into caller storage.

use std::collections::VecDeque;

use crate::error::BufferTooSmall;
use crate::id::{ChannelId, EventTypeId, PeerId};

/// A received event, without its payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageInfo {
    /// The authenticated sender (transport metadata, never payload).
    pub peer: PeerId,
    /// The event type.
    pub event: EventTypeId,
    /// The channel it arrived on.
    pub channel: ChannelId,
    /// The payload length in bytes.
    pub len: usize,
}

/// One polled record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Record<L> {
    /// A received event.
    Message(MessageInfo),
    /// A host-defined lifecycle record.
    Lifecycle(L),
}

#[derive(Debug, Clone, Copy)]
enum Entry<L> {
    Message { info: MessageInfo, offset: usize },
    Lifecycle(L),
}

#[derive(Debug, Clone, Copy, Default)]
struct Account {
    generation: u64,
    events: usize,
    bytes: usize,
}

/// A host's receive queue. Bounded per slot by the transport's pending limits.
#[derive(Debug)]
pub struct Inbox<L> {
    entries: VecDeque<Entry<L>>,
    arena: Vec<u8>,
    head: usize,
    accounts: Vec<Account>,
}

impl<L: Copy> Inbox<L> {
    /// An empty inbox for `slots` connections.
    pub fn new(slots: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            arena: Vec::new(),
            head: 0,
            accounts: vec![Account::default(); slots],
        }
    }

    /// Records waiting to be polled.
    #[inline]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing is waiting.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Starts accounting a new connection in `peer`'s slot. Records still queued for the slot's
    /// previous peer stay deliverable but no longer count against the slot.
    pub fn open_slot(&mut self, peer: PeerId) {
        self.accounts[peer.slot()] = Account {
            generation: peer.generation(),
            events: 0,
            bytes: 0,
        };
    }

    /// Whether `peer` may queue another `len`-byte event under the given limits.
    #[inline]
    pub fn has_room(&self, peer: PeerId, len: usize, max_events: usize, max_bytes: usize) -> bool {
        let account = &self.accounts[peer.slot()];
        account.events < max_events && account.bytes + len <= max_bytes
    }

    /// Events and bytes `peer` has waiting.
    pub fn pending(&self, peer: PeerId) -> (usize, usize) {
        let account = &self.accounts[peer.slot()];
        if account.generation == peer.generation() {
            (account.events, account.bytes)
        } else {
            (0, 0)
        }
    }

    /// Queues a message, copying its payload into the arena.
    #[inline]
    pub(crate) fn push_message(
        &mut self,
        peer: PeerId,
        event: EventTypeId,
        channel: ChannelId,
        payload: &[u8],
    ) {
        let offset = self.arena.len();
        self.arena.extend_from_slice(payload);
        let account = &mut self.accounts[peer.slot()];
        account.events += 1;
        account.bytes += payload.len();
        self.entries.push_back(Entry::Message {
            info: MessageInfo {
                peer,
                event,
                channel,
                len: payload.len(),
            },
            offset,
        });
    }

    /// Queues a lifecycle record after everything already queued.
    pub fn push_lifecycle(&mut self, record: L) {
        self.entries.push_back(Entry::Lifecycle(record));
    }

    #[inline]
    fn release(&mut self, info: &MessageInfo) {
        let account = &mut self.accounts[info.peer.slot()];
        if account.generation == info.peer.generation() {
            account.events -= 1;
            account.bytes -= info.len;
        }
        self.head += info.len;
    }

    #[inline]
    fn after_pop(&mut self) {
        if self.entries.is_empty() {
            self.arena.clear();
            self.head = 0;
        }
    }

    /// Pops the next record; a message's payload is borrowed from the arena until the next
    /// call.
    #[inline]
    pub fn pop(&mut self) -> Option<(Record<L>, &[u8])> {
        let entry = self.entries.pop_front()?;
        match entry {
            Entry::Lifecycle(record) => {
                self.after_pop();
                Some((Record::Lifecycle(record), &[]))
            }
            Entry::Message { info, offset } => {
                // the payload stays in the arena for this borrow; `compact` or a later
                // `pop_into` reclaims it
                self.release(&info);
                Some((
                    Record::Message(info),
                    &self.arena[offset..offset + info.len],
                ))
            }
        }
    }

    /// Pops the next record, copying a message's payload into `buffer`. If the payload does
    /// not fit, nothing is consumed.
    ///
    /// # Errors
    ///
    /// [`BufferTooSmall`] with the payload length.
    #[inline]
    pub fn pop_into(&mut self, buffer: &mut [u8]) -> Result<Option<Record<L>>, BufferTooSmall> {
        if let Some(Entry::Message { info, .. }) = self.entries.front()
            && info.len > buffer.len()
        {
            return Err(BufferTooSmall { needed: info.len });
        }
        let Some(entry) = self.entries.pop_front() else {
            return Ok(None);
        };
        let record = match entry {
            Entry::Lifecycle(record) => Record::Lifecycle(record),
            Entry::Message { info, offset } => {
                buffer[..info.len].copy_from_slice(&self.arena[offset..offset + info.len]);
                self.release(&info);
                Record::Message(info)
            }
        };
        self.after_pop();
        Ok(Some(record))
    }

    /// The payload length of the next record if it is a message.
    pub fn peek_len(&self) -> Option<usize> {
        match self.entries.front()? {
            Entry::Message { info, .. } => Some(info.len),
            Entry::Lifecycle(_) => None,
        }
    }

    /// Reclaims arena space consumed by polled messages. Called once per host update; cheap
    /// when everything was polled (the arena is simply cleared).
    pub fn compact(&mut self) {
        if self.entries.is_empty() {
            self.arena.clear();
            self.head = 0;
            return;
        }
        if self.head == 0 || self.head < self.arena.len() / 2 {
            return;
        }
        let head = self.head;
        self.arena.drain(..head);
        for entry in &mut self.entries {
            if let Entry::Message { offset, .. } = entry {
                *offset -= head;
            }
        }
        self.head = 0;
    }

    /// Approximate bytes held.
    pub fn memory_usage(&self) -> usize {
        self.arena.capacity()
            + self.entries.capacity() * size_of::<Entry<L>>()
            + self.accounts.capacity() * size_of::<Account>()
    }
}
