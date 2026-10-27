// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

pub const MAX_MESSAGE_WORDS: usize = 6;
const NONE: u16 = u16::MAX;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Message {
    pub label: u32,
    pub length: u8,
    pub flags: u8,
    pub reserved: u16,
    pub words: [u64; MAX_MESSAGE_WORDS],
}

impl Message {
    pub const EMPTY: Self = Self {
        label: 0,
        length: 0,
        flags: 0,
        reserved: 0,
        words: [0; MAX_MESSAGE_WORDS],
    };

    pub const fn new(
        label: u32,
        words: [u64; MAX_MESSAGE_WORDS],
        length: u8,
    ) -> Result<Self, Error> {
        if length as usize > MAX_MESSAGE_WORDS {
            return Err(Error::MessageTooLong);
        }
        Ok(Self {
            label,
            length,
            flags: 0,
            reserved: 0,
            words,
        })
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SenderId(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Delivery {
    pub sender: SenderId,
    pub badge: u64,
    pub message: Message,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    MessageTooLong,
    QueueFull,
    QueueCorrupt,
}

#[derive(Clone, Copy)]
struct PendingSend {
    occupied: bool,
    sender: SenderId,
    badge: u64,
    message: Message,
    next: u16,
}

impl PendingSend {
    const EMPTY: Self = Self {
        occupied: false,
        sender: SenderId(0),
        badge: 0,
        message: Message::EMPTY,
        next: NONE,
    };
}

/// Allocation-free FIFO queue for endpoint senders.
///
/// The eventual kernel IPC layer should first attempt an immediate sender/receiver handoff;
/// this queue is only the bounded slow path for blocked senders. Bulk payloads must travel
/// through shared memory, not by expanding this structure.
pub struct SendQueue<const N: usize> {
    entries: [PendingSend; N],
    head: u16,
    tail: u16,
    len: u16,
}

impl<const N: usize> Default for SendQueue<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> SendQueue<N> {
    pub const fn new() -> Self {
        Self {
            entries: [PendingSend::EMPTY; N],
            head: NONE,
            tail: NONE,
            len: 0,
        }
    }

    pub const fn len(&self) -> usize {
        self.len as usize
    }
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn push(&mut self, sender: SenderId, badge: u64, message: Message) -> Result<(), Error> {
        if N > NONE as usize || self.len as usize >= N {
            return Err(Error::QueueFull);
        }
        let slot = self
            .entries
            .iter()
            .position(|entry| !entry.occupied)
            .ok_or(Error::QueueFull)?;
        self.entries[slot] = PendingSend {
            occupied: true,
            sender,
            badge,
            message,
            next: NONE,
        };
        if self.tail == NONE {
            if self.head != NONE {
                return Err(Error::QueueCorrupt);
            }
            self.head = slot as u16;
        } else {
            let tail = self.tail as usize;
            if tail >= N || !self.entries[tail].occupied {
                return Err(Error::QueueCorrupt);
            }
            self.entries[tail].next = slot as u16;
        }
        self.tail = slot as u16;
        self.len += 1;
        Ok(())
    }

    pub fn pop(&mut self) -> Result<Option<Delivery>, Error> {
        if self.head == NONE {
            if self.tail != NONE || self.len != 0 {
                return Err(Error::QueueCorrupt);
            }
            return Ok(None);
        }
        let slot = self.head as usize;
        if slot >= N || !self.entries[slot].occupied || self.len == 0 {
            return Err(Error::QueueCorrupt);
        }
        let entry = self.entries[slot];
        self.head = entry.next;
        self.len -= 1;
        if self.head == NONE {
            self.tail = NONE;
        }
        self.entries[slot] = PendingSend::EMPTY;
        Ok(Some(Delivery {
            sender: entry.sender,
            badge: entry.badge,
            message: entry.message,
        }))
    }
}

/// A one-receiver rendezvous endpoint state machine.
///
/// `receiver_waiting` is deliberately explicit so the architecture-specific syscall path can
/// choose a register-to-register fast path without allocating a queue node.
pub struct Endpoint<const N: usize> {
    receiver_waiting: bool,
    pending: SendQueue<N>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendOutcome {
    DeliverNow(Delivery),
    SenderBlocked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveOutcome {
    Received(Delivery),
    ReceiverBlocked,
}

impl<const N: usize> Default for Endpoint<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Endpoint<N> {
    pub const fn new() -> Self {
        Self {
            receiver_waiting: false,
            pending: SendQueue::new(),
        }
    }

    pub fn send(
        &mut self,
        sender: SenderId,
        badge: u64,
        message: Message,
    ) -> Result<SendOutcome, Error> {
        let delivery = Delivery {
            sender,
            badge,
            message,
        };
        if self.receiver_waiting {
            self.receiver_waiting = false;
            return Ok(SendOutcome::DeliverNow(delivery));
        }
        self.pending.push(sender, badge, message)?;
        Ok(SendOutcome::SenderBlocked)
    }

    pub fn receive(&mut self) -> Result<ReceiveOutcome, Error> {
        if let Some(delivery) = self.pending.pop()? {
            return Ok(ReceiveOutcome::Received(delivery));
        }
        self.receiver_waiting = true;
        Ok(ReceiveOutcome::ReceiverBlocked)
    }

    pub const fn receiver_waiting(&self) -> bool {
        self.receiver_waiting
    }
    pub const fn queued_senders(&self) -> usize {
        self.pending.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(value: u64) -> Message {
        Message::new(7, [value, 0, 0, 0, 0, 0], 1).unwrap()
    }

    #[test]
    fn waiting_receiver_gets_immediate_delivery() {
        let mut ep = Endpoint::<4>::new();
        assert_eq!(ep.receive().unwrap(), ReceiveOutcome::ReceiverBlocked);
        let outcome = ep.send(SenderId(9), 0x55, msg(42)).unwrap();
        assert_eq!(
            outcome,
            SendOutcome::DeliverNow(Delivery {
                sender: SenderId(9),
                badge: 0x55,
                message: msg(42)
            })
        );
        assert!(!ep.receiver_waiting());
    }

    #[test]
    fn senders_are_fifo() {
        let mut ep = Endpoint::<4>::new();
        assert_eq!(
            ep.send(SenderId(1), 1, msg(10)).unwrap(),
            SendOutcome::SenderBlocked
        );
        assert_eq!(
            ep.send(SenderId(2), 2, msg(20)).unwrap(),
            SendOutcome::SenderBlocked
        );
        let first = ep.receive().unwrap();
        let second = ep.receive().unwrap();
        assert_eq!(
            first,
            ReceiveOutcome::Received(Delivery {
                sender: SenderId(1),
                badge: 1,
                message: msg(10)
            })
        );
        assert_eq!(
            second,
            ReceiveOutcome::Received(Delivery {
                sender: SenderId(2),
                badge: 2,
                message: msg(20)
            })
        );
    }

    #[test]
    fn bounded_queue_refuses_overflow() {
        let mut ep = Endpoint::<1>::new();
        ep.send(SenderId(1), 0, msg(1)).unwrap();
        assert_eq!(ep.send(SenderId(2), 0, msg(2)), Err(Error::QueueFull));
    }

    #[test]
    fn rejects_oversized_message() {
        assert_eq!(
            Message::new(0, [0; MAX_MESSAGE_WORDS], 7),
            Err(Error::MessageTooLong)
        );
    }
}
