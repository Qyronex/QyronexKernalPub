// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

pub const NANOS_PER_SECOND: u64 = 1_000_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    ZeroFrequency,
    InvalidShift,
    Overflow,
    Capacity,
    DuplicateTimer,
    TimerNotFound,
}

/// Fixed-point cycle-to-nanosecond scale. Runtime conversion is multiply+shift only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CycleScale {
    multiplier: u64,
    shift: u8,
}

impl CycleScale {
    pub fn from_frequency_hz(frequency_hz: u64, shift: u8) -> Result<Self, Error> {
        if frequency_hz == 0 {
            return Err(Error::ZeroFrequency);
        }
        if shift > 48 {
            return Err(Error::InvalidShift);
        }
        let numerator = (NANOS_PER_SECOND as u128) << shift;
        let multiplier = numerator
            .checked_add(frequency_hz as u128 - 1)
            .ok_or(Error::Overflow)?
            / frequency_hz as u128;
        if multiplier > u64::MAX as u128 {
            return Err(Error::Overflow);
        }
        Ok(Self {
            multiplier: multiplier as u64,
            shift,
        })
    }

    pub fn delta_to_ns(self, cycles: u64) -> Result<u64, Error> {
        let scaled = (cycles as u128)
            .checked_mul(self.multiplier as u128)
            .ok_or(Error::Overflow)?
            >> self.shift;
        u64::try_from(scaled).map_err(|_| Error::Overflow)
    }

    pub const fn multiplier(self) -> u64 {
        self.multiplier
    }
    pub const fn shift(self) -> u8 {
        self.shift
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MonotonicClock {
    scale: CycleScale,
    base_cycles: u64,
    base_ns: u64,
}

impl MonotonicClock {
    pub const fn new(scale: CycleScale, base_cycles: u64, base_ns: u64) -> Self {
        Self {
            scale,
            base_cycles,
            base_ns,
        }
    }

    pub fn now_ns(self, cycles: u64) -> Result<u64, Error> {
        let delta = cycles.wrapping_sub(self.base_cycles);
        self.base_ns
            .checked_add(self.scale.delta_to_ns(delta)?)
            .ok_or(Error::Overflow)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

pub fn ns_to_timespec(ns: u64) -> Result<Timespec, Error> {
    let sec = ns / NANOS_PER_SECOND;
    let nsec = ns % NANOS_PER_SECOND;
    Ok(Timespec {
        tv_sec: i64::try_from(sec).map_err(|_| Error::Overflow)?,
        tv_nsec: nsec as i64,
    })
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimerId(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Deadline {
    pub id: TimerId,
    pub deadline_ns: u64,
}

impl Deadline {
    const EMPTY: Self = Self {
        id: TimerId(0),
        deadline_ns: u64::MAX,
    };
}

/// Allocation-free min-heap for scheduler, futex, IPC and userspace timer deadlines.
pub struct DeadlineQueue<const N: usize> {
    heap: [Deadline; N],
    len: usize,
}

impl<const N: usize> Default for DeadlineQueue<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> DeadlineQueue<N> {
    pub const fn new() -> Self {
        Self {
            heap: [Deadline::EMPTY; N],
            len: 0,
        }
    }
    pub const fn len(&self) -> usize {
        self.len
    }
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn next_deadline(&self) -> Option<Deadline> {
        if self.len == 0 {
            None
        } else {
            Some(self.heap[0])
        }
    }

    pub fn push(&mut self, deadline: Deadline) -> Result<(), Error> {
        if self.len == N {
            return Err(Error::Capacity);
        }
        if self.heap[..self.len]
            .iter()
            .any(|item| item.id == deadline.id)
        {
            return Err(Error::DuplicateTimer);
        }
        let mut index = self.len;
        self.heap[index] = deadline;
        self.len += 1;
        while index > 0 {
            let parent = (index - 1) / 2;
            if earlier_or_equal(self.heap[parent], self.heap[index]) {
                break;
            }
            self.heap.swap(parent, index);
            index = parent;
        }
        Ok(())
    }

    pub fn pop_due(&mut self, now_ns: u64) -> Option<Deadline> {
        if self.len == 0 || self.heap[0].deadline_ns > now_ns {
            return None;
        }
        Some(self.remove_at(0))
    }

    pub fn cancel(&mut self, id: TimerId) -> Result<Deadline, Error> {
        let index = self.heap[..self.len]
            .iter()
            .position(|item| item.id == id)
            .ok_or(Error::TimerNotFound)?;
        Ok(self.remove_at(index))
    }

    fn remove_at(&mut self, index: usize) -> Deadline {
        let removed = self.heap[index];
        self.len -= 1;
        if index != self.len {
            self.heap[index] = self.heap[self.len];
        }
        self.heap[self.len] = Deadline::EMPTY;
        if index < self.len {
            let mut current = index;
            while current > 0 {
                let parent = (current - 1) / 2;
                if earlier_or_equal(self.heap[parent], self.heap[current]) {
                    break;
                }
                self.heap.swap(parent, current);
                current = parent;
            }
            loop {
                let left = current * 2 + 1;
                if left >= self.len {
                    break;
                }
                let right = left + 1;
                let mut smallest = left;
                if right < self.len && earlier_or_equal(self.heap[right], self.heap[left]) {
                    smallest = right;
                }
                if earlier_or_equal(self.heap[current], self.heap[smallest]) {
                    break;
                }
                self.heap.swap(current, smallest);
                current = smallest;
            }
        }
        removed
    }
}

const fn earlier_or_equal(a: Deadline, b: Deadline) -> bool {
    a.deadline_ns < b.deadline_ns || (a.deadline_ns == b.deadline_ns && a.id.0 <= b.id.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_point_scale_tracks_common_tsc_frequency() {
        let scale = CycleScale::from_frequency_hz(2_500_000_000, 32).unwrap();
        let ns = scale.delta_to_ns(2_500_000_000).unwrap();
        assert!((1_000_000_000..=1_000_000_001).contains(&ns));
    }

    #[test]
    fn deadline_heap_returns_chronological_order() {
        let mut q = DeadlineQueue::<8>::new();
        q.push(Deadline {
            id: TimerId(3),
            deadline_ns: 30,
        })
        .unwrap();
        q.push(Deadline {
            id: TimerId(1),
            deadline_ns: 10,
        })
        .unwrap();
        q.push(Deadline {
            id: TimerId(2),
            deadline_ns: 20,
        })
        .unwrap();
        assert_eq!(q.pop_due(9), None);
        assert_eq!(q.pop_due(10).unwrap().id, TimerId(1));
        assert_eq!(q.pop_due(25).unwrap().id, TimerId(2));
        assert_eq!(q.pop_due(30).unwrap().id, TimerId(3));
    }

    #[test]
    fn cancel_repairs_heap() {
        let mut q = DeadlineQueue::<8>::new();
        for (id, time) in [(1, 50), (2, 10), (3, 30), (4, 20)] {
            q.push(Deadline {
                id: TimerId(id),
                deadline_ns: time,
            })
            .unwrap();
        }
        assert_eq!(q.cancel(TimerId(3)).unwrap().deadline_ns, 30);
        assert_eq!(q.pop_due(20).unwrap().id, TimerId(2));
        assert_eq!(q.pop_due(20).unwrap().id, TimerId(4));
    }

    #[test]
    fn timespec_is_normalized() {
        assert_eq!(
            ns_to_timespec(2_000_000_123).unwrap(),
            Timespec {
                tv_sec: 2,
                tv_nsec: 123
            }
        );
    }
}
