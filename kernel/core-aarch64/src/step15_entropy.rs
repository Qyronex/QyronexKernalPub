// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU8, Ordering};
use kernal_fdt::{Blob, Event};

pub const AT_RANDOM_BYTES: usize = 16;
const QEMU_RNG_SEED_BYTES: usize = AT_RANDOM_BYTES * 2;

const EMPTY: u8 = 0;
const INSTALLING: u8 = 1;
const FIRST_READY: u8 = 2;
const FIRST_BORROWED: u8 = 3;
const SECOND_READY: u8 = 4;
const SECOND_BORROWED: u8 = 5;
const EXHAUSTED: u8 = 6;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Fdt(kernal_fdt::Error),
    MissingSeed,
    SeedTooShort,
    DuplicateSeed,
    AlreadyPublished,
    Busy,
    Exhausted,
    InvalidState,
    QemuDtbUnavailable,
}

impl From<kernal_fdt::Error> for Error {
    fn from(value: kernal_fdt::Error) -> Self {
        Self::Fdt(value)
    }
}

/// Bounded two-grant owner for QEMU's complete 32-byte `/chosen/rng-seed` value.
///
/// Step 30 needs exactly two Linux `AT_RANDOM` payloads: one for the initial image and one for the
/// single real exec exercised by the final QEMU oracle. The two payloads are the two disjoint halves
/// of the host-provided seed. No clock/counter input, deterministic expansion, or payload reuse is
/// accepted. A third request fails closed until a reusable cryptographic entropy owner is introduced.
struct SeedCell {
    state: AtomicU8,
    bytes: UnsafeCell<[u8; QEMU_RNG_SEED_BYTES]>,
}

// SAFETY: EMPTY -> INSTALLING gives one publisher. FIRST_READY/SECOND_READY -> *_BORROWED gives one
// temporary reader/mutator. The first grant is copied and erased before publishing SECOND_READY. The
// second grant is either erased before EXHAUSTED or left intact before rolling back to SECOND_READY;
// no reference to retained seed bytes can escape.
unsafe impl Sync for SeedCell {}

impl SeedCell {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(EMPTY),
            bytes: UnsafeCell::new([0; QEMU_RNG_SEED_BYTES]),
        }
    }

    fn publish(&self, seed: [u8; QEMU_RNG_SEED_BYTES]) -> Result<(), Error> {
        match self
            .state
            .compare_exchange(EMPTY, INSTALLING, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => {}
            Err(INSTALLING | FIRST_BORROWED | SECOND_BORROWED) => return Err(Error::Busy),
            Err(FIRST_READY | SECOND_READY | EXHAUSTED) => return Err(Error::AlreadyPublished),
            Err(_) => return Err(Error::InvalidState),
        }
        // SAFETY: INSTALLING is exclusive writer ownership and no reader can observe a ready state.
        unsafe { *self.bytes.get() = seed };
        self.state.store(FIRST_READY, Ordering::Release);
        Ok(())
    }

    fn take(&self) -> Result<[u8; AT_RANDOM_BYTES], Error> {
        let (offset, next_state) = loop {
            match self.state.load(Ordering::Acquire) {
                EMPTY => return Err(Error::MissingSeed),
                INSTALLING | FIRST_BORROWED | SECOND_BORROWED => return Err(Error::Busy),
                FIRST_READY => {
                    if self
                        .state
                        .compare_exchange(
                            FIRST_READY,
                            FIRST_BORROWED,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        break (0, SECOND_READY);
                    }
                }
                SECOND_READY => {
                    if self
                        .state
                        .compare_exchange(
                            SECOND_READY,
                            SECOND_BORROWED,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        break (AT_RANDOM_BYTES, EXHAUSTED);
                    }
                }
                EXHAUSTED => return Err(Error::Exhausted),
                _ => return Err(Error::InvalidState),
            }
        };

        let mut output = [0u8; AT_RANDOM_BYTES];
        // SAFETY: the successful *_READY -> *_BORROWED transition is the sole access right for this
        // half. The bytes are copied out by value and then erased before the next state is published.
        unsafe {
            let bytes = &mut *self.bytes.get();
            let end = offset + AT_RANDOM_BYTES;
            output.copy_from_slice(&bytes[offset..end]);
            bytes[offset..end].fill(0);
        }
        self.state.store(next_state, Ordering::Release);
        Ok(output)
    }

    /// Runs one reversible preparation transaction against the second AT_RANDOM grant.
    ///
    /// The owner retains the original bytes while `operation` stages the replacement image. A normal
    /// preparation error republishes the exact same second grant for a later exec retry. Only success
    /// erases the retained bytes and advances the owner to EXHAUSTED. This keeps Linux-visible exec
    /// failures before the irreversible image commit from consuming the process's sole exec grant.
    fn with_second_transaction<R, E>(
        &self,
        operation: impl FnOnce([u8; AT_RANDOM_BYTES]) -> Result<R, E>,
    ) -> Result<Result<R, E>, Error> {
        loop {
            match self.state.load(Ordering::Acquire) {
                EMPTY => return Err(Error::MissingSeed),
                INSTALLING | FIRST_BORROWED | SECOND_BORROWED => return Err(Error::Busy),
                FIRST_READY => return Err(Error::InvalidState),
                SECOND_READY => {
                    if self
                        .state
                        .compare_exchange(
                            SECOND_READY,
                            SECOND_BORROWED,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        break;
                    }
                }
                EXHAUSTED => return Err(Error::Exhausted),
                _ => return Err(Error::InvalidState),
            }
        }

        let mut grant = [0u8; AT_RANDOM_BYTES];
        // SAFETY: SECOND_BORROWED is exclusive access to the retained second half. Unlike `take`, the
        // owner copy is deliberately not erased until the staging operation reports success.
        unsafe {
            let bytes = &*self.bytes.get();
            grant.copy_from_slice(&bytes[AT_RANDOM_BYTES..QEMU_RNG_SEED_BYTES]);
        }

        match operation(grant) {
            Ok(value) => {
                // SAFETY: this transaction still owns SECOND_BORROWED, so no other accessor can read
                // or mutate the retained second half before EXHAUSTED is published.
                unsafe {
                    let bytes = &mut *self.bytes.get();
                    bytes[AT_RANDOM_BYTES..QEMU_RNG_SEED_BYTES].fill(0);
                }
                self.state.store(EXHAUSTED, Ordering::Release);
                Ok(Ok(value))
            }
            Err(error) => {
                // The retained owner copy was never changed, so releasing SECOND_READY makes the
                // identical grant available to a later reversible exec attempt.
                self.state.store(SECOND_READY, Ordering::Release);
                Ok(Err(error))
            }
        }
    }
}

static QEMU_AT_RANDOM: SeedCell = SeedCell::new();

/// Extracts the complete 32-byte root `/chosen/rng-seed` property prefix from a validated DTB.
///
/// QEMU ARM `virt` publishes 32 host-random bytes when DTB randomness is enabled. Step 30 retains
/// exactly those bytes so the initial image and one real exec receive disjoint 16-byte payloads.
/// Nested `rng-seed` properties do not count. Short or duplicate root-chosen seeds fail closed.
pub fn extract_at_random(blob: &Blob<'_>) -> Result<[u8; QEMU_RNG_SEED_BYTES], Error> {
    let mut depth = 0usize;
    let mut chosen_depth = None;
    let mut found = None;

    for event in blob.events() {
        match event? {
            Event::BeginNode(name) => {
                depth = depth.checked_add(1).ok_or(Error::InvalidState)?;
                if depth == 2 && name == "chosen" {
                    chosen_depth = Some(depth);
                }
            }
            Event::Property { name, value } => {
                if chosen_depth == Some(depth) && name == "rng-seed" {
                    if found.is_some() {
                        return Err(Error::DuplicateSeed);
                    }
                    let prefix = value
                        .get(..QEMU_RNG_SEED_BYTES)
                        .ok_or(Error::SeedTooShort)?;
                    let mut seed = [0u8; QEMU_RNG_SEED_BYTES];
                    seed.copy_from_slice(prefix);
                    found = Some(seed);
                }
            }
            Event::EndNode => {
                if chosen_depth == Some(depth) {
                    chosen_depth = None;
                }
                depth = depth.checked_sub(1).ok_or(Error::InvalidState)?;
            }
        }
    }

    found.ok_or(Error::MissingSeed)
}

/// Captures QEMU's complete DTB-provided randomness while the original DTB mapping is available.
///
/// # Safety
/// Must run in the QEMU proof boot before the protected-regime transition, under the parent module's
/// existing `qemu_dtb` bare-metal contract.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub unsafe fn publish_qemu_at_random() -> Result<(), Error> {
    // SAFETY: delegated caller contract; parent helper performs bounded header/Blob validation.
    let blob = unsafe {
        super::super::qemu_dtb(super::super::QEMU_VIRT_RAM_BASE).ok_or(Error::QemuDtbUnavailable)?
    };
    QEMU_AT_RANDOM.publish(extract_at_random(&blob)?)
}

/// Consumes the next of exactly two boot-provided Linux `AT_RANDOM` payloads.
///
/// Grant 0 is used by the initial Linux image. The live Step-30 exec path must use
/// [`with_exec_at_random`] for grant 1 so a reversible staging failure does not exhaust it.
pub fn take_at_random() -> Result<[u8; AT_RANDOM_BYTES], Error> {
    QEMU_AT_RANDOM.take()
}

/// Runs reversible live-exec staging with the second boot-provided `AT_RANDOM` payload.
///
/// The nested result separates entropy-owner failure from the caller's normal staging error. `Err(E)`
/// from `operation` restores the second grant unchanged; `Ok(R)` commits it permanently and every
/// later request fails with [`Error::Exhausted`]. The closure must encompass every ordinary fallible
/// preparation step before the live exec path crosses its irreversible old-image commit boundary.
pub fn with_exec_at_random<R, E>(
    operation: impl FnOnce([u8; AT_RANDOM_BYTES]) -> Result<R, E>,
) -> Result<Result<R, E>, Error> {
    QEMU_AT_RANDOM.with_second_transaction(operation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kernal_fdt::{CURRENT_VERSION, HEADER_SIZE, MAGIC};

    const BEGIN: u32 = 1;
    const END_NODE: u32 = 2;
    const PROP: u32 = 3;
    const END: u32 = 9;

    fn push_u32(bytes: &mut Vec<u8>, value: u32) {
        bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn align4(bytes: &mut Vec<u8>) {
        while !bytes.len().is_multiple_of(4) {
            bytes.push(0);
        }
    }

    fn begin(bytes: &mut Vec<u8>, name: &str) {
        push_u32(bytes, BEGIN);
        bytes.extend_from_slice(name.as_bytes());
        bytes.push(0);
        align4(bytes);
    }

    fn prop(bytes: &mut Vec<u8>, name_offset: u32, value: &[u8]) {
        push_u32(bytes, PROP);
        push_u32(bytes, value.len() as u32);
        push_u32(bytes, name_offset);
        bytes.extend_from_slice(value);
        align4(bytes);
    }

    fn blob(seed: Option<&[u8]>, nested: bool, duplicate: bool) -> Vec<u8> {
        let reserve_offset = HEADER_SIZE;
        let structure_offset = reserve_offset + 16;
        let strings = b"rng-seed\0";
        let mut structure = Vec::new();
        begin(&mut structure, "");
        begin(&mut structure, "chosen");
        if let Some(seed) = seed {
            prop(&mut structure, 0, seed);
            if duplicate {
                prop(&mut structure, 0, seed);
            }
        }
        if nested {
            begin(&mut structure, "nested");
            prop(&mut structure, 0, &[0xa5; QEMU_RNG_SEED_BYTES]);
            push_u32(&mut structure, END_NODE);
        }
        push_u32(&mut structure, END_NODE);
        push_u32(&mut structure, END_NODE);
        push_u32(&mut structure, END);

        let strings_offset = structure_offset + structure.len();
        let total = strings_offset + strings.len();
        let mut bytes = vec![0u8; total];
        bytes[0..4].copy_from_slice(&MAGIC.to_be_bytes());
        bytes[4..8].copy_from_slice(&(total as u32).to_be_bytes());
        bytes[8..12].copy_from_slice(&(structure_offset as u32).to_be_bytes());
        bytes[12..16].copy_from_slice(&(strings_offset as u32).to_be_bytes());
        bytes[16..20].copy_from_slice(&(reserve_offset as u32).to_be_bytes());
        bytes[20..24].copy_from_slice(&CURRENT_VERSION.to_be_bytes());
        bytes[24..28].copy_from_slice(&CURRENT_VERSION.to_be_bytes());
        bytes[32..36].copy_from_slice(&(strings.len() as u32).to_be_bytes());
        bytes[36..40].copy_from_slice(&(structure.len() as u32).to_be_bytes());
        bytes[structure_offset..strings_offset].copy_from_slice(&structure);
        bytes[strings_offset..].copy_from_slice(strings);
        bytes
    }

    #[test]
    fn extracts_complete_root_chosen_seed() {
        let mut source = [0x40u8; QEMU_RNG_SEED_BYTES];
        source[AT_RANDOM_BYTES..].fill(0x80);
        let bytes = blob(Some(&source), false, false);
        let parsed = Blob::parse(&bytes).unwrap();
        assert_eq!(extract_at_random(&parsed).unwrap(), source);
    }

    #[test]
    fn nested_seed_does_not_replace_root_seed() {
        let source = [0x31u8; QEMU_RNG_SEED_BYTES];
        let bytes = blob(Some(&source), true, false);
        let parsed = Blob::parse(&bytes).unwrap();
        assert_eq!(extract_at_random(&parsed).unwrap(), source);
    }

    #[test]
    fn missing_short_and_duplicate_seed_fail_closed() {
        let bytes = blob(None, false, false);
        assert_eq!(
            extract_at_random(&Blob::parse(&bytes).unwrap()),
            Err(Error::MissingSeed)
        );
        let short = blob(Some(&[7u8; QEMU_RNG_SEED_BYTES - 1]), false, false);
        assert_eq!(
            extract_at_random(&Blob::parse(&short).unwrap()),
            Err(Error::SeedTooShort)
        );
        let duplicate = blob(Some(&[9u8; QEMU_RNG_SEED_BYTES]), false, true);
        assert_eq!(
            extract_at_random(&Blob::parse(&duplicate).unwrap()),
            Err(Error::DuplicateSeed)
        );
    }

    #[test]
    fn seed_cell_serves_two_disjoint_linear_grants_then_exhausts() {
        let cell = SeedCell::new();
        assert_eq!(cell.take(), Err(Error::MissingSeed));

        let mut seed = [0u8; QEMU_RNG_SEED_BYTES];
        for (index, byte) in seed.iter_mut().enumerate() {
            *byte = index as u8;
        }
        cell.publish(seed).unwrap();

        let expected_first: [u8; AT_RANDOM_BYTES] = core::array::from_fn(|index| index as u8);
        let expected_second: [u8; AT_RANDOM_BYTES] =
            core::array::from_fn(|index| (index + AT_RANDOM_BYTES) as u8);
        assert_eq!(cell.take().unwrap(), expected_first);
        assert_eq!(cell.take().unwrap(), expected_second);
        assert_eq!(cell.take(), Err(Error::Exhausted));
        assert_eq!(cell.publish(seed), Err(Error::AlreadyPublished));
    }

    #[test]
    fn exec_grant_rolls_back_on_failed_staging_and_commits_only_on_success() {
        let cell = SeedCell::new();
        let mut seed = [0u8; QEMU_RNG_SEED_BYTES];
        for (index, byte) in seed.iter_mut().enumerate() {
            *byte = index as u8;
        }
        cell.publish(seed).unwrap();

        let expected_first: [u8; AT_RANDOM_BYTES] = core::array::from_fn(|index| index as u8);
        let expected_second: [u8; AT_RANDOM_BYTES] =
            core::array::from_fn(|index| (index + AT_RANDOM_BYTES) as u8);

        assert_eq!(
            cell.with_second_transaction(|_| Ok::<(), ()>(())),
            Err(Error::InvalidState)
        );
        assert_eq!(cell.take().unwrap(), expected_first);

        let failed = cell
            .with_second_transaction(|grant| {
                assert_eq!(grant, expected_second);
                Err::<(), u8>(7)
            })
            .unwrap();
        assert_eq!(failed, Err(7));

        let retried = cell.with_second_transaction(Ok::<_, u8>).unwrap();
        assert_eq!(retried, Ok(expected_second));
        assert_eq!(cell.take(), Err(Error::Exhausted));
        assert_eq!(
            cell.with_second_transaction(|_| Ok::<(), ()>(())),
            Err(Error::Exhausted)
        );
    }
}
