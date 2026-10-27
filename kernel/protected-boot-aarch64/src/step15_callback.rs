// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU8, Ordering};

use crate::RuntimeTablePool;

const EMPTY: u8 = 0;
const INSTALLING: u8 = 1;
const READY: u8 = 2;
const RUNNING: u8 = 3;
const COMPLETE: u8 = 4;
const FAILED: u8 = 5;

/// Core-owned Step-15 proof entry invoked inside the protected BSP construction window.
///
/// The opaque context pointer lets Core retain its own serial, FDT/initrd and runtime-owner bundle
/// without making `kernal-protected-boot-aarch64` depend on Core. The page-table backend handle
/// identifies the exact monotonic [`RuntimeTablePool`] already used by the accepted Step-7 through
/// Step-14 proof chain; no second allocator cursor is created.
///
/// The backend is deliberately passed as a raw non-owning handle rather than `&mut RuntimeTablePool`.
/// A genuine Step-15 runtime may suspend while serving FUTEX_WAIT, so retaining a Rust exclusive
/// borrow on the suspended callback stack would conflict with a different runnable thread that needs
/// a short synchronous VM/loader page-table transaction against the same canonical pool.
///
/// # Safety
/// The callback must treat `context` and `backend` as valid only while the protected Step-15 runtime
/// owns this one-shot proof window. It must not retain any Rust reference materialized from either raw
/// handle across a scheduler switch or other blocking operation. A mutable `RuntimeTablePool` borrow
/// may exist only for one short synchronous page-table transaction and must be dropped before any
/// operation that can block or switch threads. No Process, address-space, frame or identity reference
/// may remain live across a potentially blocking FUTEX_WAIT scheduler switch.
pub type Step15ProofEntry = unsafe fn(*mut (), NonNull<RuntimeTablePool>) -> Result<(), ()>;

/// One non-cloneable callback descriptor supplied by Core before protected-regime construction.
pub struct Step15ProofCallback {
    context: *mut (),
    entry: Step15ProofEntry,
}

impl Step15ProofCallback {
    pub const fn new(context: *mut (), entry: Step15ProofEntry) -> Self {
        Self { context, entry }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Step15ProofCallbackError {
    ProtectedBootInactive,
    TransitionAlreadyStarted,
    IrqsEnabled,
    AlreadyInstalled,
    Busy,
    AlreadyConsumed,
    PanUnavailable,
    CallbackFailed,
    InvalidState,
}

struct CallbackCell {
    state: AtomicU8,
    callback: UnsafeCell<MaybeUninit<Step15ProofCallback>>,
}

// SAFETY: the state machine publishes exactly one initialized callback with Release/Acquire ordering.
// Installation and invocation are additionally restricted to the single IRQ-masked BSP owner.
unsafe impl Sync for CallbackCell {}

impl CallbackCell {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(EMPTY),
            callback: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    fn install(&self, callback: Step15ProofCallback) -> Result<(), Step15ProofCallbackError> {
        match self
            .state
            .compare_exchange(EMPTY, INSTALLING, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => {}
            Err(INSTALLING | READY) => {
                return Err(Step15ProofCallbackError::AlreadyInstalled);
            }
            Err(RUNNING) => return Err(Step15ProofCallbackError::Busy),
            Err(COMPLETE | FAILED) => {
                return Err(Step15ProofCallbackError::AlreadyConsumed);
            }
            Err(_) => return Err(Step15ProofCallbackError::InvalidState),
        }

        // SAFETY: successful EMPTY -> INSTALLING gives this BSP path unique write ownership. Readers
        // cannot observe the value before the following Release publication of READY.
        unsafe { (*self.callback.get()).write(callback) };
        self.state.store(READY, Ordering::Release);
        Ok(())
    }

    fn take(&self) -> Result<Option<Step15ProofCallback>, Step15ProofCallbackError> {
        loop {
            match self.state.load(Ordering::Acquire) {
                EMPTY => return Ok(None),
                READY => {
                    if self
                        .state
                        .compare_exchange(READY, RUNNING, Ordering::AcqRel, Ordering::Acquire)
                        .is_err()
                    {
                        continue;
                    }
                    // SAFETY: READY proves initialization completed; RUNNING gives this invocation
                    // unique read/move ownership and prevents a second take.
                    return Ok(Some(unsafe { (*self.callback.get()).assume_init_read() }));
                }
                INSTALLING | RUNNING => return Err(Step15ProofCallbackError::Busy),
                COMPLETE | FAILED => return Err(Step15ProofCallbackError::AlreadyConsumed),
                _ => return Err(Step15ProofCallbackError::InvalidState),
            }
        }
    }

    fn finish(&self, succeeded: bool) -> Result<(), Step15ProofCallbackError> {
        let next = if succeeded { COMPLETE } else { FAILED };
        self.state
            .compare_exchange(RUNNING, next, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| Step15ProofCallbackError::InvalidState)
    }
}

static STEP15_CALLBACK: CallbackCell = CallbackCell::new();

/// Installs the one Core-supplied Step-15 proof callback before final protected-regime construction.
///
/// The descriptor is consumed exactly once. No Rust reference is stored in this crate; ownership and
/// lifetime of the opaque context remain with Core. The callback is invoked after the accepted
/// Step-14 proof, while secondaries are still held, local IRQs remain masked, and the original
/// `RuntimeTablePool` object is still owned by the BSP without an outer Rust borrow spanning runtime
/// suspension.
///
/// # Safety
/// `callback.context` must remain allocated and valid for `callback.entry` until the protected proof
/// window invokes it. The entry must uphold [`Step15ProofEntry`]'s contract. The caller must be the
/// BSP owner before `enter_runtime_protected_regime()` begins, with IRQ delivery masked and no
/// concurrent installer.
pub unsafe fn install_step15_proof_callback(
    callback: Step15ProofCallback,
) -> Result<(), Step15ProofCallbackError> {
    if !crate::is_active() {
        return Err(Step15ProofCallbackError::ProtectedBootInactive);
    }
    if !crate::cpu_on_bootstrap_available() {
        return Err(Step15ProofCallbackError::TransitionAlreadyStarted);
    }
    if !kernal_arch_aarch64::irqs_masked() {
        return Err(Step15ProofCallbackError::IrqsEnabled);
    }
    STEP15_CALLBACK.install(callback)
}

pub(crate) fn run_if_installed(serial: &crate::Serial, mut backend: NonNull<RuntimeTablePool>) {
    let callback = match STEP15_CALLBACK.take() {
        Ok(Some(callback)) => callback,
        Ok(None) => return,
        Err(_) => crate::fatal(
            serial,
            "KERNAL/ARM64: Step 15 protected proof callback state invalid\n",
        ),
    };

    // Step 15 uses the production PAN/usercopy boundary. Establish the default before Core receives
    // the callback; the outer runtime repeats this idempotent check before releasing secondary PEs.
    if kernal_usercopy_aarch64::enable_pan_default().is_err()
        || kernal_usercopy_aarch64::pan_enabled() != Ok(true)
    {
        let _ = STEP15_CALLBACK.finish(false);
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 15 protected proof PAN setup failed\n",
        );
    }

    // SAFETY: installation is restricted to the BSP before transition start. The one-shot state
    // machine moved the exact descriptor into this invocation. The caller forms `backend` only after
    // every Step-7 through Step-14 `&mut RuntimeTablePool` call has returned, so no outer exclusive
    // Rust borrow is suspended across the potentially blocking live Step-15 runtime.
    let result = unsafe { (callback.entry)(callback.context, backend) };
    if result.is_err() {
        let _ = STEP15_CALLBACK.finish(false);
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 15 protected proof callback failed\n",
        );
    }

    // SAFETY: the Core callback has returned successfully, so its contract guarantees that no Rust
    // reference materialized from `backend` survives. This IRQ-masked BSP still exclusively owns the
    // exact construction cursor and final runtime readiness has not yet been published. The one-way
    // handoff moves that cursor into the live owner and leaves the suspended stack-local source inert.
    if unsafe { backend.as_mut().handoff_to_live() }.is_err() {
        let _ = STEP15_CALLBACK.finish(false);
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 15 runtime table-pool handoff failed\n",
        );
    }

    if STEP15_CALLBACK.finish(true).is_err() {
        crate::fatal(
            serial,
            "KERNAL/ARM64: Step 15 protected proof callback completion invalid\n",
        );
    }
}
