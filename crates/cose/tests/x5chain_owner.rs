// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Observe the legacy certificate decoder's ownership on failure and success.

#![cfg(all(feature = "cose-crypto", not(target_arch = "wasm32")))]

use reallyme_cose::{
    cose_sign1_with_options, cose_verify1_with_x5chain_and_exact_algorithm, Algorithm, CoseError,
    CosePolicy, CoseSign1EncodeOptions, X5ChainHeaderPlacement,
};
use reallyme_crypto::dispatch::generate_keypair;
use std::sync::atomic::{AtomicUsize, Ordering};
use zeroize::Zeroizing;

// Exactly one test arms this observer, for a live synthetic buffer allocation.
// The allocator clears its address before forwarding deallocation, so reuse by
// unrelated test-harness allocations cannot affect the observation.
static WATCH_ADDRESS: AtomicUsize = AtomicUsize::new(0);
static WATCH_LENGTH: AtomicUsize = AtomicUsize::new(0);
static OBSERVATION: AtomicUsize = AtomicUsize::new(0);
const NOT_OBSERVED: usize = 0;
const CLEARED: usize = 1;
const RETAINED: usize = 2;
const INVALID_LENGTH: usize = 3;

#[allow(unsafe_code)]
mod allocator {
    use super::{CLEARED, INVALID_LENGTH, OBSERVATION, RETAINED, WATCH_ADDRESS, WATCH_LENGTH};
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::Ordering;

    pub(super) struct Observed;

    // SAFETY: Allocation and layout are forwarded unchanged to System. Only
    // the armed allocation's initialized prefix is read before deallocation;
    // ownership has reached the allocator, so no live reference may access it.
    unsafe impl GlobalAlloc for Observed {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // SAFETY: System receives the valid layout required by GlobalAlloc;
            // the returned pointer and its ownership are unchanged.
            unsafe { System.alloc(layout) }
        }

        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            if WATCH_ADDRESS
                .compare_exchange(pointer.addr(), 0, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                let length = WATCH_LENGTH.load(Ordering::SeqCst);
                let result = if length > layout.size() {
                    INVALID_LENGTH
                } else {
                    // SAFETY: The armed pointer is live, uniquely owned and
                    // allocated with this layout. The original buffer length
                    // bounds initialized bytes; this reads no spare capacity.
                    let bytes = unsafe { core::slice::from_raw_parts(pointer, length) };
                    if bytes.iter().all(|byte| *byte == 0) {
                        CLEARED
                    } else {
                        RETAINED
                    }
                };
                OBSERVATION.store(result, Ordering::SeqCst);
            }
            // SAFETY: The exact live pointer/layout pair is forwarded once;
            // inspection does not change its allocation, aliasing or ownership.
            unsafe { System.dealloc(pointer, layout) }
        }
    }
}

#[global_allocator]
static ALLOCATOR: allocator::Observed = allocator::Observed;

#[test]
fn certificate_copies_wipe_on_resolution_failure_and_receipt_drop() -> Result<(), CoseError> {
    let (public, private) = generate_keypair(Algorithm::Ed25519).map_err(|_| CoseError::Crypto)?;
    let private = Zeroizing::new(private);
    for placement in [
        X5ChainHeaderPlacement::Protected,
        X5ChainHeaderPlacement::Unprotected,
    ] {
        let encoded = cose_sign1_with_options(
            Algorithm::Ed25519,
            b"synthetic ownership payload",
            &private,
            None,
            CoseSign1EncodeOptions::new()
                .with_x5chain_der(vec![vec![0xa5; 48]])
                .with_x5chain_header_placement(placement),
        )?;
        for resolved in [false, true] {
            let result = cose_verify1_with_x5chain_and_exact_algorithm(
                &encoded,
                &CosePolicy::new().with_allow_unprotected_x5chain(true),
                |_, chain| {
                    let certificate = &chain[0];
                    WATCH_LENGTH.store(certificate.len(), Ordering::SeqCst);
                    OBSERVATION.store(NOT_OBSERVED, Ordering::SeqCst);
                    WATCH_ADDRESS.store(certificate.as_ptr().addr(), Ordering::SeqCst);
                    resolved.then(|| public.clone())
                },
            );
            if resolved {
                assert!(result.is_ok());
                // Ownership remains live through the authenticated receipt.
                assert_eq!(OBSERVATION.load(Ordering::SeqCst), NOT_OBSERVED);
            } else {
                assert_eq!(result.err(), Some(CoseError::KeyNotResolved));
                assert_eq!(OBSERVATION.load(Ordering::SeqCst), CLEARED);
                continue;
            }
            drop(result);
            assert_eq!(WATCH_ADDRESS.load(Ordering::SeqCst), 0);
            assert_eq!(OBSERVATION.load(Ordering::SeqCst), CLEARED);
        }
    }
    Ok(())
}
