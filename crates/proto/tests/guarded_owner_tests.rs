// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Observe guarded field, collection and numeric storage before release.

#![cfg(all(feature = "generated", not(target_arch = "wasm32")))]

use buffa::Message;
use reallyme_cose_proto::generated::proto::reallyme::cose::v1::{
    cose_operation_request::Operation, CoseKeyFromPrivateBytesRequest,
    CoseMultikeyToCoseKeyRequest, CoseOperationRequest, CoseSign1CreateRequest,
};
use reallyme_cose_proto::{SecretBytes, SecretString};
use std::sync::atomic::{AtomicUsize, Ordering};

// Exactly one test arms this observer, for a live synthetic buffer allocation.
// The allocator clears its address before forwarding deallocation, so reuse by
// unrelated test-harness allocations cannot affect the observation.
static WATCH_ADDRESS: AtomicUsize = AtomicUsize::new(0);
static WATCH_LENGTH: AtomicUsize = AtomicUsize::new(0);
static OBSERVATION: AtomicUsize = AtomicUsize::new(0);
static NEXT_ALLOCATION_LENGTH: AtomicUsize = AtomicUsize::new(0);
const NOT_OBSERVED: usize = 0;
const CLEARED: usize = 1;
const RETAINED: usize = 2;
const INVALID_LENGTH: usize = 3;

#[allow(unsafe_code)]
mod allocator {
    use super::{
        CLEARED, INVALID_LENGTH, NEXT_ALLOCATION_LENGTH, OBSERVATION, RETAINED, WATCH_ADDRESS,
        WATCH_LENGTH,
    };
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
            let pointer = unsafe { System.alloc(layout) };
            if !pointer.is_null()
                && layout.size() != 0
                && NEXT_ALLOCATION_LENGTH
                    .compare_exchange(layout.size(), 0, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
            {
                WATCH_LENGTH.store(layout.size(), Ordering::SeqCst);
                WATCH_ADDRESS.store(pointer.addr(), Ordering::SeqCst);
            }
            pointer
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

fn arm(pointer: usize, length: usize) {
    WATCH_LENGTH.store(length, Ordering::SeqCst);
    OBSERVATION.store(NOT_OBSERVED, Ordering::SeqCst);
    WATCH_ADDRESS.store(pointer, Ordering::SeqCst);
}

fn assert_cleared() {
    assert_eq!(WATCH_ADDRESS.load(Ordering::SeqCst), 0);
    assert_eq!(OBSERVATION.load(Ordering::SeqCst), CLEARED);
}

fn watch_next(length: usize) {
    WATCH_ADDRESS.store(0, Ordering::SeqCst);
    OBSERVATION.store(NOT_OBSERVED, Ordering::SeqCst);
    NEXT_ALLOCATION_LENGTH.store(length, Ordering::SeqCst);
}

#[test]
fn guarded_fields_and_collections_wipe_spare_capacity_replacements_and_clones(
) -> Result<(), buffa::DecodeError> {
    use buffa::{bytes::Buf, DecodeOptions};
    // A unique field size identifies the first payload allocation. If a
    // fragmented decoder stages into ordinary Bytes before the guarded owner,
    // that first allocation is released unwiped and this observer fails.
    const FRAGMENTED_KEY_BYTES: usize = 16_381;
    let input =
        CoseSign1CreateRequest::default().with_private_key(vec![0xa5; FRAGMENTED_KEY_BYTES]);
    let encoded = zeroize::Zeroizing::new(input.encode_to_vec());
    let mut fragmented = encoded[..1024].chain(&encoded[1024..]);
    watch_next(FRAGMENTED_KEY_BYTES);
    let decoded: CoseSign1CreateRequest = DecodeOptions::new()
        .reject_unknown_fields()
        .decode(&mut fragmented)?;
    assert_eq!(NEXT_ALLOCATION_LENGTH.load(Ordering::SeqCst), 0);
    assert_ne!(WATCH_ADDRESS.load(Ordering::SeqCst), 0);
    assert_eq!(OBSERVATION.load(Ordering::SeqCst), NOT_OBSERVED);
    drop(decoded);
    assert_cleared();

    const INVALID_TEXT_BYTES: usize = 8_179;
    let input =
        CoseMultikeyToCoseKeyRequest::default().with_multikey("x".repeat(INVALID_TEXT_BYTES));
    let mut encoded = zeroize::Zeroizing::new(input.encode_to_vec());
    let last = encoded.last_mut().ok_or(buffa::DecodeError::InvalidUtf8)?;
    *last = 0xff;
    let mut fragmented = encoded[..1024].chain(&encoded[1024..]);
    watch_next(INVALID_TEXT_BYTES);
    assert!(DecodeOptions::new()
        .reject_unknown_fields()
        .decode::<CoseMultikeyToCoseKeyRequest>(&mut fragmented)
        .is_err());
    assert_eq!(NEXT_ALLOCATION_LENGTH.load(Ordering::SeqCst), 0);
    assert_cleared();

    for length in [1, 127, 128, 255, 256, 4096] {
        // Initialize the entire allocation before shortening it, so the
        // observer can safely check every spare byte immediately before free.
        let mut bytes = Vec::with_capacity(length);
        bytes.resize(bytes.capacity(), 0xa5);
        let initialized = bytes.len();
        bytes.truncate(1);
        arm(bytes.as_ptr().addr(), initialized);
        let guarded = SecretBytes::from(bytes);
        let cloned = guarded.clone();
        assert_ne!(guarded.as_ptr(), cloned.as_ptr());
        drop(guarded);
        assert_cleared();
        assert_eq!(cloned.as_slice(), &[0xa5]);
        arm(cloned.as_ptr().addr(), cloned.len());
        drop(cloned);
        assert_cleared();

        let mut bytes = vec![b'A'; length];
        bytes.resize(bytes.capacity(), b'A');
        let initialized = bytes.len();
        let mut text = String::from_utf8(bytes).map_err(|_| buffa::DecodeError::InvalidUtf8)?;
        text.truncate(1);
        arm(text.as_ptr().addr(), initialized);
        drop(SecretString::from(text));
        assert_cleared();
    }
    let mut value = CoseKeyFromPrivateBytesRequest::default().with_private_key(vec![0xa5; 4096]);
    arm(value.private_key.as_ptr().addr(), value.private_key.len());
    value.merge_from_slice(&[0x12, 1, 0x24])?;
    assert_cleared();
    assert_eq!(value.private_key.as_slice(), &[0x24]);

    let mut value = CoseKeyFromPrivateBytesRequest::default().with_private_key(vec![0xa5; 65_536]);
    arm(value.private_key.as_ptr().addr(), value.private_key.len());
    value.merge_from_slice(&[0x12, 0])?;
    assert_cleared();
    for _ in 0..100 {
        value.merge_from_slice(&[0x12, 0])?;
    }
    assert!(value.private_key.is_empty());
    let mut value = CoseMultikeyToCoseKeyRequest::default().with_multikey("x".repeat(65_536));
    arm(value.multikey.as_ptr().addr(), value.multikey.len());
    value.merge_from_slice(&[0x0a, 0])?;
    assert_cleared();
    for _ in 0..100 {
        value.merge_from_slice(&[0x0a, 0])?;
    }
    assert!(value.multikey.is_empty());

    let mut value = CoseOperationRequest::default();
    let child = CoseSign1CreateRequest::default().with_private_key(vec![0xa5; 32]);
    arm(child.private_key.as_ptr().addr(), child.private_key.len());
    value.operation = Some(Operation::Sign1Create(Box::new(child)));
    value.operation = Some(Operation::PreferredCborValidate(Box::default()));
    assert_cleared();

    let mut numbers = buffa::sensitive::List::default();
    numbers.push(0xa5a5_a5a5_a5a5_a5a5_u64);
    while numbers.len() < numbers.capacity() {
        numbers.push(0xa5a5_a5a5_a5a5_a5a5);
    }
    let initialized = numbers
        .len()
        .checked_mul(core::mem::size_of::<u64>())
        .ok_or(buffa::DecodeError::MessageTooLarge)?;
    arm(numbers.as_ptr().addr(), initialized);
    numbers.push(0x2424_2424_2424_2424);
    assert_cleared();
    let clone = numbers.clone();
    let initialized = numbers
        .len()
        .checked_mul(core::mem::size_of::<u64>())
        .ok_or(buffa::DecodeError::MessageTooLarge)?;
    arm(numbers.as_ptr().addr(), initialized);
    drop(numbers.into_iter());
    assert_cleared();
    assert!(!clone.is_empty());

    Ok(())
}
