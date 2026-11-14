// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Observe sensitive JSON storage immediately before its allocator releases it.

#![cfg(all(feature = "generated", not(target_arch = "wasm32")))]

use buffa::Message;
use reallyme_cose_proto::generated::proto::reallyme::cose::v1::{
    CoseSign1CreateRequest, CoseX5Chain,
};
use std::sync::atomic::{AtomicUsize, Ordering};

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

fn arm(value: &str) -> String {
    let encoded = value.to_owned();
    WATCH_LENGTH.store(encoded.len(), Ordering::SeqCst);
    OBSERVATION.store(NOT_OBSERVED, Ordering::SeqCst);
    WATCH_ADDRESS.store(encoded.as_ptr().addr(), Ordering::SeqCst);
    encoded
}

fn arm_bytes(value: Vec<u8>) -> Vec<u8> {
    WATCH_LENGTH.store(value.len(), Ordering::SeqCst);
    OBSERVATION.store(NOT_OBSERVED, Ordering::SeqCst);
    WATCH_ADDRESS.store(value.as_ptr().addr(), Ordering::SeqCst);
    value
}

fn assert_cleared() {
    assert_eq!(WATCH_ADDRESS.load(Ordering::SeqCst), 0);
    assert_eq!(OBSERVATION.load(Ordering::SeqCst), CLEARED);
}

#[test]
fn owned_json_and_optional_byte_buffers_are_wiped_before_release() {
    for field in ["kid", "privateKey"] {
        for (encoded, late_error, valid) in [
            ("+/z9/g==", false, true),
            ("+/z9/g==", true, false),
            ("+/z9/g==%%%", false, false),
        ] {
            let mut object = serde_json::Map::new();
            object.insert(field.to_owned(), serde_json::Value::String(arm(encoded)));
            if late_error {
                object.insert("zzz".to_owned(), serde_json::Value::Bool(true));
            }
            let result =
                serde_json::from_value::<CoseSign1CreateRequest>(serde_json::Value::Object(object));
            assert_eq!(result.is_ok(), valid);
            assert_cleared();
        }
    }
    // Repeated byte fields share the same visitor and must protect each input.
    for valid in [false, true] {
        let encoded = if valid { "+/z9/g==" } else { "+/z9/g==%%%" };
        let mut object = serde_json::Map::new();
        object.insert(
            "certificatesDer".to_owned(),
            serde_json::Value::Array(vec![serde_json::Value::String(arm(encoded))]),
        );
        let result = serde_json::from_value::<CoseX5Chain>(serde_json::Value::Object(object));
        assert_eq!(result.is_ok(), valid);
        assert_cleared();
    }
    // Exercise actual generated paths as well as the static hardening guard.
    let value = CoseSign1CreateRequest::default().with_kid(arm_bytes(vec![0xa5; 4]));
    drop(value);
    assert_cleared();

    let mut value = CoseSign1CreateRequest::default().with_kid(arm_bytes(vec![0xa5; 4]));
    value.clear();
    assert!(value.kid.is_none());
    assert_cleared();

    let value = CoseSign1CreateRequest::default().with_kid(arm_bytes(vec![0xa5; 4]));
    let replaced = value.with_kid(vec![0x5a; 8]);
    assert_eq!(replaced.kid.as_deref(), Some(&[0x5a; 8][..]));
    assert_cleared();

    let replacement = zeroize::Zeroizing::new(
        CoseSign1CreateRequest::default()
            .with_kid(vec![0x5a; 64])
            .encode_to_vec(),
    );
    let mut value = CoseSign1CreateRequest::default().with_kid(arm_bytes(vec![0xa5; 4]));
    assert!(value.merge_from_slice(&replacement).is_ok());
    assert_cleared();

    let mut value = CoseSign1CreateRequest::default().with_kid(arm_bytes(vec![0xa5; 4]));
    assert!(value.merge_from_slice(&[0x22, 0x80]).is_err());
    drop(value);
    assert_cleared();
}
