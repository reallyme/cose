// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Observe exact peer-key bytes, including Base IV, before storage is released.

#![cfg(all(feature = "cose-crypto", not(target_arch = "wasm32")))]

use buffa::MessageField;
use reallyme_cose::api::{
    contract::{
        __buffa::oneof::{
            cose_operation_request::Operation, cose_operation_response_v2::Outcome,
            cose_operation_result::Result as Branch,
        },
        CoseOperationRequest, CoseVerificationKeyImportRequest,
    },
    execute,
};
use reallyme_cose::containers::{
    inspect_peer_key, CryptoPeerKeyValidator, OptionalKeyPolicy, PeerKeyUsage, SignatureSuite,
};
use reallyme_cose::iso18013::{Iso18013SignatureAlgorithm, Iso18013SignatureCurve};
use reallyme_cose::CoseError;
use std::sync::atomic::{AtomicUsize, Ordering};

// Only this test arms the observer, for a live initialized buffer. Clear the
// address before releasing its allocation so later address reuse cannot match.
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

    // SAFETY: System receives each original layout unchanged. Only an armed
    // allocation's initialized bytes are read before freeing it. Its ownership
    // has reached dealloc, with no live references permitted to access it.
    unsafe impl GlobalAlloc for Observed {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // SAFETY: The valid GlobalAlloc layout and returned ownership pass
            // through unchanged to the system allocator.
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
                    // SAFETY: The pointer/layout pair is live and uniquely
                    // owned here. The armed original length covers initialized
                    // bytes only, and is bounded by this allocation's layout.
                    let bytes = unsafe { core::slice::from_raw_parts(pointer, length) };
                    if bytes.iter().all(|byte| *byte == 0) {
                        CLEARED
                    } else {
                        RETAINED
                    }
                };
                OBSERVATION.store(result, Ordering::SeqCst);
            }
            // SAFETY: This exact live pointer and original layout reach System
            // once. Inspection changes neither ownership nor allocation.
            unsafe { System.dealloc(pointer, layout) }
        }
    }
}

#[global_allocator]
static ALLOCATOR: allocator::Observed = allocator::Observed;

fn arm(bytes: &[u8]) {
    assert!(bytes.iter().any(|byte| *byte != 0));
    WATCH_LENGTH.store(bytes.len(), Ordering::SeqCst);
    OBSERVATION.store(NOT_OBSERVED, Ordering::SeqCst);
    WATCH_ADDRESS.store(bytes.as_ptr().addr(), Ordering::SeqCst);
}

fn encoded_key(valid: bool) -> Result<Vec<u8>, CoseError> {
    use ciborium::value::Value;
    // The P-256 generator is an independent public fixture; no private material
    // enters either watched allocation. Append Base IV to retain unsorted order.
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/iso18013-sign1.json"))
            .map_err(|_| CoseError::Cbor)?;
    let encoded = fixture
        .get("cases")
        .and_then(serde_json::Value::as_array)
        .and_then(|cases| cases.first())
        .and_then(|case| case.get("cose_key_hex"))
        .and_then(serde_json::Value::as_str)
        .ok_or(CoseError::InvalidFormat)?;
    let bytes = hex::decode(encoded).map_err(|_| CoseError::InvalidFormat)?;
    let Value::Map(mut params) =
        ciborium::de::from_reader(bytes.as_slice()).map_err(|_| CoseError::Cbor)?
    else {
        return Err(CoseError::InvalidFormat);
    };
    if !valid {
        for (label, value) in &mut params {
            if *label == Value::Integer((-2).into()) || *label == Value::Integer((-3).into()) {
                *value = Value::Bytes(vec![0; 32]);
            }
        }
    }
    params.push((Value::Integer(5.into()), Value::Bytes(vec![0xa5; 12])));
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&Value::Map(params), &mut encoded).map_err(|_| CoseError::Cbor)?;
    Ok(encoded)
}

fn verify_import_wipes_owned_keys(selected: SignatureSuite, valid: bool) -> Result<(), CoseError> {
    let request = CoseVerificationKeyImportRequest {
        suite: MessageField::some(selected.into()),
        public_key: encoded_key(valid)?.into(),
        public_key_is_cose: true,
        context_id: vec![0; 32].into(),
        require_iso_pair: true,
    };
    assert!(request.public_key.ends_with(&[0xa5; 12]));
    arm(&request.public_key);
    let imported = execute(CoseOperationRequest {
        operation: Some(Operation::VerificationKeyImport(Box::new(request))),
    });
    assert_eq!(WATCH_ADDRESS.load(Ordering::SeqCst), 0);
    assert_eq!(OBSERVATION.load(Ordering::SeqCst), CLEARED);
    if valid {
        let Some(Outcome::Result(result)) = imported.outcome.as_ref() else {
            return Err(CoseError::InvalidFormat);
        };
        let Some(Branch::VerificationKeyImport(key)) = result.result.as_ref() else {
            return Err(CoseError::InvalidFormat);
        };
        arm(&key.public_key);
        drop(imported);
        assert_eq!(WATCH_ADDRESS.load(Ordering::SeqCst), 0);
        assert_eq!(OBSERVATION.load(Ordering::SeqCst), CLEARED);
    } else {
        assert!(matches!(imported.outcome.as_ref(), Some(Outcome::Error(_))));
    }
    Ok(())
}

#[test]
fn signature_key_base_iv_and_point_owners_wipe_on_drop_and_validation_failure(
) -> Result<(), CoseError> {
    let selected = SignatureSuite::iso(
        Iso18013SignatureAlgorithm::Es256,
        Iso18013SignatureCurve::P256,
    )?;
    for valid in [true, false] {
        let encoded = encoded_key(valid)?;
        for watch_original in [true, false] {
            for validate in [false, true] {
                let key = inspect_peer_key(
                    &encoded,
                    PeerKeyUsage::Signature(selected),
                    OptionalKeyPolicy::Cose,
                )?;
                assert_eq!(key.original_cose_key(), encoded);
                assert!(key.original_cose_key().ends_with(&[0xa5; 12]));
                arm(if watch_original {
                    key.original_cose_key()
                } else {
                    key.public_material()
                });
                assert_eq!(OBSERVATION.load(Ordering::SeqCst), NOT_OBSERVED);
                if validate {
                    let result = key.validate(&CryptoPeerKeyValidator);
                    if valid {
                        assert!(result.is_ok());
                        assert_eq!(OBSERVATION.load(Ordering::SeqCst), NOT_OBSERVED);
                    } else {
                        assert_eq!(
                            result.as_ref().err().copied(),
                            Some(CoseError::InvalidKeyMaterial)
                        );
                    }
                    drop(result);
                } else {
                    drop(key);
                }
                assert_eq!(WATCH_ADDRESS.load(Ordering::SeqCst), 0);
                assert_eq!(OBSERVATION.load(Ordering::SeqCst), CLEARED);
                // The borrowed input is still caller-owned and unchanged.
                assert!(encoded.ends_with(&[0xa5; 12]));
            }
        }
        verify_import_wipes_owned_keys(selected, valid)?;
    }
    Ok(())
}
