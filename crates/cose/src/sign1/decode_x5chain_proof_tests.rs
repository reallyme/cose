// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::mem::ManuallyDrop;

use ciborium::value::Value;

use super::{
    claim_x5chain_label, sign1_fields, CoseError, Sign1HeaderBucket, X5ChainHeaderPlacement,
};

const X5CHAIN_WIRE_LABEL: i64 = 33;
const SIGN1_WIRE_TAG: u64 = 18;

#[kani::proof]
#[kani::unwind(6)]
fn x5chain_wire_sign1_tag_preserves_the_header_bucket_positions() {
    let has_tag: bool = kani::any();
    let tag = if kani::any() {
        SIGN1_WIRE_TAG
    } else {
        kani::any()
    };
    let complete: bool = kani::any();
    // Separate witnesses let the proof detect a field swap when removing the
    // tag. The semantic checks on each field run after selecting the array.
    let mut items = vec![Value::Bool(false), Value::Bool(true), Value::Null];
    if complete {
        items.push(Value::Integer(1.into()));
    }
    let body = Value::Array(items);
    let envelope = ManuallyDrop::new(if has_tag {
        Value::Tag(tag, Box::new(body))
    } else {
        body
    });
    let fields = sign1_fields(&envelope);
    let supported_tag = !has_tag || tag == SIGN1_WIRE_TAG;
    if complete && supported_tag {
        let Ok(([protected, unprotected, payload, signature], tagged)) = fields else {
            assert!(
                false,
                "a supported Sign1 envelope must expose its four fields"
            );
            return;
        };
        assert!(tagged == has_tag);
        assert!(matches!(protected, Value::Bool(false)));
        assert!(matches!(unprotected, Value::Bool(true)));
        assert!(matches!(payload, Value::Null));
        assert!(matches!(signature, Value::Integer(value) if i64::try_from(*value) == Ok(1)));
    } else {
        assert!(matches!(fields, Err(CoseError::InvalidFormat)));
    }
    kani::cover!(has_tag && tag == SIGN1_WIRE_TAG && fields.is_ok(), "tag 18");
    kani::cover!(!has_tag && fields.is_ok(), "untagged Sign1");
    kani::cover!(complete && !supported_tag && fields.is_err(), "wrong tag");
    kani::cover!(
        !complete && has_tag && supported_tag && fields.is_err(),
        "incomplete tagged array"
    );
}

#[kani::proof]
fn x5chain_wire_label_33_selects_the_bucket_and_can_only_be_claimed_once() {
    let protected_label = wire_label();
    let unprotected_label = wire_label();
    let mut placement = None;

    let protected = claim_x5chain_label(
        protected_label,
        Sign1HeaderBucket::Protected,
        true,
        &mut placement,
    );
    let has_protected_chain = protected_label == X5CHAIN_WIRE_LABEL;
    assert!(protected == Ok(has_protected_chain));
    assert!(placement == has_protected_chain.then_some(X5ChainHeaderPlacement::Protected));

    let unprotected = claim_x5chain_label(
        unprotected_label,
        Sign1HeaderBucket::Unprotected,
        true,
        &mut placement,
    );
    let has_unprotected_chain = unprotected_label == X5CHAIN_WIRE_LABEL;

    match (has_protected_chain, has_unprotected_chain) {
        (true, true) => {
            assert!(unprotected == Err(CoseError::DuplicateMapLabel));
            assert!(placement == Some(X5ChainHeaderPlacement::Protected));
        }
        (true, false) => {
            assert!(unprotected == Ok(false));
            assert!(placement == Some(X5ChainHeaderPlacement::Protected));
        }
        (false, true) => {
            assert!(unprotected == Ok(true));
            assert!(placement == Some(X5ChainHeaderPlacement::Unprotected));
        }
        (false, false) => {
            assert!(unprotected == Ok(false));
            assert!(placement.is_none());
        }
    }

    kani::cover!(
        has_protected_chain && !has_unprotected_chain,
        "protected label 33"
    );
    kani::cover!(
        !has_protected_chain && has_unprotected_chain,
        "unprotected label 33"
    );
    kani::cover!(
        !has_protected_chain && !has_unprotected_chain,
        "label 33 absent"
    );
    kani::cover!(
        has_protected_chain
            && has_unprotected_chain
            && unprotected == Err(CoseError::DuplicateMapLabel),
        "label 33 in both buckets"
    );
}

// Keep 33 explicit so every presence combination has a ready witness.
// The alternative branch still covers all possible decoded integers.
fn wire_label() -> i64 {
    if kani::any() {
        X5CHAIN_WIRE_LABEL
    } else {
        kani::any()
    }
}
