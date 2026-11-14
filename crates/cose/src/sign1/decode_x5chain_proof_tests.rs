// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{claim_x5chain_label, CoseError, Sign1HeaderBucket, X5ChainHeaderPlacement};

const X5CHAIN_WIRE_LABEL: i64 = 33;

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
