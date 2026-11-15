// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use ciborium::value::Value;
use coset::{iana, CoseSign1, Label, RegisteredLabelWithPrivate};

use super::validate_cose_sign1_structure;
use crate::CoseError;

#[cfg(test)]
#[test]
fn sign1_structure_rejects_unprotected_security_headers_and_critical_headers() {
    for presence in 0_u8..32 {
        check_header_combination(presence);
    }
}

#[cfg(kani)]
#[kani::proof]
#[kani::unwind(8)]
fn sign1_protected_structure_rejects_unprotected_overrides_and_critical_headers() {
    let presence: u8 = kani::any();
    kani::assume(presence < 32);
    check_header_combination(presence);
    kani::cover!(presence == 0, "a protected-only algorithm is admitted");
    kani::cover!(
        presence & 1 != 0,
        "an unprotected algorithm cannot override the protected algorithm"
    );
    kani::cover!(presence & 0b11000 != 0, "critical fields are rejected");
}

fn check_header_combination(presence: u8) {
    let unprotected_alg = presence & 1 != 0;
    let unprotected_kid = presence & 2 != 0;
    let unprotected_type = presence & 4 != 0;
    let protected_crit = presence & 8 != 0;
    let unprotected_crit = presence & 16 != 0;
    // A protected algorithm is present in every case, so a simultaneous
    // unprotected algorithm is checked for rejection as well.
    let mut cose = CoseSign1::default();
    cose.protected.header.alg = Some(RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ES256));
    if unprotected_alg {
        cose.unprotected.alg = Some(RegisteredLabelWithPrivate::Assigned(
            iana::Algorithm::ESP256,
        ));
    }
    if unprotected_kid {
        cose.unprotected.key_id = vec![1];
    }
    if unprotected_type {
        cose.unprotected.rest = vec![(Label::Int(16), Value::Integer(1_i64.into()))];
    }
    if protected_crit {
        cose.protected.header.crit = vec![RegisteredLabelWithPrivate::Assigned(
            iana::HeaderParameter::Alg,
        )];
    }
    if unprotected_crit {
        cose.unprotected.crit = vec![RegisteredLabelWithPrivate::Assigned(
            iana::HeaderParameter::Alg,
        )];
    }
    // Model the structural guard independently of teardown of the synthetic
    // parsed headers.
    #[cfg(kani)]
    let cose = core::mem::ManuallyDrop::new(cose);
    let actual = validate_cose_sign1_structure(&cose);
    let expected = if protected_crit {
        Err(CoseError::UnsupportedCriticalHeader)
    } else if unprotected_alg || unprotected_kid || unprotected_type {
        Err(CoseError::UnprotectedHeaderNotAllowed)
    } else if unprotected_crit {
        Err(CoseError::UnsupportedCriticalHeader)
    } else {
        Ok(())
    };
    assert!(actual == expected);
}
