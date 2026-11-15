// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::mem::ManuallyDrop;

use ciborium::Value;
use coset::{iana, Label, RegisteredLabelWithPrivate};
use zeroize::Zeroizing;

use super::{akp_profile_from_cose_algorithm, akp_public_bytes_from_params};
use crate::{Algorithm, CoseError};

#[kani::proof]
#[kani::unwind(18)]
fn akp_public_projection_excludes_the_private_parameter() {
    let public: [u8; 3] = kani::any();
    let secret = ManuallyDrop::new(Zeroizing::new(kani::any::<[u8; 64]>()));
    let supplied_public: bool = kani::any();
    let expected_len: usize = kani::any();
    // Only the projection borrows this fixture. Recursive teardown of the
    // synthetic CBOR values is outside the proof.
    let params = ManuallyDrop::new([
        (Label::Int(-1), Value::Bytes(public.to_vec())),
        (Label::Int(-2), Value::Bytes(secret.to_vec())),
    ]);
    let result =
        akp_public_bytes_from_params(&params[usize::from(!supplied_public)..], expected_len);
    let expected = if !supplied_public {
        Err(CoseError::MissingKeyMaterial)
    } else if expected_len != public.len() {
        Err(CoseError::InvalidKeyMaterial)
    } else {
        Ok(public.as_slice())
    };
    assert!(result == expected);
    kani::cover!(
        expected_len == 64 && !supplied_public,
        "private material cannot supply a missing public parameter"
    );
    kani::cover!(
        expected_len == 3 && supplied_public && public[0] != secret[0],
        "projection retains the distinct public bytes"
    );
}

#[kani::proof]
fn akp_registered_profiles_bind_exact_algorithm_and_material_widths() {
    let private_use: bool = kani::any();
    let identifier: i64 = kani::any();
    let (registered, expected) = if private_use {
        let expected = match identifier {
            -65_537 => Some((Algorithm::MlKem512, 800, 64, false)),
            -65_538 => Some((Algorithm::MlKem768, 1184, 64, false)),
            -65_539 => Some((Algorithm::MlKem1024, 1568, 64, false)),
            _ => None,
        };
        (RegisteredLabelWithPrivate::PrivateUse(identifier), expected)
    } else {
        let ordinal: u8 = kani::any();
        kani::assume(ordinal < 4);
        let (registered, expected) = match ordinal {
            0 => (
                iana::Algorithm::ML_DSA_44,
                Some((Algorithm::MlDsa44, 1312, 32, true)),
            ),
            1 => (
                iana::Algorithm::ML_DSA_65,
                Some((Algorithm::MlDsa65, 1952, 32, true)),
            ),
            2 => (
                iana::Algorithm::ML_DSA_87,
                Some((Algorithm::MlDsa87, 2592, 32, true)),
            ),
            _ => (iana::Algorithm::Ed25519, None),
        };
        (RegisteredLabelWithPrivate::Assigned(registered), expected)
    };
    match (akp_profile_from_cose_algorithm(&registered), expected) {
        (Ok(actual), Some((algorithm, public_len, private_len, is_signature))) => {
            assert!(actual.algorithm == algorithm);
            assert!(actual.public_key_len == public_len && actual.private_key_len == private_len);
            assert!(actual.is_signature == is_signature);
        }
        (Err(error), None) => {
            assert!(error == CoseError::UnsupportedAlgorithm);
        }
        _ => {
            assert!(false, "the AKP profile must match the registered algorithm");
        }
    }
    kani::cover!(
        private_use && identifier == -65_537,
        "the exact ML-KEM registration is reachable"
    );
    kani::cover!(
        !private_use && expected.is_some(),
        "an assigned ML-DSA registration is reachable"
    );
    kani::cover!(
        private_use && identifier == -65_540,
        "an ML-KEM key-wrap ID cannot select a COSE_Key profile"
    );
}
