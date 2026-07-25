// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::unwrap_used)]

use super::{backend_signature_from_cose, cose_signature_from_backend};
use crate::CoseError;
use reallyme_crypto::core::Algorithm;

const P256_SIGNATURE_LEN: usize = 64;
const P521_SIGNATURE_LEN: usize = 132;

fn sample_fixed(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| u8::try_from(index % 251).unwrap().wrapping_add(1))
        .collect()
}

#[test]
fn fixed_roundtrips_through_der() {
    for (alg, len) in [
        (Algorithm::P256, P256_SIGNATURE_LEN),
        (Algorithm::P384, 96),
        (Algorithm::P521, P521_SIGNATURE_LEN),
    ] {
        let fixed = sample_fixed(len);
        let der = backend_signature_from_cose(alg, &fixed).unwrap();
        let back = cose_signature_from_backend(alg, der).unwrap();
        assert_eq!(back, fixed);
    }
}

#[test]
fn high_bit_scalars_gain_der_sign_padding_and_roundtrip() {
    let mut fixed = vec![0xff_u8; P256_SIGNATURE_LEN];
    fixed[0] = 0x80;
    fixed[32] = 0x80;
    let der = backend_signature_from_cose(Algorithm::P256, &fixed).unwrap();
    assert_eq!(der[4], 0);
    let back = cose_signature_from_backend(Algorithm::P256, der).unwrap();
    assert_eq!(back, fixed);
}

#[test]
fn short_scalars_left_pad_to_coordinate_width() {
    let mut fixed = vec![0_u8; P256_SIGNATURE_LEN];
    fixed[31] = 0x01;
    fixed[63] = 0x02;
    let der = backend_signature_from_cose(Algorithm::P256, &fixed).unwrap();
    let back = cose_signature_from_backend(Algorithm::P256, der).unwrap();
    assert_eq!(back, fixed);
}

#[test]
fn p521_uses_long_form_der_length() {
    let fixed = sample_fixed(P521_SIGNATURE_LEN);
    let der = backend_signature_from_cose(Algorithm::P521, &fixed).unwrap();
    assert_eq!(der[1], 0x81);
    let back = cose_signature_from_backend(Algorithm::P521, der).unwrap();
    assert_eq!(back, fixed);
}

#[test]
fn wrong_length_fixed_signature_is_rejected() {
    let fixed = sample_fixed(P256_SIGNATURE_LEN - 1);
    let err = backend_signature_from_cose(Algorithm::P256, &fixed).unwrap_err();
    assert_eq!(err, CoseError::InvalidSignatureEncoding);
}

#[test]
fn zero_scalars_are_rejected() {
    let fixed = vec![0_u8; P256_SIGNATURE_LEN];
    let err = backend_signature_from_cose(Algorithm::P256, &fixed).unwrap_err();
    assert_eq!(err, CoseError::InvalidSignatureEncoding);
}

#[test]
fn der_with_trailing_bytes_is_rejected() {
    let fixed = sample_fixed(P256_SIGNATURE_LEN);
    let mut der = backend_signature_from_cose(Algorithm::P256, &fixed).unwrap();
    der.push(0);
    let err = cose_signature_from_backend(Algorithm::P256, der).unwrap_err();
    assert_eq!(err, CoseError::InvalidSignatureEncoding);
}

#[test]
fn negative_der_integer_is_rejected() {
    let der = vec![0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01];
    let err = cose_signature_from_backend(Algorithm::P256, der).unwrap_err();
    assert_eq!(err, CoseError::InvalidSignatureEncoding);
}

#[test]
fn non_minimal_der_integer_is_rejected() {
    let der = vec![0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01];
    let err = cose_signature_from_backend(Algorithm::P256, der).unwrap_err();
    assert_eq!(err, CoseError::InvalidSignatureEncoding);
}

#[test]
fn direct_signature_encodings_pass_through_unchanged() {
    let fixed = sample_fixed(64);
    assert_eq!(
        cose_signature_from_backend(Algorithm::Ed25519, fixed.clone()).unwrap(),
        fixed
    );
    assert_eq!(
        backend_signature_from_cose(Algorithm::Ed25519, &fixed).unwrap(),
        fixed
    );
}

#[test]
fn direct_signature_encodings_reject_wrong_widths() {
    for (alg, expected_len) in [
        (Algorithm::Ed25519, 64_usize),
        (Algorithm::MlDsa44, 2_420),
        (Algorithm::MlDsa65, 3_309),
        (Algorithm::MlDsa87, 4_627),
    ] {
        for invalid_len in [expected_len - 1, expected_len + 1] {
            let signature = vec![1_u8; invalid_len];
            assert_eq!(
                backend_signature_from_cose(alg, &signature),
                Err(CoseError::InvalidSignatureEncoding),
            );
            assert_eq!(
                cose_signature_from_backend(alg, signature),
                Err(CoseError::InvalidSignatureEncoding),
            );
        }
    }
}

#[test]
fn secp256k1_backend_encoding_remains_opaque() {
    let signature = sample_fixed(64);
    assert_eq!(
        cose_signature_from_backend(Algorithm::Secp256k1, signature.clone()).unwrap(),
        signature
    );
    assert_eq!(
        backend_signature_from_cose(Algorithm::Secp256k1, &signature).unwrap(),
        signature
    );
}
