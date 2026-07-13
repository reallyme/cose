#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Interop-facing verification behavior: externally-encoded COSE_Sign1 input
//! that differs from this crate's own output encoding but is valid per
//! RFC 9052 must still verify.

use std::io::Cursor;

use ciborium::{ser::into_writer, value::Value};
use coset::{CborSerializable, CoseSign1};
use reallyme_cose::{cose_sign1, cose_verify1, CoseError};
use reallyme_crypto::core::Algorithm;
use reallyme_crypto::dispatch::sign;

use crate::support::{gen_ed25519, gen_p256, sample_payload, test_kid};

fn encode_value(value: &Value) -> Vec<u8> {
    let mut encoded = Vec::new();
    into_writer(value, Cursor::new(&mut encoded)).expect("test CBOR encoding must succeed");
    encoded
}

/// Hand-assemble a COSE_Sign1 whose protected header map places `kid` before
/// `alg` — a valid encoding this crate would never emit itself.
fn build_reordered_header_sign1(key: &crate::support::TestKey, payload: &[u8]) -> Vec<u8> {
    let protected_map = Value::Map(vec![
        (Value::Integer(4.into()), Value::Bytes(test_kid().to_vec())),
        (Value::Integer(1.into()), Value::Integer((-8).into())),
    ]);
    let protected_bytes = encode_value(&protected_map);

    let sig_structure = Value::Array(vec![
        Value::Text("Signature1".to_string()),
        Value::Bytes(protected_bytes.clone()),
        Value::Bytes(Vec::new()),
        Value::Bytes(payload.to_vec()),
    ]);
    let to_sign = encode_value(&sig_structure);
    let signature = sign(Algorithm::Ed25519, &key.private, &to_sign).unwrap();

    let cose = Value::Array(vec![
        Value::Bytes(protected_bytes),
        Value::Map(Vec::new()),
        Value::Bytes(payload.to_vec()),
        Value::Bytes(signature),
    ]);
    encode_value(&cose)
}

#[test]
fn verify_accepts_non_canonical_protected_header_order() {
    let key = gen_ed25519();
    let payload = sample_payload();
    let cose_bytes = build_reordered_header_sign1(&key, &payload);

    let verified = cose_verify1(&cose_bytes, |kid| {
        (kid == test_kid()).then(|| key.public.clone())
    })
    .expect("reordered protected header must verify over received bytes");

    assert_eq!(verified, payload);
}

#[test]
fn verify_accepts_cose_sign1_tag_18_root() {
    let key = gen_ed25519();
    let payload = sample_payload();
    let untagged = cose_sign1(key.alg, &payload, &key.private, Some(test_kid())).unwrap();

    let decoded: Value =
        ciborium::de::from_reader(Cursor::new(untagged.as_slice())).expect("must decode");
    let tagged = encode_value(&Value::Tag(18, Box::new(decoded)));

    let verified = cose_verify1(&tagged, |kid| {
        (kid == test_kid()).then(|| key.public.clone())
    })
    .expect("tag 18 COSE_Sign1 must verify");

    assert_eq!(verified, payload);
}

#[test]
fn ecdsa_der_encoded_signature_is_rejected() {
    let key = gen_p256();
    let payload = sample_payload();
    let cose_bytes = cose_sign1(key.alg, &payload, &key.private, Some(test_kid())).unwrap();

    let mut cose = CoseSign1::from_slice(&cose_bytes).unwrap();
    cose.signature = raw_to_der(&cose.signature);
    let mutated = cose.to_vec().unwrap();

    let err = cose_verify1(&mutated, |kid| {
        (kid == test_kid()).then(|| key.public.clone())
    })
    .expect_err("DER-encoded ECDSA signature must be rejected");

    assert_eq!(err, CoseError::InvalidSignature);
}

#[test]
fn ecdsa_signature_is_fixed_width_r_s() {
    let key = gen_p256();
    let payload = sample_payload();
    let cose_bytes = cose_sign1(key.alg, &payload, &key.private, Some(test_kid())).unwrap();

    let cose = CoseSign1::from_slice(&cose_bytes).unwrap();
    assert_eq!(cose.signature.len(), 64, "ES256 must be raw r||s");
}

/// Minimal DER ECDSA-Sig-Value encoder for negative-path fixtures.
fn raw_to_der(raw: &[u8]) -> Vec<u8> {
    let half = raw.len() / 2;
    let encode_int = |scalar: &[u8]| {
        let trimmed: Vec<u8> = {
            let start = scalar.iter().position(|b| *b != 0).unwrap_or(scalar.len());
            scalar[start..].to_vec()
        };
        let mut body = Vec::new();
        if trimmed.first().is_some_and(|b| b & 0x80 != 0) {
            body.push(0);
        }
        body.extend_from_slice(&trimmed);
        let mut out = vec![0x02, u8::try_from(body.len()).unwrap()];
        out.extend_from_slice(&body);
        out
    };
    let r = encode_int(&raw[..half]);
    let s = encode_int(&raw[half..]);
    let mut der = vec![0x30, u8::try_from(r.len() + s.len()).unwrap()];
    der.extend_from_slice(&r);
    der.extend_from_slice(&s);
    der
}
