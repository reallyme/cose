// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

use ciborium::value::Value;
use zeroize::Zeroizing;

use crate::iso18013::{cose_verify_iso18013_sign1, Iso18013CryptoVerifier, Iso18013Sign1Content};
use crate::{Algorithm, CoseError};

use super::support::{assert_error, encode, envelope, key, request, suite, vectors};

fn sign_case(protected: &[u8], payload: &[u8], aad: &[u8]) -> Result<Vec<u8>, CoseError> {
    // Ciborium is the independent structure encoder for these boundary tests;
    // production crypto remains behind reallyme-crypto even in this helper.
    let structure = Zeroizing::new(encode(Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(protected.to_vec()),
        Value::Bytes(aad.to_vec()),
        Value::Bytes(payload.to_vec()),
    ])));
    let mut private = Zeroizing::new(vec![0; 32]);
    let last = private.last_mut().ok_or(CoseError::InvalidKeyMaterial)?;
    *last = 1;
    let signature = reallyme_crypto::dispatch::sign(Algorithm::P256, &private, &structure)
        .map_err(|_| CoseError::Crypto)?;
    let signature = p256::ecdsa::Signature::from_der(&signature)
        .map_err(|_| CoseError::InvalidSignatureEncoding)?;
    Ok(signature.to_bytes().to_vec())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn maximum_detached_payload_and_exact_application_limits_verify() -> Result<(), CoseError> {
    let vectors = vectors()?;
    let vector = vectors.first().ok_or(CoseError::InvalidFormat)?;
    let selected = suite(vector)?;
    let allowed = [selected];
    let verifier = Iso18013CryptoVerifier::new(selected, key(vector))?;
    let payload = vec![0x21; crate::limits::MAX_DETACHED_PAYLOAD_BYTES];
    let protected = encode(Value::Map(vec![(1.into(), (-7).into())]));
    let signature = sign_case(&protected, &payload, &[])?;
    let encoded = envelope(&protected, Value::Map(vec![]), None, &signature);
    let mut input = request(
        &encoded,
        Iso18013Sign1Content::DeviceDetached(&payload),
        &allowed,
    );
    input.limits.max_encoded_bytes = encoded.len();
    input.limits.max_payload_bytes = payload.len();
    let verified = cose_verify_iso18013_sign1(input, &verifier)?;
    assert_eq!(verified.protected_key_id(), None);
    let mut input = request(
        &encoded,
        Iso18013Sign1Content::DeviceDetached(&payload),
        &allowed,
    );
    input.limits.max_encoded_bytes = encoded.len() - 1;
    assert_error(
        cose_verify_iso18013_sign1(input, &verifier),
        CoseError::ResourceLimitExceeded,
    );
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn unprotected_hints_are_not_authenticated_and_nonempty_aad_cannot_verify() -> Result<(), CoseError>
{
    let vectors = vectors()?;
    let vector = vectors.first().ok_or(CoseError::InvalidFormat)?;
    let selected = suite(vector)?;
    let allowed = [selected];
    let verifier = Iso18013CryptoVerifier::new(selected, key(vector))?;
    let payload = b"synthetic";
    let protected = encode(Value::Map(vec![(1.into(), (-7).into())]));
    let signature = sign_case(&protected, payload, &[])?;
    for hint in [b"first".as_slice(), b"changed".as_slice()] {
        let unprotected = Value::Map(vec![
            (4.into(), Value::Bytes(hint.to_vec())),
            (33.into(), Value::Bytes(vec![1])),
        ]);
        let encoded = envelope(&protected, unprotected, None, &signature);
        let verified = cose_verify_iso18013_sign1(
            request(
                &encoded,
                Iso18013Sign1Content::ReaderDetached(payload),
                &allowed,
            ),
            &verifier,
        )?;
        assert_eq!(verified.protected_key_id(), None);
    }
    let signature = sign_case(&protected, payload, b"nonempty aad")?;
    let encoded = envelope(&protected, Value::Map(vec![]), None, &signature);
    assert_error(
        cose_verify_iso18013_sign1(
            request(
                &encoded,
                Iso18013Sign1Content::ReaderDetached(payload),
                &allowed,
            ),
            &verifier,
        ),
        CoseError::InvalidSignature,
    );
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn common_header_values_are_checked_without_processing_unsupported_security_semantics(
) -> Result<(), CoseError> {
    for value in [Value::from(0), Value::Text("application/cbor".into())] {
        let protected = vec![(1.into(), (-7).into()), (3.into(), value)];
        let (algorithm, kid) = super::super::validate_headers::validate(&protected, &[])?;
        assert_eq!(algorithm.identifier(), -7);
        assert_eq!(kid, None);
    }
    for (label, value) in [
        (3, Value::Null),
        (3, Value::Text("invalid".into())),
        (3, Value::Text("application/*".into())),
        (5, Value::Bytes(vec![])),
        (7, Value::Array(vec![])),
    ] {
        let protected = vec![(1.into(), (-7).into()), (label.into(), value)];
        assert_error(
            super::super::validate_headers::validate(&protected, &[]),
            CoseError::InvalidFormat,
        );
    }
    Ok(())
}
