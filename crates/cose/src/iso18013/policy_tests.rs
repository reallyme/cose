// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

use std::cell::Cell;

use ciborium::value::Value;

use crate::iso18013::{
    cose_verify_iso18013_sign1, Iso18013CryptoVerifier, Iso18013Sign1Content,
    Iso18013SignatureAlgorithm, Iso18013SignatureCurve, Iso18013SignatureSuite, Iso18013Verifier,
};
use crate::{CoseError, CoseSignatureAlgorithm};

use super::support::{assert_error, encode, envelope, hex, key, request, suite, vectors};

struct AttemptVerifier {
    suite: Iso18013SignatureSuite,
    calls: Cell<usize>,
}

impl Iso18013Verifier for AttemptVerifier {
    fn suite(&self) -> Iso18013SignatureSuite {
        self.suite
    }
    fn verify(&self, _: &[u8], _: &[u8]) -> Result<(), CoseError> {
        self.calls.set(self.calls.get() + 1);
        Err(CoseError::ProviderUnavailable)
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn registrations_and_curve_families_remain_distinct_and_opt_in() -> Result<(), CoseError> {
    for identifier in [-35, -36, -8] {
        assert_error(
            CoseSignatureAlgorithm::from_identifier(identifier)?.crypto_algorithm(),
            CoseError::UnsupportedAlgorithm,
        );
        assert_eq!(
            Iso18013SignatureAlgorithm::from_identifier(identifier)?.identifier(),
            identifier
        );
    }
    for identifier in [-9, -19, -51, -52] {
        assert_error(
            Iso18013SignatureSuite::new(
                Iso18013SignatureAlgorithm::from_identifier(identifier)?,
                Iso18013SignatureCurve::P256,
            ),
            CoseError::UnsupportedAlgorithm,
        );
        let selected = crate::containers::SignatureSuite::modern(
            CoseSignatureAlgorithm::from_identifier(identifier)?,
        )?;
        let verifier = AttemptVerifier {
            suite: selected,
            calls: Cell::new(0),
        };
        let encoded = envelope(
            &encode(Value::Map(vec![(1.into(), identifier.into())])),
            Value::Map(vec![]),
            None,
            &vec![1; selected.curve().signature_length()?],
        );
        assert_error(
            cose_verify_iso18013_sign1(
                request(
                    &encoded,
                    Iso18013Sign1Content::ReaderDetached(b"reader"),
                    &[selected],
                ),
                &verifier,
            ),
            CoseError::UnsupportedAlgorithm,
        );
        assert_eq!(verifier.calls.get(), 0);
    }
    for algorithm in [
        Iso18013SignatureAlgorithm::Es256,
        Iso18013SignatureAlgorithm::Es384,
        Iso18013SignatureAlgorithm::Es512,
    ] {
        assert_error(
            Iso18013SignatureSuite::new(algorithm, Iso18013SignatureCurve::Ed25519),
            CoseError::UnsupportedAlgorithm,
        );
        for curve in [
            Iso18013SignatureCurve::P256,
            Iso18013SignatureCurve::P384,
            Iso18013SignatureCurve::P521,
        ] {
            assert_eq!(
                Iso18013SignatureSuite::new(algorithm, curve)?.curve(),
                curve
            );
        }
    }
    assert_error(
        Iso18013SignatureSuite::new(
            Iso18013SignatureAlgorithm::EdDsa,
            Iso18013SignatureCurve::P256,
        ),
        CoseError::UnsupportedAlgorithm,
    );
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn allowlists_and_algorithm_key_mismatches_fail_before_provider_execution() -> Result<(), CoseError>
{
    let vectors = vectors()?;
    let vector = vectors.first().ok_or(CoseError::InvalidFormat)?;
    let selected = suite(vector)?;
    let verifier = AttemptVerifier {
        suite: selected,
        calls: Cell::new(0),
    };
    let encoded = hex(&vector.detached_hex);
    let payload = hex(&vector.payload_hex);
    let other = Iso18013SignatureSuite::new(
        selected.algorithm(),
        Iso18013SignatureCurve::BrainpoolP256r1,
    )?;
    for allowlist in [&[][..], &[other][..]] {
        assert_error(
            cose_verify_iso18013_sign1(
                request(
                    &encoded,
                    Iso18013Sign1Content::DeviceDetached(&payload),
                    allowlist,
                ),
                &verifier,
            ),
            CoseError::UnsupportedAlgorithm,
        );
    }
    let changed = envelope(
        &encode(Value::Map(vec![(1.into(), (-35).into())])),
        Value::Map(vec![]),
        None,
        &hex(&vector.signature_hex),
    );
    assert_error(
        cose_verify_iso18013_sign1(
            request(
                &changed,
                Iso18013Sign1Content::DeviceDetached(&payload),
                &[selected],
            ),
            &verifier,
        ),
        CoseError::InvalidKeyMaterial,
    );
    assert_eq!(verifier.calls.get(), 0);
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn role_shapes_tags_and_payload_limits_are_enforced() -> Result<(), CoseError> {
    let vectors = vectors()?;
    let vector = vectors.first().ok_or(CoseError::InvalidFormat)?;
    let selected = suite(vector)?;
    let allowed = [selected];
    let verifier = Iso18013CryptoVerifier::new(selected, key(vector))?;
    let attached = hex(&vector.attached_hex);
    let detached = hex(&vector.detached_hex);
    let payload = hex(&vector.payload_hex);
    assert_error(
        cose_verify_iso18013_sign1(
            request(&detached, Iso18013Sign1Content::IssuerAttached, &allowed),
            &verifier,
        ),
        CoseError::MissingPayload,
    );
    for content in [
        Iso18013Sign1Content::DeviceDetached(payload.as_slice()),
        Iso18013Sign1Content::ReaderDetached(payload.as_slice()),
    ] {
        assert_error(
            cose_verify_iso18013_sign1(request(&attached, content, &allowed), &verifier),
            CoseError::InvalidFormat,
        );
    }
    let mut tagged = vec![0xd2];
    tagged.extend_from_slice(&detached);
    assert_error(
        cose_verify_iso18013_sign1(
            request(
                &tagged,
                Iso18013Sign1Content::DeviceDetached(&payload),
                &allowed,
            ),
            &verifier,
        ),
        CoseError::InvalidFormat,
    );
    let mut trailing = detached.clone();
    trailing.push(0);
    assert_error(
        cose_verify_iso18013_sign1(
            request(
                &trailing,
                Iso18013Sign1Content::DeviceDetached(&payload),
                &allowed,
            ),
            &verifier,
        ),
        CoseError::Cbor,
    );
    let mut limited = request(
        &detached,
        Iso18013Sign1Content::DeviceDetached(&payload),
        &allowed,
    );
    limited.limits.payload_bytes = payload.len() - 1;
    assert_error(
        cose_verify_iso18013_sign1(limited, &verifier),
        CoseError::ResourceLimitExceeded,
    );
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn duplicate_unprotected_and_critical_headers_fail_closed() -> Result<(), CoseError> {
    let vectors = vectors()?;
    let vector = vectors.first().ok_or(CoseError::InvalidFormat)?;
    let selected = suite(vector)?;
    let allowed = [selected];
    let verifier = AttemptVerifier {
        suite: selected,
        calls: Cell::new(0),
    };
    let payload = hex(&vector.payload_hex);
    for (protected, unprotected, error) in [
        (
            hex("a201260126"),
            Value::Map(vec![]),
            CoseError::DuplicateMapLabel,
        ),
        (
            hex("a10126"),
            Value::Map(vec![(1.into(), (-7).into())]),
            CoseError::DuplicateMapLabel,
        ),
        (
            hex("a1044161"),
            Value::Map(vec![(1.into(), (-7).into())]),
            CoseError::UnprotectedHeaderNotAllowed,
        ),
        (
            hex("a201260281182a"),
            Value::Map(vec![]),
            CoseError::UnsupportedCriticalHeader,
        ),
        (
            hex("a10126"),
            Value::Map(vec![(2.into(), Value::Array(vec![42.into()]))]),
            CoseError::UnsupportedCriticalHeader,
        ),
        (
            hex("a1180126"),
            Value::Map(vec![]),
            CoseError::NonCanonicalCbor,
        ),
        (
            hex("a10126"),
            Value::Map(vec![(
                33.into(),
                Value::Array(vec![Value::Bytes(vec![1]), Value::Null]),
            )]),
            CoseError::InvalidFormat,
        ),
    ] {
        let encoded = envelope(&protected, unprotected, None, &hex(&vector.signature_hex));
        assert_error(
            cose_verify_iso18013_sign1(
                request(
                    &encoded,
                    Iso18013Sign1Content::DeviceDetached(&payload),
                    &allowed,
                ),
                &verifier,
            ),
            error,
        );
    }
    assert_eq!(verifier.calls.get(), 0);
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn empty_protected_missing_and_non_integer_algorithms_fail_closed() -> Result<(), CoseError> {
    let vectors = vectors()?;
    let vector = vectors.first().ok_or(CoseError::InvalidFormat)?;
    let selected = suite(vector)?;
    let allowed = [selected];
    let verifier = AttemptVerifier {
        suite: selected,
        calls: Cell::new(0),
    };
    let payload = hex(&vector.payload_hex);
    for protected in [
        Vec::new(),
        hex("a1044161"),
        encode(Value::Map(vec![(1.into(), Value::Text("ES256".into()))])),
    ] {
        let encoded = envelope(
            &protected,
            Value::Map(vec![]),
            None,
            &hex(&vector.signature_hex),
        );
        assert_error(
            cose_verify_iso18013_sign1(
                request(
                    &encoded,
                    Iso18013Sign1Content::DeviceDetached(&payload),
                    &allowed,
                ),
                &verifier,
            ),
            CoseError::UnsupportedAlgorithm,
        );
    }
    assert_eq!(verifier.calls.get(), 0);
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn byte_limits_and_signature_lengths_fail_before_provider_execution() -> Result<(), CoseError> {
    let vectors = vectors()?;
    let vector = vectors.first().ok_or(CoseError::InvalidFormat)?;
    let selected = suite(vector)?;
    let verifier = AttemptVerifier {
        suite: selected,
        calls: Cell::new(0),
    };
    let allowed = [selected];
    let protected = hex(&vector.protected_hex);
    let payload = hex(&vector.payload_hex);
    for length in [0, 1, 63, 65, 132] {
        let encoded = envelope(&protected, Value::Map(vec![]), None, &vec![0; length]);
        assert_error(
            cose_verify_iso18013_sign1(
                request(
                    &encoded,
                    Iso18013Sign1Content::DeviceDetached(&payload),
                    &allowed,
                ),
                &verifier,
            ),
            CoseError::InvalidSignatureEncoding,
        );
    }
    let oversized_encoded = vec![0; crate::limits::MAX_COSE_SIGN1_BYTES + 1];
    let oversized_payload = vec![0; crate::limits::MAX_DETACHED_PAYLOAD_BYTES + 1];
    for (encoded, payload) in [
        (oversized_encoded.as_slice(), &[][..]),
        (&[][..], oversized_payload.as_slice()),
    ] {
        let mut input = request(
            encoded,
            Iso18013Sign1Content::DeviceDetached(payload),
            &allowed,
        );
        input.limits.encoded_bytes = usize::MAX;
        input.limits.payload_bytes = usize::MAX;
        assert_error(
            cose_verify_iso18013_sign1(input, &verifier),
            CoseError::ResourceLimitExceeded,
        );
    }
    let detached = hex(&vector.detached_hex);
    for end in 0..detached.len() {
        assert_error(
            cose_verify_iso18013_sign1(
                request(
                    &detached[..end],
                    Iso18013Sign1Content::DeviceDetached(&payload),
                    &allowed,
                ),
                &verifier,
            ),
            CoseError::Cbor,
        );
    }
    assert_eq!(verifier.calls.get(), 0);
    Ok(())
}
