// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::support::{assert_error, hex, int, map, value};
use crate::containers::{
    inspect_peer_key, signature_to_cose, ContainerError, ContainerErrorReason as Reason,
    CryptoPeerKeyValidator, CryptoVerificationKey, OptionalKeyPolicy, PeerCurve, PeerKeyUsage,
    PeerPointEncoding, SignatureEncoding, SignatureSuite,
};
use crate::iso18013::{Iso18013SignatureAlgorithm as Alg, Iso18013SignatureCurve as Curve};
use ciborium::value::Value;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Vectors {
    schema: String,
    cases: Vec<Case>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    curve: i64,
    algorithm: i64,
    key: String,
    compressed: String,
    public: String,
    der: String,
    signature: String,
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn independent_all_eleven_key_mappings_preserve_original_representation_and_fail_closed(
) -> Result<(), ContainerError> {
    let vectors: Vectors =
        serde_json::from_str(include_str!("../../tests/fixtures/peer-keys.json"))
            .map_err(|_| Reason::Malformed)?;
    assert_eq!(vectors.schema, "reallyme.cose.peer-keys.v1");
    assert_eq!(vectors.cases.len(), 11);
    for case in vectors.cases {
        let curve = PeerCurve::from_identifier(case.curve)?;
        let usage = if case.algorithm == 0 {
            PeerKeyUsage::Agreement
        } else {
            PeerKeyUsage::Signature(SignatureSuite::iso(
                Alg::from_identifier(case.algorithm)?,
                Curve::from_identifier(case.curve)?,
            )?)
        };
        let encoded = hex(&case.key);
        let inspected = inspect_peer_key(&encoded, usage, OptionalKeyPolicy::Cose)?;
        assert_eq!(inspected.original_cose_key(), encoded);
        assert_eq!(inspected.public_material(), hex(&case.public));
        assert_eq!(inspected.curve(), curve);
        assert_eq!(inspected.usage(), usage);
        if !case.compressed.is_empty() {
            let compressed = hex(&case.compressed);
            let key = inspect_peer_key(&compressed, usage, OptionalKeyPolicy::Cose)?;
            assert_eq!(key.point_encoding(), PeerPointEncoding::Ec2YSign);
            assert_eq!(key.original_cose_key(), compressed);
            if matches!(case.curve, 1..=3) {
                key.validate(&CryptoPeerKeyValidator)?;
            }
        }
        if matches!(case.curve, 1..=4 | 6) {
            inspected.validate(&CryptoPeerKeyValidator)?;
        } else {
            assert_error(
                inspected.validate(&CryptoPeerKeyValidator),
                Reason::Provider,
            );
        }
        if let PeerKeyUsage::Signature(suite) = usage {
            if !matches!(case.curve, 1..=3 | 6) {
                assert_error(
                    CryptoVerificationKey::new(
                        suite,
                        zeroize::Zeroizing::new(hex(&case.public)),
                        [0; 32],
                    ),
                    Reason::Provider,
                );
            }
            if !case.signature.is_empty() {
                let raw = hex(&case.signature);
                crate::containers::validate_cose_signature(suite.curve(), &raw)?;
                let encoding = if case.der.is_empty() {
                    SignatureEncoding::EdDsa
                } else {
                    SignatureEncoding::EcdsaDer
                };
                let provider = if case.der.is_empty() {
                    raw.clone()
                } else {
                    hex(&case.der)
                };
                assert_eq!(*signature_to_cose(suite.curve(), encoding, &provider)?, raw);
            }
        }
    }
    assert_eq!(PeerCurve::from_identifier(5)?.okp_bytes(), Some(56));
    assert_eq!(PeerCurve::from_identifier(7)?.okp_bytes(), Some(57));
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn agreement_hpke_do_not_require_or_invent_a_signing_algorithm() -> Result<(), ContainerError> {
    let fixtures: Vectors =
        serde_json::from_str(include_str!("../../tests/fixtures/peer-keys.json"))
            .map_err(|_| Reason::Malformed)?;
    let encoded = hex(&fixtures.cases[0].key);
    for usage in [PeerKeyUsage::Agreement, PeerKeyUsage::HpkeRecipient] {
        let validated = inspect_peer_key(&encoded, usage, OptionalKeyPolicy::Cose)?
            .validate(&CryptoPeerKeyValidator)?;
        assert_eq!(validated.public_view().usage(), usage);
        assert_eq!(
            validated.public_view().point_encoding(),
            PeerPointEncoding::Ec2Coordinates
        );
        assert_eq!(validated.public_view().original_cose_key(), encoded);
    }
    let ed = fixtures
        .cases
        .iter()
        .find(|v| v.curve == 7)
        .ok_or(Reason::Key)?;
    assert_error(
        inspect_peer_key(
            &hex(&ed.key),
            PeerKeyUsage::Agreement,
            OptionalKeyPolicy::Cose,
        ),
        Reason::Key,
    );
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn optional_parameter_policy_private_material_and_usage_mismatches_are_explicit(
) -> Result<(), ContainerError> {
    let fixtures: Vectors =
        serde_json::from_str(include_str!("../../tests/fixtures/peer-keys.json"))
            .map_err(|_| Reason::Malformed)?;
    let Value::Map(base) = value(&hex(&fixtures.cases[0].key)) else {
        return Err(Reason::Malformed.into());
    };
    for (label, parameter) in [
        (3, int(-8)),
        (4, Value::Array(vec![int(1)])),
        (99, Value::Bytes(vec![1])),
    ] {
        let mut params = base.clone();
        params.push((int(label), parameter));
        let encoded = map(params);
        assert_error(
            inspect_peer_key(&encoded, PeerKeyUsage::Agreement, OptionalKeyPolicy::Cose),
            Reason::Key,
        );
        inspect_peer_key(
            &encoded,
            PeerKeyUsage::Agreement,
            OptionalKeyPolicy::IsoPeer,
        )?
        .validate(&CryptoPeerKeyValidator)?;
    }
    for private_label in [-4, -5] {
        let mut params = base.clone();
        params.push((int(private_label), Value::Bytes(vec![0x42; 32])));
        assert_error(
            inspect_peer_key(
                &map(params),
                PeerKeyUsage::Agreement,
                OptionalKeyPolicy::IsoPeer,
            ),
            Reason::Key,
        );
    }
    let suite = SignatureSuite::iso(Alg::Es384, Curve::P384)?;
    assert_error(
        inspect_peer_key(
            &hex(&fixtures.cases[0].key),
            PeerKeyUsage::Signature(suite),
            OptionalKeyPolicy::Cose,
        ),
        Reason::Key,
    );
    assert_error(
        SignatureSuite::iso(Alg::Es256, Curve::P384),
        Reason::Algorithm,
    );
    assert_error(
        SignatureSuite::iso(Alg::EdDsa, Curve::P256),
        Reason::Algorithm,
    );
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn malformed_private_duplicate_wrong_type_width_trailing_and_key_limits_fail(
) -> Result<(), ContainerError> {
    let fixtures: Vectors =
        serde_json::from_str(include_str!("../../tests/fixtures/peer-keys.json"))
            .map_err(|_| Reason::Malformed)?;
    for case in &fixtures.cases {
        let encoded = hex(&case.key);
        let usage = if case.algorithm == 0 {
            PeerKeyUsage::Agreement
        } else {
            PeerKeyUsage::Signature(SignatureSuite::iso(
                Alg::from_identifier(case.algorithm)?,
                Curve::from_identifier(case.curve)?,
            )?)
        };
        for end in 0..encoded.len() {
            assert!(inspect_peer_key(&encoded[..end], usage, OptionalKeyPolicy::Cose).is_err());
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_error(
            inspect_peer_key(&trailing, usage, OptionalKeyPolicy::Cose),
            Reason::Malformed,
        );
        let Value::Map(base) = value(&encoded) else {
            return Err(Reason::Malformed.into());
        };
        let mut duplicate = base.clone();
        duplicate.push((int(1), int(2)));
        assert_error(
            inspect_peer_key(&map(duplicate), usage, OptionalKeyPolicy::Cose),
            Reason::Duplicate,
        );
        let mut wrong = base.clone();
        for (label, value) in &mut wrong {
            if *label == int(-2) {
                *value = Value::Bytes(vec![1; 3]);
            }
        }
        assert_error(
            inspect_peer_key(&map(wrong), usage, OptionalKeyPolicy::Cose),
            Reason::Key,
        );
        let mut wrong = base;
        for (label, value) in &mut wrong {
            if *label == int(1) {
                *value = int(
                    if case.curve == 4 || case.curve == 5 || case.curve == 6 || case.curve == 7 {
                        2
                    } else {
                        1
                    },
                );
            }
        }
        assert_error(
            inspect_peer_key(&map(wrong), usage, OptionalKeyPolicy::Cose),
            Reason::Key,
        );
    }
    let Value::Map(mut maximum) = value(&hex(&fixtures.cases[0].key)) else {
        return Err(Reason::Malformed.into());
    };
    maximum.push((int(99), Value::Bytes(Vec::new())));
    let overhead = map(maximum.clone()).len() + 2;
    if let Some((_, value)) = maximum.last_mut() {
        *value = Value::Bytes(vec![0x42; crate::limits::MAX_COSE_KEY_BYTES - overhead]);
    }
    let encoded = map(maximum);
    assert_eq!(encoded.len(), crate::limits::MAX_COSE_KEY_BYTES);
    inspect_peer_key(
        &encoded,
        PeerKeyUsage::HpkeRecipient,
        OptionalKeyPolicy::IsoPeer,
    )?
    .validate(&CryptoPeerKeyValidator)?;
    let too_large = vec![0; crate::limits::MAX_COSE_KEY_BYTES + 1];
    assert_error(
        inspect_peer_key(
            &too_large,
            PeerKeyUsage::Agreement,
            OptionalKeyPolicy::IsoPeer,
        ),
        Reason::Limit,
    );
    let wrong = map(vec![
        (int(1), int(2)),
        (int(-1), int(1)),
        (int(-2), Value::Bytes(vec![0; 32])),
        (int(-3), Value::Bytes(vec![0; 32])),
    ]);
    assert_error(
        inspect_peer_key(&wrong, PeerKeyUsage::Agreement, OptionalKeyPolicy::Cose)?
            .validate(&CryptoPeerKeyValidator),
        Reason::Key,
    );
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn floating_point_values_cannot_substitute_for_ec2_y_booleans() -> Result<(), ContainerError> {
    let fixtures: Vectors =
        serde_json::from_str(include_str!("../../tests/fixtures/peer-keys.json"))
            .map_err(|_| Reason::Malformed)?;
    let case = fixtures
        .cases
        .iter()
        .find(|case| case.curve == 1)
        .ok_or(Reason::Key)?;
    let Value::Map(base) = value(&hex(&case.key)) else {
        return Err(Reason::Malformed.into());
    };
    for parity in [false, true] {
        let mut parameters = base.clone();
        let y = parameters
            .iter_mut()
            .find(|(label, _)| *label == int(-3))
            .ok_or(Reason::Key)?;
        y.1 = Value::Bool(parity);
        let encoded = map(parameters.clone());
        let key = inspect_peer_key(&encoded, PeerKeyUsage::Agreement, OptionalKeyPolicy::Cose)?;
        assert_eq!(key.point_encoding(), PeerPointEncoding::Ec2YSign);
        for value in [
            half::f16::from_bits(if parity { 21 } else { 20 }).to_f64(),
            f64::from(f32::from_bits(if parity { 21 } else { 20 })),
            f64::from_bits(if parity { 21 } else { 20 }),
        ] {
            let mut parameters = parameters.clone();
            let y = parameters
                .iter_mut()
                .find(|(label, _)| *label == int(-3))
                .ok_or(Reason::Key)?;
            y.1 = Value::Float(value);
            let encoded = map(parameters);
            crate::containers::validate_preferred_cbor(&encoded)?;
            assert_error(
                inspect_peer_key(&encoded, PeerKeyUsage::Agreement, OptionalKeyPolicy::Cose),
                Reason::Key,
            );
        }
    }
    Ok(())
}
