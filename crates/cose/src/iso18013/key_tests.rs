// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

use ciborium::value::Value;
use zeroize::Zeroizing;

use crate::iso18013::{
    Iso18013CryptoVerifier, Iso18013SignatureAlgorithm, Iso18013SignatureCurve,
    Iso18013SignatureSuite, Iso18013Verifier,
};
use crate::CoseError;

use super::support::{assert_error, encode, hex, key, suite, vectors};

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn exact_cose_key_import_and_provider_matrix() -> Result<(), CoseError> {
    for vector in vectors()? {
        let selected = suite(&vector)?;
        let result = Iso18013CryptoVerifier::from_cose_key(selected, &hex(&vector.cose_key_hex));
        if selected.has_builtin_provider() {
            assert_eq!(result?.suite(), selected);
        } else {
            assert_error(result, CoseError::ProviderUnavailable);
            assert_error(
                Iso18013CryptoVerifier::new(selected, key(&vector)),
                CoseError::ProviderUnavailable,
            );
        }
    }
    Ok(())
}

fn replace_key_field(encoded: &[u8], label: i64, replacement: Value) -> Result<Vec<u8>, CoseError> {
    let mut value: Value = ciborium::de::from_reader(encoded).map_err(|_| CoseError::Cbor)?;
    let Value::Map(entries) = &mut value else {
        return Err(CoseError::InvalidFormat);
    };
    let key = Value::Integer(label.into());
    entries.retain(|(existing, _)| existing != &key);
    entries.push((key, replacement));
    entries.sort_by_key(|(label, _)| encode(label.clone()));
    Ok(encode(value))
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn key_algorithm_curve_type_usage_private_and_point_mismatches_are_typed() -> Result<(), CoseError>
{
    let vectors = vectors()?;
    let vector = vectors.first().ok_or(CoseError::InvalidFormat)?;
    let selected = suite(vector)?;
    let encoded = hex(&vector.cose_key_hex);
    for (label, value) in [
        (1, 1.into()),
        (3, (-9).into()),
        (3, (-35).into()),
        (-1, 256.into()),
        (-1, 2.into()),
        (-2, Value::Bytes(vec![0; 31])),
        (-3, Value::Bytes(vec![0; 32])),
        (-4, Value::Bytes(vec![0; 32])),
        (4, Value::Array(vec![1.into()])),
        (4, Value::Array(vec![3.into()])),
        (4, Value::Array(vec![])),
    ] {
        let invalid = replace_key_field(&encoded, label, value)?;
        assert_error(
            Iso18013CryptoVerifier::from_cose_key(selected, &invalid),
            CoseError::InvalidKeyMaterial,
        );
    }
    let duplicated = replace_key_field(&encoded, 4, Value::Array(vec![2.into(), 2.into()]))?;
    assert_error(
        Iso18013CryptoVerifier::from_cose_key(selected, &duplicated),
        CoseError::DuplicateMapLabel,
    );
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_error(
        Iso18013CryptoVerifier::from_cose_key(selected, &trailing),
        CoseError::Cbor,
    );
    let oversized = vec![0; crate::limits::MAX_COSE_KEY_BYTES + 1];
    assert_error(
        Iso18013CryptoVerifier::from_cose_key(selected, &oversized),
        CoseError::ResourceLimitExceeded,
    );
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn ed25519_key_type_width_coordinate_and_low_order_mismatches_are_typed() -> Result<(), CoseError> {
    let vectors = vectors()?;
    let vector = vectors
        .iter()
        .find(|vector| vector.curve == Iso18013SignatureCurve::Ed25519.identifier())
        .ok_or(CoseError::InvalidFormat)?;
    let selected = suite(vector)?;
    let encoded = hex(&vector.cose_key_hex);
    assert_eq!(
        Iso18013CryptoVerifier::from_cose_key(selected, &encoded)?.suite(),
        selected
    );
    for (label, value) in [
        (1, 2.into()),
        (-2, Value::Bytes(vec![0x11; 31])),
        (-2, Value::Bytes(vec![0x11; 33])),
        (-3, Value::Bytes(vec![0x11; 32])),
        (-3, Value::Bool(false)),
    ] {
        let invalid = replace_key_field(&encoded, label, value)?;
        assert_error(
            Iso18013CryptoVerifier::from_cose_key(selected, &invalid),
            CoseError::InvalidKeyMaterial,
        );
    }
    // The Edwards identity has order one and must not become a verifier.
    let mut identity = vec![0; 32];
    identity[0] = 1;
    assert_error(
        Iso18013CryptoVerifier::new(selected, Zeroizing::new(identity)),
        CoseError::InvalidKeyMaterial,
    );
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn registered_unimplemented_curves_never_alias_a_same_size_nist_curve() -> Result<(), CoseError> {
    for curve in [
        Iso18013SignatureCurve::BrainpoolP256r1,
        Iso18013SignatureCurve::BrainpoolP320r1,
        Iso18013SignatureCurve::BrainpoolP384r1,
        Iso18013SignatureCurve::BrainpoolP512r1,
        Iso18013SignatureCurve::Ed448,
    ] {
        let algorithm = if curve == Iso18013SignatureCurve::Ed448 {
            Iso18013SignatureAlgorithm::EdDsa
        } else {
            Iso18013SignatureAlgorithm::Es256
        };
        let selected = Iso18013SignatureSuite::new(algorithm, curve)?;
        assert!(!selected.has_builtin_provider());
        assert_error(
            Iso18013CryptoVerifier::new(selected, Zeroizing::new(vec![0; 133])),
            CoseError::ProviderUnavailable,
        );
        assert_eq!(
            Iso18013SignatureCurve::from_identifier(curve.identifier())?,
            curve
        );
    }
    for identifier in [4, 5, 8] {
        let recognized = Iso18013SignatureCurve::from_identifier(identifier)?;
        assert_error(
            Iso18013SignatureSuite::new(Iso18013SignatureAlgorithm::Es256, recognized),
            CoseError::UnsupportedAlgorithm,
        );
    }
    for identifier in [0, 255, 260, -65537] {
        assert_error(
            Iso18013SignatureCurve::from_identifier(identifier),
            CoseError::UnsupportedAlgorithm,
        );
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn compressed_coordinates_and_absent_optional_algorithm_import() -> Result<(), CoseError> {
    for vector in vectors()?.iter().filter(|vector| vector.curve <= 3) {
        let selected = suite(vector)?;
        if !selected.has_builtin_provider() {
            continue;
        }
        let raw = hex(&vector.public_key_hex);
        let odd = raw.last().is_some_and(|value| value & 1 == 1);
        let encoded = replace_key_field(&hex(&vector.cose_key_hex), -3, Value::Bool(odd))?;
        Iso18013CryptoVerifier::from_cose_key(selected, &encoded)?;
        let mut value: Value =
            ciborium::de::from_reader(encoded.as_slice()).map_err(|_| CoseError::Cbor)?;
        let Value::Map(entries) = &mut value else {
            return Err(CoseError::InvalidFormat);
        };
        entries.retain(|(label, _)| label != &Value::Integer(3.into()));
        Iso18013CryptoVerifier::from_cose_key(selected, &encode(value))?;
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn iso_key_import_preserves_permitted_unsorted_map_encodings() -> Result<(), CoseError> {
    for vector in vectors()? {
        let selected = suite(&vector)?;
        if !selected.has_builtin_provider() {
            continue;
        }
        let encoded = hex(&vector.cose_key_hex);
        let mut value: Value =
            ciborium::de::from_reader(encoded.as_slice()).map_err(|_| CoseError::Cbor)?;
        let Value::Map(entries) = &mut value else {
            return Err(CoseError::InvalidFormat);
        };
        entries.reverse();
        Iso18013CryptoVerifier::from_cose_key(selected, &encode(value))?;
    }
    Ok(())
}
