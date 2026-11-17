// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::support::{codec_parity, hex, reason, success};
use crate::api::contract::{
    __buffa::oneof::{cose_operation_request::Operation, cose_operation_result::Result as Branch},
    CoseKeyBytesRequest,
};
use crate::zeroize_coset::SensitiveCborValue;
use crate::{
    cose_key_from_private_bytes, cose_key_from_public_bytes, cose_key_from_signature_public_bytes,
    cose_key_from_slice, cose_key_to_multikey, cose_key_to_public_vec, cose_key_to_vec,
    derive_kid_from_cose_key_public, Algorithm, CoseError, CoseSignatureAlgorithm,
};
use ciborium::value::Value;
use zeroize::Zeroizing;

fn project(encoded: &[u8]) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    let key = cose_key_from_slice(encoded)?;
    let native = cose_key_to_public_vec(&key)?;
    let response = success(codec_parity(Operation::KeyToPublicVec(Box::new(
        CoseKeyBytesRequest::default().with_cose_key(encoded.to_vec()),
    )))?);
    let Branch::KeyToPublicVec(output) = &response else {
        return Err(CoseError::InvalidFormat);
    };
    assert!(output.key_bytes.as_slice() == native.as_slice());
    assert_eq!(
        output.signature_algorithm.as_known(),
        Some(crate::key::cose_key_signature_algorithm(&key)?.map_or(
            crate::api::contract::CoseSignatureAlgorithm::Unspecified,
            crate::api::contract::CoseSignatureAlgorithm::from,
        ))
    );
    Ok(native)
}

fn decorated(
    encoded: &[u8],
    signature: bool,
    private: bool,
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    let mut value = SensitiveCborValue::decode_cose_key(encoded)?;
    let Value::Map(params) = value.value_mut() else {
        return Err(CoseError::InvalidFormat);
    };
    let position = params
        .iter()
        .position(|(label, _)| matches!(label, Value::Integer(v) if i128::from(*v) < 0))
        .ok_or(CoseError::InvalidFormat)?;
    let operations = if signature {
        if private {
            vec![1, 2]
        } else {
            vec![2]
        }
    } else {
        vec![7, 8]
    };
    params.insert(
        position,
        (Value::Integer(5.into()), Value::Bytes(vec![0x55; 12])),
    );
    params.insert(
        position,
        (
            Value::Integer(4.into()),
            Value::Array(
                operations
                    .into_iter()
                    .map(|v: i64| Value::Integer(v.into()))
                    .collect(),
            ),
        ),
    );
    params.insert(1, (Value::Integer(2.into()), Value::Bytes(vec![0x99])));
    // This deliberately is not a registered private parameter. Any opaque
    // extension can carry a secret, regardless of the input's public shape.
    params.push((Value::Text("d".to_owned()), Value::Bytes(vec![0xa5; 32])));
    crate::encode_cbor::encode_cbor_value(value.take_value())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn public_projection_excludes_private_and_extension_material_for_every_key_family(
) -> Result<(), CoseError> {
    for algorithm in [
        Algorithm::Ed25519,
        Algorithm::P256,
        Algorithm::MlDsa44,
        Algorithm::X25519,
        Algorithm::MlKem768,
    ] {
        let (public, private) = reallyme_crypto::dispatch::generate_keypair(algorithm)
            .map_err(|_| CoseError::Crypto)?;
        let signature = !matches!(algorithm, Algorithm::X25519 | Algorithm::MlKem768);
        let base = cose_key_from_public_bytes(algorithm, &public)?;
        let expected = cose_key_to_vec(&base)?;
        for include_private in [false, true] {
            if include_private && algorithm == Algorithm::X25519 {
                continue;
            }
            let key = if include_private {
                cose_key_from_private_bytes(algorithm, &private, Some(&public))?
            } else {
                cose_key_from_public_bytes(algorithm, &public)?
            };
            let encoded = decorated(&cose_key_to_vec(&key)?, signature, include_private)?;
            let key = cose_key_from_slice(&encoded)?;
            let projected = project(&encoded)?;
            assert!(projected.as_slice() == expected.as_slice());
            assert_eq!(
                derive_kid_from_cose_key_public(&key)?,
                derive_kid_from_cose_key_public(&base)?
            );
            assert_eq!(cose_key_to_multikey(&key)?, cose_key_to_multikey(&base)?);
            // Full serialization remains explicit and sensitive; projection
            // neither changes the owned input nor overwrites received bytes.
            assert!(cose_key_to_vec(&key)?.as_slice() == encoded.as_slice());
            assert!(project(&projected)?.as_slice() == projected.as_slice());
        }
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn public_projection_preserves_exact_registration_and_algorithm_absence() -> Result<(), CoseError> {
    let public = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    for explicit in [false, true] {
        // Independent RFC 8032 public point with an opaque text-label secret.
        let mut encoded = Zeroizing::new(if explicit {
            b"\xa5\x01\x01\x03\x32\x20\x06\x21\x58\x20".to_vec()
        } else {
            b"\xa4\x01\x01\x20\x06\x21\x58\x20".to_vec()
        });
        encoded.extend_from_slice(&public);
        encoded.extend_from_slice(b"\x61d\x43\x41\x42\x43");
        let mut expected = if explicit {
            b"\xa4\x01\x01\x03\x32\x20\x06\x21\x58\x20".to_vec()
        } else {
            b"\xa3\x01\x01\x20\x06\x21\x58\x20".to_vec()
        };
        expected.extend_from_slice(&public);
        assert_eq!(project(&encoded)?.as_slice(), expected);
    }
    let (public, _) = reallyme_crypto::dispatch::generate_keypair(Algorithm::P256)
        .map_err(|_| CoseError::Crypto)?;
    let mut encodings = Vec::new();
    for registration in [
        CoseSignatureAlgorithm::Es256,
        CoseSignatureAlgorithm::Esp256,
    ] {
        let key = cose_key_from_signature_public_bytes(registration, &public)?;
        let encoded = decorated(&cose_key_to_vec(&key)?, true, false)?;
        let projected = project(&encoded)?;
        let parsed = cose_key_from_slice(&projected)?;
        assert_eq!(
            crate::key::cose_key_signature_algorithm(&parsed)?,
            Some(registration)
        );
        encodings.push(projected);
    }
    assert_ne!(encodings.first(), encodings.last());
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn public_projection_rejects_malformed_and_oversized_keys() -> Result<(), CoseError> {
    for (encoded, expected) in [
        (vec![], CoseError::Cbor),
        (
            vec![
                0;
                crate::limits::MAX_COSE_KEY_BYTES
                    .checked_add(1)
                    .ok_or(CoseError::ResourceLimitExceeded)?
            ],
            CoseError::ResourceLimitExceeded,
        ),
    ] {
        assert_eq!(
            reason(&codec_parity(Operation::KeyToPublicVec(Box::new(
                CoseKeyBytesRequest::default().with_cose_key(encoded),
            )))?),
            expected.reason()
        );
    }
    Ok(())
}
