// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::support::{codec_parity, hex, reason, success};
use crate::api::contract::{
    __buffa::oneof::{cose_operation_request::Operation, cose_operation_result::Result as Branch},
    CoseKeyBytesRequest,
};
use crate::zeroize_coset::SensitiveCborValue;
use crate::{
    cose_key_from_private_bytes, cose_key_from_public_bytes, cose_key_from_slice,
    cose_key_to_private_bytes, cose_key_to_public_bytes, cose_key_to_vec, Algorithm, CoseError,
};
use ciborium::value::Value;
use coset::{iana, RegisteredLabel};
use zeroize::Zeroizing;

const SIGNATURE_ALGORITHMS: [Algorithm; 8] = [
    Algorithm::Ed25519,
    Algorithm::P256,
    Algorithm::P384,
    Algorithm::P521,
    Algorithm::Secp256k1,
    Algorithm::MlDsa44,
    Algorithm::MlDsa65,
    Algorithm::MlDsa87,
];

fn request(encoded: &[u8]) -> Box<CoseKeyBytesRequest> {
    Box::new(CoseKeyBytesRequest::default().with_cose_key(encoded.to_vec()))
}

fn with_operations(encoded: &[u8], operations: &[i64]) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    // Inject the independently selected restriction before parsing. The decoded
    // private tree and encoded result retain their wiping owners on every exit.
    let mut value = SensitiveCborValue::decode_cose_key(encoded)?;
    let Value::Map(params) = value.value_mut() else {
        return Err(CoseError::InvalidFormat);
    };
    let position = params
        .iter()
        .position(|(label, _)| matches!(label, Value::Integer(v) if i128::from(*v) < 0))
        .ok_or(CoseError::InvalidFormat)?;
    params.insert(
        position,
        (
            Value::Integer((iana::KeyParameter::KeyOps as i64).into()),
            Value::Array(
                operations
                    .iter()
                    .map(|op| Value::Integer((*op).into()))
                    .collect(),
            ),
        ),
    );
    crate::encode_cbor::encode_cbor_value(value.take_value())
}

fn reject(encoded: &[u8]) -> Result<(), CoseError> {
    assert_eq!(
        cose_key_from_slice(encoded).err(),
        Some(CoseError::InvalidKeyMaterial)
    );
    for operation in [
        Operation::KeyParse(request(encoded)),
        Operation::KeyToPrivateBytes(request(encoded)),
    ] {
        assert_eq!(
            reason(&codec_parity(operation)?),
            CoseError::InvalidKeyMaterial.reason()
        );
    }
    Ok(())
}

fn export(encoded: &[u8], expected: &[u8]) -> Result<(), CoseError> {
    let parsed = cose_key_from_slice(encoded)?;
    assert!(cose_key_to_private_bytes(&parsed)?.as_slice() == expected);
    assert!(cose_key_to_vec(&parsed)?.as_slice() == encoded);
    let parsed = success(codec_parity(Operation::KeyParse(request(encoded)))?);
    let Branch::KeyParse(output) = &parsed else {
        return Err(CoseError::InvalidFormat);
    };
    assert!(output.key_bytes.as_slice() == encoded);
    let exported = success(codec_parity(Operation::KeyToPrivateBytes(request(
        encoded,
    )))?);
    let Branch::KeyToPrivateBytes(output) = &exported else {
        return Err(CoseError::InvalidFormat);
    };
    assert!(output.key_bytes.as_slice() == expected);
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn verify_only_private_keys_are_rejected_in_every_signature_family() -> Result<(), CoseError> {
    for algorithm in SIGNATURE_ALGORITHMS {
        let (public, private) = reallyme_crypto::dispatch::generate_keypair(algorithm)
            .map_err(|_| CoseError::Crypto)?;
        let mut key = cose_key_from_private_bytes(algorithm, &private, Some(&public))?;
        let encoded = cose_key_to_vec(&key)?;
        reject(&with_operations(&encoded, &[2])?)?;

        // Internal owners are revalidated too: an adapter cannot bypass the
        // restriction by handing extraction a previously constructed key.
        key.inner_mut().key_ops = [RegisteredLabel::Assigned(iana::KeyOperation::Verify)]
            .into_iter()
            .collect();
        assert_eq!(
            cose_key_to_private_bytes(&key).err(),
            Some(CoseError::InvalidKeyMaterial)
        );
        assert_eq!(
            cose_key_to_vec(&key).err(),
            Some(CoseError::InvalidKeyMaterial)
        );
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn private_signing_keys_accept_omitted_or_explicit_sign_permission() -> Result<(), CoseError> {
    const MESSAGE: &[u8] = b"COSE private key operation restriction";
    for algorithm in SIGNATURE_ALGORITHMS {
        let (public, private) = reallyme_crypto::dispatch::generate_keypair(algorithm)
            .map_err(|_| CoseError::Crypto)?;
        let key = cose_key_from_private_bytes(algorithm, &private, Some(&public))?;
        let encoded = cose_key_to_vec(&key)?;
        for encoded in [
            encoded.clone(),
            with_operations(&encoded, &[1])?,
            with_operations(&encoded, &[1, 2])?,
        ] {
            export(&encoded, &private)?;
            let parsed = cose_key_from_slice(&encoded)?;
            let exported = cose_key_to_private_bytes(&parsed)?;
            let signature = Zeroizing::new(
                reallyme_crypto::dispatch::sign(algorithm, &exported, MESSAGE)
                    .map_err(|_| CoseError::Crypto)?,
            );
            reallyme_crypto::dispatch::verify(algorithm, &public, MESSAGE, &signature)
                .map_err(|_| CoseError::InvalidSignature)?;
        }
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn public_verify_only_keys_remain_valid_and_cannot_export_private_material() -> Result<(), CoseError>
{
    for algorithm in SIGNATURE_ALGORITHMS {
        let (public, _) = reallyme_crypto::dispatch::generate_keypair(algorithm)
            .map_err(|_| CoseError::Crypto)?;
        let key = cose_key_from_public_bytes(algorithm, &public)?;
        let encoded = cose_key_to_vec(&key)?;
        let restricted = with_operations(&encoded, &[2])?;
        let parsed = cose_key_from_slice(&restricted)?;
        assert_eq!(cose_key_to_public_bytes(&parsed)?, public);
        assert!(cose_key_to_vec(&parsed)?.as_slice() == restricted.as_slice());
        assert_eq!(
            cose_key_to_private_bytes(&parsed).err(),
            Some(CoseError::MissingKeyMaterial)
        );
        let response = success(codec_parity(Operation::KeyParse(request(&restricted)))?);
        let Branch::KeyParse(output) = &response else {
            return Err(CoseError::InvalidFormat);
        };
        assert_eq!(output.key_bytes.as_slice(), restricted.as_slice());
        assert_eq!(
            reason(&codec_parity(Operation::KeyToPrivateBytes(request(
                &restricted
            )))?),
            CoseError::MissingKeyMaterial.reason()
        );
        reject(&with_operations(&encoded, &[1])?)?;
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn rfc8032_verify_only_private_key_rejection_does_not_depend_on_optional_alg(
) -> Result<(), CoseError> {
    // RFC 8032 section 7.1 TEST 1: independently assembled keys, not a roundtrip
    // through the constructor under test. The valid pair must still be rejected
    // for its restriction, with or without the optional algorithm registration.
    let public = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let private = Zeroizing::new(hex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    ));
    const MAX_ENCODED_BYTES: usize = 80;
    for explicit_algorithm in [false, true] {
        let mut encoded = Zeroizing::new(Vec::new());
        encoded
            .try_reserve_exact(MAX_ENCODED_BYTES)
            .map_err(|_| CoseError::ResourceLimitExceeded)?;
        encoded.push(if explicit_algorithm { 0xa6 } else { 0xa5 });
        encoded.extend_from_slice(b"\x01\x01");
        if explicit_algorithm {
            encoded.extend_from_slice(b"\x03\x32");
        }
        encoded.extend_from_slice(b"\x04\x81\x02\x20\x06\x21\x58\x20");
        encoded.extend_from_slice(&public);
        encoded.extend_from_slice(b"\x23\x58\x20");
        encoded.extend_from_slice(&private);
        reject(&encoded)?;
        // Only the allowed operation changes; key, map and alg remain exact.
        let operation = if explicit_algorithm { 7 } else { 5 };
        *encoded.get_mut(operation).ok_or(CoseError::InvalidFormat)? = 1;
        export(&encoded, &private)?;
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn non_signature_private_keys_keep_their_distinct_operation_rules() -> Result<(), CoseError> {
    let (public, private) = reallyme_crypto::dispatch::generate_keypair(Algorithm::MlKem768)
        .map_err(|_| CoseError::Crypto)?;
    let key = cose_key_from_private_bytes(Algorithm::MlKem768, &private, Some(&public))?;
    let encoded = cose_key_to_vec(&key)?;
    export(&with_operations(&encoded, &[7, 8])?, &private)?;
    reject(&with_operations(&encoded, &[1])?)?;
    reject(&with_operations(&encoded, &[2])?)?;
    Ok(())
}
