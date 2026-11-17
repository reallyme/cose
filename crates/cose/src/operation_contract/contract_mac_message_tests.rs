// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::support::{codec_parity, field, hex, reason, success};
use crate::api::contract::{
    self as contract,
    __buffa::oneof::{
        cose_operation_request::Operation, cose_operation_result::Result as Branch,
        cose_recipient_create::KeySource,
    },
    CoseContentMode as Mode, CoseMacAlgorithm as Alg, CoseRecipientAlgorithm as Distribution,
};
use crate::{error::CoseErrorReason, CoseError};
use buffa::Message;
#[path = "contract_mac_message_vectors.rs"]
mod vectors;

fn headers(protected: &[u8], unprotected: &[u8]) -> contract::CoseMessageHeaders {
    contract::CoseMessageHeaders {
        protected: protected.to_vec().into(),
        unprotected: unprotected.to_vec().into(),
    }
}
fn recipient(algorithm: Distribution, key: &[u8]) -> contract::CoseRecipientCreate {
    let id = match algorithm {
        Distribution::Direct => 0x25,
        Distribution::A128kw => 0x22,
        Distribution::A192kw => 0x23,
        _ => 0x24,
    };
    contract::CoseRecipientCreate {
        headers: field(headers(&[], &[0xa1, 1, id])),
        key_source: Some(KeySource::Key(key.to_vec().into())),
    }
}
fn request(
    encoded: &[u8],
    algorithm: Alg,
    key: &[u8],
    path: &[u32],
) -> contract::CoseMacVerifyRequest {
    contract::CoseMacVerifyRequest {
        encoded: encoded.to_vec().into(),
        detached_payload: None,
        external_aad: Vec::new().into(),
        algorithm: algorithm.into(),
        allowed_algorithms: vec![algorithm.into()].into(),
        recipient_path: path.to_vec().into(),
        recipient_key: key.to_vec().into(),
        allowed_recipient_algorithms: vec![
            Distribution::Direct.into(),
            Distribution::A128kw.into(),
            Distribution::A192kw.into(),
            Distribution::A256kw.into(),
        ]
        .into(),
        envelope: contract::CoseEnvelopePolicy::Either.into(),
    }
}
fn create(
    algorithm: Alg,
    recipients: Vec<contract::CoseRecipientCreate>,
) -> contract::CoseMacCreateRequest {
    let id = match algorithm {
        Alg::Hmac25664 => 4,
        Alg::Hmac256256 => 5,
        Alg::Hmac384384 => 6,
        _ => 7,
    };
    contract::CoseMacCreateRequest {
        headers: field(headers(&[0xa1, 1, id], &[0xa0])),
        payload: b"This is the content.".to_vec().into(),
        external_aad: Vec::new().into(),
        algorithm: algorithm.into(),
        allowed_algorithms: vec![algorithm.into()].into(),
        content_mode: Mode::Attached.into(),
        tagged: true,
        recipients: recipients.into(),
        allowed_recipient_algorithms: vec![
            Distribution::Direct.into(),
            Distribution::A128kw.into(),
            Distribution::A192kw.into(),
            Distribution::A256kw.into(),
        ]
        .into(),
    }
}
fn verify(
    request: contract::CoseMacVerifyRequest,
) -> Result<contract::CoseOperationResponseV2, CoseError> {
    codec_parity(Operation::MacVerify(Box::new(request)))
}

// Wrapped-key creation intentionally obtains fresh entropy for each transport.
// Verify each independent result rather than expecting RNG outputs to repeat.
fn randomized_create(input: contract::CoseMacCreateRequest) -> Result<Vec<Branch>, CoseError> {
    let request = super::support::request(Operation::MacCreate(Box::new(input)));
    let typed = crate::api::execute(request.clone());
    let binary = crate::wire::execute_operation_proto(&request.encode_to_vec());
    let binary = crate::wire::decode_operation_response_for_request(&request, &binary)
        .map_err(|_| CoseError::InvalidFormat)?;
    let json = zeroize::Zeroizing::new(
        serde_json::to_string(&request).map_err(|_| CoseError::InvalidFormat)?,
    );
    let json = crate::wire::execute_operation_proto_json(&json);
    let json = crate::wire::decode_operation_response_for_request(&request, &json)
        .map_err(|_| CoseError::InvalidFormat)?;
    Ok(vec![success(typed), success(binary), success(json)])
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn mac_independent_hmac_vectors_match_creation_and_verification() -> Result<(), CoseError> {
    for ((key, encoded), algorithm) in
        vectors::HMAC
            .iter()
            .zip([Alg::Hmac256256, Alg::Hmac384384, Alg::Hmac512512])
    {
        let key = hex(key);
        let encoded = hex(encoded);
        let result = success(verify(request(&encoded, algorithm, &key, &[0]))?);
        let Branch::MacVerify(result) = &result else {
            return Err(CoseError::InvalidFormat);
        };
        assert_eq!(
            result.attached_payload.as_deref(),
            Some(b"This is the content.".as_slice())
        );
        let mut leaf = recipient(Distribution::Direct, &key);
        let kid = match algorithm {
            Alg::Hmac256256 => "a20125044a6f75722d736563726574",
            Alg::Hmac384384 => "a2012504467365632d3438",
            _ => "a2012504467365632d3634",
        };
        leaf.headers = field(headers(&[], &hex(kid)));
        let result = success(codec_parity(Operation::MacCreate(Box::new(create(
            algorithm,
            vec![leaf],
        ))))?);
        let Branch::MacCreate(result) = &result else {
            return Err(CoseError::InvalidFormat);
        };
        assert_eq!(result.encoded, encoded);
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn mac_independent_wrapped_hmac_vector_and_invalid_wrap() -> Result<(), CoseError> {
    let valid = request(
        &hex(vectors::WRAPPED),
        Alg::Hmac512512,
        &hex(vectors::WRAP_KEY),
        &[0],
    );
    let _ = success(verify(valid.clone())?);
    let mut changed = valid.clone();
    changed.recipient_key = vec![0; 16].into();
    assert_eq!(
        reason(&verify(changed)?),
        CoseError::KeyUnwrapFailed.reason()
    );
    let mut changed = valid;
    let mut bytes = changed.encoded.to_vec();
    *bytes.last_mut().ok_or(CoseError::InvalidFormat)? ^= 1;
    changed.encoded = bytes.into();
    assert_eq!(
        reason(&verify(changed)?),
        CoseError::KeyUnwrapFailed.reason()
    );
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn mac_tamper_payload_aad_tag_key_and_structure_fail_with_fixed_reasons() -> Result<(), CoseError> {
    let valid = request(
        &hex(vectors::HMAC[0].1),
        Alg::Hmac256256,
        &hex(vectors::HMAC[0].0),
        &[0],
    );
    for position in [9, 31, 59] {
        let mut changed = valid.clone();
        let mut bytes = changed.encoded.to_vec();
        *bytes.get_mut(position).ok_or(CoseError::InvalidFormat)? ^= 1;
        changed.encoded = bytes.into();
        assert_eq!(
            reason(&verify(changed)?),
            CoseErrorReason::CommonAuthenticationFailed
        );
    }
    let mut changed = valid.clone();
    changed.external_aad = vec![1].into();
    assert_eq!(
        reason(&verify(changed)?),
        CoseErrorReason::CommonAuthenticationFailed
    );
    let mut changed = valid.clone();
    changed.recipient_key = vec![1; 32].into();
    assert_eq!(
        reason(&verify(changed)?),
        CoseErrorReason::CommonAuthenticationFailed
    );
    let mut changed = valid.clone();
    changed.algorithm = Alg::Hmac384384.into();
    assert_eq!(
        reason(&verify(changed)?),
        CoseError::UnsupportedAlgorithm.reason()
    );
    let mut changed = valid.clone();
    changed.recipient_key = vec![0; 31].into();
    assert_eq!(
        reason(&verify(changed)?),
        CoseError::InvalidKeyMaterial.reason()
    );
    let mut changed = valid.clone();
    let mut bytes = changed.encoded.to_vec();
    bytes.push(0);
    changed.encoded = bytes.into();
    assert_eq!(reason(&verify(changed)?), CoseError::Cbor.reason());
    let mut changed = valid.clone();
    let mut bytes = changed.encoded.to_vec();
    *bytes.last_mut().ok_or(CoseError::InvalidFormat)? = 0xf6;
    changed.encoded = bytes.into();
    assert_eq!(reason(&verify(changed)?), CoseError::Cbor.reason());
    let mut changed = valid;
    changed.recipient_path = vec![1].into();
    assert_eq!(
        reason(&verify(changed)?),
        CoseError::InvalidRecipient.reason()
    );
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn mac_detached_truncated_and_protected_byte_ownership() -> Result<(), CoseError> {
    let key = hex(vectors::HMAC[0].0);
    let mut input = create(Alg::Hmac25664, vec![recipient(Distribution::Direct, &key)]);
    input.content_mode = Mode::Detached.into();
    input.external_aad = b"aad".to_vec().into();
    input.headers = field(headers(&hex("a204400104"), &[0xa0]));
    let result = success(codec_parity(Operation::MacCreate(Box::new(input.clone())))?);
    let Branch::MacCreate(result) = &result else {
        return Err(CoseError::InvalidFormat);
    };
    let mut valid = request(&result.encoded, Alg::Hmac25664, &key, &[0]);
    valid.detached_payload = Some(input.payload.clone());
    valid.external_aad = input.external_aad.clone();
    let result = success(verify(valid.clone())?);
    let Branch::MacVerify(result) = &result else {
        return Err(CoseError::InvalidFormat);
    };
    assert!(result.attached_payload.is_none());
    assert_eq!(result.protected, hex("a204400104"));
    assert_eq!(result.protected_kid.as_deref(), Some([].as_slice()));
    let mut changed = valid.clone();
    changed.detached_payload = Some(b"wrong".to_vec().into());
    assert_eq!(
        reason(&verify(changed)?),
        CoseErrorReason::CommonAuthenticationFailed
    );
    let mut changed = valid;
    let mut bytes = changed.encoded.to_vec();
    bytes
        .get_mut(4..9)
        .ok_or(CoseError::InvalidFormat)?
        .copy_from_slice(&hex("a201040440"));
    changed.encoded = bytes.into();
    assert_eq!(
        reason(&verify(changed)?),
        CoseErrorReason::CommonAuthenticationFailed
    );
    input.clear();
    assert!(input.payload.is_empty());
    assert!(input.recipients.is_empty());
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn mac_multiple_and_nested_aes_wrap_recipients_use_explicit_paths() -> Result<(), CoseError> {
    for (distribution, length) in [
        (Distribution::A128kw, 16),
        (Distribution::A192kw, 24),
        (Distribution::A256kw, 32),
    ] {
        let key = vec![7; length];
        let other = vec![8; length];
        let mut parent = recipient(distribution, &[]);
        parent.key_source = Some(KeySource::Recipients(Box::new(
            contract::CoseRecipientCreateGroup {
                recipients: vec![
                    recipient(distribution, &key),
                    recipient(distribution, &other),
                ]
                .into(),
            },
        )));
        let input = create(
            Alg::Hmac256256,
            vec![parent, recipient(distribution, &other)],
        );
        for output in randomized_create(input)? {
            let Branch::MacCreate(result) = &output else {
                return Err(CoseError::InvalidFormat);
            };
            for (path, key) in [(&[0, 0][..], &key), (&[0, 1], &other), (&[1], &other)] {
                let _ = success(verify(request(
                    &result.encoded,
                    Alg::Hmac256256,
                    key,
                    path,
                ))?);
            }
        }
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn mac_unsupported_unselected_recipient_does_not_block_valid_path() -> Result<(), CoseError> {
    let key = vec![7; 16];
    let other = vec![8; 16];
    let input = create(
        Alg::Hmac256256,
        vec![
            recipient(Distribution::A128kw, &key),
            recipient(Distribution::A128kw, &other),
        ],
    );
    for output in randomized_create(input)? {
        let Branch::MacCreate(result) = &output else {
            return Err(CoseError::InvalidFormat);
        };
        let mut bytes = result.encoded.to_vec();
        let index = bytes
            .windows(3)
            .position(|bytes| bytes == [0xa1, 1, 0x22])
            .ok_or(CoseError::InvalidFormat)?;
        bytes.splice(index..index + 3, hex("a1013819"));
        let _ = success(verify(request(&bytes, Alg::Hmac256256, &other, &[1]))?);
        assert_eq!(
            reason(&verify(request(&bytes, Alg::Hmac256256, &key, &[0]))?),
            CoseError::UnsupportedAlgorithm.reason()
        );
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn mac_rejects_mixed_direct_recipients_invalid_headers_tags_and_limits() -> Result<(), CoseError> {
    let key = hex(vectors::HMAC[0].0);
    let mut mixed = create(
        Alg::Hmac256256,
        vec![
            recipient(Distribution::Direct, &key),
            recipient(Distribution::A128kw, &[0; 16]),
        ],
    );
    assert_eq!(
        reason(&codec_parity(Operation::MacCreate(Box::new(
            mixed.clone()
        )))?),
        CoseError::InvalidRecipient.reason()
    );
    mixed.recipients.clear();
    assert_eq!(
        reason(&codec_parity(Operation::MacCreate(Box::new(mixed)))?),
        CoseError::InvalidRecipient.reason()
    );
    for (protected, unprotected, expected) in [
        ("a10125", "a0", CoseError::InvalidRecipient),
        ("", "a201250125", CoseError::DuplicateMapLabel),
        ("", "a10101", CoseError::UnsupportedAlgorithm),
    ] {
        let mut leaf = recipient(Distribution::Direct, &key);
        leaf.headers = field(headers(&hex(protected), &hex(unprotected)));
        assert_eq!(
            reason(&codec_parity(Operation::MacCreate(Box::new(create(
                Alg::Hmac256256,
                vec![leaf]
            ))))?),
            expected.reason()
        );
    }
    let mut input = create(Alg::Hmac256256, vec![recipient(Distribution::Direct, &key)]);
    input.external_aad = vec![0; 65_537].into();
    assert_eq!(
        reason(&codec_parity(Operation::MacCreate(Box::new(input)))?),
        CoseError::ResourceLimitExceeded.reason()
    );
    // Four nested recipient layers are supported; a fifth is rejected before RNG.
    for layers in [4, 5] {
        let mut leaf = recipient(Distribution::A128kw, &[7; 16]);
        for _ in 1..layers {
            let child = leaf;
            leaf = recipient(Distribution::A128kw, &[]);
            leaf.key_source = Some(KeySource::Recipients(Box::new(
                contract::CoseRecipientCreateGroup {
                    recipients: vec![child].into(),
                },
            )));
        }
        let input = create(Alg::Hmac256256, vec![leaf]);
        if layers == 4 {
            for output in randomized_create(input)? {
                let Branch::MacCreate(result) = &output else {
                    return Err(CoseError::InvalidFormat);
                };
                let _ = success(verify(request(
                    &result.encoded,
                    Alg::Hmac256256,
                    &[7; 16],
                    &[0; 4],
                ))?);
            }
        } else {
            assert_eq!(
                reason(&codec_parity(Operation::MacCreate(Box::new(input)))?),
                CoseError::ResourceLimitExceeded.reason()
            );
        }
    }
    let mut valid = request(&hex(vectors::HMAC[0].1), Alg::Hmac256256, &key, &[0]);
    let mut bytes = valid.encoded.to_vec();
    // Replace the full tag with a 31-byte bstr, retaining valid envelope framing.
    *bytes.get_mut(30).ok_or(CoseError::InvalidFormat)? = 31;
    bytes.remove(31);
    valid.encoded = bytes.into();
    assert_eq!(
        reason(&verify(valid)?),
        CoseErrorReason::CommonInvalidLength
    );
    Ok(())
}
