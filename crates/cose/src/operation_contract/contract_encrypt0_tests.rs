// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::support::{codec_parity, field, hex, reason, success};
use crate::api::contract::{
    self as contract,
    __buffa::oneof::{cose_operation_request::Operation, cose_operation_result::Result as Branch},
    CoseContentEncryptionAlgorithm as Alg, CoseContentMode as Mode,
};
use crate::CoseError;
use buffa::Message;

fn create(
    algorithm: Alg,
    key: &[u8],
    protected: &[u8],
    unprotected: &[u8],
) -> contract::CoseEncrypt0CreateRequest {
    contract::CoseEncrypt0CreateRequest {
        headers: field(contract::CoseMessageHeaders {
            protected: protected.to_vec().into(),
            unprotected: unprotected.to_vec().into(),
        }),
        plaintext: b"This is the content.".to_vec().into(),
        external_aad: Vec::new().into(),
        key_algorithm: algorithm.into(),
        key: key.to_vec().into(),
        allowed_algorithms: vec![algorithm.into()].into(),
        base_iv: None,
        content_mode: Mode::Attached.into(),
        tagged: true,
    }
}
fn decrypt(
    request: &contract::CoseEncrypt0CreateRequest,
    output: &contract::CoseEncrypt0CreateResult,
) -> contract::CoseEncrypt0DecryptRequest {
    contract::CoseEncrypt0DecryptRequest {
        encoded: output.encoded.clone(),
        detached_ciphertext: output.detached_ciphertext.clone(),
        external_aad: request.external_aad.clone(),
        key_algorithm: request.key_algorithm,
        key: request.key.clone(),
        allowed_algorithms: request.allowed_algorithms.clone(),
        base_iv: request.base_iv.clone(),
        envelope: contract::CoseEnvelopePolicy::Either.into(),
    }
}
fn run(
    request: contract::CoseEncrypt0DecryptRequest,
) -> Result<contract::CoseOperationResponseV2, CoseError> {
    codec_parity(Operation::Encrypt0Decrypt(Box::new(request)))
}
fn vectors() -> [(Alg, &'static str, &'static str); 3] {
    // Independent COSE WG aes-gcm-examples/aes-gcm-enc-01/02/03.json.
    [
        (
            Alg::Aes128Gcm,
            "849b57219dae48de646d07dbb533566e",
            "60973a94bb2898009ee52ecfd9ab1dd25867374b162e2c03568b41f57c3cc16f9166250a",
        ),
        (
            Alg::Aes192Gcm,
            "0f1e2d3c4b5a69788796a5b4c3d2e1f01f2e3d4c5b6a7988",
            "134d3b9223a00c1552c77585c157f467f295919d530fbe21f7689ab3cd4d18ffe8e17ceb",
        ),
        (
            Alg::Aes256Gcm,
            "0f1e2d3c4b5a69788796a5b4c3d2e1f01f2e3d4c5b6a798897a6b5c4d3e2f100",
            "9d64a5a59a3b04867dccf6b8ef82f7d1a3b25ef84eca2bc5d7593a96e943859a9cc24ad3",
        ),
    ]
}
fn standard(algorithm: Alg, key: &str) -> contract::CoseEncrypt0CreateRequest {
    let identifier = match algorithm {
        Alg::Aes128Gcm => 1,
        Alg::Aes192Gcm => 2,
        _ => 3,
    };
    create(
        algorithm,
        &hex(key),
        &[0xa1, 1, identifier],
        &hex("a1054c02d1f7e6f26c43d4868d87ce"),
    )
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn encrypt0_independent_aes_gcm_vectors_match_creation_and_decryption() -> Result<(), CoseError> {
    for (algorithm, key, ciphertext) in vectors() {
        let input = standard(algorithm, key);
        let mut expected = vec![0xd0, 0x83, 0x43];
        expected.extend_from_slice(
            &input
                .headers
                .as_option()
                .ok_or(CoseError::InvalidFormat)?
                .protected,
        );
        expected.extend_from_slice(&hex("a1054c02d1f7e6f26c43d4868d87ce5824"));
        expected.extend_from_slice(&hex(ciphertext));
        let result = success(codec_parity(Operation::Encrypt0Create(Box::new(
            input.clone(),
        )))?);
        let Branch::Encrypt0Create(result) = &result else {
            return Err(CoseError::InvalidFormat);
        };
        assert_eq!(result.encoded, expected);
        assert_eq!(result.detached_ciphertext, None);
        let result = success(run(decrypt(&input, result))?);
        let Branch::Encrypt0Decrypt(result) = &result else {
            return Err(CoseError::InvalidFormat);
        };
        assert_eq!(result.plaintext, b"This is the content.");
        assert_eq!(result.algorithm, algorithm);
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn encrypt0_detached_partial_iv_empty_plaintext_and_ownership() -> Result<(), CoseError> {
    for mode in [Mode::Attached, Mode::Detached] {
        let mut input = standard(Alg::Aes128Gcm, vectors()[0].1);
        input.headers = field(contract::CoseMessageHeaders {
            protected: hex("a10101").into(),
            unprotected: hex("a10641ce").into(),
        });
        input.base_iv = Some(hex("02d1f7e6f26c43d4868d8700").into());
        input.content_mode = mode.into();
        let result = success(codec_parity(Operation::Encrypt0Create(Box::new(
            input.clone(),
        )))?);
        let Branch::Encrypt0Create(result) = &result else {
            return Err(CoseError::InvalidFormat);
        };
        if mode == Mode::Detached {
            assert_eq!(
                result.detached_ciphertext.as_deref(),
                Some(hex(vectors()[0].2).as_slice())
            );
        }
        let result = success(run(decrypt(&input, result))?);
        let Branch::Encrypt0Decrypt(result) = &result else {
            return Err(CoseError::InvalidFormat);
        };
        assert_eq!(result.plaintext, input.plaintext);
        input.clear();
        assert!(input.key.is_empty());
        assert!(input.plaintext.is_empty());
        assert!(input.base_iv.is_none());
    }
    let mut input = standard(Alg::Aes128Gcm, vectors()[0].1);
    input.plaintext = Default::default();
    let result = success(codec_parity(Operation::Encrypt0Create(Box::new(
        input.clone(),
    )))?);
    let Branch::Encrypt0Create(result) = &result else {
        return Err(CoseError::InvalidFormat);
    };
    let result = success(run(decrypt(&input, result))?);
    let Branch::Encrypt0Decrypt(result) = &result else {
        return Err(CoseError::InvalidFormat);
    };
    assert!(result.plaintext.is_empty());
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn encrypt0_tampered_content_aad_headers_nonce_tag_and_key_fail_closed() -> Result<(), CoseError> {
    let input = standard(Alg::Aes128Gcm, vectors()[0].1);
    let result = success(codec_parity(Operation::Encrypt0Create(Box::new(
        input.clone(),
    )))?);
    let Branch::Encrypt0Create(result) = &result else {
        return Err(CoseError::InvalidFormat);
    };
    let valid = decrypt(&input, result);
    for position in [12, 23, 58] {
        let mut changed = valid.clone();
        let mut encoded = changed.encoded.to_vec();
        *encoded.get_mut(position).ok_or(CoseError::InvalidFormat)? ^= 1;
        changed.encoded = encoded.into();
        assert_eq!(
            reason(&run(changed)?),
            CoseError::AuthenticationFailed.reason()
        );
    }
    let mut changed = valid.clone();
    changed.external_aad = vec![1].into();
    assert_eq!(
        reason(&run(changed)?),
        CoseError::AuthenticationFailed.reason()
    );
    let mut changed = valid.clone();
    changed.key = vec![1; 16].into();
    assert_eq!(
        reason(&run(changed)?),
        CoseError::AuthenticationFailed.reason()
    );
    let mut changed = valid.clone();
    changed.key_algorithm = Alg::Aes256Gcm.into();
    assert_eq!(
        reason(&run(changed)?),
        CoseError::UnsupportedAlgorithm.reason()
    );
    let mut changed = valid.clone();
    changed.key = vec![0; 15].into();
    assert_eq!(
        reason(&run(changed)?),
        CoseError::InvalidKeyMaterial.reason()
    );
    let mut changed = valid.clone();
    let mut bytes = changed.encoded.to_vec();
    bytes.push(0);
    changed.encoded = bytes.into();
    assert_eq!(reason(&run(changed)?), CoseError::Cbor.reason());
    let mut changed = valid.clone();
    changed.detached_ciphertext = Some(Vec::new().into());
    assert_eq!(reason(&run(changed)?), CoseError::InvalidFormat.reason());
    let mut changed = valid;
    changed.allowed_algorithms.clear();
    assert_eq!(
        reason(&run(changed)?),
        CoseError::UnsupportedAlgorithm.reason()
    );
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn encrypt0_rejects_conflicting_malformed_iv_critical_and_resource_inputs() -> Result<(), CoseError>
{
    for (protected, unprotected, expected) in [
        ("a10101", "a0", CoseError::InvalidIv),
        ("a10101", "a1054100", CoseError::InvalidIv),
        ("a10101", "a1064100", CoseError::InvalidIv),
        (
            "a10101",
            "a2054c02d1f7e6f26c43d4868d87ce064100",
            CoseError::InvalidIv,
        ),
        ("a10101", "a10501", CoseError::Cbor),
        ("a201010281182a", "a0", CoseError::UnsupportedCriticalHeader),
        ("a10101", "a10101", CoseError::DuplicateMapLabel),
    ] {
        let input = create(
            Alg::Aes128Gcm,
            &hex(vectors()[0].1),
            &hex(protected),
            &hex(unprotected),
        );
        assert_eq!(
            reason(&codec_parity(Operation::Encrypt0Create(Box::new(input)))?),
            expected.reason()
        );
    }
    let mut input = standard(Alg::Aes128Gcm, vectors()[0].1);
    input.external_aad = vec![0; 65_537].into();
    assert_eq!(
        reason(&codec_parity(Operation::Encrypt0Create(Box::new(input)))?),
        CoseError::ResourceLimitExceeded.reason()
    );
    let mut input = standard(Alg::Aes128Gcm, vectors()[0].1);
    input.plaintext = vec![0; 1_048_561].into();
    assert_eq!(
        reason(&codec_parity(Operation::Encrypt0Create(Box::new(input)))?),
        CoseError::ResourceLimitExceeded.reason()
    );
    Ok(())
}
