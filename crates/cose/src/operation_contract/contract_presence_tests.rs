// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::support::{codec_parity, field, reason, success, suite};
use crate::api::contract as wire;
use crate::{Algorithm, CoseError, CoseSignatureAlgorithm};
use buffa::Message;
use wire::{cose_operation_request::Operation, cose_operation_result::Result as Branch};

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn signing_presence_reaches_binary_and_json_without_a_second_flag() -> Result<(), CoseError> {
    let (public, private) = reallyme_crypto::dispatch::generate_keypair(Algorithm::Ed25519)
        .map_err(|_| CoseError::Crypto)?;
    for kid in [None, Some(Vec::new()), Some(b"key-id".to_vec())] {
        let input = wire::CoseSign1CreateRequest {
            algorithm: wire::CoseSignatureAlgorithm::Ed25519.into(),
            payload: b"presence".to_vec().into(),
            private_key: private.to_vec().into(),
            kid: kid.clone().map(Into::into),
            options: Default::default(),
            external_aad: Vec::new().into(),
        };
        let response = codec_parity(Operation::Sign1Create(Box::new(input)))?;
        if kid.as_ref().is_some_and(Vec::is_empty) {
            assert_eq!(
                reason(&response),
                wire::CoseErrorReason::CommonInvalidFormat
            );
        } else {
            let Branch::Sign1Create(output) = &mut success(response) else {
                return Err(CoseError::InvalidFormat);
            };
            let result =
                crate::cose_verify1_with_metadata(&output.cose_sign1, |_, _| Some(public.clone()))?;
            assert_eq!(result.kid.as_slice(), kid.as_deref().unwrap_or_default());
        }
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn absent_and_present_empty_private_kdf_context_are_authenticated_differently(
) -> Result<(), CoseError> {
    let (public, private) = reallyme_crypto::ml_kem_512::generate_ml_kem_512_keypair()
        .map_err(|_| CoseError::Crypto)?;
    let key = crate::cose_key_from_public_bytes(Algorithm::MlKem512, &public)?;
    let kid = crate::derive_kid_from_cose_key_public(&key)?;
    for wrapped in [false, true] {
        for context in [None, Some(Vec::new())] {
            let encrypt = wire::CoseMlKemEncryptRequest {
                kem_algorithm: wire::CoseKemAlgorithm::MlKem512.into(),
                content_algorithm: wire::CoseContentEncryptionAlgorithm::Aes128Gcm.into(),
                recipient_public_key: public.clone().into(),
                recipient_kid: kid.to_vec().into(),
                plaintext: b"private context presence".to_vec().into(),
                supp_priv_info: context.clone().map(Into::into),
                external_aad: Vec::new().into(),
            };
            let operation = if wrapped {
                Operation::MlKemEncryptKeyWrap(Box::new(encrypt))
            } else {
                Operation::MlKemEncryptDirect(Box::new(encrypt))
            };
            // Encryption is randomized. Compare authenticated plaintext across
            // transports, rather than comparing independently generated ciphertext.
            let request = super::support::request(operation);
            let json = zeroize::Zeroizing::new(
                serde_json::to_string(&request).map_err(|_| CoseError::InvalidFormat)?,
            );
            let binary = crate::wire::execute_operation_proto(&request.encode_to_vec());
            let json = crate::wire::execute_operation_proto_json(&json);
            for response in [
                crate::api::execute(request),
                crate::wire::decode_operation_response(&binary)
                    .map_err(|_| CoseError::InvalidFormat)?,
                crate::wire::decode_operation_response(&json)
                    .map_err(|_| CoseError::InvalidFormat)?,
            ] {
                let mut branch = success(response);
                let encrypted = match &mut branch {
                    Branch::MlKemEncryptDirect(value) | Branch::MlKemEncryptKeyWrap(value) => value,
                    _ => return Err(CoseError::InvalidFormat),
                };
                let decrypt = wire::CoseMlKemDecryptRequest {
                    cose_encrypt: encrypted.cose_encrypt.clone(),
                    recipient_private_key: private.to_vec().into(),
                    expected_recipient_kid: kid.to_vec().into(),
                    supp_priv_info: context.clone().map(Into::into),
                    external_aad: Vec::new().into(),
                };
                let Branch::MlKemDecrypt(output) = &mut success(codec_parity(
                    Operation::MlKemDecrypt(Box::new(decrypt.clone())),
                )?) else {
                    return Err(CoseError::InvalidFormat);
                };
                assert_eq!(output.plaintext, b"private context presence");
                let mut changed = decrypt;
                changed.supp_priv_info = if context.is_some() {
                    None
                } else {
                    Some(Vec::new().into())
                };
                let expected = if wrapped {
                    wire::CoseErrorReason::EncryptKeyUnwrapFailed
                } else {
                    wire::CoseErrorReason::EncryptAuthenticationFailed
                };
                assert_eq!(
                    reason(&codec_parity(Operation::MlKemDecrypt(Box::new(changed)))?),
                    expected
                );
            }
        }
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn iso_receipt_keeps_a_verified_empty_attached_payload_distinct_from_detached_content(
) -> Result<(), CoseError> {
    let (public, private) = reallyme_crypto::dispatch::generate_keypair(Algorithm::P256)
        .map_err(|_| CoseError::Crypto)?;
    for attached in [false, true] {
        let encoded = if attached {
            crate::cose_sign1_with_signature_algorithm(
                CoseSignatureAlgorithm::Es256,
                &[],
                &private,
                None,
            )?
        } else {
            crate::cose_sign1_detached_with_signature_algorithm(
                CoseSignatureAlgorithm::Es256,
                &[],
                &private,
                None,
            )?
        };
        let selected = suite(-7, 1)?;
        let input = wire::CoseIsoSign1VerifyRequest {
            encoded: encoded.to_vec().into(),
            content: if attached {
                wire::CoseIsoSign1Content::IssuerAttached
            } else {
                wire::CoseIsoSign1Content::ReaderDetached
            }
            .into(),
            allowed_suites: vec![selected.clone()].into(),
            key_suite: field(selected),
            public_key: public.clone().into(),
            key_source: wire::CoseKeySource::Direct.into(),
            detached_payload: Vec::new().into(),
            public_key_is_cose: false,
            capability: Default::default(),
            limits: Default::default(),
        };
        let Branch::IsoSign1Verify(output) =
            &mut success(codec_parity(Operation::IsoSign1Verify(Box::new(input)))?)
        else {
            return Err(CoseError::InvalidFormat);
        };
        assert_eq!(output.protected_kid, None);
        assert_eq!(
            output.attached_payload.as_deref(),
            attached.then_some(&[][..])
        );
    }
    Ok(())
}
