// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::support::{codec_parity, reason, success};
use crate::api::contract::{
    self as wire,
    __buffa::oneof::{cose_operation_request::Operation, cose_operation_result::Result as Branch},
};
use crate::encrypt::{
    cose_decrypt_ml_kem, cose_encrypt_ml_kem_direct, cose_encrypt_ml_kem_key_wrap,
    CoseContentEncryptionAlgorithm as Content, CoseMlKemAlgorithm as Kem, CoseMlKemDecryptRequest,
    CoseMlKemEncryptRequest,
};
use crate::{Algorithm, CoseError};
use reallyme_crypto::kmac::KMAC256_MAX_CONTEXT_LENGTH;
use zeroize::Zeroizing;

const MAX_OVERHEAD_BYTES: usize = 53;

fn maximum() -> Result<usize, CoseError> {
    KMAC256_MAX_CONTEXT_LENGTH
        .checked_sub(MAX_OVERHEAD_BYTES)
        .ok_or(CoseError::ResourceLimitExceeded)
}

fn kid(algorithm: Algorithm, public: &[u8]) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    crate::derive_kid_from_cose_key_public(&crate::cose_key_from_public_bytes(algorithm, public)?)
}

fn wire_encrypt(input: &CoseMlKemEncryptRequest<'_>) -> wire::CoseMlKemEncryptRequest {
    wire::CoseMlKemEncryptRequest {
        kem_algorithm: wire::CoseKemAlgorithm::from(input.kem_algorithm).into(),
        content_algorithm: wire::CoseContentEncryptionAlgorithm::from(input.content_algorithm)
            .into(),
        recipient_public_key: input.recipient_public_key.to_vec().into(),
        recipient_kid: input.recipient_kid.to_vec().into(),
        plaintext: input.plaintext.to_vec().into(),
        external_aad: Default::default(),
        supp_priv_info: input.supp_priv_info.map(|v| v.to_vec().into()),
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn supp_priv_info_overflow_rejects_before_key_checks_or_envelope_decoding() -> Result<(), CoseError>
{
    let oversized = Zeroizing::new(vec![
        0x55;
        maximum()?
            .checked_add(1)
            .ok_or(CoseError::ResourceLimitExceeded)?
    ]);
    let input = CoseMlKemEncryptRequest::new(
        Kem::MlKem512,
        Content::Aes128Gcm,
        &[],
        &[0x42; 32],
        b"data",
        Some(&oversized),
    );
    assert_eq!(
        cose_encrypt_ml_kem_direct(&input).err(),
        Some(CoseError::ResourceLimitExceeded)
    );
    assert_eq!(
        cose_encrypt_ml_kem_key_wrap(&input).err(),
        Some(CoseError::ResourceLimitExceeded)
    );
    for operation in [
        Operation::MlKemEncryptDirect(Box::new(wire_encrypt(&input))),
        Operation::MlKemEncryptKeyWrap(Box::new(wire_encrypt(&input))),
    ] {
        assert_eq!(
            reason(&codec_parity(operation)?),
            CoseError::ResourceLimitExceeded.reason()
        );
    }
    let input = CoseMlKemDecryptRequest::new(&[], &[0x42; 64], &[0x42; 32], Some(&oversized));
    assert_eq!(
        cose_decrypt_ml_kem(&input).err(),
        Some(CoseError::ResourceLimitExceeded)
    );
    assert_eq!(
        reason(&codec_parity(Operation::MlKemDecrypt(Box::new(
            wire::CoseMlKemDecryptRequest {
                cose_encrypt: Default::default(),
                recipient_private_key: vec![0x42; 64].into(),
                expected_recipient_kid: vec![0x42; 32].into(),
                external_aad: Default::default(),
                supp_priv_info: Some(oversized.to_vec().into()),
            }
        )))?),
        CoseError::ResourceLimitExceeded.reason()
    );
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn supp_priv_info_maximum_roundtrips_all_kem_modes_and_content_algorithms() -> Result<(), CoseError>
{
    let private_context = Zeroizing::new(vec![0x55; maximum()?]);
    for (kem, algorithm) in [
        (Kem::MlKem512, Algorithm::MlKem512),
        (Kem::MlKem768, Algorithm::MlKem768),
        (Kem::MlKem1024, Algorithm::MlKem1024),
    ] {
        let (public, private) = reallyme_crypto::dispatch::generate_keypair(algorithm)
            .map_err(|_| CoseError::Crypto)?;
        let kid = kid(algorithm, &public)?;
        for content in [Content::Aes128Gcm, Content::Aes192Gcm, Content::Aes256Gcm] {
            for wrap in [false, true] {
                let input = CoseMlKemEncryptRequest::new(
                    kem,
                    content,
                    &public,
                    &kid,
                    b"maximum private context",
                    Some(&private_context),
                );
                let encoded = if wrap {
                    cose_encrypt_ml_kem_key_wrap(&input)?
                } else {
                    cose_encrypt_ml_kem_direct(&input)?
                };
                let input =
                    CoseMlKemDecryptRequest::new(&encoded, &private, &kid, Some(&private_context));
                let decrypted = cose_decrypt_ml_kem(&input)?;
                assert_eq!(decrypted.plaintext.as_slice(), b"maximum private context");
                let response = success(codec_parity(Operation::MlKemDecrypt(Box::new(
                    wire::CoseMlKemDecryptRequest {
                        cose_encrypt: encoded.to_vec().into(),
                        recipient_private_key: private.to_vec().into(),
                        expected_recipient_kid: kid.to_vec().into(),
                        external_aad: Default::default(),
                        supp_priv_info: Some(private_context.to_vec().into()),
                    },
                )))?);
                let Branch::MlKemDecrypt(output) = &response else {
                    return Err(CoseError::InvalidFormat);
                };
                assert_eq!(output.plaintext.as_slice(), b"maximum private context");
            }
        }
    }
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn oversized_supp_priv_info_fails_without_allocations_or_kem_work() -> Result<(), CoseError> {
    let (public, private) = reallyme_crypto::dispatch::generate_keypair(Algorithm::MlKem512)
        .map_err(|_| CoseError::Crypto)?;
    let kid = kid(Algorithm::MlKem512, &public)?;
    let oversized = Zeroizing::new(vec![
        0x55;
        maximum()?
            .checked_add(1)
            .ok_or(CoseError::ResourceLimitExceeded)?
    ]);
    let input = CoseMlKemEncryptRequest::new(
        Kem::MlKem512,
        Content::Aes256Gcm,
        &public,
        &kid,
        b"data",
        None,
    );
    let encoded = cose_encrypt_ml_kem_direct(&input)?;
    let input = input.with_supp_priv_info(Some(&oversized));
    let decrypt = CoseMlKemDecryptRequest::new(&encoded, &private, &kid, Some(&oversized));
    let measured = allocation_counter::measure(|| {
        assert_eq!(
            cose_encrypt_ml_kem_direct(&input).err(),
            Some(CoseError::ResourceLimitExceeded)
        );
        assert_eq!(
            cose_encrypt_ml_kem_key_wrap(&input).err(),
            Some(CoseError::ResourceLimitExceeded)
        );
        assert_eq!(
            cose_decrypt_ml_kem(&decrypt).err(),
            Some(CoseError::ResourceLimitExceeded)
        );
    });
    assert_eq!(measured.count_total, 0);
    Ok(())
}
