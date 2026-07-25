// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_crypto::aes::{
    decrypt, decrypt_aes128_gcm, decrypt_aes192_gcm, Aes128GcmDecryptRequest, Aes128GcmKey,
    Aes128GcmNonce, Aes192GcmDecryptRequest, Aes192GcmKey, Aes192GcmNonce, Aes256GcmKey,
    Aes256GcmNonce, CiphertextWithTag, DecryptRequest,
};
use reallyme_crypto::aes_kw::{
    unwrap_key_aes128, unwrap_key_aes192, unwrap_key_aes256, Aes128KwKek, Aes192KwKek, Aes256KwKek,
};
use zeroize::Zeroizing;

use crate::encode_cbor::encode_protected_header;
use crate::error::{decrypt_error_from_crypto_error, key_unwrap_error_from_crypto_error};
use crate::failure::CoseFailure;
use crate::key::derive_kid_from_ml_kem_public_key;
use crate::CoseError;

use super::codec::{
    decode, encapsulated_key, validate_structure, AES_GCM_TAG_LENGTH, MAX_EXTERNAL_AAD_BYTES,
    MAX_KID_BYTES, MAX_PLAINTEXT_BYTES, MAX_SUPP_PRIV_INFO_BYTES,
};
use super::kdf::{derive_key, enc_structure};
use super::profile::{
    content_algorithm_from_cose, content_algorithm_profile, suite_from_cose_algorithm, MlKemSuite,
    ML_KEM_KID_LENGTH, ML_KEM_PRIVATE_SEED_LENGTH,
};
use super::types::{
    CoseContentEncryptionAlgorithm, CoseMlKemAlgorithm, CoseMlKemDecryptInput,
    CoseMlKemDecryptRequest, CoseMlKemMode, DecryptedCoseEncrypt,
};

/// Decrypts the ReallyMe ML-KEM COSE profile with empty external AAD.
///
/// # Errors
///
/// Returns [`CoseError`] for malformed or oversized COSE, unsupported or
/// misplaced algorithms, key identifier mismatch, invalid key material,
/// AES-KW integrity failure, or content authentication failure.
pub fn cose_decrypt_ml_kem(
    request: &CoseMlKemDecryptRequest<'_>,
) -> Result<DecryptedCoseEncrypt, CoseError> {
    cose_decrypt_ml_kem_with_external_aad(request, &[])
}

/// Decrypts the ReallyMe ML-KEM COSE profile with caller-supplied external AAD.
///
/// # Errors
///
/// Returns [`CoseError`] for malformed or oversized COSE, unsupported or
/// misplaced algorithms, key identifier mismatch, invalid key material,
/// AES-KW integrity failure, or content authentication failure.
pub fn cose_decrypt_ml_kem_with_external_aad(
    request: &CoseMlKemDecryptRequest<'_>,
    external_aad: &[u8],
) -> Result<DecryptedCoseEncrypt, CoseError> {
    decrypt_cose_ml_kem(CoseMlKemDecryptInput::new(request, external_aad))
        .map_err(CoseFailure::into_native_error)
}

pub(crate) fn decrypt_cose_ml_kem(
    input: CoseMlKemDecryptInput<'_, '_>,
) -> Result<DecryptedCoseEncrypt, CoseFailure> {
    decrypt_ml_kem(input.request, input.external_aad).map_err(CoseFailure::from_encrypt_error)
}

fn decrypt_ml_kem(
    request: &CoseMlKemDecryptRequest<'_>,
    external_aad: &[u8],
) -> Result<DecryptedCoseEncrypt, CoseError> {
    validate_request(request, external_aad)?;
    let sensitive = decode(request.cose_encrypt)?;
    let cose = &sensitive.inner;
    validate_structure(cose)?;

    let body_algorithm = cose
        .protected
        .header
        .alg
        .as_ref()
        .ok_or(CoseError::UnsupportedAlgorithm)?;
    let content_algorithm = content_algorithm_from_cose(body_algorithm)?;
    let (content_cose_algorithm, _, content_key_length) =
        content_algorithm_profile(content_algorithm);
    let recipient = cose.recipients.first().ok_or(CoseError::InvalidRecipient)?;
    let recipient_algorithm = recipient
        .protected
        .header
        .alg
        .as_ref()
        .ok_or(CoseError::UnsupportedAlgorithm)?;
    let suite = suite_from_cose_algorithm(recipient_algorithm)?;

    if !reallyme_crypto::operations::constant_time::equal(
        &recipient.protected.header.key_id,
        request.expected_recipient_kid,
    ) {
        return Err(CoseError::KidMismatch);
    }
    let recipient_public_key =
        derive_public_key_from_seed(suite.kem, request.recipient_private_key)?;
    let derived_kid = Zeroizing::new(derive_kid_from_ml_kem_public_key(
        suite.kem.crypto_algorithm(),
        &recipient_public_key,
    )?);
    if !reallyme_crypto::operations::constant_time::equal(
        derived_kid.as_ref(),
        &recipient.protected.header.key_id,
    ) {
        return Err(CoseError::KidMismatch);
    }
    match suite.mode {
        CoseMlKemMode::Direct if recipient.ciphertext.is_some() => {
            return Err(CoseError::InvalidRecipient);
        }
        CoseMlKemMode::KeyWrap if recipient.ciphertext.is_none() => {
            return Err(CoseError::MissingCiphertext);
        }
        CoseMlKemMode::Direct | CoseMlKemMode::KeyWrap => {}
    }

    let encapsulated_key = encapsulated_key(recipient)?;
    if encapsulated_key.len() != suite.encapsulated_key_length {
        return Err(CoseError::InvalidEncapsulatedKey);
    }
    let shared_secret = decapsulate(suite.kem, encapsulated_key, request.recipient_private_key)?;
    let recipient_protected = encode_protected_header(&recipient.protected)?;
    let content_key = match suite.mode {
        CoseMlKemMode::Direct => derive_key(
            &shared_secret,
            content_cose_algorithm as i64,
            content_key_length,
            &recipient_protected,
            request.supp_priv_info,
        )?,
        CoseMlKemMode::KeyWrap => {
            let kek_length = suite.kek_length.ok_or(CoseError::UnsupportedAlgorithm)?;
            let algorithm_id = suite
                .key_wrap_algorithm_id
                .ok_or(CoseError::UnsupportedAlgorithm)?;
            let kek = derive_key(
                &shared_secret,
                algorithm_id,
                kek_length,
                &recipient_protected,
                request.supp_priv_info,
            )?;
            let wrapped = recipient
                .ciphertext
                .as_deref()
                .ok_or(CoseError::MissingCiphertext)?;
            unwrap_content_key(&suite, &kek, wrapped, content_key_length)?
        }
    };

    let body_protected = encode_protected_header(&cose.protected)?;
    let aad = enc_structure(&body_protected, external_aad)?;
    let ciphertext = cose
        .ciphertext
        .as_deref()
        .ok_or(CoseError::MissingCiphertext)?;
    let plaintext = decrypt_content(
        content_algorithm,
        &content_key,
        &cose.unprotected.iv,
        &aad,
        ciphertext,
    )?;
    if plaintext.len() > MAX_PLAINTEXT_BYTES {
        return Err(CoseError::ResourceLimitExceeded);
    }

    Ok(DecryptedCoseEncrypt {
        plaintext,
        content_algorithm,
        kem_algorithm: suite.kem,
        mode: suite.mode,
        kid: Zeroizing::new(recipient.protected.header.key_id.clone()),
        profile: suite.profile,
    })
}

fn validate_request(
    request: &CoseMlKemDecryptRequest<'_>,
    external_aad: &[u8],
) -> Result<(), CoseError> {
    if request.recipient_private_key.len() != ML_KEM_PRIVATE_SEED_LENGTH {
        return Err(CoseError::InvalidKeyMaterial);
    }
    if request.expected_recipient_kid.is_empty() {
        return Err(CoseError::MissingKid);
    }
    if request.expected_recipient_kid.len() > MAX_KID_BYTES
        || external_aad.len() > MAX_EXTERNAL_AAD_BYTES
        || request
            .supp_priv_info
            .is_some_and(|value| value.len() > MAX_SUPP_PRIV_INFO_BYTES)
    {
        return Err(CoseError::ResourceLimitExceeded);
    }
    if request.expected_recipient_kid.len() != ML_KEM_KID_LENGTH {
        return Err(CoseError::KidMismatch);
    }
    Ok(())
}

fn derive_public_key_from_seed(
    algorithm: CoseMlKemAlgorithm,
    private_key: &[u8],
) -> Result<Vec<u8>, CoseError> {
    let seed = <&[u8; ML_KEM_PRIVATE_SEED_LENGTH]>::try_from(private_key)
        .map_err(|_| CoseError::InvalidKeyMaterial)?;
    let (public_key, derived_private_key) = match algorithm {
        CoseMlKemAlgorithm::MlKem512 => {
            reallyme_crypto::ml_kem_512::generate_ml_kem_512_keypair_from_seed(seed)
        }
        CoseMlKemAlgorithm::MlKem768 => {
            reallyme_crypto::ml_kem_768::generate_ml_kem_768_keypair_from_seed(seed)
        }
        CoseMlKemAlgorithm::MlKem1024 => {
            reallyme_crypto::ml_kem_1024::generate_ml_kem_1024_keypair_from_seed(seed)
        }
    }
    .map_err(|_| CoseError::Crypto)?;
    drop(derived_private_key);
    Ok(public_key)
}

fn decapsulate(
    algorithm: CoseMlKemAlgorithm,
    ciphertext: &[u8],
    private_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    match algorithm {
        CoseMlKemAlgorithm::MlKem512 => {
            reallyme_crypto::ml_kem_512::ml_kem_512_decapsulate(ciphertext, private_key)
        }
        CoseMlKemAlgorithm::MlKem768 => {
            reallyme_crypto::ml_kem_768::ml_kem_768_decapsulate(ciphertext, private_key)
        }
        CoseMlKemAlgorithm::MlKem1024 => {
            reallyme_crypto::ml_kem_1024::ml_kem_1024_decapsulate(ciphertext, private_key)
        }
    }
    .map_err(|_| CoseError::Crypto)
}

fn unwrap_content_key(
    suite: &MlKemSuite,
    kek: &[u8],
    wrapped: &[u8],
    expected_length: usize,
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    let unwrapped = match suite.kem {
        CoseMlKemAlgorithm::MlKem512 => {
            let key = Aes128KwKek::from_slice(kek).map_err(|_| CoseError::Crypto)?;
            unwrap_key_aes128(&key, wrapped)
        }
        CoseMlKemAlgorithm::MlKem768 => {
            let key = Aes192KwKek::from_slice(kek).map_err(|_| CoseError::Crypto)?;
            unwrap_key_aes192(&key, wrapped)
        }
        CoseMlKemAlgorithm::MlKem1024 => {
            let key = Aes256KwKek::from_slice(kek).map_err(|_| CoseError::Crypto)?;
            unwrap_key_aes256(&key, wrapped)
        }
    }
    .map_err(key_unwrap_error_from_crypto_error)?;
    if unwrapped.len() != expected_length {
        return Err(CoseError::InvalidRecipient);
    }
    Ok(unwrapped.into_zeroizing())
}

fn decrypt_content(
    algorithm: CoseContentEncryptionAlgorithm,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    if ciphertext.len() < AES_GCM_TAG_LENGTH {
        return Err(CoseError::InvalidFormat);
    }
    let ciphertext =
        CiphertextWithTag::from_vec(ciphertext.to_vec()).map_err(|_| CoseError::InvalidFormat)?;
    let result = match algorithm {
        CoseContentEncryptionAlgorithm::Aes128Gcm => {
            let key = Aes128GcmKey::from_slice(key).map_err(|_| CoseError::Crypto)?;
            let nonce = Aes128GcmNonce::from_slice(nonce).map_err(|_| CoseError::InvalidIv)?;
            decrypt_aes128_gcm(&Aes128GcmDecryptRequest {
                key: &key,
                nonce,
                aad,
                ciphertext: &ciphertext,
            })
        }
        CoseContentEncryptionAlgorithm::Aes192Gcm => {
            let key = Aes192GcmKey::from_slice(key).map_err(|_| CoseError::Crypto)?;
            let nonce = Aes192GcmNonce::from_slice(nonce).map_err(|_| CoseError::InvalidIv)?;
            decrypt_aes192_gcm(&Aes192GcmDecryptRequest {
                key: &key,
                nonce,
                aad,
                ciphertext: &ciphertext,
            })
        }
        CoseContentEncryptionAlgorithm::Aes256Gcm => {
            let key = Aes256GcmKey::from_slice(key).map_err(|_| CoseError::Crypto)?;
            let nonce = Aes256GcmNonce::from_slice(nonce).map_err(|_| CoseError::InvalidIv)?;
            decrypt(&DecryptRequest {
                key: &key,
                nonce,
                aad,
                ciphertext: &ciphertext,
            })
        }
    };
    result
        .map(Zeroizing::new)
        .map_err(decrypt_error_from_crypto_error)
}
