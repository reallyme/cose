// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use coset::{CoseEncrypt, CoseRecipient, RegisteredLabelWithPrivate};
use reallyme_crypto::aes::{
    encrypt, encrypt_aes128_gcm, encrypt_aes192_gcm, Aes128GcmEncryptRequest, Aes128GcmKey,
    Aes128GcmNonce, Aes192GcmEncryptRequest, Aes192GcmKey, Aes192GcmNonce, Aes256GcmKey,
    Aes256GcmNonce, EncryptRequest,
};
use reallyme_crypto::aes_kw::{
    wrap_key_aes128, wrap_key_aes192, wrap_key_aes256, Aes128KwKek, Aes192KwKek, Aes256KwKek,
};
use reallyme_crypto::core::RngOutputKind;
use reallyme_crypto::csprng::{generate_aead_nonce_12, OsSecureRandom, SecureRandom};
use zeroize::{Zeroize, Zeroizing};

use crate::encode_cbor::encode_protected_header;
use crate::failure::CoseFailure;
use crate::key::derive_kid_from_ml_kem_public_key;
use crate::CoseError;

use super::codec::{
    body_unprotected, encode, protected_header, recipient_unprotected, AES_GCM_NONCE_LENGTH,
    MAX_EXTERNAL_AAD_BYTES, MAX_KID_BYTES, MAX_PLAINTEXT_BYTES, MAX_SUPP_PRIV_INFO_BYTES,
};
use super::kdf::{derive_key, enc_structure};
use super::profile::{content_algorithm_profile, suite_for, MlKemSuite, ML_KEM_KID_LENGTH};
use super::types::{
    CoseContentEncryptionAlgorithm, CoseMlKemAlgorithm, CoseMlKemEncryptInput,
    CoseMlKemEncryptRequest, CoseMlKemMode,
};

#[must_use]
pub(crate) struct CoseMlKemEncryptOutput {
    cose_encrypt: Zeroizing<Vec<u8>>,
}

impl CoseMlKemEncryptOutput {
    pub(crate) fn into_zeroizing(self) -> Zeroizing<Vec<u8>> {
        self.cose_encrypt
    }
}

/// Encrypts using the direct ReallyMe ML-KEM COSE profile with empty external AAD.
///
/// # Errors
///
/// Returns [`CoseError`] for unsupported algorithms, invalid keys or identifiers,
/// oversized inputs, entropy failure, cryptographic failure, or encoding failure.
pub fn cose_encrypt_ml_kem_direct(
    request: &CoseMlKemEncryptRequest<'_>,
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    cose_encrypt_ml_kem_direct_with_external_aad(request, &[])
}

/// Encrypts using the direct ReallyMe ML-KEM COSE profile and external AAD.
///
/// # Errors
///
/// Returns [`CoseError`] for unsupported algorithms, invalid keys or identifiers,
/// oversized inputs, entropy failure, cryptographic failure, or encoding failure.
pub fn cose_encrypt_ml_kem_direct_with_external_aad(
    request: &CoseMlKemEncryptRequest<'_>,
    external_aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    encrypt_cose_ml_kem_direct(CoseMlKemEncryptInput::new(request, external_aad))
        .map(CoseMlKemEncryptOutput::into_zeroizing)
        .map_err(CoseFailure::into_native_error)
}

/// Encrypts using the AES-KW ReallyMe ML-KEM COSE profile with empty external AAD.
///
/// # Errors
///
/// Returns [`CoseError`] for unsupported algorithms, invalid keys or identifiers,
/// oversized inputs, entropy failure, cryptographic failure, or encoding failure.
pub fn cose_encrypt_ml_kem_key_wrap(
    request: &CoseMlKemEncryptRequest<'_>,
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    cose_encrypt_ml_kem_key_wrap_with_external_aad(request, &[])
}

/// Encrypts using the AES-KW ReallyMe ML-KEM COSE profile and external AAD.
///
/// # Errors
///
/// Returns [`CoseError`] for unsupported algorithms, invalid keys or identifiers,
/// oversized inputs, entropy failure, cryptographic failure, or encoding failure.
pub fn cose_encrypt_ml_kem_key_wrap_with_external_aad(
    request: &CoseMlKemEncryptRequest<'_>,
    external_aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    encrypt_cose_ml_kem_key_wrap(CoseMlKemEncryptInput::new(request, external_aad))
        .map(CoseMlKemEncryptOutput::into_zeroizing)
        .map_err(CoseFailure::into_native_error)
}

pub(crate) fn encrypt_cose_ml_kem_direct(
    input: CoseMlKemEncryptInput<'_, '_>,
) -> Result<CoseMlKemEncryptOutput, CoseFailure> {
    encrypt_ml_kem(input.request, CoseMlKemMode::Direct, input.external_aad)
        .map(|cose_encrypt| CoseMlKemEncryptOutput { cose_encrypt })
        .map_err(CoseFailure::from_encrypt_error)
}

pub(crate) fn encrypt_cose_ml_kem_key_wrap(
    input: CoseMlKemEncryptInput<'_, '_>,
) -> Result<CoseMlKemEncryptOutput, CoseFailure> {
    encrypt_ml_kem(input.request, CoseMlKemMode::KeyWrap, input.external_aad)
        .map(|cose_encrypt| CoseMlKemEncryptOutput { cose_encrypt })
        .map_err(CoseFailure::from_encrypt_error)
}

fn encrypt_ml_kem(
    request: &CoseMlKemEncryptRequest<'_>,
    mode: CoseMlKemMode,
    external_aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    validate_request(request, external_aad)?;
    let suite = suite_for(request.kem_algorithm, mode)?;
    if request.recipient_public_key.len() != suite.public_key_length {
        return Err(CoseError::InvalidKeyMaterial);
    }
    let (encapsulated_key, shared_secret) = encapsulate(suite.kem, request.recipient_public_key)?;
    if encapsulated_key.len() != suite.encapsulated_key_length {
        return Err(CoseError::Crypto);
    }
    let expected_kid = Zeroizing::new(derive_kid_from_ml_kem_public_key(
        suite.kem.crypto_algorithm(),
        request.recipient_public_key,
    )?);
    if !reallyme_crypto::operations::constant_time::equal(
        expected_kid.as_ref(),
        request.recipient_kid,
    ) {
        return Err(CoseError::KidMismatch);
    }

    let recipient_protected = protected_header(
        RegisteredLabelWithPrivate::PrivateUse(suite.cose_algorithm),
        Some(request.recipient_kid),
    );
    let recipient_protected_bytes = encode_protected_header(&recipient_protected)?;
    let (content_cose_algorithm, _, content_key_length) =
        content_algorithm_profile(request.content_algorithm);

    let mut rng = OsSecureRandom;
    let (content_key, recipient_ciphertext) = match suite.mode {
        CoseMlKemMode::Direct => (
            derive_key(
                &shared_secret,
                content_cose_algorithm as i64,
                content_key_length,
                &recipient_protected_bytes,
                request.supp_priv_info,
            )?,
            None,
        ),
        CoseMlKemMode::KeyWrap => {
            let kek_length = suite.kek_length.ok_or(CoseError::UnsupportedAlgorithm)?;
            let algorithm_id = suite
                .key_wrap_algorithm_id
                .ok_or(CoseError::UnsupportedAlgorithm)?;
            let kek = derive_key(
                &shared_secret,
                algorithm_id,
                kek_length,
                &recipient_protected_bytes,
                request.supp_priv_info,
            )?;
            let mut content_key = Zeroizing::new(vec![0u8; content_key_length]);
            rng.fill_secure(&mut content_key, RngOutputKind::Generic)
                .map_err(|_| CoseError::Crypto)?;
            let wrapped = wrap_content_key(&suite, &kek, &content_key)?;
            (content_key, Some(wrapped))
        }
    };

    let nonce = generate_aead_nonce_12(&mut rng).map_err(|_| CoseError::Crypto)?;
    let body_protected = protected_header(
        RegisteredLabelWithPrivate::Assigned(content_cose_algorithm),
        None,
    );
    let body_protected_bytes = encode_protected_header(&body_protected)?;
    let aad = enc_structure(&body_protected_bytes, external_aad)?;
    let ciphertext = encrypt_content(
        request.content_algorithm,
        &content_key,
        nonce.as_bytes(),
        &aad,
        request.plaintext,
    )?;

    let recipient = CoseRecipient {
        protected: recipient_protected,
        unprotected: recipient_unprotected(encapsulated_key),
        ciphertext: recipient_ciphertext,
        recipients: Vec::new(),
    };
    let cose = CoseEncrypt {
        protected: body_protected,
        unprotected: body_unprotected(nonce.as_bytes()),
        ciphertext: Some(ciphertext),
        recipients: vec![recipient],
    };
    encode(cose)
}

fn validate_request(
    request: &CoseMlKemEncryptRequest<'_>,
    external_aad: &[u8],
) -> Result<(), CoseError> {
    if request.plaintext.len() > MAX_PLAINTEXT_BYTES
        || external_aad.len() > MAX_EXTERNAL_AAD_BYTES
        || request
            .supp_priv_info
            .is_some_and(|value| value.len() > MAX_SUPP_PRIV_INFO_BYTES)
    {
        return Err(CoseError::ResourceLimitExceeded);
    }
    if request.recipient_kid.is_empty() {
        return Err(CoseError::MissingKid);
    }
    if request.recipient_kid.len() > MAX_KID_BYTES {
        return Err(CoseError::ResourceLimitExceeded);
    }
    if request.recipient_kid.len() != ML_KEM_KID_LENGTH {
        return Err(CoseError::KidMismatch);
    }
    Ok(())
}

fn encapsulate(
    algorithm: CoseMlKemAlgorithm,
    public_key: &[u8],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CoseError> {
    match algorithm {
        CoseMlKemAlgorithm::MlKem512 => {
            reallyme_crypto::ml_kem_512::ml_kem_512_encapsulate(public_key)
        }
        CoseMlKemAlgorithm::MlKem768 => {
            reallyme_crypto::ml_kem_768::ml_kem_768_encapsulate(public_key)
        }
        CoseMlKemAlgorithm::MlKem1024 => {
            reallyme_crypto::ml_kem_1024::ml_kem_1024_encapsulate(public_key)
        }
    }
    .map_err(|error| match error {
        reallyme_crypto::core::CryptoError::InvalidKey => CoseError::InvalidKeyMaterial,
        _ => CoseError::Crypto,
    })
}

fn wrap_content_key(
    suite: &MlKemSuite,
    kek: &[u8],
    content_key: &[u8],
) -> Result<Vec<u8>, CoseError> {
    let wrapped = match suite.kem {
        CoseMlKemAlgorithm::MlKem512 => {
            let key = Aes128KwKek::from_slice(kek).map_err(|_| CoseError::Crypto)?;
            wrap_key_aes128(&key, content_key)
        }
        CoseMlKemAlgorithm::MlKem768 => {
            let key = Aes192KwKek::from_slice(kek).map_err(|_| CoseError::Crypto)?;
            wrap_key_aes192(&key, content_key)
        }
        CoseMlKemAlgorithm::MlKem1024 => {
            let key = Aes256KwKek::from_slice(kek).map_err(|_| CoseError::Crypto)?;
            wrap_key_aes256(&key, content_key)
        }
    }
    .map_err(|_| CoseError::Crypto)?;
    Ok(wrapped.into_vec())
}

fn encrypt_content(
    algorithm: CoseContentEncryptionAlgorithm,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CoseError> {
    if nonce.len() != AES_GCM_NONCE_LENGTH {
        return Err(CoseError::InvalidIv);
    }
    let result = match algorithm {
        CoseContentEncryptionAlgorithm::Aes128Gcm => {
            let key = Aes128GcmKey::from_slice(key).map_err(|_| CoseError::Crypto)?;
            let nonce = Aes128GcmNonce::from_slice(nonce).map_err(|_| CoseError::InvalidIv)?;
            encrypt_aes128_gcm(&Aes128GcmEncryptRequest {
                key: &key,
                nonce,
                aad,
                plaintext,
            })
        }
        CoseContentEncryptionAlgorithm::Aes192Gcm => {
            let key = Aes192GcmKey::from_slice(key).map_err(|_| CoseError::Crypto)?;
            let nonce = Aes192GcmNonce::from_slice(nonce).map_err(|_| CoseError::InvalidIv)?;
            encrypt_aes192_gcm(&Aes192GcmEncryptRequest {
                key: &key,
                nonce,
                aad,
                plaintext,
            })
        }
        CoseContentEncryptionAlgorithm::Aes256Gcm => {
            let key = Aes256GcmKey::from_slice(key).map_err(|_| CoseError::Crypto)?;
            let nonce = Aes256GcmNonce::from_slice(nonce).map_err(|_| CoseError::InvalidIv)?;
            encrypt(&EncryptRequest {
                key: &key,
                nonce,
                aad,
                plaintext,
            })
        }
    }
    .map_err(|_| CoseError::Crypto)?;
    let mut ciphertext = result.into_vec();
    let expected_length = plaintext
        .len()
        .checked_add(super::codec::AES_GCM_TAG_LENGTH)
        .ok_or(CoseError::ResourceLimitExceeded)?;
    if ciphertext.len() != expected_length {
        ciphertext.zeroize();
        return Err(CoseError::Crypto);
    }
    Ok(ciphertext)
}
