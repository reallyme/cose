// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use coset::{iana, RegisteredLabelWithPrivate};
use reallyme_crypto::core::AeadAlgorithm;

use crate::algorithm::{
    REALLYME_COSE_ALG_ML_KEM_1024, REALLYME_COSE_ALG_ML_KEM_1024_A256KW,
    REALLYME_COSE_ALG_ML_KEM_512, REALLYME_COSE_ALG_ML_KEM_512_A128KW,
    REALLYME_COSE_ALG_ML_KEM_768, REALLYME_COSE_ALG_ML_KEM_768_A192KW,
};
use crate::CoseError;

use super::types::{
    CoseContentEncryptionAlgorithm, CoseMlKemAlgorithm, CoseMlKemMode, CoseMlKemProfile,
};

pub(crate) const ML_KEM_PRIVATE_SEED_LENGTH: usize = 64;
pub(crate) const ML_KEM_KID_LENGTH: usize = 32;
pub(crate) const ML_KEM_512_PUBLIC_KEY_LENGTH: usize = 800;
pub(crate) const ML_KEM_768_PUBLIC_KEY_LENGTH: usize = 1_184;
pub(crate) const ML_KEM_1024_PUBLIC_KEY_LENGTH: usize = 1_568;
pub(crate) const ML_KEM_512_CIPHERTEXT_LENGTH: usize = 768;
pub(crate) const ML_KEM_768_CIPHERTEXT_LENGTH: usize = 1_088;
pub(crate) const ML_KEM_1024_CIPHERTEXT_LENGTH: usize = 1_568;

#[derive(Clone, Copy)]
pub(crate) struct MlKemSuite {
    pub(crate) profile: CoseMlKemProfile,
    pub(crate) mode: CoseMlKemMode,
    pub(crate) kem: CoseMlKemAlgorithm,
    pub(crate) cose_algorithm: i64,
    pub(crate) kek_length: Option<usize>,
    pub(crate) key_wrap_algorithm_id: Option<i64>,
    pub(crate) public_key_length: usize,
    pub(crate) encapsulated_key_length: usize,
}

pub(crate) fn suite_for(
    kem: CoseMlKemAlgorithm,
    mode: CoseMlKemMode,
) -> Result<MlKemSuite, CoseError> {
    let (
        cose_algorithm,
        kek_length,
        key_wrap_algorithm_id,
        public_key_length,
        encapsulated_key_length,
    ) = match (kem, mode) {
        (CoseMlKemAlgorithm::MlKem512, CoseMlKemMode::Direct) => (
            REALLYME_COSE_ALG_ML_KEM_512,
            None,
            None,
            ML_KEM_512_PUBLIC_KEY_LENGTH,
            ML_KEM_512_CIPHERTEXT_LENGTH,
        ),
        (CoseMlKemAlgorithm::MlKem768, CoseMlKemMode::Direct) => (
            REALLYME_COSE_ALG_ML_KEM_768,
            None,
            None,
            ML_KEM_768_PUBLIC_KEY_LENGTH,
            ML_KEM_768_CIPHERTEXT_LENGTH,
        ),
        (CoseMlKemAlgorithm::MlKem1024, CoseMlKemMode::Direct) => (
            REALLYME_COSE_ALG_ML_KEM_1024,
            None,
            None,
            ML_KEM_1024_PUBLIC_KEY_LENGTH,
            ML_KEM_1024_CIPHERTEXT_LENGTH,
        ),
        (CoseMlKemAlgorithm::MlKem512, CoseMlKemMode::KeyWrap) => (
            REALLYME_COSE_ALG_ML_KEM_512_A128KW,
            Some(16),
            Some(iana::Algorithm::A128KW as i64),
            ML_KEM_512_PUBLIC_KEY_LENGTH,
            ML_KEM_512_CIPHERTEXT_LENGTH,
        ),
        (CoseMlKemAlgorithm::MlKem768, CoseMlKemMode::KeyWrap) => (
            REALLYME_COSE_ALG_ML_KEM_768_A192KW,
            Some(24),
            Some(iana::Algorithm::A192KW as i64),
            ML_KEM_768_PUBLIC_KEY_LENGTH,
            ML_KEM_768_CIPHERTEXT_LENGTH,
        ),
        (CoseMlKemAlgorithm::MlKem1024, CoseMlKemMode::KeyWrap) => (
            REALLYME_COSE_ALG_ML_KEM_1024_A256KW,
            Some(32),
            Some(iana::Algorithm::A256KW as i64),
            ML_KEM_1024_PUBLIC_KEY_LENGTH,
            ML_KEM_1024_CIPHERTEXT_LENGTH,
        ),
    };

    Ok(MlKemSuite {
        profile: CoseMlKemProfile::ReallyMeV1,
        mode,
        kem,
        cose_algorithm,
        kek_length,
        key_wrap_algorithm_id,
        public_key_length,
        encapsulated_key_length,
    })
}

pub(crate) fn suite_from_cose_algorithm(
    algorithm: &RegisteredLabelWithPrivate<iana::Algorithm>,
) -> Result<MlKemSuite, CoseError> {
    let value = match algorithm {
        RegisteredLabelWithPrivate::PrivateUse(value) => *value,
        RegisteredLabelWithPrivate::Assigned(_) | RegisteredLabelWithPrivate::Text(_) => {
            return Err(CoseError::UnsupportedAlgorithm);
        }
    };

    match value {
        REALLYME_COSE_ALG_ML_KEM_512 => {
            suite_for(CoseMlKemAlgorithm::MlKem512, CoseMlKemMode::Direct)
        }
        REALLYME_COSE_ALG_ML_KEM_768 => {
            suite_for(CoseMlKemAlgorithm::MlKem768, CoseMlKemMode::Direct)
        }
        REALLYME_COSE_ALG_ML_KEM_1024 => {
            suite_for(CoseMlKemAlgorithm::MlKem1024, CoseMlKemMode::Direct)
        }
        REALLYME_COSE_ALG_ML_KEM_512_A128KW => {
            suite_for(CoseMlKemAlgorithm::MlKem512, CoseMlKemMode::KeyWrap)
        }
        REALLYME_COSE_ALG_ML_KEM_768_A192KW => {
            suite_for(CoseMlKemAlgorithm::MlKem768, CoseMlKemMode::KeyWrap)
        }
        REALLYME_COSE_ALG_ML_KEM_1024_A256KW => {
            suite_for(CoseMlKemAlgorithm::MlKem1024, CoseMlKemMode::KeyWrap)
        }
        _ => Err(CoseError::UnsupportedAlgorithm),
    }
}

pub(crate) fn content_algorithm_profile(
    algorithm: CoseContentEncryptionAlgorithm,
) -> (iana::Algorithm, AeadAlgorithm, usize) {
    match algorithm {
        CoseContentEncryptionAlgorithm::Aes128Gcm => {
            (iana::Algorithm::A128GCM, AeadAlgorithm::Aes128Gcm, 16)
        }
        CoseContentEncryptionAlgorithm::Aes192Gcm => {
            (iana::Algorithm::A192GCM, AeadAlgorithm::Aes192Gcm, 24)
        }
        CoseContentEncryptionAlgorithm::Aes256Gcm => {
            (iana::Algorithm::A256GCM, AeadAlgorithm::Aes256Gcm, 32)
        }
    }
}

pub(crate) fn content_algorithm_from_cose(
    algorithm: &RegisteredLabelWithPrivate<iana::Algorithm>,
) -> Result<CoseContentEncryptionAlgorithm, CoseError> {
    match algorithm {
        RegisteredLabelWithPrivate::Assigned(iana::Algorithm::A128GCM) => {
            Ok(CoseContentEncryptionAlgorithm::Aes128Gcm)
        }
        RegisteredLabelWithPrivate::Assigned(iana::Algorithm::A192GCM) => {
            Ok(CoseContentEncryptionAlgorithm::Aes192Gcm)
        }
        RegisteredLabelWithPrivate::Assigned(iana::Algorithm::A256GCM) => {
            Ok(CoseContentEncryptionAlgorithm::Aes256Gcm)
        }
        _ => Err(CoseError::UnsupportedAlgorithm),
    }
}
