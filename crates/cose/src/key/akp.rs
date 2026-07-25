// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Additional-key-type COSE_Key profiles for ML-DSA and ML-KEM.

use ciborium::value::Value;
use coset::{iana, CoseKeyBuilder, MlDsaVariant, RegisteredLabelWithPrivate};
use reallyme_crypto::core::Algorithm;

use crate::algorithm::{
    REALLYME_COSE_ALG_ML_KEM_1024, REALLYME_COSE_ALG_ML_KEM_512, REALLYME_COSE_ALG_ML_KEM_768,
};
use crate::CoseError;

const ML_DSA_PRIVATE_SEED_BYTES: usize = 32;
const ML_DSA_44_PUBLIC_KEY_BYTES: usize = 1_312;
const ML_DSA_65_PUBLIC_KEY_BYTES: usize = 1_952;
const ML_DSA_87_PUBLIC_KEY_BYTES: usize = 2_592;
const ML_KEM_PRIVATE_SEED_BYTES: usize = 64;
const ML_KEM_512_PUBLIC_KEY_BYTES: usize = 800;
const ML_KEM_768_PUBLIC_KEY_BYTES: usize = 1_184;
const ML_KEM_1024_PUBLIC_KEY_BYTES: usize = 1_568;

#[derive(Clone, Copy)]
pub(crate) struct AkpProfile {
    pub(crate) algorithm: Algorithm,
    pub(crate) public_key_len: usize,
    pub(crate) private_key_len: usize,
    pub(crate) is_signature: bool,
}

pub(crate) fn akp_profile(algorithm: Algorithm) -> Result<AkpProfile, CoseError> {
    match algorithm {
        Algorithm::MlDsa44 => Ok(AkpProfile {
            algorithm,
            public_key_len: ML_DSA_44_PUBLIC_KEY_BYTES,
            private_key_len: ML_DSA_PRIVATE_SEED_BYTES,
            is_signature: true,
        }),
        Algorithm::MlDsa65 => Ok(AkpProfile {
            algorithm,
            public_key_len: ML_DSA_65_PUBLIC_KEY_BYTES,
            private_key_len: ML_DSA_PRIVATE_SEED_BYTES,
            is_signature: true,
        }),
        Algorithm::MlDsa87 => Ok(AkpProfile {
            algorithm,
            public_key_len: ML_DSA_87_PUBLIC_KEY_BYTES,
            private_key_len: ML_DSA_PRIVATE_SEED_BYTES,
            is_signature: true,
        }),
        Algorithm::MlKem512 => Ok(AkpProfile {
            algorithm,
            public_key_len: ML_KEM_512_PUBLIC_KEY_BYTES,
            private_key_len: ML_KEM_PRIVATE_SEED_BYTES,
            is_signature: false,
        }),
        Algorithm::MlKem768 => Ok(AkpProfile {
            algorithm,
            public_key_len: ML_KEM_768_PUBLIC_KEY_BYTES,
            private_key_len: ML_KEM_PRIVATE_SEED_BYTES,
            is_signature: false,
        }),
        Algorithm::MlKem1024 => Ok(AkpProfile {
            algorithm,
            public_key_len: ML_KEM_1024_PUBLIC_KEY_BYTES,
            private_key_len: ML_KEM_PRIVATE_SEED_BYTES,
            is_signature: false,
        }),
        _ => Err(CoseError::UnsupportedAlgorithm),
    }
}

pub(crate) fn akp_profile_from_cose_algorithm(
    algorithm: &RegisteredLabelWithPrivate<iana::Algorithm>,
) -> Result<AkpProfile, CoseError> {
    match algorithm {
        RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ML_DSA_44) => {
            akp_profile(Algorithm::MlDsa44)
        }
        RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ML_DSA_65) => {
            akp_profile(Algorithm::MlDsa65)
        }
        RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ML_DSA_87) => {
            akp_profile(Algorithm::MlDsa87)
        }
        RegisteredLabelWithPrivate::PrivateUse(REALLYME_COSE_ALG_ML_KEM_512) => {
            akp_profile(Algorithm::MlKem512)
        }
        RegisteredLabelWithPrivate::PrivateUse(REALLYME_COSE_ALG_ML_KEM_768) => {
            akp_profile(Algorithm::MlKem768)
        }
        RegisteredLabelWithPrivate::PrivateUse(REALLYME_COSE_ALG_ML_KEM_1024) => {
            akp_profile(Algorithm::MlKem1024)
        }
        _ => Err(CoseError::UnsupportedAlgorithm),
    }
}

pub(crate) const fn algorithm_for_akp_profile(profile: AkpProfile) -> Algorithm {
    profile.algorithm
}

pub(crate) fn akp_key(
    algorithm: Algorithm,
    public_key: &[u8],
    private_key: Option<&[u8]>,
) -> Result<coset::CoseKey, CoseError> {
    if matches!(
        algorithm,
        Algorithm::MlDsa44 | Algorithm::MlDsa65 | Algorithm::MlDsa87
    ) {
        let mut builder =
            CoseKeyBuilder::new_mldsa_pub_key(ml_dsa_variant(algorithm)?, public_key.to_vec());
        if let Some(private_key) = private_key {
            builder = builder.param(
                iana::AkpKeyParameter::Priv as i64,
                Value::Bytes(private_key.to_vec()),
            );
        }
        return Ok(builder.build());
    }

    let mut builder = CoseKeyBuilder::new_okp_key()
        .key_type(iana::KeyType::AKP)
        .param(
            iana::AkpKeyParameter::Pub as i64,
            Value::Bytes(public_key.to_vec()),
        );
    if let Some(private_key) = private_key {
        builder = builder.param(
            iana::AkpKeyParameter::Priv as i64,
            Value::Bytes(private_key.to_vec()),
        );
    }
    let mut key = builder.build();
    key.alg = Some(RegisteredLabelWithPrivate::PrivateUse(
        ml_kem_cose_algorithm(algorithm)?,
    ));
    Ok(key)
}

fn ml_dsa_variant(algorithm: Algorithm) -> Result<MlDsaVariant, CoseError> {
    match algorithm {
        Algorithm::MlDsa44 => Ok(MlDsaVariant::MlDsa44),
        Algorithm::MlDsa65 => Ok(MlDsaVariant::MlDsa65),
        Algorithm::MlDsa87 => Ok(MlDsaVariant::MlDsa87),
        _ => Err(CoseError::UnsupportedAlgorithm),
    }
}

fn ml_kem_cose_algorithm(algorithm: Algorithm) -> Result<i64, CoseError> {
    match algorithm {
        Algorithm::MlKem512 => Ok(REALLYME_COSE_ALG_ML_KEM_512),
        Algorithm::MlKem768 => Ok(REALLYME_COSE_ALG_ML_KEM_768),
        Algorithm::MlKem1024 => Ok(REALLYME_COSE_ALG_ML_KEM_1024),
        _ => Err(CoseError::UnsupportedAlgorithm),
    }
}
