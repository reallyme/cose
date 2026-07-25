// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Backend-assisted validation for raw public and private key material.

use reallyme_crypto::core::Algorithm;
#[cfg(feature = "cose-crypto")]
use reallyme_crypto::core::CryptoError;
#[cfg(feature = "cose-crypto")]
use reallyme_crypto::dispatch::{derive_shared_secret, sign, verify};
#[cfg(feature = "cose-crypto")]
use zeroize::{Zeroize, Zeroizing};

#[cfg(feature = "cose-crypto")]
use crate::error::{sign_error_from_algorithm_error, verify_error_from_algorithm_error};
use crate::CoseError;

#[cfg(feature = "cose-crypto")]
use super::reject_weak_public_key::reject_weak_public_key;

#[cfg(feature = "cose-crypto")]
const KEY_VALIDATION_MESSAGE: &[u8] = b"ReallyMe COSE key validation v1";
#[cfg(feature = "cose-crypto")]
const ECDSA_VALIDATION_SIGNATURE_DER: &[u8] = &[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
#[cfg(feature = "cose-crypto")]
const SECP256K1_VALIDATION_SIGNATURE_BYTES: usize = 64;
#[cfg(feature = "cose-crypto")]
const ED25519_VALIDATION_SIGNATURE_BYTES: usize = 64;
#[cfg(feature = "cose-crypto")]
const ML_DSA_44_SIGNATURE_BYTES: usize = 2_420;
#[cfg(feature = "cose-crypto")]
const ML_DSA_65_SIGNATURE_BYTES: usize = 3_309;
#[cfg(feature = "cose-crypto")]
const ML_DSA_87_SIGNATURE_BYTES: usize = 4_627;
#[cfg(feature = "cose-crypto")]
const X25519_PUBLIC_KEY_BYTES: usize = 32;
#[cfg(feature = "cose-crypto")]
const X25519_VALIDATION_SECRET: [u8; X25519_PUBLIC_KEY_BYTES] = [0x42; X25519_PUBLIC_KEY_BYTES];

#[cfg(feature = "cose-crypto")]
pub(crate) fn validate_public_key(
    algorithm: Algorithm,
    public_key: &[u8],
) -> Result<(), CoseError> {
    reject_weak_public_key(algorithm, public_key)?;

    if algorithm == Algorithm::X25519 {
        return match derive_shared_secret(algorithm, &X25519_VALIDATION_SECRET, public_key) {
            Ok(mut shared_secret) => {
                shared_secret.zeroize();
                Ok(())
            }
            Err(error) => match sign_error_from_algorithm_error(error) {
                CoseError::ProviderUnavailable => Err(CoseError::ProviderUnavailable),
                CoseError::UnsupportedAlgorithm => Err(CoseError::UnsupportedAlgorithm),
                _ => Err(CoseError::InvalidKeyMaterial),
            },
        };
    }

    if matches!(
        algorithm,
        Algorithm::MlKem512 | Algorithm::MlKem768 | Algorithm::MlKem1024
    ) {
        let (_, shared_secret) = ml_kem_encapsulate(algorithm, public_key)?;
        drop(shared_secret);
        return Ok(());
    }

    let mut signature = match algorithm {
        Algorithm::Ed25519 => Zeroizing::new(vec![0u8; ED25519_VALIDATION_SIGNATURE_BYTES]),
        Algorithm::P256 | Algorithm::P384 | Algorithm::P521 => {
            Zeroizing::new(ECDSA_VALIDATION_SIGNATURE_DER.to_vec())
        }
        // The secp256k1 backend accepts compact r||s, unlike the NIST-curve
        // backends' DER input. A correctly shaped dummy reaches public-key
        // parsing before failing signature validation.
        Algorithm::Secp256k1 => Zeroizing::new(vec![0u8; SECP256K1_VALIDATION_SIGNATURE_BYTES]),
        Algorithm::MlDsa44 => Zeroizing::new(vec![0u8; ML_DSA_44_SIGNATURE_BYTES]),
        Algorithm::MlDsa65 => Zeroizing::new(vec![0u8; ML_DSA_65_SIGNATURE_BYTES]),
        Algorithm::MlDsa87 => Zeroizing::new(vec![0u8; ML_DSA_87_SIGNATURE_BYTES]),
        _ => return Err(CoseError::UnsupportedAlgorithm),
    };
    let result = verify(algorithm, public_key, KEY_VALIDATION_MESSAGE, &signature);
    signature.zeroize();
    match result {
        Ok(()) => Ok(()),
        Err(error) => match verify_error_from_algorithm_error(error) {
            CoseError::InvalidSignature => Ok(()),
            other => Err(other),
        },
    }
}

#[cfg(not(feature = "cose-crypto"))]
pub(crate) fn validate_public_key(_: Algorithm, _: &[u8]) -> Result<(), CoseError> {
    Err(CoseError::UnsupportedAlgorithm)
}

#[cfg(feature = "cose-crypto")]
pub(crate) fn validate_private_public_pair(
    algorithm: Algorithm,
    private_key: &[u8],
    public_key: &[u8],
) -> Result<(), CoseError> {
    if matches!(
        algorithm,
        Algorithm::MlKem512 | Algorithm::MlKem768 | Algorithm::MlKem1024
    ) {
        let (ciphertext, encapsulated_secret) = ml_kem_encapsulate(algorithm, public_key)?;
        let decapsulated_secret = ml_kem_decapsulate(algorithm, &ciphertext, private_key)?;
        if reallyme_crypto::operations::constant_time::equal(
            &encapsulated_secret,
            &decapsulated_secret,
        ) {
            return Ok(());
        }
        return Err(CoseError::InvalidKeyMaterial);
    }

    let mut signature = Zeroizing::new(
        sign(algorithm, private_key, KEY_VALIDATION_MESSAGE)
            .map_err(sign_error_from_algorithm_error)?,
    );
    let verification = verify(algorithm, public_key, KEY_VALIDATION_MESSAGE, &signature)
        .map_err(verify_error_from_algorithm_error);
    signature.zeroize();
    match verification {
        Err(CoseError::InvalidSignature) => Err(CoseError::InvalidKeyMaterial),
        result => result,
    }
}

#[cfg(not(feature = "cose-crypto"))]
pub(crate) fn validate_private_public_pair(
    _: Algorithm,
    _: &[u8],
    _: &[u8],
) -> Result<(), CoseError> {
    Err(CoseError::UnsupportedAlgorithm)
}

#[cfg(feature = "cose-crypto")]
fn ml_kem_encapsulate(
    algorithm: Algorithm,
    public_key: &[u8],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), CoseError> {
    match algorithm {
        Algorithm::MlKem512 => reallyme_crypto::ml_kem_512::ml_kem_512_encapsulate(public_key),
        Algorithm::MlKem768 => reallyme_crypto::ml_kem_768::ml_kem_768_encapsulate(public_key),
        Algorithm::MlKem1024 => reallyme_crypto::ml_kem_1024::ml_kem_1024_encapsulate(public_key),
        _ => return Err(CoseError::UnsupportedAlgorithm),
    }
    .map_err(ml_kem_key_operation_error)
}

#[cfg(feature = "cose-crypto")]
fn ml_kem_decapsulate(
    algorithm: Algorithm,
    ciphertext: &[u8],
    private_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    match algorithm {
        Algorithm::MlKem512 => {
            reallyme_crypto::ml_kem_512::ml_kem_512_decapsulate(ciphertext, private_key)
        }
        Algorithm::MlKem768 => {
            reallyme_crypto::ml_kem_768::ml_kem_768_decapsulate(ciphertext, private_key)
        }
        Algorithm::MlKem1024 => {
            reallyme_crypto::ml_kem_1024::ml_kem_1024_decapsulate(ciphertext, private_key)
        }
        _ => return Err(CoseError::UnsupportedAlgorithm),
    }
    .map_err(ml_kem_key_operation_error)
}

#[cfg(feature = "cose-crypto")]
fn ml_kem_key_operation_error(error: CryptoError) -> CoseError {
    match error {
        CryptoError::InvalidKey | CryptoError::InvalidCiphertextLength { .. } => {
            CoseError::InvalidKeyMaterial
        }
        _ => CoseError::Crypto,
    }
}
