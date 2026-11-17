// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_crypto::core::{CryptoError, CryptoErrorReason};
use reallyme_crypto::rsa::{self, RsaHash, RsaPssParams, RsaPublicKeyDerEncoding};

use crate::{CoseError, CoseSignatureAlgorithm as Registration};

const SHA256_DIGEST_BYTES: usize = 32;
const SHA384_DIGEST_BYTES: usize = 48;
const SHA512_DIGEST_BYTES: usize = 64;

// COSE registrations bind padding, message hash, MGF1 hash and salt length.
// These parameters are never taken from an untrusted header or DER defaults.
pub(super) const fn parameters(registration: Registration) -> Option<(RsaHash, Option<usize>)> {
    match registration {
        Registration::Ps256 => Some((RsaHash::Sha256, Some(SHA256_DIGEST_BYTES))),
        Registration::Ps384 => Some((RsaHash::Sha384, Some(SHA384_DIGEST_BYTES))),
        Registration::Ps512 => Some((RsaHash::Sha512, Some(SHA512_DIGEST_BYTES))),
        Registration::Rs256 => Some((RsaHash::Sha256, None)),
        Registration::Rs384 => Some((RsaHash::Sha384, None)),
        Registration::Rs512 => Some((RsaHash::Sha512, None)),
        _ => None,
    }
}

pub(super) fn verify(
    registration: Registration,
    key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), CoseError> {
    let (hash, salt) = parameters(registration).ok_or(CoseError::UnsupportedAlgorithm)?;
    let width = super::rsa_public::modulus_bytes(key)?;
    if signature.len() != width {
        return Err(CoseError::InvalidSignatureEncoding);
    }
    match salt {
        Some(salt_len) => rsa::verify_rsa_pss(
            key,
            RsaPublicKeyDerEncoding::Spki,
            RsaPssParams {
                message_hash: hash,
                mgf1_hash: hash,
                salt_len,
            },
            message,
            signature,
        ),
        None => {
            rsa::verify_rsa_pkcs1v15(key, RsaPublicKeyDerEncoding::Spki, hash, message, signature)
        }
    }
    .map_err(failure)
}

fn failure(error: CryptoError) -> CoseError {
    match error.reason() {
        CryptoErrorReason::PrimitiveInvalidKey | CryptoErrorReason::PrimitiveInvalidPublicKey => {
            CoseError::InvalidKeyMaterial
        }
        CryptoErrorReason::PrimitiveInvalidSignature
        | CryptoErrorReason::PrimitiveVerificationFailed => CoseError::InvalidSignature,
        CryptoErrorReason::PrimitiveResourceLimitExceeded => CoseError::ResourceLimitExceeded,
        CryptoErrorReason::ProviderUnavailable => CoseError::ProviderUnavailable,
        CryptoErrorReason::ProviderUnsupportedAlgorithm => CoseError::UnsupportedAlgorithm,
        _ => CoseError::Crypto,
    }
}
