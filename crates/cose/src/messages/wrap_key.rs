// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::bounded;
use crate::{api::contract::CoseRecipientAlgorithm as Algorithm, CoseError};
use reallyme_cose_proto::SecretBytes;
use reallyme_crypto::aes_kw::{
    unwrap_key_aes128, unwrap_key_aes192, unwrap_key_aes256, wrap_key_aes128, wrap_key_aes192,
    wrap_key_aes256, Aes128KwKek, Aes192KwKek, Aes256KwKek, AES_KW_INTEGRITY_CHECK_LENGTH,
};

pub(super) fn length(algorithm: Algorithm) -> Result<usize, CoseError> {
    match algorithm {
        Algorithm::A128kw => Ok(16),
        Algorithm::A192kw => Ok(24),
        Algorithm::A256kw => Ok(32),
        _ => Err(CoseError::UnsupportedAlgorithm),
    }
}
pub(super) fn wrap(
    algorithm: Algorithm,
    key: &[u8],
    plaintext: &[u8],
) -> Result<SecretBytes, CoseError> {
    if key.len() != length(algorithm)? {
        return Err(CoseError::InvalidKeyMaterial);
    }
    let output = match algorithm {
        Algorithm::A128kw => wrap_key_aes128(
            &Aes128KwKek::from_slice(key).map_err(|_| CoseError::InvalidKeyMaterial)?,
            plaintext,
        ),
        Algorithm::A192kw => wrap_key_aes192(
            &Aes192KwKek::from_slice(key).map_err(|_| CoseError::InvalidKeyMaterial)?,
            plaintext,
        ),
        Algorithm::A256kw => wrap_key_aes256(
            &Aes256KwKek::from_slice(key).map_err(|_| CoseError::InvalidKeyMaterial)?,
            plaintext,
        ),
        _ => return Err(CoseError::UnsupportedAlgorithm),
    }
    .map_err(|_| CoseError::Crypto)?;
    bounded::copy(output.as_bytes())
}
pub(super) fn unwrap(
    algorithm: Algorithm,
    key: &[u8],
    wrapped: &[u8],
    expected: usize,
) -> Result<SecretBytes, CoseError> {
    if key.len() != length(algorithm)? {
        return Err(CoseError::InvalidKeyMaterial);
    }
    if wrapped.len()
        != expected
            .checked_add(AES_KW_INTEGRITY_CHECK_LENGTH)
            .ok_or(CoseError::ResourceLimitExceeded)?
    {
        return Err(CoseError::InvalidRecipient);
    }
    let output = match algorithm {
        Algorithm::A128kw => unwrap_key_aes128(
            &Aes128KwKek::from_slice(key).map_err(|_| CoseError::InvalidKeyMaterial)?,
            wrapped,
        ),
        Algorithm::A192kw => unwrap_key_aes192(
            &Aes192KwKek::from_slice(key).map_err(|_| CoseError::InvalidKeyMaterial)?,
            wrapped,
        ),
        Algorithm::A256kw => unwrap_key_aes256(
            &Aes256KwKek::from_slice(key).map_err(|_| CoseError::InvalidKeyMaterial)?,
            wrapped,
        ),
        _ => return Err(CoseError::UnsupportedAlgorithm),
    }
    .map_err(crate::error::key_unwrap_error_from_crypto_error)?;
    if output.as_bytes().len() != expected {
        return Err(CoseError::InvalidRecipient);
    }
    bounded::copy(output.as_bytes())
}
