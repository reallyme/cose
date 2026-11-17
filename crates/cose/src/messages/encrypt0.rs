// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{bounded, read_headers, read_message};
use crate::api::contract::{
    self as contract, CoseContentEncryptionAlgorithm as WireAlgorithm, CoseContentMode,
};
use crate::{encrypt::CoseContentEncryptionAlgorithm, CoseError};
use reallyme_codec::cbor::general::ValueRef;
use zeroize::Zeroizing;

const GCM_NONCE_BYTES: usize = 12;
const GCM_TAG_BYTES: usize = 16;

fn authorize(
    value: buffa::EnumValue<WireAlgorithm>,
    allowed: &[buffa::EnumValue<WireAlgorithm>],
    received: Option<i64>,
    key: &[u8],
) -> Result<CoseContentEncryptionAlgorithm, CoseError> {
    if allowed.is_empty() || allowed.len() > 3 {
        return Err(CoseError::UnsupportedAlgorithm);
    }
    for (index, algorithm) in allowed.iter().enumerate() {
        CoseContentEncryptionAlgorithm::try_from(*algorithm)?;
        if allowed
            .get(..index)
            .ok_or(CoseError::InvalidFormat)?
            .contains(algorithm)
        {
            return Err(CoseError::InvalidFormat);
        }
    }
    let algorithm = CoseContentEncryptionAlgorithm::try_from(value)?;
    let (identifier, key_length) = match algorithm {
        CoseContentEncryptionAlgorithm::Aes128Gcm => (1, 16),
        CoseContentEncryptionAlgorithm::Aes192Gcm => (2, 24),
        CoseContentEncryptionAlgorithm::Aes256Gcm => (3, 32),
    };
    if received != Some(identifier) || !allowed.contains(&value) {
        return Err(CoseError::UnsupportedAlgorithm);
    }
    if key.len() != key_length {
        return Err(CoseError::InvalidKeyMaterial);
    }
    Ok(algorithm)
}

fn nonce(
    headers: &read_headers::Headers<'_>,
    base: Option<&[u8]>,
) -> Result<Zeroizing<[u8; GCM_NONCE_BYTES]>, CoseError> {
    let iv = read_headers::optional_bytes(headers, 5)?;
    let partial = read_headers::optional_bytes(headers, 6)?;
    match (iv, partial, base) {
        (Some(iv), None, None) => Ok(Zeroizing::new(
            iv.try_into().map_err(|_| CoseError::InvalidIv)?,
        )),
        (None, Some(partial), Some(base))
            if !partial.is_empty() && partial.len() <= GCM_NONCE_BYTES =>
        {
            let mut nonce = Zeroizing::new(
                <[u8; GCM_NONCE_BYTES]>::try_from(base).map_err(|_| CoseError::InvalidIv)?,
            );
            let offset = GCM_NONCE_BYTES
                .checked_sub(partial.len())
                .ok_or(CoseError::InvalidIv)?;
            for (target, value) in nonce
                .get_mut(offset..)
                .ok_or(CoseError::InvalidIv)?
                .iter_mut()
                .zip(partial)
            {
                *target ^= value;
            }
            Ok(nonce)
        }
        _ => Err(CoseError::InvalidIv),
    }
}

fn structure(protected: &[u8], aad: &[u8]) -> Result<reallyme_cose_proto::SecretBytes, CoseError> {
    let values = [
        ValueRef::Text("Encrypt0"),
        ValueRef::Bytes(protected),
        ValueRef::Bytes(aad),
    ];
    let value = ValueRef::Array(&values);
    bounded::encode(&value)
}

pub(crate) fn create(
    request: &contract::CoseEncrypt0CreateRequest,
) -> Result<contract::CoseEncrypt0CreateResult, CoseError> {
    read_message::aad(&request.external_aad)?;
    if request
        .plaintext
        .len()
        .checked_add(GCM_TAG_BYTES)
        .ok_or(CoseError::ResourceLimitExceeded)?
        > bounded::MAX_MESSAGE_BYTES
    {
        return Err(CoseError::ResourceLimitExceeded);
    }
    let input = request
        .headers
        .as_option()
        .ok_or(CoseError::InvalidFormat)?;
    let headers =
        read_headers::read_with_critical(&input.protected, &input.unprotected, &[1, 3, 4, 5, 6])?;
    let algorithm = authorize(
        request.key_algorithm,
        &request.allowed_algorithms,
        headers.algorithm,
        &request.key,
    )?;
    let nonce = nonce(&headers, request.base_iv.as_deref())?;
    let aad = structure(headers.protected, &request.external_aad)?;
    // Validate mode before any cryptographic work, including empty plaintext.
    let _mode = read_message::content(&request.plaintext, request.content_mode)?;
    let ciphertext = Zeroizing::new(crate::encrypt::create::encrypt_content(
        algorithm,
        &request.key,
        nonce.as_ref(),
        &aad,
        &request.plaintext,
    )?);
    let content = read_message::content(&ciphertext, request.content_mode)?;
    let values = [
        ValueRef::Bytes(headers.protected),
        ValueRef::Received(&headers.unprotected),
        content,
    ];
    let body = ValueRef::Array(&values);
    let value = if request.tagged {
        ValueRef::Tag(16, &body)
    } else {
        ValueRef::Array(&values)
    };
    Ok(contract::CoseEncrypt0CreateResult {
        encoded: bounded::encode(&value)?,
        detached_ciphertext: if request.content_mode == CoseContentMode::Detached {
            Some(bounded::copy(&ciphertext)?)
        } else {
            None
        },
    })
}

pub(crate) fn decrypt(
    request: &contract::CoseEncrypt0DecryptRequest,
) -> Result<contract::CoseEncrypt0DecryptResult, CoseError> {
    read_message::aad(&request.external_aad)?;
    let fields = read_message::envelope(&request.encoded, 16, request.envelope, 3)?;
    let [protected, unprotected, ciphertext] = fields.as_slice() else {
        return Err(CoseError::InvalidFormat);
    };
    let headers = read_headers::read_with_critical(
        protected.as_bytes().map_err(crate::cbor_boundary::error)?,
        unprotected.received_bytes(),
        &[1, 3, 4, 5, 6],
    )?;
    let ciphertext = read_message::payload(ciphertext, request.detached_ciphertext.as_deref())?;
    if ciphertext.len() < GCM_TAG_BYTES {
        return Err(CoseError::InvalidFormat);
    }
    let algorithm = authorize(
        request.key_algorithm,
        &request.allowed_algorithms,
        headers.algorithm,
        &request.key,
    )?;
    let nonce = nonce(&headers, request.base_iv.as_deref())?;
    let aad = structure(headers.protected, &request.external_aad)?;
    let plaintext = crate::encrypt::decrypt::decrypt_content(
        algorithm,
        &request.key,
        nonce.as_ref(),
        &aad,
        ciphertext,
    )?;
    Ok(contract::CoseEncrypt0DecryptResult {
        plaintext: bounded::copy(&plaintext)?,
        algorithm: request.key_algorithm,
        protected: bounded::copy(headers.protected)?,
        protected_kid: headers.protected_kid.map(bounded::copy).transpose()?,
    })
}

pub(crate) fn valid_created(result: &contract::CoseEncrypt0CreateResult) -> bool {
    !result.encoded.is_empty()
        && result.encoded.len() <= bounded::MAX_MESSAGE_BYTES
        && result
            .detached_ciphertext
            .as_ref()
            .is_none_or(|v| (GCM_TAG_BYTES..=bounded::MAX_MESSAGE_BYTES).contains(&v.len()))
}
pub(crate) fn valid_decrypted(result: &contract::CoseEncrypt0DecryptResult) -> bool {
    CoseContentEncryptionAlgorithm::try_from(result.algorithm).is_ok()
        && result.plaintext.len() <= bounded::MAX_MESSAGE_BYTES
        && result.protected.len() <= read_message::MAX_HEADER_BYTES
}
