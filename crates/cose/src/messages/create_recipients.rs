// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{bounded, read_headers, recipient, wrap_key};
use crate::api::contract::{
    __buffa::oneof::cose_recipient_create::KeySource, CoseRecipientAlgorithm as Algorithm,
    CoseRecipientCreate,
};
use crate::CoseError;
use reallyme_codec::cbor::general::ValueRef;
use reallyme_cose_proto::SecretBytes;
use reallyme_crypto::{
    core::RngOutputKind,
    csprng::{OsSecureRandom, SecureRandom},
};
use zeroize::Zeroizing;

const MAX_DISTRIBUTED_KEY_BYTES: usize = 64;

fn headers(request: &CoseRecipientCreate) -> Result<read_headers::Headers<'_>, CoseError> {
    let headers = request
        .headers
        .as_option()
        .ok_or(CoseError::InvalidRecipient)?;
    read_headers::recipient(&headers.protected, &headers.unprotected)
}

pub(super) fn validate(
    requests: &[CoseRecipientCreate],
    allowed: &[buffa::EnumValue<Algorithm>],
    length: usize,
    depth: usize,
    total: &mut usize,
) -> Result<(), CoseError> {
    if requests.is_empty() || requests.len() > recipient::MAX_RECIPIENTS {
        return Err(CoseError::InvalidRecipient);
    }
    for request in requests {
        recipient::count(total, depth)?;
        let algorithm = recipient::algorithm(&headers(request)?, allowed)?;
        if algorithm == Algorithm::Direct {
            if requests.len() != 1 {
                return Err(CoseError::InvalidRecipient);
            }
            match request.key_source.as_ref() {
                Some(KeySource::Key(key)) if key.len() == length => {}
                _ => return Err(CoseError::InvalidKeyMaterial),
            }
        } else {
            let length = wrap_key::length(algorithm)?;
            match request.key_source.as_ref() {
                Some(KeySource::Key(key)) if key.len() == length => {}
                Some(KeySource::Recipients(group)) => validate(
                    &group.recipients,
                    allowed,
                    length,
                    depth
                        .checked_add(1)
                        .ok_or(CoseError::ResourceLimitExceeded)?,
                    total,
                )?,
                _ => return Err(CoseError::InvalidKeyMaterial),
            }
        }
    }
    Ok(())
}

pub(super) fn key(
    requests: &[CoseRecipientCreate],
    allowed: &[buffa::EnumValue<Algorithm>],
    length: usize,
) -> Result<SecretBytes, CoseError> {
    let first = requests.first().ok_or(CoseError::InvalidRecipient)?;
    if recipient::algorithm(&headers(first)?, allowed)? == Algorithm::Direct {
        if requests.len() != 1 {
            return Err(CoseError::InvalidRecipient);
        }
        let Some(KeySource::Key(key)) = first.key_source.as_ref() else {
            return Err(CoseError::InvalidKeyMaterial);
        };
        if key.len() != length {
            return Err(CoseError::InvalidKeyMaterial);
        }
        return bounded::copy(key);
    }
    // The longest supported MAC key is SHA-512's 64-byte key. Intermediate
    // AES KEKs are shorter. The unused stack tail is wiped with the key.
    let mut owner = Zeroizing::new([0_u8; MAX_DISTRIBUTED_KEY_BYTES]);
    let bytes = owner
        .get_mut(..length)
        .ok_or(CoseError::InvalidKeyMaterial)?;
    OsSecureRandom
        .fill_secure(bytes, RngOutputKind::Generic)
        .map_err(|_| CoseError::Crypto)?;
    bounded::copy(bytes)
}

pub(super) fn create(
    requests: &[CoseRecipientCreate],
    allowed: &[buffa::EnumValue<Algorithm>],
    parent_key: &[u8],
) -> Result<SecretBytes, CoseError> {
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(requests.len())
        .map_err(|_| CoseError::ResourceLimitExceeded)?;
    for request in requests {
        let headers = headers(request)?;
        let algorithm = recipient::algorithm(&headers, allowed)?;
        let (ciphertext, children) = if algorithm == Algorithm::Direct {
            let Some(KeySource::Key(key)) = request.key_source.as_ref() else {
                return Err(CoseError::InvalidKeyMaterial);
            };
            if !reallyme_crypto::operations::constant_time::equal(key, parent_key) {
                return Err(CoseError::InvalidKeyMaterial);
            }
            (bounded::copy(&[])?, None)
        } else {
            match request.key_source.as_ref() {
                Some(KeySource::Key(key)) => (wrap_key::wrap(algorithm, key, parent_key)?, None),
                Some(KeySource::Recipients(group)) => {
                    let kek = key(&group.recipients, allowed, wrap_key::length(algorithm)?)?;
                    let wrapped = wrap_key::wrap(algorithm, &kek, parent_key)?;
                    let children = create(&group.recipients, allowed, &kek)?;
                    (wrapped, Some(children))
                }
                _ => return Err(CoseError::InvalidKeyMaterial),
            }
        };
        let children = children
            .as_ref()
            .map(|bytes| bounded::frame(bytes))
            .transpose()?;
        let mut values = Vec::new();
        values
            .try_reserve_exact(4)
            .map_err(|_| CoseError::ResourceLimitExceeded)?;
        values.push(ValueRef::Bytes(headers.protected));
        values.push(ValueRef::Received(&headers.unprotected));
        values.push(ValueRef::Bytes(&ciphertext));
        if let Some(children) = &children {
            values.push(ValueRef::Received(children));
        }
        let value = ValueRef::Array(&values);
        encoded.push(bounded::encode(&value)?);
    }
    let mut frames = Vec::new();
    frames
        .try_reserve_exact(encoded.len())
        .map_err(|_| CoseError::ResourceLimitExceeded)?;
    for bytes in &encoded {
        frames.push(bounded::frame(bytes)?);
    }
    let mut values = Vec::new();
    values
        .try_reserve_exact(frames.len())
        .map_err(|_| CoseError::ResourceLimitExceeded)?;
    for frame in &frames {
        values.push(ValueRef::Received(frame));
    }
    let value = ValueRef::Array(&values);
    bounded::encode(&value)
}
