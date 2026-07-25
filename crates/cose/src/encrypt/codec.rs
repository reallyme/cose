// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use ciborium::value::Value;
use coset::{
    iana, AsCborValue, CoseEncrypt, CoseRecipient, Header, Label, ProtectedHeader,
    RegisteredLabelWithPrivate,
};
use zeroize::Zeroizing;

use crate::algorithm::REALLYME_COSE_HEADER_EK;
use crate::encode_cbor::encode_cbor_value;
use crate::limits::MAX_COSE_ENCRYPT_BYTES;
use crate::zeroize_coset::{zeroize_cose_encrypt, SensitiveCborValue};
use crate::CoseError;

use super::profile::ML_KEM_KID_LENGTH;

pub(crate) const COSE_ENCRYPT_TAG: u64 = 96;
pub(crate) const MAX_PLAINTEXT_BYTES: usize = 1_048_576;
pub(crate) const MAX_EXTERNAL_AAD_BYTES: usize = 1_048_576;
pub(crate) const MAX_KID_BYTES: usize = 1_024;
pub(crate) const MAX_SUPP_PRIV_INFO_BYTES: usize = 65_536;
pub(crate) const AES_GCM_NONCE_LENGTH: usize = 12;
pub(crate) const AES_GCM_TAG_LENGTH: usize = 16;

pub(crate) fn protected_header(
    algorithm: RegisteredLabelWithPrivate<iana::Algorithm>,
    kid: Option<&[u8]>,
) -> ProtectedHeader {
    ProtectedHeader {
        original_data: None,
        header: Header {
            alg: Some(algorithm),
            key_id: kid.map(<[u8]>::to_vec).unwrap_or_default(),
            ..Header::default()
        },
    }
}

pub(crate) fn recipient_unprotected(encapsulated_key: Vec<u8>) -> Header {
    Header {
        rest: vec![(
            Label::Int(REALLYME_COSE_HEADER_EK),
            Value::Bytes(encapsulated_key),
        )],
        ..Header::default()
    }
}

pub(crate) fn body_unprotected(iv: &[u8]) -> Header {
    Header {
        iv: iv.to_vec(),
        ..Header::default()
    }
}

pub(crate) fn encode(cose: CoseEncrypt) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    let mut value = cose.to_cbor_value().map_err(|_| CoseError::Cbor)?;
    value = Value::Tag(COSE_ENCRYPT_TAG, Box::new(value));
    let encoded = encode_cbor_value(value)?;
    if encoded.len() > MAX_COSE_ENCRYPT_BYTES {
        return Err(CoseError::ResourceLimitExceeded);
    }
    Ok(encoded)
}

pub(crate) fn decode(bytes: &[u8]) -> Result<SensitiveCoseEncrypt, CoseError> {
    let decoded = SensitiveCborValue::decode_cose_encrypt(bytes)?;
    let body = match decoded.value() {
        Value::Tag(COSE_ENCRYPT_TAG, body) => body.as_ref(),
        value => value,
    };
    let items = match body {
        Value::Array(items) if items.len() == 4 => items,
        _ => return Err(CoseError::InvalidFormat),
    };

    // Establish the recursive wipe owner before any payload, ciphertext,
    // identifier, or protected-header bytes are cloned out of the decoded
    // tree. Rejected semantic parses therefore clear both owners.
    let mut sensitive = SensitiveCoseEncrypt {
        inner: CoseEncrypt::default(),
    };
    decode_protected_header(
        &items[0],
        &mut sensitive.inner.protected,
        EncryptHeaderBucket::BodyProtected,
    )?;
    decode_encrypt_header(
        &items[1],
        &mut sensitive.inner.unprotected,
        EncryptHeaderBucket::BodyUnprotected,
    )?;
    sensitive.inner.ciphertext = decode_optional_bytes(&items[2])?;

    let recipients = match &items[3] {
        Value::Array(recipients) if recipients.len() == 1 => recipients,
        _ => return Err(CoseError::InvalidRecipient),
    };
    let recipient_items = match &recipients[0] {
        Value::Array(items) if items.len() == 3 => items,
        _ => return Err(CoseError::InvalidRecipient),
    };
    sensitive.inner.recipients.push(CoseRecipient::default());
    let recipient = sensitive
        .inner
        .recipients
        .first_mut()
        .ok_or(CoseError::InvalidRecipient)?;
    decode_protected_header(
        &recipient_items[0],
        &mut recipient.protected,
        EncryptHeaderBucket::RecipientProtected,
    )?;
    decode_encrypt_header(
        &recipient_items[1],
        &mut recipient.unprotected,
        EncryptHeaderBucket::RecipientUnprotected,
    )?;
    recipient.ciphertext = decode_optional_bytes(&recipient_items[2])?;

    Ok(sensitive)
}

#[derive(Clone, Copy)]
enum EncryptHeaderBucket {
    BodyProtected,
    BodyUnprotected,
    RecipientProtected,
    RecipientUnprotected,
}

fn decode_protected_header(
    value: &Value,
    protected: &mut ProtectedHeader,
    bucket: EncryptHeaderBucket,
) -> Result<(), CoseError> {
    let bytes = match value {
        Value::Bytes(bytes) => bytes,
        _ => return Err(CoseError::InvalidFormat),
    };
    protected.original_data = Some(bytes.clone());
    if bytes.is_empty() {
        return Ok(());
    }

    let decoded = SensitiveCborValue::decode_protected_header(bytes)?;
    decode_encrypt_header(decoded.value(), &mut protected.header, bucket)
}

fn decode_encrypt_header(
    value: &Value,
    header: &mut Header,
    bucket: EncryptHeaderBucket,
) -> Result<(), CoseError> {
    let entries = match value {
        Value::Map(entries) => entries,
        _ => return Err(CoseError::InvalidFormat),
    };
    let mut saw_algorithm = false;
    let mut saw_kid = false;
    let mut saw_iv = false;
    let mut saw_encapsulated_key = false;

    for (label, value) in entries {
        let label = match label {
            Value::Integer(integer) => {
                i64::try_from(*integer).map_err(|_| CoseError::InvalidFormat)?
            }
            _ => return Err(header_bucket_error(bucket)),
        };

        if label == iana::HeaderParameter::Alg as i64 {
            if saw_algorithm {
                return Err(CoseError::DuplicateMapLabel);
            }
            saw_algorithm = true;
            if matches!(
                bucket,
                EncryptHeaderBucket::BodyUnprotected | EncryptHeaderBucket::RecipientUnprotected
            ) {
                return Err(CoseError::UnprotectedHeaderNotAllowed);
            }
            header.alg = Some(parse_header_algorithm(value)?);
        } else if label == iana::HeaderParameter::Kid as i64 {
            if saw_kid {
                return Err(CoseError::DuplicateMapLabel);
            }
            saw_kid = true;
            if !matches!(bucket, EncryptHeaderBucket::RecipientProtected) {
                return Err(header_bucket_error(bucket));
            }
            header.key_id = match value {
                Value::Bytes(kid) if !kid.is_empty() => kid.clone(),
                _ => return Err(CoseError::InvalidRecipient),
            };
        } else if label == iana::HeaderParameter::Iv as i64 {
            if saw_iv {
                return Err(CoseError::DuplicateMapLabel);
            }
            saw_iv = true;
            if !matches!(bucket, EncryptHeaderBucket::BodyUnprotected) {
                return Err(header_bucket_error(bucket));
            }
            header.iv = match value {
                Value::Bytes(iv) if !iv.is_empty() => iv.clone(),
                _ => return Err(CoseError::InvalidIv),
            };
        } else if label == REALLYME_COSE_HEADER_EK {
            if saw_encapsulated_key {
                return Err(CoseError::DuplicateMapLabel);
            }
            saw_encapsulated_key = true;
            if !matches!(bucket, EncryptHeaderBucket::RecipientUnprotected) {
                return Err(header_bucket_error(bucket));
            }
            let encapsulated_key = match value {
                Value::Bytes(encapsulated_key) => encapsulated_key.clone(),
                _ => return Err(CoseError::InvalidEncapsulatedKey),
            };
            header.rest.push((
                Label::Int(REALLYME_COSE_HEADER_EK),
                Value::Bytes(encapsulated_key),
            ));
        } else {
            return Err(header_bucket_error(bucket));
        }
    }
    Ok(())
}

fn parse_header_algorithm(
    value: &Value,
) -> Result<RegisteredLabelWithPrivate<iana::Algorithm>, CoseError> {
    match value {
        Value::Integer(integer) => {
            RegisteredLabelWithPrivate::from_cbor_value(Value::Integer(*integer))
                .map_err(|_| CoseError::InvalidFormat)
        }
        Value::Text(text) => Ok(RegisteredLabelWithPrivate::Text(text.clone())),
        _ => Err(CoseError::InvalidFormat),
    }
}

fn decode_optional_bytes(value: &Value) -> Result<Option<Vec<u8>>, CoseError> {
    match value {
        Value::Bytes(bytes) => Ok(Some(bytes.clone())),
        Value::Null => Ok(None),
        _ => Err(CoseError::InvalidFormat),
    }
}

const fn header_bucket_error(bucket: EncryptHeaderBucket) -> CoseError {
    match bucket {
        EncryptHeaderBucket::BodyProtected | EncryptHeaderBucket::BodyUnprotected => {
            CoseError::InvalidFormat
        }
        EncryptHeaderBucket::RecipientProtected | EncryptHeaderBucket::RecipientUnprotected => {
            CoseError::InvalidRecipient
        }
    }
}

pub(crate) fn validate_structure(cose: &CoseEncrypt) -> Result<(), CoseError> {
    if cose.recipients.len() != 1 {
        return Err(CoseError::InvalidRecipient);
    }
    if cose.ciphertext.is_none() {
        return Err(CoseError::MissingCiphertext);
    }
    if cose.unprotected.alg.is_some() || cose.protected.header.alg.is_none() {
        return Err(CoseError::UnprotectedHeaderNotAllowed);
    }
    if cose.unprotected.iv.len() != AES_GCM_NONCE_LENGTH
        || !cose.protected.header.iv.is_empty()
        || !cose.unprotected.partial_iv.is_empty()
        || !cose.protected.header.partial_iv.is_empty()
    {
        return Err(CoseError::InvalidIv);
    }
    if !cose.protected.header.key_id.is_empty()
        || !cose.unprotected.key_id.is_empty()
        || !cose.protected.header.rest.is_empty()
        || !cose.unprotected.rest.is_empty()
        || !cose.protected.header.crit.is_empty()
        || !cose.unprotected.crit.is_empty()
        || has_unsupported_profile_headers(&cose.protected.header)
        || has_unsupported_profile_headers(&cose.unprotected)
    {
        return Err(CoseError::InvalidFormat);
    }

    let recipient = cose.recipients.first().ok_or(CoseError::InvalidRecipient)?;
    validate_recipient(recipient)
}

fn validate_recipient(recipient: &CoseRecipient) -> Result<(), CoseError> {
    if !recipient.recipients.is_empty() {
        return Err(CoseError::InvalidRecipient);
    }
    if recipient.protected.header.alg.is_none() || recipient.unprotected.alg.is_some() {
        return Err(CoseError::UnprotectedHeaderNotAllowed);
    }
    if recipient.protected.header.key_id.len() != ML_KEM_KID_LENGTH
        || !recipient.unprotected.key_id.is_empty()
        || !recipient.protected.header.iv.is_empty()
        || !recipient.unprotected.iv.is_empty()
        || !recipient.protected.header.partial_iv.is_empty()
        || !recipient.unprotected.partial_iv.is_empty()
        || !recipient.protected.header.crit.is_empty()
        || !recipient.unprotected.crit.is_empty()
        || !recipient.protected.header.rest.is_empty()
        || has_unsupported_profile_headers(&recipient.protected.header)
        || has_unsupported_profile_headers(&recipient.unprotected)
    {
        return Err(CoseError::InvalidRecipient);
    }

    let mut encapsulated_key_count = 0usize;
    for (label, value) in &recipient.unprotected.rest {
        if *label != Label::Int(REALLYME_COSE_HEADER_EK) {
            return Err(CoseError::InvalidRecipient);
        }
        if !matches!(value, Value::Bytes(_)) {
            return Err(CoseError::InvalidEncapsulatedKey);
        }
        encapsulated_key_count = encapsulated_key_count
            .checked_add(1)
            .ok_or(CoseError::ResourceLimitExceeded)?;
    }
    if encapsulated_key_count != 1 {
        return Err(CoseError::MissingEncapsulatedKey);
    }
    Ok(())
}

fn has_unsupported_profile_headers(header: &Header) -> bool {
    // The ReallyMe ML-KEM profile does not define content-type processing or
    // counter-signature semantics. Accepting either would let callers treat a
    // successfully decrypted object as fully processed while authenticated or
    // unauthenticated header requirements were silently ignored.
    header.content_type.is_some() || !header.counter_signatures.is_empty()
}

pub(crate) fn encapsulated_key(recipient: &CoseRecipient) -> Result<&[u8], CoseError> {
    recipient
        .unprotected
        .rest
        .iter()
        .find_map(|(label, value)| {
            if *label == Label::Int(REALLYME_COSE_HEADER_EK) {
                match value {
                    Value::Bytes(bytes) => Some(bytes.as_slice()),
                    _ => None,
                }
            } else {
                None
            }
        })
        .ok_or(CoseError::MissingEncapsulatedKey)
}

pub(crate) struct SensitiveCoseEncrypt {
    pub(crate) inner: CoseEncrypt,
}

impl Drop for SensitiveCoseEncrypt {
    fn drop(&mut self) {
        zeroize_cose_encrypt(&mut self.inner);
    }
}
