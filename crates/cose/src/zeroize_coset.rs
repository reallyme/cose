// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Recursive wiping for decoded `coset` owners.
//!
//! `coset` correctly models COSE wire objects, but its decoded buffers are
//! ordinary vectors and strings. Profile bounds are enforced before tree
//! decoding; semantic validation still happens afterward, so rejected objects
//! can contain sensitive caller-controlled bytes. These helpers wipe the entire
//! decoded owner, not only the fields used on the success path.

use ciborium::value::Value;
#[cfg(feature = "cose-crypto")]
use coset::{
    CoseEncrypt, CoseRecipient, CoseSign1, CoseSignature, Header, Label, ProtectedHeader,
    RegisteredLabel, RegisteredLabelWithPrivate,
};
use zeroize::Zeroize;

use crate::limits::validate_cose_key_bytes;
#[cfg(feature = "cose-crypto")]
use crate::limits::{
    validate_cose_encrypt_bytes, validate_cose_sign1_bytes_with_limit,
    validate_protected_header_bytes,
};
use crate::CoseError;

/// Decoded CBOR tree that recursively wipes owned byte and text values.
///
/// Keeping the original decoded tree alive while semantic fields are copied
/// into a profile-specific wipe-on-drop owner prevents rejected parses from
/// abandoning partially decoded payloads, keys, claims, or ciphertexts in
/// ordinary allocator-owned buffers.
pub(crate) struct SensitiveCborValue {
    value: Value,
}

impl SensitiveCborValue {
    pub(crate) const fn from_value(value: Value) -> Self {
        Self { value }
    }

    pub(crate) fn decode_cose_key(bytes: &[u8]) -> Result<Self, CoseError> {
        validate_cose_key_bytes(bytes)?;
        Self::decode_validated(bytes)
    }

    #[cfg(feature = "cose-crypto")]
    pub(crate) fn decode_cose_sign1(bytes: &[u8], max_len: usize) -> Result<Self, CoseError> {
        validate_cose_sign1_bytes_with_limit(bytes, max_len)?;
        Self::decode_validated(bytes)
    }

    #[cfg(feature = "cose-crypto")]
    pub(crate) fn decode_cose_encrypt(bytes: &[u8]) -> Result<Self, CoseError> {
        validate_cose_encrypt_bytes(bytes)?;
        Self::decode_validated(bytes)
    }

    #[cfg(feature = "cose-crypto")]
    pub(crate) fn decode_protected_header(bytes: &[u8]) -> Result<Self, CoseError> {
        validate_protected_header_bytes(bytes)?;
        Self::decode_validated(bytes)
    }

    fn decode_validated(bytes: &[u8]) -> Result<Self, CoseError> {
        let mut reader = bytes;
        let value = ciborium::de::from_reader(&mut reader).map_err(|_| CoseError::Cbor)?;
        if !reader.is_empty() {
            let mut value = value;
            zeroize_value(&mut value);
            return Err(CoseError::Cbor);
        }
        Ok(Self { value })
    }

    pub(crate) fn value_mut(&mut self) -> &mut Value {
        &mut self.value
    }

    pub(crate) fn value(&self) -> &Value {
        &self.value
    }
}

impl Drop for SensitiveCborValue {
    fn drop(&mut self) {
        zeroize_value(&mut self.value);
    }
}

#[cfg(feature = "cose-crypto")]
pub(crate) fn zeroize_cose_encrypt(cose: &mut CoseEncrypt) {
    zeroize_protected_header(&mut cose.protected);
    zeroize_header(&mut cose.unprotected);
    if let Some(ciphertext) = &mut cose.ciphertext {
        ciphertext.zeroize();
    }
    for recipient in &mut cose.recipients {
        zeroize_recipient(recipient);
    }
}

#[cfg(feature = "cose-crypto")]
pub(crate) fn zeroize_cose_sign1(cose: &mut CoseSign1) {
    zeroize_protected_header(&mut cose.protected);
    zeroize_header(&mut cose.unprotected);
    if let Some(payload) = &mut cose.payload {
        payload.zeroize();
    }
    cose.signature.zeroize();
}

#[cfg(feature = "cose-crypto")]
fn zeroize_recipient(recipient: &mut CoseRecipient) {
    zeroize_protected_header(&mut recipient.protected);
    zeroize_header(&mut recipient.unprotected);
    if let Some(ciphertext) = &mut recipient.ciphertext {
        ciphertext.zeroize();
    }
    for child in &mut recipient.recipients {
        zeroize_recipient(child);
    }
}

#[cfg(feature = "cose-crypto")]
fn zeroize_protected_header(protected: &mut ProtectedHeader) {
    if let Some(original) = &mut protected.original_data {
        original.zeroize();
    }
    zeroize_header(&mut protected.header);
}

#[cfg(feature = "cose-crypto")]
fn zeroize_header(header: &mut Header) {
    if let Some(RegisteredLabelWithPrivate::Text(text)) = &mut header.alg {
        text.zeroize();
    }
    for label in &mut header.crit {
        if let RegisteredLabelWithPrivate::Text(text) = label {
            text.zeroize();
        }
    }
    if let Some(RegisteredLabel::Text(text)) = &mut header.content_type {
        text.zeroize();
    }
    header.key_id.zeroize();
    header.iv.zeroize();
    header.partial_iv.zeroize();
    for signature in &mut header.counter_signatures {
        zeroize_signature(signature);
    }
    for (label, value) in &mut header.rest {
        if let Label::Text(text) = label {
            text.zeroize();
        }
        zeroize_value(value);
    }
}

#[cfg(feature = "cose-crypto")]
fn zeroize_signature(signature: &mut CoseSignature) {
    zeroize_protected_header(&mut signature.protected);
    zeroize_header(&mut signature.unprotected);
    signature.signature.zeroize();
}

pub(crate) fn zeroize_value(value: &mut Value) {
    match value {
        Value::Bytes(bytes) => bytes.zeroize(),
        Value::Text(text) => text.zeroize(),
        Value::Array(values) => {
            for value in values {
                zeroize_value(value);
            }
        }
        Value::Map(entries) => {
            for (key, value) in entries {
                zeroize_value(key);
                zeroize_value(value);
            }
        }
        Value::Tag(_, tagged) => zeroize_value(tagged),
        Value::Integer(_) | Value::Float(_) | Value::Bool(_) | Value::Null => {}
        // `ciborium::Value` is non-exhaustive. Dependency upgrades must review
        // any new variants here before release; unknown variants cannot be
        // safely assumed to be buffer-free.
        _ => {}
    }
}

#[cfg(test)]
mod decode_sensitive_tests;
