// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Public COSE profile limits and entrypoint-specific validation.

use crate::CoseError;

use super::validate::{validate_cbor_bytes, CborItemRole};

/// Maximum accepted encoded COSE_Sign1 size.
pub const MAX_COSE_SIGN1_BYTES: usize = 65_536;

/// Maximum accepted encoded COSE_Key size.
pub const MAX_COSE_KEY_BYTES: usize = 16_384;

/// Maximum accepted encoded `COSE_Encrypt` size.
pub const MAX_COSE_ENCRYPT_BYTES: usize = 1_114_112;

/// Maximum accepted detached payload size for signing and verification.
pub const MAX_DETACHED_PAYLOAD_BYTES: usize = 1_048_576;

#[cfg(feature = "cose-crypto")]
pub(crate) fn validate_cose_sign1_bytes_with_limit(
    bytes: &[u8],
    max_len: usize,
) -> Result<(), CoseError> {
    validate_cbor_bytes(bytes, max_len, CborItemRole::CoseSign1Top)
}

#[cfg(feature = "cose-crypto")]
pub(crate) fn validate_cose_encrypt_bytes(bytes: &[u8]) -> Result<(), CoseError> {
    validate_cbor_bytes(bytes, MAX_COSE_ENCRYPT_BYTES, CborItemRole::CoseEncryptTop)
}

pub(crate) fn validate_cose_key_bytes(bytes: &[u8]) -> Result<(), CoseError> {
    validate_cbor_bytes(bytes, MAX_COSE_KEY_BYTES, CborItemRole::CoseKeyTop)
}

#[cfg(feature = "cose-crypto")]
pub(crate) fn validate_detached_payload(payload: &[u8]) -> Result<(), CoseError> {
    validate_detached_payload_with_limit(payload, MAX_DETACHED_PAYLOAD_BYTES)
}

#[cfg(feature = "cose-crypto")]
pub(crate) fn validate_detached_payload_with_limit(
    payload: &[u8],
    max_len: usize,
) -> Result<(), CoseError> {
    if payload.len() > max_len {
        return Err(CoseError::ResourceLimitExceeded);
    }
    Ok(())
}

#[cfg(feature = "cose-crypto")]
pub(crate) fn validate_protected_header_bytes(bytes: &[u8]) -> Result<(), CoseError> {
    if bytes.is_empty() {
        return Ok(());
    }
    validate_cbor_bytes(bytes, bytes.len(), CborItemRole::ProtectedHeaderMap)
}
