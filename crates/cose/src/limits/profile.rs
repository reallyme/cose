// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

//! Public COSE profile limits and entrypoint-specific validation.

use crate::CoseError;

use super::validate::{validate_cbor_bytes, CborItemRole};

/// Maximum accepted encoded COSE_Sign1 size.
pub use crate::generated_contract::values::MAX_COSE_SIGN1_BYTES;

/// Maximum accepted encoded detached COSE_Mac0 size.
pub use crate::generated_contract::values::MAX_COSE_MAC0_BYTES;

/// Maximum accepted external AAD size for detached COSE_Mac0 verification.
pub use crate::generated_contract::values::MAX_MAC0_EXTERNAL_AAD_BYTES;

#[cfg(feature = "cose-crypto")]
pub(crate) fn validate_cose_mac0_bytes(bytes: &[u8], max_len: usize) -> Result<(), CoseError> {
    validate_cbor_bytes(bytes, max_len, CborItemRole::CoseMac0Top)
}

/// Maximum accepted encoded COSE_Key size.
pub use crate::generated_contract::values::MAX_COSE_KEY_BYTES;

/// Maximum accepted encoded `COSE_Encrypt` size.
pub use crate::generated_contract::values::MAX_COSE_ENCRYPT_BYTES;

/// Maximum accepted detached payload size for signing and verification.
pub use crate::generated_contract::values::MAX_DETACHED_PAYLOAD_BYTES;

/// Maximum certificates accepted in one RFC 9360 `x5chain` header.
pub use crate::generated_contract::values::MAX_COSE_X5CHAIN_CERTIFICATES;

/// Maximum DER bytes accepted for one RFC 9360 `x5chain` certificate.
pub use crate::generated_contract::values::MAX_COSE_X5CHAIN_CERTIFICATE_BYTES;

/// Maximum aggregate DER bytes accepted for one RFC 9360 `x5chain` header.
pub use crate::generated_contract::values::MAX_COSE_X5CHAIN_TOTAL_BYTES;

pub(crate) fn native_limit(value: u64, maximum: usize) -> usize {
    // A portable request can exceed a 32-bit address space. Conversion failure
    // must retain the hard ceiling rather than widen it or vary by platform.
    match usize::try_from(value) {
        Ok(value) => value.min(maximum),
        Err(_) => maximum,
    }
}

pub(crate) fn portable_limit(value: usize, maximum: usize) -> u64 {
    u64::try_from(value.min(maximum)).unwrap_or(u64::MAX)
}

pub(super) fn next_depth(depth: usize) -> Result<usize, CoseError> {
    depth.checked_add(1).ok_or(CoseError::ResourceLimitExceeded)
}

pub(super) fn validate_item_depth(depth: usize) -> Result<(), CoseError> {
    if depth > crate::cbor_boundary::MAX_ITEM_DEPTH {
        return Err(CoseError::ResourceLimitExceeded);
    }
    Ok(())
}

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
pub(crate) fn validate_iso_cose_key_bytes(bytes: &[u8]) -> Result<(), CoseError> {
    validate_cbor_bytes(bytes, MAX_COSE_KEY_BYTES, CborItemRole::CoseIsoKeyTop)
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
