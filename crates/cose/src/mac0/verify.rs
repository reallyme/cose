// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::build_authentication_structure::{
    build_authentication_structure, AuthenticationContext,
};
use crate::limits::{MAX_COSE_MAC0_BYTES, MAX_DETACHED_PAYLOAD_BYTES, MAX_MAC0_EXTERNAL_AAD_BYTES};

use super::decode::decode;
use super::{
    CoseMac0Error, CoseMac0ErrorReason, CoseMac0VerifyRequest, CoseMacKey, VerifiedDetachedCoseMac0,
};

/// Verify detached COSE_Mac0 bytes using RFC 9052 §§6.2–6.3.
///
/// The received protected byte string is authenticated verbatim in
/// `["MAC0", protected, external_aad, detached_payload]`. The explicit
/// allowlist and key must both authorize the exact protected registration.
/// No authenticated metadata is returned until constant-time MAC verification
/// succeeds. Unprotected `kid` is never used to select or replace the key.
///
/// # Errors
///
/// Returns a fixed [`CoseMac0ErrorReason`] for invalid encoding, malformed or
/// conflicting headers, unsupported critical semantics, resource limits,
/// algorithm/key mismatches, tag length errors, or authentication failure.
pub fn cose_verify_mac0_detached(
    request: CoseMac0VerifyRequest<'_>,
    key: &CoseMacKey,
) -> Result<VerifiedDetachedCoseMac0, CoseMac0Error> {
    let limits = request.limits;
    if request.encoded.len() > limits.max_encoded_bytes.min(MAX_COSE_MAC0_BYTES)
        || request.detached_payload.len() > limits.max_payload_bytes.min(MAX_DETACHED_PAYLOAD_BYTES)
        || request.external_aad.len()
            > limits
                .max_external_aad_bytes
                .min(MAX_MAC0_EXTERNAL_AAD_BYTES)
    {
        return Err(CoseMac0ErrorReason::ResourceLimitExceeded.into());
    }

    let decoded = decode(
        request.encoded,
        limits.max_encoded_bytes.min(MAX_COSE_MAC0_BYTES),
    )?;
    let algorithm = decoded.metadata.algorithm;
    if !request.allowed_algorithms.contains(&algorithm) {
        return Err(CoseMac0ErrorReason::UnsupportedAlgorithm.into());
    }
    if key.algorithm() != algorithm {
        return Err(CoseMac0ErrorReason::KeyAlgorithmMismatch.into());
    }
    if decoded.tag.len() != algorithm.tag_length() {
        return Err(CoseMac0ErrorReason::InvalidTagLength.into());
    }

    let to_be_maced = build_authentication_structure(
        AuthenticationContext::Mac0,
        &decoded.metadata.protected_bytes,
        request.external_aad,
        request.detached_payload,
    )?;
    key.verify(&to_be_maced, &decoded.tag)?;
    Ok(decoded.metadata)
}
