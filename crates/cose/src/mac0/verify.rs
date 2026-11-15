// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::build_authentication_structure::{
    build_authentication_structure, AuthenticationContext,
};
use crate::limits::{MAX_COSE_MAC0_BYTES, MAX_DETACHED_PAYLOAD_BYTES, MAX_MAC0_EXTERNAL_AAD_BYTES};

use super::decode::decode;
use super::{
    CoseMac0Error, CoseMac0ErrorReason, CoseMac0VerifyRequest, CoseMacAlgorithm, CoseMacKey,
    VerifiedDetachedCoseMac0,
};

#[cfg(kani)]
#[path = "verify_mac0_authentication_proof_tests.rs"]
mod verification;

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
    verify_mac0_operation(request, key)
}

pub(crate) fn verify_mac0_operation(
    request: CoseMac0VerifyRequest<'_>,
    key: &dyn super::CoseMacVerifier,
) -> Result<VerifiedDetachedCoseMac0, CoseMac0Error> {
    let limits = request.limits;
    if request.allowed_algorithms.len() > crate::generated_contract::values::MAX_ALLOWLIST_ENTRIES
        || request.encoded.len() > limits.encoded_bytes.min(MAX_COSE_MAC0_BYTES)
        || request.detached_payload.len() > limits.payload_bytes.min(MAX_DETACHED_PAYLOAD_BYTES)
        || request.external_aad.len() > limits.external_aad_bytes.min(MAX_MAC0_EXTERNAL_AAD_BYTES)
    {
        return Err(CoseMac0ErrorReason::ResourceLimitExceeded.into());
    }

    let decoded = decode(
        request.encoded,
        limits.encoded_bytes.min(MAX_COSE_MAC0_BYTES),
    )?;
    let algorithm = decoded.metadata.algorithm;
    authorize_tag(
        algorithm,
        request.allowed_algorithms,
        || key.algorithm(),
        decoded.tag.len(),
    )?;

    let to_be_maced = build_authentication_structure(
        AuthenticationContext::Mac0,
        &decoded.metadata.protected_bytes,
        request.external_aad,
        request.detached_payload,
    )?;
    key.verify(&to_be_maced, &decoded.tag)?;
    Ok(decoded.metadata)
}

fn authorize_tag(
    algorithm: CoseMacAlgorithm,
    allowed: &[CoseMacAlgorithm],
    key_algorithm: impl FnOnce() -> CoseMacAlgorithm,
    tag_len: usize,
) -> Result<(), CoseMac0Error> {
    if !allowed.contains(&algorithm) {
        return Err(CoseMac0ErrorReason::UnsupportedAlgorithm.into());
    }
    if key_algorithm() != algorithm {
        return Err(CoseMac0ErrorReason::KeyAlgorithmMismatch.into());
    }
    if tag_len != algorithm.tag_length() {
        return Err(CoseMac0ErrorReason::InvalidTagLength.into());
    }
    Ok(())
}
