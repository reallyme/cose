// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::build_authentication_structure::{
    build_authentication_structure, AuthenticationContext,
};
use crate::limits::{MAX_COSE_SIGN1_BYTES, MAX_DETACHED_PAYLOAD_BYTES};
use crate::CoseError;

use super::decode::decode;
use super::{Iso18013Sign1Content, Iso18013Sign1Request, Iso18013Verifier, VerifiedIso18013Sign1};

/// Verify issuer, device, or reader Sign1 under an explicit ISO 2021 policy.
///
/// The exact legacy registration and named provider key curve must occur
/// together in the caller's allowlist. AAD is always the empty byte string;
/// issuer content must be attached and device/reader content must be detached.
/// Received protected bytes are never rewritten. No result is released before
/// signature verification succeeds. Certificate trust, ISO encoding preflight,
/// transcript construction, and application acceptance remain caller duties.
///
/// # Errors
///
/// Returns fixed [`CoseError`] variants for encoding, limits, unsupported or
/// disallowed suites, algorithm/key mismatch, invalid signature encoding,
/// authentication failure, or missing providers.
pub fn cose_verify_iso18013_sign1(
    request: Iso18013Sign1Request<'_>,
    verifier: &dyn Iso18013Verifier,
) -> Result<VerifiedIso18013Sign1, CoseError> {
    let encoded_limit = request.limits.max_encoded_bytes.min(MAX_COSE_SIGN1_BYTES);
    let payload_limit = request
        .limits
        .max_payload_bytes
        .min(MAX_DETACHED_PAYLOAD_BYTES);
    if request.encoded.len() > encoded_limit {
        return Err(CoseError::ResourceLimitExceeded);
    }
    if let Iso18013Sign1Content::DeviceDetached(payload)
    | Iso18013Sign1Content::ReaderDetached(payload) = request.content
    {
        if payload.len() > payload_limit {
            return Err(CoseError::ResourceLimitExceeded);
        }
    }
    let decoded = decode(request.encoded, encoded_limit)?;
    let payload = match request.content {
        Iso18013Sign1Content::IssuerAttached => decoded
            .payload
            .as_ref()
            .map(|payload| payload.as_slice())
            .ok_or(CoseError::MissingPayload)?,
        Iso18013Sign1Content::DeviceDetached(payload)
        | Iso18013Sign1Content::ReaderDetached(payload) => {
            if decoded.payload.is_some() {
                return Err(CoseError::InvalidFormat);
            }
            payload
        }
    };
    if payload.len() > payload_limit {
        return Err(CoseError::ResourceLimitExceeded);
    }
    let suite = verifier.suite();
    if suite.algorithm() != decoded.algorithm {
        return Err(CoseError::InvalidKeyMaterial);
    }
    if !request.allowed_suites.contains(&suite) {
        return Err(CoseError::UnsupportedAlgorithm);
    }
    if decoded.signature.len() != suite.curve().signature_length()? {
        return Err(CoseError::InvalidSignatureEncoding);
    }
    let structure = build_authentication_structure(
        AuthenticationContext::Signature1,
        &decoded.protected,
        &[],
        payload,
    )?;
    verifier.verify(&structure, &decoded.signature)?;
    Ok(VerifiedIso18013Sign1 {
        suite,
        protected: decoded.protected,
        protected_kid: decoded.protected_kid,
        payload: decoded.payload,
    })
}
