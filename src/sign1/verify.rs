// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use coset::{CborSerializable, CoseSign1, TaggedCborSerializable};
use reallyme_crypto::core::Algorithm;
use reallyme_crypto::dispatch::verify;

use crate::policy::{validate_cose_sign1_policy, CosePolicy};
use crate::{key::map_algorithm::cose_to_alg, CoseError};

use super::build_sig_structure::build_sig_structure;
use super::convert_ecdsa_signature::backend_signature_from_cose;
use crate::limits::{
    validate_cose_sign1_bytes_with_limit, validate_detached_payload_with_limit,
    validate_protected_header_bytes,
};

/// Verified COSE_Sign1 attached payload and protected-header metadata.
pub struct VerifiedCoseSign1 {
    /// Verified attached payload bytes.
    pub payload: Vec<u8>,

    /// Verified protected-header algorithm.
    pub alg: Algorithm,

    /// Verified protected-header key identifier.
    pub kid: Vec<u8>,
}

/// Verified COSE_Sign1 protected-header metadata for detached payloads.
pub struct VerifiedDetachedCoseSign1 {
    /// Verified protected-header algorithm.
    pub alg: Algorithm,

    /// Verified protected-header key identifier.
    pub kid: Vec<u8>,
}

/// Verify COSE_Sign1 with an attached payload.
pub fn cose_verify1(
    cose_bytes: &[u8],
    public_key_resolver: impl Fn(&[u8]) -> Option<Vec<u8>>,
) -> Result<Vec<u8>, CoseError> {
    let verified =
        cose_verify1_with_policy(cose_bytes, &CosePolicy::default(), public_key_resolver)?;
    Ok(verified.payload)
}

/// Verify COSE_Sign1 with an attached payload and return verified metadata.
pub fn cose_verify1_with_metadata(
    cose_bytes: &[u8],
    public_key_resolver: impl Fn(&[u8]) -> Option<Vec<u8>>,
) -> Result<VerifiedCoseSign1, CoseError> {
    cose_verify1_with_policy(cose_bytes, &CosePolicy::default(), public_key_resolver)
}

/// Verify COSE_Sign1 with an attached payload under an explicit policy.
pub fn cose_verify1_with_policy(
    cose_bytes: &[u8],
    policy: &CosePolicy,
    public_key_resolver: impl Fn(&[u8]) -> Option<Vec<u8>>,
) -> Result<VerifiedCoseSign1, CoseError> {
    validate_cose_sign1_bytes_with_limit(cose_bytes, policy.max_cose_sign1_bytes)?;
    let cose = decode_cose_sign1(cose_bytes)?;
    let payload = cose.payload.as_ref().ok_or(CoseError::MissingPayload)?;

    let metadata = verify_cose_signature(&cose, payload, policy, public_key_resolver)?;

    Ok(VerifiedCoseSign1 {
        payload: payload.clone(),
        alg: metadata.alg,
        kid: metadata.kid,
    })
}

/// Verify COSE_Sign1 with a detached payload.
pub fn cose_verify1_detached(
    cose_bytes: &[u8],
    payload: &[u8],
    public_key_resolver: impl Fn(&[u8]) -> Option<Vec<u8>>,
) -> Result<(), CoseError> {
    cose_verify1_detached_with_policy(
        cose_bytes,
        payload,
        &CosePolicy::default(),
        public_key_resolver,
    )
    .map(|_| ())
}

/// Verify COSE_Sign1 with a detached payload and return verified metadata.
pub fn cose_verify1_detached_with_metadata(
    cose_bytes: &[u8],
    payload: &[u8],
    public_key_resolver: impl Fn(&[u8]) -> Option<Vec<u8>>,
) -> Result<VerifiedDetachedCoseSign1, CoseError> {
    cose_verify1_detached_with_policy(
        cose_bytes,
        payload,
        &CosePolicy::default(),
        public_key_resolver,
    )
}

/// Verify COSE_Sign1 with a detached payload under an explicit policy.
pub fn cose_verify1_detached_with_policy(
    cose_bytes: &[u8],
    payload: &[u8],
    policy: &CosePolicy,
    public_key_resolver: impl Fn(&[u8]) -> Option<Vec<u8>>,
) -> Result<VerifiedDetachedCoseSign1, CoseError> {
    validate_cose_sign1_bytes_with_limit(cose_bytes, policy.max_cose_sign1_bytes)?;
    validate_detached_payload_with_limit(payload, policy.max_detached_payload_bytes)?;
    let cose = decode_cose_sign1(cose_bytes)?;

    if cose.payload.is_some() {
        return Err(CoseError::InvalidFormat);
    }

    verify_cose_signature(&cose, payload, policy, public_key_resolver)
}

/// Decode untagged COSE_Sign1 bytes, or bytes carrying the registered
/// COSE_Sign1 tag (18) already allowed by the byte-boundary tag policy.
fn decode_cose_sign1(cose_bytes: &[u8]) -> Result<CoseSign1, CoseError> {
    CoseSign1::from_slice(cose_bytes)
        .or_else(|_| CoseSign1::from_tagged_slice(cose_bytes))
        .map_err(|_| CoseError::Cbor)
}

fn verify_cose_signature(
    cose: &CoseSign1,
    payload: &[u8],
    policy: &CosePolicy,
    public_key_resolver: impl Fn(&[u8]) -> Option<Vec<u8>>,
) -> Result<VerifiedDetachedCoseSign1, CoseError> {
    validate_cose_sign1_structure(cose)?;
    validate_cose_sign1_policy(cose, policy)?;

    let cose_alg = cose
        .protected
        .header
        .alg
        .as_ref()
        .ok_or(CoseError::UnsupportedAlgorithm)?;
    let alg = cose_to_alg(cose_alg)?;

    let kid: &[u8] = &cose.protected.header.key_id;
    let public_key = public_key_resolver(kid).ok_or_else(|| key_resolution_error(kid))?;

    // RFC 9052 §4.4: the Sig_structure must carry the protected header bstr
    // exactly as received, not a re-encoding of the parsed header.
    let protected_bytes = match &cose.protected.original_data {
        Some(original) => original.clone(),
        None => cose
            .protected
            .clone()
            .to_vec()
            .map_err(|_| CoseError::Cbor)?,
    };
    let to_verify = build_sig_structure(&protected_bytes, payload);
    let backend_signature = backend_signature_from_cose(alg, &cose.signature)?;

    verify(alg, &public_key, &to_verify, &backend_signature)
        .map_err(|_| CoseError::InvalidSignature)?;

    Ok(VerifiedDetachedCoseSign1 {
        alg,
        kid: kid.to_vec(),
    })
}

fn key_resolution_error(kid: &[u8]) -> CoseError {
    if kid.is_empty() {
        CoseError::MissingKid
    } else {
        CoseError::KeyNotResolved
    }
}

fn validate_cose_sign1_structure(cose: &CoseSign1) -> Result<(), CoseError> {
    if let Some(protected_bytes) = &cose.protected.original_data {
        validate_protected_header_bytes(protected_bytes)?;
    }

    if !cose.protected.header.crit.is_empty() {
        return Err(CoseError::UnsupportedCriticalHeader);
    }

    if cose.unprotected.alg.is_some() || !cose.unprotected.key_id.is_empty() {
        return Err(CoseError::UnprotectedHeaderNotAllowed);
    }

    if !cose.unprotected.crit.is_empty() {
        return Err(CoseError::UnsupportedCriticalHeader);
    }

    Ok(())
}
