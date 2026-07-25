// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use coset::CoseSign1;
use reallyme_crypto::core::Algorithm;
use reallyme_crypto::dispatch::verify;

use crate::encode_cbor::encode_protected_header;
use crate::error::verify_error_from_algorithm_error;
use crate::failure::CoseFailure;
use crate::policy::{validate_cose_sign1_policy, CosePolicy};
use crate::{key::map_algorithm::cose_to_alg, CoseError};

use super::build_sig_structure::build_sig_structure;
use super::convert_signature::backend_signature_from_cose;
use super::decode::{decode_cose_sign1, validate_cose_sign1_structure};
use super::types::{CoseSign1DetachedVerifyInput, CoseSign1KeyResolution, CoseSign1VerifyInput};
use crate::limits::validate_detached_payload_with_limit;
use zeroize::Zeroizing;

/// Verified COSE_Sign1 attached payload and protected-header metadata.
#[must_use]
#[non_exhaustive]
pub struct VerifiedCoseSign1 {
    /// Verified attached payload bytes.
    pub payload: Zeroizing<Vec<u8>>,

    /// Verified protected-header algorithm.
    pub alg: Algorithm,

    /// Verified protected-header key identifier.
    pub kid: Zeroizing<Vec<u8>>,
}

/// Verified COSE_Sign1 protected-header metadata for detached payloads.
#[must_use]
#[non_exhaustive]
pub struct VerifiedDetachedCoseSign1 {
    /// Verified protected-header algorithm.
    pub alg: Algorithm,

    /// Verified protected-header key identifier.
    pub kid: Zeroizing<Vec<u8>>,
}

/// Verify COSE_Sign1 with an attached payload.
///
/// # Errors
///
/// Returns [`CoseError`] for malformed or oversized COSE, unsupported or
/// disallowed algorithms, unresolved keys, invalid keys, or invalid signatures.
pub fn cose_verify1(
    cose_bytes: &[u8],
    public_key_resolver: impl Fn(Algorithm, &[u8]) -> Option<Vec<u8>>,
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    let verified =
        cose_verify1_with_policy(cose_bytes, &CosePolicy::default(), public_key_resolver)?;
    Ok(verified.payload)
}

/// Verify COSE_Sign1 with an attached payload and return verified metadata.
///
/// # Errors
///
/// Returns [`CoseError`] for malformed or oversized COSE, unsupported or
/// disallowed algorithms, unresolved keys, invalid keys, or invalid signatures.
pub fn cose_verify1_with_metadata(
    cose_bytes: &[u8],
    public_key_resolver: impl Fn(Algorithm, &[u8]) -> Option<Vec<u8>>,
) -> Result<VerifiedCoseSign1, CoseError> {
    cose_verify1_with_policy(cose_bytes, &CosePolicy::default(), public_key_resolver)
}

/// Verify COSE_Sign1 with an attached payload under an explicit policy.
///
/// # Errors
///
/// Returns [`CoseError`] when decoding, policy validation, key resolution, key
/// validation, signature decoding, or signature verification fails.
pub fn cose_verify1_with_policy(
    cose_bytes: &[u8],
    policy: &CosePolicy,
    public_key_resolver: impl Fn(Algorithm, &[u8]) -> Option<Vec<u8>>,
) -> Result<VerifiedCoseSign1, CoseError> {
    cose_verify1_with_policy_and_external_aad(cose_bytes, &[], policy, public_key_resolver)
}

/// Verify an attached COSE_Sign1 with explicit external AAD and policy.
///
/// # Errors
///
/// Returns [`CoseError`] when the COSE structure, external AAD, policy,
/// resolver result, key material, signature encoding, or signature is invalid.
pub fn cose_verify1_with_policy_and_external_aad(
    cose_bytes: &[u8],
    external_aad: &[u8],
    policy: &CosePolicy,
    public_key_resolver: impl Fn(Algorithm, &[u8]) -> Option<Vec<u8>>,
) -> Result<VerifiedCoseSign1, CoseError> {
    verify_cose_sign1(
        CoseSign1VerifyInput::new(cose_bytes, external_aad, policy),
        |algorithm, kid| match public_key_resolver(algorithm, kid) {
            Some(public_key) => CoseSign1KeyResolution::Resolved(Zeroizing::new(public_key)),
            None => CoseSign1KeyResolution::NotResolved,
        },
    )
    .map_err(CoseFailure::into_native_error)
}

/// Verify COSE_Sign1 with a detached payload.
///
/// # Errors
///
/// Returns [`CoseError`] for malformed or oversized COSE, an attached payload,
/// unsupported algorithms, unresolved keys, invalid keys, or invalid signatures.
pub fn cose_verify1_detached(
    cose_bytes: &[u8],
    payload: &[u8],
    public_key_resolver: impl Fn(Algorithm, &[u8]) -> Option<Vec<u8>>,
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
///
/// # Errors
///
/// Returns [`CoseError`] for malformed or oversized COSE, an attached payload,
/// unsupported algorithms, unresolved keys, invalid keys, or invalid signatures.
pub fn cose_verify1_detached_with_metadata(
    cose_bytes: &[u8],
    payload: &[u8],
    public_key_resolver: impl Fn(Algorithm, &[u8]) -> Option<Vec<u8>>,
) -> Result<VerifiedDetachedCoseSign1, CoseError> {
    cose_verify1_detached_with_policy(
        cose_bytes,
        payload,
        &CosePolicy::default(),
        public_key_resolver,
    )
}

/// Verify COSE_Sign1 with a detached payload under an explicit policy.
///
/// # Errors
///
/// Returns [`CoseError`] when decoding, policy validation, payload validation,
/// key resolution, key validation, or signature verification fails.
pub fn cose_verify1_detached_with_policy(
    cose_bytes: &[u8],
    payload: &[u8],
    policy: &CosePolicy,
    public_key_resolver: impl Fn(Algorithm, &[u8]) -> Option<Vec<u8>>,
) -> Result<VerifiedDetachedCoseSign1, CoseError> {
    cose_verify1_detached_with_policy_and_external_aad(
        cose_bytes,
        payload,
        &[],
        policy,
        public_key_resolver,
    )
}

/// Verify a detached COSE_Sign1 with explicit external AAD and policy.
///
/// # Errors
///
/// Returns [`CoseError`] when the COSE structure, detached payload, external
/// AAD, policy, resolver result, key material, or signature is invalid.
pub fn cose_verify1_detached_with_policy_and_external_aad(
    cose_bytes: &[u8],
    payload: &[u8],
    external_aad: &[u8],
    policy: &CosePolicy,
    public_key_resolver: impl Fn(Algorithm, &[u8]) -> Option<Vec<u8>>,
) -> Result<VerifiedDetachedCoseSign1, CoseError> {
    verify_detached_cose_sign1(
        CoseSign1DetachedVerifyInput::new(cose_bytes, payload, external_aad, policy),
        |algorithm, kid| match public_key_resolver(algorithm, kid) {
            Some(public_key) => CoseSign1KeyResolution::Resolved(Zeroizing::new(public_key)),
            None => CoseSign1KeyResolution::NotResolved,
        },
    )
    .map_err(CoseFailure::into_native_error)
}

pub(crate) fn verify_cose_sign1(
    input: CoseSign1VerifyInput<'_>,
    public_key_resolver: impl FnOnce(Algorithm, &[u8]) -> CoseSign1KeyResolution,
) -> Result<VerifiedCoseSign1, CoseFailure> {
    validate_detached_payload_with_limit(
        input.external_aad,
        input.policy.max_detached_payload_bytes(),
    )?;
    let mut cose = decode_cose_sign1(input.cose_sign1, input.policy.max_cose_sign1_bytes())?;
    let payload = cose
        .inner()
        .payload
        .as_ref()
        .ok_or(CoseError::MissingPayload)?;
    let metadata = verify_cose_signature(
        cose.inner(),
        input.external_aad,
        payload,
        input.policy,
        public_key_resolver,
    )?;
    let payload = cose
        .inner_mut()
        .payload
        .take()
        .ok_or(CoseError::MissingPayload)?;

    Ok(VerifiedCoseSign1 {
        payload: Zeroizing::new(payload),
        alg: metadata.alg,
        kid: metadata.kid,
    })
}

pub(crate) fn verify_detached_cose_sign1(
    input: CoseSign1DetachedVerifyInput<'_>,
    public_key_resolver: impl FnOnce(Algorithm, &[u8]) -> CoseSign1KeyResolution,
) -> Result<VerifiedDetachedCoseSign1, CoseFailure> {
    validate_detached_payload_with_limit(input.payload, input.policy.max_detached_payload_bytes())?;
    validate_detached_payload_with_limit(
        input.external_aad,
        input.policy.max_detached_payload_bytes(),
    )?;
    let cose = decode_cose_sign1(input.cose_sign1, input.policy.max_cose_sign1_bytes())?;
    if cose.inner().payload.is_some() {
        return Err(CoseFailure::from(CoseError::InvalidFormat));
    }

    verify_cose_signature(
        cose.inner(),
        input.external_aad,
        input.payload,
        input.policy,
        public_key_resolver,
    )
}

fn verify_cose_signature(
    cose: &CoseSign1,
    external_aad: &[u8],
    payload: &[u8],
    policy: &CosePolicy,
    public_key_resolver: impl FnOnce(Algorithm, &[u8]) -> CoseSign1KeyResolution,
) -> Result<VerifiedDetachedCoseSign1, CoseFailure> {
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
    // Key stores must resolve the algorithm and identifier as one tuple. This
    // prevents a shared kid from selecting bytes belonging to another key
    // family and keeps that invariant independent of backend key-shape checks.
    let public_key = match public_key_resolver(alg, kid) {
        CoseSign1KeyResolution::Resolved(public_key) => public_key,
        CoseSign1KeyResolution::NotResolved => {
            return Err(CoseFailure::from(key_resolution_error(kid)));
        }
        #[cfg(feature = "wire")]
        CoseSign1KeyResolution::KidMismatch => {
            return Err(CoseFailure::sign1_kid_key_mismatch());
        }
    };

    // RFC 9052 §4.4: the Sig_structure must carry the protected header bstr
    // exactly as received, not a re-encoding of the parsed header.
    let protected_bytes = encode_protected_header(&cose.protected)?;
    let to_verify = build_sig_structure(&protected_bytes, external_aad, payload)?;
    let backend_signature = backend_signature_from_cose(alg, &cose.signature)?;

    verify(alg, &public_key, &to_verify, &backend_signature)
        .map_err(verify_error_from_algorithm_error)?;

    Ok(VerifiedDetachedCoseSign1 {
        alg,
        kid: Zeroizing::new(kid.to_vec()),
    })
}

fn key_resolution_error(kid: &[u8]) -> CoseError {
    if kid.is_empty() {
        CoseError::MissingKid
    } else {
        CoseError::KeyNotResolved
    }
}
