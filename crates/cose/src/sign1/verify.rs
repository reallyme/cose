// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::sign1::cose_type::CoseTypeExt;
use coset::CoseSign1;
use reallyme_crypto::core::Algorithm;
use reallyme_crypto::dispatch::verify;

use crate::error::signature_error_from_algorithm_error;
use crate::failure::CoseFailure;
use crate::policy::{validate_cose_sign1_policy, CosePolicy};
use crate::CoseError;

use super::build_sig_structure::build_received_sig_structure;
use super::convert_signature::backend_signature_from_cose;
use super::cose_type::CoseType;
use super::decode::{
    decode_cose_sign1, decode_cose_sign1_with_x5chain, validate_cose_sign1_structure,
    DecodedCoseSign1WithX5Chain,
};
use super::sign::X5ChainHeaderPlacement;
use super::types::{CoseSign1DetachedVerifyInput, CoseSign1KeyResolution, CoseSign1VerifyInput};
use crate::limits::validate_detached_payload_with_limit;
use zeroize::Zeroizing;

use crate::algorithm::CoseSignatureAlgorithm;

#[cfg(kani)]
#[path = "verify_authentication_gate_proof_tests.rs"]
mod verification;

#[cfg(test)]
#[cfg(not(kani))]
#[path = "verify_x5chain_wire_tests.rs"]
mod x5chain_wire_tests;

#[cfg(kani)]
#[path = "verify_x5chain_wire_tests.rs"]
mod x5chain_wire_tests;

/// Verified COSE_Sign1 attached payload and protected-header metadata.
pub use crate::generated_contract::VerifiedCoseSign1;

/// Verified COSE_Sign1 protected-header metadata for detached payloads.
pub use crate::generated_contract::VerifiedDetachedCoseSign1;

/// Verified COSE_Sign1 payload and RFC 9360 certificate path.
pub use crate::generated_contract::VerifiedCoseSign1WithX5Chain;

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
        |algorithm, kid| super::resolve_key::primitive(algorithm, kid, &public_key_resolver),
    )
    .map_err(CoseFailure::into_native_error)
}

/// Verify an attached COSE_Sign1 while resolving by its exact registration.
///
/// The resolver receives [`CoseSignatureAlgorithm`] so a key authorized for
/// ES256 cannot also be selected for ESP256 merely because both use P-256.
///
/// # Errors
///
/// Returns [`CoseError`] for invalid structure, policy, key resolution, or
/// signature verification.
pub fn cose_verify1_with_exact_algorithm(
    cose_bytes: &[u8],
    external_aad: &[u8],
    policy: &CosePolicy,
    public_key_resolver: impl FnOnce(CoseSignatureAlgorithm, &[u8]) -> Option<Vec<u8>>,
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

/// Verify an attached COSE_Sign1 carrying an RFC 9360 `x5chain` header.
///
/// The ordinary verification APIs continue to reject unprotected extensions.
/// This profile-specific entry point requires a non-empty, bounded path in
/// label 33 and supplies it to the caller's trust resolver before signature
/// verification. The resolver must validate certificate semantics, trust, and
/// the end-entity public key.
///
/// The path must be in the protected header unless the policy explicitly
/// enables [`CosePolicy::with_allow_unprotected_x5chain`]. An unprotected path
/// is not covered by the signature.
///
/// # Errors
///
/// Returns [`CoseError`] when the COSE structure, certificate path, policy,
/// trust resolution, key material, or signature is invalid. Returns
/// [`CoseError::UnprotectedHeaderNotAllowed`] for an unprotected path that the
/// policy does not accept.
pub fn cose_verify1_with_x5chain(
    cose_bytes: &[u8],
    policy: &CosePolicy,
    public_key_resolver: impl FnOnce(Algorithm, &[Vec<u8>]) -> Option<Vec<u8>>,
) -> Result<VerifiedCoseSign1WithX5Chain, CoseError> {
    cose_verify1_with_x5chain_and_exact_algorithm(cose_bytes, policy, |algorithm, certificates| {
        algorithm
            .crypto_algorithm()
            .ok()
            .and_then(|primitive| public_key_resolver(primitive, certificates))
    })
}

/// Verify an attached certificate-bearing COSE_Sign1 with exact algorithm
/// registration supplied to the trust resolver.
///
/// Header placement follows [`cose_verify1_with_x5chain`].
///
/// # Errors
///
/// Returns [`CoseError`] for invalid structure, certificates, policy, key
/// resolution, or signature verification.
pub fn cose_verify1_with_x5chain_and_exact_algorithm(
    cose_bytes: &[u8],
    policy: &CosePolicy,
    public_key_resolver: impl FnOnce(CoseSignatureAlgorithm, &[Vec<u8>]) -> Option<Vec<u8>>,
) -> Result<VerifiedCoseSign1WithX5Chain, CoseError> {
    verify_cose_sign1_x5chain(cose_bytes, policy, public_key_resolver)
}

pub(crate) fn verify_cose_sign1_x5chain(
    cose_bytes: &[u8],
    policy: &CosePolicy,
    public_key_resolver: impl FnOnce(CoseSignatureAlgorithm, &[Vec<u8>]) -> Option<Vec<u8>>,
) -> Result<VerifiedCoseSign1WithX5Chain, CoseError> {
    let mut decoded = decode_cose_sign1_with_x5chain(cose_bytes, policy.max_cose_sign1_bytes())?;
    let (metadata, x5chain_header_placement) =
        verify_x5chain_signature(&decoded, policy, public_key_resolver)?;
    let payload = decoded
        .cose
        .inner_mut()
        .payload
        .take()
        .ok_or(CoseError::MissingPayload)?;
    Ok(VerifiedCoseSign1WithX5Chain {
        payload: Zeroizing::new(payload),
        alg: metadata.alg,
        cose_algorithm: metadata.cose_algorithm,
        kid: metadata.kid,
        cose_type: metadata.cose_type,
        x5chain_der: decoded.x5chain_der,
        x5chain_header_placement,
    })
}

// Keep the decoded chain under its original owner until verification
// succeeds. This lets the trust resolver borrow the exact decoded chain.
fn verify_x5chain_signature(
    decoded: &DecodedCoseSign1WithX5Chain,
    policy: &CosePolicy,
    public_key_resolver: impl FnOnce(CoseSignatureAlgorithm, &[Vec<u8>]) -> Option<Vec<u8>>,
) -> Result<(VerifiedDetachedCoseSign1, X5ChainHeaderPlacement), CoseError> {
    let placement = match decoded.x5chain_placement {
        None => return Err(CoseError::InvalidFormat),
        Some(_) if decoded.x5chain_der.is_empty() => return Err(CoseError::InvalidFormat),
        Some(X5ChainHeaderPlacement::Unprotected) if !policy.allow_unprotected_x5chain() => {
            return Err(CoseError::UnprotectedHeaderNotAllowed);
        }
        Some(placement) => placement,
    };
    let cose = decoded.cose.inner();
    let payload = cose.payload.as_ref().ok_or(CoseError::MissingPayload)?;
    let metadata = verify_cose_signature(
        cose,
        decoded.tagged,
        &[],
        payload,
        policy,
        |algorithm, _| match public_key_resolver(algorithm, &decoded.x5chain_der) {
            Some(public_key) => CoseSign1KeyResolution::Resolved(Zeroizing::new(public_key)),
            None => CoseSign1KeyResolution::NotResolved,
        },
    )
    .map_err(CoseFailure::into_native_error)?;
    Ok((metadata, placement))
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
        |algorithm, kid| super::resolve_key::primitive(algorithm, kid, &public_key_resolver),
    )
    .map_err(CoseFailure::into_native_error)
}

/// Verify a detached COSE_Sign1 while resolving by its exact registration.
///
/// # Errors
///
/// Returns [`CoseError`] for invalid structure, policy, key resolution, or
/// signature verification.
pub fn cose_verify1_detached_with_exact_algorithm(
    cose_bytes: &[u8],
    payload: &[u8],
    external_aad: &[u8],
    policy: &CosePolicy,
    public_key_resolver: impl FnOnce(CoseSignatureAlgorithm, &[u8]) -> Option<Vec<u8>>,
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
    public_key_resolver: impl FnOnce(CoseSignatureAlgorithm, &[u8]) -> CoseSign1KeyResolution,
) -> Result<VerifiedCoseSign1, CoseFailure> {
    validate_detached_payload_with_limit(
        input.external_aad,
        input.policy.max_detached_payload_bytes(),
    )?;
    let decoded = decode_cose_sign1(input.cose_sign1, input.policy.max_cose_sign1_bytes())?;
    let mut cose = decoded.cose;
    let payload = cose
        .inner()
        .payload
        .as_ref()
        .ok_or(CoseError::MissingPayload)?;
    let metadata = verify_cose_signature(
        cose.inner(),
        decoded.tagged,
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
        cose_algorithm: metadata.cose_algorithm,
        kid: metadata.kid,
        cose_type: metadata.cose_type,
    })
}

pub(crate) fn verify_detached_cose_sign1(
    input: CoseSign1DetachedVerifyInput<'_>,
    public_key_resolver: impl FnOnce(CoseSignatureAlgorithm, &[u8]) -> CoseSign1KeyResolution,
) -> Result<VerifiedDetachedCoseSign1, CoseFailure> {
    validate_detached_payload_with_limit(input.payload, input.policy.max_detached_payload_bytes())?;
    validate_detached_payload_with_limit(
        input.external_aad,
        input.policy.max_detached_payload_bytes(),
    )?;
    let decoded = decode_cose_sign1(input.cose_sign1, input.policy.max_cose_sign1_bytes())?;
    let cose = decoded.cose;
    if cose.inner().payload.is_some() {
        return Err(CoseFailure::from(CoseError::InvalidFormat));
    }

    verify_cose_signature(
        cose.inner(),
        decoded.tagged,
        input.external_aad,
        input.payload,
        input.policy,
        public_key_resolver,
    )
}

fn verify_cose_signature(
    cose: &CoseSign1,
    tagged: bool,
    external_aad: &[u8],
    payload: &[u8],
    policy: &CosePolicy,
    public_key_resolver: impl FnOnce(CoseSignatureAlgorithm, &[u8]) -> CoseSign1KeyResolution,
) -> Result<VerifiedDetachedCoseSign1, CoseFailure> {
    validate_cose_sign1_structure(cose)?;
    validate_cose_sign1_policy(cose, tagged, policy)?;

    let cose_alg = cose
        .protected
        .header
        .alg
        .as_ref()
        .ok_or(CoseError::UnsupportedAlgorithm)?;
    let cose_algorithm = crate::key::map_algorithm::cose_to_signature_algorithm(cose_alg)?;
    let alg = cose_algorithm.crypto_algorithm()?;

    let kid: &[u8] = &cose.protected.header.key_id;
    let cose_type = CoseType::from_protected_header(&cose.protected.header)?;
    // Key stores must resolve the algorithm and identifier as one tuple. This
    // prevents a shared kid from selecting bytes belonging to another key
    // family and keeps that invariant independent of backend key-shape checks.
    let public_key = match public_key_resolver(cose_algorithm, kid) {
        CoseSign1KeyResolution::Resolved(public_key) => public_key,
        CoseSign1KeyResolution::NotResolved => {
            return Err(CoseFailure::from(CoseError::KeyNotResolved));
        }
        #[cfg(feature = "wire")]
        CoseSign1KeyResolution::KidMismatch => {
            return Err(CoseFailure::sign1_kid_key_mismatch());
        }
        #[cfg(feature = "wire")]
        CoseSign1KeyResolution::AlgorithmMismatch => {
            return Err(CoseFailure::from(CoseError::UnsupportedAlgorithm));
        }
    };

    // RFC 9052 §4.4: the Sig_structure must carry the protected header bstr
    // exactly as received, not a re-encoding of the parsed header.
    let to_verify = build_received_sig_structure(&cose.protected, external_aad, payload)?;
    let backend_signature = backend_signature_from_cose(alg, &cose.signature)?;

    verify_signature_with_backend(alg, &public_key, &to_verify, &backend_signature)?;

    Ok(VerifiedDetachedCoseSign1 {
        alg,
        cose_algorithm,
        kid: Zeroizing::new(kid.to_vec()),
        cose_type,
    })
}

// Translate provider errors at the boundary so the verification flow can be
// checked against a typed provider result independent of the provider version.
fn verify_signature_with_backend(
    algorithm: Algorithm,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), CoseError> {
    verify(algorithm, public_key, message, signature).map_err(signature_error_from_algorithm_error)
}
