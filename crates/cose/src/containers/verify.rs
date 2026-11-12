// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::own_bytes::copy;
use super::{
    ContainerContent, ContainerError, ContainerErrorReason as Reason, ContainerLimits,
    ContainerPolicy, ContainerProfile, ContainerPurpose, EndEntityIntegrity, HeaderProvenance,
    SignatureSuite, VerificationSource, VerifiedContainer,
};
use crate::build_authentication_structure::{
    build_authentication_structure, AuthenticationContext,
};
use crate::limits::{
    MAX_COSE_KEY_BYTES, MAX_COSE_SIGN1_BYTES, MAX_COSE_X5CHAIN_CERTIFICATE_BYTES,
    MAX_DETACHED_PAYLOAD_BYTES,
};
use crate::X5ChainHeaderPlacement;
use reallyme_crypto::operations::{constant_time, hash};
use zeroize::Zeroizing;

/// All bounded inputs and explicit policy for a single verification.
pub struct ContainerVerifyRequest<'a> {
    /// Received encoded Sign1 bytes.
    pub encoded: &'a [u8],
    /// Attached or exact caller-supplied detached content.
    pub content: ContainerContent<'a>,
    /// Explicit AAD; ISO contracts require empty bytes.
    pub external_aad: &'a [u8],
    /// Source baseline, purpose and envelope policy.
    pub policy: ContainerPolicy,
    /// Exact algorithm/curve allowlist; an empty list permits nothing.
    pub allowed_suites: &'a [SignatureSuite],
    /// Caller-tightenable limits.
    pub limits: ContainerLimits,
}

/// Authenticate a bounded opaque container with exact received protected bytes.
///
/// Certificate trust, payload schemas, ordered request construction, permission
/// to use ReaderAuthAll, and revocation freshness remain outside this function.
///
/// # Errors
/// Returns only fixed `ContainerErrorReason` values. No receipt is released for
/// malformed input, policy/identity mismatch, unavailable crypto or failed authentication.
pub fn verify_container(
    request: ContainerVerifyRequest<'_>,
    source: VerificationSource<'_>,
) -> Result<VerifiedContainer, ContainerError> {
    check_limits(&request)?;
    let envelope = super::decode::decode(request.encoded)?;
    let payload = match request.content {
        ContainerContent::Attached => envelope.payload.ok_or(Reason::Profile)?,
        ContainerContent::Detached(payload) => {
            if envelope.payload.is_some() {
                return Err(Reason::Profile.into());
            }
            payload
        }
    };
    if payload.len() > request.limits.payload_bytes.min(MAX_DETACHED_PAYLOAD_BYTES) {
        return Err(Reason::Limit.into());
    }
    let permitted = request
        .allowed_suites
        .iter()
        .find(|suite| suite.registration().identifier() == envelope.headers.algorithm)
        .ok_or(Reason::Algorithm)?;
    // Reject COSE-owned policy and framing failures before invoking an external
    // certificate boundary, which may involve expensive path validation.
    request.policy.check(
        *permitted,
        envelope.payload.is_some(),
        envelope.tagged,
        request.external_aad,
    )?;
    let headers = &envelope.headers.certificates;
    let has_certificate = matches!(&source, VerificationSource::Certificates(_));
    if !has_certificate && (headers.count != 0 || headers.thumbprint.is_some()) {
        return Err(Reason::Profile.into());
    }
    let provenance = check_placement(request.policy, headers, has_certificate)?;
    if matches!(
        request.policy.purpose,
        ContainerPurpose::IssuerMso
            | ContainerPurpose::MsoRevocation
            | ContainerPurpose::Vical
            | ContainerPurpose::Rical
    ) {
        super::validate_preferred_cbor(payload)?;
    }
    // An exact key curve can be resolved only by the trusted boundary. Before
    // that work, the signature must at least fit one explicitly permitted pair.
    if !request
        .allowed_suites
        .iter()
        .filter(|suite| suite.registration().identifier() == envelope.headers.algorithm)
        .any(|suite| {
            super::signature::validate_cose_signature(suite.curve(), envelope.signature).is_ok()
        })
    {
        return Err(Reason::SignatureEncoding.into());
    }
    let (key, certificate) = match source {
        VerificationSource::Key(key) => (key, None),
        VerificationSource::Certificates(validator) => {
            let selection = validator.resolve(headers, envelope.headers.algorithm)?;
            (selection.key, Some(selection.end_entity_der))
        }
    };
    let suite = key.suite();
    if suite.registration().identifier() != envelope.headers.algorithm {
        return Err(Reason::Key.into());
    }
    if !request.allowed_suites.contains(&suite) {
        return Err(Reason::Algorithm.into());
    }
    if key.public_key().is_empty() || key.public_key().len() > MAX_COSE_KEY_BYTES {
        return Err(Reason::Key.into());
    }
    let certificate_digest = certificate
        .map(|der| check_certificate(der, headers))
        .transpose()?;
    super::signature::validate_cose_signature(suite.curve(), envelope.signature)?;
    let structure = build_authentication_structure(
        AuthenticationContext::Signature1,
        envelope.protected,
        request.external_aad,
        payload,
    )?;
    key.verify(&structure, envelope.signature)?;
    Ok(VerifiedContainer {
        policy: request.policy,
        suite,
        provenance,
        encoded: copy(request.encoded)?,
        protected: copy(envelope.protected)?,
        unprotected: copy(envelope.unprotected)?,
        payload: copy(payload)?,
        public_key: copy(key.public_key())?,
        context: Zeroizing::new(*key.context_id()),
        certificate_digest,
    })
}

pub(super) fn check_limits(request: &ContainerVerifyRequest<'_>) -> Result<(), ContainerError> {
    if request.encoded.len() > request.limits.encoded_bytes.min(MAX_COSE_SIGN1_BYTES)
        || request.external_aad.len() > request.limits.external_aad_bytes.min(MAX_COSE_SIGN1_BYTES)
    {
        return Err(Reason::Limit.into());
    }
    if let ContainerContent::Detached(payload) = request.content {
        if payload.len() > request.limits.payload_bytes.min(MAX_DETACHED_PAYLOAD_BYTES) {
            return Err(Reason::Limit.into());
        }
    }
    Ok(())
}

fn check_certificate(
    der: &[u8],
    headers: &super::CertificateHeaders<'_>,
) -> Result<Zeroizing<[u8; 32]>, ContainerError> {
    if der.is_empty() || der.len() > MAX_COSE_X5CHAIN_CERTIFICATE_BYTES {
        return Err(Reason::Limit.into());
    }
    if let Some(leaf) = headers.certificates().next() {
        if !constant_time::equal(leaf, der) {
            return Err(Reason::CertificateMismatch.into());
        }
    }
    let digest = Zeroizing::new(hash::sha2_256(der).into_bytes());
    if headers
        .thumbprint
        .is_some_and(|expected| !constant_time::equal(expected, digest.as_ref()))
    {
        return Err(Reason::CertificateMismatch.into());
    }
    Ok(digest)
}

pub(super) fn check_placement(
    policy: ContainerPolicy,
    headers: &super::CertificateHeaders<'_>,
    has_certificate: bool,
) -> Result<HeaderProvenance, ContainerError> {
    use ContainerPurpose as Purpose;
    use X5ChainHeaderPlacement::{Protected, Unprotected};
    match policy.purpose {
        Purpose::IssuerMso | Purpose::Vical if headers.placement.is_none() => {
            return Err(Reason::Profile.into())
        }
        Purpose::ReaderAuthentication | Purpose::ReaderAuthenticationAll
            if has_certificate && headers.placement.is_none() =>
        {
            return Err(Reason::Profile.into())
        }
        _ => {}
    }
    if matches!(policy.purpose, Purpose::MsoRevocation | Purpose::Rical)
        && headers.placement != Some(Protected)
    {
        return Err(Reason::Profile.into());
    }
    if policy.purpose == Purpose::Vical && headers.placement != Some(Unprotected) {
        return Err(Reason::Profile.into());
    }
    if policy.profile == ContainerProfile::Iso2021
        && matches!(
            policy.purpose,
            Purpose::IssuerMso | Purpose::ReaderAuthentication
        )
        && headers.placement != Some(Unprotected)
        && has_certificate
    {
        return Err(Reason::Profile.into());
    }
    let integrity = if headers.thumbprint.is_some() {
        EndEntityIntegrity::ProtectedThumbprint
    } else if headers.placement == Some(Protected) {
        EndEntityIntegrity::ProtectedChain
    } else if headers.placement == Some(Unprotected) && policy.profile != ContainerProfile::Rfc9360
    {
        EndEntityIntegrity::IsoUnprotectedChain
    } else if !has_certificate {
        EndEntityIntegrity::ExternalKey
    } else {
        return Err(Reason::Profile.into());
    };
    Ok(HeaderProvenance {
        chain_placement: headers.placement,
        protected_thumbprint: headers.thumbprint.is_some(),
        end_entity_integrity: integrity,
    })
}
