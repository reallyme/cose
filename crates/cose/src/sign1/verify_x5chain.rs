// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::decode::DecodedCoseSign1WithX5Chain;
use super::types::CoseSign1KeyResolution;
use super::verify::{VerifiedCoseSign1WithX5Chain, VerifiedDetachedCoseSign1};
use crate::{CoseError, CosePolicy, CoseSignatureAlgorithm, X5ChainHeaderPlacement};
use zeroize::Zeroizing;

pub(super) fn verify_signature(
    decoded: &DecodedCoseSign1WithX5Chain,
    policy: &CosePolicy,
    resolver: impl FnOnce(
        CoseSignatureAlgorithm,
        X5ChainHeaderPlacement,
        &[Vec<u8>],
    ) -> CoseSign1KeyResolution,
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
    let metadata = super::verify::verify_cose_signature(
        cose,
        decoded.tagged,
        &[],
        payload,
        policy,
        |algorithm, _| resolver(algorithm, placement, &decoded.x5chain_der),
    )
    .map_err(crate::failure::CoseFailure::into_native_error)?;
    Ok((metadata, placement))
}

pub(super) fn finish(
    mut decoded: DecodedCoseSign1WithX5Chain,
    metadata: VerifiedDetachedCoseSign1,
    placement: X5ChainHeaderPlacement,
) -> Result<VerifiedCoseSign1WithX5Chain, CoseError> {
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
        x5chain_header_placement: placement,
    })
}

#[cfg(feature = "wire")]
pub(crate) fn verify_with_certificate(
    encoded: &[u8],
    policy: &CosePolicy,
    resolver: impl FnOnce(
        CoseSignatureAlgorithm,
        X5ChainHeaderPlacement,
        &[Vec<u8>],
    ) -> Result<crate::api::contract::CoseProviderCertificateResult, CoseError>,
) -> Result<VerifiedCoseSign1WithX5Chain, CoseError> {
    let decoded =
        super::decode::decode_cose_sign1_with_x5chain(encoded, policy.max_cose_sign1_bytes())?;
    let (metadata, placement) = verify_signature(
        &decoded,
        policy,
        |algorithm, placement, chain| match resolver(algorithm, placement, chain)
            .and_then(|selection| selected_key(algorithm, chain, selection))
        {
            Ok(key) => CoseSign1KeyResolution::Resolved(key),
            Err(error) => CoseSign1KeyResolution::Rejected(error),
        },
    )?;
    finish(decoded, metadata, placement)
}

#[cfg(feature = "wire")]
fn selected_key(
    algorithm: CoseSignatureAlgorithm,
    chain: &[Vec<u8>],
    mut selection: crate::api::contract::CoseProviderCertificateResult,
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    use crate::containers::SignatureSuite;
    use crate::error::CoseErrorReason as Reason;
    use crate::iso18013::Iso18013SignatureCurve;
    use crate::limits::{MAX_COSE_KEY_BYTES, MAX_COSE_X5CHAIN_CERTIFICATE_BYTES};
    use reallyme_crypto::operations::constant_time;

    const VERIFICATION_CONTEXT_BYTES: usize = 32;
    if selection.end_entity_der.len() > MAX_COSE_X5CHAIN_CERTIFICATE_BYTES {
        return Err(CoseError::ResourceLimitExceeded);
    }
    let leaf = chain.first().ok_or(CoseError::InvalidFormat)?;
    if !constant_time::equal(&selection.end_entity_der, leaf) {
        return Err(Reason::CertificateMismatch.into());
    }
    let mut key = selection.key.take().ok_or(CoseError::InvalidKeyMaterial)?;
    if key.public_key.len() > MAX_COSE_KEY_BYTES {
        return Err(CoseError::ResourceLimitExceeded);
    }
    if key.public_key.is_empty() || key.context_id.len() != VERIFICATION_CONTEXT_BYTES {
        return Err(CoseError::InvalidKeyMaterial);
    }
    let selected = key.suite.as_option().ok_or(CoseError::InvalidKeyMaterial)?;
    let selected = SignatureSuite::try_from(selected)
        .map_err(|_| CoseError::from(Reason::KeyAlgorithmMismatch))?;
    // This is the existing modern Sign1 profile, whose ES256 compatibility
    // registration selects P-256. The ISO operation resolves legacy hash/curve
    // choices separately. ES256 and ESP256 remain distinct even on that curve.
    let expected = if algorithm == CoseSignatureAlgorithm::Es256 {
        SignatureSuite::iso(algorithm, Iso18013SignatureCurve::P256)?
    } else {
        SignatureSuite::modern(algorithm)?
    };
    if selected != expected {
        return Err(Reason::KeyAlgorithmMismatch.into());
    }
    // No key bytes leave the generated wiping owner before all provider
    // assertions have been bound to the exact leaf and protected registration.
    Ok(core::mem::take(&mut key.public_key).into_zeroizing())
}
