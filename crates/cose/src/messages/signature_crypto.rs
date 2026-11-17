// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::bounded;
use crate::api::contract::{CoseNamedCurve as Curve, CoseSignatureSuite};
use crate::{CoseError, CoseSignatureAlgorithm as Registration};
use reallyme_crypto::core::Algorithm;

pub(super) const MAX_ALLOWED_SUITES: usize = 32;

#[derive(Clone, Copy)]
pub(super) enum Backend {
    Primitive(Algorithm),
    Rsa(Registration),
}

pub(super) fn algorithm(suite: &CoseSignatureSuite) -> Result<Backend, CoseError> {
    let registration = Registration::try_from(suite.registration)?;
    if super::rsa::parameters(registration).is_some() {
        if suite.curve != Curve::Unspecified {
            return Err(CoseError::InvalidKeyMaterial);
        }
        return Ok(Backend::Rsa(registration));
    }
    if registration.is_iso() {
        let curve = crate::iso18013::Iso18013SignatureCurve::try_from(suite.curve)?;
        return crate::containers::SignatureSuite::new(registration, curve)?
            .crypto_algorithm()
            .map(Backend::Primitive);
    }
    let expected = match registration {
        Registration::Ed25519 => Curve::Ed25519,
        Registration::Esp256 => Curve::P256,
        Registration::Esp384 => Curve::P384,
        Registration::Esp512 => Curve::P521,
        Registration::Es256K => Curve::Secp256k1,
        Registration::MlDsa44 | Registration::MlDsa65 | Registration::MlDsa87 => Curve::Unspecified,
        _ => return Err(CoseError::UnsupportedAlgorithm),
    };
    if suite.curve != expected {
        return Err(CoseError::InvalidKeyMaterial);
    }
    registration.crypto_algorithm().map(Backend::Primitive)
}

pub(super) fn authorize(
    suite: &CoseSignatureSuite,
    allowed: &[CoseSignatureSuite],
    received: i64,
) -> Result<Backend, CoseError> {
    if allowed.is_empty() || allowed.len() > MAX_ALLOWED_SUITES {
        return Err(CoseError::UnsupportedAlgorithm);
    }
    for (index, candidate) in allowed.iter().enumerate() {
        // Validate identity independently of provider availability.
        let registration = Registration::try_from(candidate.registration)?;
        if registration.is_iso() {
            crate::containers::SignatureSuite::new(
                registration,
                crate::iso18013::Iso18013SignatureCurve::try_from(candidate.curve)?,
            )?;
        } else {
            algorithm(candidate)?;
        }
        if allowed
            .get(..index)
            .ok_or(CoseError::InvalidFormat)?
            .iter()
            .any(|prior| same_suite(prior, candidate))
        {
            return Err(CoseError::InvalidFormat);
        }
    }
    if Registration::try_from(suite.registration)?.identifier() != received
        || !allowed.iter().any(|candidate| same_suite(candidate, suite))
    {
        return Err(CoseError::UnsupportedAlgorithm);
    }
    algorithm(suite)
}

pub(super) fn same_suite(a: &CoseSignatureSuite, b: &CoseSignatureSuite) -> bool {
    match (
        Registration::try_from(a.registration),
        Registration::try_from(b.registration),
    ) {
        (Ok(a_registration), Ok(b_registration)) => {
            a_registration == b_registration && a.curve == b.curve
        }
        _ => false,
    }
}

pub(super) fn sign(
    backend: Backend,
    key: &[u8],
    message: &[u8],
) -> Result<reallyme_cose_proto::SecretBytes, CoseError> {
    let Backend::Primitive(algorithm) = backend else {
        return Err(CoseError::ProviderUnavailable);
    };
    if key.is_empty() {
        return Err(CoseError::MissingPrivateKey);
    }
    let signature = reallyme_crypto::dispatch::sign(algorithm, key, message)
        .map_err(crate::error::signature_error_from_algorithm_error)?;
    let signature = zeroize::Zeroizing::new(crate::sign1::cose_signature_from_backend(
        algorithm, signature,
    )?);
    bounded::copy(&signature)
}

pub(super) fn verify(
    backend: Backend,
    key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), CoseError> {
    let algorithm = match backend {
        Backend::Primitive(algorithm) => algorithm,
        Backend::Rsa(registration) => {
            return super::rsa::verify(registration, key, message, signature)
        }
    };
    crate::key::validate_public_key(algorithm, key)?;
    let signature = zeroize::Zeroizing::new(crate::sign1::backend_signature_from_cose(
        algorithm, signature,
    )?);
    reallyme_crypto::dispatch::verify(algorithm, key, message, &signature)
        .map_err(crate::error::signature_error_from_algorithm_error)
}
