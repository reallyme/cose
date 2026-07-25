// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use coset::{iana, RegisteredLabelWithPrivate};
use reallyme_crypto::core::Algorithm;

use crate::CoseError;

pub(crate) fn alg_to_cose(alg: Algorithm) -> Result<iana::Algorithm, CoseError> {
    match alg {
        Algorithm::Ed25519 => Ok(iana::Algorithm::Ed25519),
        Algorithm::P256 => Ok(iana::Algorithm::ESP256),
        Algorithm::P384 => Ok(iana::Algorithm::ESP384),
        Algorithm::P521 => Ok(iana::Algorithm::ESP512),
        Algorithm::Secp256k1 => Ok(iana::Algorithm::ES256K),
        Algorithm::MlDsa44 => Ok(iana::Algorithm::ML_DSA_44),
        Algorithm::MlDsa65 => Ok(iana::Algorithm::ML_DSA_65),
        Algorithm::MlDsa87 => Ok(iana::Algorithm::ML_DSA_87),
        _ => Err(CoseError::UnsupportedAlgorithm),
    }
}

pub(crate) fn cose_to_alg(
    alg: &RegisteredLabelWithPrivate<iana::Algorithm>,
) -> Result<Algorithm, CoseError> {
    match alg {
        RegisteredLabelWithPrivate::Assigned(iana::Algorithm::Ed25519) => Ok(Algorithm::Ed25519),
        RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ESP256) => Ok(Algorithm::P256),
        RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ESP384) => Ok(Algorithm::P384),
        RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ESP512) => Ok(Algorithm::P521),
        RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ES256K) => Ok(Algorithm::Secp256k1),
        RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ML_DSA_44) => Ok(Algorithm::MlDsa44),
        RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ML_DSA_65) => Ok(Algorithm::MlDsa65),
        RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ML_DSA_87) => Ok(Algorithm::MlDsa87),
        _ => Err(CoseError::UnsupportedAlgorithm),
    }
}
