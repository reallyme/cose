// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use coset::{iana, RegisteredLabelWithPrivate};
use reallyme_crypto::core::Algorithm;

use crate::CoseError;

pub(crate) fn alg_to_cose(alg: Algorithm) -> Result<iana::Algorithm, CoseError> {
    match alg {
        Algorithm::Ed25519 => Ok(iana::Algorithm::EdDSA),
        Algorithm::P256 => Ok(iana::Algorithm::ES256),
        Algorithm::P384 => Ok(iana::Algorithm::ES384),
        Algorithm::P521 => Ok(iana::Algorithm::ES512),
        Algorithm::Secp256k1 => Ok(iana::Algorithm::ES256K),
        _ => Err(CoseError::UnsupportedAlgorithm),
    }
}

pub(crate) fn cose_to_alg(
    alg: &RegisteredLabelWithPrivate<iana::Algorithm>,
) -> Result<Algorithm, CoseError> {
    match alg {
        RegisteredLabelWithPrivate::Assigned(iana::Algorithm::EdDSA) => Ok(Algorithm::Ed25519),
        RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ES256) => Ok(Algorithm::P256),
        RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ES384) => Ok(Algorithm::P384),
        RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ES512) => Ok(Algorithm::P521),
        RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ES256K) => Ok(Algorithm::Secp256k1),
        _ => Err(CoseError::UnsupportedAlgorithm),
    }
}
