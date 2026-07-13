// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0
use crate::CoseError;
use coset::iana;
use reallyme_crypto::core::Algorithm;

/// Strict DID-scoped algorithm mapping.
pub fn algorithm_from_cose_alg(alg: &coset::Algorithm) -> Result<Algorithm, CoseError> {
    match alg {
        coset::Algorithm::Assigned(iana::Algorithm::EdDSA) => Ok(Algorithm::Ed25519),

        coset::Algorithm::Assigned(iana::Algorithm::ES256) => Ok(Algorithm::P256),

        coset::Algorithm::Assigned(iana::Algorithm::ES384) => Ok(Algorithm::P384),

        coset::Algorithm::Assigned(iana::Algorithm::ES512) => Ok(Algorithm::P521),

        coset::Algorithm::Assigned(iana::Algorithm::ES256K) => Ok(Algorithm::Secp256k1),

        _ => Err(CoseError::UnsupportedAlgorithm),
    }
}
