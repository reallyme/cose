// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0
use crate::CoseError;
use coset::iana;
use reallyme_crypto::core::Algorithm;

/// Strict internal mapping from a parsed COSE algorithm to the public selector.
///
/// # Errors
///
/// Returns [`CoseError::UnsupportedAlgorithm`] when the COSE algorithm is not
/// one of the registered algorithms implemented by this crate.
pub(crate) fn algorithm_from_cose_alg(alg: &coset::Algorithm) -> Result<Algorithm, CoseError> {
    match alg {
        coset::Algorithm::Assigned(iana::Algorithm::Ed25519) => Ok(Algorithm::Ed25519),

        coset::Algorithm::Assigned(iana::Algorithm::ESP256) => Ok(Algorithm::P256),

        coset::Algorithm::Assigned(iana::Algorithm::ESP384) => Ok(Algorithm::P384),

        coset::Algorithm::Assigned(iana::Algorithm::ESP512) => Ok(Algorithm::P521),

        coset::Algorithm::Assigned(iana::Algorithm::ES256K) => Ok(Algorithm::Secp256k1),

        coset::Algorithm::Assigned(iana::Algorithm::ML_DSA_44) => Ok(Algorithm::MlDsa44),

        coset::Algorithm::Assigned(iana::Algorithm::ML_DSA_65) => Ok(Algorithm::MlDsa65),

        coset::Algorithm::Assigned(iana::Algorithm::ML_DSA_87) => Ok(Algorithm::MlDsa87),

        _ => Err(CoseError::UnsupportedAlgorithm),
    }
}
