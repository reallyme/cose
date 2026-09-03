// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0
use crate::algorithm::CoseSignatureAlgorithm;
use crate::CoseError;
use reallyme_crypto::core::Algorithm;

/// Strict internal mapping from a parsed COSE algorithm to the public selector.
///
/// # Errors
///
/// Returns [`CoseError::UnsupportedAlgorithm`] when the COSE algorithm is not
/// one of the registered algorithms implemented by this crate.
pub(crate) fn algorithm_from_cose_alg(alg: &coset::Algorithm) -> Result<Algorithm, CoseError> {
    CoseSignatureAlgorithm::from_registered(alg).map(CoseSignatureAlgorithm::crypto_algorithm)
}
