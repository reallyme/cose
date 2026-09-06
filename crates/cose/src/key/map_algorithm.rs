// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use coset::iana;

use crate::algorithm::CoseSignatureAlgorithm;
use crate::CoseError;

pub(crate) fn cose_to_signature_algorithm(
    alg: &coset::RegisteredLabelWithPrivate<iana::Algorithm>,
) -> Result<CoseSignatureAlgorithm, CoseError> {
    CoseSignatureAlgorithm::from_registered(alg)
}
