// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::types::CoseSign1KeyResolution;
use crate::{Algorithm, CoseSignatureAlgorithm};
use zeroize::Zeroizing;

pub(super) fn primitive(
    algorithm: CoseSignatureAlgorithm,
    kid: &[u8],
    resolver: &impl Fn(Algorithm, &[u8]) -> Option<Vec<u8>>,
) -> CoseSign1KeyResolution {
    match algorithm
        .crypto_algorithm()
        .ok()
        .and_then(|primitive| resolver(primitive, kid))
    {
        Some(key) => CoseSign1KeyResolution::Resolved(Zeroizing::new(key)),
        None => CoseSign1KeyResolution::NotResolved,
    }
}
