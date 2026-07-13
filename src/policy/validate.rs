// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0
use crate::algorithm::algorithm_from_cose_alg;
use coset::CoseSign1;
use reallyme_crypto::core::Algorithm;

use crate::limits::{MAX_COSE_SIGN1_BYTES, MAX_DETACHED_PAYLOAD_BYTES};
use crate::CoseError;

/// Verification policy for COSE_Sign1 byte-boundary APIs.
#[derive(Debug, Clone)]
pub struct CosePolicy {
    /// Require a `kid` / key_id in protected header.
    pub require_kid: bool,

    /// Allowed algorithms. Empty means any algorithm supported by this crate.
    pub allowed_algs: Vec<Algorithm>,

    /// Maximum accepted encoded COSE_Sign1 bytes at public verification APIs.
    pub max_cose_sign1_bytes: usize,

    /// Maximum accepted detached payload bytes at detached verification APIs.
    pub max_detached_payload_bytes: usize,
}

impl Default for CosePolicy {
    fn default() -> Self {
        Self {
            require_kid: false,
            allowed_algs: Vec::new(),
            max_cose_sign1_bytes: MAX_COSE_SIGN1_BYTES,
            max_detached_payload_bytes: MAX_DETACHED_PAYLOAD_BYTES,
        }
    }
}

/// Validate COSE_Sign1 header policy without performing cryptographic verification.
pub fn validate_cose_sign1_policy(cose: &CoseSign1, policy: &CosePolicy) -> Result<(), CoseError> {
    // --- kid requirement ---
    if policy.require_kid && cose.protected.header.key_id.is_empty() {
        return Err(CoseError::MissingKid);
    }

    // --- algorithm allow-list ---
    if !policy.allowed_algs.is_empty() {
        let cose_alg = cose
            .protected
            .header
            .alg
            .as_ref()
            .ok_or(CoseError::UnsupportedAlgorithm)?;

        let alg = algorithm_from_cose_alg(cose_alg)?;

        if !policy.allowed_algs.contains(&alg) {
            return Err(CoseError::UnsupportedAlgorithm);
        }
    }

    Ok(())
}
