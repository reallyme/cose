// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0
#[cfg(feature = "cose-crypto")]
use crate::algorithm::algorithm_from_cose_alg;
#[cfg(feature = "cose-crypto")]
use coset::CoseSign1;
use reallyme_crypto::core::Algorithm;

use crate::algorithm::CoseSignatureAlgorithm;
use crate::limits::{MAX_COSE_SIGN1_BYTES, MAX_DETACHED_PAYLOAD_BYTES};
#[cfg(feature = "cose-crypto")]
use crate::CoseError;

/// Verification policy for COSE_Sign1 byte-boundary APIs.
#[must_use]
#[derive(Debug, Clone)]
pub struct CosePolicy {
    /// Require a `kid` / key_id in protected header.
    require_kid: bool,

    /// Allowed algorithms. Empty means any algorithm supported by this crate.
    allowed_algs: Vec<Algorithm>,

    /// Exact COSE registrations accepted by verification.
    allowed_cose_algs: Vec<CoseSignatureAlgorithm>,

    /// Maximum accepted encoded COSE_Sign1 bytes at public verification APIs.
    max_cose_sign1_bytes: usize,

    /// Maximum accepted detached payload bytes at detached verification APIs.
    max_detached_payload_bytes: usize,
}

impl Default for CosePolicy {
    fn default() -> Self {
        Self {
            require_kid: false,
            allowed_algs: Vec::new(),
            allowed_cose_algs: Vec::new(),
            max_cose_sign1_bytes: MAX_COSE_SIGN1_BYTES,
            max_detached_payload_bytes: MAX_DETACHED_PAYLOAD_BYTES,
        }
    }
}

impl CosePolicy {
    /// Construct the default verification policy.
    pub fn new() -> Self {
        Self::default()
    }

    /// Return whether protected-header `kid` is required.
    #[must_use]
    pub fn require_kid(&self) -> bool {
        self.require_kid
    }

    /// Return the configured algorithm allow-list.
    ///
    /// An empty list means any algorithm supported by this crate is accepted.
    #[must_use]
    pub fn allowed_algorithms(&self) -> &[Algorithm] {
        &self.allowed_algs
    }

    /// Return the exact COSE registration allow-list.
    ///
    /// An empty list means no additional registration-specific restriction.
    #[must_use]
    pub fn allowed_cose_algorithms(&self) -> &[CoseSignatureAlgorithm] {
        &self.allowed_cose_algs
    }

    /// Return the maximum accepted encoded COSE_Sign1 size.
    #[must_use]
    pub fn max_cose_sign1_bytes(&self) -> usize {
        self.max_cose_sign1_bytes
    }

    /// Return the maximum accepted detached payload size.
    #[must_use]
    pub fn max_detached_payload_bytes(&self) -> usize {
        self.max_detached_payload_bytes
    }

    /// Configure whether protected-header `kid` is required.
    pub fn with_require_kid(mut self, require_kid: bool) -> Self {
        self.require_kid = require_kid;
        self
    }

    /// Replace the algorithm allow-list.
    ///
    /// Pass an empty iterator to accept any algorithm supported by this crate.
    pub fn with_allowed_algorithms(
        mut self,
        allowed_algorithms: impl IntoIterator<Item = Algorithm>,
    ) -> Self {
        self.allowed_algs = allowed_algorithms.into_iter().collect();
        self
    }

    /// Add one algorithm to the allow-list.
    pub fn allow_algorithm(mut self, algorithm: Algorithm) -> Self {
        self.allowed_algs.push(algorithm);
        self
    }

    /// Replace the exact COSE registration allow-list.
    pub fn with_allowed_cose_algorithms(
        mut self,
        allowed_algorithms: impl IntoIterator<Item = CoseSignatureAlgorithm>,
    ) -> Self {
        self.allowed_cose_algs = allowed_algorithms.into_iter().collect();
        self
    }

    /// Add one exact COSE signature registration to the allow-list.
    pub fn allow_cose_algorithm(mut self, algorithm: CoseSignatureAlgorithm) -> Self {
        self.allowed_cose_algs.push(algorithm);
        self
    }

    /// Configure the maximum accepted encoded COSE_Sign1 size.
    pub fn with_max_cose_sign1_bytes(mut self, max_cose_sign1_bytes: usize) -> Self {
        self.max_cose_sign1_bytes = max_cose_sign1_bytes;
        self
    }

    /// Configure the maximum accepted detached payload size.
    pub fn with_max_detached_payload_bytes(mut self, max_detached_payload_bytes: usize) -> Self {
        self.max_detached_payload_bytes = max_detached_payload_bytes;
        self
    }
}

/// Validate COSE_Sign1 header policy without performing cryptographic verification.
///
/// # Errors
///
/// Returns [`CoseError`] when required protected headers are missing, an
/// integrity-sensitive header is unprotected, or the algorithm is disallowed.
#[cfg(feature = "cose-crypto")]
pub(crate) fn validate_cose_sign1_policy(
    cose: &CoseSign1,
    policy: &CosePolicy,
) -> Result<(), CoseError> {
    // --- kid requirement ---
    if policy.require_kid() && cose.protected.header.key_id.is_empty() {
        return Err(CoseError::MissingKid);
    }

    // --- algorithm allow-list ---
    if !policy.allowed_algorithms().is_empty() {
        let cose_alg = cose
            .protected
            .header
            .alg
            .as_ref()
            .ok_or(CoseError::UnsupportedAlgorithm)?;

        let alg = algorithm_from_cose_alg(cose_alg)?;

        if !policy.allowed_algorithms().contains(&alg) {
            return Err(CoseError::UnsupportedAlgorithm);
        }
    }

    if !policy.allowed_cose_algorithms().is_empty() {
        let cose_alg = cose
            .protected
            .header
            .alg
            .as_ref()
            .ok_or(CoseError::UnsupportedAlgorithm)?;
        let algorithm = CoseSignatureAlgorithm::from_registered(cose_alg)?;
        if !policy.allowed_cose_algorithms().contains(&algorithm) {
            return Err(CoseError::UnsupportedAlgorithm);
        }
    }

    Ok(())
}
