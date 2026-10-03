// SPDX-FileCopyrightText: 2026 ReallyMe LLC

// SPDX-License-Identifier: MIT OR Apache-2.0
#[cfg(feature = "cose-crypto")]
use crate::algorithm::algorithm_from_cose_alg;
#[cfg(feature = "cose-crypto")]
use coset::CoseSign1;
use reallyme_crypto::core::Algorithm;

use crate::algorithm::CoseSignatureAlgorithm;
use crate::limits::{MAX_COSE_SIGN1_BYTES, MAX_DETACHED_PAYLOAD_BYTES};
#[cfg(feature = "cose-crypto")]
use crate::sign1::CoseType;
#[cfg(feature = "cose-crypto")]
use crate::CoseError;

/// Verification policy for COSE_Sign1 byte-boundary APIs.
#[must_use]
#[derive(Debug, Clone)]
pub struct CosePolicy {
    /// Require a `kid` / key_id in protected header.
    require_kid: bool,

    /// Allowed algorithms. An explicitly configured empty list rejects all.
    allowed_algs: Vec<Algorithm>,
    allowed_algs_configured: bool,

    /// Exact COSE registrations accepted by verification.
    allowed_cose_algs: Vec<CoseSignatureAlgorithm>,
    allowed_cose_algs_configured: bool,

    /// Maximum accepted encoded COSE_Sign1 bytes at public verification APIs.
    max_cose_sign1_bytes: usize,

    /// Maximum accepted detached payload bytes at detached verification APIs.
    max_detached_payload_bytes: usize,

    /// Require the registered COSE_Sign1 root tag (18).
    require_tagged_sign1: bool,

    /// Exact authenticated protected type required by the caller.
    #[cfg(feature = "cose-crypto")]
    expected_type: Option<CoseType>,
}

impl Default for CosePolicy {
    fn default() -> Self {
        Self {
            require_kid: false,
            allowed_algs: Vec::new(),
            allowed_algs_configured: false,
            allowed_cose_algs: Vec::new(),
            allowed_cose_algs_configured: false,
            max_cose_sign1_bytes: MAX_COSE_SIGN1_BYTES,
            max_detached_payload_bytes: MAX_DETACHED_PAYLOAD_BYTES,
            require_tagged_sign1: false,
            #[cfg(feature = "cose-crypto")]
            expected_type: None,
        }
    }
}

impl CosePolicy {
    /// Construct the default verification policy.
    ///
    /// The default accepts every signature registration supported by the
    /// crate. Applications with a known credential suite should configure an
    /// allow-list before accepting externally supplied signatures.
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
    /// An empty list means either no restriction was configured or an
    /// explicitly empty list that rejects every algorithm.
    #[must_use]
    pub fn allowed_algorithms(&self) -> &[Algorithm] {
        &self.allowed_algs
    }

    /// Return the exact COSE registration allow-list.
    ///
    /// An explicitly configured empty list rejects every registration.
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

    /// Return whether verification requires the COSE_Sign1 root tag (18).
    #[must_use]
    pub fn require_tagged_sign1(&self) -> bool {
        self.require_tagged_sign1
    }

    /// Return the required authenticated protected type, if configured.
    #[must_use]
    #[cfg(feature = "cose-crypto")]
    pub fn expected_type(&self) -> Option<&CoseType> {
        self.expected_type.as_ref()
    }

    /// Configure whether protected-header `kid` is required.
    pub fn with_require_kid(mut self, require_kid: bool) -> Self {
        self.require_kid = require_kid;
        self
    }

    /// Replace the algorithm allow-list.
    ///
    /// An empty iterator fails closed at verification with
    /// [`CoseError::UnsupportedAlgorithm`]. Use [`Self::allow_any_algorithm`]
    /// when unrestricted verification is intentional.
    pub fn with_allowed_algorithms(
        mut self,
        allowed_algorithms: impl IntoIterator<Item = Algorithm>,
    ) -> Self {
        self.allowed_algs = allowed_algorithms.into_iter().collect();
        self.allowed_algs_configured = true;
        self
    }

    /// Add one algorithm to the allow-list.
    pub fn allow_algorithm(mut self, algorithm: Algorithm) -> Self {
        self.allowed_algs.push(algorithm);
        self.allowed_algs_configured = true;
        self
    }

    /// Replace the exact COSE registration allow-list.
    pub fn with_allowed_cose_algorithms(
        mut self,
        allowed_algorithms: impl IntoIterator<Item = CoseSignatureAlgorithm>,
    ) -> Self {
        self.allowed_cose_algs = allowed_algorithms.into_iter().collect();
        self.allowed_cose_algs_configured = true;
        self
    }

    /// Add one exact COSE signature registration to the allow-list.
    pub fn allow_cose_algorithm(mut self, algorithm: CoseSignatureAlgorithm) -> Self {
        self.allowed_cose_algs.push(algorithm);
        self.allowed_cose_algs_configured = true;
        self
    }

    /// Explicitly accept any signature registration supported by this crate.
    pub fn allow_any_algorithm(mut self) -> Self {
        self.allowed_algs.clear();
        self.allowed_cose_algs.clear();
        self.allowed_algs_configured = false;
        self.allowed_cose_algs_configured = false;
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

    /// Configure whether verification requires the COSE_Sign1 root tag (18).
    pub fn with_require_tagged_sign1(mut self, require_tagged_sign1: bool) -> Self {
        self.require_tagged_sign1 = require_tagged_sign1;
        self
    }

    /// Require an exact RFC 9596 protected `typ` value.
    #[cfg(feature = "cose-crypto")]
    pub fn with_expected_type(mut self, expected_type: CoseType) -> Self {
        self.expected_type = Some(expected_type);
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
    tagged: bool,
    policy: &CosePolicy,
) -> Result<(), CoseError> {
    if policy.require_tagged_sign1() && !tagged {
        return Err(CoseError::InvalidFormat);
    }

    if let Some(expected_type) = policy.expected_type() {
        expected_type.validate()?;
        if CoseType::from_protected_header(&cose.protected.header)?.as_ref() != Some(expected_type)
        {
            return Err(CoseError::InvalidFormat);
        }
    }

    // --- kid requirement ---
    if policy.require_kid() && cose.protected.header.key_id.is_empty() {
        return Err(CoseError::MissingKid);
    }

    // --- algorithm allow-list ---
    if policy.allowed_algs_configured {
        if policy.allowed_algs.is_empty() {
            return Err(CoseError::UnsupportedAlgorithm);
        }
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

    if policy.allowed_cose_algs_configured {
        if policy.allowed_cose_algs.is_empty() {
            return Err(CoseError::UnsupportedAlgorithm);
        }
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
