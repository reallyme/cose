// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0
use super::typ::CoseTypeExt;
#[cfg(all(kani, feature = "cose-crypto"))]
#[path = "verify_sign1_policy_proof_tests.rs"]
mod verification;

#[cfg(feature = "cose-crypto")]
use coset::CoseSign1;
use reallyme_crypto::core::Algorithm;

use crate::algorithm::CoseSignatureAlgorithm;
use crate::limits::{
    native_limit, portable_limit, MAX_COSE_SIGN1_BYTES, MAX_DETACHED_PAYLOAD_BYTES,
};
#[cfg(feature = "cose-crypto")]
use crate::sign1::CoseType;
#[cfg(feature = "cose-crypto")]
use crate::CoseError;

use buffa::{EnumValue, MessageField};
#[cfg(feature = "cose-crypto")]
use reallyme_cose_proto::generated::proto::reallyme::cose::v1::CoseType as ContractType;
use reallyme_cose_proto::generated::proto::reallyme::cose::v1::{
    CoseByteLimits as ContractLimits, CoseSignatureAlgorithm as ContractAlgorithm,
    CoseVerificationPolicy as ContractPolicy,
};
/// Native convenience builder over the single generated verification policy.
#[must_use]
#[derive(Debug, Clone)]
pub struct CosePolicy {
    contract: ContractPolicy,
}

impl Default for CosePolicy {
    fn default() -> Self {
        let mut contract = ContractPolicy::default();
        contract.allow_any_algorithm = true;
        Self { contract }
    }
}
impl CosePolicy {
    /// Create the historical unrestricted modern policy explicitly.
    pub fn new() -> Self {
        Self::default()
    }
    /// Exact generated policy; no independent crypto-selector list exists.
    pub fn contract(&self) -> &ContractPolicy {
        &self.contract
    }
    /// Validate an owned generated policy before entering native semantics.
    ///
    /// # Errors
    /// Rejects unknown selectors, contradictory allowlist modes and invalid typ.
    pub fn from_contract(contract: ContractPolicy) -> Result<Self, crate::CoseError> {
        if contract.allowed_algorithms.len() > 32
            || (contract.allow_any_algorithm && !contract.allowed_algorithms.is_empty())
        {
            return Err(crate::error::CoseErrorReason::CommonInvalidParameter.into());
        }
        for value in &contract.allowed_algorithms {
            CoseSignatureAlgorithm::try_from(*value)?;
        }
        if let Some(value) = contract.expected_type.as_option() {
            value
                .value
                .as_ref()
                .ok_or(crate::CoseError::InvalidFormat)?
                .validate()?;
        }
        Ok(Self { contract })
    }
    /// Whether a nonempty protected kid is required.
    pub fn require_kid(&self) -> bool {
        self.contract.require_kid
    }
    /// Iterates checked, exact registrations from the generated policy.
    pub fn allowed_cose_algorithms(&self) -> impl Iterator<Item = CoseSignatureAlgorithm> + '_ {
        exact_signature_registrations(&self.contract.allowed_algorithms)
    }
    /// Effective encoded Sign1 ceiling, bounded by the implementation maximum.
    pub fn max_cose_sign1_bytes(&self) -> usize {
        self.contract
            .limits
            .as_option()
            .map_or(MAX_COSE_SIGN1_BYTES, |limits| {
                native_limit(limits.encoded_bytes, MAX_COSE_SIGN1_BYTES)
            })
    }
    /// Effective payload ceiling, including detached content.
    pub fn max_detached_payload_bytes(&self) -> usize {
        self.contract
            .limits
            .as_option()
            .map_or(MAX_DETACHED_PAYLOAD_BYTES, |limits| {
                native_limit(limits.payload_bytes, MAX_DETACHED_PAYLOAD_BYTES)
            })
    }
    #[cfg(feature = "cose-crypto")]
    pub(crate) fn max_external_aad_bytes(&self) -> usize {
        self.contract
            .limits
            .as_option()
            .map_or(MAX_COSE_SIGN1_BYTES, |limits| {
                native_limit(limits.external_aad_bytes, MAX_COSE_SIGN1_BYTES)
            })
    }
    /// Whether the registered Sign1 root tag is required.
    pub fn require_tagged_sign1(&self) -> bool {
        self.contract.require_tagged_sign1
    }
    /// Whether the explicitly selected profile accepts an unprotected chain.
    pub fn allow_unprotected_x5chain(&self) -> bool {
        self.contract.allow_unprotected_x5chain
    }
    #[cfg(feature = "cose-crypto")]
    /// Borrow the generated authenticated typ alternative.
    pub fn expected_type(&self) -> Option<&CoseType> {
        self.contract
            .expected_type
            .as_option()
            .and_then(|value| value.value.as_ref())
    }
    /// Set protected-kid enforcement.
    pub fn with_require_kid(mut self, value: bool) -> Self {
        self.contract.require_kid = value;
        self
    }
    /// Legacy primitive convenience selection expands immediately into exact IDs.
    pub fn with_allowed_algorithms(self, values: impl IntoIterator<Item = Algorithm>) -> Self {
        self.with_allowed_cose_algorithms(values.into_iter().flat_map(|primitive| {
            CoseSignatureAlgorithm::ALL
                .iter()
                .copied()
                .filter(move |candidate| candidate.crypto_algorithm() == Ok(primitive))
        }))
    }
    /// Add a legacy primitive family by immediately expanding its exact registrations.
    pub fn allow_algorithm(mut self, primitive: Algorithm) -> Self {
        for algorithm in CoseSignatureAlgorithm::ALL {
            if algorithm.crypto_algorithm() == Ok(primitive) {
                self = self.allow_cose_algorithm(*algorithm);
            }
        }
        self.contract.allow_any_algorithm = false;
        self
    }
    /// Replace the one exact-registration allowlist; empty rejects all.
    pub fn with_allowed_cose_algorithms(
        mut self,
        values: impl IntoIterator<Item = CoseSignatureAlgorithm>,
    ) -> Self {
        self.contract.allowed_algorithms = values
            .into_iter()
            .map(|value| ContractAlgorithm::from(value).into())
            .collect();
        self.contract.allow_any_algorithm = false;
        self
    }
    /// Add one exact registration to the same generated allowlist.
    pub fn allow_cose_algorithm(mut self, value: CoseSignatureAlgorithm) -> Self {
        self.contract
            .allowed_algorithms
            .push(ContractAlgorithm::from(value).into());
        self.contract.allow_any_algorithm = false;
        self
    }
    /// Explicitly clear restrictions within the modern operation profile.
    pub fn allow_any_algorithm(mut self) -> Self {
        self.contract.allowed_algorithms.clear();
        self.contract.allow_any_algorithm = true;
        self
    }
    fn limits(&mut self) -> &mut ContractLimits {
        if self.contract.limits.as_option().is_none() {
            self.contract.limits = MessageField::some(ContractLimits {
                encoded_bytes: portable_limit(MAX_COSE_SIGN1_BYTES, MAX_COSE_SIGN1_BYTES),
                payload_bytes: portable_limit(
                    MAX_DETACHED_PAYLOAD_BYTES,
                    MAX_DETACHED_PAYLOAD_BYTES,
                ),
                external_aad_bytes: portable_limit(MAX_COSE_SIGN1_BYTES, MAX_COSE_SIGN1_BYTES),
            });
        }
        self.contract.limits.get_or_insert_default()
    }
    /// Tighten the encoded Sign1 ceiling.
    pub fn with_max_cose_sign1_bytes(mut self, value: usize) -> Self {
        self.limits().encoded_bytes = portable_limit(value, MAX_COSE_SIGN1_BYTES);
        self
    }
    /// Tighten the detached payload ceiling.
    pub fn with_max_detached_payload_bytes(mut self, value: usize) -> Self {
        self.limits().payload_bytes = portable_limit(value, MAX_DETACHED_PAYLOAD_BYTES);
        self
    }
    /// Set root-tag enforcement.
    pub fn with_require_tagged_sign1(mut self, value: bool) -> Self {
        self.contract.require_tagged_sign1 = value;
        self
    }
    /// Select explicit unprotected-chain interoperability.
    pub fn with_allow_unprotected_x5chain(mut self, value: bool) -> Self {
        self.contract.allow_unprotected_x5chain = value;
        self
    }
    #[cfg(feature = "cose-crypto")]
    /// Require the supplied generated typ alternative.
    pub fn with_expected_type(mut self, value: CoseType) -> Self {
        self.contract.expected_type = MessageField::some(ContractType { value: Some(value) });
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
    if !policy.contract.allow_any_algorithm {
        let cose_alg = cose
            .protected
            .header
            .alg
            .as_ref()
            .ok_or(CoseError::UnsupportedAlgorithm)?;
        let algorithm = CoseSignatureAlgorithm::from_registered(cose_alg)?;
        require_exact_signature_registration(&policy.contract.allowed_algorithms, algorithm)?;
    }

    Ok(())
}

#[cfg(feature = "cose-crypto")]
fn require_exact_signature_registration(
    allowlist: &[EnumValue<ContractAlgorithm>],
    algorithm: CoseSignatureAlgorithm,
) -> Result<(), CoseError> {
    if exact_signature_registrations(allowlist).any(|allowed| allowed == algorithm) {
        Ok(())
    } else {
        Err(CoseError::UnsupportedAlgorithm)
    }
}

fn exact_signature_registrations(
    allowlist: &[EnumValue<ContractAlgorithm>],
) -> impl Iterator<Item = CoseSignatureAlgorithm> + '_ {
    allowlist
        .iter()
        .filter_map(|value| CoseSignatureAlgorithm::try_from(*value).ok())
}
