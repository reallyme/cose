// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Checked conversion from schema selectors to borrowed semantic inputs.

use crate::containers::{
    ContainerError, ContainerErrorReason as Reason, ContainerLimits, ContainerPolicy,
    OptionalKeyPolicy, PeerCurve, PeerPointEncoding, SignatureSuite,
};
use crate::iso18013::{Iso18013SignatureAlgorithm, Iso18013SignatureCurve, Iso18013SignatureSuite};
use crate::wire::{
    CoseAgreementOptionalParameters, CoseByteLimits, CoseContainerPolicy, CoseNamedCurve,
    CosePointEncoding, CoseSignatureSuite,
};
use buffa::EnumValue;
use zeroize::Zeroizing;

pub(crate) use crate::generated_contract::values::MAX_ALLOWLIST_ENTRIES as MAX_SUITES;
pub(crate) const VERIFICATION_CONTEXT_BYTES: usize = 32;
pub(crate) const SHA256_DIGEST_BYTES: usize = 32;

pub(crate) fn copy(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, ContainerError> {
    let mut owner = Zeroizing::new(Vec::new());
    owner
        .try_reserve_exact(bytes.len())
        .map_err(|_| Reason::Limit)?;
    owner.extend_from_slice(bytes);
    Ok(owner)
}

pub(crate) fn bounded_length(n: u64, hard_maximum: usize) -> Result<usize, ContainerError> {
    // Clamp before conversion: the same ceiling must mean the same thing on
    // 64-bit native and 32-bit WASM/Android, including an explicit zero ceiling.
    let maximum = u64::try_from(hard_maximum).map_err(|_| Reason::Limit)?;
    usize::try_from(n.min(maximum)).map_err(|_| Reason::Limit.into())
}

pub(crate) fn limits(value: Option<&CoseByteLimits>) -> Result<ContainerLimits, ContainerError> {
    value.map_or_else(|| Ok(ContainerLimits::default()), ContainerLimits::try_from)
}

pub(crate) fn curve(
    value: EnumValue<CoseNamedCurve>,
) -> Result<Iso18013SignatureCurve, ContainerError> {
    value
        .as_known()
        .filter(|v| *v != CoseNamedCurve::Unspecified)
        .ok_or(Reason::Algorithm)?;
    Iso18013SignatureCurve::try_from(value)
}

pub(crate) fn peer_curve(value: EnumValue<CoseNamedCurve>) -> Result<PeerCurve, ContainerError> {
    value.as_known().ok_or(Reason::Algorithm)?;
    PeerCurve::try_from(value)
}

pub(crate) fn iso_suite(
    value: &CoseSignatureSuite,
) -> Result<Iso18013SignatureSuite, ContainerError> {
    value.registration.as_known().ok_or(Reason::Algorithm)?;
    Iso18013SignatureSuite::new(
        Iso18013SignatureAlgorithm::try_from(value.registration)?,
        curve(value.curve)?,
    )
}

pub(crate) fn suite(value: &CoseSignatureSuite) -> Result<SignatureSuite, ContainerError> {
    let algorithm = crate::CoseSignatureAlgorithm::try_from(value.registration)?;
    SignatureSuite::for_container(algorithm, curve(value.curve)?)
}

pub(crate) fn suites(values: &[CoseSignatureSuite]) -> Result<Vec<SignatureSuite>, ContainerError> {
    if values.len() > MAX_SUITES {
        return Err(Reason::Limit.into());
    }
    let mut result = Vec::new();
    result
        .try_reserve_exact(values.len())
        .map_err(|_| Reason::Limit)?;
    for value in values {
        result.push(suite(value)?);
    }
    Ok(result)
}

pub(crate) fn optional(
    value: EnumValue<CoseAgreementOptionalParameters>,
) -> Result<OptionalKeyPolicy, ContainerError> {
    OptionalKeyPolicy::try_from(value)
}

pub(crate) fn point_encoding(
    value: EnumValue<CosePointEncoding>,
) -> Result<PeerPointEncoding, ContainerError> {
    PeerPointEncoding::try_from(value)
}

pub(crate) fn policy(
    value: Option<&CoseContainerPolicy>,
) -> Result<ContainerPolicy, ContainerError> {
    let value = value.ok_or(Reason::Profile)?;
    ContainerPolicy::try_from(value)
}

pub(crate) fn suite_message(value: SignatureSuite) -> Result<CoseSignatureSuite, ContainerError> {
    Ok(CoseSignatureSuite::from(value))
}
