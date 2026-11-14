// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Schema-defined public agreement construction and validated import.

use super::map_profile_failure::container as boundary_error_from_failure;
use super::profile_input::{copy, optional, point_encoding};
use super::providers::OperationProviders;
use crate::containers::agreement_key::parse_agreement_key;
use crate::containers::construct_agreement_key::construct_agreement_key;
use crate::containers::{
    AgreementEc2EncodingPolicy, AgreementKey, AgreementKeyPolicy, ContainerError,
    ContainerErrorReason as Reason, CryptoAgreementKeyProvider, PeerCurve,
};
use crate::wire::{
    cose_operation_result::Result as Branch, CoseAgreementKeyCreateRequest,
    CoseAgreementKeyParseRequest, CoseAgreementKeyPolicy, CoseAgreementKeyResult,
    CoseOperationResult, CoseWireResult,
};
use buffa::EnumValue;

struct Policy {
    curves: Vec<PeerCurve>,
    encoding: AgreementEc2EncodingPolicy,
    optional: crate::containers::OptionalKeyPolicy,
}
impl Policy {
    fn parse(value: Option<&CoseAgreementKeyPolicy>) -> Result<Self, ContainerError> {
        let value = value.ok_or(Reason::Profile)?;
        AgreementKeyPolicy::check_allowlist_size(value.allowed_curves.len())?;
        let mut curves = Vec::new();
        curves
            .try_reserve_exact(value.allowed_curves.len())
            .map_err(|_| Reason::Limit)?;
        for id in &value.allowed_curves {
            id.as_known().ok_or(Reason::Algorithm)?;
            let curve = PeerCurve::from_identifier(i64::from(id.to_i32()))?;
            curves.push(curve);
        }
        let encoding = AgreementEc2EncodingPolicy::try_from(value.ec2_encoding)?;
        let policy = Self {
            curves,
            encoding,
            optional: optional(value.optional_parameters)?,
        };
        policy.view().validate()?;
        Ok(policy)
    }
    fn view(&self) -> AgreementKeyPolicy<'_> {
        AgreementKeyPolicy {
            allowed_curves: &self.curves,
            optional_parameters: self.optional,
            ec2_encoding: self.encoding,
        }
    }
}

pub(crate) fn create(
    request: CoseAgreementKeyCreateRequest,
    providers: &dyn OperationProviders,
) -> CoseWireResult<CoseOperationResult> {
    let provider_handle = crate::operation_contract::providers::capability_handle(
        request.capability.as_option(),
        crate::api::contract::CoseProviderKind::AgreementKeyNormalizer,
    )?;
    let policy = Policy::parse(request.policy.as_option()).map_err(boundary_error_from_failure)?;
    request
        .curve
        .as_known()
        .ok_or(Reason::Algorithm)
        .map_err(|e| boundary_error_from_failure(e.into()))?;
    let curve = PeerCurve::from_identifier(i64::from(request.curve.to_i32()))
        .map_err(boundary_error_from_failure)?;
    let encoding = point_encoding(request.point_encoding).map_err(boundary_error_from_failure)?;
    let provider = if provider_handle == 0 {
        &CryptoAgreementKeyProvider
    } else {
        providers
            .agreement_key_provider(provider_handle)
            .map_err(boundary_error_from_failure)?
    };
    let key = construct_agreement_key(
        curve,
        &request.public_key,
        encoding,
        policy.view(),
        provider,
    )
    .map_err(boundary_error_from_failure)?;
    Ok(super::profile_result::operation(
        Branch::AgreementKeyCreate(Box::new(message(key).map_err(boundary_error_from_failure)?)),
    ))
}

pub(crate) fn parse(
    request: CoseAgreementKeyParseRequest,
    providers: &dyn OperationProviders,
) -> CoseWireResult<CoseOperationResult> {
    let provider_handle = crate::operation_contract::providers::capability_handle(
        request.capability.as_option(),
        crate::api::contract::CoseProviderKind::AgreementKeyNormalizer,
    )?;
    let policy = Policy::parse(request.policy.as_option()).map_err(boundary_error_from_failure)?;
    let provider = if provider_handle == 0 {
        &CryptoAgreementKeyProvider
    } else {
        providers
            .agreement_key_provider(provider_handle)
            .map_err(boundary_error_from_failure)?
    };
    let key = parse_agreement_key(&request.cose_key, policy.view(), provider)
        .map_err(boundary_error_from_failure)?;
    Ok(super::profile_result::operation(Branch::AgreementKeyParse(
        Box::new(message(key).map_err(boundary_error_from_failure)?),
    )))
}

fn message(key: AgreementKey) -> Result<CoseAgreementKeyResult, ContainerError> {
    let mut encoded = copy(key.original_cose_key())?;
    let mut public = copy(key.public_material())?;
    Ok(CoseAgreementKeyResult {
        cose_key: core::mem::take(&mut *encoded).into(),
        public_key: core::mem::take(&mut *public).into(),
        curve: EnumValue::from(
            i32::try_from(key.curve().identifier()).map_err(|_| Reason::Algorithm)?,
        ),
        point_encoding: super::profile_result::encoding(key.point_encoding()).into(),
    })
}
