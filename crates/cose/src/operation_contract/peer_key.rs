// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Distinct inspection and mathematical validation under generated key purposes.

use super::map_profile_failure::container as boundary_error_from_failure;
use super::profile_input::{copy, optional, suite, suite_message};
use super::providers::OperationProviders;
use crate::containers::{
    inspect_peer_key_operation, ContainerError, ContainerErrorReason as Reason,
    CryptoPeerKeyValidator, InspectedPeerKey, PeerKeyUsage,
};
use crate::wire::{
    cose_operation_result::Result as Branch, CoseOperationResult, CosePeerKeyPurpose,
    CosePeerKeyRequest, CosePeerKeyResult, CoseWireResult,
};
use buffa::{EnumValue, MessageField};

pub(crate) fn inspect(request: CosePeerKeyRequest) -> CoseWireResult<CoseOperationResult> {
    let validator_handle = crate::operation_contract::providers::capability_handle(
        request.capability.as_option(),
        crate::api::contract::CoseProviderKind::PeerKeyValidator,
    )?;
    if validator_handle != 0 {
        return Err(boundary_error_from_failure(Reason::Profile.into()));
    }
    let usage = PeerKeyUsage::try_from(&request).map_err(boundary_error_from_failure)?;
    let output = inspect_peer_key_operation(
        &request.cose_key,
        usage,
        optional(request.optional_parameters).map_err(boundary_error_from_failure)?,
    )
    .map_err(boundary_error_from_failure)?;
    let message = message(&output, false).map_err(boundary_error_from_failure)?;
    Ok(super::profile_result::operation(Branch::PeerKeyInspect(
        Box::new(message),
    )))
}

pub(crate) fn validate(
    request: CosePeerKeyRequest,
    providers: &dyn OperationProviders,
) -> CoseWireResult<CoseOperationResult> {
    let validator_handle = crate::operation_contract::providers::capability_handle(
        request.capability.as_option(),
        crate::api::contract::CoseProviderKind::PeerKeyValidator,
    )?;
    let usage = PeerKeyUsage::try_from(&request).map_err(boundary_error_from_failure)?;
    let output = inspect_peer_key_operation(
        &request.cose_key,
        usage,
        optional(request.optional_parameters).map_err(boundary_error_from_failure)?,
    )
    .map_err(boundary_error_from_failure)?;
    let validator = if validator_handle == 0 {
        &CryptoPeerKeyValidator
    } else {
        providers
            .peer_key_validator(validator_handle)
            .map_err(boundary_error_from_failure)?
    };
    let validated = output
        .validate(validator)
        .map_err(boundary_error_from_failure)?;
    let message = message(validated.public_view(), true).map_err(boundary_error_from_failure)?;
    Ok(super::profile_result::operation(Branch::PeerKeyValidate(
        Box::new(message),
    )))
}

impl TryFrom<&CosePeerKeyRequest> for PeerKeyUsage {
    type Error = ContainerError;
    fn try_from(request: &CosePeerKeyRequest) -> Result<Self, Self::Error> {
        match request.purpose.as_known() {
            Some(CosePeerKeyPurpose::Signature) => Ok(PeerKeyUsage::Signature(suite(
                request.signature_suite.as_option().ok_or(Reason::Key)?,
            )?)),
            Some(CosePeerKeyPurpose::Agreement)
                if request.signature_suite.as_option().is_none() =>
            {
                Ok(PeerKeyUsage::Agreement)
            }
            Some(CosePeerKeyPurpose::HpkeRecipient)
                if request.signature_suite.as_option().is_none() =>
            {
                Ok(PeerKeyUsage::HpkeRecipient)
            }
            _ => Err(Reason::Key.into()),
        }
    }
}

fn message(
    output: &InspectedPeerKey,
    validated: bool,
) -> Result<CosePeerKeyResult, ContainerError> {
    let mut encoded = copy(output.original_cose_key())?;
    let mut public = copy(output.public_material())?;
    let (purpose, signature_suite) = match output.usage() {
        PeerKeyUsage::Signature(suite) => (
            CosePeerKeyPurpose::Signature,
            MessageField::some(suite_message(suite)?),
        ),
        PeerKeyUsage::Agreement => (CosePeerKeyPurpose::Agreement, MessageField::none()),
        PeerKeyUsage::HpkeRecipient => (CosePeerKeyPurpose::HpkeRecipient, MessageField::none()),
    };
    Ok(CosePeerKeyResult {
        cose_key: core::mem::take(&mut *encoded).into(),
        public_key: core::mem::take(&mut *public).into(),
        curve: EnumValue::from(
            i32::try_from(output.curve().identifier()).map_err(|_| Reason::Algorithm)?,
        ),
        purpose: purpose.into(),
        signature_suite,
        point_encoding: super::profile_result::encoding(output.point_encoding()).into(),
        validated,
    })
}
