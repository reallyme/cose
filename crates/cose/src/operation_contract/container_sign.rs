// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Non-exporting signing of finalized schema-defined container inputs.

use super::map_profile_failure::container as boundary_error_from_failure;
use super::profile_input::{copy, limits, policy, suites};
use super::providers::OperationProviders;
use crate::containers::{
    sign_container_operation, ContainerErrorReason as Reason, ContainerSignRequest as Input,
    SigningContent,
};
use crate::wire::{
    cose_operation_result::Result as Branch, CoseContainerSignRequest, CoseContentMode,
    CoseOpaqueBytes, CoseOperationResult, CoseWireResult,
};

pub(crate) fn sign(
    request: CoseContainerSignRequest,
    providers: &dyn OperationProviders,
) -> CoseWireResult<CoseOperationResult> {
    let signer_handle = crate::operation_contract::providers::capability_handle(
        request.capability.as_option(),
        crate::api::contract::CoseProviderKind::Signer,
    )?;
    let selected = policy(request.policy.as_option()).map_err(boundary_error_from_failure)?;
    let allowed = suites(&request.allowed_suites).map_err(boundary_error_from_failure)?;
    let bounds = limits(request.limits.as_option()).map_err(boundary_error_from_failure)?;
    let content = match request.content_mode.as_known() {
        Some(CoseContentMode::Attached) => SigningContent::Attached(&request.payload),
        Some(CoseContentMode::Detached) => SigningContent::Detached(&request.payload),
        _ => return Err(boundary_error_from_failure(Reason::Profile.into())),
    };
    if signer_handle == 0 {
        return Err(boundary_error_from_failure(Reason::Provider.into()));
    }
    let signer = providers
        .container_signer(signer_handle)
        .map_err(boundary_error_from_failure)?;
    let output = sign_container_operation(
        Input {
            protected_headers: &request.protected_headers,
            unprotected_headers: &request.unprotected_headers,
            content,
            external_aad: &request.external_aad,
            policy: selected,
            allowed_suites: &allowed,
            limits: bounds,
        },
        signer,
    )
    .map_err(boundary_error_from_failure)?;
    let mut encoded = copy(output.encoded()).map_err(boundary_error_from_failure)?;
    Ok(super::profile_result::operation(Branch::ContainerSign(
        Box::new(CoseOpaqueBytes {
            encoded: core::mem::take(&mut *encoded).into(),
        }),
    )))
}
