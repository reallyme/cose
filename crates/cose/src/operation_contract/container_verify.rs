// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Exact-byte container verification using generated policies and capabilities.

use super::map_profile_failure::container as boundary_error_from_failure;
use super::profile_input::{copy, limits, policy, suite, suite_message, suites};
use super::providers::OperationProviders;
use crate::containers::{
    verify_container_operation, ContainerContent, ContainerError, ContainerErrorReason as Reason,
    ContainerVerifyRequest as Input, CryptoVerificationKey, EndEntityIntegrity, VerificationSource,
    VerifiedContainer,
};
use crate::wire::{
    cose_operation_result::Result as Branch, CoseContainerVerifyRequest, CoseContainerVerifyResult,
    CoseContentMode, CoseEndEntityIntegrity, CoseKeySource, CoseOperationResult, CoseWireResult,
    CoseWorkingKey, CoseX5ChainHeaderPlacement,
};
use buffa::MessageField;
use zeroize::Zeroizing;

pub(crate) fn verify(
    mut request: CoseContainerVerifyRequest,
    providers: &dyn OperationProviders,
) -> CoseWireResult<CoseOperationResult> {
    let capability_handle = crate::operation_contract::providers::capability_handle(
        request.capability.as_option(),
        if request.key_source == crate::wire::CoseKeySource::Certificates {
            crate::api::contract::CoseProviderKind::CertificateValidator
        } else {
            crate::api::contract::CoseProviderKind::VerificationKey
        },
    )?;
    let selected = policy(request.policy.as_option()).map_err(boundary_error_from_failure)?;
    let allowed = suites(&request.allowed_suites).map_err(boundary_error_from_failure)?;
    let bounds = limits(request.limits.as_option()).map_err(boundary_error_from_failure)?;
    let content = match request.content_mode.as_known() {
        Some(CoseContentMode::Attached) if request.detached_payload.is_empty() => {
            ContainerContent::Attached
        }
        Some(CoseContentMode::Detached) => ContainerContent::Detached(&request.detached_payload),
        _ => return Err(boundary_error_from_failure(Reason::Profile.into())),
    };
    let owned;
    let source = match request.key_source.as_known() {
        Some(CoseKeySource::Direct) if capability_handle == 0 => {
            let key = request
                .key
                .as_option_mut()
                .ok_or(Reason::Key)
                .map_err(|e| boundary_error_from_failure(e.into()))?;
            let selected = suite(
                key.suite
                    .as_option()
                    .ok_or(Reason::Key)
                    .map_err(|e| boundary_error_from_failure(e.into()))?,
            )
            .map_err(boundary_error_from_failure)?;
            if key.context_id.len() != super::profile_input::VERIFICATION_CONTEXT_BYTES {
                return Err(boundary_error_from_failure(Reason::Key.into()));
            }
            let mut context = Zeroizing::new([0; super::profile_input::VERIFICATION_CONTEXT_BYTES]);
            context.copy_from_slice(&key.context_id);
            owned = CryptoVerificationKey::new(
                selected,
                core::mem::take(&mut key.public_key).into_zeroizing(),
                *context,
            )
            .map_err(boundary_error_from_failure)?;
            VerificationSource::Key(&owned)
        }
        Some(CoseKeySource::Provider)
            if capability_handle != 0 && request.key.as_option().is_none() =>
        {
            VerificationSource::Key(
                providers
                    .verification_key(capability_handle)
                    .map_err(boundary_error_from_failure)?,
            )
        }
        Some(CoseKeySource::Certificates)
            if capability_handle != 0 && request.key.as_option().is_none() =>
        {
            VerificationSource::Certificates(
                providers
                    .certificate_validator(capability_handle)
                    .map_err(boundary_error_from_failure)?,
            )
        }
        _ => return Err(boundary_error_from_failure(Reason::Key.into())),
    };
    let output = verify_container_operation(
        Input {
            encoded: &request.encoded,
            content,
            external_aad: &request.external_aad,
            policy: selected,
            allowed_suites: &allowed,
            limits: bounds,
        },
        source,
    )
    .map_err(boundary_error_from_failure)?;
    let message = message(
        output,
        request
            .policy
            .take()
            .ok_or(Reason::Profile)
            .map_err(|e| boundary_error_from_failure(e.into()))?,
    )
    .map_err(boundary_error_from_failure)?;
    Ok(super::profile_result::operation(Branch::ContainerVerify(
        Box::new(message),
    )))
}

fn message(
    output: VerifiedContainer,
    policy: crate::wire::CoseContainerPolicy,
) -> Result<CoseContainerVerifyResult, ContainerError> {
    let mut encoded = copy(output.encoded())?;
    let mut protected = copy(output.protected_headers())?;
    let mut unprotected = copy(output.unprotected_headers())?;
    let mut payload = copy(output.payload())?;
    let mut public = copy(output.verification_public_key())?;
    let mut context = copy(output.verification_context())?;
    let mut certificate = copy(
        output
            .selected_certificate_sha256()
            .map_or(&[][..], |v| &v[..]),
    )?;
    let provenance = output.provenance();
    let placement = match provenance.chain_placement {
        Some(crate::X5ChainHeaderPlacement::Protected) => CoseX5ChainHeaderPlacement::Protected,
        Some(crate::X5ChainHeaderPlacement::Unprotected) => CoseX5ChainHeaderPlacement::Unprotected,
        None => CoseX5ChainHeaderPlacement::Unspecified,
    };
    let integrity = match provenance.end_entity_integrity {
        EndEntityIntegrity::ExternalKey => CoseEndEntityIntegrity::ExternalKey,
        EndEntityIntegrity::ProtectedChain => CoseEndEntityIntegrity::ProtectedChain,
        EndEntityIntegrity::ProtectedThumbprint => CoseEndEntityIntegrity::ProtectedThumbprint,
        EndEntityIntegrity::IsoUnprotectedChain => CoseEndEntityIntegrity::IsoUnprotectedChain,
    };
    Ok(CoseContainerVerifyResult {
        encoded: core::mem::take(&mut *encoded).into(),
        protected_headers: core::mem::take(&mut *protected).into(),
        unprotected_headers: core::mem::take(&mut *unprotected).into(),
        payload: core::mem::take(&mut *payload).into(),
        policy: MessageField::some(policy),
        key: MessageField::some(CoseWorkingKey {
            suite: MessageField::some(suite_message(output.suite())?),
            public_key: core::mem::take(&mut *public).into(),
            context_id: core::mem::take(&mut *context).into(),
        }),
        chain_placement: placement.into(),
        protected_thumbprint: provenance.protected_thumbprint,
        end_entity_integrity: integrity.into(),
        certificate_sha256: output
            .selected_certificate_sha256()
            .map(|_| core::mem::take(&mut *certificate).into()),
    })
}
