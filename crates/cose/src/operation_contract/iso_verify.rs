// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Original ISO registrations through generated request/result definitions.

use super::map_failure::boundary_error_from_failure;
use super::map_profile_failure::container;
use super::profile_input::{copy, iso_suite, limits, MAX_SUITES};
use super::providers::OperationProviders;
use crate::containers::ContainerErrorReason as Reason;
use crate::failure::CoseFailure;
use crate::iso18013::{
    verify_iso18013_operation, Iso18013CryptoVerifier, Iso18013Sign1Content, Iso18013Sign1Limits,
    Iso18013Sign1Request, Iso18013Verifier,
};
use crate::wire::{
    cose_operation_result::Result as Branch, CoseIsoSign1Content, CoseIsoSign1VerifyRequest,
    CoseIsoSign1VerifyResult, CoseKeySource, CoseOperationResult, CoseSignatureSuite,
    CoseWireResult,
};
use buffa::MessageField;

pub(crate) fn verify(
    mut request: CoseIsoSign1VerifyRequest,
    providers: &dyn OperationProviders,
) -> CoseWireResult<CoseOperationResult> {
    let verifier_handle = crate::operation_contract::providers::capability_handle(
        request.capability.as_option(),
        crate::api::contract::CoseProviderKind::VerificationKey,
    )?;
    let key_suite = iso_suite(
        request
            .key_suite
            .as_option()
            .ok_or(Reason::Key)
            .map_err(|e| container(e.into()))?,
    )
    .map_err(container)?;
    let bounds = limits(request.limits.as_option()).map_err(container)?;
    if request.allowed_suites.len() > MAX_SUITES {
        return Err(container(Reason::Limit.into()));
    }
    let mut allowed = Vec::new();
    allowed
        .try_reserve_exact(request.allowed_suites.len())
        .map_err(|_| container(Reason::Limit.into()))?;
    for value in &request.allowed_suites {
        allowed.push(iso_suite(value).map_err(container)?);
    }
    let content = match request.content.as_known() {
        Some(CoseIsoSign1Content::IssuerAttached) if request.detached_payload.is_empty() => {
            Iso18013Sign1Content::IssuerAttached
        }
        Some(CoseIsoSign1Content::DeviceDetached) => {
            Iso18013Sign1Content::DeviceDetached(&request.detached_payload)
        }
        Some(CoseIsoSign1Content::ReaderDetached) => {
            Iso18013Sign1Content::ReaderDetached(&request.detached_payload)
        }
        _ => return Err(container(Reason::Profile.into())),
    };
    let owned;
    let verifier: &dyn Iso18013Verifier = match request.key_source.as_known() {
        Some(CoseKeySource::Direct) if verifier_handle == 0 => {
            owned = if request.public_key_is_cose {
                Iso18013CryptoVerifier::from_cose_key(key_suite, &request.public_key)
            } else {
                Iso18013CryptoVerifier::new(
                    key_suite,
                    core::mem::take(&mut request.public_key).into_zeroizing(),
                )
            }
            .map_err(|e| boundary_error_from_failure(CoseFailure::from(e)))?;
            &owned
        }
        Some(CoseKeySource::Provider)
            if verifier_handle != 0
                && request.public_key.is_empty()
                && !request.public_key_is_cose =>
        {
            let verifier = providers.iso_verifier(verifier_handle).map_err(container)?;
            if verifier.suite() != key_suite {
                return Err(container(Reason::Key.into()));
            }
            verifier
        }
        _ => return Err(container(Reason::Key.into())),
    };
    let output = verify_iso18013_operation(
        Iso18013Sign1Request {
            encoded: &request.encoded,
            content,
            allowed_suites: &allowed,
            limits: Iso18013Sign1Limits {
                encoded_bytes: bounds.encoded_bytes,
                payload_bytes: bounds.payload_bytes,
                external_aad_bytes: 0,
            },
        },
        verifier,
    )
    .map_err(|e| boundary_error_from_failure(CoseFailure::from(e)))?;
    let mut protected = copy(output.protected_header_bytes()).map_err(container)?;
    let mut kid = copy(output.protected_key_id().unwrap_or_default()).map_err(container)?;
    let mut payload = copy(output.attached_payload().unwrap_or_default()).map_err(container)?;
    let suite = CoseSignatureSuite::from(output.suite());
    let message = CoseIsoSign1VerifyResult {
        suite: MessageField::some(suite),
        protected_headers: core::mem::take(&mut *protected).into(),
        protected_kid: output
            .protected_key_id()
            .map(|_| core::mem::take(&mut *kid).into()),
        attached_payload: output
            .attached_payload()
            .map(|_| core::mem::take(&mut *payload).into()),
    };
    Ok(super::profile_result::operation(Branch::IsoSign1Verify(
        Box::new(message),
    )))
}
