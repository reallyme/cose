// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Complete modern Sign1 contract, including borrowed callback capabilities.

use super::super::input::{
    encode_options_from_proto, policy_from_parts, signature_algorithm_from_proto,
};
use super::super::map_failure::boundary_error_from_failure;
use super::super::providers::OperationProviders;
use crate::failure::CoseFailure;
use crate::sign1::cose_type::CoseTypeExt;
use crate::sign1::sign::{create_cose_sign1, create_detached_cose_sign1};
use crate::sign1::types::{
    CoseSign1CreateInput, CoseSign1DetachedVerifyInput, CoseSign1KeyResolution,
    CoseSign1VerifyInput,
};
use crate::sign1::verify::verify_x5chain_with_certificate;
use crate::sign1::verify::{verify_cose_sign1, verify_detached_cose_sign1};
use crate::wire::{
    cose_operation_result::Result as Branch, CoseErrorReason, CoseOperationResult,
    CoseSign1CreateProfileRequest, CoseSign1CreateResult, CoseSign1VerifyProfileRequest,
    CoseSign1X5ChainResult, CoseWireError, CoseWireResult, CoseX5Chain, CoseX5ChainHeaderPlacement,
};
use buffa::MessageField;
use zeroize::Zeroizing;

pub(crate) fn create(
    request: CoseSign1CreateProfileRequest,
    providers: &dyn OperationProviders,
) -> CoseWireResult<CoseOperationResult> {
    create_result(request, providers, false)
}
pub(crate) fn create_detached(
    request: CoseSign1CreateProfileRequest,
    providers: &dyn OperationProviders,
) -> CoseWireResult<CoseOperationResult> {
    create_result(request, providers, true)
}

fn create_result(
    mut request: CoseSign1CreateProfileRequest,
    providers: &dyn OperationProviders,
    detached: bool,
) -> CoseWireResult<CoseOperationResult> {
    let signer_handle = crate::operation_contract::providers::capability_handle(
        request.capability.as_option(),
        crate::api::contract::CoseProviderKind::Signer,
    )?;
    let input = request.request.as_option_mut().ok_or_else(invalid)?;
    let algorithm = signature_algorithm_from_proto(input.algorithm)?;
    let mut options = encode_options_from_proto(input.options.as_option_mut())?;
    if let Some(typ) = request.protected_type.as_option_mut() {
        if options.protected_type().is_some() {
            return Err(invalid());
        }
        let typ = typ.value.take().ok_or_else(invalid)?;
        typ.validate()
            .map_err(|e| boundary_error_from_failure(e.into()))?;
        options = options.with_protected_type(typ);
    }
    let kid = input.kid.as_deref();
    let operation = if signer_handle == 0 {
        CoseSign1CreateInput::with_signature_algorithm(
            algorithm,
            &input.payload,
            &input.private_key,
            kid,
            &input.external_aad,
            options,
        )
        .map_err(|error| boundary_error_from_failure(error.into()))?
    } else {
        if !input.private_key.is_empty() {
            return Err(invalid());
        }
        let signer = providers
            .cose_signer(signer_handle)
            .map_err(super::super::map_profile_failure::container)?;
        if signer
            .cose_algorithm()
            .map_err(|e| boundary_error_from_failure(e.into()))?
            != algorithm
        {
            return Err(boundary_error_from_failure(
                crate::CoseError::UnsupportedAlgorithm.into(),
            ));
        }
        CoseSign1CreateInput::with_signer(signer, &input.payload, kid, &input.external_aad, options)
            .map_err(|e| boundary_error_from_failure(e.into()))?
    };
    let output = if detached {
        create_detached_cose_sign1(operation)
    } else {
        create_cose_sign1(operation)
    }
    .map_err(boundary_error_from_failure)?;
    let mut encoded = output.into_zeroizing();
    let message = Box::new(CoseSign1CreateResult {
        cose_sign1: core::mem::take(&mut *encoded).into(),
    });
    Ok(super::super::profile_result::operation(if detached {
        Branch::Sign1CreateDetachedProfile(message)
    } else {
        Branch::Sign1CreateProfile(message)
    }))
}

pub(crate) fn verify(
    mut request: CoseSign1VerifyProfileRequest,
    providers: &dyn OperationProviders,
) -> CoseWireResult<CoseOperationResult> {
    let resolver_handle = crate::operation_contract::providers::capability_handle(
        request.capability.as_option(),
        crate::api::contract::CoseProviderKind::KeyResolver,
    )?;
    let input = request.request.as_option_mut().ok_or_else(invalid)?;
    if !request.detached && !request.detached_payload.is_empty() {
        return Err(invalid());
    }
    if resolver_handle != 0 && !input.public_key.is_empty() {
        return Err(invalid());
    }
    let key_algorithm = super::verify::expected_key_algorithm(input.public_key_algorithm)?;
    let legacy_policy = policy_from_parts(
        input.max_cose_sign1_bytes,
        input.max_detached_payload_bytes,
        input.require_kid,
        &input.allowed_algorithms,
        input.require_tagged_sign1,
        input.expected_type.as_option(),
    )?
    .with_allow_unprotected_x5chain(request.allow_unprotected_x5chain);
    let policy = if let Some(canonical) = request.policy.take() {
        if input.require_kid
            || input.require_tagged_sign1
            || !input.allowed_algorithms.is_empty()
            || input.expected_type.as_option().is_some()
            || input.max_cose_sign1_bytes != 0
            || input.max_detached_payload_bytes != 0
            || request.allow_unprotected_x5chain
        {
            return Err(invalid());
        }
        crate::CosePolicy::from_contract(canonical)
            .map_err(|error| boundary_error_from_failure(error.into()))?
    } else {
        legacy_policy
    };
    let public = core::mem::take(&mut input.public_key).into_zeroizing();
    let resolver = |algorithm: crate::CoseSignatureAlgorithm, kid: &[u8]| {
        if key_algorithm.is_some_and(|configured| configured != algorithm) {
            return CoseSign1KeyResolution::AlgorithmMismatch;
        }
        if !input.expected_kid.is_empty()
            && !reallyme_crypto::operations::constant_time::equal(kid, &input.expected_kid)
        {
            return CoseSign1KeyResolution::KidMismatch;
        }
        if resolver_handle == 0 {
            CoseSign1KeyResolution::Resolved(public)
        } else {
            let registration = Some(crate::wire::CoseSignatureAlgorithm::from(algorithm));
            match registration.and_then(|registration| {
                providers.resolve_sign1_key(resolver_handle, registration, kid)
            }) {
                Some(public) => CoseSign1KeyResolution::Resolved(public),
                None => CoseSign1KeyResolution::NotResolved,
            }
        }
    };
    let message = if request.detached {
        let output = verify_detached_cose_sign1(
            CoseSign1DetachedVerifyInput::new(
                &input.cose_sign1,
                &request.detached_payload,
                &input.external_aad,
                &policy,
            ),
            resolver,
        )
        .map_err(boundary_error_from_failure)?;
        super::result::verify_message(
            Zeroizing::new(Vec::new()),
            output.cose_algorithm,
            output.kid,
            output.cose_type,
        )?
    } else {
        let output = verify_cose_sign1(
            CoseSign1VerifyInput::new(&input.cose_sign1, &input.external_aad, &policy),
            resolver,
        )
        .map_err(boundary_error_from_failure)?;
        super::result::verify_message(
            output.payload,
            output.cose_algorithm,
            output.kid,
            output.cose_type,
        )?
    };
    Ok(super::super::profile_result::operation(
        Branch::Sign1VerifyProfile(Box::new(message)),
    ))
}

pub(crate) fn x5chain(
    mut request: CoseSign1VerifyProfileRequest,
    providers: &dyn OperationProviders,
) -> CoseWireResult<CoseOperationResult> {
    let resolver_handle = crate::operation_contract::providers::capability_handle(
        request.capability.as_option(),
        crate::api::contract::CoseProviderKind::KeyResolver,
    )?;
    let input = request.request.as_option_mut().ok_or_else(invalid)?;
    if request.detached
        || !request.detached_payload.is_empty()
        || !input.external_aad.is_empty()
        || resolver_handle == 0
        || !input.public_key.is_empty()
    {
        return Err(invalid());
    }
    let key_algorithm = super::verify::expected_key_algorithm(input.public_key_algorithm)?;
    let legacy_policy = policy_from_parts(
        input.max_cose_sign1_bytes,
        input.max_detached_payload_bytes,
        input.require_kid,
        &input.allowed_algorithms,
        input.require_tagged_sign1,
        input.expected_type.as_option(),
    )?
    .with_allow_unprotected_x5chain(request.allow_unprotected_x5chain);
    let policy = if let Some(canonical) = request.policy.take() {
        if input.require_kid
            || input.require_tagged_sign1
            || !input.allowed_algorithms.is_empty()
            || input.expected_type.as_option().is_some()
            || input.max_cose_sign1_bytes != 0
            || input.max_detached_payload_bytes != 0
            || request.allow_unprotected_x5chain
        {
            return Err(invalid());
        }
        crate::CosePolicy::from_contract(canonical)
            .map_err(|error| boundary_error_from_failure(error.into()))?
    } else {
        legacy_policy
    };
    // The chain callback has no kid argument; a requested kid binding must be
    // checked explicitly rather than silently ignored by this operation.
    if !input.expected_kid.is_empty() {
        return Err(invalid());
    }
    let mut output = verify_x5chain_with_certificate(
        &input.cose_sign1,
        &policy,
        |algorithm, placement, chain| {
            if key_algorithm.is_some_and(|configured| configured != algorithm) {
                return Err(crate::CoseError::KeyNotResolved);
            }
            providers.resolve_x5chain_key(
                resolver_handle,
                crate::wire::CoseSignatureAlgorithm::from(algorithm),
                CoseX5ChainHeaderPlacement::from(placement),
                chain,
            )
        },
    )
    .map_err(|e| boundary_error_from_failure(CoseFailure::from(e)))?;
    let placement = match output.x5chain_header_placement {
        crate::X5ChainHeaderPlacement::Protected => CoseX5ChainHeaderPlacement::Protected,
        crate::X5ChainHeaderPlacement::Unprotected => CoseX5ChainHeaderPlacement::Unprotected,
    };
    let message = CoseSign1X5ChainResult {
        verified: MessageField::some(super::result::verify_message(
            output.payload,
            output.cose_algorithm,
            output.kid,
            output.cose_type,
        )?),
        x5chain: MessageField::some(CoseX5Chain {
            certificates_der: output
                .x5chain_der
                .iter_mut()
                .map(|certificate| core::mem::take(certificate).into())
                .collect(),
        }),
        placement: placement.into(),
    };
    Ok(super::super::profile_result::operation(
        Branch::Sign1VerifyX5chain(Box::new(message)),
    ))
}

fn invalid() -> CoseWireError {
    CoseWireError::primitive_internal(CoseErrorReason::CommonInvalidParameter)
}
