// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::provider_support::{sign_request, Fault, Port};
use super::support::{field, reason, request, success};
use crate::api::{self, contract as wire};
use crate::CoseError;
use wire::{cose_operation_request::Operation, cose_operation_result::Result as Branch};

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn generated_provider_failures_remain_fixed_and_do_not_release_partial_results(
) -> Result<(), CoseError> {
    for (fault, expected) in [
        (Fault::WrongResult, wire::CoseErrorReason::BackendInternal),
        (
            Fault::UnknownResponse,
            wire::CoseErrorReason::CommonMalformedProtobuf,
        ),
        (
            Fault::Unavailable,
            wire::CoseErrorReason::ProviderUnavailable,
        ),
        (
            Fault::CorruptSignature,
            wire::CoseErrorReason::Sign1InvalidSignature,
        ),
        (
            Fault::WrongHash,
            wire::CoseErrorReason::ContainerSigningInput,
        ),
        (
            Fault::WrongEncoding,
            wire::CoseErrorReason::Sign1InvalidSignatureEncoding,
        ),
        (
            Fault::OversizedKey,
            wire::CoseErrorReason::CommonResourceLimitExceeded,
        ),
        (
            Fault::VerifierContext,
            wire::CoseErrorReason::KeyAlgorithmMismatch,
        ),
        (
            Fault::VerifierPublicKey,
            wire::CoseErrorReason::KeyAlgorithmMismatch,
        ),
        (
            Fault::VerifierSuite,
            wire::CoseErrorReason::KeyAlgorithmMismatch,
        ),
    ] {
        let mut port = Port::new(-8)?;
        port.fault = fault;
        let response = api::execute_with_provider_transport(
            request(Operation::ContainerSign(Box::new(sign_request(-8)?))),
            &port,
        );
        assert_eq!(reason(&response), expected);
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn generated_provider_rejects_double_hash_and_invalid_capability_roles() -> Result<(), CoseError> {
    let mut port = Port::new(-7)?;
    port.prehash = true;
    port.fault = Fault::DoubleHash;
    assert_eq!(
        reason(&api::execute_with_provider_transport(
            request(Operation::ContainerSign(Box::new(sign_request(-7)?))),
            &port
        )),
        wire::CoseErrorReason::Sign1InvalidSignature
    );
    let port = Port::new(-8)?;
    let mut input = sign_request(-8)?;
    input.capability = super::support::capability(1, wire::CoseProviderKind::MacVerifier);
    assert_eq!(
        reason(&api::execute_with_provider_transport(
            request(Operation::ContainerSign(Box::new(input))),
            &port
        )),
        wire::CoseErrorReason::CommonInvalidParameter
    );
    assert_eq!(port.calls.get(), 0);
    let mut port = Port::new(-8)?;
    port.registry.capabilities = core::mem::take(&mut port.registry.capabilities)
        .into_iter()
        .filter(|capability| capability.kind != wire::CoseProviderKind::VerificationKey)
        .collect();
    assert_eq!(
        reason(&api::execute_with_provider_transport(
            request(Operation::ContainerSign(Box::new(sign_request(-8)?))),
            &port
        )),
        wire::CoseErrorReason::ProviderUnavailable
    );
    assert_eq!(port.signatures.get(), 0);
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn generated_provider_registry_bounds_duplicates_and_authorization_fail_before_callbacks(
) -> Result<(), CoseError> {
    let mut port = Port::new(-8)?;
    port.registry.capabilities.clear();
    assert_eq!(
        reason(&api::execute_with_provider_transport(
            request(Operation::ContainerSign(Box::new(sign_request(-8)?))),
            &port
        )),
        wire::CoseErrorReason::ProviderUnavailable
    );
    assert_eq!(port.calls.get(), 0);
    port.registry.capabilities = vec![
        wire::CoseProviderCapability {
            handle: 1,
            kind: wire::CoseProviderKind::Signer.into(),
        };
        2
    ]
    .into();
    assert_eq!(
        reason(&api::execute_with_provider_transport(
            request(Operation::ContainerSign(Box::new(sign_request(-8)?))),
            &port
        )),
        wire::CoseErrorReason::CommonInvalidParameter
    );
    while port.registry.capabilities.len() < 33 {
        port.registry
            .capabilities
            .push(wire::CoseProviderCapability::default());
    }
    assert_eq!(
        reason(&api::execute_with_provider_transport(
            request(Operation::ContainerSign(Box::new(sign_request(-8)?))),
            &port
        )),
        wire::CoseErrorReason::CommonResourceLimitExceeded
    );
    assert_eq!(port.calls.get(), 0);
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn canonical_policy_has_one_allowlist_and_explicit_empty_denial() -> Result<(), CoseError> {
    let policy = crate::CosePolicy::new().with_allowed_algorithms([crate::Algorithm::P256]);
    assert_eq!(
        policy.contract().allowed_algorithms,
        vec![
            buffa::EnumValue::from(wire::CoseSignatureAlgorithm::Es256),
            wire::CoseSignatureAlgorithm::Esp256.into()
        ]
        .into()
    );
    let restored = crate::CosePolicy::from_contract(policy.contract().clone())?;
    assert_eq!(restored.contract(), policy.contract());
    let (public, private) = reallyme_crypto::dispatch::generate_keypair(crate::Algorithm::Ed25519)
        .map_err(|_| CoseError::Crypto)?;
    let encoded = crate::cose_sign1(crate::Algorithm::Ed25519, b"policy", &private, None)?;
    let mut verify = wire::CoseSign1VerifyRequest::default();
    verify.cose_sign1 = encoded.to_vec().into();
    verify.public_key = public.into();
    let input = wire::CoseSign1VerifyProfileRequest {
        request: field(verify),
        policy: field(wire::CoseVerificationPolicy::default()),
        detached: false,
        detached_payload: Vec::new().into(),
        allow_unprotected_x5chain: false,
        capability: Default::default(),
    };
    assert_eq!(
        reason(&api::execute(request(Operation::Sign1VerifyProfile(
            Box::new(input.clone())
        )))),
        wire::CoseErrorReason::CommonUnsupportedAlgorithm
    );
    let mut allowed = input;
    allowed
        .policy
        .as_option_mut()
        .ok_or(CoseError::InvalidFormat)?
        .allowed_algorithms
        .push(wire::CoseSignatureAlgorithm::Ed25519.into());
    let Branch::Sign1VerifyProfile(output) = &mut success(api::execute(request(
        Operation::Sign1VerifyProfile(Box::new(allowed)),
    ))) else {
        return Err(CoseError::InvalidFormat);
    };
    assert_eq!(output.payload, b"policy");
    Ok(())
}
