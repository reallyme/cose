// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::provider_support::{bytes, Port};
use super::support::{codec_parity_with_providers, field, reason, request, success, suite};
use crate::api::{self, contract as wire, ProviderTransport};
use crate::CoseError;
use core::cell::Cell;
use wire::{
    cose_operation_request::Operation, cose_operation_result::Result as Branch,
    cose_provider_call_request::Call, cose_provider_call_response::Outcome,
    cose_provider_call_result::Result as ProviderResult,
};

struct CertificatePort {
    inner: Port,
    replacement_suite: Option<wire::CoseSignatureSuite>,
    placement: Cell<Option<wire::CoseX5ChainHeaderPlacement>>,
    algorithm: Cell<Option<wire::CoseSignatureAlgorithm>>,
}

impl ProviderTransport for CertificatePort {
    fn registry(&self) -> &wire::CoseProviderRegistry {
        self.inner.registry()
    }

    fn call(&self, request: wire::CoseProviderCallRequest) -> wire::CoseProviderCallResponse {
        if let Some(Call::ResolveCertificate(input)) = request.call.as_ref() {
            self.placement.set(input.placement.as_known());
            self.algorithm.set(input.algorithm.as_known());
        }
        let mut response = self.inner.call(request);
        if let Some(replacement) = &self.replacement_suite {
            if let Some(Outcome::Result(result)) = response.outcome.as_mut() {
                if let Some(ProviderResult::ResolveCertificate(selected)) = result.result.as_mut() {
                    if let Some(key) = selected.key.as_option_mut() {
                        key.suite = field(replacement.clone());
                    }
                }
            }
        }
        response
    }
}

fn fixture(
    id: &str,
) -> Result<
    (
        wire::CoseSign1VerifyProfileRequest,
        CertificatePort,
        Vec<u8>,
    ),
    CoseError,
> {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/fixtures/containers.json"))
            .map_err(|_| CoseError::Cbor)?;
    let case = vectors["cases"]
        .as_array()
        .and_then(|cases| cases.iter().find(|case| case["id"] == id))
        .ok_or(CoseError::InvalidFormat)?;
    let mut port = Port::new(-7)?;
    port.selected_certificate = bytes(&vectors, "certificate_a")?;
    let verification = wire::CoseSign1VerifyRequest::default()
        .with_cose_sign1(bytes(case, "encoded")?)
        .with_allowed_algorithms(vec![wire::CoseSignatureAlgorithm::Es256.into()])
        .with_public_key_algorithm(wire::CoseSignatureAlgorithm::Es256);
    let input = wire::CoseSign1VerifyProfileRequest::default()
        .with_request(verification)
        .with_allow_unprotected_x5chain(id == "issuer-2021")
        .with_capability(super::support::capability(
            1,
            wire::CoseProviderKind::KeyResolver,
        ));
    Ok((
        input,
        CertificatePort {
            inner: port,
            replacement_suite: None,
            placement: Cell::new(None),
            algorithm: Cell::new(None),
        },
        bytes(&vectors, "certificate_b")?,
    ))
}

fn execute(
    input: wire::CoseSign1VerifyProfileRequest,
    port: &CertificatePort,
) -> Result<wire::CoseOperationResponseV2, CoseError> {
    let operation = Operation::Sign1VerifyX5chain(Box::new(input));
    let response = api::execute_with_provider_transport(request(operation.clone()), port);
    let session = crate::operation_contract::provider_transport::Session::new(port);
    let parity = codec_parity_with_providers(operation, &session)?;
    assert_eq!(response, parity);
    assert_eq!(session.take_failure(), None);
    Ok(response)
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn x5chain_provider_binds_leaf_and_forwards_real_placement_for_independent_vectors(
) -> Result<(), CoseError> {
    for (id, placement) in [
        ("issuer-2021", wire::CoseX5ChainHeaderPlacement::Unprotected),
        (
            "issuer-protected-chain",
            wire::CoseX5ChainHeaderPlacement::Protected,
        ),
        ("revocation", wire::CoseX5ChainHeaderPlacement::Protected),
    ] {
        let (input, port, _) = fixture(id)?;
        let Branch::Sign1VerifyX5chain(output) = &success(execute(input, &port)?) else {
            return Err(CoseError::InvalidFormat);
        };
        assert_eq!(port.placement.get(), Some(placement));
        assert_eq!(
            port.algorithm.get(),
            Some(wire::CoseSignatureAlgorithm::Es256)
        );
        assert_eq!(output.placement.as_known(), Some(placement));
        assert_eq!(
            output
                .x5chain
                .as_option()
                .ok_or(CoseError::InvalidFormat)?
                .certificates_der[0]
                .as_slice(),
            port.inner.selected_certificate
        );
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn x5chain_provider_rejects_different_selected_der_even_when_keys_match() -> Result<(), CoseError> {
    // The independent certificates share a public key but have distinct DER.
    // Selecting the non-leaf of a two-entry chain must also fail (p02).
    for id in ["issuer-2021", "issuer-protected-chain", "revocation"] {
        let (input, mut port, other_certificate) = fixture(id)?;
        port.inner.selected_certificate = other_certificate;
        assert_eq!(
            reason(&execute(input.clone(), &port)?),
            wire::CoseErrorReason::CertificateMismatch
        );
        port.inner.selected_certificate.clear();
        assert_eq!(
            reason(&execute(input, &port)?),
            wire::CoseErrorReason::CertificateMismatch
        );
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn x5chain_provider_rejects_registration_and_curve_mismatches_before_signature_verification(
) -> Result<(), CoseError> {
    for selected in [suite(-9, 1)?, suite(-7, 2)?] {
        let (input, mut port, _) = fixture("issuer-protected-chain")?;
        // ES256 and ESP256 use the same P-256 verifier. Reinterpreting this
        // response as the requested suite would accept the valid signature.
        port.replacement_suite = Some(selected);
        assert_eq!(
            reason(&execute(input, &port)?),
            wire::CoseErrorReason::KeyAlgorithmMismatch
        );
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn x5chain_provider_preserves_policy_and_bounds_at_the_certificate_boundary(
) -> Result<(), CoseError> {
    let (mut input, mut port, _) = fixture("issuer-2021")?;
    input.allow_unprotected_x5chain = false;
    assert_eq!(
        reason(&execute(input, &port)?),
        wire::CoseErrorReason::Sign1UnprotectedHeaderNotAllowed
    );
    assert_eq!(port.inner.calls.get(), 0);
    let (input, _, _) = fixture("issuer-protected-chain")?;
    let oversized = crate::limits::MAX_COSE_X5CHAIN_CERTIFICATE_BYTES
        .checked_add(1)
        .ok_or(CoseError::ResourceLimitExceeded)?;
    port.inner.selected_certificate = vec![0; oversized];
    assert_eq!(
        reason(&execute(input, &port)?),
        wire::CoseErrorReason::CommonResourceLimitExceeded
    );
    Ok(())
}
