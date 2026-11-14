// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::provider_support::{bytes, fixture, sign_request, Port};
use super::support::{field, hex, keys, reason, request, success, suite};
use crate::api::{self, contract as wire};
use crate::CoseError;
use wire::{cose_operation_request::Operation, cose_operation_result::Result as Branch};

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn generated_provider_signing_preserves_independent_eddsa_container_bytes() -> Result<(), CoseError>
{
    for external_verifier in [false, true] {
        let mut port = Port::new(-8)?;
        port.external_verifier = external_verifier;
        let input = sign_request(-8)?;
        let Branch::ContainerSign(output) = &mut success(api::execute_with_provider_transport(
            request(Operation::ContainerSign(Box::new(input))),
            &port,
        )) else {
            return Err(CoseError::InvalidFormat);
        };
        assert_eq!(output.encoded, bytes(&fixture(-8)?, "encoded")?);
        assert_eq!(port.signatures.get(), 1);
        assert_eq!(port.verifications.get(), usize::from(external_verifier));
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn generated_provider_prehash_signing_has_one_hash_and_independent_verification(
) -> Result<(), CoseError> {
    let mut port = Port::new(-7)?;
    port.prehash = true;
    let input = sign_request(-7)?;
    let Branch::ContainerSign(output) = &mut success(api::execute_with_provider_transport(
        request(Operation::ContainerSign(Box::new(input))),
        &port,
    )) else {
        return Err(CoseError::InvalidFormat);
    };
    let selected = crate::iso18013::Iso18013SignatureSuite::new(
        crate::CoseSignatureAlgorithm::Es256,
        crate::iso18013::Iso18013SignatureCurve::P256,
    )?;
    let public = hex(&keys()?
        .into_iter()
        .find(|key| key.curve == 1)
        .ok_or(CoseError::InvalidKeyMaterial)?
        .public);
    let verifier =
        crate::iso18013::Iso18013CryptoVerifier::new(selected, zeroize::Zeroizing::new(public))?;
    crate::iso18013::cose_verify_iso18013_sign1(
        crate::iso18013::Iso18013Sign1Request {
            encoded: &output.encoded,
            content: crate::iso18013::Iso18013Sign1Content::ReaderDetached(&bytes(
                &fixture(-7)?,
                "payload",
            )?),
            allowed_suites: &[selected],
            limits: Default::default(),
        },
        &verifier,
    )?;
    assert_eq!(port.signatures.get(), 1);
    assert_eq!(port.verifications.get(), 1);
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn generated_provider_mac_keeps_keys_nonexporting_and_preserves_standard_metadata(
) -> Result<(), CoseError> {
    let port = Port::new(-8)?;
    let mut input = super::mac::input();
    input.key.fill(0);
    input.key = Default::default();
    input.key_source = wire::CoseKeySource::Provider.into();
    input.capability = super::support::capability(1, wire::CoseProviderKind::MacVerifier);
    let Branch::Mac0VerifyDetached(output) = &mut success(api::execute_with_provider_transport(
        request(Operation::Mac0VerifyDetached(Box::new(input.clone()))),
        &port,
    )) else {
        return Err(CoseError::InvalidFormat);
    };
    assert_eq!(output.protected_headers, hex("a10105"));
    assert!(output.protected_kid.is_none());
    input.detached_payload[0] ^= 1;
    assert_eq!(
        reason(&api::execute_with_provider_transport(
            request(Operation::Mac0VerifyDetached(Box::new(input))),
            &port
        )),
        wire::CoseErrorReason::CommonAuthenticationFailed
    );
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn generated_provider_normalization_and_validation_keep_received_points_separate(
) -> Result<(), CoseError> {
    let port = Port::new(-8)?;
    let key = keys()?
        .into_iter()
        .find(|key| key.curve == 1)
        .ok_or(CoseError::InvalidKeyMaterial)?;
    let original = hex(&key.compressed);
    let input = wire::CoseAgreementKeyParseRequest {
        cose_key: original.clone().into(),
        policy: field(wire::CoseAgreementKeyPolicy {
            allowed_curves: vec![wire::CoseNamedCurve::P256.into()].into(),
            optional_parameters: wire::CoseAgreementOptionalParameters::IgnoreIsoOptional.into(),
            ec2_encoding: wire::CoseAgreementEc2EncodingPolicy::FullOrCompressed.into(),
        }),
        capability: super::support::capability(1, wire::CoseProviderKind::AgreementKeyNormalizer),
    };
    let Branch::AgreementKeyParse(output) = &mut success(api::execute_with_provider_transport(
        request(Operation::AgreementKeyParse(Box::new(input))),
        &port,
    )) else {
        return Err(CoseError::InvalidFormat);
    };
    assert_eq!(output.cose_key, original);
    assert_eq!(output.public_key, hex(&key.public));
    let input = wire::CosePeerKeyRequest {
        cose_key: original.into(),
        purpose: wire::CosePeerKeyPurpose::Agreement.into(),
        signature_suite: Default::default(),
        optional_parameters: wire::CoseAgreementOptionalParameters::IgnoreIsoOptional.into(),
        capability: super::support::capability(1, wire::CoseProviderKind::PeerKeyValidator),
    };
    let Branch::PeerKeyValidate(output) = &mut success(api::execute_with_provider_transport(
        request(Operation::PeerKeyValidate(Box::new(input))),
        &port,
    )) else {
        return Err(CoseError::InvalidFormat);
    };
    assert!(output.validated);
    assert_eq!(output.point_encoding, wire::CosePointEncoding::Ec2YSign);
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn generated_provider_verifier_preserves_original_algorithm_suite_and_context(
) -> Result<(), CoseError> {
    let port = Port::new(-7)?;
    let value = fixture(-7)?;
    let input = wire::CoseIsoSign1VerifyRequest {
        encoded: bytes(&value, "encoded")?.into(),
        content: wire::CoseIsoSign1Content::ReaderDetached.into(),
        detached_payload: bytes(&value, "payload")?.into(),
        allowed_suites: vec![suite(-7, 1)?].into(),
        key_suite: field(suite(-7, 1)?),
        public_key: Vec::new().into(),
        public_key_is_cose: false,
        key_source: wire::CoseKeySource::Provider.into(),
        capability: super::support::capability(1, wire::CoseProviderKind::VerificationKey),
        limits: Default::default(),
    };
    let Branch::IsoSign1Verify(output) = &mut success(api::execute_with_provider_transport(
        request(Operation::IsoSign1Verify(Box::new(input))),
        &port,
    )) else {
        return Err(CoseError::InvalidFormat);
    };
    assert_eq!(output.suite.as_option(), Some(&suite(-7, 1)?));
    assert_eq!(port.verifications.get(), 1);
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn generated_provider_certificate_selection_is_bound_to_exact_der_not_only_public_key(
) -> Result<(), CoseError> {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/fixtures/containers.json"))
            .map_err(|_| CoseError::Cbor)?;
    let case = vectors["cases"]
        .as_array()
        .and_then(|cases| {
            cases
                .iter()
                .find(|case| case["id"] == "issuer-dis-thumbprint")
        })
        .ok_or(CoseError::InvalidFormat)?;
    let mut port = Port::new(-7)?;
    port.selected_certificate = bytes(&vectors, "certificate_a")?;
    let input = wire::CoseContainerVerifyRequest {
        encoded: bytes(case, "encoded")?.into(),
        content_mode: wire::CoseContentMode::Attached.into(),
        detached_payload: Vec::new().into(),
        external_aad: Vec::new().into(),
        policy: field(wire::CoseContainerPolicy {
            profile: wire::CoseContainerProfile::IsoEdition2Dis.into(),
            purpose: wire::CoseContainerPurpose::IssuerMso.into(),
            envelope: wire::CoseEnvelopePolicy::Untagged.into(),
        }),
        allowed_suites: vec![suite(-7, 1)?].into(),
        key_source: wire::CoseKeySource::Certificates.into(),
        key: Default::default(),
        capability: super::support::capability(1, wire::CoseProviderKind::CertificateValidator),
        limits: Default::default(),
    };
    let Branch::ContainerVerify(output) = &mut success(api::execute_with_provider_transport(
        request(Operation::ContainerVerify(Box::new(input.clone()))),
        &port,
    )) else {
        return Err(CoseError::InvalidFormat);
    };
    assert_eq!(
        output
            .key
            .as_option()
            .ok_or(CoseError::InvalidFormat)?
            .context_id,
        vec![0x42; 32]
    );
    port.selected_certificate = bytes(&vectors, "certificate_b")?;
    assert_eq!(
        reason(&api::execute_with_provider_transport(
            request(Operation::ContainerVerify(Box::new(input))),
            &port
        )),
        wire::CoseErrorReason::ContainerCertificateMismatch
    );
    assert_eq!(port.verifications.get(), 1);
    Ok(())
}
