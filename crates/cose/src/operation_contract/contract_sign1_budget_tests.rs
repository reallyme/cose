// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::support::{
    capability, codec_parity, codec_parity_with_providers, field, hex, reason, success,
};
use crate::api::{contract as wire, OperationProviders};
use crate::containers::{
    self, CertificateHeaders, CertificateSelection, CertificateValidator, ContainerError,
    ContainerLimits, ContainerPolicy, ContainerProfile, ContainerPurpose, ContainerSignRequest,
    ContainerSigner, ContainerVerifyRequest, CryptoVerificationKey, EnvelopePolicy,
    SignatureEncoding, SignatureSuite, SigningContent, SigningInput, SigningMode, VerificationKey,
    VerificationSource,
};
use crate::limits::{MAX_COSE_SIGN1_BYTES, MAX_COSE_SIGN1_ENCODED_BYTES};
use crate::{Algorithm, CoseError, CosePolicy, CoseSign1EncodeOptions, CoseSignatureAlgorithm};
use wire::{cose_operation_request::Operation, cose_operation_result::Result as Branch};
use zeroize::Zeroizing;

const SELECTED_BUDGET: usize = 700_000;
const LIST_BYTES: usize = 600_000;

struct Fixture {
    key: CryptoVerificationKey,
    private: Zeroizing<Vec<u8>>,
    certificate: Zeroizing<Vec<u8>>,
    protected: Zeroizing<Vec<u8>>,
}
impl Fixture {
    fn new() -> Result<Self, CoseError> {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/fixtures/containers.json"))
                .map_err(|_| CoseError::Cbor)?;
        let case = vectors["cases"]
            .as_array()
            .and_then(|cases| cases.iter().find(|case| case["id"] == "strict-modern"))
            .ok_or(CoseError::InvalidFormat)?;
        let certificate = Zeroizing::new(hex(vectors["certificate_a"]
            .as_str()
            .ok_or(CoseError::InvalidFormat)?));
        let key = CryptoVerificationKey::new(
            SignatureSuite::modern(CoseSignatureAlgorithm::Esp256)?,
            Zeroizing::new(hex(case["public_key"]
                .as_str()
                .ok_or(CoseError::InvalidFormat)?)),
            [0x42; 32],
        )?;
        let mut private = Zeroizing::new(vec![0; 32]);
        private[31] = 1;
        // Deliberately retain the received non-sorted protected map order.
        let protected = crate::encode_cbor::encode_cbor_value(ciborium::Value::Map(vec![
            (33.into(), ciborium::Value::Bytes(certificate.to_vec())),
            (1.into(), (-9).into()),
        ]))?;
        Ok(Self {
            key,
            private,
            certificate,
            protected,
        })
    }
}
impl ContainerSigner for Fixture {
    fn verification_key(&self) -> &dyn VerificationKey {
        &self.key
    }
    fn input_mode(&self) -> SigningMode {
        SigningMode::Message
    }
    fn signature_encoding(&self) -> SignatureEncoding {
        SignatureEncoding::EcdsaDer
    }
    fn sign(&self, input: SigningInput<'_>) -> Result<Zeroizing<Vec<u8>>, ContainerError> {
        let SigningInput::Message(message) = input else {
            return Err(CoseError::InvalidFormat);
        };
        reallyme_crypto::dispatch::sign(Algorithm::P256, &self.private, message)
            .map(Zeroizing::new)
            .map_err(|_| CoseError::Crypto)
    }
}
impl CertificateValidator for Fixture {
    fn resolve(
        &self,
        _: &CertificateHeaders<'_>,
        algorithm: i64,
    ) -> Result<CertificateSelection<'_>, ContainerError> {
        assert_eq!(algorithm, -9);
        Ok(CertificateSelection {
            key: &self.key,
            end_entity_der: &self.certificate,
        })
    }
}
impl OperationProviders for Fixture {
    fn container_signer(&self, handle: u64) -> Result<&dyn ContainerSigner, ContainerError> {
        assert_eq!(handle, 1);
        Ok(self)
    }
    fn certificate_validator(
        &self,
        handle: u64,
    ) -> Result<&dyn CertificateValidator, ContainerError> {
        assert_eq!(handle, 1);
        Ok(self)
    }
}

fn policy() -> ContainerPolicy {
    ContainerPolicy {
        profile: ContainerProfile::Rfc9360,
        purpose: ContainerPurpose::Generic,
        envelope: EnvelopePolicy::Untagged,
    }
}
fn bounds(encoded: usize) -> ContainerLimits {
    ContainerLimits {
        encoded_bytes: encoded,
        ..Default::default()
    }
}
fn portable_bounds(encoded: usize) -> Result<wire::CoseByteLimits, CoseError> {
    Ok(wire::CoseByteLimits {
        encoded_bytes: u64::try_from(encoded).map_err(|_| CoseError::ResourceLimitExceeded)?,
        payload_bytes: u64::try_from(crate::limits::MAX_DETACHED_PAYLOAD_BYTES)
            .map_err(|_| CoseError::ResourceLimitExceeded)?,
        external_aad_bytes: u64::try_from(MAX_COSE_SIGN1_BYTES)
            .map_err(|_| CoseError::ResourceLimitExceeded)?,
    })
}
fn payload(length: usize) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    // COSE authenticates this CBOR claims map. Status-list compression, size
    // policy and claim acceptance belong to SSI, including its negative cases.
    crate::encode_cbor::encode_cbor_value(ciborium::Value::Map(vec![
        (1.into(), "https://issuer.example".into()),
        (
            "status_list".into(),
            ciborium::Value::Map(vec![
                ("bits".into(), 1.into()),
                ("lst".into(), ciborium::Value::Bytes(vec![0x42; length])),
            ]),
        ),
    ]))
}
fn sign_native(
    fixture: &Fixture,
    payload: &[u8],
    budget: usize,
) -> Result<containers::SignedContainer, CoseError> {
    containers::sign_container(
        ContainerSignRequest {
            protected_headers: &fixture.protected,
            unprotected_headers: &[0xa0],
            content: SigningContent::Attached(payload),
            external_aad: &[],
            policy: policy(),
            allowed_suites: &[fixture.key.suite()],
            limits: bounds(budget),
        },
        fixture,
    )
}
fn verify_native(
    fixture: &Fixture,
    encoded: &[u8],
    budget: usize,
) -> Result<containers::VerifiedContainer, CoseError> {
    containers::verify_container(
        ContainerVerifyRequest {
            encoded,
            content: containers::ContainerContent::Attached,
            external_aad: &[],
            policy: policy(),
            allowed_suites: &[fixture.key.suite()],
            limits: bounds(budget),
        },
        VerificationSource::Certificates(fixture),
    )
}
fn sign_request(
    fixture: &Fixture,
    payload: &[u8],
    budget: usize,
) -> Result<wire::CoseContainerSignRequest, CoseError> {
    Ok(wire::CoseContainerSignRequest {
        protected_headers: fixture.protected.to_vec().into(),
        unprotected_headers: vec![0xa0].into(),
        payload: payload.to_vec().into(),
        content_mode: wire::CoseContentMode::Attached.into(),
        policy: field(policy().into()),
        allowed_suites: vec![fixture.key.suite().into()].into(),
        capability: capability(1, wire::CoseProviderKind::Signer),
        limits: field(portable_bounds(budget)?),
        external_aad: Default::default(),
    })
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn certificate_backed_cwt_uses_the_exact_selected_sign1_budget_in_every_lane(
) -> Result<(), CoseError> {
    let fixture = Fixture::new()?;
    for list_bytes in [
        LIST_BYTES,
        LIST_BYTES
            .checked_add(1)
            .ok_or(CoseError::ResourceLimitExceeded)?,
    ] {
        let payload = payload(list_bytes)?;
        assert_eq!(
            sign_native(&fixture, &payload, MAX_COSE_SIGN1_BYTES).err(),
            Some(CoseError::ResourceLimitExceeded)
        );
        let signed = sign_native(&fixture, &payload, SELECTED_BUDGET)?;
        assert!(signed.encoded().len() > MAX_COSE_SIGN1_BYTES);
        let verified = verify_native(&fixture, signed.encoded(), SELECTED_BUDGET)?;
        assert_eq!(verified.payload(), payload.as_slice());
        assert_eq!(verified.protected_headers(), fixture.protected.as_slice());
        assert_eq!(
            verify_native(&fixture, signed.encoded(), MAX_COSE_SIGN1_BYTES).err(),
            Some(CoseError::ResourceLimitExceeded)
        );

        let input = sign_request(&fixture, &payload, SELECTED_BUDGET)?;
        let mut default_sign = input.clone();
        default_sign.limits = Default::default();
        assert_eq!(
            reason(&codec_parity_with_providers(
                Operation::ContainerSign(Box::new(default_sign)),
                &fixture
            )?),
            wire::CoseErrorReason::CommonResourceLimitExceeded
        );
        assert_eq!(
            input.limits.as_option().map(|value| value.encoded_bytes),
            Some(700_000)
        );
        let Branch::ContainerSign(ref output) = success(codec_parity_with_providers(
            Operation::ContainerSign(Box::new(input)),
            &fixture,
        )?) else {
            return Err(CoseError::InvalidFormat);
        };
        assert_eq!(output.encoded.as_ref(), signed.encoded());
        let verify = wire::CoseContainerVerifyRequest {
            encoded: output.encoded.clone(),
            content_mode: wire::CoseContentMode::Attached.into(),
            policy: field(policy().into()),
            allowed_suites: vec![fixture.key.suite().into()].into(),
            key_source: wire::CoseKeySource::Certificates.into(),
            capability: capability(1, wire::CoseProviderKind::CertificateValidator),
            limits: field(portable_bounds(SELECTED_BUDGET)?),
            detached_payload: Default::default(),
            external_aad: Default::default(),
            key: Default::default(),
        };
        let mut default_verify = verify.clone();
        default_verify.limits = Default::default();
        assert_eq!(
            reason(&codec_parity_with_providers(
                Operation::ContainerVerify(Box::new(default_verify)),
                &fixture
            )?),
            wire::CoseErrorReason::CommonResourceLimitExceeded
        );
        let Branch::ContainerVerify(ref receipt) = success(codec_parity_with_providers(
            Operation::ContainerVerify(Box::new(verify.clone())),
            &fixture,
        )?) else {
            return Err(CoseError::InvalidFormat);
        };
        assert_eq!(receipt.payload.as_ref(), payload.as_slice());
        assert_eq!(
            receipt.protected_headers.as_ref(),
            fixture.protected.as_slice()
        );
        let smaller = signed
            .encoded()
            .len()
            .checked_sub(1)
            .ok_or(CoseError::ResourceLimitExceeded)?;
        assert_eq!(
            reason(&codec_parity_with_providers(
                Operation::ContainerSign(Box::new(sign_request(&fixture, &payload, smaller)?)),
                &fixture
            )?),
            wire::CoseErrorReason::CommonResourceLimitExceeded
        );
        let mut too_small = verify;
        too_small.limits = field(portable_bounds(smaller)?);
        assert_eq!(
            reason(&codec_parity_with_providers(
                Operation::ContainerVerify(Box::new(too_small)),
                &fixture
            )?),
            wire::CoseErrorReason::CommonResourceLimitExceeded
        );
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn sign1_selected_and_absolute_budget_boundaries_preserve_defaults_and_typed_failures(
) -> Result<(), CoseError> {
    let fixture = Fixture::new()?;
    let base_payload = payload(LIST_BYTES)?;
    let base = sign_native(&fixture, &base_payload, SELECTED_BUDGET)?;
    let overhead = base
        .encoded()
        .len()
        .checked_sub(LIST_BYTES)
        .ok_or(CoseError::ResourceLimitExceeded)?;
    for budget in [SELECTED_BUDGET, MAX_COSE_SIGN1_ENCODED_BYTES] {
        let count = budget
            .checked_sub(overhead)
            .ok_or(CoseError::ResourceLimitExceeded)?;
        let exact_payload = payload(count)?;
        let signed = sign_native(&fixture, &exact_payload, budget)?;
        assert_eq!(signed.encoded().len(), budget);
        verify_native(&fixture, signed.encoded(), budget)?;
        let over_payload = payload(
            count
                .checked_add(1)
                .ok_or(CoseError::ResourceLimitExceeded)?,
        )?;
        assert_eq!(
            sign_native(&fixture, &over_payload, budget).err(),
            Some(CoseError::ResourceLimitExceeded)
        );
    }
    for budget in [
        MAX_COSE_SIGN1_ENCODED_BYTES
            .checked_add(1)
            .ok_or(CoseError::ResourceLimitExceeded)?,
        usize::MAX,
    ] {
        assert_eq!(
            sign_native(&fixture, &base_payload, budget).err(),
            Some(CoseError::ResourceLimitExceeded)
        );
        assert_eq!(
            verify_native(&fixture, base.encoded(), budget).err(),
            Some(CoseError::ResourceLimitExceeded)
        );
        let options = CoseSign1EncodeOptions::new().with_max_cose_sign1_bytes(budget);
        assert_eq!(
            crate::cose_sign1_with_options(
                Algorithm::P256,
                &base_payload,
                &fixture.private,
                None,
                options
            )
            .err(),
            Some(CoseError::ResourceLimitExceeded)
        );
    }
    // Retained native builders and legacy protobuf scalar fields must preserve
    // the same explicit budget, rather than quietly restoring the default.
    let options = CoseSign1EncodeOptions::new()
        .with_max_cose_sign1_bytes(SELECTED_BUDGET)
        .with_x5chain_der(vec![fixture.certificate.to_vec()]);
    let selected = CosePolicy::new().with_max_cose_sign1_bytes(SELECTED_BUDGET);
    assert_eq!(options.max_cose_sign1_bytes(), SELECTED_BUDGET);
    assert_eq!(selected.max_cose_sign1_bytes(), SELECTED_BUDGET);
    let legacy = crate::cose_sign1_with_options(
        Algorithm::P256,
        &base_payload,
        &fixture.private,
        None,
        options,
    )?;
    let receipt = crate::cose_verify1_with_x5chain(&legacy, &selected, |_, chain| {
        assert_eq!(
            chain.first().map(Vec::as_slice),
            Some(fixture.certificate.as_slice())
        );
        Some(fixture.key.public_key().to_vec())
    })?;
    assert_eq!(receipt.payload.as_slice(), base_payload.as_slice());
    let create = wire::CoseSign1CreateRequest::default()
        .with_algorithm(wire::CoseSignatureAlgorithm::Esp256)
        .with_private_key(fixture.private.to_vec())
        .with_payload(base_payload.to_vec())
        .with_options(wire::CoseSign1Options::default().with_max_cose_sign1_bytes(700_000));
    let Branch::Sign1Create(ref encoded) =
        success(codec_parity(Operation::Sign1Create(Box::new(create)))?)
    else {
        return Err(CoseError::InvalidFormat);
    };
    let verify = wire::CoseSign1VerifyRequest::default()
        .with_cose_sign1(encoded.cose_sign1.clone())
        .with_public_key(fixture.key.public_key().to_vec())
        .with_public_key_algorithm(wire::CoseSignatureAlgorithm::Esp256)
        .with_max_cose_sign1_bytes(700_000);
    success(codec_parity(Operation::Sign1Verify(Box::new(verify)))?);
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn unsupported_sign1_budgets_have_one_reason_before_platform_length_conversion(
) -> Result<(), CoseError> {
    let fixture = Fixture::new()?;
    let maximum = u64::try_from(MAX_COSE_SIGN1_ENCODED_BYTES)
        .map_err(|_| CoseError::ResourceLimitExceeded)?;
    for encoded in [
        maximum
            .checked_add(1)
            .ok_or(CoseError::ResourceLimitExceeded)?,
        u64::MAX,
    ] {
        for canonical in [false, true] {
            let mut options = wire::CoseSign1Options::default();
            if canonical {
                let mut limits = portable_bounds(SELECTED_BUDGET)?;
                limits.encoded_bytes = encoded;
                options.limits = field(limits);
            } else {
                options.max_cose_sign1_bytes = encoded;
            }
            let create = wire::CoseSign1CreateRequest::default()
                .with_algorithm(wire::CoseSignatureAlgorithm::Esp256)
                .with_private_key(fixture.private.to_vec())
                .with_options(options);
            assert_eq!(
                reason(&codec_parity(Operation::Sign1Create(Box::new(create)))?),
                wire::CoseErrorReason::CommonResourceLimitExceeded
            );
        }
        let verify = wire::CoseSign1VerifyRequest::default()
            .with_public_key(fixture.key.public_key().to_vec())
            .with_public_key_algorithm(wire::CoseSignatureAlgorithm::Esp256)
            .with_max_cose_sign1_bytes(encoded);
        assert_eq!(
            reason(&codec_parity(Operation::Sign1Verify(Box::new(verify)))?),
            wire::CoseErrorReason::CommonResourceLimitExceeded
        );
    }
    Ok(())
}
