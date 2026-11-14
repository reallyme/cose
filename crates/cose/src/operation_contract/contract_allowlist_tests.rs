// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::support::{codec_parity, field, hex, keys, reason, success};
use crate::api::contract::{self as wire, __buffa::oneof::cose_operation_request::Operation};
use crate::containers::{
    self as native, AgreementKey, AgreementKeyPolicy, ContainerError, ContainerSigner,
    CryptoAgreementKeyProvider, OptionalKeyPolicy, PeerCurve, SignatureSuite, VerificationKey,
};
use crate::iso18013::Iso18013Verifier;
use crate::{CoseError, CoseSignatureAlgorithm};
use zeroize::Zeroizing;

// Generated owners implement Drop; populate defaults without moving other
// fields out of a temporary owner through Rust struct-update syntax.
fn message<T: Default>(populate: impl FnOnce(&mut T)) -> T {
    let mut value = T::default();
    populate(&mut value);
    value
}

fn failure<T>(result: Result<T, CoseError>) -> Result<wire::CoseErrorReason, CoseError> {
    match result {
        Err(error) => Ok(error.reason()),
        Ok(_) => Err(CoseError::InvalidFormat),
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn agreement_allowlist_invariants_match_native_create_and_parse() -> Result<(), CoseError> {
    let fixture = keys()?
        .into_iter()
        .find(|case| case.curve == 1)
        .ok_or(CoseError::InvalidFormat)?;
    let encoded = hex(&fixture.key);
    let public = hex(&fixture.public);
    for (curves, expected) in [
        (vec![], wire::CoseErrorReason::CommonResourceLimitExceeded),
        (
            vec![PeerCurve::P256; 2],
            wire::CoseErrorReason::CommonDuplicateMapLabel,
        ),
        (
            vec![PeerCurve::P256; 10],
            wire::CoseErrorReason::CommonResourceLimitExceeded,
        ),
        (
            vec![PeerCurve::P256, PeerCurve::Ed25519],
            wire::CoseErrorReason::KeyInvalidKeyMaterial,
        ),
        (
            vec![PeerCurve::P256, PeerCurve::Secp256k1],
            wire::CoseErrorReason::CommonUnsupportedAlgorithm,
        ),
        (
            vec![PeerCurve::P384],
            wire::CoseErrorReason::CommonUnsupportedAlgorithm,
        ),
    ] {
        let selected = AgreementKeyPolicy {
            allowed_curves: &curves,
            optional_parameters: OptionalKeyPolicy::Cose,
            ec2_encoding: native::AgreementEc2EncodingPolicy::FullCoordinatesOnly,
        };
        assert_eq!(
            failure(AgreementKey::from_slice(
                &encoded,
                selected,
                &CryptoAgreementKeyProvider
            ))?,
            expected
        );
        assert_eq!(
            failure(AgreementKey::from_public_key(
                PeerCurve::P256,
                &public,
                native::PeerPointEncoding::Ec2Coordinates,
                selected,
                &CryptoAgreementKeyProvider
            ))?,
            expected
        );
        let selected = wire::CoseAgreementKeyPolicy {
            allowed_curves: curves
                .into_iter()
                .map(|curve| wire::CoseNamedCurve::from(curve).into())
                .collect(),
            optional_parameters: wire::CoseAgreementOptionalParameters::ValidateCose.into(),
            ec2_encoding: wire::CoseAgreementEc2EncodingPolicy::FullCoordinatesOnly.into(),
        };
        for operation in [
            Operation::AgreementKeyParse(Box::new(message::<wire::CoseAgreementKeyParseRequest>(
                |value| {
                    value.cose_key = encoded.clone().into();
                    value.policy = field(selected.clone());
                },
            ))),
            Operation::AgreementKeyCreate(Box::new(
                message::<wire::CoseAgreementKeyCreateRequest>(|value| {
                    value.curve = wire::CoseNamedCurve::P256.into();
                    value.public_key = public.clone().into();
                    value.point_encoding = wire::CosePointEncoding::Ec2Coordinates.into();
                    value.policy = field(selected);
                }),
            )),
        ] {
            assert_eq!(reason(&codec_parity(operation)?), expected);
        }
    }
    Ok(())
}

struct UnavailableKey(SignatureSuite);
impl VerificationKey for UnavailableKey {
    fn suite(&self) -> SignatureSuite {
        self.0
    }
    fn public_key(&self) -> &[u8] {
        &[]
    }
    fn context_id(&self) -> &[u8; 32] {
        &[0; 32]
    }
    fn verify(&self, _: &[u8], _: &[u8]) -> Result<(), ContainerError> {
        Err(CoseError::ProviderUnavailable)
    }
}
impl Iso18013Verifier for UnavailableKey {
    fn suite(&self) -> SignatureSuite {
        self.0
    }
    fn verify(&self, _: &[u8], _: &[u8]) -> Result<(), CoseError> {
        Err(CoseError::ProviderUnavailable)
    }
}
impl ContainerSigner for UnavailableKey {
    fn verification_key(&self) -> &dyn VerificationKey {
        self
    }
    fn input_mode(&self) -> native::SigningMode {
        native::SigningMode::Message
    }
    fn signature_encoding(&self) -> native::SignatureEncoding {
        native::SignatureEncoding::EcdsaFixed
    }
    fn sign(&self, _: native::SigningInput<'_>) -> Result<Zeroizing<Vec<u8>>, ContainerError> {
        Err(CoseError::ProviderUnavailable)
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn signature_allowlist_bounds_and_unused_invalid_tuples_match_every_entrypoint(
) -> Result<(), CoseError> {
    let selected = SignatureSuite::modern(CoseSignatureAlgorithm::Esp256)?;
    let invalid = SignatureSuite::try_from(&message::<wire::CoseSignatureSuite>(|value| {
        value.registration = wire::CoseSignatureAlgorithm::Esp256.into();
        value.curve = wire::CoseNamedCurve::P384.into();
    }))?;
    let policy = native::ContainerPolicy {
        profile: native::ContainerProfile::Rfc9360,
        purpose: native::ContainerPurpose::Generic,
        envelope: native::EnvelopePolicy::Untagged,
    };
    let key = UnavailableKey(selected);
    let mismatch = wire::CoseErrorReason::KeyAlgorithmMismatch;
    assert_eq!(
        failure(native::CryptoVerificationKey::new(
            invalid,
            Zeroizing::new(Vec::new()),
            [0; 32]
        ))?,
        mismatch
    );
    assert_eq!(
        reason(&codec_parity(Operation::VerificationKeyImport(Box::new(
            message::<wire::CoseVerificationKeyImportRequest>(|value| {
                value.suite = field(invalid.into());
                value.context_id = vec![0; 32].into();
            })
        )))?),
        mismatch
    );
    let unsupported = wire::CoseErrorReason::CommonUnsupportedAlgorithm;
    assert_eq!(
        failure(crate::iso18013::Iso18013CryptoVerifier::new(
            selected,
            Zeroizing::new(Vec::new())
        ))?,
        unsupported
    );
    assert_eq!(
        failure(crate::iso18013::Iso18013CryptoVerifier::from_cose_key(
            selected,
            &[]
        ))?,
        unsupported
    );
    assert_eq!(
        reason(&codec_parity(Operation::IsoSign1Verify(Box::new(
            message::<wire::CoseIsoSign1VerifyRequest>(|value| {
                value.key_suite = field(selected.into());
            })
        )))?),
        unsupported
    );
    for (allowed, expected) in [
        (
            vec![selected; 33],
            wire::CoseErrorReason::CommonResourceLimitExceeded,
        ),
        (
            vec![selected, invalid],
            wire::CoseErrorReason::KeyAlgorithmMismatch,
        ),
    ] {
        assert_eq!(
            failure(native::verify_container(
                native::ContainerVerifyRequest {
                    encoded: &[],
                    content: native::ContainerContent::Attached,
                    external_aad: &[],
                    policy,
                    allowed_suites: &allowed,
                    limits: Default::default(),
                },
                native::VerificationSource::Key(&key)
            ))?,
            expected
        );
        assert_eq!(
            failure(native::sign_container(
                native::ContainerSignRequest {
                    protected_headers: &[],
                    unprotected_headers: &[],
                    content: native::SigningContent::Detached(&[]),
                    external_aad: &[],
                    policy,
                    allowed_suites: &allowed,
                    limits: Default::default(),
                },
                &key
            ))?,
            expected
        );
        let allowed: Vec<wire::CoseSignatureSuite> = allowed.into_iter().map(Into::into).collect();
        for operation in [
            Operation::ContainerVerify(Box::new(message::<wire::CoseContainerVerifyRequest>(
                |value| {
                    value.policy = field(policy.into());
                    value.allowed_suites = allowed.clone().into();
                },
            ))),
            Operation::ContainerSign(Box::new(message::<wire::CoseContainerSignRequest>(
                |value| {
                    value.policy = field(policy.into());
                    value.allowed_suites = allowed.into();
                },
            ))),
        ] {
            assert_eq!(reason(&codec_parity(operation)?), expected);
        }
    }
    let iso = SignatureSuite::new(CoseSignatureAlgorithm::Es256, PeerCurve::P256)?;
    let allowed = vec![iso; 33];
    let expected = wire::CoseErrorReason::CommonResourceLimitExceeded;
    assert_eq!(
        failure(crate::iso18013::cose_verify_iso18013_sign1(
            crate::iso18013::Iso18013Sign1Request {
                encoded: &[],
                content: crate::iso18013::Iso18013Sign1Content::IssuerAttached,
                allowed_suites: &allowed,
                limits: Default::default(),
            },
            &UnavailableKey(iso)
        ))?,
        expected
    );
    assert_eq!(
        reason(&codec_parity(Operation::IsoSign1Verify(Box::new(
            message::<wire::CoseIsoSign1VerifyRequest>(|value| {
                value.key_suite = field(iso.into());
                value.allowed_suites = allowed.into_iter().map(Into::into).collect();
            })
        )))?),
        expected
    );
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn mac_allowlist_bound_matches_the_native_detached_contract() -> Result<(), CoseError> {
    let mut request = super::mac::input();
    let key = crate::CoseMacKey::new(
        crate::CoseMacAlgorithm::Hmac256_256,
        request.key.clone().into_zeroizing(),
    )?;
    request.allowed_algorithms = vec![wire::CoseMacAlgorithm::Hmac256256.into(); 32].into();
    let at_limit = vec![crate::CoseMacAlgorithm::Hmac256_256; 32];
    let native = crate::cose_verify_mac0_detached(
        crate::CoseMac0VerifyRequest {
            encoded: &request.encoded,
            detached_payload: &request.detached_payload,
            external_aad: &request.external_aad,
            allowed_algorithms: &at_limit,
            limits: Default::default(),
        },
        &key,
    )?;
    let wire::__buffa::oneof::cose_operation_result::Result::Mac0VerifyDetached(verified) =
        &mut success(codec_parity(Operation::Mac0VerifyDetached(Box::new(
            request.clone(),
        )))?)
    else {
        return Err(CoseError::InvalidFormat);
    };
    assert_eq!(verified.protected_headers, native.protected_header_bytes());
    request.allowed_algorithms = vec![wire::CoseMacAlgorithm::Hmac256256.into(); 33].into();
    let allowed = vec![crate::CoseMacAlgorithm::Hmac256_256; 33];
    let expected = wire::CoseErrorReason::CommonResourceLimitExceeded;
    assert_eq!(
        failure(crate::cose_verify_mac0_detached(
            crate::CoseMac0VerifyRequest {
                encoded: &request.encoded,
                detached_payload: &request.detached_payload,
                external_aad: &request.external_aad,
                allowed_algorithms: &allowed,
                limits: Default::default(),
            },
            &key
        ))?,
        expected
    );
    assert_eq!(
        reason(&codec_parity(Operation::Mac0VerifyDetached(Box::new(
            request
        )))?),
        expected
    );
    Ok(())
}
