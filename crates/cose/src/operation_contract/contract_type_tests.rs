// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::support::{reason, request, success};
use crate::api::{self, contract as wire};
use crate::{generated_contract as native, CoseError};
use buffa::{EnumValue, Enumeration, Message};
use wire::{cose_operation_request::Operation, cose_operation_result::Result as Branch};

fn closed<T, W>(values: &[T])
where
    T: Copy + Eq + core::fmt::Debug + TryFrom<EnumValue<W>, Error = CoseError>,
    W: Enumeration + From<T>,
{
    for value in values {
        assert_eq!(T::try_from(W::from(*value).into()), Ok(*value));
    }
    for number in [0, i32::MIN, i32::MAX] {
        assert_eq!(
            T::try_from(EnumValue::<W>::from(number))
                .err()
                .map(CoseError::reason),
            Some(wire::CoseErrorReason::CommonInvalidParameter)
        );
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn every_generated_closed_selector_roundtrips_and_rejects_unknown_or_unspecified() {
    closed::<native::CoseSignatureAlgorithm, wire::CoseSignatureAlgorithm>(
        native::CoseSignatureAlgorithm::ALL,
    );
    closed::<native::CoseCurve, wire::CoseNamedCurve>(native::CoseCurve::ALL);
    closed::<native::CosePointEncoding, wire::CosePointEncoding>(native::CosePointEncoding::ALL);
    closed::<native::CoseMacAlgorithm, wire::CoseMacAlgorithm>(native::CoseMacAlgorithm::ALL);
    closed::<native::Iso18013EcdsaHash, wire::CoseHashAlgorithm>(native::Iso18013EcdsaHash::ALL);
    closed::<native::OptionalKeyPolicy, wire::CoseAgreementOptionalParameters>(
        native::OptionalKeyPolicy::ALL,
    );
    closed::<native::AgreementEc2EncodingPolicy, wire::CoseAgreementEc2EncodingPolicy>(
        native::AgreementEc2EncodingPolicy::ALL,
    );
    closed::<native::ContainerProfile, wire::CoseContainerProfile>(native::ContainerProfile::ALL);
    closed::<native::ContainerPurpose, wire::CoseContainerPurpose>(native::ContainerPurpose::ALL);
    closed::<native::EnvelopePolicy, wire::CoseEnvelopePolicy>(native::EnvelopePolicy::ALL);
    closed::<native::SignatureEncoding, wire::CoseSignatureEncoding>(
        native::SignatureEncoding::ALL,
    );
    closed::<native::EndEntityIntegrity, wire::CoseEndEntityIntegrity>(
        native::EndEntityIntegrity::ALL,
    );
    closed::<native::X5ChainHeaderPlacement, wire::CoseX5ChainHeaderPlacement>(
        native::X5ChainHeaderPlacement::ALL,
    );
    closed::<native::CoseMlKemAlgorithm, wire::CoseKemAlgorithm>(native::CoseMlKemAlgorithm::ALL);
    closed::<native::CoseMlKemMode, wire::CoseMlKemMode>(native::CoseMlKemMode::ALL);
    closed::<native::CoseMlKemProfile, wire::CoseMlKemProfile>(native::CoseMlKemProfile::ALL);
    closed::<native::CoseContentEncryptionAlgorithm, wire::CoseContentEncryptionAlgorithm>(
        native::CoseContentEncryptionAlgorithm::ALL,
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn original_and_modern_signature_registrations_keep_independent_wire_identities(
) -> Result<(), CoseError> {
    use native::{CoseSignatureAlgorithm as A, Iso18013EcdsaHash as H};
    let cases = [
        (-7, A::Es256, Some(H::Sha256)),
        (-35, A::Es384, Some(H::Sha384)),
        (-36, A::Es512, Some(H::Sha512)),
        (-8, A::EdDsa, None),
        (-9, A::Esp256, Some(H::Sha256)),
        (-51, A::Esp384, Some(H::Sha384)),
        (-52, A::Esp512, Some(H::Sha512)),
        (-19, A::Ed25519, None),
        (-47, A::Es256K, Some(H::Sha256)),
        (-48, A::MlDsa44, None),
        (-49, A::MlDsa65, None),
        (-50, A::MlDsa87, None),
    ];
    for (identifier, algorithm, hash) in cases {
        assert_eq!(A::from_identifier(identifier)?, algorithm);
        assert_eq!(algorithm.identifier(), identifier);
        assert_eq!(algorithm.ecdsa_hash(), hash);
        assert!(wire::CoseSignatureAlgorithm::from(algorithm).to_i32() > 0);
    }
    assert_ne!(A::Es256, A::Esp256);
    assert_ne!(A::Es384, A::Esp384);
    assert_ne!(A::EdDsa, A::Ed25519);
    for algorithm in [A::Esp256, A::Esp384, A::Esp512, A::Ed25519] {
        assert!(native::SignatureSuite::modern(algorithm)?.has_builtin_provider());
    }
    assert_eq!(
        native::CosePointEncoding::try_from(EnumValue::from(
            wire::CoseEc2PointEncoding::Compressed
        ))?,
        native::CosePointEncoding::Ec2YSign
    );
    assert_eq!(
        native::CosePointEncoding::try_from(EnumValue::from(
            wire::CoseEc2PointEncoding::FullCoordinates
        ))?,
        native::CosePointEncoding::Ec2Coordinates
    );
    assert_eq!(native::CoseCurve::Ed448.signature_length()?, 114);
    assert_eq!(
        native::CoseCurve::X448.signature_length(),
        Err(CoseError::UnsupportedAlgorithm)
    );
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn one_generated_reason_is_retained_by_all_native_error_names_and_correct_branches() {
    let mac: crate::CoseMac0ErrorReason = wire::CoseErrorReason::CommonCbor;
    let container: crate::containers::ContainerErrorReason = mac;
    assert_eq!(container, wire::CoseErrorReason::CommonCbor);
    let native: crate::CoseSignerError = CoseError::ProviderUnavailable;
    assert_eq!(native.reason(), wire::CoseErrorReason::ProviderUnavailable);
    for reason in wire::CoseErrorReason::values() {
        let owner = CoseError::from(*reason);
        let actual = if *reason == wire::CoseErrorReason::Unspecified {
            wire::CoseErrorReason::BackendInternal
        } else {
            *reason
        };
        assert_eq!(owner.reason(), actual);
        let encoded =
            crate::wire::cose_error(crate::wire::CoseWireError::from_reason(owner.reason()));
        assert!(crate::wire::validate_cose_error_proto_wire(&encoded).is_ok());
        match encoded.error.as_ref() {
            Some(wire::cose_error::Error::Provider(_)) => {
                assert!((200..300).contains(&actual.to_i32()))
            }
            Some(wire::cose_error::Error::Backend(_)) => {
                assert!((300..400).contains(&actual.to_i32()))
            }
            Some(wire::cose_error::Error::Primitive(_)) => {
                assert!(!(200..400).contains(&actual.to_i32()))
            }
            None => assert_eq!(actual, wire::CoseErrorReason::Unspecified),
        }
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn payload_mode_conversion_is_total_and_protected_owners_have_drop_contracts(
) -> Result<(), CoseError> {
    fn protected<T: zeroize::ZeroizeOnDrop>() {}
    protected::<wire::CoseError>();
    protected::<wire::CosePrimitiveError>();
    protected::<wire::CoseProviderCallRequest>();
    protected::<wire::CoseProviderCallResponse>();
    protected::<wire::CoseProviderDescription>();
    protected::<wire::CoseProviderSignerDescription>();
    protected::<wire::CoseWorkingKey>();
    let mut value = wire::CoseProviderSignerDescription::default();
    assert_eq!(
        native::SigningMode::try_from(&value)
            .err()
            .map(CoseError::reason),
        Some(wire::CoseErrorReason::ContainerSigningInput)
    );
    value.signing_mode = wire::CoseSigningMode::Message.into();
    assert_eq!(
        native::SigningMode::try_from(&value)?,
        native::SigningMode::Message
    );
    for hash in native::Iso18013EcdsaHash::ALL {
        value.signing_mode = wire::CoseSigningMode::EcdsaPrehash.into();
        value.prehash = wire::CoseHashAlgorithm::from(*hash).into();
        assert_eq!(
            native::SigningMode::try_from(&value)?,
            native::SigningMode::EcdsaPrehash(*hash)
        );
        value.signing_mode = wire::CoseSigningMode::Message.into();
        assert!(native::SigningMode::try_from(&value).is_err());
    }
    value.signing_mode = EnumValue::from(999);
    assert!(native::SigningMode::try_from(&value).is_err());
    let limits = native::ContainerLimits::try_from(&wire::CoseByteLimits::default())?;
    assert_eq!(limits.encoded_bytes, 0);
    assert_eq!(limits.payload_bytes, 0);
    assert_eq!(limits.external_aad_bytes, 0);
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn contract_constant_catalog_is_generated_and_result_validation_rejects_tampering(
) -> Result<(), CoseError> {
    let input = request(Operation::ContractInfo(Box::default()));
    let response = api::execute(input.clone());
    let Branch::ContractInfo(value) = &mut success(response.clone()) else {
        return Err(CoseError::InvalidFormat);
    };
    assert!(value.constants.iter().any(|entry| entry.constant
        == wire::CoseImplementationConstant::ReallymeCoseAlgMlKem512
        && entry.value == crate::REALLYME_COSE_ALG_ML_KEM_512));
    assert!(
        crate::wire::decode_operation_response_for_request(&input, &response.encode_to_vec())
            .is_ok()
    );
    let altered = value;
    altered
        .constants
        .get_mut(0)
        .ok_or(CoseError::InvalidFormat)?
        .value = 0;
    let response = super::support::result(Branch::ContractInfo(core::mem::take(altered)));
    let outer = wire::CoseOperationResponseV2 {
        outcome: Some(wire::cose_operation_response_v2::Outcome::Result(Box::new(
            response,
        ))),
    };
    let failure = crate::wire::decode_operation_response(&outer.encode_to_vec())
        .err()
        .ok_or(CoseError::InvalidFormat)?;
    assert_eq!(reason(&failure), wire::CoseErrorReason::BackendInternal);
    Ok(())
}
