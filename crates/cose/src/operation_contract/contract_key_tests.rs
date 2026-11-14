// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::support::{codec_parity, field, hex, keys, reason, request, success};
use crate::api::contract::{
    __buffa::oneof::{cose_operation_request::Operation, cose_operation_result::Result as Branch},
    CoseAgreementEc2EncodingPolicy as EncodingPolicy, CoseAgreementKeyCreateRequest,
    CoseAgreementKeyParseRequest, CoseAgreementKeyPolicy, CoseAgreementOptionalParameters,
    CoseErrorReason, CoseNamedCurve as CoseAgreementCurve, CosePeerKeyPurpose, CosePeerKeyRequest,
    CosePointEncoding,
};
use crate::containers::{
    AgreementEc2EncodingPolicy, AgreementKey, AgreementKeyPolicy, CryptoAgreementKeyProvider,
    OptionalKeyPolicy, PeerCurve,
};
use crate::CoseError;
use buffa::EnumValue;

fn policy(
    curve: EnumValue<CoseAgreementCurve>,
    encoding: EncodingPolicy,
) -> CoseAgreementKeyPolicy {
    CoseAgreementKeyPolicy {
        allowed_curves: vec![curve].into(),
        optional_parameters: CoseAgreementOptionalParameters::ValidateCose.into(),
        ec2_encoding: encoding.into(),
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn agreement_contract_preserves_unsorted_wire_bytes_and_normalized_points() -> Result<(), CoseError>
{
    for case in keys()?.into_iter().filter(|c| matches!(c.curve, 1..=4)) {
        let curve =
            EnumValue::from(i32::try_from(case.curve).map_err(|_| CoseError::InvalidFormat)?);
        let encoding = if case.curve == 4 {
            CosePointEncoding::Okp
        } else {
            CosePointEncoding::Ec2Coordinates
        };
        let create = CoseAgreementKeyCreateRequest {
            curve,
            public_key: hex(&case.public).into(),
            point_encoding: encoding.into(),
            policy: field(policy(curve, EncodingPolicy::FullCoordinatesOnly)),
            capability: super::support::capability(
                0,
                crate::api::contract::CoseProviderKind::AgreementKeyNormalizer,
            ),
        };
        let Branch::AgreementKeyCreate(constructed) = &mut success(codec_parity(
            Operation::AgreementKeyCreate(Box::new(create)),
        )?) else {
            return Err(CoseError::InvalidFormat);
        };
        let raw = hex(&case.key);
        let Branch::AgreementKeyParse(parsed) = &mut success(codec_parity(
            Operation::AgreementKeyParse(Box::new(CoseAgreementKeyParseRequest {
                cose_key: raw.clone().into(),
                policy: field(policy(curve, EncodingPolicy::FullCoordinatesOnly)),
                capability: super::support::capability(
                    0,
                    crate::api::contract::CoseProviderKind::AgreementKeyNormalizer,
                ),
            })),
        )?) else {
            return Err(CoseError::InvalidFormat);
        };
        assert_eq!(parsed.cose_key, raw);
        assert_eq!(parsed.public_key, constructed.public_key);
        assert_eq!(parsed.public_key, hex(&case.public));
        let selected =
            PeerCurve::from_identifier(case.curve).map_err(|_| CoseError::UnsupportedAlgorithm)?;
        let native = AgreementKey::from_slice(
            &raw,
            AgreementKeyPolicy {
                allowed_curves: &[selected],
                optional_parameters: OptionalKeyPolicy::Cose,
                ec2_encoding: AgreementEc2EncodingPolicy::FullCoordinatesOnly,
            },
            &CryptoAgreementKeyProvider,
        )
        .map_err(|_| CoseError::InvalidKeyMaterial)?;
        assert_eq!(parsed.cose_key, native.original_cose_key());
        assert_eq!(parsed.public_key, native.public_material());
        if !case.compressed.is_empty() {
            let mut input = CoseAgreementKeyParseRequest {
                cose_key: hex(&case.compressed).into(),
                policy: field(policy(curve, EncodingPolicy::FullCoordinatesOnly)),
                capability: super::support::capability(
                    0,
                    crate::api::contract::CoseProviderKind::AgreementKeyNormalizer,
                ),
            };
            assert_eq!(
                reason(&codec_parity(Operation::AgreementKeyParse(Box::new(
                    input.clone()
                )))?),
                CoseErrorReason::ContainerProfile
            );
            input.policy = field(policy(curve, EncodingPolicy::FullOrCompressed));
            let Branch::AgreementKeyParse(parsed) =
                &mut success(codec_parity(Operation::AgreementKeyParse(Box::new(input)))?)
            else {
                return Err(CoseError::InvalidFormat);
            };
            assert_eq!(
                parsed.point_encoding.as_known(),
                Some(CosePointEncoding::Ec2YSign)
            );
            assert_eq!(parsed.public_key, native.public_material());
        }
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn agreement_wire_contract_rejects_duplicate_private_and_implicit_policy() -> Result<(), CoseError>
{
    let fixture = keys()?
        .into_iter()
        .find(|c| c.curve == 1)
        .ok_or(CoseError::InvalidFormat)?;
    let base: ciborium::value::Value =
        ciborium::de::from_reader(hex(&fixture.key).as_slice()).map_err(|_| CoseError::Cbor)?;
    let ciborium::value::Value::Map(base) = base else {
        return Err(CoseError::InvalidFormat);
    };
    for (label, expected) in [
        (1, CoseErrorReason::CommonDuplicateMapLabel),
        (-4, CoseErrorReason::KeyInvalidKeyMaterial),
    ] {
        let mut params = base.clone();
        params.push((
            ciborium::value::Value::Integer(label.into()),
            ciborium::value::Value::Bytes(vec![0x42; 32]),
        ));
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&ciborium::value::Value::Map(params), &mut encoded)
            .map_err(|_| CoseError::Cbor)?;
        let input = CoseAgreementKeyParseRequest {
            cose_key: encoded.into(),
            policy: field(policy(
                CoseAgreementCurve::P256.into(),
                EncodingPolicy::FullCoordinatesOnly,
            )),
            capability: super::support::capability(
                0,
                crate::api::contract::CoseProviderKind::AgreementKeyNormalizer,
            ),
        };
        assert_eq!(
            reason(&codec_parity(Operation::AgreementKeyParse(Box::new(
                input
            )))?),
            expected
        );
    }
    let missing = crate::api::execute(request(Operation::AgreementKeyParse(Box::default())));
    assert_eq!(reason(&missing), CoseErrorReason::ContainerProfile);
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn peer_inspection_never_claims_validation_and_all_registered_providers_fail_closed(
) -> Result<(), CoseError> {
    for case in keys()? {
        let signing = matches!(case.curve, 6 | 7);
        let input = CosePeerKeyRequest {
            cose_key: hex(&case.key).into(),
            purpose: if signing {
                CosePeerKeyPurpose::Signature
            } else {
                CosePeerKeyPurpose::Agreement
            }
            .into(),
            signature_suite: if signing {
                field(super::support::suite(-8, case.curve)?)
            } else {
                Default::default()
            },
            optional_parameters: CoseAgreementOptionalParameters::ValidateCose.into(),
            capability: super::support::capability(
                0,
                crate::api::contract::CoseProviderKind::PeerKeyValidator,
            ),
        };
        let Branch::PeerKeyInspect(inspected) = &mut success(codec_parity(
            Operation::PeerKeyInspect(Box::new(input.clone())),
        )?) else {
            return Err(CoseError::InvalidFormat);
        };
        assert!(!inspected.validated);
        assert_eq!(inspected.cose_key, hex(&case.key));
        assert_eq!(inspected.public_key, hex(&case.public));
        let response = codec_parity(Operation::PeerKeyValidate(Box::new(input)))?;
        if matches!(case.curve, 1..=4 | 6) {
            let Branch::PeerKeyValidate(validated) = &mut success(response) else {
                return Err(CoseError::InvalidFormat);
            };
            assert!(validated.validated);
            assert_eq!(validated.cose_key, inspected.cose_key);
        } else {
            assert_eq!(reason(&response), CoseErrorReason::ProviderUnavailable);
        }
    }
    Ok(())
}
