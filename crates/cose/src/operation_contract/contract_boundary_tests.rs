// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
// SPDX-License-Identifier: MIT OR Apache-2.0
use super::support::{codec_parity, reason, request, result};
use crate::api::contract::{
    self,
    __buffa::oneof::{
        cose_operation_request::Operation, cose_operation_response_v2::Outcome,
        cose_operation_result::Result as Branch,
    },
    CoseAgreementKeyParseRequest, CoseErrorReason, CoseOpaqueBytes, CoseOperationResponseV2,
};
use crate::CoseError;
use buffa::Message;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn every_schema_operation_has_an_executable_fixed_error_and_frozen_field_number(
) -> Result<(), CoseError> {
    let operations = [
        (
            Operation::SignCreate(Box::<contract::CoseSignCreateRequest>::default()),
            1020u64,
        ),
        (
            Operation::SignVerify(Box::<contract::CoseSignVerifyRequest>::default()),
            1021u64,
        ),
        (
            Operation::Sign1Create(Box::<contract::CoseSign1CreateRequest>::default()),
            1000u64,
        ),
        (
            Operation::Sign1CreateDetached(
                Box::<contract::CoseSign1CreateDetachedRequest>::default(),
            ),
            1001u64,
        ),
        (
            Operation::Sign1Verify(Box::<contract::CoseSign1VerifyRequest>::default()),
            1002u64,
        ),
        (
            Operation::Sign1VerifyDetached(
                Box::<contract::CoseSign1VerifyDetachedRequest>::default(),
            ),
            1003u64,
        ),
        (
            Operation::IsoSign1Verify(Box::<contract::CoseIsoSign1VerifyRequest>::default()),
            1004u64,
        ),
        (
            Operation::ContainerVerify(Box::<contract::CoseContainerVerifyRequest>::default()),
            1005u64,
        ),
        (
            Operation::ContainerSign(Box::<contract::CoseContainerSignRequest>::default()),
            1006u64,
        ),
        (
            Operation::SignatureToCose(Box::<contract::CoseSignatureConvertRequest>::default()),
            1010u64,
        ),
        (
            Operation::SignatureToDer(Box::<contract::CoseSignatureConvertRequest>::default()),
            1011u64,
        ),
        (
            Operation::SignatureValidate(Box::<contract::CoseSignatureConvertRequest>::default()),
            1012u64,
        ),
        (
            Operation::SignatureSuiteInfo(Box::<contract::CoseSuiteInfoRequest>::default()),
            1013u64,
        ),
        (
            Operation::Sign1CreateProfile(Box::<contract::CoseSign1CreateProfileRequest>::default()),
            1014u64,
        ),
        (
            Operation::Sign1CreateDetachedProfile(
                Box::<contract::CoseSign1CreateProfileRequest>::default(),
            ),
            1015u64,
        ),
        (
            Operation::Sign1VerifyProfile(Box::<contract::CoseSign1VerifyProfileRequest>::default()),
            1016u64,
        ),
        (
            Operation::Sign1VerifyX5chain(Box::<contract::CoseSign1VerifyProfileRequest>::default()),
            1017u64,
        ),
        (
            Operation::Sign1SignatureStructure(
                Box::<contract::CoseSign1SignatureStructureRequest>::default(),
            ),
            1018u64,
        ),
        (
            Operation::KeyFromPublicBytes(Box::<contract::CoseKeyFromPublicBytesRequest>::default()),
            2000u64,
        ),
        (
            Operation::KeyFromPrivateBytes(
                Box::<contract::CoseKeyFromPrivateBytesRequest>::default(),
            ),
            2001u64,
        ),
        (
            Operation::KeyParse(Box::<contract::CoseKeyBytesRequest>::default()),
            2002u64,
        ),
        (
            Operation::KeyToPublicVec(Box::<contract::CoseKeyBytesRequest>::default()),
            2013u64,
        ),
        (
            Operation::KeySetParse(Box::<contract::CoseKeySetParseRequest>::default()),
            2014u64,
        ),
        (
            Operation::KeySetCreate(Box::<contract::CoseKeySetCreateRequest>::default()),
            2015u64,
        ),
        (
            Operation::KeyToPublicBytes(Box::<contract::CoseKeyBytesRequest>::default()),
            2003u64,
        ),
        (
            Operation::KeyToPrivateBytes(Box::<contract::CoseKeyBytesRequest>::default()),
            2004u64,
        ),
        (
            Operation::KeyDerivePublicKid(Box::<contract::CoseKeyBytesRequest>::default()),
            2005u64,
        ),
        (
            Operation::KeyToMultikey(Box::<contract::CoseKeyBytesRequest>::default()),
            2006u64,
        ),
        (
            Operation::MultikeyToCoseKey(Box::<contract::CoseMultikeyToCoseKeyRequest>::default()),
            2007u64,
        ),
        (
            Operation::AgreementKeyCreate(Box::<contract::CoseAgreementKeyCreateRequest>::default()),
            2008u64,
        ),
        (
            Operation::AgreementKeyParse(Box::<contract::CoseAgreementKeyParseRequest>::default()),
            2009u64,
        ),
        (
            Operation::PeerKeyInspect(Box::<contract::CosePeerKeyRequest>::default()),
            2010u64,
        ),
        (
            Operation::PeerKeyValidate(Box::<contract::CosePeerKeyRequest>::default()),
            2011u64,
        ),
        (
            Operation::VerificationKeyImport(
                Box::<contract::CoseVerificationKeyImportRequest>::default(),
            ),
            2012u64,
        ),
        (
            Operation::MlKemEncryptDirect(Box::<contract::CoseMlKemEncryptRequest>::default()),
            3000u64,
        ),
        (
            Operation::MlKemEncryptKeyWrap(Box::<contract::CoseMlKemEncryptRequest>::default()),
            3001u64,
        ),
        (
            Operation::MlKemDecrypt(Box::<contract::CoseMlKemDecryptRequest>::default()),
            3002u64,
        ),
        (
            Operation::Mac0VerifyDetached(Box::<contract::CoseMac0VerifyRequest>::default()),
            4000u64,
        ),
        (
            Operation::PreferredCborValidate(Box::<contract::CoseOpaqueBytes>::default()),
            5000u64,
        ),
    ];
    assert_eq!(operations.len(), 39);
    for (operation, expected) in operations {
        let encoded = request(operation.clone()).encode_to_vec();
        let (mut tag, mut shift) = (0u64, 0u32);
        for byte in encoded {
            tag |= u64::from(byte & 0x7f)
                .checked_shl(shift)
                .ok_or(CoseError::InvalidFormat)?;
            if byte & 0x80 == 0 {
                break;
            }
            shift = shift.checked_add(7).ok_or(CoseError::InvalidFormat)?;
        }
        assert_eq!(tag >> 3, expected);
        let response = codec_parity(operation)?;
        assert_ne!(reason(&response), CoseErrorReason::Unspecified);
    }
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn preferred_cbor_contract_accepts_unique_unsorted_maps_and_rejects_duplicates(
) -> Result<(), CoseError> {
    let valid = CoseOpaqueBytes {
        encoded: vec![0xa2, 2, 0, 1, 0].into(),
    };
    assert!(matches!(
        super::support::success(codec_parity(Operation::PreferredCborValidate(Box::new(
            valid
        )))?),
        Branch::PreferredCborValidate(_)
    ));
    let duplicate = CoseOpaqueBytes {
        encoded: vec![0xa2, 1, 0, 1, 0].into(),
    };
    assert_eq!(
        reason(&codec_parity(Operation::PreferredCborValidate(Box::new(
            duplicate
        )))?),
        CoseErrorReason::CommonDuplicateMapLabel
    );
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn guarded_wire_admission_rejects_nested_unknown_fields_without_storage() -> Result<(), CoseError> {
    // AgreementKeyParse (2009), with an unknown length-delimited field in
    // its nested policy. Construct the original bytes: a default decoder that
    // discards unknowns cannot reconstruct this evidence from a typed message.
    let wire = [0xca, 0x7d, 8, 0x12, 6, 0xd2, 5, 3, 1, 2, 3];
    let decoded = crate::wire::decode_protobuf::<crate::api::contract::CoseOperationRequest>(&wire);
    assert!(decoded.is_err());
    let binary = crate::wire::execute_operation_proto(&wire);
    let response =
        crate::wire::decode_operation_response(&binary).map_err(|_| CoseError::InvalidFormat)?;
    assert_eq!(reason(&response), CoseErrorReason::CommonMalformedProtobuf);
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn request_resource_limits_and_invalid_response_metadata_fail_without_partial_results(
) -> Result<(), CoseError> {
    let large = CoseOpaqueBytes {
        encoded: vec![
            0;
            crate::wire::MAX_COSE_PROTO_MESSAGE_BYTES
                .checked_add(1)
                .ok_or(CoseError::ResourceLimitExceeded)?
        ]
        .into(),
    };
    assert_eq!(
        reason(&codec_parity(Operation::PreferredCborValidate(Box::new(
            large
        )))?),
        CoseErrorReason::CommonResourceLimitExceeded
    );
    let malformed = CoseOperationResponseV2 {
        outcome: Some(Outcome::Result(Box::new(result(Branch::ContainerSign(
            Box::default(),
        ))))),
    };
    let failure = crate::wire::decode_operation_response(&malformed.encode_to_vec())
        .err()
        .ok_or(CoseError::InvalidFormat)?;
    assert_eq!(reason(&failure), CoseErrorReason::BackendInternal);
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn generated_owners_redact_handles_and_keep_clone_and_clear_ownership_separate(
) -> Result<(), CoseError> {
    let mut value = CoseAgreementKeyParseRequest {
        cose_key: vec![0x42; 32].into(),
        policy: Default::default(),
        capability: super::support::capability(
            12345,
            crate::api::contract::CoseProviderKind::AgreementKeyNormalizer,
        ),
    };
    assert!(core::mem::needs_drop::<CoseAgreementKeyParseRequest>());
    let cloned = value.clone();
    let debug = format!("{value:?}");
    assert!(!debug.contains("12345"));
    assert!(!debug.contains("66, 66"));
    value.clear();
    assert!(value.cose_key.is_empty());
    assert!(value.capability.as_option().is_none());
    assert_eq!(cloned.cose_key, [0x42; 32]);
    let error =
        serde_json::from_str::<contract::CoseX5Chain>(r#"{"certificatesDer":["AQID","%%%"]}"#)
            .err()
            .ok_or(CoseError::InvalidFormat)?;
    assert!(!error.to_string().contains("AQID"));
    assert!(!error.to_string().contains("%%%"));
    Ok(())
}
