// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Wire-identifier freeze tests for the public COSE 0.2.0 protobuf contract.

#![cfg(feature = "generated")]
#![allow(clippy::panic)]

use buffa::{EnumValue, Message};
use reallyme_cose_proto::generated::proto::reallyme::cose::v1::{
    __buffa::oneof::{
        cose_algorithm_identifier, cose_operation_request, cose_operation_response_v2,
        cose_operation_result,
    },
    CoseAlgorithmIdentifier, CoseContentEncryptionAlgorithm, CoseErrorReason, CoseKemAlgorithm,
    CoseKeyAgreementAlgorithm, CoseKeyBytesRequest, CoseKeyBytesResult,
    CoseKeyFromPrivateBytesRequest, CoseKeyFromPublicBytesRequest, CoseMlKemDecryptRequest,
    CoseMlKemDecryptResult, CoseMlKemEncryptRequest, CoseMlKemEncryptResult, CoseMlKemMode,
    CoseMultikeyResult, CoseMultikeyToCoseKeyRequest, CoseOperationRequest,
    CoseOperationResponseV2, CoseOperationResult, CoseSign1CreateDetachedRequest,
    CoseSign1CreateRequest, CoseSign1CreateResult, CoseSign1VerifyDetachedRequest,
    CoseSign1VerifyRequest, CoseSign1VerifyResult, CoseSignatureAlgorithm,
};

type Operation = cose_operation_request::Operation;
type OperationResult = cose_operation_result::Result;

#[test]
fn operation_oneof_field_numbers_are_frozen() {
    for (operation, field_number) in [
        (
            Operation::Sign1Create(Box::<CoseSign1CreateRequest>::default()),
            1000,
        ),
        (
            Operation::Sign1CreateDetached(Box::<CoseSign1CreateDetachedRequest>::default()),
            1001,
        ),
        (
            Operation::Sign1Verify(Box::<CoseSign1VerifyRequest>::default()),
            1002,
        ),
        (
            Operation::Sign1VerifyDetached(Box::<CoseSign1VerifyDetachedRequest>::default()),
            1003,
        ),
        (
            Operation::KeyFromPublicBytes(Box::<CoseKeyFromPublicBytesRequest>::default()),
            2000,
        ),
        (
            Operation::KeyFromPrivateBytes(Box::<CoseKeyFromPrivateBytesRequest>::default()),
            2001,
        ),
        (
            Operation::KeyParse(Box::<CoseKeyBytesRequest>::default()),
            2002,
        ),
        (
            Operation::KeyToPublicBytes(Box::<CoseKeyBytesRequest>::default()),
            2003,
        ),
        (
            Operation::KeyToPrivateBytes(Box::<CoseKeyBytesRequest>::default()),
            2004,
        ),
        (
            Operation::KeyDerivePublicKid(Box::<CoseKeyBytesRequest>::default()),
            2005,
        ),
        (
            Operation::KeyToMultikey(Box::<CoseKeyBytesRequest>::default()),
            2006,
        ),
        (
            Operation::MultikeyToCoseKey(Box::<CoseMultikeyToCoseKeyRequest>::default()),
            2007,
        ),
        (
            Operation::MlKemEncryptDirect(Box::<CoseMlKemEncryptRequest>::default()),
            3000,
        ),
        (
            Operation::MlKemEncryptKeyWrap(Box::<CoseMlKemEncryptRequest>::default()),
            3001,
        ),
        (
            Operation::MlKemDecrypt(Box::<CoseMlKemDecryptRequest>::default()),
            3002,
        ),
    ] {
        assert_operation_field_number(operation, field_number);
    }
}

#[test]
fn version_two_response_field_numbers_are_frozen() {
    for (result, field_number) in [
        (
            OperationResult::Sign1Create(Box::<CoseSign1CreateResult>::default()),
            1000,
        ),
        (
            OperationResult::Sign1CreateDetached(Box::<CoseSign1CreateResult>::default()),
            1001,
        ),
        (
            OperationResult::Sign1Verify(Box::<CoseSign1VerifyResult>::default()),
            1002,
        ),
        (
            OperationResult::Sign1VerifyDetached(Box::<CoseSign1VerifyResult>::default()),
            1003,
        ),
        (
            OperationResult::KeyFromPublicBytes(Box::<CoseKeyBytesResult>::default()),
            2000,
        ),
        (
            OperationResult::KeyFromPrivateBytes(Box::<CoseKeyBytesResult>::default()),
            2001,
        ),
        (
            OperationResult::KeyParse(Box::<CoseKeyBytesResult>::default()),
            2002,
        ),
        (
            OperationResult::KeyToPublicBytes(Box::<CoseKeyBytesResult>::default()),
            2003,
        ),
        (
            OperationResult::KeyToPrivateBytes(Box::<CoseKeyBytesResult>::default()),
            2004,
        ),
        (
            OperationResult::KeyDerivePublicKid(Box::<CoseKeyBytesResult>::default()),
            2005,
        ),
        (
            OperationResult::KeyToMultikey(Box::<CoseMultikeyResult>::default()),
            2006,
        ),
        (
            OperationResult::MultikeyToCoseKey(Box::<CoseKeyBytesResult>::default()),
            2007,
        ),
        (
            OperationResult::MlKemEncryptDirect(Box::<CoseMlKemEncryptResult>::default()),
            3000,
        ),
        (
            OperationResult::MlKemEncryptKeyWrap(Box::<CoseMlKemEncryptResult>::default()),
            3001,
        ),
        (
            OperationResult::MlKemDecrypt(Box::<CoseMlKemDecryptResult>::default()),
            3002,
        ),
    ] {
        assert_result_field_number(result, field_number);
    }

    let result_response = CoseOperationResponseV2 {
        outcome: Some(cose_operation_response_v2::Outcome::Result(Box::default())),
        __buffa_unknown_fields: Default::default(),
    };
    assert_eq!(result_response.encode_to_vec(), [0x0a, 0x00]);

    let error_response = CoseOperationResponseV2 {
        outcome: Some(cose_operation_response_v2::Outcome::Error(Box::default())),
        __buffa_unknown_fields: Default::default(),
    };
    assert_eq!(error_response.encode_to_vec(), [0x12, 0x00]);
    assert_eq!(
        CoseOperationResponseV2::TYPE_URL,
        "type.googleapis.com/reallyme.cose.v1.CoseOperationResponseV2"
    );
}

#[test]
fn algorithm_identifier_oneof_field_numbers_are_frozen() {
    let signature = CoseAlgorithmIdentifier {
        algorithm: Some(cose_algorithm_identifier::Algorithm::Signature(
            EnumValue::from(CoseSignatureAlgorithm::Ed25519),
        )),
        __buffa_unknown_fields: Default::default(),
    };
    assert_eq!(signature.encode_to_vec(), [0x08, 0x64]);

    let key_agreement = CoseAlgorithmIdentifier {
        algorithm: Some(cose_algorithm_identifier::Algorithm::KeyAgreement(
            EnumValue::from(CoseKeyAgreementAlgorithm::X25519),
        )),
        __buffa_unknown_fields: Default::default(),
    };
    assert_eq!(key_agreement.encode_to_vec(), [0x10, 0x64]);

    let kem = CoseAlgorithmIdentifier {
        algorithm: Some(cose_algorithm_identifier::Algorithm::Kem(EnumValue::from(
            CoseKemAlgorithm::MlKem512,
        ))),
        __buffa_unknown_fields: Default::default(),
    };
    assert_eq!(kem.encode_to_vec(), [0x18, 0xe8, 0x07]);
}

#[test]
fn operation_request_type_name_is_frozen() {
    assert_eq!(
        CoseOperationRequest::TYPE_URL,
        "type.googleapis.com/reallyme.cose.v1.CoseOperationRequest"
    );
}

#[test]
fn algorithm_and_mode_numbers_are_frozen() {
    for (actual, expected) in [
        (CoseSignatureAlgorithm::Unspecified as i32, 0),
        (CoseSignatureAlgorithm::Ed25519 as i32, 100),
        (CoseSignatureAlgorithm::EcdsaP256Sha256 as i32, 200),
        (CoseSignatureAlgorithm::EcdsaP384Sha384 as i32, 210),
        (CoseSignatureAlgorithm::EcdsaP521Sha512 as i32, 220),
        (CoseSignatureAlgorithm::EcdsaSecp256k1Sha256 as i32, 230),
        (CoseSignatureAlgorithm::MlDsa44 as i32, 1000),
        (CoseSignatureAlgorithm::MlDsa65 as i32, 1010),
        (CoseSignatureAlgorithm::MlDsa87 as i32, 1020),
        (CoseKeyAgreementAlgorithm::Unspecified as i32, 0),
        (CoseKeyAgreementAlgorithm::X25519 as i32, 100),
        (CoseKemAlgorithm::Unspecified as i32, 0),
        (CoseKemAlgorithm::MlKem512 as i32, 1000),
        (CoseKemAlgorithm::MlKem768 as i32, 1010),
        (CoseKemAlgorithm::MlKem1024 as i32, 1020),
        (CoseKemAlgorithm::XWing768 as i32, 1100),
        (CoseContentEncryptionAlgorithm::Unspecified as i32, 0),
        (CoseContentEncryptionAlgorithm::Aes128Gcm as i32, 100),
        (CoseContentEncryptionAlgorithm::Aes192Gcm as i32, 110),
        (CoseContentEncryptionAlgorithm::Aes256Gcm as i32, 120),
        (CoseMlKemMode::Unspecified as i32, 0),
        (CoseMlKemMode::Direct as i32, 1),
        (CoseMlKemMode::KeyWrap as i32, 2),
    ] {
        assert_eq!(actual, expected);
    }
}

#[test]
fn error_reason_numbers_are_frozen() {
    for (actual, expected) in [
        (CoseErrorReason::Unspecified as i32, 0),
        (CoseErrorReason::CommonCbor as i32, 100),
        (CoseErrorReason::CommonInvalidFormat as i32, 101),
        (CoseErrorReason::CommonResourceLimitExceeded as i32, 102),
        (CoseErrorReason::CommonNonCanonicalCbor as i32, 103),
        (CoseErrorReason::CommonUnexpectedCborTag as i32, 104),
        (CoseErrorReason::CommonDuplicateMapLabel as i32, 105),
        (CoseErrorReason::CommonMalformedProtobuf as i32, 120),
        (CoseErrorReason::CommonMalformedJson as i32, 121),
        (CoseErrorReason::CommonInvalidParameter as i32, 130),
        (CoseErrorReason::CommonInvalidLength as i32, 131),
        (CoseErrorReason::CommonInvalidEncoding as i32, 132),
        (CoseErrorReason::CommonUnsupportedAlgorithm as i32, 200),
        (CoseErrorReason::ProviderUnavailable as i32, 201),
        (CoseErrorReason::CommonCryptoFailed as i32, 300),
        (CoseErrorReason::BackendInternal as i32, 301),
        (CoseErrorReason::Sign1KidKeyMismatch as i32, 400),
        (CoseErrorReason::Sign1MissingPayload as i32, 401),
        (CoseErrorReason::Sign1MissingKid as i32, 402),
        (CoseErrorReason::Sign1KeyNotResolved as i32, 403),
        (CoseErrorReason::Sign1UnsupportedCriticalHeader as i32, 410),
        (
            CoseErrorReason::Sign1UnprotectedHeaderNotAllowed as i32,
            411,
        ),
        (CoseErrorReason::Sign1InvalidSignature as i32, 420),
        (CoseErrorReason::Sign1MissingPrivateKey as i32, 421),
        (CoseErrorReason::Sign1InvalidSignatureEncoding as i32, 422),
        (CoseErrorReason::KeyMissingKeyMaterial as i32, 500),
        (CoseErrorReason::KeyInvalidKeyMaterial as i32, 501),
        (CoseErrorReason::MultikeyInvalidMultikey as i32, 600),
        (CoseErrorReason::EncryptMissingCiphertext as i32, 700),
        (CoseErrorReason::EncryptInvalidIv as i32, 701),
        (CoseErrorReason::EncryptInvalidRecipient as i32, 702),
        (CoseErrorReason::EncryptMissingEncapsulatedKey as i32, 703),
        (CoseErrorReason::EncryptInvalidEncapsulatedKey as i32, 704),
        (CoseErrorReason::EncryptAuthenticationFailed as i32, 720),
        (CoseErrorReason::EncryptKeyUnwrapFailed as i32, 721),
        (CoseErrorReason::EncryptKidMismatch as i32, 730),
        (CoseErrorReason::EncryptMissingKid as i32, 731),
        (
            CoseErrorReason::EncryptUnprotectedHeaderNotAllowed as i32,
            740,
        ),
    ] {
        assert_eq!(actual, expected);
    }
}

fn assert_operation_field_number(operation: Operation, field_number: u32) {
    let request = CoseOperationRequest {
        operation: Some(operation),
        __buffa_unknown_fields: Default::default(),
    };
    let mut expected = protobuf_length_delimited_field_key(field_number);
    expected.push(0);
    assert_eq!(request.encode_to_vec(), expected);
}

fn assert_result_field_number(result: OperationResult, field_number: u32) {
    let result = CoseOperationResult {
        result: Some(result),
        __buffa_unknown_fields: Default::default(),
    };
    let mut expected = protobuf_length_delimited_field_key(field_number);
    expected.push(0);
    assert_eq!(result.encode_to_vec(), expected);
}

fn protobuf_length_delimited_field_key(field_number: u32) -> Vec<u8> {
    let shifted = match field_number.checked_shl(3) {
        Some(value) => value,
        None => panic!("protobuf field-number shift overflowed"),
    };
    let mut value = match shifted.checked_add(2) {
        Some(value) => value,
        None => panic!("protobuf field key overflowed"),
    };
    let mut encoded = Vec::new();

    loop {
        let low_bits = match u8::try_from(value & 0x7f) {
            Ok(value) => value,
            Err(_) => panic!("protobuf field key chunk did not fit in u8"),
        };
        value >>= 7;
        if value == 0 {
            encoded.push(low_bits);
            return encoded;
        }
        encoded.push(low_bits | 0x80);
    }
}
