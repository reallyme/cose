// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Contract tests for generated ReallyMe COSE protobuf messages.

#![cfg(feature = "generated")]
#![allow(clippy::panic)]

use buffa::{EnumValue, Message};
use reallyme_cose_proto::generated::proto::reallyme::cose::v1::{
    __buffa::oneof::{cose_algorithm_identifier, cose_error},
    CoseAlgorithmIdentifier, CoseContentEncryptionAlgorithm, CoseError, CoseErrorReason,
    CoseKemAlgorithm, CoseKeyAgreementAlgorithm, CoseKeyBytesRequest, CoseKeyBytesResult,
    CoseKeyBytesResultOwnedView, CoseKeyFromPrivateBytesRequest, CoseMlKemDecryptResult,
    CoseMlKemDecryptResultOwnedView, CoseMultikeyResult, CoseMultikeyToCoseKeyRequest,
    CoseMultikeyToCoseKeyRequestOwnedView, CoseOperationRequest, CoseOperationResponseV2,
    CoseOperationResult, CosePrimitiveError, CoseSign1CreateDetachedRequest,
    CoseSign1CreateRequest, CoseSign1CreateResult, CoseSign1Options,
    CoseSign1VerifyDetachedRequest, CoseSign1VerifyRequest, CoseSign1VerifyResult,
    CoseSignatureAlgorithm,
};

fn ed25519_identifier(
) -> buffa::MessageField<CoseAlgorithmIdentifier, buffa::Inline<CoseAlgorithmIdentifier>> {
    buffa::MessageField::some(CoseAlgorithmIdentifier {
        algorithm: Some(cose_algorithm_identifier::Algorithm::Signature(
            EnumValue::from(CoseSignatureAlgorithm::Ed25519),
        )),
        __buffa_unknown_fields: Default::default(),
    })
}

#[test]
fn family_scoped_algorithm_numbers_match_the_crypto_boundary() {
    assert_eq!(CoseSignatureAlgorithm::Ed25519 as i32, 100);
    assert_eq!(CoseSignatureAlgorithm::EcdsaP256Sha256 as i32, 200);
    assert_eq!(CoseSignatureAlgorithm::EcdsaP384Sha384 as i32, 210);
    assert_eq!(CoseSignatureAlgorithm::EcdsaP521Sha512 as i32, 220);
    assert_eq!(CoseSignatureAlgorithm::EcdsaSecp256k1Sha256 as i32, 230);
    assert_eq!(CoseSignatureAlgorithm::MlDsa44 as i32, 1000);
    assert_eq!(CoseSignatureAlgorithm::MlDsa65 as i32, 1010);
    assert_eq!(CoseSignatureAlgorithm::MlDsa87 as i32, 1020);
    assert_eq!(CoseKeyAgreementAlgorithm::X25519 as i32, 100);
    assert_eq!(CoseKemAlgorithm::MlKem512 as i32, 1000);
    assert_eq!(CoseKemAlgorithm::MlKem768 as i32, 1010);
    assert_eq!(CoseKemAlgorithm::MlKem1024 as i32, 1020);
    assert_eq!(CoseKemAlgorithm::XWing768 as i32, 1100);
    assert_eq!(CoseContentEncryptionAlgorithm::Aes128Gcm as i32, 100);
    assert_eq!(CoseContentEncryptionAlgorithm::Aes192Gcm as i32, 110);
    assert_eq!(CoseContentEncryptionAlgorithm::Aes256Gcm as i32, 120);
}

#[test]
fn top_level_operation_request_has_an_ordinary_drop_wipe_path() {
    // This deliberately checks the generated explicit `Drop` implementation,
    // not merely `needs_drop`, which would also be true because of the boxed
    // operation branch and would therefore miss removal of the wipe hook.
    #[allow(drop_bounds)]
    fn assert_drop_implementation<T: Drop>() {}

    // Unknown fields belong to the top-level message itself, so recursive leaf
    // hardening is insufficient. This compile-time assertion prevents the
    // postprocessor from silently dropping the ordinary-destruction hook.
    assert_drop_implementation::<CoseOperationRequest>();
}

#[test]
fn version_two_response_owners_have_ordinary_drop_wipe_paths() {
    #[allow(drop_bounds)]
    fn assert_drop_implementation<T: Drop>() {}

    // Both wrappers can retain length-delimited unknown fields in addition to
    // owning nested sensitive result messages. Their explicit Drop hooks are
    // therefore independently required.
    assert_drop_implementation::<CoseOperationResponseV2>();
    assert_drop_implementation::<CoseOperationResult>();
}

#[test]
fn cose_error_wire_contract_is_stable() {
    let error = CoseError {
        error: Some(cose_error::Error::Primitive(Box::new(CosePrimitiveError {
            reason: EnumValue::from(CoseErrorReason::COSE_ERROR_REASON_SIGN1_INVALID_SIGNATURE),
            __buffa_unknown_fields: Default::default(),
        }))),
        __buffa_unknown_fields: Default::default(),
    };

    assert_eq!(error.encode_to_vec(), [0x0a, 0x03, 0x08, 0xa4, 0x03]);
}

#[test]
fn key_bytes_result_uses_unambiguous_proto_json_and_view_accessors(
) -> Result<(), buffa::DecodeError> {
    let result = CoseKeyBytesResult {
        key_bytes: vec![241, 242, 243, 244],
        __buffa_unknown_fields: Default::default(),
    };

    let json = serde_json::to_string(&result).unwrap_or_else(|error| {
        panic!("generated key-bytes result JSON encoding failed: {error}");
    });
    assert_eq!(json, r#"{"keyBytes":"8fLz9A=="}"#);

    let view = CoseKeyBytesResultOwnedView::from_owned(&result)?;
    assert_eq!(view.key_bytes(), result.key_bytes.as_slice());
    Ok(())
}

#[test]
fn generated_proto_json_rejects_unknown_fields() {
    let request = serde_json::from_str::<CoseSign1CreateRequest>(
        r#"{"algorithm":"COSE_SIGNATURE_ALGORITHM_ED25519","payload":"","privateKey":"","kid":"","hasKid":false,"externalAad":"","private_key_typo":""}"#,
    );
    assert!(request.is_err());
}

#[test]
fn generated_proto_json_enum_range_errors_do_not_reflect_untrusted_values() {
    for (untrusted_value, expected_diagnostic) in [
        ("42424242", "unknown enum value"),
        ("9223372036854775807", "enum value out of i32 range"),
    ] {
        let result = serde_json::from_str::<CoseSignatureAlgorithm>(untrusted_value);
        let error = match result {
            Ok(_) => panic!("invalid concrete ProtoJSON enum value was accepted"),
            Err(error) => error,
        };
        let diagnostic = error.to_string();
        assert!(
            diagnostic.contains(expected_diagnostic),
            "unexpected fixed diagnostic: {diagnostic}"
        );
        assert!(!diagnostic.contains(untrusted_value));
    }
}

#[test]
fn generated_owned_views_redact_retained_protobuf_buffers() -> Result<(), buffa::DecodeError> {
    let result = CoseMlKemDecryptResult {
        plaintext: vec![251, 252, 253, 254],
        content_algorithm: Default::default(),
        kem_algorithm: Default::default(),
        mode: Default::default(),
        recipient_kid: vec![241, 242, 243, 244],
        __buffa_unknown_fields: Default::default(),
    };
    let view = CoseMlKemDecryptResultOwnedView::from_owned(&result)?;
    let debug = format!("{view:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("251"));
    assert!(!debug.contains("252"));
    assert!(!debug.contains("253"));
    assert!(!debug.contains("254"));
    assert!(!debug.contains("241"));
    assert!(!debug.contains("242"));
    assert!(!debug.contains("243"));
    assert!(!debug.contains("244"));
    Ok(())
}

#[test]
fn generated_private_key_requests_redact_debug_output() {
    let private_key = vec![251, 252, 253, 254];

    let attached = CoseSign1CreateRequest {
        algorithm: EnumValue::from(CoseSignatureAlgorithm::Ed25519),
        payload: b"payload".to_vec(),
        private_key: private_key.clone(),
        kid: b"kid".to_vec(),
        has_kid: true,
        options: buffa::MessageField::some(CoseSign1Options {
            tag: true,
            max_cose_sign1_bytes: 0,
            __buffa_unknown_fields: Default::default(),
        }),
        external_aad: Vec::new(),
        __buffa_unknown_fields: Default::default(),
    };
    assert_redacts_private_key(format!("{attached:?}"));

    let detached = CoseSign1CreateDetachedRequest {
        algorithm: EnumValue::from(CoseSignatureAlgorithm::Ed25519),
        payload: b"payload".to_vec(),
        private_key: private_key.clone(),
        kid: b"kid".to_vec(),
        has_kid: true,
        options: buffa::MessageField::none(),
        external_aad: Vec::new(),
        __buffa_unknown_fields: Default::default(),
    };
    assert_redacts_private_key(format!("{detached:?}"));

    let key = CoseKeyFromPrivateBytesRequest {
        algorithm: ed25519_identifier(),
        private_key,
        public_key: Vec::new(),
        has_public_key: false,
        __buffa_unknown_fields: Default::default(),
    };
    assert_redacts_private_key(format!("{key:?}"));
}

#[test]
fn generated_byte_fields_redact_debug_output() {
    let cose_sign1 = CoseSign1CreateResult {
        cose_sign1: vec![241, 242, 243, 244],
        __buffa_unknown_fields: Default::default(),
    };
    assert_redacts_bytes(format!("{cose_sign1:?}"), "cose_sign1");

    let verified = CoseSign1VerifyResult {
        payload: vec![241, 242, 243, 244],
        algorithm: EnumValue::from(CoseSignatureAlgorithm::Ed25519),
        kid: vec![245, 246, 247, 248],
        __buffa_unknown_fields: Default::default(),
    };
    let verified_debug = format!("{verified:?}");
    assert_redacts_bytes(verified_debug.clone(), "payload");
    assert_redacts_bytes(verified_debug, "kid");

    let key_request = CoseKeyBytesRequest {
        cose_key: vec![241, 242, 243, 244],
        __buffa_unknown_fields: Default::default(),
    };
    assert_redacts_bytes(format!("{key_request:?}"), "cose_key");

    let key_result = CoseKeyBytesResult {
        key_bytes: vec![241, 242, 243, 244],
        __buffa_unknown_fields: Default::default(),
    };
    assert_redacts_bytes(format!("{key_result:?}"), "key_bytes");

    let verify = CoseSign1VerifyRequest {
        cose_sign1: vec![241, 242, 243, 244],
        public_key: vec![241, 242, 243, 244],
        max_cose_sign1_bytes: 0,
        max_detached_payload_bytes: 0,
        require_kid: true,
        allowed_algorithms: Vec::new(),
        external_aad: vec![241, 242, 243, 244],
        expected_kid: vec![245, 246, 247, 248],
        __buffa_unknown_fields: Default::default(),
    };
    let verify_debug = format!("{verify:?}");
    assert_redacts_bytes(verify_debug.clone(), "external_aad");
    assert_redacts_bytes(verify_debug, "expected_kid");

    let detached_verify = CoseSign1VerifyDetachedRequest {
        cose_sign1: vec![241, 242, 243, 244],
        payload: vec![241, 242, 243, 244],
        public_key: vec![241, 242, 243, 244],
        max_cose_sign1_bytes: 0,
        max_detached_payload_bytes: 0,
        require_kid: true,
        allowed_algorithms: Vec::new(),
        external_aad: vec![241, 242, 243, 244],
        expected_kid: vec![245, 246, 247, 248],
        __buffa_unknown_fields: Default::default(),
    };
    let detached_verify_debug = format!("{detached_verify:?}");
    assert_redacts_bytes(detached_verify_debug.clone(), "external_aad");
    assert_redacts_bytes(detached_verify_debug, "expected_kid");
}

#[test]
fn generated_multikey_strings_redact_owned_and_view_debug_output() -> Result<(), buffa::DecodeError>
{
    const MULTIKEY: &str = "z6MkrzSensitivePersistentIdentifier";
    let request = serde_json::from_str::<CoseMultikeyToCoseKeyRequest>(&format!(
        r#"{{"multikey":"{MULTIKEY}"}}"#
    ))
    .unwrap_or_else(|error| panic!("generated Multikey request JSON decoding failed: {error}"));
    assert_redacts_string(format!("{request:?}"), MULTIKEY);

    let view = CoseMultikeyToCoseKeyRequestOwnedView::from_owned(&request)?;
    assert_redacts_string(format!("{view:?}"), MULTIKEY);

    let result = CoseMultikeyResult {
        multikey: MULTIKEY.to_owned(),
        __buffa_unknown_fields: Default::default(),
    };
    assert_redacts_string(format!("{result:?}"), MULTIKEY);
    Ok(())
}

fn assert_redacts_private_key(debug: String) {
    assert_redacts_bytes(debug, "private_key");
}

fn assert_redacts_bytes(debug: String, field_name: &str) {
    assert!(debug.contains(field_name));
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("251"));
    assert!(!debug.contains("252"));
    assert!(!debug.contains("253"));
    assert!(!debug.contains("254"));
    assert!(!debug.contains("241"));
    assert!(!debug.contains("242"));
    assert!(!debug.contains("243"));
    assert!(!debug.contains("244"));
    assert!(!debug.contains("245"));
    assert!(!debug.contains("246"));
    assert!(!debug.contains("247"));
    assert!(!debug.contains("248"));
}

fn assert_redacts_string(debug: String, value: &str) {
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains(value));
}
