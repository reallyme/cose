// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used, clippy::panic)]

use buffa::{EnumValue, Message};
use reallyme_cose::wire::{
    cose_algorithm_identifier, cose_error_proto, cose_operation_request,
    cose_operation_response_v2, cose_operation_result, decode_operation_response_for_request,
    execute_operation_proto, execute_operation_proto_json, CoseAlgorithmIdentifier,
    CoseContentEncryptionAlgorithm, CoseErrorProto, CoseErrorReason, CoseKemAlgorithm,
    CoseKeyBytesRequest, CoseKeyFromPrivateBytesRequest, CoseKeyFromPublicBytesRequest,
    CoseMlKemDecryptRequest, CoseMlKemEncryptRequest, CoseMultikeyToCoseKeyRequest,
    CoseOperationRequest, CoseOperationResponseV2, CoseOperationResult,
    CoseSign1CreateDetachedRequest, CoseSign1CreateRequest, CoseSign1Options,
    CoseSign1VerifyDetachedRequest, CoseSign1VerifyRequest, CoseSignatureAlgorithm,
    MAX_COSE_PROTO_MESSAGE_BYTES,
};
use reallyme_cose::{
    cose_decrypt_ml_kem, cose_key_from_public_bytes, derive_kid_from_cose_key_public, Algorithm,
    CoseMlKemDecryptRequest as NativeDecryptRequest,
};
use zeroize::Zeroizing;

use super::support::{gen_ed25519, gen_mlkem512, test_kid};

type RequestBranch = cose_operation_request::Operation;
type ResponseOutcome = cose_operation_response_v2::Outcome;
type ResultBranch = cose_operation_result::Result;
const PAYLOAD: &[u8] = b"discriminated operation response payload";

#[test]
fn every_executable_operation_returns_its_exact_version_two_variant() {
    let mut signing_key = gen_ed25519();
    let public_key = Zeroizing::new(core::mem::take(&mut signing_key.public));
    let private_key = Zeroizing::new(core::mem::take(&mut signing_key.private));

    let request = operation(RequestBranch::KeyFromPublicBytes(Box::new(
        CoseKeyFromPublicBytesRequest {
            algorithm: ed25519_identifier(),
            public_key: public_key.to_vec().into(),
            ec2_point_encoding: Default::default(),
        },
    )));
    let public_cose = match &mut take_result_branch(execute_result(&request)) {
        ResultBranch::KeyFromPublicBytes(message) => {
            Zeroizing::new(core::mem::take(&mut message.key_bytes))
        }
        _ => panic!("key_from_public_bytes returned the wrong v2 result variant"),
    };

    let request = operation(RequestBranch::KeyFromPrivateBytes(Box::new(
        CoseKeyFromPrivateBytesRequest {
            algorithm: ed25519_identifier(),
            private_key: private_key.to_vec().into(),
            public_key: Some(public_key.to_vec().into()),
        },
    )));
    let private_cose = match &mut take_result_branch(execute_result(&request)) {
        ResultBranch::KeyFromPrivateBytes(message) => {
            Zeroizing::new(core::mem::take(&mut message.key_bytes))
        }
        _ => panic!("key_from_private_bytes returned the wrong v2 result variant"),
    };

    assert_key_result(
        operation(RequestBranch::KeyParse(Box::new(key_request(&public_cose)))),
        ResultBranchKind::Parse,
    );
    assert_key_result(
        operation(RequestBranch::KeyToPublicBytes(Box::new(key_request(
            &private_cose,
        )))),
        ResultBranchKind::PublicBytes,
    );
    assert_key_result(
        operation(RequestBranch::KeyToPrivateBytes(Box::new(key_request(
            &private_cose,
        )))),
        ResultBranchKind::PrivateBytes,
    );
    assert_key_result(
        operation(RequestBranch::KeyDerivePublicKid(Box::new(key_request(
            &public_cose,
        )))),
        ResultBranchKind::PublicKid,
    );

    let request = operation(RequestBranch::KeyToMultikey(Box::new(key_request(
        &public_cose,
    ))));
    let multikey = match &mut take_result_branch(execute_result(&request)) {
        ResultBranch::KeyToMultikey(message) => {
            Zeroizing::new(core::mem::take(&mut message.multikey))
        }
        _ => panic!("key_to_multikey returned the wrong v2 result variant"),
    };
    let request = operation(RequestBranch::MultikeyToCoseKey(Box::new(
        CoseMultikeyToCoseKeyRequest {
            multikey: multikey.to_string().into(),
        },
    )));
    match &mut take_result_branch(execute_result(&request)) {
        ResultBranch::MultikeyToCoseKey(message) => assert!(!message.key_bytes.is_empty()),
        _ => panic!("multikey_to_cose_key returned the wrong v2 result variant"),
    }

    let request = operation(RequestBranch::Sign1Create(Box::new(sign_request(
        &private_key,
    ))));
    let attached = match &mut take_result_branch(execute_result(&request)) {
        ResultBranch::Sign1Create(message) => {
            Zeroizing::new(core::mem::take(&mut message.cose_sign1))
        }
        _ => panic!("sign1_create returned the wrong v2 result variant"),
    };
    let request = operation(RequestBranch::Sign1CreateDetached(Box::new(
        detached_sign_request(&private_key),
    )));
    let detached = match &mut take_result_branch(execute_result(&request)) {
        ResultBranch::Sign1CreateDetached(message) => {
            Zeroizing::new(core::mem::take(&mut message.cose_sign1))
        }
        _ => panic!("sign1_create_detached returned the wrong v2 result variant"),
    };

    let request = operation(RequestBranch::Sign1Verify(Box::new(verify_request(
        &attached,
        &public_key,
    ))));
    match &mut take_result_branch(execute_result(&request)) {
        ResultBranch::Sign1Verify(message) => assert_eq!(message.payload, PAYLOAD),
        _ => panic!("sign1_verify returned the wrong v2 result variant"),
    }
    let request = operation(RequestBranch::Sign1VerifyDetached(Box::new(
        detached_verify_request(&detached, &public_key),
    )));
    match &mut take_result_branch(execute_result(&request)) {
        ResultBranch::Sign1VerifyDetached(message) => assert!(message.payload.is_empty()),
        _ => panic!("sign1_verify_detached returned the wrong v2 result variant"),
    }

    let mut kem_key = gen_mlkem512();
    let kem_public = Zeroizing::new(core::mem::take(&mut kem_key.public));
    let kem_private = Zeroizing::new(core::mem::take(&mut kem_key.private));
    let public_cose_key = cose_key_from_public_bytes(Algorithm::MlKem512, &kem_public)
        .expect("ML-KEM public key must construct");
    let kid = Zeroizing::new(
        derive_kid_from_cose_key_public(&public_cose_key).expect("ML-KEM kid must derive"),
    );

    let direct_request = operation(RequestBranch::MlKemEncryptDirect(Box::new(
        encrypt_request(&kem_public, &kid),
    )));
    let direct = match &mut take_result_branch(execute_result(&direct_request)) {
        ResultBranch::MlKemEncryptDirect(message) => {
            Zeroizing::new(core::mem::take(&mut message.cose_encrypt))
        }
        _ => panic!("ml_kem_encrypt_direct returned the wrong v2 result variant"),
    };
    assert_plaintext(&direct, &kem_private, &kid);

    let key_wrap_request = operation(RequestBranch::MlKemEncryptKeyWrap(Box::new(
        encrypt_request(&kem_public, &kid),
    )));
    let key_wrapped = match &mut take_result_branch(execute_result(&key_wrap_request)) {
        ResultBranch::MlKemEncryptKeyWrap(message) => {
            Zeroizing::new(core::mem::take(&mut message.cose_encrypt))
        }
        _ => panic!("ml_kem_encrypt_key_wrap returned the wrong v2 result variant"),
    };
    assert_plaintext(&key_wrapped, &kem_private, &kid);

    let request = operation(RequestBranch::MlKemDecrypt(Box::new(decrypt_request(
        &direct,
        &kem_private,
        &kid,
    ))));
    match &mut take_result_branch(execute_result(&request)) {
        ResultBranch::MlKemDecrypt(message) => {
            assert_eq!(message.plaintext, PAYLOAD);
        }
        _ => panic!("ml_kem_decrypt returned the wrong v2 result variant"),
    }
}

#[test]
fn operation_error_outcomes_match_binary_and_json_contracts() {
    let request = operation(RequestBranch::KeyParse(Box::new(CoseKeyBytesRequest {
        cose_key: vec![0xff].into(),
    })));
    let binary_request = Zeroizing::new(request.encode_to_vec());
    let binary = execute_operation_proto(&binary_request);
    let json = Zeroizing::new(
        serde_json::to_string(&request).expect("generated request must encode as ProtoJSON"),
    );
    let json_response = execute_operation_proto_json(&json);
    assert_eq!(binary.as_slice(), json_response.as_slice());

    let response = decode_operation_response_for_request(&request, &binary)
        .expect("generated v2 error response must validate");
    let error = take_error(response);
    assert!(matches!(
        error.error,
        Some(cose_error_proto::Error::Primitive(_))
    ));
}

#[test]
#[allow(deprecated)] // Exercise published compatibility selectors.
fn version_two_decoder_rejects_mismatched_and_hostile_responses_as_backend_failures() {
    let request = operation(RequestBranch::KeyParse(Box::default()));
    let mismatched = response_with_result(ResultBranch::KeyToPublicBytes(Box::default()));
    assert_backend_error(
        decode_operation_response_for_request(&request, &mismatched.encode_to_vec()),
        CoseErrorReason::BackendInternal,
    );

    let missing_outcome = CoseOperationResponseV2::default();
    assert_backend_error(
        decode_operation_response_for_request(&request, &missing_outcome.encode_to_vec()),
        CoseErrorReason::BackendInternal,
    );

    let verify_request = operation(RequestBranch::Sign1Verify(Box::default()));
    let invalid_metadata = response_with_result(ResultBranch::Sign1Verify(Box::new(
        reallyme_cose::wire::CoseSign1VerifyResult {
            payload: Vec::new().into(),
            algorithm: EnumValue::from(42_424_242),
            kid: Vec::new().into(),
            exact_signature_algorithm: EnumValue::from(42_424_242),

            protected_type: buffa::MessageField::none(),
        },
    )));
    assert_backend_error(
        decode_operation_response_for_request(&verify_request, &invalid_metadata.encode_to_vec()),
        CoseErrorReason::BackendInternal,
    );

    let mismatched_exact = response_with_result(ResultBranch::Sign1Verify(Box::new(
        reallyme_cose::wire::CoseSign1VerifyResult {
            payload: Vec::new().into(),
            algorithm: EnumValue::from(CoseSignatureAlgorithm::EcdsaP256Sha256),
            kid: Vec::new().into(),
            exact_signature_algorithm: EnumValue::from(CoseSignatureAlgorithm::Ed25519),

            protected_type: buffa::MessageField::none(),
        },
    )));
    assert_backend_error(
        decode_operation_response_for_request(&verify_request, &mismatched_exact.encode_to_vec()),
        CoseErrorReason::BackendInternal,
    );

    let legacy_metadata = response_with_result(ResultBranch::Sign1Verify(Box::new(
        reallyme_cose::wire::CoseSign1VerifyResult {
            payload: Vec::new().into(),
            algorithm: EnumValue::from(CoseSignatureAlgorithm::Ed25519),
            kid: Vec::new().into(),
            exact_signature_algorithm: EnumValue::from(0),

            protected_type: buffa::MessageField::none(),
        },
    )));
    assert!(
        decode_operation_response_for_request(&verify_request, &legacy_metadata.encode_to_vec())
            .is_ok(),
        "pre-0.2.2 verification results must remain decodable",
    );

    let mut unknown_field = mismatched.encode_to_vec();
    unknown_field.extend_from_slice(&[0x1a, 0x00]);
    assert_backend_error(
        decode_operation_response_for_request(&request, &unknown_field),
        CoseErrorReason::BackendInternal,
    );

    let oversized_len = MAX_COSE_PROTO_MESSAGE_BYTES
        .checked_add(33)
        .expect("test response size must fit usize");
    let oversized = Zeroizing::new(vec![0_u8; oversized_len]);
    assert_backend_error(
        decode_operation_response_for_request(&request, &oversized),
        CoseErrorReason::BackendResourceLimitExceeded,
    );
}

#[derive(Clone, Copy)]
enum ResultBranchKind {
    Parse,
    PublicBytes,
    PrivateBytes,
    PublicKid,
}

fn assert_key_result(request: CoseOperationRequest, expected: ResultBranchKind) {
    let mut result = take_result_branch(execute_result(&request));
    let message = match (expected, &mut result) {
        (ResultBranchKind::Parse, ResultBranch::KeyParse(message))
        | (ResultBranchKind::PublicBytes, ResultBranch::KeyToPublicBytes(message))
        | (ResultBranchKind::PrivateBytes, ResultBranch::KeyToPrivateBytes(message))
        | (ResultBranchKind::PublicKid, ResultBranch::KeyDerivePublicKid(message)) => message,
        _ => panic!("key operation returned the wrong v2 result variant"),
    };
    assert!(!message.key_bytes.is_empty());
}

fn execute_v2(request: &CoseOperationRequest) -> CoseOperationResponseV2 {
    let request_bytes = Zeroizing::new(request.encode_to_vec());
    let response_bytes = execute_operation_proto(&request_bytes);
    let response = decode_operation_response_for_request(request, &response_bytes)
        .expect("generated binary v2 response must validate for its request");

    let request_json = Zeroizing::new(
        serde_json::to_string(request).expect("generated request must encode as ProtoJSON"),
    );
    let json_response_bytes = execute_operation_proto_json(&request_json);
    let _json_response = decode_operation_response_for_request(request, &json_response_bytes)
        .expect("generated ProtoJSON v2 response must validate for its request");
    if !request_has_randomized_output(request) {
        assert_eq!(response_bytes.as_slice(), json_response_bytes.as_slice());
    }
    response
}

fn request_has_randomized_output(request: &CoseOperationRequest) -> bool {
    matches!(
        request.operation.as_ref(),
        Some(RequestBranch::MlKemEncryptDirect(_) | RequestBranch::MlKemEncryptKeyWrap(_))
    )
}

fn execute_result(request: &CoseOperationRequest) -> CoseOperationResult {
    take_operation_result(execute_v2(request))
}

fn take_operation_result(mut response: CoseOperationResponseV2) -> CoseOperationResult {
    match response.outcome.as_mut() {
        Some(ResponseOutcome::Result(result)) => core::mem::take(&mut **result),
        _ => panic!("operation returned a v2 error outcome"),
    }
}

fn take_result_branch(mut result: CoseOperationResult) -> ResultBranch {
    result
        .result
        .take()
        .expect("successful v2 result must contain an operation branch")
}

fn take_error(mut response: CoseOperationResponseV2) -> CoseErrorProto {
    match response.outcome.as_mut() {
        Some(ResponseOutcome::Error(error)) => core::mem::take(&mut **error),
        _ => panic!("operation returned a v2 success outcome"),
    }
}

fn assert_backend_error(
    result: Result<CoseOperationResponseV2, CoseOperationResponseV2>,
    expected: CoseErrorReason,
) {
    let error = take_error(result.expect_err("hostile v2 response must be rejected"));
    match error.error.as_ref() {
        Some(cose_error_proto::Error::Backend(error)) => {
            assert_eq!(error.reason.as_known(), Some(expected));
        }
        _ => panic!("hostile v2 response did not return a backend error"),
    }
}

fn response_with_result(result: ResultBranch) -> CoseOperationResponseV2 {
    CoseOperationResponseV2 {
        outcome: Some(ResponseOutcome::Result(Box::new(CoseOperationResult {
            result: Some(result),
        }))),
    }
}

fn operation(operation: RequestBranch) -> CoseOperationRequest {
    CoseOperationRequest {
        operation: Some(operation),
    }
}

fn ed25519_identifier(
) -> buffa::MessageField<CoseAlgorithmIdentifier, buffa::Inline<CoseAlgorithmIdentifier>> {
    buffa::MessageField::some(CoseAlgorithmIdentifier {
        algorithm: Some(cose_algorithm_identifier::Algorithm::Signature(
            EnumValue::from(CoseSignatureAlgorithm::Ed25519),
        )),
    })
}

fn key_request(cose_key: &[u8]) -> CoseKeyBytesRequest {
    CoseKeyBytesRequest {
        cose_key: cose_key.to_vec().into(),
    }
}

fn sign_options() -> buffa::MessageField<CoseSign1Options, buffa::Inline<CoseSign1Options>> {
    buffa::MessageField::some(CoseSign1Options::default())
}

fn sign_request(private_key: &[u8]) -> CoseSign1CreateRequest {
    CoseSign1CreateRequest {
        algorithm: EnumValue::from(CoseSignatureAlgorithm::Ed25519),
        payload: PAYLOAD.to_vec().into(),
        private_key: private_key.to_vec().into(),
        kid: Some(test_kid().to_vec().into()),
        options: sign_options(),
        external_aad: Vec::new().into(),
    }
}

fn detached_sign_request(private_key: &[u8]) -> CoseSign1CreateDetachedRequest {
    CoseSign1CreateDetachedRequest {
        algorithm: EnumValue::from(CoseSignatureAlgorithm::Ed25519),
        payload: PAYLOAD.to_vec().into(),
        private_key: private_key.to_vec().into(),
        kid: Some(test_kid().to_vec().into()),
        options: sign_options(),
        external_aad: Vec::new().into(),
    }
}

fn verify_request(cose_sign1: &[u8], public_key: &[u8]) -> CoseSign1VerifyRequest {
    CoseSign1VerifyRequest {
        cose_sign1: cose_sign1.to_vec().into(),
        public_key: public_key.to_vec().into(),
        max_cose_sign1_bytes: 0,
        max_detached_payload_bytes: 0,
        require_kid: true,
        allowed_algorithms: vec![EnumValue::from(CoseSignatureAlgorithm::Ed25519)].into(),
        external_aad: Vec::new().into(),
        expected_kid: test_kid().to_vec().into(),
        require_tagged_sign1: false,
        expected_type: buffa::MessageField::none(),
        public_key_algorithm: EnumValue::from(CoseSignatureAlgorithm::Ed25519),
    }
}

fn detached_verify_request(cose_sign1: &[u8], public_key: &[u8]) -> CoseSign1VerifyDetachedRequest {
    CoseSign1VerifyDetachedRequest {
        cose_sign1: cose_sign1.to_vec().into(),
        payload: PAYLOAD.to_vec().into(),
        public_key: public_key.to_vec().into(),
        max_cose_sign1_bytes: 0,
        max_detached_payload_bytes: 0,
        require_kid: true,
        allowed_algorithms: vec![EnumValue::from(CoseSignatureAlgorithm::Ed25519)].into(),
        external_aad: Vec::new().into(),
        expected_kid: test_kid().to_vec().into(),
        require_tagged_sign1: false,
        expected_type: buffa::MessageField::none(),
        public_key_algorithm: EnumValue::from(CoseSignatureAlgorithm::Ed25519),
    }
}

fn encrypt_request(public_key: &[u8], kid: &[u8]) -> CoseMlKemEncryptRequest {
    CoseMlKemEncryptRequest {
        kem_algorithm: EnumValue::from(CoseKemAlgorithm::MlKem512),
        content_algorithm: EnumValue::from(CoseContentEncryptionAlgorithm::Aes128Gcm),
        recipient_public_key: public_key.to_vec().into(),
        recipient_kid: kid.to_vec().into(),
        plaintext: PAYLOAD.to_vec().into(),
        external_aad: Vec::new().into(),
        supp_priv_info: None,
    }
}

fn decrypt_request(cose_encrypt: &[u8], private_key: &[u8], kid: &[u8]) -> CoseMlKemDecryptRequest {
    CoseMlKemDecryptRequest {
        cose_encrypt: cose_encrypt.to_vec().into(),
        recipient_private_key: private_key.to_vec().into(),
        expected_recipient_kid: kid.to_vec().into(),
        external_aad: Vec::new().into(),
        supp_priv_info: None,
    }
}

fn assert_plaintext(cose_encrypt: &[u8], private_key: &[u8], kid: &[u8]) {
    let request = NativeDecryptRequest::new(cose_encrypt, private_key, kid, None);
    let decrypted = cose_decrypt_ml_kem(&request).expect("v2 ciphertext must decrypt natively");
    assert_eq!(decrypted.plaintext.as_slice(), PAYLOAD);
}

#[test]
fn response_decoder_rejects_unspecified_legacy_signature_algorithm() {
    let request = operation(RequestBranch::Sign1Verify(Box::default()));
    let response = response_with_result(ResultBranch::Sign1Verify(Box::default()));
    assert_backend_error(
        decode_operation_response_for_request(&request, &response.encode_to_vec()),
        CoseErrorReason::BackendInternal,
    );
}

#[test]
fn response_decoder_validates_key_algorithm_presence_and_registration() {
    let request = operation(RequestBranch::KeyParse(Box::default()));
    for (algorithm, valid) in [
        (0, true),
        (100, true),
        (201, true),
        (202, true),
        (200, false),
        (42_424_242, false),
    ] {
        let response = response_with_result(ResultBranch::KeyParse(Box::new(
            reallyme_cose::wire::CoseKeyBytesResult {
                signature_algorithm: EnumValue::from(algorithm),

                key_bytes: Vec::new().into(),
            },
        )));
        let decoded = decode_operation_response_for_request(&request, &response.encode_to_vec());
        if valid {
            assert!(decoded.is_ok());
        } else {
            assert_backend_error(decoded, CoseErrorReason::BackendInternal);
        }
    }
}

#[test]
#[allow(deprecated)] // Exercise published compatibility selectors.
fn legacy_verification_metadata_remains_accepted_for_every_supported_algorithm() {
    for algorithm in [
        CoseSignatureAlgorithm::Ed25519,
        CoseSignatureAlgorithm::EcdsaP256Sha256,
        CoseSignatureAlgorithm::Es256,
        CoseSignatureAlgorithm::Esp256,
        CoseSignatureAlgorithm::EcdsaP384Sha384,
        CoseSignatureAlgorithm::Esp384,
        CoseSignatureAlgorithm::EcdsaP521Sha512,
        CoseSignatureAlgorithm::Esp512,
        CoseSignatureAlgorithm::EcdsaSecp256k1Sha256,
        CoseSignatureAlgorithm::MlDsa44,
        CoseSignatureAlgorithm::MlDsa65,
        CoseSignatureAlgorithm::MlDsa87,
    ] {
        for detached in [false, true] {
            let metadata = Box::new(reallyme_cose::wire::CoseSign1VerifyResult {
                algorithm: EnumValue::from(algorithm),
                payload: Vec::new().into(),
                kid: Vec::new().into(),
                exact_signature_algorithm: EnumValue::from(0),

                protected_type: buffa::MessageField::none(),
            });
            let (request, result) = if detached {
                (
                    RequestBranch::Sign1VerifyDetached(Box::default()),
                    ResultBranch::Sign1VerifyDetached(metadata),
                )
            } else {
                (
                    RequestBranch::Sign1Verify(Box::default()),
                    ResultBranch::Sign1Verify(metadata),
                )
            };
            assert!(
                decode_operation_response_for_request(
                    &operation(request),
                    &response_with_result(result).encode_to_vec(),
                )
                .is_ok(),
                "{algorithm:?}"
            );
        }
    }
}
