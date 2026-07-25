// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

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
            public_key: public_key.to_vec(),
            __buffa_unknown_fields: Default::default(),
        },
    )));
    let public_cose = match take_result_branch(execute_result(&request)) {
        ResultBranch::KeyFromPublicBytes(mut message) => {
            Zeroizing::new(core::mem::take(&mut message.key_bytes))
        }
        _ => panic!("key_from_public_bytes returned the wrong v2 result variant"),
    };

    let request = operation(RequestBranch::KeyFromPrivateBytes(Box::new(
        CoseKeyFromPrivateBytesRequest {
            algorithm: ed25519_identifier(),
            private_key: private_key.to_vec(),
            public_key: public_key.to_vec(),
            has_public_key: true,
            __buffa_unknown_fields: Default::default(),
        },
    )));
    let private_cose = match take_result_branch(execute_result(&request)) {
        ResultBranch::KeyFromPrivateBytes(mut message) => {
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
    let multikey = match take_result_branch(execute_result(&request)) {
        ResultBranch::KeyToMultikey(mut message) => {
            Zeroizing::new(core::mem::take(&mut message.multikey))
        }
        _ => panic!("key_to_multikey returned the wrong v2 result variant"),
    };
    let request = operation(RequestBranch::MultikeyToCoseKey(Box::new(
        CoseMultikeyToCoseKeyRequest {
            multikey: multikey.to_string(),
            __buffa_unknown_fields: Default::default(),
        },
    )));
    match take_result_branch(execute_result(&request)) {
        ResultBranch::MultikeyToCoseKey(message) => assert!(!message.key_bytes.is_empty()),
        _ => panic!("multikey_to_cose_key returned the wrong v2 result variant"),
    }

    let request = operation(RequestBranch::Sign1Create(Box::new(sign_request(
        &private_key,
    ))));
    let attached = match take_result_branch(execute_result(&request)) {
        ResultBranch::Sign1Create(mut message) => {
            Zeroizing::new(core::mem::take(&mut message.cose_sign1))
        }
        _ => panic!("sign1_create returned the wrong v2 result variant"),
    };
    let request = operation(RequestBranch::Sign1CreateDetached(Box::new(
        detached_sign_request(&private_key),
    )));
    let detached = match take_result_branch(execute_result(&request)) {
        ResultBranch::Sign1CreateDetached(mut message) => {
            Zeroizing::new(core::mem::take(&mut message.cose_sign1))
        }
        _ => panic!("sign1_create_detached returned the wrong v2 result variant"),
    };

    let request = operation(RequestBranch::Sign1Verify(Box::new(verify_request(
        &attached,
        &public_key,
    ))));
    match take_result_branch(execute_result(&request)) {
        ResultBranch::Sign1Verify(message) => assert_eq!(message.payload, PAYLOAD),
        _ => panic!("sign1_verify returned the wrong v2 result variant"),
    }
    let request = operation(RequestBranch::Sign1VerifyDetached(Box::new(
        detached_verify_request(&detached, &public_key),
    )));
    match take_result_branch(execute_result(&request)) {
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
    let direct = match take_result_branch(execute_result(&direct_request)) {
        ResultBranch::MlKemEncryptDirect(mut message) => {
            Zeroizing::new(core::mem::take(&mut message.cose_encrypt))
        }
        _ => panic!("ml_kem_encrypt_direct returned the wrong v2 result variant"),
    };
    assert_plaintext(&direct, &kem_private, &kid);

    let key_wrap_request = operation(RequestBranch::MlKemEncryptKeyWrap(Box::new(
        encrypt_request(&kem_public, &kid),
    )));
    let key_wrapped = match take_result_branch(execute_result(&key_wrap_request)) {
        ResultBranch::MlKemEncryptKeyWrap(mut message) => {
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
    match take_result_branch(execute_result(&request)) {
        ResultBranch::MlKemDecrypt(message) => {
            assert_eq!(message.plaintext, PAYLOAD);
        }
        _ => panic!("ml_kem_decrypt returned the wrong v2 result variant"),
    }
}

#[test]
fn operation_error_outcomes_match_binary_and_json_contracts() {
    let request = operation(RequestBranch::KeyParse(Box::new(CoseKeyBytesRequest {
        cose_key: vec![0xff],
        __buffa_unknown_fields: Default::default(),
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
            payload: Vec::new(),
            algorithm: EnumValue::from(42_424_242),
            kid: Vec::new(),
            __buffa_unknown_fields: Default::default(),
        },
    )));
    assert_backend_error(
        decode_operation_response_for_request(&verify_request, &invalid_metadata.encode_to_vec()),
        CoseErrorReason::BackendInternal,
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
        CoseErrorReason::CommonResourceLimitExceeded,
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
    let result = take_result_branch(execute_result(&request));
    let message = match (expected, result) {
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
    match response.outcome.take() {
        Some(ResponseOutcome::Result(result)) => *result,
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
    match response.outcome.take() {
        Some(ResponseOutcome::Error(error)) => *error,
        _ => panic!("operation returned a v2 success outcome"),
    }
}

fn assert_backend_error(
    result: Result<CoseOperationResponseV2, CoseOperationResponseV2>,
    expected: CoseErrorReason,
) {
    let error = take_error(result.expect_err("hostile v2 response must be rejected"));
    match error.error {
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
            __buffa_unknown_fields: Default::default(),
        }))),
        __buffa_unknown_fields: Default::default(),
    }
}

fn operation(operation: RequestBranch) -> CoseOperationRequest {
    CoseOperationRequest {
        operation: Some(operation),
        __buffa_unknown_fields: Default::default(),
    }
}

fn ed25519_identifier(
) -> buffa::MessageField<CoseAlgorithmIdentifier, buffa::Inline<CoseAlgorithmIdentifier>> {
    buffa::MessageField::some(CoseAlgorithmIdentifier {
        algorithm: Some(cose_algorithm_identifier::Algorithm::Signature(
            EnumValue::from(CoseSignatureAlgorithm::Ed25519),
        )),
        __buffa_unknown_fields: Default::default(),
    })
}

fn key_request(cose_key: &[u8]) -> CoseKeyBytesRequest {
    CoseKeyBytesRequest {
        cose_key: cose_key.to_vec(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn sign_options() -> buffa::MessageField<CoseSign1Options, buffa::Inline<CoseSign1Options>> {
    buffa::MessageField::some(CoseSign1Options::default())
}

fn sign_request(private_key: &[u8]) -> CoseSign1CreateRequest {
    CoseSign1CreateRequest {
        algorithm: EnumValue::from(CoseSignatureAlgorithm::Ed25519),
        payload: PAYLOAD.to_vec(),
        private_key: private_key.to_vec(),
        kid: test_kid().to_vec(),
        has_kid: true,
        options: sign_options(),
        external_aad: Vec::new(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn detached_sign_request(private_key: &[u8]) -> CoseSign1CreateDetachedRequest {
    CoseSign1CreateDetachedRequest {
        algorithm: EnumValue::from(CoseSignatureAlgorithm::Ed25519),
        payload: PAYLOAD.to_vec(),
        private_key: private_key.to_vec(),
        kid: test_kid().to_vec(),
        has_kid: true,
        options: sign_options(),
        external_aad: Vec::new(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn verify_request(cose_sign1: &[u8], public_key: &[u8]) -> CoseSign1VerifyRequest {
    CoseSign1VerifyRequest {
        cose_sign1: cose_sign1.to_vec(),
        public_key: public_key.to_vec(),
        max_cose_sign1_bytes: 0,
        max_detached_payload_bytes: 0,
        require_kid: true,
        allowed_algorithms: vec![EnumValue::from(CoseSignatureAlgorithm::Ed25519)],
        external_aad: Vec::new(),
        expected_kid: test_kid().to_vec(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn detached_verify_request(cose_sign1: &[u8], public_key: &[u8]) -> CoseSign1VerifyDetachedRequest {
    CoseSign1VerifyDetachedRequest {
        cose_sign1: cose_sign1.to_vec(),
        payload: PAYLOAD.to_vec(),
        public_key: public_key.to_vec(),
        max_cose_sign1_bytes: 0,
        max_detached_payload_bytes: 0,
        require_kid: true,
        allowed_algorithms: vec![EnumValue::from(CoseSignatureAlgorithm::Ed25519)],
        external_aad: Vec::new(),
        expected_kid: test_kid().to_vec(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn encrypt_request(public_key: &[u8], kid: &[u8]) -> CoseMlKemEncryptRequest {
    CoseMlKemEncryptRequest {
        kem_algorithm: EnumValue::from(CoseKemAlgorithm::MlKem512),
        content_algorithm: EnumValue::from(CoseContentEncryptionAlgorithm::Aes128Gcm),
        recipient_public_key: public_key.to_vec(),
        recipient_kid: kid.to_vec(),
        plaintext: PAYLOAD.to_vec(),
        external_aad: Vec::new(),
        supp_priv_info: Vec::new(),
        has_supp_priv_info: false,
        __buffa_unknown_fields: Default::default(),
    }
}

fn decrypt_request(cose_encrypt: &[u8], private_key: &[u8], kid: &[u8]) -> CoseMlKemDecryptRequest {
    CoseMlKemDecryptRequest {
        cose_encrypt: cose_encrypt.to_vec(),
        recipient_private_key: private_key.to_vec(),
        expected_recipient_kid: kid.to_vec(),
        external_aad: Vec::new(),
        supp_priv_info: Vec::new(),
        has_supp_priv_info: false,
        __buffa_unknown_fields: Default::default(),
    }
}

fn assert_plaintext(cose_encrypt: &[u8], private_key: &[u8], kid: &[u8]) {
    let request = NativeDecryptRequest::new(cose_encrypt, private_key, kid, None);
    let decrypted = cose_decrypt_ml_kem(&request).expect("v2 ciphertext must decrypt natively");
    assert_eq!(decrypted.plaintext.as_slice(), PAYLOAD);
}
