// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::panic)]

use buffa::{EnumValue, Message};
use coset::{CoseEncrypt, TaggedCborSerializable};
use reallyme_cose::wire::cose_operation_request::Operation as CoseOperationRequestBranch;
use reallyme_cose::wire::{
    cose_algorithm_identifier, decode_cose_error, execute_operation_proto,
    execute_operation_proto_json, CoseAlgorithmIdentifier, CoseContentEncryptionAlgorithm,
    CoseErrorProto, CoseErrorReason, CoseKemAlgorithm, CoseKeyAgreementAlgorithm,
    CoseKeyBytesResult, CoseKeyFromPublicBytesRequest, CoseMlKemDecryptRequest,
    CoseMlKemDecryptResult, CoseMlKemEncryptRequest, CoseMlKemEncryptResult, CoseMlKemMode,
    CoseOperationRequest, CosePrimitiveError, CoseSign1CreateDetachedRequest,
    CoseSign1CreateRequest, CoseSign1CreateResult, CoseSign1Options,
    CoseSign1VerifyDetachedRequest, CoseSign1VerifyRequest, CoseSign1VerifyResult,
    CoseSignatureAlgorithm, MAX_COSE_PROTO_MESSAGE_BYTES,
};
use reallyme_cose::{
    cose_key_from_public_bytes, cose_key_from_slice, cose_key_signature_algorithm,
    derive_kid_from_cose_key_public, CoseSignatureAlgorithm as NativeSignatureAlgorithm,
};

use crate::support::{
    decode_operation_output, gen_ed25519, gen_p256, sample_payload, test_kid, OperationOutput,
    OperationOutputStatus,
};

fn signature_value(algorithm: CoseSignatureAlgorithm) -> EnumValue<CoseSignatureAlgorithm> {
    EnumValue::from(algorithm)
}

fn kem_value(algorithm: CoseKemAlgorithm) -> EnumValue<CoseKemAlgorithm> {
    EnumValue::from(algorithm)
}

fn signature_identifier(
    algorithm: CoseSignatureAlgorithm,
) -> buffa::MessageField<CoseAlgorithmIdentifier, buffa::Inline<CoseAlgorithmIdentifier>> {
    buffa::MessageField::some(CoseAlgorithmIdentifier {
        algorithm: Some(cose_algorithm_identifier::Algorithm::Signature(
            signature_value(algorithm),
        )),
        __buffa_unknown_fields: Default::default(),
    })
}

fn key_agreement_identifier(
    algorithm: CoseKeyAgreementAlgorithm,
) -> buffa::MessageField<CoseAlgorithmIdentifier, buffa::Inline<CoseAlgorithmIdentifier>> {
    buffa::MessageField::some(CoseAlgorithmIdentifier {
        algorithm: Some(cose_algorithm_identifier::Algorithm::KeyAgreement(
            EnumValue::from(algorithm),
        )),
        __buffa_unknown_fields: Default::default(),
    })
}

fn error_reason(error: &CoseErrorProto) -> Option<CoseErrorReason> {
    let reason = match error.error.as_ref()? {
        reallyme_cose::wire::cose_error_proto::Error::Primitive(error) => error.reason,
        reallyme_cose::wire::cose_error_proto::Error::Provider(error) => error.reason,
        reallyme_cose::wire::cose_error_proto::Error::Backend(error) => error.reason,
    };
    reason.as_known()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExpectedErrorBranch {
    Primitive,
    Provider,
    Backend,
}

fn error_branch(error: &CoseErrorProto) -> Option<ExpectedErrorBranch> {
    match error.error.as_ref()? {
        reallyme_cose::wire::cose_error_proto::Error::Primitive(_) => {
            Some(ExpectedErrorBranch::Primitive)
        }
        reallyme_cose::wire::cose_error_proto::Error::Provider(_) => {
            Some(ExpectedErrorBranch::Provider)
        }
        reallyme_cose::wire::cose_error_proto::Error::Backend(_) => {
            Some(ExpectedErrorBranch::Backend)
        }
    }
}

fn sign1_create_request(
    algorithm: CoseSignatureAlgorithm,
    payload: Vec<u8>,
    private_key: Vec<u8>,
    kid: Vec<u8>,
    has_kid: bool,
) -> CoseSign1CreateRequest {
    CoseSign1CreateRequest {
        algorithm: signature_value(algorithm),
        payload,
        private_key,
        kid,
        has_kid,
        options: Default::default(),
        external_aad: Vec::new(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn sign1_create_detached_request(
    algorithm: CoseSignatureAlgorithm,
    payload: Vec<u8>,
    private_key: Vec<u8>,
    kid: Vec<u8>,
    has_kid: bool,
) -> CoseSign1CreateDetachedRequest {
    CoseSign1CreateDetachedRequest {
        algorithm: signature_value(algorithm),
        payload,
        private_key,
        kid,
        has_kid,
        options: Default::default(),
        external_aad: Vec::new(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn sign1_verify_request(
    cose_sign1: Vec<u8>,
    public_key: Vec<u8>,
    require_kid: bool,
) -> CoseSign1VerifyRequest {
    CoseSign1VerifyRequest {
        cose_sign1,
        public_key,
        max_cose_sign1_bytes: 0,
        max_detached_payload_bytes: 0,
        require_kid,
        allowed_algorithms: vec![signature_value(CoseSignatureAlgorithm::Ed25519)],
        external_aad: Vec::new(),
        expected_kid: Vec::new(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn sign1_verify_detached_request(
    cose_sign1: Vec<u8>,
    payload: Vec<u8>,
    public_key: Vec<u8>,
    require_kid: bool,
) -> CoseSign1VerifyDetachedRequest {
    CoseSign1VerifyDetachedRequest {
        cose_sign1,
        payload,
        public_key,
        max_cose_sign1_bytes: 0,
        max_detached_payload_bytes: 0,
        require_kid,
        allowed_algorithms: vec![signature_value(CoseSignatureAlgorithm::Ed25519)],
        external_aad: Vec::new(),
        expected_kid: Vec::new(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn operation_request(operation: CoseOperationRequestBranch) -> CoseOperationRequest {
    CoseOperationRequest {
        operation: Some(operation),
        __buffa_unknown_fields: Default::default(),
    }
}

fn decode_operation_envelope(bytes: &[u8]) -> OperationOutput {
    let envelope = execute_operation_proto(bytes);
    match decode_operation_output(&envelope) {
        Ok(output) => output,
        Err(output) => output,
    }
}

fn execute_operation_bytes(bytes: &[u8]) -> OperationOutput {
    decode_operation_envelope(bytes)
}

fn execute_operation_json(json: &str) -> OperationOutput {
    let envelope = execute_operation_proto_json(json);
    match decode_operation_output(&envelope) {
        Ok(output) => output,
        Err(output) => output,
    }
}

fn execute_typed_request<M>(
    bytes: &[u8],
    wrap: fn(Box<M>) -> CoseOperationRequestBranch,
) -> OperationOutput
where
    M: Message,
{
    let request = match M::decode_from_slice(bytes) {
        Ok(request) => request,
        Err(_) => return execute_operation_bytes(bytes),
    };
    execute_operation_bytes(&operation_request(wrap(Box::new(request))).encode_to_vec())
}

fn execute_cose_sign1_create_request(bytes: &[u8]) -> OperationOutput {
    execute_typed_request(bytes, CoseOperationRequestBranch::Sign1Create)
}

fn execute_cose_sign1_create_detached_request(bytes: &[u8]) -> OperationOutput {
    execute_typed_request(bytes, CoseOperationRequestBranch::Sign1CreateDetached)
}

fn execute_cose_sign1_verify_request(bytes: &[u8]) -> OperationOutput {
    execute_typed_request(bytes, CoseOperationRequestBranch::Sign1Verify)
}

fn execute_cose_sign1_verify_detached_request(bytes: &[u8]) -> OperationOutput {
    execute_typed_request(bytes, CoseOperationRequestBranch::Sign1VerifyDetached)
}

fn assert_error_reason(output: &OperationOutput, expected: CoseErrorReason) {
    assert_eq!(output.status(), OperationOutputStatus::CoseError);
    let error = match decode_cose_error(output.bytes()) {
        Ok(error) => error,
        Err(_) => panic!("error protobuf must decode"),
    };
    assert_eq!(error_reason(&error), Some(expected));
}

fn assert_error_branch_and_reason(
    output: &OperationOutput,
    expected_branch: ExpectedErrorBranch,
    expected_reason: CoseErrorReason,
) {
    assert_eq!(output.status(), OperationOutputStatus::CoseError);
    let error = match decode_cose_error(output.bytes()) {
        Ok(error) => error,
        Err(_) => panic!("error protobuf must decode"),
    };
    assert_eq!(error_branch(&error), Some(expected_branch));
    assert_eq!(error_reason(&error), Some(expected_reason));
}

#[test]
fn cose_error_oneof_wire_bytes_are_stable() {
    let cases = [
        (
            reallyme_cose::wire::cose_error_proto::Error::Primitive(Box::new(CosePrimitiveError {
                reason: EnumValue::from(CoseErrorReason::Sign1InvalidSignature),
                __buffa_unknown_fields: Default::default(),
            })),
            &[0x0a, 0x03, 0x08, 0xa4, 0x03][..],
        ),
        (
            reallyme_cose::wire::cose_error_proto::Error::Provider(Box::new(
                reallyme_cose::wire::CoseProviderError {
                    reason: EnumValue::from(CoseErrorReason::CommonUnsupportedAlgorithm),
                    __buffa_unknown_fields: Default::default(),
                },
            )),
            &[0x12, 0x03, 0x08, 0xc8, 0x01][..],
        ),
        (
            reallyme_cose::wire::cose_error_proto::Error::Backend(Box::new(
                reallyme_cose::wire::CoseBackendError {
                    reason: EnumValue::from(CoseErrorReason::BackendInternal),
                    __buffa_unknown_fields: Default::default(),
                },
            )),
            &[0x1a, 0x03, 0x08, 0xad, 0x02][..],
        ),
    ];
    for (branch, expected) in cases {
        let error = CoseErrorProto {
            error: Some(branch),
            __buffa_unknown_fields: Default::default(),
        };
        assert_eq!(error.encode_to_vec(), expected);
    }
}

#[test]
fn sign1_wire_attached_happy_path_round_trips() {
    let key = gen_ed25519();
    let payload = sample_payload();
    let create = sign1_create_request(
        CoseSignatureAlgorithm::Ed25519,
        payload.clone(),
        key.private,
        test_kid().to_vec(),
        true,
    );
    let signed = execute_cose_sign1_create_request(&create.encode_to_vec());
    assert_eq!(signed.status(), OperationOutputStatus::Result);
    let create_result = CoseSign1CreateResult::decode_from_slice(signed.bytes())
        .expect("create result protobuf must decode");

    let verify = sign1_verify_request(create_result.cose_sign1.clone(), key.public, true);
    let verified = execute_cose_sign1_verify_request(&verify.encode_to_vec());
    assert_eq!(verified.status(), OperationOutputStatus::Result);
    let verify_result = CoseSign1VerifyResult::decode_from_slice(verified.bytes())
        .expect("verify result protobuf must decode");
    assert_eq!(verify_result.payload, payload);
    assert_eq!(verify_result.kid, test_kid());
}

#[test]
fn sign1_wire_external_aad_round_trips_and_wrong_aad_is_invalid_signature() {
    let key = gen_ed25519();
    let payload = sample_payload();
    let external_aad = b"reallyme-cose/wire-aad/v1".to_vec();
    let mut create = sign1_create_request(
        CoseSignatureAlgorithm::Ed25519,
        payload.clone(),
        key.private,
        test_kid().to_vec(),
        true,
    );
    create.external_aad = external_aad.clone();
    let signed = execute_cose_sign1_create_request(&create.encode_to_vec());
    assert_eq!(signed.status(), OperationOutputStatus::Result);
    let create_result = CoseSign1CreateResult::decode_from_slice(signed.bytes())
        .expect("create result protobuf must decode");

    let mut verify = sign1_verify_request(create_result.cose_sign1.clone(), key.public, true);
    verify.external_aad = external_aad;
    let verified = execute_cose_sign1_verify_request(&verify.encode_to_vec());
    assert_eq!(verified.status(), OperationOutputStatus::Result);

    verify.external_aad = b"wrong-wire-aad".to_vec();
    let rejected = execute_cose_sign1_verify_request(&verify.encode_to_vec());
    assert_error_reason(&rejected, CoseErrorReason::Sign1InvalidSignature);
}

#[test]
fn sign1_wire_expected_kid_binds_the_supplied_public_key() {
    let key = gen_ed25519();
    let create = sign1_create_request(
        CoseSignatureAlgorithm::Ed25519,
        sample_payload(),
        key.private,
        test_kid().to_vec(),
        true,
    );
    let signed = execute_cose_sign1_create_request(&create.encode_to_vec());
    assert_eq!(signed.status(), OperationOutputStatus::Result);
    let create_result = CoseSign1CreateResult::decode_from_slice(signed.bytes())
        .expect("create result protobuf must decode");

    let mut verify = sign1_verify_request(create_result.cose_sign1.clone(), key.public, true);
    verify.expected_kid = test_kid().to_vec();
    let verified = execute_cose_sign1_verify_request(&verify.encode_to_vec());
    assert_eq!(verified.status(), OperationOutputStatus::Result);

    verify.expected_kid = b"different-trusted-kid".to_vec();
    let rejected = execute_cose_sign1_verify_request(&verify.encode_to_vec());
    assert_error_branch_and_reason(
        &rejected,
        ExpectedErrorBranch::Primitive,
        CoseErrorReason::Sign1KidKeyMismatch,
    );
}

#[test]
fn execute_operation_proto_dispatches_attached_sign1_happy_path() {
    let key = gen_ed25519();
    let payload = sample_payload();
    let create = operation_request(CoseOperationRequestBranch::Sign1Create(Box::new(
        sign1_create_request(
            CoseSignatureAlgorithm::Ed25519,
            payload.clone(),
            key.private,
            test_kid().to_vec(),
            true,
        ),
    )));
    let signed = execute_operation_bytes(&create.encode_to_vec());
    assert_eq!(signed.status(), OperationOutputStatus::Result);
    let create_result = CoseSign1CreateResult::decode_from_slice(signed.bytes())
        .expect("create result protobuf must decode");

    let verify = operation_request(CoseOperationRequestBranch::Sign1Verify(Box::new(
        sign1_verify_request(create_result.cose_sign1.clone(), key.public, true),
    )));
    let verified = execute_operation_bytes(&verify.encode_to_vec());
    assert_eq!(verified.status(), OperationOutputStatus::Result);
    let verify_result = CoseSign1VerifyResult::decode_from_slice(verified.bytes())
        .expect("verify result protobuf must decode");
    assert_eq!(verify_result.payload, payload);
    assert_eq!(verify_result.kid, test_kid());
}

#[test]
fn execute_operation_proto_envelope_bytes_round_trip_status_and_payload() {
    let key = gen_ed25519();
    let request = operation_request(CoseOperationRequestBranch::Sign1Create(Box::new(
        sign1_create_request(
            CoseSignatureAlgorithm::Ed25519,
            sample_payload(),
            key.private,
            test_kid().to_vec(),
            true,
        ),
    )));

    let request_bytes = request.encode_to_vec();
    let envelope_bytes = execute_operation_proto(&request_bytes);
    let envelope = match decode_operation_output(envelope_bytes.as_slice()) {
        Ok(envelope) => envelope,
        Err(_) => panic!("result envelope protobuf must decode"),
    };
    assert_eq!(envelope.status(), OperationOutputStatus::Result);
    let create_result = CoseSign1CreateResult::decode_from_slice(envelope.bytes())
        .expect("enveloped create result protobuf must decode");
    assert!(!create_result.cose_sign1.is_empty());
}

#[test]
fn proto_json_and_binary_operation_match_for_generated_dispatcher() {
    let key = gen_ed25519();
    let request = operation_request(CoseOperationRequestBranch::Sign1Create(Box::new(
        sign1_create_request(
            CoseSignatureAlgorithm::Ed25519,
            sample_payload(),
            key.private,
            test_kid().to_vec(),
            true,
        ),
    )));

    let protobuf_output = execute_operation_bytes(&request.encode_to_vec());
    let json = serde_json::to_string(&request).expect("operation JSON must encode");
    let json_output = execute_operation_json(&json);
    assert_eq!(protobuf_output.status(), OperationOutputStatus::Result);
    assert_eq!(json_output.status(), OperationOutputStatus::Result);
    assert_eq!(protobuf_output.bytes(), json_output.bytes());
}

#[test]
fn execute_operation_proto_missing_operation_returns_structured_error() {
    let request = CoseOperationRequest {
        operation: None,
        __buffa_unknown_fields: Default::default(),
    };
    let output = execute_operation_bytes(&request.encode_to_vec());
    assert_error_branch_and_reason(
        &output,
        ExpectedErrorBranch::Primitive,
        CoseErrorReason::CommonInvalidParameter,
    );
}

#[test]
fn cose_key_dispatch_accepts_family_scoped_signature_and_key_agreement_selectors() {
    let ed25519 = gen_ed25519();
    let ed25519_request = CoseKeyFromPublicBytesRequest {
        algorithm: signature_identifier(CoseSignatureAlgorithm::Ed25519),
        public_key: ed25519.public,
        __buffa_unknown_fields: Default::default(),
    };
    let ed25519_output = execute_operation_bytes(
        &operation_request(CoseOperationRequestBranch::KeyFromPublicBytes(Box::new(
            ed25519_request,
        )))
        .encode_to_vec(),
    );
    assert_eq!(ed25519_output.status(), OperationOutputStatus::Result);
    let ed25519_result = CoseKeyBytesResult::decode_from_slice(ed25519_output.bytes())
        .expect("Ed25519 COSE_Key result must decode");
    assert!(!ed25519_result.key_bytes.is_empty());
    assert!(ed25519_result.has_signature_algorithm);
    assert_eq!(
        ed25519_result.signature_algorithm.as_known(),
        Some(CoseSignatureAlgorithm::Ed25519),
    );

    let (x25519_public, _) = reallyme_crypto::x25519::generate_x25519_keypair()
        .expect("X25519 test keypair generation must succeed");
    let x25519_request = CoseKeyFromPublicBytesRequest {
        algorithm: key_agreement_identifier(CoseKeyAgreementAlgorithm::X25519),
        public_key: x25519_public,
        __buffa_unknown_fields: Default::default(),
    };
    let x25519_output = execute_operation_bytes(
        &operation_request(CoseOperationRequestBranch::KeyFromPublicBytes(Box::new(
            x25519_request,
        )))
        .encode_to_vec(),
    );
    assert_eq!(x25519_output.status(), OperationOutputStatus::Result);
    let x25519_result = CoseKeyBytesResult::decode_from_slice(x25519_output.bytes())
        .expect("X25519 COSE_Key result must decode");
    assert!(!x25519_result.key_bytes.is_empty());
    assert!(!x25519_result.has_signature_algorithm);
}

#[test]
fn es256_wire_contract_preserves_the_exact_registration() {
    let key = gen_p256();
    let key_request = CoseKeyFromPublicBytesRequest {
        algorithm: signature_identifier(CoseSignatureAlgorithm::Es256),
        public_key: key.public.clone(),
        __buffa_unknown_fields: Default::default(),
    };
    let key_output = execute_operation_bytes(
        &operation_request(CoseOperationRequestBranch::KeyFromPublicBytes(Box::new(
            key_request,
        )))
        .encode_to_vec(),
    );
    assert_eq!(key_output.status(), OperationOutputStatus::Result);
    let key_result = CoseKeyBytesResult::decode_from_slice(key_output.bytes())
        .expect("ES256 COSE_Key result must decode");
    assert!(key_result.has_signature_algorithm);
    assert_eq!(
        key_result.signature_algorithm.as_known(),
        Some(CoseSignatureAlgorithm::Es256),
    );
    let parsed_key =
        cose_key_from_slice(&key_result.key_bytes).expect("wire-produced ES256 key must parse");
    assert_eq!(
        cose_key_signature_algorithm(&parsed_key).expect("ES256 metadata must validate"),
        Some(NativeSignatureAlgorithm::Es256),
    );

    let legacy_request = CoseKeyFromPublicBytesRequest {
        algorithm: signature_identifier(CoseSignatureAlgorithm::EcdsaP256Sha256),
        public_key: key.public.clone(),
        __buffa_unknown_fields: Default::default(),
    };
    let legacy_output = execute_operation_bytes(
        &operation_request(CoseOperationRequestBranch::KeyFromPublicBytes(Box::new(
            legacy_request,
        )))
        .encode_to_vec(),
    );
    let legacy_result = CoseKeyBytesResult::decode_from_slice(legacy_output.bytes())
        .expect("legacy P-256 result must decode");
    assert_eq!(
        legacy_result.signature_algorithm.as_known(),
        Some(CoseSignatureAlgorithm::Esp256),
    );

    let create = sign1_create_request(
        CoseSignatureAlgorithm::Es256,
        sample_payload(),
        key.private,
        test_kid().to_vec(),
        true,
    );
    let signed = execute_cose_sign1_create_request(&create.encode_to_vec());
    assert_eq!(signed.status(), OperationOutputStatus::Result);
    let create_result = CoseSign1CreateResult::decode_from_slice(signed.bytes())
        .expect("ES256 create result must decode");

    let mut verify = sign1_verify_request(create_result.cose_sign1.clone(), key.public, true);
    verify.allowed_algorithms = vec![signature_value(CoseSignatureAlgorithm::Es256)];
    let verified = execute_cose_sign1_verify_request(&verify.encode_to_vec());
    assert_eq!(verified.status(), OperationOutputStatus::Result);
    let verify_result = CoseSign1VerifyResult::decode_from_slice(verified.bytes())
        .expect("ES256 verify result must decode");
    assert_eq!(
        verify_result.algorithm.as_known(),
        Some(CoseSignatureAlgorithm::EcdsaP256Sha256),
    );
    assert!(verify_result.has_exact_signature_algorithm);
    assert_eq!(
        verify_result.exact_signature_algorithm.as_known(),
        Some(CoseSignatureAlgorithm::Es256),
    );
}

#[test]
fn binary_proto_decoder_rejects_unknown_length_delimited_fields() {
    let mut bytes = CoseOperationRequest::default().encode_to_vec();
    // Field 100, wire type 2, followed by bytes that must not be retained in
    // generated UnknownFields storage.
    bytes.extend_from_slice(&[0xa2, 0x06, 0x06]);
    bytes.extend_from_slice(b"secret");

    let output = execute_operation_bytes(&bytes);
    assert_error_reason(&output, CoseErrorReason::CommonMalformedProtobuf);
}

#[test]
fn ml_kem_wire_binary_and_proto_json_paths_preserve_authenticated_metadata() {
    const PLAINTEXT: &[u8] = b"protobuf operation ML-KEM plaintext";
    const EXTERNAL_AAD: &[u8] = b"protobuf operation external aad";

    for expected_mode in [CoseMlKemMode::Direct, CoseMlKemMode::KeyWrap] {
        let (public_key, private_key) = reallyme_crypto::ml_kem_512::generate_ml_kem_512_keypair()
            .expect("ML-KEM-512 key generation");
        let cose_key =
            cose_key_from_public_bytes(reallyme_crypto::core::Algorithm::MlKem512, &public_key)
                .expect("ML-KEM public COSE_Key conversion");
        let kid = derive_kid_from_cose_key_public(&cose_key).expect("ML-KEM public kid derivation");
        let encrypt = CoseMlKemEncryptRequest {
            kem_algorithm: kem_value(CoseKemAlgorithm::MlKem512),
            content_algorithm: EnumValue::from(CoseContentEncryptionAlgorithm::Aes128Gcm),
            recipient_public_key: public_key,
            recipient_kid: kid.to_vec(),
            plaintext: PLAINTEXT.to_vec(),
            external_aad: EXTERNAL_AAD.to_vec(),
            supp_priv_info: b"private-context".to_vec(),
            has_supp_priv_info: true,
            __buffa_unknown_fields: Default::default(),
        };
        let operation = if expected_mode == CoseMlKemMode::Direct {
            CoseOperationRequestBranch::MlKemEncryptDirect(Box::new(encrypt))
        } else {
            CoseOperationRequestBranch::MlKemEncryptKeyWrap(Box::new(encrypt))
        };
        let request = operation_request(operation);
        let encrypted = if expected_mode == CoseMlKemMode::Direct {
            execute_operation_bytes(&request.encode_to_vec())
        } else {
            let json = serde_json::to_string(&request).expect("ML-KEM request JSON must encode");
            execute_operation_json(&json)
        };
        assert_eq!(encrypted.status(), OperationOutputStatus::Result);
        let mut encrypted_result = CoseMlKemEncryptResult::decode_from_slice(encrypted.bytes())
            .expect("ML-KEM encrypt result must decode");

        let decrypt = CoseMlKemDecryptRequest {
            cose_encrypt: core::mem::take(&mut encrypted_result.cose_encrypt),
            recipient_private_key: private_key.to_vec(),
            expected_recipient_kid: kid.to_vec(),
            external_aad: EXTERNAL_AAD.to_vec(),
            supp_priv_info: b"private-context".to_vec(),
            has_supp_priv_info: true,
            __buffa_unknown_fields: Default::default(),
        };
        let decrypted = execute_operation_bytes(
            &operation_request(CoseOperationRequestBranch::MlKemDecrypt(Box::new(decrypt)))
                .encode_to_vec(),
        );
        assert_eq!(decrypted.status(), OperationOutputStatus::Result);
        let decrypted_result = CoseMlKemDecryptResult::decode_from_slice(decrypted.bytes())
            .expect("ML-KEM decrypt result must decode");
        assert_eq!(decrypted_result.plaintext, PLAINTEXT);
        assert_eq!(
            decrypted_result.content_algorithm.as_known(),
            Some(CoseContentEncryptionAlgorithm::Aes128Gcm)
        );
        assert_eq!(
            decrypted_result.kem_algorithm.as_known(),
            Some(CoseKemAlgorithm::MlKem512)
        );
        assert_eq!(decrypted_result.mode.as_known(), Some(expected_mode));
        assert_eq!(decrypted_result.recipient_kid.as_slice(), kid.as_slice());
    }
}

#[test]
fn ml_kem_wire_preserves_private_key_to_kid_mismatch() {
    let (public_key, _) = reallyme_crypto::ml_kem_512::generate_ml_kem_512_keypair()
        .expect("ML-KEM-512 recipient key generation");
    let (_, wrong_private_key) = reallyme_crypto::ml_kem_512::generate_ml_kem_512_keypair()
        .expect("ML-KEM-512 wrong key generation");
    let cose_key =
        cose_key_from_public_bytes(reallyme_crypto::core::Algorithm::MlKem512, &public_key)
            .expect("ML-KEM public COSE_Key conversion");
    let kid = derive_kid_from_cose_key_public(&cose_key).expect("ML-KEM public kid derivation");
    let encrypt = CoseMlKemEncryptRequest {
        kem_algorithm: kem_value(CoseKemAlgorithm::MlKem512),
        content_algorithm: EnumValue::from(CoseContentEncryptionAlgorithm::Aes128Gcm),
        recipient_public_key: public_key,
        recipient_kid: kid.to_vec(),
        plaintext: b"key binding".to_vec(),
        external_aad: Vec::new(),
        supp_priv_info: Vec::new(),
        has_supp_priv_info: false,
        __buffa_unknown_fields: Default::default(),
    };
    let encrypted = execute_operation_bytes(
        &operation_request(CoseOperationRequestBranch::MlKemEncryptDirect(Box::new(
            encrypt,
        )))
        .encode_to_vec(),
    );
    assert_eq!(encrypted.status(), OperationOutputStatus::Result);
    let mut encrypted_result = CoseMlKemEncryptResult::decode_from_slice(encrypted.bytes())
        .expect("ML-KEM encrypt result must decode");
    let decrypt = CoseMlKemDecryptRequest {
        cose_encrypt: core::mem::take(&mut encrypted_result.cose_encrypt),
        recipient_private_key: wrong_private_key.to_vec(),
        expected_recipient_kid: kid.to_vec(),
        external_aad: Vec::new(),
        supp_priv_info: Vec::new(),
        has_supp_priv_info: false,
        __buffa_unknown_fields: Default::default(),
    };
    let output = execute_operation_bytes(
        &operation_request(CoseOperationRequestBranch::MlKemDecrypt(Box::new(decrypt)))
            .encode_to_vec(),
    );

    assert_error_branch_and_reason(
        &output,
        ExpectedErrorBranch::Primitive,
        CoseErrorReason::EncryptKidMismatch,
    );
}

#[test]
fn ml_kem_wire_preserves_encrypt_specific_missing_kid_reason() {
    let (public_key, _) = reallyme_crypto::ml_kem_512::generate_ml_kem_512_keypair()
        .expect("ML-KEM-512 recipient key generation");
    let request = CoseMlKemEncryptRequest {
        kem_algorithm: kem_value(CoseKemAlgorithm::MlKem512),
        content_algorithm: EnumValue::from(CoseContentEncryptionAlgorithm::Aes128Gcm),
        recipient_public_key: public_key,
        recipient_kid: Vec::new(),
        plaintext: b"missing kid".to_vec(),
        external_aad: Vec::new(),
        supp_priv_info: Vec::new(),
        has_supp_priv_info: false,
        __buffa_unknown_fields: Default::default(),
    };
    let output = execute_operation_bytes(
        &operation_request(CoseOperationRequestBranch::MlKemEncryptDirect(Box::new(
            request,
        )))
        .encode_to_vec(),
    );

    assert_error_branch_and_reason(
        &output,
        ExpectedErrorBranch::Primitive,
        CoseErrorReason::EncryptMissingKid,
    );
}

#[test]
fn ml_kem_wire_preserves_encrypt_specific_unprotected_header_reason() {
    let (public_key, private_key) = reallyme_crypto::ml_kem_512::generate_ml_kem_512_keypair()
        .expect("ML-KEM-512 recipient key generation");
    let cose_key =
        cose_key_from_public_bytes(reallyme_crypto::core::Algorithm::MlKem512, &public_key)
            .expect("ML-KEM public COSE_Key conversion");
    let kid = derive_kid_from_cose_key_public(&cose_key).expect("ML-KEM public kid derivation");
    let encrypt = CoseMlKemEncryptRequest {
        kem_algorithm: kem_value(CoseKemAlgorithm::MlKem512),
        content_algorithm: EnumValue::from(CoseContentEncryptionAlgorithm::Aes128Gcm),
        recipient_public_key: public_key,
        recipient_kid: kid.to_vec(),
        plaintext: b"protected algorithm".to_vec(),
        external_aad: Vec::new(),
        supp_priv_info: Vec::new(),
        has_supp_priv_info: false,
        __buffa_unknown_fields: Default::default(),
    };
    let encrypted = execute_operation_bytes(
        &operation_request(CoseOperationRequestBranch::MlKemEncryptDirect(Box::new(
            encrypt,
        )))
        .encode_to_vec(),
    );
    assert_eq!(encrypted.status(), OperationOutputStatus::Result);
    let encrypted_result = CoseMlKemEncryptResult::decode_from_slice(encrypted.bytes())
        .expect("ML-KEM encrypt result must decode");
    let mut malformed = CoseEncrypt::from_tagged_slice(&encrypted_result.cose_encrypt)
        .expect("generated COSE_Encrypt must decode");
    let recipient = malformed
        .recipients
        .first_mut()
        .expect("generated COSE_Encrypt has one recipient");
    recipient.unprotected.alg = recipient.protected.header.alg.take();
    recipient.protected.original_data = None;
    let malformed = malformed
        .to_tagged_vec()
        .expect("malformed COSE_Encrypt must encode");
    let decrypt = CoseMlKemDecryptRequest {
        cose_encrypt: malformed,
        recipient_private_key: private_key.to_vec(),
        expected_recipient_kid: kid.to_vec(),
        external_aad: Vec::new(),
        supp_priv_info: Vec::new(),
        has_supp_priv_info: false,
        __buffa_unknown_fields: Default::default(),
    };
    let output = execute_operation_bytes(
        &operation_request(CoseOperationRequestBranch::MlKemDecrypt(Box::new(decrypt)))
            .encode_to_vec(),
    );

    assert_error_branch_and_reason(
        &output,
        ExpectedErrorBranch::Primitive,
        CoseErrorReason::EncryptUnprotectedHeaderNotAllowed,
    );
}

include!("wire_tests/boundary_tests.rs");
