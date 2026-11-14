// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

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
fn ml_kem_wire_rejects_unknown_content_algorithm_without_fallback() {
    let (public_key, _) = reallyme_crypto::ml_kem_512::generate_ml_kem_512_keypair()
        .expect("ML-KEM-512 key generation");
    let request = CoseMlKemEncryptRequest {
        kem_algorithm: kem_value(CoseKemAlgorithm::MlKem512),
        content_algorithm: EnumValue::from(999_999),
        recipient_public_key: public_key.into(),
        recipient_kid: b"recipient".to_vec().into(),
        plaintext: b"plaintext".to_vec().into(),
        external_aad: Vec::new().into(),
        supp_priv_info: None,

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
        CoseErrorReason::CommonInvalidParameter,
    );
}

#[test]
fn ml_kem_wire_rejects_known_but_unsupported_hybrid_without_fallback() {
    let request = CoseMlKemEncryptRequest {
        kem_algorithm: kem_value(CoseKemAlgorithm::XWing768),
        content_algorithm: EnumValue::from(CoseContentEncryptionAlgorithm::Aes128Gcm),
        recipient_public_key: Vec::new().into(),
        recipient_kid: Vec::new().into(),
        plaintext: Vec::new().into(),
        external_aad: Vec::new().into(),
        supp_priv_info: None,

    };
    let output = execute_operation_bytes(
        &operation_request(CoseOperationRequestBranch::MlKemEncryptDirect(Box::new(
            request,
        )))
        .encode_to_vec(),
    );
    assert_error_branch_and_reason(
        &output,
        ExpectedErrorBranch::Provider,
        CoseErrorReason::CommonUnsupportedAlgorithm,
    );
}

#[test]
fn sign1_wire_detached_rejects_wrong_payload_as_invalid_signature() {
    let key = gen_ed25519();
    let create = sign1_create_detached_request(
        CoseSignatureAlgorithm::Ed25519,
        sample_payload(),
        key.private,
        Some(test_kid().to_vec()),
    );
    let signed = execute_cose_sign1_create_detached_request(&create.encode_to_vec());
    assert_eq!(signed.status(), OperationOutputStatus::Result);
    let create_result = CoseSign1CreateResult::decode_from_slice(signed.bytes())
        .expect("create result protobuf must decode");

    let verify = sign1_verify_detached_request(
        create_result.cose_sign1.clone(),
        b"wrong payload".to_vec(),
        key.public,
        true,
    );
    let output = execute_cose_sign1_verify_detached_request(&verify.encode_to_vec());
    assert_error_reason(&output, CoseErrorReason::Sign1InvalidSignature);
}

#[test]
fn invalid_private_key_length_is_not_reported_as_signature_failure() {
    let create = sign1_create_request(
        CoseSignatureAlgorithm::Ed25519,
        sample_payload(),
        vec![0],
        None,
    );
    let output = execute_cose_sign1_create_request(&create.encode_to_vec());
    assert_error_reason(&output, CoseErrorReason::KeyInvalidKeyMaterial);
}

#[test]
fn unknown_signature_algorithm_is_invalid_without_fallback() {
    let mut request = sign1_create_request(
        CoseSignatureAlgorithm::Ed25519,
        sample_payload(),
        vec![0; 32],
        None,
    );
    // The pre-release compact value is deliberately reserved. Decoding it as
    // another algorithm would silently reinterpret an old wire request.
    request.algorithm = EnumValue::from(1);
    let output = execute_cose_sign1_create_request(&request.encode_to_vec());
    assert_eq!(output.status(), OperationOutputStatus::CoseError);
    let error = match decode_cose_error(output.bytes()) {
        Ok(error) => error,
        Err(_) => panic!("error protobuf must decode"),
    };
    assert!(matches!(
        error.error,
        Some(reallyme_cose::wire::cose_error_proto::Error::Primitive(_))
    ));
    assert_eq!(
        error_reason(&error),
        Some(CoseErrorReason::CommonInvalidParameter)
    );
}

#[test]
fn malformed_protobuf_returns_structured_error_bytes() {
    let output = execute_cose_sign1_create_request(&[0xff]);
    assert_error_reason(&output, CoseErrorReason::CommonMalformedProtobuf);
}

#[test]
fn oversized_protobuf_returns_resource_limit_error() {
    let oversized = vec![0_u8; MAX_COSE_PROTO_MESSAGE_BYTES + 1];
    let output = execute_cose_sign1_create_request(&oversized);
    assert_error_reason(&output, CoseErrorReason::CommonResourceLimitExceeded);
}

#[test]
fn proto_sign1_create_limit_cannot_exceed_wire_message_cap() {
    let mut request = sign1_create_request(
        CoseSignatureAlgorithm::Ed25519,
        b"payload".to_vec(),
        vec![7; 32],
        None,
    );
    request.options = buffa::MessageField::some(CoseSign1Options {
protected_type:Default::default(),
limits:Default::default(),
        tag: false,
        max_cose_sign1_bytes: u64::try_from(MAX_COSE_PROTO_MESSAGE_BYTES + 1).unwrap_or(u64::MAX),
        x5chain: buffa::MessageField::none(),
        x5chain_header_placement: buffa::EnumValue::from(0),

    });

    let output = execute_cose_sign1_create_request(&request.encode_to_vec());
    assert_error_reason(&output, CoseErrorReason::CommonResourceLimitExceeded);
}

#[test]
fn proto_verify_limits_cannot_exceed_wire_message_cap() {
    let mut attached = sign1_verify_request(Vec::new(), Vec::new(), false);
    attached.max_cose_sign1_bytes =
        u64::try_from(MAX_COSE_PROTO_MESSAGE_BYTES + 1).unwrap_or(u64::MAX);

    let output = execute_cose_sign1_verify_request(&attached.encode_to_vec());
    assert_error_reason(&output, CoseErrorReason::CommonResourceLimitExceeded);

    let mut detached = sign1_verify_detached_request(Vec::new(), Vec::new(), Vec::new(), false);
    detached.max_detached_payload_bytes =
        u64::try_from(MAX_COSE_PROTO_MESSAGE_BYTES + 1).unwrap_or(u64::MAX);

    let output = execute_cose_sign1_verify_detached_request(&detached.encode_to_vec());
    assert_error_reason(&output, CoseErrorReason::CommonResourceLimitExceeded);
}

#[test]
fn missing_error_branch_is_not_accepted_as_structured_error() {
    let response = match decode_cose_error(&[]) {
        Ok(_) => panic!("empty error envelope must fail"),
        Err(response) => response,
    };
    let output = match decode_operation_output(&response.encode_to_vec()) {
        Ok(output) | Err(output) => output,
    };
    assert_error_branch_and_reason(
        &output,
        ExpectedErrorBranch::Primitive,
        CoseErrorReason::CommonMalformedProtobuf,
    );
}

#[test]
fn json_request_adapter_preserves_protobuf_bytes() {
    let request = sign1_create_request(
        CoseSignatureAlgorithm::Ed25519,
        b"abc".to_vec(),
        vec![7; 32],
        Some(b"kid".to_vec()),
    );
    let json = serde_json::to_string(&request).expect("request JSON must encode");
    assert!(json.contains("\"payload\":\"YWJj\""));
    let decoded: CoseSign1CreateRequest =
        serde_json::from_str(&json).expect("request JSON must decode");
    assert_eq!(decoded.encode_to_vec(), request.encode_to_vec());
}

#[test]
fn operation_proto_json_rejects_unknown_nested_fields() {
    let output = execute_operation_json(
        r#"{"sign1Create":{"algorithm":"COSE_SIGNATURE_ALGORITHM_ED25519","payload":"","privateKey":"","kid":"","hasKid":false,"externalAad":"","private_key_typo":""}}"#,
    );
    assert_error_reason(&output, CoseErrorReason::CommonMalformedJson);
}
