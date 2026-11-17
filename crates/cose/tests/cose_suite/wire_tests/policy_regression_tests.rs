// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wire policy flags must not silently discard caller intent.

use buffa::Message;
use reallyme_cose::wire::{
    CoseContentEncryptionAlgorithm, CoseErrorReason, CoseKemAlgorithm, CoseMlKemDecryptRequest,
    CoseMlKemEncryptRequest, CoseSign1CreateResult, CoseSignatureAlgorithm,
};

use crate::support::{gen_ed25519, gen_p256, OperationOutputStatus};

use super::{
    assert_error_reason, execute_cose_sign1_create_request, execute_cose_sign1_verify_request,
    execute_operation_bytes, operation_request, sign1_create_request, sign1_verify_request,
    CoseOperationRequestBranch, EnumValue,
};

#[test]
fn wire_public_key_registration_must_match_protected_algorithm() {
    let key = gen_p256();
    let create = sign1_create_request(
        CoseSignatureAlgorithm::Es256,
        b"payload".to_vec(),
        key.private,
        Some(b"kid".to_vec()),
    );
    let signed = execute_cose_sign1_create_request(&create.encode_to_vec());
    assert_eq!(signed.status(), OperationOutputStatus::Result);
    let mut result = CoseSign1CreateResult::decode_from_slice(signed.bytes())
        .expect("signed fixture must decode");

    let mut verify =
        sign1_verify_request(core::mem::take(&mut result.cose_sign1), key.public, true);
    verify.allowed_algorithms = vec![EnumValue::from(CoseSignatureAlgorithm::Es256)].into();
    verify.public_key_algorithm = EnumValue::from(CoseSignatureAlgorithm::Esp256);
    let output = execute_cose_sign1_verify_request(&verify.encode_to_vec());
    assert_error_reason(&output, CoseErrorReason::KeyAlgorithmMismatch);
}

#[test]
fn wire_signing_rejects_a_present_empty_kid() {
    let key = gen_ed25519();
    let request = sign1_create_request(
        CoseSignatureAlgorithm::Ed25519,
        b"payload".to_vec(),
        key.private,
        Some(Vec::new()),
    );
    let output = execute_cose_sign1_create_request(&request.encode_to_vec());
    assert_error_reason(&output, CoseErrorReason::CommonInvalidFormat);
}

#[test]
fn wire_require_kid_rejects_an_omitted_kid() {
    let key = gen_ed25519();
    let signed =
        reallyme_cose::cose_sign1(key.alg, b"payload", &key.private, None).expect("test signature");
    let request = sign1_verify_request(signed.to_vec(), key.public, true);
    let output = execute_cose_sign1_verify_request(&request.encode_to_vec());
    assert_error_reason(&output, CoseErrorReason::Sign1MissingKid);
}

#[test]
fn wire_encrypt_and_decrypt_reject_retired_presence_flags() {
    let encrypt = CoseMlKemEncryptRequest {
        kem_algorithm: EnumValue::from(CoseKemAlgorithm::MlKem512),
        content_algorithm: EnumValue::from(CoseContentEncryptionAlgorithm::Aes128Gcm),
        recipient_public_key: Vec::new().into(),
        recipient_kid: Vec::new().into(),
        plaintext: Vec::new().into(),
        external_aad: Vec::new().into(),
        supp_priv_info: Some(b"private-context".to_vec().into()),
    };
    let mut legacy = encrypt.encode_to_vec();
    legacy.extend_from_slice(&[0x40, 0x01]);
    let encrypted = execute_operation_bytes(&legacy_operation(
        operation_request(CoseOperationRequestBranch::MlKemEncryptDirect(
            Box::default(),
        )),
        &legacy,
    ));
    assert_eq!(encrypted.status(), OperationOutputStatus::CoseError);
    assert_error_reason(&encrypted, CoseErrorReason::CommonMalformedProtobuf);

    let decrypt = CoseMlKemDecryptRequest {
        cose_encrypt: Vec::new().into(),
        recipient_private_key: Vec::new().into(),
        expected_recipient_kid: Vec::new().into(),
        external_aad: Vec::new().into(),
        supp_priv_info: Some(b"private-context".to_vec().into()),
    };
    let mut legacy = decrypt.encode_to_vec();
    legacy.extend_from_slice(&[0x30, 0x01]);
    let decrypted = execute_operation_bytes(&legacy_operation(
        operation_request(CoseOperationRequestBranch::MlKemDecrypt(Box::default())),
        &legacy,
    ));
    assert_error_reason(&decrypted, CoseErrorReason::CommonMalformedProtobuf);
}

// Keep the offending bytes through admission: decoding and re-encoding a
// message with unknown storage disabled would discard the retired flag.
fn legacy_operation(request: reallyme_cose::wire::CoseOperationRequest, child: &[u8]) -> Vec<u8> {
    let mut encoded = request.encode_to_vec();
    assert_eq!(encoded.pop(), Some(0));
    assert!(child.len() < 128);
    encoded.push(u8::try_from(child.len()).expect("bounded fixture length"));
    encoded.extend_from_slice(child);
    encoded
}
