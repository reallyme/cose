// SPDX-FileCopyrightText: 2026 ReallyMe LLC
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
        b"kid".to_vec(),
        true,
    );
    let signed = execute_cose_sign1_create_request(&create.encode_to_vec());
    assert_eq!(signed.status(), OperationOutputStatus::Result);
    let mut result = CoseSign1CreateResult::decode_from_slice(signed.bytes())
        .expect("signed fixture must decode");

    let mut verify =
        sign1_verify_request(core::mem::take(&mut result.cose_sign1), key.public, true);
    verify.allowed_algorithms = vec![EnumValue::from(CoseSignatureAlgorithm::Es256)];
    verify.public_key_algorithm = EnumValue::from(CoseSignatureAlgorithm::Esp256);
    let output = execute_cose_sign1_verify_request(&verify.encode_to_vec());
    assert_error_reason(&output, CoseErrorReason::CommonUnsupportedAlgorithm);
}

#[test]
fn wire_signing_rejects_a_present_empty_kid() {
    let key = gen_ed25519();
    let request = sign1_create_request(
        CoseSignatureAlgorithm::Ed25519,
        b"payload".to_vec(),
        key.private,
        Vec::new(),
        true,
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
fn wire_encrypt_and_decrypt_reject_false_supp_priv_info_flags_with_bytes() {
    let encrypt = CoseMlKemEncryptRequest {
        kem_algorithm: EnumValue::from(CoseKemAlgorithm::MlKem512),
        content_algorithm: EnumValue::from(CoseContentEncryptionAlgorithm::Aes128Gcm),
        recipient_public_key: Vec::new(),
        recipient_kid: Vec::new(),
        plaintext: Vec::new(),
        external_aad: Vec::new(),
        supp_priv_info: b"unexpected".to_vec(),
        has_supp_priv_info: false,
        __buffa_unknown_fields: Default::default(),
    };
    let encrypted = execute_operation_bytes(
        &operation_request(CoseOperationRequestBranch::MlKemEncryptDirect(Box::new(
            encrypt,
        )))
        .encode_to_vec(),
    );
    assert_eq!(encrypted.status(), OperationOutputStatus::CoseError);
    assert_error_reason(&encrypted, CoseErrorReason::CommonInvalidParameter);

    let decrypt = CoseMlKemDecryptRequest {
        cose_encrypt: Vec::new(),
        recipient_private_key: Vec::new(),
        expected_recipient_kid: Vec::new(),
        external_aad: Vec::new(),
        supp_priv_info: b"unexpected".to_vec(),
        has_supp_priv_info: false,
        __buffa_unknown_fields: Default::default(),
    };
    let decrypted = execute_operation_bytes(
        &operation_request(CoseOperationRequestBranch::MlKemDecrypt(Box::new(decrypt)))
            .encode_to_vec(),
    );
    assert_error_reason(&decrypted, CoseErrorReason::CommonInvalidParameter);
}
