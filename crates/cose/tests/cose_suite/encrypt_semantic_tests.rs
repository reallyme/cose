// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use buffa::{EnumValue, Message};
use reallyme_cose::wire::cose_error_proto;
use reallyme_cose::wire::cose_operation_request::Operation;
use reallyme_cose::wire::{
    decode_cose_error, execute_operation_proto, execute_operation_proto_json,
    CoseContentEncryptionAlgorithm as ProtoContentAlgorithm, CoseErrorReason, CoseKemAlgorithm,
    CoseMlKemDecryptRequest as ProtoDecryptRequest, CoseMlKemDecryptResult,
    CoseMlKemEncryptRequest as ProtoEncryptRequest, CoseMlKemEncryptResult,
    CoseMlKemMode as ProtoMode, CoseOperationRequest,
};
use reallyme_cose::{
    cose_decrypt_ml_kem_with_external_aad, cose_encrypt_ml_kem_direct_with_external_aad,
    cose_encrypt_ml_kem_key_wrap_with_external_aad, cose_key_from_public_bytes,
    derive_kid_from_cose_key_public, Algorithm, CoseContentEncryptionAlgorithm, CoseError,
    CoseMlKemAlgorithm, CoseMlKemDecryptRequest, CoseMlKemEncryptRequest, CoseMlKemMode,
    DecryptedCoseEncrypt,
};
use zeroize::Zeroizing;

use super::support::{decode_operation_output, OperationOutputStatus};

const PLAINTEXT: &[u8] = b"authenticated COSE plaintext";
const EXTERNAL_AAD: &[u8] = b"COSE external aad";
const SUPP_PRIV_INFO: &[u8] = b"COSE private context";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ErrorBranch {
    Primitive,
    Provider,
    Backend,
}

struct MlKemFixture {
    public_key: Zeroizing<Vec<u8>>,
    private_key: Zeroizing<Vec<u8>>,
    kid: Zeroizing<Vec<u8>>,
}

#[test]
fn ml_kem_operations_match_native_binary_and_proto_json_semantics() {
    let MlKemFixture {
        public_key,
        private_key,
        kid,
    } = keypair();

    for mode in [CoseMlKemMode::Direct, CoseMlKemMode::KeyWrap] {
        let native_request = native_encrypt_request(&public_key, &kid);
        let native_ciphertext = match mode {
            CoseMlKemMode::Direct => {
                cose_encrypt_ml_kem_direct_with_external_aad(&native_request, EXTERNAL_AAD)
            }
            CoseMlKemMode::KeyWrap => {
                cose_encrypt_ml_kem_key_wrap_with_external_aad(&native_request, EXTERNAL_AAD)
            }
            _ => return,
        }
        .expect("native ML-KEM encryption must succeed");
        assert_native_decryption(&native_ciphertext, &private_key, &kid, mode);

        let binary_ciphertext = execute_encrypt_binary(encrypt_operation(
            mode,
            proto_encrypt_request(&public_key, &kid),
        ));
        assert_native_decryption(&binary_ciphertext, &private_key, &kid, mode);

        let json_ciphertext = execute_encrypt_json(encrypt_operation(
            mode,
            proto_encrypt_request(&public_key, &kid),
        ));
        assert_native_decryption(&json_ciphertext, &private_key, &kid, mode);

        let decrypted = execute_decrypt_both(
            proto_decrypt_request(&native_ciphertext, &private_key, &kid, EXTERNAL_AAD),
            proto_decrypt_request(&native_ciphertext, &private_key, &kid, EXTERNAL_AAD),
        );
        assert_eq!(decrypted.plaintext, PLAINTEXT);
        assert_eq!(
            decrypted.content_algorithm.as_known(),
            Some(ProtoContentAlgorithm::Aes128Gcm)
        );
        assert_eq!(
            decrypted.kem_algorithm.as_known(),
            Some(CoseKemAlgorithm::MlKem512)
        );
        assert_eq!(decrypted.mode.as_known(), Some(proto_mode(mode)));
        assert_eq!(decrypted.recipient_kid, kid.as_slice());
    }
}

#[test]
fn ml_kem_failures_preserve_native_and_exact_wire_semantics() {
    let MlKemFixture {
        public_key,
        private_key,
        kid,
    } = keypair();
    let missing_kid_request = CoseMlKemEncryptRequest::new(
        CoseMlKemAlgorithm::MlKem512,
        CoseContentEncryptionAlgorithm::Aes128Gcm,
        &public_key,
        &[],
        PLAINTEXT,
        Some(SUPP_PRIV_INFO),
    );
    assert_native_error(
        cose_encrypt_ml_kem_direct_with_external_aad(&missing_kid_request, EXTERNAL_AAD),
        CoseError::MissingKid,
    );
    assert_error(
        Operation::MlKemEncryptDirect(Box::new(proto_encrypt_request(&public_key, &[]))),
        Operation::MlKemEncryptDirect(Box::new(proto_encrypt_request(&public_key, &[]))),
        ErrorBranch::Primitive,
        CoseErrorReason::EncryptMissingKid,
    );

    let invalid_public_key = Zeroizing::new(vec![0_u8; 31]);
    let invalid_key_request = native_encrypt_request(&invalid_public_key, &kid);
    assert_native_error(
        cose_encrypt_ml_kem_direct_with_external_aad(&invalid_key_request, EXTERNAL_AAD),
        CoseError::InvalidKeyMaterial,
    );
    assert_error(
        Operation::MlKemEncryptDirect(Box::new(proto_encrypt_request(&invalid_public_key, &kid))),
        Operation::MlKemEncryptDirect(Box::new(proto_encrypt_request(&invalid_public_key, &kid))),
        ErrorBranch::Primitive,
        CoseErrorReason::KeyInvalidKeyMaterial,
    );

    let native_ciphertext = cose_encrypt_ml_kem_direct_with_external_aad(
        &native_encrypt_request(&public_key, &kid),
        EXTERNAL_AAD,
    )
    .expect("valid direct fixture must encrypt");
    let invalid_private_key = Zeroizing::new(vec![0_u8; 63]);
    assert_native_error(
        cose_decrypt_ml_kem_with_external_aad(
            &native_decrypt_request(&native_ciphertext, &invalid_private_key, &kid),
            EXTERNAL_AAD,
        ),
        CoseError::InvalidKeyMaterial,
    );
    assert_error(
        Operation::MlKemDecrypt(Box::new(proto_decrypt_request(
            &native_ciphertext,
            &invalid_private_key,
            &kid,
            EXTERNAL_AAD,
        ))),
        Operation::MlKemDecrypt(Box::new(proto_decrypt_request(
            &native_ciphertext,
            &invalid_private_key,
            &kid,
            EXTERNAL_AAD,
        ))),
        ErrorBranch::Primitive,
        CoseErrorReason::KeyInvalidKeyMaterial,
    );

    let wrong_kid = Zeroizing::new(vec![0xA5_u8; kid.len()]);
    assert_native_error(
        cose_decrypt_ml_kem_with_external_aad(
            &native_decrypt_request(&native_ciphertext, &private_key, &wrong_kid),
            EXTERNAL_AAD,
        ),
        CoseError::KidMismatch,
    );
    assert_error(
        Operation::MlKemDecrypt(Box::new(proto_decrypt_request(
            &native_ciphertext,
            &private_key,
            &wrong_kid,
            EXTERNAL_AAD,
        ))),
        Operation::MlKemDecrypt(Box::new(proto_decrypt_request(
            &native_ciphertext,
            &private_key,
            &wrong_kid,
            EXTERNAL_AAD,
        ))),
        ErrorBranch::Primitive,
        CoseErrorReason::EncryptKidMismatch,
    );

    assert_native_error(
        cose_decrypt_ml_kem_with_external_aad(
            &native_decrypt_request(&native_ciphertext, &private_key, &kid),
            b"wrong external aad",
        ),
        CoseError::AuthenticationFailed,
    );
    assert_error(
        Operation::MlKemDecrypt(Box::new(proto_decrypt_request(
            &native_ciphertext,
            &private_key,
            &kid,
            b"wrong external aad",
        ))),
        Operation::MlKemDecrypt(Box::new(proto_decrypt_request(
            &native_ciphertext,
            &private_key,
            &kid,
            b"wrong external aad",
        ))),
        ErrorBranch::Primitive,
        CoseErrorReason::EncryptAuthenticationFailed,
    );

    let mut unsupported = proto_encrypt_request(&public_key, &kid);
    unsupported.kem_algorithm = EnumValue::from(CoseKemAlgorithm::XWing768);
    let mut unsupported_json = proto_encrypt_request(&public_key, &kid);
    unsupported_json.kem_algorithm = EnumValue::from(CoseKemAlgorithm::XWing768);
    assert_error(
        Operation::MlKemEncryptDirect(Box::new(unsupported)),
        Operation::MlKemEncryptDirect(Box::new(unsupported_json)),
        ErrorBranch::Provider,
        CoseErrorReason::CommonUnsupportedAlgorithm,
    );
}

fn keypair() -> MlKemFixture {
    let (public_key, private_key) = reallyme_crypto::ml_kem_512::generate_ml_kem_512_keypair()
        .expect("ML-KEM-512 key generation must succeed");
    let public_key = Zeroizing::new(public_key);
    let cose_key = cose_key_from_public_bytes(Algorithm::MlKem512, &public_key)
        .expect("ML-KEM public COSE_Key must construct");
    let kid =
        derive_kid_from_cose_key_public(&cose_key).expect("ML-KEM kid derivation must succeed");
    MlKemFixture {
        public_key,
        private_key,
        kid,
    }
}

fn native_encrypt_request<'a>(public_key: &'a [u8], kid: &'a [u8]) -> CoseMlKemEncryptRequest<'a> {
    CoseMlKemEncryptRequest::new(
        CoseMlKemAlgorithm::MlKem512,
        CoseContentEncryptionAlgorithm::Aes128Gcm,
        public_key,
        kid,
        PLAINTEXT,
        Some(SUPP_PRIV_INFO),
    )
}

fn native_decrypt_request<'a>(
    cose_encrypt: &'a [u8],
    private_key: &'a [u8],
    kid: &'a [u8],
) -> CoseMlKemDecryptRequest<'a> {
    CoseMlKemDecryptRequest::new(cose_encrypt, private_key, kid, Some(SUPP_PRIV_INFO))
}

fn proto_encrypt_request(public_key: &[u8], kid: &[u8]) -> ProtoEncryptRequest {
    ProtoEncryptRequest {
        kem_algorithm: EnumValue::from(CoseKemAlgorithm::MlKem512),
        content_algorithm: EnumValue::from(ProtoContentAlgorithm::Aes128Gcm),
        recipient_public_key: public_key.to_vec(),
        recipient_kid: kid.to_vec(),
        plaintext: PLAINTEXT.to_vec(),
        external_aad: EXTERNAL_AAD.to_vec(),
        supp_priv_info: SUPP_PRIV_INFO.to_vec(),
        has_supp_priv_info: true,
        __buffa_unknown_fields: Default::default(),
    }
}

fn proto_decrypt_request(
    cose_encrypt: &[u8],
    private_key: &[u8],
    kid: &[u8],
    external_aad: &[u8],
) -> ProtoDecryptRequest {
    ProtoDecryptRequest {
        cose_encrypt: cose_encrypt.to_vec(),
        recipient_private_key: private_key.to_vec(),
        expected_recipient_kid: kid.to_vec(),
        external_aad: external_aad.to_vec(),
        supp_priv_info: SUPP_PRIV_INFO.to_vec(),
        has_supp_priv_info: true,
        __buffa_unknown_fields: Default::default(),
    }
}

fn encrypt_operation(mode: CoseMlKemMode, request: ProtoEncryptRequest) -> Operation {
    match mode {
        CoseMlKemMode::Direct => Operation::MlKemEncryptDirect(Box::new(request)),
        CoseMlKemMode::KeyWrap => Operation::MlKemEncryptKeyWrap(Box::new(request)),
        _ => Operation::MlKemEncryptDirect(Box::new(request)),
    }
}

fn proto_mode(mode: CoseMlKemMode) -> ProtoMode {
    match mode {
        CoseMlKemMode::Direct => ProtoMode::Direct,
        CoseMlKemMode::KeyWrap => ProtoMode::KeyWrap,
        _ => ProtoMode::Unspecified,
    }
}

fn assert_native_decryption(
    cose_encrypt: &[u8],
    private_key: &[u8],
    kid: &[u8],
    expected_mode: CoseMlKemMode,
) {
    let decrypted = cose_decrypt_ml_kem_with_external_aad(
        &native_decrypt_request(cose_encrypt, private_key, kid),
        EXTERNAL_AAD,
    )
    .expect("native ML-KEM decryption must succeed");
    assert_decrypted(&decrypted, expected_mode, kid);
}

fn assert_decrypted(decrypted: &DecryptedCoseEncrypt, expected_mode: CoseMlKemMode, kid: &[u8]) {
    assert_eq!(decrypted.plaintext.as_slice(), PLAINTEXT);
    assert_eq!(
        decrypted.content_algorithm,
        CoseContentEncryptionAlgorithm::Aes128Gcm
    );
    assert_eq!(decrypted.kem_algorithm, CoseMlKemAlgorithm::MlKem512);
    assert_eq!(decrypted.mode, expected_mode);
    assert_eq!(decrypted.kid.as_slice(), kid);
}

fn execute_encrypt_binary(operation: Operation) -> Zeroizing<Vec<u8>> {
    decode_encrypt_result(process_binary(operation))
}

fn execute_encrypt_json(operation: Operation) -> Zeroizing<Vec<u8>> {
    decode_encrypt_result(process_json(operation))
}

fn decode_encrypt_result(payload: Zeroizing<Vec<u8>>) -> Zeroizing<Vec<u8>> {
    let mut result = CoseMlKemEncryptResult::decode_from_slice(&payload)
        .expect("ML-KEM encrypt result must decode");
    Zeroizing::new(core::mem::take(&mut result.cose_encrypt))
}

fn execute_decrypt_both(
    binary_request: ProtoDecryptRequest,
    json_request: ProtoDecryptRequest,
) -> CoseMlKemDecryptResult {
    let binary_operation = Operation::MlKemDecrypt(Box::new(binary_request));
    let json_operation = Operation::MlKemDecrypt(Box::new(json_request));
    let binary_envelope = process_binary_envelope(binary_operation);
    let json_envelope = process_json_envelope(json_operation);
    assert_eq!(binary_envelope.as_slice(), json_envelope.as_slice());
    let payload = decode_success(&binary_envelope);
    CoseMlKemDecryptResult::decode_from_slice(&payload).expect("ML-KEM decrypt result must decode")
}

fn process_binary(operation: Operation) -> Zeroizing<Vec<u8>> {
    decode_success(&process_binary_envelope(operation))
}

fn process_json(operation: Operation) -> Zeroizing<Vec<u8>> {
    decode_success(&process_json_envelope(operation))
}

fn process_binary_envelope(operation: Operation) -> Zeroizing<Vec<u8>> {
    let request = operation_request(operation);
    execute_operation_proto(&Zeroizing::new(request.encode_to_vec()))
}

fn process_json_envelope(operation: Operation) -> Zeroizing<Vec<u8>> {
    let request = operation_request(operation);
    let json = Zeroizing::new(
        serde_json::to_string(&request).expect("generated encrypt ProtoJSON must encode"),
    );
    execute_operation_proto_json(&json)
}

fn decode_success(envelope: &[u8]) -> Zeroizing<Vec<u8>> {
    let output = decode_operation_output(envelope)
        .ok()
        .expect("successful encrypt envelope must decode");
    assert_eq!(output.status(), OperationOutputStatus::Result);
    Zeroizing::new(output.bytes().to_vec())
}

fn assert_error(
    binary_operation: Operation,
    json_operation: Operation,
    expected_branch: ErrorBranch,
    expected_reason: CoseErrorReason,
) {
    let binary_envelope = process_binary_envelope(binary_operation);
    let json_envelope = process_json_envelope(json_operation);
    assert_eq!(binary_envelope.as_slice(), json_envelope.as_slice());
    let output = match decode_operation_output(&binary_envelope) {
        Ok(output) | Err(output) => output,
    };
    assert_eq!(output.status(), OperationOutputStatus::CoseError);
    let error = decode_cose_error(output.bytes()).expect("structured encrypt error must decode");
    let Some(branch) = error.error.as_ref() else {
        assert!(error.error.is_some(), "structured error branch must exist");
        return;
    };
    let (branch, reason) = match branch {
        cose_error_proto::Error::Primitive(error) => {
            (ErrorBranch::Primitive, error.reason.as_known())
        }
        cose_error_proto::Error::Provider(error) => {
            (ErrorBranch::Provider, error.reason.as_known())
        }
        cose_error_proto::Error::Backend(error) => (ErrorBranch::Backend, error.reason.as_known()),
    };
    assert_eq!(branch, expected_branch);
    assert_eq!(reason, Some(expected_reason));
}

fn assert_native_error<T>(result: Result<T, CoseError>, expected: CoseError) {
    assert!(matches!(result, Err(error) if error == expected));
}

fn operation_request(operation: Operation) -> CoseOperationRequest {
    CoseOperationRequest {
        operation: Some(operation),
        __buffa_unknown_fields: Default::default(),
    }
}
