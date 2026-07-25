// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use buffa::{EnumValue, Message};
use libfuzzer_sys::fuzz_target;
use reallyme_cose::wire::cose_algorithm_identifier;
use reallyme_cose::wire::cose_operation_request::Operation;
use reallyme_cose::wire::{
    CoseAlgorithmIdentifier, CoseContentEncryptionAlgorithm, CoseKemAlgorithm, CoseKeyBytesRequest,
    CoseKeyFromPrivateBytesRequest, CoseKeyFromPublicBytesRequest, CoseMlKemDecryptRequest,
    CoseMlKemEncryptRequest, CoseMultikeyToCoseKeyRequest, CoseOperationRequest,
    CoseSign1CreateDetachedRequest, CoseSign1CreateRequest, CoseSign1VerifyDetachedRequest,
    CoseSign1VerifyRequest, CoseSignatureAlgorithm,
};
use zeroize::Zeroizing;

fuzz_target!(|data: &[u8]| {
    let result = reallyme_cose::wire::execute_operation_proto(data);
    let _ = reallyme_cose::wire::decode_operation_response(&result);
    let _ = reallyme_cose::wire::decode_operation_response(data);
    let _ = reallyme_cose::wire::decode_cose_error(data);

    if let Ok(json) = core::str::from_utf8(data) {
        let result = reallyme_cose::wire::execute_operation_proto_json(json);
        let _ = reallyme_cose::wire::decode_operation_response(&result);
    }

    // Sparse operation fields are almost never selected by arbitrary protobuf
    // bytes. Wrap every input so all migrated key-family routes remain
    // continuously reachable through both generated transport lanes.
    let signature_algorithm = signature_algorithm(data);
    execute(Operation::KeyParse(Box::new(key_request(data))));
    execute(Operation::KeyFromPublicBytes(Box::new(
        CoseKeyFromPublicBytesRequest {
            algorithm: signature_identifier(signature_algorithm),
            public_key: data.to_vec(),
            __buffa_unknown_fields: Default::default(),
        },
    )));
    execute(Operation::KeyFromPrivateBytes(Box::new(
        CoseKeyFromPrivateBytesRequest {
            algorithm: signature_identifier(signature_algorithm),
            private_key: data.to_vec(),
            public_key: data.to_vec(),
            has_public_key: true,
            __buffa_unknown_fields: Default::default(),
        },
    )));
    execute(Operation::KeyToPublicBytes(Box::new(key_request(data))));
    execute(Operation::KeyToPrivateBytes(Box::new(key_request(data))));
    execute(Operation::KeyDerivePublicKid(Box::new(key_request(data))));
    execute(Operation::KeyToMultikey(Box::new(key_request(data))));

    if let Ok(multikey) = core::str::from_utf8(data) {
        execute(Operation::MultikeyToCoseKey(Box::new(
            CoseMultikeyToCoseKeyRequest {
                multikey: multikey.to_owned(),
                __buffa_unknown_fields: Default::default(),
            },
        )));
    }

    // Sign1 operation tags are equally sparse. Exercise attached and detached
    // creation and verification through both transports on every iteration.
    execute(Operation::Sign1Create(Box::new(sign1_create_request(
        data,
        signature_algorithm,
    ))));
    execute(Operation::Sign1CreateDetached(Box::new(
        sign1_create_detached_request(data, signature_algorithm),
    )));
    execute(Operation::Sign1Verify(Box::new(sign1_verify_request(
        data,
        signature_algorithm,
    ))));
    execute(Operation::Sign1VerifyDetached(Box::new(
        sign1_verify_detached_request(data, signature_algorithm),
    )));
    execute(Operation::MlKemEncryptDirect(Box::new(
        ml_kem_encrypt_request(data),
    )));
    execute(Operation::MlKemEncryptKeyWrap(Box::new(
        ml_kem_encrypt_request(data),
    )));
    execute(Operation::MlKemDecrypt(Box::new(ml_kem_decrypt_request(
        data,
    ))));
});

fn ml_kem_encrypt_request(data: &[u8]) -> CoseMlKemEncryptRequest {
    CoseMlKemEncryptRequest {
        kem_algorithm: EnumValue::from(CoseKemAlgorithm::MlKem512),
        content_algorithm: EnumValue::from(CoseContentEncryptionAlgorithm::Aes128Gcm),
        recipient_public_key: data.to_vec(),
        recipient_kid: data.to_vec(),
        plaintext: data.to_vec(),
        external_aad: data.to_vec(),
        supp_priv_info: data.to_vec(),
        has_supp_priv_info: true,
        __buffa_unknown_fields: Default::default(),
    }
}

fn ml_kem_decrypt_request(data: &[u8]) -> CoseMlKemDecryptRequest {
    CoseMlKemDecryptRequest {
        cose_encrypt: data.to_vec(),
        recipient_private_key: data.to_vec(),
        expected_recipient_kid: data.to_vec(),
        external_aad: data.to_vec(),
        supp_priv_info: data.to_vec(),
        has_supp_priv_info: true,
        __buffa_unknown_fields: Default::default(),
    }
}

fn sign1_create_request(data: &[u8], algorithm: CoseSignatureAlgorithm) -> CoseSign1CreateRequest {
    CoseSign1CreateRequest {
        algorithm: EnumValue::from(algorithm),
        payload: data.to_vec(),
        private_key: data.to_vec(),
        kid: data.to_vec(),
        has_kid: true,
        options: Default::default(),
        external_aad: data.to_vec(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn sign1_create_detached_request(
    data: &[u8],
    algorithm: CoseSignatureAlgorithm,
) -> CoseSign1CreateDetachedRequest {
    CoseSign1CreateDetachedRequest {
        algorithm: EnumValue::from(algorithm),
        payload: data.to_vec(),
        private_key: data.to_vec(),
        kid: data.to_vec(),
        has_kid: true,
        options: Default::default(),
        external_aad: data.to_vec(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn sign1_verify_request(data: &[u8], algorithm: CoseSignatureAlgorithm) -> CoseSign1VerifyRequest {
    CoseSign1VerifyRequest {
        cose_sign1: data.to_vec(),
        public_key: data.to_vec(),
        max_cose_sign1_bytes: 0,
        max_detached_payload_bytes: 0,
        require_kid: false,
        allowed_algorithms: vec![EnumValue::from(algorithm)],
        external_aad: data.to_vec(),
        expected_kid: Vec::new(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn sign1_verify_detached_request(
    data: &[u8],
    algorithm: CoseSignatureAlgorithm,
) -> CoseSign1VerifyDetachedRequest {
    CoseSign1VerifyDetachedRequest {
        cose_sign1: data.to_vec(),
        payload: data.to_vec(),
        public_key: data.to_vec(),
        max_cose_sign1_bytes: 0,
        max_detached_payload_bytes: 0,
        require_kid: false,
        allowed_algorithms: vec![EnumValue::from(algorithm)],
        external_aad: data.to_vec(),
        expected_kid: Vec::new(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn key_request(data: &[u8]) -> CoseKeyBytesRequest {
    CoseKeyBytesRequest {
        cose_key: data.to_vec(),
        __buffa_unknown_fields: Default::default(),
    }
}

fn signature_identifier(
    algorithm: CoseSignatureAlgorithm,
) -> buffa::MessageField<CoseAlgorithmIdentifier, buffa::Inline<CoseAlgorithmIdentifier>> {
    buffa::MessageField::some(CoseAlgorithmIdentifier {
        algorithm: Some(cose_algorithm_identifier::Algorithm::Signature(
            EnumValue::from(algorithm),
        )),
        __buffa_unknown_fields: Default::default(),
    })
}

fn signature_algorithm(data: &[u8]) -> CoseSignatureAlgorithm {
    match data.first().copied().unwrap_or_default() % 8 {
        0 => CoseSignatureAlgorithm::Ed25519,
        1 => CoseSignatureAlgorithm::EcdsaP256Sha256,
        2 => CoseSignatureAlgorithm::EcdsaP384Sha384,
        3 => CoseSignatureAlgorithm::EcdsaP521Sha512,
        4 => CoseSignatureAlgorithm::EcdsaSecp256k1Sha256,
        5 => CoseSignatureAlgorithm::MlDsa44,
        6 => CoseSignatureAlgorithm::MlDsa65,
        _ => CoseSignatureAlgorithm::MlDsa87,
    }
}

fn execute(operation: Operation) {
    let request = CoseOperationRequest {
        operation: Some(operation),
        __buffa_unknown_fields: Default::default(),
    };
    let encoded_request = Zeroizing::new(request.encode_to_vec());
    let result = reallyme_cose::wire::execute_operation_proto(&encoded_request);
    let _ = reallyme_cose::wire::decode_operation_response_for_request(&request, &result);

    if let Ok(json) = serde_json::to_string(&request) {
        let json = Zeroizing::new(json);
        let result = reallyme_cose::wire::execute_operation_proto_json(&json);
        let _ = reallyme_cose::wire::decode_operation_response_for_request(&request, &result);
    }
}
