// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

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
    let key_set_policy = reallyme_cose::api::contract::CoseKeySetPolicy {
        projection: reallyme_cose::api::contract::CoseKeySetProjection::SensitiveStorage.into(),
        allowed_key_types: vec![reallyme_cose::api::contract::CoseKeySetKeyType::Ec2.into()].into(),
    };
    execute(Operation::KeySetParse(Box::new(
        reallyme_cose::api::contract::CoseKeySetParseRequest {
            encoded: data.to_vec().into(),
            policy: buffa::MessageField::some(key_set_policy.clone()),
        },
    )));
    execute(Operation::KeySetCreate(Box::new(
        reallyme_cose::api::contract::CoseKeySetCreateRequest {
            keys: vec![data.to_vec().into()].into(),
            policy: buffa::MessageField::some(key_set_policy),
        },
    )));
    execute(Operation::KeyParse(Box::new(key_request(data))));
    execute(Operation::KeyFromPublicBytes(Box::new(
        CoseKeyFromPublicBytesRequest {
            algorithm: signature_identifier(signature_algorithm),
            public_key: data.to_vec().into(),
            ec2_point_encoding: EnumValue::from(
                data.first().copied().map(i32::from).unwrap_or_default(),
            ),
        },
    )));
    execute(Operation::KeyFromPrivateBytes(Box::new(
        CoseKeyFromPrivateBytesRequest {
            algorithm: signature_identifier(signature_algorithm),
            private_key: data.to_vec().into(),
            public_key: Some(data.to_vec().into()),
        },
    )));
    execute(Operation::KeyToPublicBytes(Box::new(key_request(data))));
    execute(Operation::KeyToPublicVec(Box::new(key_request(data))));
    execute(Operation::KeyToPrivateBytes(Box::new(key_request(data))));
    execute(Operation::KeyDerivePublicKid(Box::new(key_request(data))));
    execute(Operation::KeyToMultikey(Box::new(key_request(data))));

    if let Ok(multikey) = core::str::from_utf8(data) {
        execute(Operation::MultikeyToCoseKey(Box::new(
            CoseMultikeyToCoseKeyRequest {
                multikey: multikey.to_owned().into(),
            },
        )));
    }

    let message_suite = reallyme_cose::api::contract::CoseSignatureSuite {
        registration: reallyme_cose::api::contract::CoseSignatureAlgorithm::Es256.into(),
        curve: reallyme_cose::api::contract::CoseNamedCurve::P256.into(),
    };
    execute(Operation::SignVerify(Box::new(
        reallyme_cose::api::contract::CoseSignVerifyRequest {
            encoded: data.to_vec().into(),
            detached_payload: None,
            external_aad: Vec::new().into(),
            envelope: reallyme_cose::api::contract::CoseEnvelopePolicy::Either.into(),
            keys: vec![reallyme_cose::api::contract::CoseSignKeyBinding {
                signature_index: 0,
                suite: buffa::MessageField::some(message_suite.clone()),
                public_key: data.to_vec().into(),
            }]
            .into(),
            allowed_suites: vec![message_suite].into(),
        },
    )));
    execute(Operation::Encrypt0Decrypt(Box::new(
        reallyme_cose::api::contract::CoseEncrypt0DecryptRequest {
            encoded: data.to_vec().into(),
            detached_ciphertext: None,
            external_aad: Vec::new().into(),
            key_algorithm: CoseContentEncryptionAlgorithm::Aes128Gcm.into(),
            key: data.to_vec().into(),
            allowed_algorithms: vec![CoseContentEncryptionAlgorithm::Aes128Gcm.into()].into(),
            base_iv: None,
            envelope: reallyme_cose::api::contract::CoseEnvelopePolicy::Either.into(),
        },
    )));
    execute(Operation::MacVerify(Box::new(
        reallyme_cose::api::contract::CoseMacVerifyRequest {
            encoded: data.to_vec().into(),
            detached_payload: None,
            external_aad: Vec::new().into(),
            algorithm: reallyme_cose::api::contract::CoseMacAlgorithm::Hmac256256.into(),
            allowed_algorithms: vec![
                reallyme_cose::api::contract::CoseMacAlgorithm::Hmac256256.into()
            ]
            .into(),
            recipient_path: vec![0].into(),
            recipient_key: data.to_vec().into(),
            allowed_recipient_algorithms: vec![
                reallyme_cose::api::contract::CoseRecipientAlgorithm::Direct.into(),
            ]
            .into(),
            envelope: reallyme_cose::api::contract::CoseEnvelopePolicy::Either.into(),
        },
    )));
    let counter_suite = reallyme_cose::api::contract::CoseSignatureSuite {
        registration: reallyme_cose::api::contract::CoseSignatureAlgorithm::Eddsa.into(),
        curve: reallyme_cose::api::contract::CoseNamedCurve::Ed25519.into(),
    };
    let counter_target = reallyme_cose::api::contract::CoseCounterSignatureTarget {
        // Finalized-field framing is independent of primary authentication.
        encoded: vec![
            0x83, 0x43, 0xa1, 1, 1, 0xa0, 0x50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]
        .into(),
        kind: reallyme_cose::api::contract::CoseCounterSignatureTargetKind::Encrypt0.into(),
        envelope: reallyme_cose::api::contract::CoseEnvelopePolicy::Untagged.into(),
        detached_content: None,
    };
    let counter_key = reallyme_cose::api::contract::CoseSignKeyBinding {
        signature_index: 0,
        suite: buffa::MessageField::some(counter_suite.clone()),
        public_key: data.to_vec().into(),
    };
    execute(Operation::CounterSignatureVerify(Box::new(reallyme_cose::api::contract::CoseCounterSignatureVerifyRequest {
        target:buffa::MessageField::some(counter_target.clone()),key:buffa::MessageField::some(counter_key.clone()),
        allowed_suites:vec![counter_suite.clone()].into(),external_aad:Vec::new().into(),
        signature:Some(reallyme_cose::api::contract::__buffa::oneof::cose_counter_signature_verify_request::Signature::Standalone(Box::new(reallyme_cose::api::contract::CoseCounterSignatureEncoded {
            encoded:data.to_vec().into(),envelope:reallyme_cose::api::contract::CoseEnvelopePolicy::Either.into(),
        }))),
    })));
    execute(Operation::CounterSignature0Verify(Box::new(reallyme_cose::api::contract::CoseCounterSignature0VerifyRequest {
        target:buffa::MessageField::some(counter_target.clone()),key:buffa::MessageField::some(counter_key),
        allowed_suites:vec![counter_suite].into(),external_aad:Vec::new().into(),
        signature:Some(reallyme_cose::api::contract::__buffa::oneof::cose_counter_signature0verify_request::Signature::Standalone(data.to_vec().into())),
    })));
    execute(Operation::CounterSignatureAttach(Box::new(reallyme_cose::api::contract::CoseCounterSignatureAttachRequest {
        target:buffa::MessageField::some(counter_target),
        signature:Some(reallyme_cose::api::contract::__buffa::oneof::cose_counter_signature_attach_request::Signature::Full(data.to_vec().into())),
    })));
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
        recipient_public_key: data.to_vec().into(),
        recipient_kid: data.to_vec().into(),
        plaintext: data.to_vec().into(),
        external_aad: data.to_vec().into(),
        supp_priv_info: Some(data.to_vec().into()),
    }
}

fn ml_kem_decrypt_request(data: &[u8]) -> CoseMlKemDecryptRequest {
    CoseMlKemDecryptRequest {
        cose_encrypt: data.to_vec().into(),
        recipient_private_key: data.to_vec().into(),
        expected_recipient_kid: data.to_vec().into(),
        external_aad: data.to_vec().into(),
        supp_priv_info: Some(data.to_vec().into()),
    }
}

fn sign1_create_request(data: &[u8], algorithm: CoseSignatureAlgorithm) -> CoseSign1CreateRequest {
    CoseSign1CreateRequest {
        algorithm: EnumValue::from(algorithm),
        payload: data.to_vec().into(),
        private_key: data.to_vec().into(),
        kid: Some(data.to_vec().into()),
        options: Default::default(),
        external_aad: data.to_vec().into(),
    }
}

fn sign1_create_detached_request(
    data: &[u8],
    algorithm: CoseSignatureAlgorithm,
) -> CoseSign1CreateDetachedRequest {
    CoseSign1CreateDetachedRequest {
        algorithm: EnumValue::from(algorithm),
        payload: data.to_vec().into(),
        private_key: data.to_vec().into(),
        kid: Some(data.to_vec().into()),
        options: Default::default(),
        external_aad: data.to_vec().into(),
    }
}

fn sign1_verify_request(data: &[u8], algorithm: CoseSignatureAlgorithm) -> CoseSign1VerifyRequest {
    CoseSign1VerifyRequest {
        cose_sign1: data.to_vec().into(),
        public_key: data.to_vec().into(),
        max_cose_sign1_bytes: 0,
        max_detached_payload_bytes: 0,
        require_kid: false,
        allowed_algorithms: vec![EnumValue::from(algorithm)].into(),
        external_aad: data.to_vec().into(),
        expected_kid: Vec::new().into(),
        require_tagged_sign1: data.first().is_some_and(|byte| byte & 1 == 1),
        expected_type: buffa::MessageField::none(),
        public_key_algorithm: EnumValue::from(algorithm),
    }
}

fn sign1_verify_detached_request(
    data: &[u8],
    algorithm: CoseSignatureAlgorithm,
) -> CoseSign1VerifyDetachedRequest {
    CoseSign1VerifyDetachedRequest {
        cose_sign1: data.to_vec().into(),
        payload: data.to_vec().into(),
        public_key: data.to_vec().into(),
        max_cose_sign1_bytes: 0,
        max_detached_payload_bytes: 0,
        require_kid: false,
        allowed_algorithms: vec![EnumValue::from(algorithm)].into(),
        external_aad: data.to_vec().into(),
        expected_kid: Vec::new().into(),
        require_tagged_sign1: data.first().is_some_and(|byte| byte & 1 == 1),
        expected_type: buffa::MessageField::none(),
        public_key_algorithm: EnumValue::from(algorithm),
    }
}

fn key_request(data: &[u8]) -> CoseKeyBytesRequest {
    CoseKeyBytesRequest {
        cose_key: data.to_vec().into(),
    }
}

fn signature_identifier(
    algorithm: CoseSignatureAlgorithm,
) -> buffa::MessageField<CoseAlgorithmIdentifier, buffa::Inline<CoseAlgorithmIdentifier>> {
    buffa::MessageField::some(CoseAlgorithmIdentifier {
        algorithm: Some(cose_algorithm_identifier::Algorithm::Signature(
            EnumValue::from(algorithm),
        )),
    })
}

#[allow(deprecated)] // Exercise the published compatibility selectors.
fn signature_algorithm(data: &[u8]) -> CoseSignatureAlgorithm {
    match data.first().copied().unwrap_or_default() % 12 {
        0 => CoseSignatureAlgorithm::Ed25519,
        1 => CoseSignatureAlgorithm::EcdsaP256Sha256,
        2 => CoseSignatureAlgorithm::EcdsaP384Sha384,
        3 => CoseSignatureAlgorithm::EcdsaP521Sha512,
        4 => CoseSignatureAlgorithm::EcdsaSecp256k1Sha256,
        5 => CoseSignatureAlgorithm::MlDsa44,
        6 => CoseSignatureAlgorithm::MlDsa65,
        7 => CoseSignatureAlgorithm::MlDsa87,
        8 => CoseSignatureAlgorithm::Es256,
        9 => CoseSignatureAlgorithm::Esp256,
        10 => CoseSignatureAlgorithm::Esp384,
        _ => CoseSignatureAlgorithm::Esp512,
    }
}

fn execute(operation: Operation) {
    let request = CoseOperationRequest {
        operation: Some(operation),
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
