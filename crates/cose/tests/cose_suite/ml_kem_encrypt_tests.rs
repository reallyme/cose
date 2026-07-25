// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use coset::{ContentType, CoseEncrypt, TaggedCborSerializable};
use reallyme_cose::{
    cose_decrypt_ml_kem, cose_decrypt_ml_kem_with_external_aad, cose_encrypt_ml_kem_direct,
    cose_encrypt_ml_kem_direct_with_external_aad, cose_encrypt_ml_kem_key_wrap,
    cose_key_from_public_bytes, derive_kid_from_cose_key_public, CoseContentEncryptionAlgorithm,
    CoseError, CoseMlKemAlgorithm, CoseMlKemDecryptRequest, CoseMlKemEncryptRequest, CoseMlKemMode,
};
use reallyme_crypto::core::Algorithm;
use zeroize::Zeroizing;

const PLAINTEXT: &[u8] = b"ReallyMe ML-KEM COSE profile test plaintext";
const EXTERNAL_AAD: &[u8] = b"authenticated transport metadata";
#[test]
fn every_direct_kem_and_content_algorithm_round_trips() {
    for kem_algorithm in kem_algorithms() {
        let (public_key, private_key, kid) = keypair(kem_algorithm);
        for content_algorithm in content_algorithms() {
            let request = encrypt_request(
                kem_algorithm,
                content_algorithm,
                &public_key,
                &kid,
                PLAINTEXT,
            );
            let encoded = cose_encrypt_ml_kem_direct(&request).expect("direct encryption");
            let decrypted = cose_decrypt_ml_kem(&decrypt_request(&encoded, &private_key, &kid))
                .expect("direct decryption");

            assert_eq!(decrypted.plaintext.as_slice(), PLAINTEXT);
            assert_eq!(decrypted.kem_algorithm, kem_algorithm);
            assert_eq!(decrypted.content_algorithm, content_algorithm);
            assert_eq!(decrypted.mode, CoseMlKemMode::Direct);
            assert_eq!(decrypted.kid.as_slice(), kid.as_slice());

            let cose = CoseEncrypt::from_tagged_slice(&encoded).expect("tagged COSE_Encrypt");
            assert!(cose.protected.header.alg.is_some());
            assert!(cose.unprotected.alg.is_none());
            let recipient = cose.recipients.first().expect("one recipient");
            assert!(recipient.protected.header.alg.is_some());
            assert!(recipient.unprotected.alg.is_none());
            assert_eq!(recipient.protected.header.key_id.as_slice(), kid.as_slice());
            assert!(recipient.unprotected.key_id.is_empty());
            assert!(recipient.ciphertext.is_none());
        }
    }
}

#[test]
fn every_wrapped_kem_and_content_algorithm_round_trips() {
    for kem_algorithm in kem_algorithms() {
        let (public_key, private_key, kid) = keypair(kem_algorithm);
        for content_algorithm in content_algorithms() {
            let request = encrypt_request(
                kem_algorithm,
                content_algorithm,
                &public_key,
                &kid,
                PLAINTEXT,
            );
            let encoded = cose_encrypt_ml_kem_key_wrap(&request).expect("wrapped encryption");
            let decrypted = cose_decrypt_ml_kem(&decrypt_request(&encoded, &private_key, &kid))
                .expect("wrapped decryption");

            assert_eq!(decrypted.plaintext.as_slice(), PLAINTEXT);
            assert_eq!(decrypted.kem_algorithm, kem_algorithm);
            assert_eq!(decrypted.content_algorithm, content_algorithm);
            assert_eq!(decrypted.mode, CoseMlKemMode::KeyWrap);
            assert_eq!(decrypted.kid.as_slice(), kid.as_slice());

            let cose = CoseEncrypt::from_tagged_slice(&encoded).expect("tagged COSE_Encrypt");
            let wrapped = cose
                .recipients
                .first()
                .and_then(|recipient| recipient.ciphertext.as_ref())
                .expect("wrapped CEK");
            assert_eq!(wrapped.len(), content_key_length(content_algorithm) + 8);
        }
    }
}

#[test]
fn external_aad_and_supp_priv_info_are_required_to_match() {
    let (public_key, private_key, kid) = keypair(CoseMlKemAlgorithm::MlKem768);
    let supp_priv_info = b"mutually known private context";
    let request = encrypt_request(
        CoseMlKemAlgorithm::MlKem768,
        CoseContentEncryptionAlgorithm::Aes192Gcm,
        &public_key,
        &kid,
        PLAINTEXT,
    )
    .with_supp_priv_info(Some(supp_priv_info));
    let encoded = cose_encrypt_ml_kem_direct_with_external_aad(&request, EXTERNAL_AAD)
        .expect("encryption with context");

    let decrypt =
        decrypt_request(&encoded, &private_key, &kid).with_supp_priv_info(Some(supp_priv_info));
    let decrypted =
        cose_decrypt_ml_kem_with_external_aad(&decrypt, EXTERNAL_AAD).expect("matching context");
    assert_eq!(decrypted.plaintext.as_slice(), PLAINTEXT);

    assert_eq!(
        cose_decrypt_ml_kem_with_external_aad(&decrypt, b"wrong aad").map(|_| ()),
        Err(CoseError::AuthenticationFailed),
    );

    let decrypt = decrypt.with_supp_priv_info(Some(b"wrong private context"));
    assert_eq!(
        cose_decrypt_ml_kem_with_external_aad(&decrypt, EXTERNAL_AAD).map(|_| ()),
        Err(CoseError::AuthenticationFailed),
    );
}

#[test]
fn wrong_kid_fails_before_private_key_use() {
    let (public_key, private_key, kid) = keypair(CoseMlKemAlgorithm::MlKem512);
    let request = encrypt_request(
        CoseMlKemAlgorithm::MlKem512,
        CoseContentEncryptionAlgorithm::Aes128Gcm,
        &public_key,
        &kid,
        PLAINTEXT,
    );
    let encoded = cose_encrypt_ml_kem_direct(&request).expect("direct encryption");
    let mut wrong_kid = kid;
    wrong_kid[0] ^= 0x80;
    let decrypt = decrypt_request(&encoded, &private_key, &wrong_kid);

    assert_eq!(
        cose_decrypt_ml_kem(&decrypt).map(|_| ()),
        Err(CoseError::KidMismatch),
    );
}

#[test]
fn malformed_recipient_kid_length_is_rejected_as_structure() {
    let (public_key, private_key, kid) = keypair(CoseMlKemAlgorithm::MlKem512);
    let request = encrypt_request(
        CoseMlKemAlgorithm::MlKem512,
        CoseContentEncryptionAlgorithm::Aes128Gcm,
        &public_key,
        &kid,
        PLAINTEXT,
    );
    let encoded = cose_encrypt_ml_kem_direct(&request).expect("direct encryption");
    let mut cose = CoseEncrypt::from_tagged_slice(&encoded).expect("tagged COSE_Encrypt");
    cose.recipients
        .first_mut()
        .expect("recipient")
        .protected
        .header
        .key_id
        .truncate(31);
    cose.recipients
        .first_mut()
        .expect("recipient")
        .protected
        .original_data = None;
    let malformed = cose.to_tagged_vec().expect("encode malformed object");

    assert_eq!(
        cose_decrypt_ml_kem(&decrypt_request(&malformed, &private_key, &kid)).map(|_| ()),
        Err(CoseError::InvalidRecipient),
    );
}

#[test]
fn encryption_rejects_a_kid_that_does_not_identify_the_public_key() {
    let (public_key, _, mut kid) = keypair(CoseMlKemAlgorithm::MlKem512);
    kid[0] ^= 0x80;
    let request = encrypt_request(
        CoseMlKemAlgorithm::MlKem512,
        CoseContentEncryptionAlgorithm::Aes128Gcm,
        &public_key,
        &kid,
        PLAINTEXT,
    );

    assert_eq!(
        cose_encrypt_ml_kem_direct(&request).map(|_| ()),
        Err(CoseError::KidMismatch),
    );
}

#[test]
fn encryption_rejects_malformed_public_key_encoding_as_key_material() {
    let (mut malformed_public_key, _, _) = keypair(CoseMlKemAlgorithm::MlKem512);
    malformed_public_key.fill(0xff);
    let request = encrypt_request(
        CoseMlKemAlgorithm::MlKem512,
        CoseContentEncryptionAlgorithm::Aes128Gcm,
        &malformed_public_key,
        &[0u8; 32],
        PLAINTEXT,
    );

    assert_eq!(
        cose_encrypt_ml_kem_direct(&request).map(|_| ()),
        Err(CoseError::InvalidKeyMaterial),
    );
}

#[test]
fn decryption_rejects_a_private_key_that_does_not_own_the_protected_kid() {
    let (public_key, _, kid) = keypair(CoseMlKemAlgorithm::MlKem768);
    let (_, wrong_private_key, _) = keypair(CoseMlKemAlgorithm::MlKem768);
    let request = encrypt_request(
        CoseMlKemAlgorithm::MlKem768,
        CoseContentEncryptionAlgorithm::Aes192Gcm,
        &public_key,
        &kid,
        PLAINTEXT,
    );
    let encoded = cose_encrypt_ml_kem_direct(&request).expect("direct encryption");

    assert_eq!(
        cose_decrypt_ml_kem(&decrypt_request(&encoded, &wrong_private_key, &kid)).map(|_| ()),
        Err(CoseError::KidMismatch),
    );
}

#[test]
fn wrapped_cek_tampering_is_not_collapsed_into_content_authentication_failure() {
    let (public_key, private_key, kid) = keypair(CoseMlKemAlgorithm::MlKem1024);
    let request = encrypt_request(
        CoseMlKemAlgorithm::MlKem1024,
        CoseContentEncryptionAlgorithm::Aes256Gcm,
        &public_key,
        &kid,
        PLAINTEXT,
    );
    let encoded = cose_encrypt_ml_kem_key_wrap(&request).expect("wrapped encryption");
    let mut cose = CoseEncrypt::from_tagged_slice(&encoded).expect("tagged COSE_Encrypt");
    let wrapped = cose
        .recipients
        .first_mut()
        .and_then(|recipient| recipient.ciphertext.as_mut())
        .expect("wrapped CEK");
    wrapped[0] ^= 0x80;
    let tampered = cose.to_tagged_vec().expect("encode tampered object");

    assert_eq!(
        cose_decrypt_ml_kem(&decrypt_request(&tampered, &private_key, &kid)).map(|_| ()),
        Err(CoseError::KeyUnwrapFailed),
    );
}

#[test]
fn direct_profile_rejects_a_recipient_ciphertext() {
    let (public_key, private_key, kid) = keypair(CoseMlKemAlgorithm::MlKem512);
    let request = encrypt_request(
        CoseMlKemAlgorithm::MlKem512,
        CoseContentEncryptionAlgorithm::Aes128Gcm,
        &public_key,
        &kid,
        PLAINTEXT,
    );
    let encoded = cose_encrypt_ml_kem_direct(&request).expect("direct encryption");
    let mut cose = CoseEncrypt::from_tagged_slice(&encoded).expect("tagged COSE_Encrypt");
    cose.recipients.first_mut().expect("recipient").ciphertext = Some(vec![0u8; 24]);
    let malformed = cose.to_tagged_vec().expect("encode malformed object");

    assert_eq!(
        cose_decrypt_ml_kem(&decrypt_request(&malformed, &private_key, &kid)).map(|_| ()),
        Err(CoseError::InvalidRecipient),
    );
}

#[test]
fn profile_rejects_unsupported_body_header_semantics() {
    let (public_key, private_key, kid) = keypair(CoseMlKemAlgorithm::MlKem512);
    let request = encrypt_request(
        CoseMlKemAlgorithm::MlKem512,
        CoseContentEncryptionAlgorithm::Aes128Gcm,
        &public_key,
        &kid,
        PLAINTEXT,
    );
    let encoded = cose_encrypt_ml_kem_direct(&request).expect("direct encryption");
    let mut cose = CoseEncrypt::from_tagged_slice(&encoded).expect("tagged COSE_Encrypt");
    cose.unprotected.content_type = Some(ContentType::Text("application/example".to_owned()));
    let malformed = cose.to_tagged_vec().expect("encode unsupported header");

    assert_eq!(
        cose_decrypt_ml_kem(&decrypt_request(&malformed, &private_key, &kid)).map(|_| ()),
        Err(CoseError::InvalidFormat),
    );
}

#[test]
fn profile_rejects_unsupported_recipient_header_semantics() {
    let (public_key, private_key, kid) = keypair(CoseMlKemAlgorithm::MlKem512);
    let request = encrypt_request(
        CoseMlKemAlgorithm::MlKem512,
        CoseContentEncryptionAlgorithm::Aes128Gcm,
        &public_key,
        &kid,
        PLAINTEXT,
    );
    let encoded = cose_encrypt_ml_kem_direct(&request).expect("direct encryption");
    let mut cose = CoseEncrypt::from_tagged_slice(&encoded).expect("tagged COSE_Encrypt");
    let recipient = cose.recipients.first_mut().expect("recipient");
    recipient.protected.original_data = None;
    recipient.protected.header.content_type =
        Some(ContentType::Text("application/example".to_owned()));
    let malformed = cose.to_tagged_vec().expect("encode unsupported header");

    assert_eq!(
        cose_decrypt_ml_kem(&decrypt_request(&malformed, &private_key, &kid)).map(|_| ()),
        Err(CoseError::InvalidRecipient),
    );
}

#[test]
fn invalid_encapsulated_key_length_is_rejected_structurally() {
    let (public_key, private_key, kid) = keypair(CoseMlKemAlgorithm::MlKem768);
    let request = encrypt_request(
        CoseMlKemAlgorithm::MlKem768,
        CoseContentEncryptionAlgorithm::Aes192Gcm,
        &public_key,
        &kid,
        PLAINTEXT,
    );
    let encoded = cose_encrypt_ml_kem_direct(&request).expect("direct encryption");
    let mut cose = CoseEncrypt::from_tagged_slice(&encoded).expect("tagged COSE_Encrypt");
    let recipient = cose.recipients.first_mut().expect("recipient");
    let (_, encapsulated_key) = recipient.unprotected.rest.first_mut().expect("ek header");
    *encapsulated_key = ciborium::value::Value::Bytes(vec![0u8; 16]);
    let malformed = cose.to_tagged_vec().expect("encode malformed object");

    assert_eq!(
        cose_decrypt_ml_kem(&decrypt_request(&malformed, &private_key, &kid)).map(|_| ()),
        Err(CoseError::InvalidEncapsulatedKey),
    );
}

fn encrypt_request<'a>(
    kem_algorithm: CoseMlKemAlgorithm,
    content_algorithm: CoseContentEncryptionAlgorithm,
    public_key: &'a [u8],
    kid: &'a [u8],
    plaintext: &'a [u8],
) -> CoseMlKemEncryptRequest<'a> {
    CoseMlKemEncryptRequest::new(
        kem_algorithm,
        content_algorithm,
        public_key,
        kid,
        plaintext,
        None,
    )
}

fn decrypt_request<'a>(
    encoded: &'a [u8],
    private_key: &'a [u8],
    kid: &'a [u8],
) -> CoseMlKemDecryptRequest<'a> {
    CoseMlKemDecryptRequest::new(encoded, private_key, kid, None)
}

fn keypair(algorithm: CoseMlKemAlgorithm) -> (Vec<u8>, Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>) {
    let (public_key, private_key, crypto_algorithm) = if algorithm == CoseMlKemAlgorithm::MlKem512 {
        let (public_key, private_key) = reallyme_crypto::ml_kem_512::generate_ml_kem_512_keypair()
            .expect("ML-KEM-512 key generation");
        (public_key, private_key, Algorithm::MlKem512)
    } else if algorithm == CoseMlKemAlgorithm::MlKem768 {
        let (public_key, private_key) = reallyme_crypto::ml_kem_768::generate_ml_kem_768_keypair()
            .expect("ML-KEM-768 key generation");
        (public_key, private_key, Algorithm::MlKem768)
    } else {
        let (public_key, private_key) =
            reallyme_crypto::ml_kem_1024::generate_ml_kem_1024_keypair()
                .expect("ML-KEM-1024 key generation");
        (public_key, private_key, Algorithm::MlKem1024)
    };
    let cose_key = cose_key_from_public_bytes(crypto_algorithm, &public_key)
        .expect("ML-KEM public COSE_Key conversion");
    let kid = derive_kid_from_cose_key_public(&cose_key).expect("ML-KEM public kid derivation");
    (public_key, private_key, kid)
}

fn kem_algorithms() -> [CoseMlKemAlgorithm; 3] {
    [
        CoseMlKemAlgorithm::MlKem512,
        CoseMlKemAlgorithm::MlKem768,
        CoseMlKemAlgorithm::MlKem1024,
    ]
}

fn content_algorithms() -> [CoseContentEncryptionAlgorithm; 3] {
    [
        CoseContentEncryptionAlgorithm::Aes128Gcm,
        CoseContentEncryptionAlgorithm::Aes192Gcm,
        CoseContentEncryptionAlgorithm::Aes256Gcm,
    ]
}

fn content_key_length(algorithm: CoseContentEncryptionAlgorithm) -> usize {
    if algorithm == CoseContentEncryptionAlgorithm::Aes128Gcm {
        16
    } else if algorithm == CoseContentEncryptionAlgorithm::Aes192Gcm {
        24
    } else {
        32
    }
}
