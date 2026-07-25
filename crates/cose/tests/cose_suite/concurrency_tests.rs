// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_cose::{
    cose_decrypt_ml_kem, cose_encrypt_ml_kem_direct, cose_key_from_public_bytes,
    cose_key_from_slice, cose_key_to_multikey, cose_key_to_vec, cose_sign1,
    cose_verify1_with_policy, derive_kid_from_cose_key_public, Algorithm,
    CoseContentEncryptionAlgorithm, CoseMlKemAlgorithm, CoseMlKemDecryptRequest,
    CoseMlKemEncryptRequest, CosePolicy,
};
use reallyme_crypto::dispatch::generate_keypair;
use zeroize::Zeroizing;

const CONCURRENT_WORKERS: usize = 4;
const PAYLOAD: &[u8] = b"concurrent semantic operation payload";

#[test]
fn operation_families_are_deterministic_and_independently_owned_under_concurrency() {
    let (signing_public_key, signing_private_key) =
        generate_keypair(Algorithm::Ed25519).expect("Ed25519 fixture generation must succeed");
    let signing_key = cose_key_from_public_bytes(Algorithm::Ed25519, &signing_public_key)
        .expect("Ed25519 COSE_Key construction must succeed");
    let encoded_signing_key =
        cose_key_to_vec(&signing_key).expect("Ed25519 COSE_Key encoding must succeed");

    let (kem_public_key, kem_private_key) =
        generate_keypair(Algorithm::MlKem512).expect("ML-KEM-512 fixture generation must succeed");
    let kem_key = cose_key_from_public_bytes(Algorithm::MlKem512, &kem_public_key)
        .expect("ML-KEM COSE_Key construction must succeed");
    let kem_kid =
        derive_kid_from_cose_key_public(&kem_key).expect("ML-KEM kid derivation must succeed");
    let policy = CosePolicy::new().allow_algorithm(Algorithm::Ed25519);

    let outputs = std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(CONCURRENT_WORKERS);
        for _ in 0..CONCURRENT_WORKERS {
            handles.push(scope.spawn(|| {
                let cose_sign1 = cose_sign1(
                    Algorithm::Ed25519,
                    PAYLOAD,
                    &signing_private_key,
                    Some(b"concurrent-key"),
                )
                .expect("concurrent signing must succeed");
                let verified = cose_verify1_with_policy(&cose_sign1, &policy, |_, _| {
                    Some(signing_public_key.to_vec())
                })
                .expect("concurrent verification must succeed");
                assert_eq!(verified.payload.as_slice(), PAYLOAD);

                let parsed = cose_key_from_slice(&encoded_signing_key)
                    .expect("concurrent COSE_Key parsing must succeed");
                let multikey = cose_key_to_multikey(&parsed)
                    .expect("concurrent Multikey conversion must succeed");

                let encrypt_request = CoseMlKemEncryptRequest::new(
                    CoseMlKemAlgorithm::MlKem512,
                    CoseContentEncryptionAlgorithm::Aes128Gcm,
                    &kem_public_key,
                    &kem_kid,
                    PAYLOAD,
                    None,
                );
                let cose_encrypt = cose_encrypt_ml_kem_direct(&encrypt_request)
                    .expect("concurrent encryption must succeed");
                let decrypt_request =
                    CoseMlKemDecryptRequest::new(&cose_encrypt, &kem_private_key, &kem_kid, None);
                let decrypted = cose_decrypt_ml_kem(&decrypt_request)
                    .expect("concurrent decryption must succeed");

                (cose_sign1, multikey, decrypted.plaintext, decrypted.kid)
            }));
        }
        handles
            .into_iter()
            .map(|handle| handle.join().expect("concurrent operation must not panic"))
            .collect::<Vec<_>>()
    });

    let (expected_sign1, expected_multikey, _, _) = outputs
        .first()
        .expect("the fixed worker count must produce at least one output");
    for (cose_sign1, multikey, plaintext, kid) in &outputs {
        assert_eq!(cose_sign1.as_slice(), expected_sign1.as_slice());
        assert_eq!(multikey.as_str(), expected_multikey.as_str());
        assert_eq!(plaintext.as_slice(), PAYLOAD);
        assert_eq!(kid.as_slice(), kem_kid.as_slice());
    }

    // Keep the owner types visible in this test so a future return-type
    // regression to unmanaged buffers fails compilation.
    let _: &Zeroizing<Vec<u8>> = expected_sign1;
    let _: &Zeroizing<String> = expected_multikey;
}
