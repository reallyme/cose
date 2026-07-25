// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_cose::{
    cose_decrypt_ml_kem_with_external_aad, cose_encrypt_ml_kem_direct_with_external_aad,
    cose_encrypt_ml_kem_key_wrap_with_external_aad, cose_key_from_public_bytes,
    derive_kid_from_cose_key_public, Algorithm, CoseContentEncryptionAlgorithm, CoseMlKemAlgorithm,
    CoseMlKemDecryptRequest, CoseMlKemEncryptRequest,
};
use zeroize::Zeroizing;

const EXTERNAL_AAD: &[u8] = b"ReallyMe COSE_Encrypt fuzz AAD";
const SUPP_PRIV_INFO: &[u8] = b"ReallyMe COSE_Encrypt fuzz private context";
const MAX_FUZZ_PLAINTEXT_BYTES: usize = 4_096;

fuzz_target!(|data: &[u8]| {
    let selector = data.first().copied().unwrap_or_default();
    let (algorithm, crypto_algorithm) = match selector % 3 {
        0 => (CoseMlKemAlgorithm::MlKem512, Algorithm::MlKem512),
        1 => (CoseMlKemAlgorithm::MlKem768, Algorithm::MlKem768),
        _ => (CoseMlKemAlgorithm::MlKem1024, Algorithm::MlKem1024),
    };
    let content_algorithm = match selector.wrapping_div(3) % 3 {
        0 => CoseContentEncryptionAlgorithm::Aes128Gcm,
        1 => CoseContentEncryptionAlgorithm::Aes192Gcm,
        _ => CoseContentEncryptionAlgorithm::Aes256Gcm,
    };
    let seed = [selector.wrapping_add(1); 64];
    let keypair = match algorithm {
        CoseMlKemAlgorithm::MlKem512 => {
            reallyme_crypto::ml_kem_512::generate_ml_kem_512_keypair_from_seed(&seed)
        }
        CoseMlKemAlgorithm::MlKem768 => {
            reallyme_crypto::ml_kem_768::generate_ml_kem_768_keypair_from_seed(&seed)
        }
        CoseMlKemAlgorithm::MlKem1024 => {
            reallyme_crypto::ml_kem_1024::generate_ml_kem_1024_keypair_from_seed(&seed)
        }
        _ => return,
    };
    let (public_key, private_key) = match keypair {
        Ok(keypair) => keypair,
        Err(_) => return,
    };
    let cose_key = match cose_key_from_public_bytes(crypto_algorithm, &public_key) {
        Ok(key) => key,
        Err(_) => return,
    };
    let kid = match derive_kid_from_cose_key_public(&cose_key) {
        Ok(kid) => kid,
        Err(_) => return,
    };
    let plaintext_start = usize::from(!data.is_empty());
    let plaintext_end = data
        .len()
        .min(plaintext_start.saturating_add(MAX_FUZZ_PLAINTEXT_BYTES));
    let plaintext = &data[plaintext_start..plaintext_end];
    let request = CoseMlKemEncryptRequest::new(
        algorithm,
        content_algorithm,
        &public_key,
        &kid,
        plaintext,
        Some(SUPP_PRIV_INFO),
    );
    let encoded = if selector & 1 == 0 {
        cose_encrypt_ml_kem_direct_with_external_aad(&request, EXTERNAL_AAD)
    } else {
        cose_encrypt_ml_kem_key_wrap_with_external_aad(&request, EXTERNAL_AAD)
    };
    let encoded = match encoded {
        Ok(encoded) => encoded,
        Err(_) => return,
    };
    let decrypt = CoseMlKemDecryptRequest::new(&encoded, &private_key, &kid, Some(SUPP_PRIV_INFO));
    let _ = cose_decrypt_ml_kem_with_external_aad(&decrypt, EXTERNAL_AAD);

    // Mutate a valid object so libFuzzer reaches recipient/header/KDF/AEAD
    // rejection paths that uniform random bytes would almost never discover.
    let mut mutated = Zeroizing::new(encoded.to_vec());
    for mutation in data[plaintext_end..].chunks_exact(2) {
        if mutated.is_empty() {
            break;
        }
        let index = usize::from(mutation[0]) % mutated.len();
        mutated[index] ^= mutation[1];
    }
    let mutated_request =
        CoseMlKemDecryptRequest::new(&mutated, &private_key, &kid, Some(SUPP_PRIV_INFO));
    let _ = cose_decrypt_ml_kem_with_external_aad(&mutated_request, EXTERNAL_AAD);

    // Retain a fully arbitrary parser path as well as the structured mutations.
    let raw_request = CoseMlKemDecryptRequest::new(data, &private_key, &kid, Some(SUPP_PRIV_INFO));
    let _ = cose_decrypt_ml_kem_with_external_aad(&raw_request, EXTERNAL_AAD);
});
