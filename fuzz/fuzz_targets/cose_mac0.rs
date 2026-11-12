// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_cose::{
    cose_verify_mac0_detached, CoseMac0Limits, CoseMac0VerifyRequest, CoseMacAlgorithm, CoseMacKey,
};
use zeroize::Zeroizing;

const ALGORITHMS: [CoseMacAlgorithm; 4] = [
    CoseMacAlgorithm::Hmac256_64,
    CoseMacAlgorithm::Hmac256_256,
    CoseMacAlgorithm::Hmac384_384,
    CoseMacAlgorithm::Hmac512_512,
];

fuzz_target!(|data: &[u8]| {
    for algorithm in ALGORITHMS {
        // Public fixed test material drives the full verification path without
        // allowing the input to choose a key or widen the algorithm policy.
        let Ok(key) = CoseMacKey::new(
            algorithm,
            Zeroizing::new(vec![0x11; algorithm.key_length()]),
        ) else {
            return;
        };
        let _ = cose_verify_mac0_detached(
            CoseMac0VerifyRequest {
                encoded: data,
                detached_payload: b"payload",
                external_aad: b"aad",
                allowed_algorithms: &ALGORITHMS,
                limits: CoseMac0Limits::default(),
            },
            &key,
        );
        if let Some((split_byte, rest)) = data.split_first() {
            let Some(modulus) = rest.len().checked_add(1) else {
                return;
            };
            let split = usize::from(*split_byte) % modulus;
            let (encoded, payload) = rest.split_at(split);
            let _ = cose_verify_mac0_detached(
                CoseMac0VerifyRequest {
                    encoded,
                    detached_payload: payload,
                    external_aad: rest,
                    allowed_algorithms: &ALGORITHMS,
                    limits: CoseMac0Limits::default(),
                },
                &key,
            );
        }
    }
});
