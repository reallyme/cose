#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
#![allow(dead_code)]
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_cose::Algorithm;
use reallyme_crypto::dispatch::generate_keypair;

#[derive(Debug)]
pub struct TestKey {
    pub alg: Algorithm,
    pub public: Vec<u8>,
    pub private: Vec<u8>,
}

pub fn gen_ed25519() -> TestKey {
    let (public, private) = generate_keypair(Algorithm::Ed25519).unwrap();

    TestKey {
        alg: Algorithm::Ed25519,
        public,
        private: private.to_vec(),
    }
}

pub fn gen_p256() -> TestKey {
    let (public, private) = generate_keypair(Algorithm::P256).unwrap();

    TestKey {
        alg: Algorithm::P256,
        public,
        private: private.to_vec(),
    }
}

pub fn gen_p384() -> TestKey {
    let (public, private) = generate_keypair(Algorithm::P384).unwrap();

    TestKey {
        alg: Algorithm::P384,
        public,
        private: private.to_vec(),
    }
}

pub fn gen_p521() -> TestKey {
    let (public, private) = generate_keypair(Algorithm::P521).unwrap();

    TestKey {
        alg: Algorithm::P521,
        public,
        private: private.to_vec(),
    }
}

pub fn gen_secp256k1() -> TestKey {
    let (public, private) = generate_keypair(Algorithm::Secp256k1).unwrap();

    TestKey {
        alg: Algorithm::Secp256k1,
        public,
        private: private.to_vec(),
    }
}

pub fn gen_x25519() -> TestKey {
    let (public, private) = generate_keypair(Algorithm::X25519).unwrap();

    TestKey {
        alg: Algorithm::X25519,
        public,
        private: private.to_vec(),
    }
}

pub fn sample_payload() -> Vec<u8> {
    b"hello cose world".to_vec()
}

/// Shared test `kid`
pub fn test_kid() -> &'static [u8] {
    b"test-key"
}
