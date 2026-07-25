#![allow(missing_docs, clippy::expect_used, clippy::unwrap_used)]
#![allow(dead_code)]
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_cose::Algorithm;
use reallyme_crypto::dispatch::generate_keypair;

#[cfg(feature = "wire")]
use buffa::Message;
#[cfg(feature = "wire")]
use reallyme_cose::wire::{
    cose_operation_response_v2, cose_operation_result, decode_operation_response,
    execute_operation_proto, execute_operation_proto_json,
};

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

pub fn gen_mldsa87() -> TestKey {
    let (public, private) = generate_keypair(Algorithm::MlDsa87).unwrap();

    TestKey {
        alg: Algorithm::MlDsa87,
        public,
        private: private.to_vec(),
    }
}

pub fn gen_mldsa44() -> TestKey {
    let (public, private) = generate_keypair(Algorithm::MlDsa44).unwrap();

    TestKey {
        alg: Algorithm::MlDsa44,
        public,
        private: private.to_vec(),
    }
}

pub fn gen_mldsa65() -> TestKey {
    let (public, private) = generate_keypair(Algorithm::MlDsa65).unwrap();

    TestKey {
        alg: Algorithm::MlDsa65,
        public,
        private: private.to_vec(),
    }
}

pub fn gen_mlkem512() -> TestKey {
    let (public, private) = generate_keypair(Algorithm::MlKem512).unwrap();

    TestKey {
        alg: Algorithm::MlKem512,
        public,
        private: private.to_vec(),
    }
}

pub fn gen_mlkem768() -> TestKey {
    let (public, private) = generate_keypair(Algorithm::MlKem768).unwrap();

    TestKey {
        alg: Algorithm::MlKem768,
        public,
        private: private.to_vec(),
    }
}

pub fn gen_mlkem1024() -> TestKey {
    let (public, private) = generate_keypair(Algorithm::MlKem1024).unwrap();

    TestKey {
        alg: Algorithm::MlKem1024,
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

#[cfg(feature = "wire")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationOutputStatus {
    Result,
    CoseError,
}

#[cfg(feature = "wire")]
pub struct OperationOutput {
    status: OperationOutputStatus,
    bytes: Vec<u8>,
}

#[cfg(feature = "wire")]
impl OperationOutput {
    pub fn status(&self) -> OperationOutputStatus {
        self.status
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[cfg(feature = "wire")]
pub fn execute_binary_output(request: &[u8]) -> OperationOutput {
    match decode_operation_output(&execute_operation_proto(request)) {
        Ok(output) | Err(output) => output,
    }
}

#[cfg(feature = "wire")]
pub fn execute_json_output(request: &str) -> OperationOutput {
    match decode_operation_output(&execute_operation_proto_json(request)) {
        Ok(output) | Err(output) => output,
    }
}

#[cfg(feature = "wire")]
pub fn decode_operation_output(bytes: &[u8]) -> Result<OperationOutput, OperationOutput> {
    match decode_operation_response(bytes) {
        Ok(response) => Ok(operation_output_from_response(response)),
        Err(response) => Err(operation_output_from_response(response)),
    }
}

#[cfg(feature = "wire")]
fn operation_output_from_response(
    mut response: reallyme_cose::wire::CoseOperationResponseV2,
) -> OperationOutput {
    match response.outcome.take() {
        Some(cose_operation_response_v2::Outcome::Result(result)) => OperationOutput {
            status: OperationOutputStatus::Result,
            bytes: encode_result_branch(*result),
        },
        Some(cose_operation_response_v2::Outcome::Error(error)) => OperationOutput {
            status: OperationOutputStatus::CoseError,
            bytes: error.encode_to_vec(),
        },
        None => OperationOutput {
            status: OperationOutputStatus::CoseError,
            bytes: Vec::new(),
        },
    }
}

#[cfg(feature = "wire")]
fn encode_result_branch(mut result: reallyme_cose::wire::CoseOperationResult) -> Vec<u8> {
    match result.result.take() {
        Some(cose_operation_result::Result::Sign1Create(message))
        | Some(cose_operation_result::Result::Sign1CreateDetached(message)) => {
            message.encode_to_vec()
        }
        Some(cose_operation_result::Result::Sign1Verify(message))
        | Some(cose_operation_result::Result::Sign1VerifyDetached(message)) => {
            message.encode_to_vec()
        }
        Some(cose_operation_result::Result::KeyFromPublicBytes(message))
        | Some(cose_operation_result::Result::KeyFromPrivateBytes(message))
        | Some(cose_operation_result::Result::KeyParse(message))
        | Some(cose_operation_result::Result::KeyToPublicBytes(message))
        | Some(cose_operation_result::Result::KeyToPrivateBytes(message))
        | Some(cose_operation_result::Result::KeyDerivePublicKid(message))
        | Some(cose_operation_result::Result::MultikeyToCoseKey(message)) => {
            message.encode_to_vec()
        }
        Some(cose_operation_result::Result::KeyToMultikey(message)) => message.encode_to_vec(),
        Some(cose_operation_result::Result::MlKemEncryptDirect(message))
        | Some(cose_operation_result::Result::MlKemEncryptKeyWrap(message)) => {
            message.encode_to_vec()
        }
        Some(cose_operation_result::Result::MlKemDecrypt(message)) => message.encode_to_vec(),
        None => Vec::new(),
    }
}
