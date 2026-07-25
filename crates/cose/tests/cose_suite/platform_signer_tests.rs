// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use reallyme_cose::{
    cose_sign1_detached_with_signer, cose_sign1_with_signer, cose_verify1_detached_with_policy,
    cose_verify1_with_policy, Algorithm, CoseError, CosePolicy, CoseSign1EncodeOptions, CoseSigner,
    CoseSignerError,
};
use reallyme_crypto::dispatch::{generate_keypair, sign};
use zeroize::Zeroizing;

const PAYLOAD: &[u8] = b"platform-owned signing payload";
const KID: &[u8] = b"platform-key-handle";

struct TestPlatformSigner {
    algorithm: Algorithm,
    private_key: Zeroizing<Vec<u8>>,
}

impl CoseSigner for TestPlatformSigner {
    fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    fn sign(&self, sig_structure: &[u8]) -> Result<Zeroizing<Vec<u8>>, CoseSignerError> {
        sign(self.algorithm, &self.private_key, sig_structure)
            .map(Zeroizing::new)
            .map_err(|_| CoseSignerError::Backend)
    }
}

struct FailingPlatformSigner {
    error: CoseSignerError,
}

impl CoseSigner for FailingPlatformSigner {
    fn algorithm(&self) -> Algorithm {
        Algorithm::Ed25519
    }

    fn sign(&self, _sig_structure: &[u8]) -> Result<Zeroizing<Vec<u8>>, CoseSignerError> {
        Err(self.error)
    }
}

#[test]
fn provider_owned_key_signs_attached_and_detached_without_key_export() {
    let (public_key, private_key) =
        generate_keypair(Algorithm::Ed25519).expect("Ed25519 fixture generation must succeed");
    let signer = TestPlatformSigner {
        algorithm: Algorithm::Ed25519,
        private_key,
    };
    let policy = CosePolicy::new()
        .with_require_kid(true)
        .allow_algorithm(Algorithm::Ed25519);

    let attached = cose_sign1_with_signer(
        &signer,
        PAYLOAD,
        Some(KID),
        &[],
        CoseSign1EncodeOptions::default(),
    )
    .expect("provider-backed attached signing must succeed");
    let verified = cose_verify1_with_policy(&attached, &policy, |_, _| Some(public_key.to_vec()))
        .expect("provider-backed attached signature must verify");
    assert_eq!(verified.payload.as_slice(), PAYLOAD);
    assert_eq!(verified.kid.as_slice(), KID);

    let detached = cose_sign1_detached_with_signer(
        &signer,
        PAYLOAD,
        Some(KID),
        &[],
        CoseSign1EncodeOptions::default(),
    )
    .expect("provider-backed detached signing must succeed");
    let verified = cose_verify1_detached_with_policy(&detached, PAYLOAD, &policy, |_, _| {
        Some(public_key.clone())
    })
    .expect("provider-backed detached signature must verify");
    assert_eq!(verified.kid.as_slice(), KID);
}

#[test]
fn provider_failures_map_to_stable_native_errors() {
    for (provider_error, expected) in [
        (
            CoseSignerError::UnsupportedAlgorithm,
            CoseError::UnsupportedAlgorithm,
        ),
        (CoseSignerError::InvalidKey, CoseError::InvalidKeyMaterial),
        (CoseSignerError::Unavailable, CoseError::ProviderUnavailable),
        (CoseSignerError::Backend, CoseError::Crypto),
    ] {
        let signer = FailingPlatformSigner {
            error: provider_error,
        };
        let result = cose_sign1_with_signer(
            &signer,
            PAYLOAD,
            Some(KID),
            &[],
            CoseSign1EncodeOptions::default(),
        );
        assert_eq!(result, Err(expected));
    }
}
