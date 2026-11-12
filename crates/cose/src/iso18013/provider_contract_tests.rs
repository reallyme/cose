// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited

// SPDX-License-Identifier: MIT OR Apache-2.0

use p256::ecdsa::signature::hazmat::PrehashVerifier;
use reallyme_crypto::core::HashAlgorithm;
use zeroize::Zeroizing;

use crate::iso18013::{
    cose_verify_iso18013_sign1, Iso18013EcdsaHash, Iso18013Sign1Content, Iso18013SignatureCurve,
    Iso18013SignatureSuite, Iso18013Verifier,
};
use crate::CoseError;

use super::support::{assert_error, hex, request, suite, vectors, Vector};

enum PublicKey {
    P256(p256::ecdsa::VerifyingKey),
    P384(p384::ecdsa::VerifyingKey),
    P521(p521::ecdsa::VerifyingKey),
}

/// Test-only provider backed directly by RustCrypto. Production primitives stay
/// in the crypto repository; this adapter demonstrates the COSE provider contract
/// against independent OpenSSL fixtures for separately selected hashes/curves.
struct TestVerifier {
    suite: Iso18013SignatureSuite,
    key: PublicKey,
}

impl TestVerifier {
    fn from_vector(vector: &Vector) -> Result<Self, CoseError> {
        let suite = suite(vector)?;
        let encoded = Zeroizing::new(hex(&vector.public_key_hex));
        let key = match suite.curve() {
            Iso18013SignatureCurve::P256 => PublicKey::P256(
                p256::ecdsa::VerifyingKey::from_sec1_bytes(&encoded)
                    .map_err(|_| CoseError::InvalidKeyMaterial)?,
            ),
            Iso18013SignatureCurve::P384 => PublicKey::P384(
                p384::ecdsa::VerifyingKey::from_sec1_bytes(&encoded)
                    .map_err(|_| CoseError::InvalidKeyMaterial)?,
            ),
            Iso18013SignatureCurve::P521 => PublicKey::P521(
                p521::ecdsa::VerifyingKey::from_sec1_bytes(&encoded)
                    .map_err(|_| CoseError::InvalidKeyMaterial)?,
            ),
            _ => return Err(CoseError::UnsupportedAlgorithm),
        };
        Ok(Self { suite, key })
    }
}

impl Iso18013Verifier for TestVerifier {
    fn suite(&self) -> Iso18013SignatureSuite {
        self.suite
    }

    fn verify(&self, structure: &[u8], signature: &[u8]) -> Result<(), CoseError> {
        let hash = match self.suite.algorithm().ecdsa_hash() {
            Some(Iso18013EcdsaHash::Sha256) => HashAlgorithm::Sha2_256,
            Some(Iso18013EcdsaHash::Sha384) => HashAlgorithm::Sha2_384,
            Some(Iso18013EcdsaHash::Sha512) => HashAlgorithm::Sha2_512,
            None => return Err(CoseError::UnsupportedAlgorithm),
        };
        let digest = Zeroizing::new(
            reallyme_crypto::operations::hash::digest(hash, structure)
                .map_err(|_| CoseError::Crypto)?,
        );
        match &self.key {
            PublicKey::P256(key) => {
                let signature = p256::ecdsa::Signature::from_slice(signature)
                    .map_err(|_| CoseError::InvalidSignatureEncoding)?;
                key.verify_prehash(&digest, &signature)
                    .map_err(|_| CoseError::InvalidSignature)
            }
            PublicKey::P384(key) => {
                let signature = p384::ecdsa::Signature::from_slice(signature)
                    .map_err(|_| CoseError::InvalidSignatureEncoding)?;
                key.verify_prehash(&digest, &signature)
                    .map_err(|_| CoseError::InvalidSignature)
            }
            PublicKey::P521(key) => {
                let signature = p521::ecdsa::Signature::from_slice(signature)
                    .map_err(|_| CoseError::InvalidSignatureEncoding)?;
                key.verify_prehash(&digest, &signature)
                    .map_err(|_| CoseError::InvalidSignature)
            }
        }
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[test]
fn provider_selects_each_ecdsa_hash_and_curve_independently() -> Result<(), CoseError> {
    for vector in vectors()?.iter().filter(|vector| vector.curve != 6) {
        let verifier = TestVerifier::from_vector(vector)?;
        let suite = [suite(vector)?];
        let detached = hex(&vector.detached_hex);
        let payload = hex(&vector.payload_hex);
        for content in [
            Iso18013Sign1Content::DeviceDetached(payload.as_slice()),
            Iso18013Sign1Content::ReaderDetached(payload.as_slice()),
        ] {
            assert_eq!(
                cose_verify_iso18013_sign1(request(&detached, content, &suite), &verifier)?.suite(),
                suite[0]
            );
        }
        let attached = hex(&vector.attached_hex);
        cose_verify_iso18013_sign1(
            request(&attached, Iso18013Sign1Content::IssuerAttached, &suite),
            &verifier,
        )?;
        assert_error(
            cose_verify_iso18013_sign1(
                request(
                    &detached,
                    Iso18013Sign1Content::DeviceDetached(b"changed"),
                    &suite,
                ),
                &verifier,
            ),
            CoseError::InvalidSignature,
        );
    }
    Ok(())
}
