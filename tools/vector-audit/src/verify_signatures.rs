// SPDX-FileCopyrightText: 2026 ReallyMe LLC

// SPDX-License-Identifier: MIT OR Apache-2.0

fn derived_public(algorithm: Algorithm, seed: &[u8]) -> AuditResult<Vec<u8>> {
    match algorithm {
        Algorithm::Ed25519 => {
            use ed25519_dalek::SigningKey;
            let seed_bytes = fixed_32(seed, AuditReason::InvalidSeedLength)?;
            let signing_key = SigningKey::from_bytes(&seed_bytes);
            Ok(signing_key.verifying_key().to_bytes().to_vec())
        }
        Algorithm::Es256 | Algorithm::P256 => {
            use p256::ecdsa::SigningKey;
            let signing_key = SigningKey::from_slice(seed)
                .map_err(|_| general(AuditReason::InvalidSeedLength))?;
            Ok(signing_key
                .verifying_key()
                .to_sec1_point(true)
                .as_bytes()
                .to_vec())
        }
        Algorithm::P384 => {
            use p384::ecdsa::SigningKey;
            let signing_key = SigningKey::from_slice(seed)
                .map_err(|_| general(AuditReason::InvalidSeedLength))?;
            Ok(signing_key
                .verifying_key()
                .to_sec1_point(true)
                .as_bytes()
                .to_vec())
        }
        Algorithm::P521 => {
            use p521::elliptic_curve::sec1::ToSec1Point;
            let secret_key = p521::SecretKey::from_slice(seed)
                .map_err(|_| general(AuditReason::InvalidSeedLength))?;
            Ok(secret_key
                .public_key()
                .to_sec1_point(true)
                .as_bytes()
                .to_vec())
        }
        Algorithm::Secp256k1 => {
            use k256::ecdsa::SigningKey;
            let signing_key = SigningKey::from_slice(seed)
                .map_err(|_| general(AuditReason::InvalidSeedLength))?;
            Ok(signing_key
                .verifying_key()
                .to_sec1_point(true)
                .as_bytes()
                .to_vec())
        }
        Algorithm::X25519 => Err(general(AuditReason::UnsupportedAlgorithm)),
    }
}

fn independent_verify(
    algorithm: Algorithm,
    public: &[u8],
    message: &[u8],
    signature: &[u8],
) -> AuditResult<bool> {
    match algorithm {
        Algorithm::Ed25519 => {
            use ed25519_dalek::{Signature, VerifyingKey};
            let public_key =
                VerifyingKey::from_bytes(&fixed_32(public, AuditReason::InvalidPublicKeyLength)?)
                    .map_err(|_| general(AuditReason::InvalidPublicKeyLength))?;
            let Ok(sig) = Signature::from_slice(signature) else {
                return Ok(false);
            };
            // The COSE profile rejects low-order points and malleable
            // signatures; the independent oracle must enforce that profile too.
            Ok(public_key.verify_strict(message, &sig).is_ok())
        }
        Algorithm::Es256 | Algorithm::P256 => {
            use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
            let Ok(public_key) = VerifyingKey::from_sec1_bytes(public) else {
                return Ok(false);
            };
            let Ok(sig) = Signature::from_slice(signature) else {
                return Ok(false);
            };
            Ok(public_key.verify(message, &sig).is_ok())
        }
        Algorithm::P384 => {
            use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
            let Ok(public_key) = VerifyingKey::from_sec1_bytes(public) else {
                return Ok(false);
            };
            let Ok(sig) = Signature::from_slice(signature) else {
                return Ok(false);
            };
            Ok(public_key.verify(message, &sig).is_ok())
        }
        Algorithm::P521 => {
            use p521::ecdsa::{signature::Verifier, Signature, VerifyingKey};
            let Ok(public_key) = VerifyingKey::from_sec1_bytes(public) else {
                return Ok(false);
            };
            let Ok(sig) = Signature::from_slice(signature) else {
                return Ok(false);
            };
            Ok(public_key.verify(message, &sig).is_ok())
        }
        Algorithm::Secp256k1 => {
            use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
            let Ok(public_key) = VerifyingKey::from_sec1_bytes(public) else {
                return Ok(false);
            };
            let Ok(sig) = Signature::from_slice(signature) else {
                return Ok(false);
            };
            Ok(public_key.verify(message, &sig).is_ok())
        }
        Algorithm::X25519 => Err(general(AuditReason::UnsupportedAlgorithm)),
    }
}

fn ec2_point_is_valid(algorithm: Algorithm, sec1: &[u8]) -> bool {
    match algorithm {
        Algorithm::Es256 | Algorithm::P256 => {
            p256::ecdsa::VerifyingKey::from_sec1_bytes(sec1).is_ok()
        }
        Algorithm::P384 => p384::ecdsa::VerifyingKey::from_sec1_bytes(sec1).is_ok(),
        Algorithm::P521 => p521::ecdsa::VerifyingKey::from_sec1_bytes(sec1).is_ok(),
        Algorithm::Secp256k1 => k256::ecdsa::VerifyingKey::from_sec1_bytes(sec1).is_ok(),
        Algorithm::Ed25519 | Algorithm::X25519 => false,
    }
}

fn cose_key_profile(algorithm: Algorithm) -> AuditResult<CoseKeyProfile> {
    match algorithm {
        Algorithm::Ed25519 => Ok(CoseKeyProfile {
            kty: 1,
            crv: 6,
            alg: Some(-19),
            multicodec: 0xed,
        }),
        Algorithm::X25519 => Ok(CoseKeyProfile {
            kty: 1,
            crv: 4,
            alg: None,
            multicodec: 0xec,
        }),
        Algorithm::P256 => Ok(CoseKeyProfile {
            kty: 2,
            crv: 1,
            alg: Some(-9),
            multicodec: 0x1200,
        }),
        Algorithm::Es256 => Ok(CoseKeyProfile {
            kty: 2,
            crv: 1,
            alg: Some(-7),
            multicodec: 0x1200,
        }),
        Algorithm::P384 => Ok(CoseKeyProfile {
            kty: 2,
            crv: 2,
            alg: Some(-51),
            multicodec: 0x1201,
        }),
        Algorithm::P521 => Ok(CoseKeyProfile {
            kty: 2,
            crv: 3,
            alg: Some(-52),
            multicodec: 0x1202,
        }),
        Algorithm::Secp256k1 => Ok(CoseKeyProfile {
            kty: 2,
            crv: 8,
            alg: Some(-47),
            multicodec: 0xe7,
        }),
    }
}
