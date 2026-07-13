// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

use coset::{iana, CoseKey, Label, RegisteredLabel};

use reallyme_crypto::core::Algorithm;

use reallyme_codec::multikey::{encode_multikey, parse_multikey};

use crate::{cose_key_from_public_bytes, cose_key_to_public_bytes, CoseError};

/// Convert COSE_Key (public) → multikey string.
pub fn cose_key_to_multikey(key: &CoseKey) -> Result<String, CoseError> {
    let alg = algorithm_from_cose_key(key)?;

    let public_key = cose_key_to_public_bytes(key)?;

    let codec_name = match alg {
        Algorithm::Ed25519 => "ed25519-pub",
        Algorithm::X25519 => "x25519-pub",
        Algorithm::P256 => "p256-pub",
        Algorithm::P384 => "p384-pub",
        Algorithm::P521 => "p521-pub",
        Algorithm::Secp256k1 => "secp256k1-pub",
        // These algorithms are defined by the wider crypto plane, but this
        // COSE bridge only maps the currently supported COSE_Key profiles.
        // New algorithms should be added here only with an intentional
        // COSE/COSE_Key representation and vectors.
        Algorithm::MlDsa44
        | Algorithm::MlDsa65
        | Algorithm::MlDsa87
        | Algorithm::MlKem512
        | Algorithm::MlKem768
        | Algorithm::MlKem1024
        | Algorithm::XWing768
        | Algorithm::XWing1024 => return Err(CoseError::UnsupportedAlgorithm),
    };

    encode_multikey(codec_name, &public_key).map_err(|_| CoseError::InvalidFormat)
}

/// Extract Algorithm from COSE_Key (strict)
fn algorithm_from_cose_key(key: &CoseKey) -> Result<Algorithm, CoseError> {
    match key.kty {
        RegisteredLabel::Assigned(iana::KeyType::OKP) => {
            let crv = key
                .params
                .iter()
                .find(|(l, _)| *l == Label::Int(iana::OkpKeyParameter::Crv as i64))
                .and_then(|(_, v)| v.as_integer())
                .and_then(|i| TryInto::<i64>::try_into(i).ok())
                .ok_or(CoseError::InvalidFormat)?;

            match crv {
                x if x == iana::EllipticCurve::Ed25519 as i64 => Ok(Algorithm::Ed25519),
                x if x == iana::EllipticCurve::X25519 as i64 => Ok(Algorithm::X25519),
                _ => Err(CoseError::UnsupportedAlgorithm),
            }
        }

        RegisteredLabel::Assigned(iana::KeyType::EC2) => {
            let crv = key
                .params
                .iter()
                .find(|(l, _)| *l == Label::Int(iana::Ec2KeyParameter::Crv as i64))
                .and_then(|(_, v)| v.as_integer())
                .and_then(|i| TryInto::<i64>::try_into(i).ok())
                .ok_or(CoseError::InvalidFormat)?;

            match crv {
                x if x == iana::EllipticCurve::P_256 as i64 => Ok(Algorithm::P256),
                x if x == iana::EllipticCurve::P_384 as i64 => Ok(Algorithm::P384),
                x if x == iana::EllipticCurve::P_521 as i64 => Ok(Algorithm::P521),
                x if x == iana::EllipticCurve::Secp256k1 as i64 => Ok(Algorithm::Secp256k1),
                _ => Err(CoseError::UnsupportedAlgorithm),
            }
        }

        _ => Err(CoseError::UnsupportedAlgorithm),
    }
}

/// Convert multikey string → COSE_Key (public only).
pub fn multikey_to_cose_key(multikey: &str) -> Result<CoseKey, CoseError> {
    let parsed = parse_multikey(multikey).map_err(|_| CoseError::InvalidFormat)?;

    let alg = match parsed.codec_name {
        "ed25519-pub" => Algorithm::Ed25519,
        "x25519-pub" => Algorithm::X25519,
        "p256-pub" => Algorithm::P256,
        "p384-pub" => Algorithm::P384,
        "p521-pub" => Algorithm::P521,
        "secp256k1-pub" => Algorithm::Secp256k1,
        // The multikey codec is valid, but this bridge does not currently map
        // it into a deliberate COSE_Key representation.
        _ => return Err(CoseError::UnsupportedAlgorithm),
    };

    // ParsedMultikey already exposes the raw public key bytes
    cose_key_from_public_bytes(alg, &parsed.public_key)
}
