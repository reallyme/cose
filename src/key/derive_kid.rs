// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0
use crate::CoseError;

use coset::{iana, CborSerializable, CoseKey, CoseKeyBuilder, Label, RegisteredLabel};
use reallyme_codec::cbor::sha2_256_content_hash;

fn get_param_bytes(key: &CoseKey, label: i64) -> Option<&[u8]> {
    key.params
        .iter()
        .find(|(l, _)| *l == Label::Int(label))
        .and_then(|(_, v)| v.as_bytes())
        .map(|v| v.as_slice())
}

fn get_param_bool(key: &CoseKey, label: i64) -> Option<bool> {
    key.params
        .iter()
        .find(|(l, _)| *l == Label::Int(label))
        .and_then(|(_, v)| v.as_bool())
}

fn get_param_i64(key: &CoseKey, label: i64) -> Option<i64> {
    key.params
        .iter()
        .find(|(l, _)| *l == Label::Int(label))
        .and_then(|(_, v)| v.as_integer())
        .and_then(|i| i.try_into().ok())
}

fn curve_from_i64(v: i64) -> Option<iana::EllipticCurve> {
    if v == iana::EllipticCurve::Ed25519 as i64 {
        Some(iana::EllipticCurve::Ed25519)
    } else if v == iana::EllipticCurve::X25519 as i64 {
        Some(iana::EllipticCurve::X25519)
    } else if v == iana::EllipticCurve::P_256 as i64 {
        Some(iana::EllipticCurve::P_256)
    } else if v == iana::EllipticCurve::P_384 as i64 {
        Some(iana::EllipticCurve::P_384)
    } else if v == iana::EllipticCurve::P_521 as i64 {
        Some(iana::EllipticCurve::P_521)
    } else if v == iana::EllipticCurve::Secp256k1 as i64 {
        Some(iana::EllipticCurve::Secp256k1)
    } else {
        None
    }
}

/// Derive `kid = SHA-256(canonical COSE_Key(public))`.
/// The input may contain private material; it is ignored for derivation.
pub fn derive_kid_from_cose_key_public(key: &CoseKey) -> Result<Vec<u8>, CoseError> {
    let public_only: CoseKey = match key.kty {
        RegisteredLabel::Assigned(iana::KeyType::OKP) => {
            let crv_i = get_param_i64(key, iana::OkpKeyParameter::Crv as i64)
                .ok_or(CoseError::InvalidFormat)?;
            let crv = curve_from_i64(crv_i).ok_or(CoseError::UnsupportedAlgorithm)?;

            let x = get_param_bytes(key, iana::OkpKeyParameter::X as i64)
                .ok_or(CoseError::MissingKeyMaterial)?
                .to_vec();

            // Minimal public-only OKP key: kty + crv + x (no kid/alg/ops/base_iv/d)
            CoseKeyBuilder::new_okp_key()
                .param(
                    iana::OkpKeyParameter::Crv as i64,
                    ciborium::value::Value::Integer((crv as i64).into()),
                )
                .param(
                    iana::OkpKeyParameter::X as i64,
                    ciborium::value::Value::Bytes(x),
                )
                .build()
        }

        RegisteredLabel::Assigned(iana::KeyType::EC2) => {
            let crv_i = get_param_i64(key, iana::Ec2KeyParameter::Crv as i64)
                .ok_or(CoseError::InvalidFormat)?;
            let crv = curve_from_i64(crv_i).ok_or(CoseError::UnsupportedAlgorithm)?;

            let x = get_param_bytes(key, iana::Ec2KeyParameter::X as i64)
                .ok_or(CoseError::MissingKeyMaterial)?
                .to_vec();

            // If Y is boolean => compressed form (y_sign)
            if let Some(y_sign) = get_param_bool(key, iana::Ec2KeyParameter::Y as i64) {
                CoseKeyBuilder::new_ec2_pub_key_y_sign(crv, x, y_sign).build()
            } else {
                let y = get_param_bytes(key, iana::Ec2KeyParameter::Y as i64)
                    .ok_or(CoseError::MissingKeyMaterial)?
                    .to_vec();
                CoseKeyBuilder::new_ec2_pub_key(crv, x, y).build()
            }
        }

        _ => return Err(CoseError::UnsupportedAlgorithm),
    };

    let canonical = public_only.to_vec().map_err(|_| CoseError::Cbor)?;

    Ok(sha2_256_content_hash(&canonical).to_vec())
}
