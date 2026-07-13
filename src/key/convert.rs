// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0
use crate::CoseError;
use ciborium::value::Value;
use coset::{iana, CborSerializable, CoseKey, CoseKeyBuilder, Label, RegisteredLabelWithPrivate};
use reallyme_crypto::core::Algorithm;
use zeroize::Zeroizing;

use crate::limits::validate_cose_key_bytes;

const COMPRESSED_EC_POINT_PREFIX_LEN: usize = 1;
const COMPRESSED_EC_POINT_EVEN_PREFIX: u8 = 0x02;
const COMPRESSED_EC_POINT_ODD_PREFIX: u8 = 0x03;
const UNCOMPRESSED_EC_POINT_PREFIX: u8 = 0x04;
pub(crate) const P256_COORDINATE_BYTES: usize = 32;
pub(crate) const P384_COORDINATE_BYTES: usize = 48;
pub(crate) const P521_COORDINATE_BYTES: usize = 66;
const ED25519_PUBLIC_KEY_BYTES: usize = 32;
const ED25519_SECRET_KEY_BYTES: usize = 32;
const X25519_PUBLIC_KEY_BYTES: usize = 32;

#[derive(Clone, Copy)]
struct Ec2Profile {
    curve: iana::EllipticCurve,
    alg: iana::Algorithm,
    coordinate_len: usize,
}

#[derive(Clone, Copy)]
enum KeyProfile {
    Okp(OkpProfile),
    Ec2(Ec2Profile),
}

#[derive(Clone, Copy)]
struct OkpProfile {
    alg: Option<iana::Algorithm>,
    coordinate_len: usize,
}

/// Decode a COSE_Key from canonical, untagged CBOR bytes.
pub fn cose_key_from_slice(bytes: &[u8]) -> Result<CoseKey, CoseError> {
    validate_cose_key_bytes(bytes)?;
    let key = CoseKey::from_slice(bytes).map_err(|_| CoseError::Cbor)?;
    validate_cose_key_profile(&key)?;
    Ok(key)
}

/// Encode a COSE_Key to canonical CBOR bytes.
pub fn cose_key_to_vec(key: &CoseKey) -> Result<Vec<u8>, CoseError> {
    let encoded = key.clone().to_vec().map_err(|_| CoseError::Cbor)?;
    validate_cose_key_bytes(&encoded)?;
    Ok(encoded)
}

/// Build a COSE_Key from raw public key bytes
pub fn cose_key_from_public_bytes(alg: Algorithm, public_key: &[u8]) -> Result<CoseKey, CoseError> {
    match alg {
        Algorithm::Ed25519 => {
            if public_key.len() != ED25519_PUBLIC_KEY_BYTES {
                return Err(CoseError::InvalidKeyMaterial);
            }
            Ok(CoseKeyBuilder::new_okp_key()
                .param(
                    iana::OkpKeyParameter::Crv as i64,
                    Value::Integer((iana::EllipticCurve::Ed25519 as i64).into()),
                )
                .param(
                    iana::OkpKeyParameter::X as i64,
                    Value::Bytes(public_key.to_vec()),
                )
                .algorithm(iana::Algorithm::EdDSA)
                .build())
        }

        Algorithm::X25519 => {
            if public_key.len() != X25519_PUBLIC_KEY_BYTES {
                return Err(CoseError::InvalidKeyMaterial);
            }
            Ok(CoseKeyBuilder::new_okp_key()
                .param(
                    iana::OkpKeyParameter::Crv as i64,
                    Value::Integer((iana::EllipticCurve::X25519 as i64).into()),
                )
                .param(
                    iana::OkpKeyParameter::X as i64,
                    Value::Bytes(public_key.to_vec()),
                )
                .build())
        }

        Algorithm::P256 | Algorithm::P384 | Algorithm::P521 | Algorithm::Secp256k1 => {
            let profile = ec2_profile(alg)?;
            Ok(ec2_public_key_builder(profile, public_key)?
                .algorithm(profile.alg)
                .build())
        }

        _ => Err(CoseError::UnsupportedAlgorithm),
    }
}

/// Extract raw public key bytes from a COSE_Key
pub fn cose_key_to_public_bytes(key: &CoseKey) -> Result<Vec<u8>, CoseError> {
    let profile = validate_cose_key_profile(key)?;
    match profile {
        KeyProfile::Okp(profile) => {
            let x = get_param_bytes(key, iana::OkpKeyParameter::X as i64)
                .ok_or(CoseError::MissingKeyMaterial)?;
            if x.len() != profile.coordinate_len {
                return Err(CoseError::InvalidKeyMaterial);
            }

            Ok(x.to_vec())
        }

        KeyProfile::Ec2(profile) => {
            let x = get_param_bytes(key, iana::Ec2KeyParameter::X as i64)
                .ok_or(CoseError::MissingKeyMaterial)?;
            if x.len() != profile.coordinate_len {
                return Err(CoseError::InvalidKeyMaterial);
            }

            let y_val = get_param_value(key, iana::Ec2KeyParameter::Y as i64)
                .ok_or(CoseError::MissingKeyMaterial)?;

            // EC2 compressed form: Y is a boolean "y_sign".
            if let Some(y_sign) = y_val.as_bool() {
                let prefix = if y_sign {
                    COMPRESSED_EC_POINT_ODD_PREFIX
                } else {
                    COMPRESSED_EC_POINT_EVEN_PREFIX
                };
                let len = x
                    .len()
                    .checked_add(COMPRESSED_EC_POINT_PREFIX_LEN)
                    .ok_or(CoseError::InvalidFormat)?;
                let mut out = Vec::with_capacity(len);
                out.push(prefix);
                out.extend_from_slice(x);
                return Ok(out);
            }

            // EC2 uncompressed form: Y is bytes.
            let y = y_val.as_bytes().ok_or(CoseError::InvalidFormat)?;
            if y.len() != profile.coordinate_len {
                return Err(CoseError::InvalidKeyMaterial);
            }

            let len = x
                .len()
                .checked_add(y.len())
                .ok_or(CoseError::InvalidFormat)?;
            let mut out = Vec::with_capacity(len);
            out.extend_from_slice(x);
            out.extend_from_slice(y);
            Ok(out)
        }
    }
}

/// Build a COSE_Key from raw private key bytes
pub fn cose_key_from_private_bytes(
    alg: Algorithm,
    private_key: &[u8],
    public_key: Option<&[u8]>,
) -> Result<CoseKey, CoseError> {
    match alg {
        Algorithm::Ed25519 => {
            if private_key.len() != ED25519_SECRET_KEY_BYTES {
                return Err(CoseError::InvalidKeyMaterial);
            }
            let mut b = CoseKeyBuilder::new_okp_key()
                .param(
                    iana::OkpKeyParameter::Crv as i64,
                    Value::Integer((iana::EllipticCurve::Ed25519 as i64).into()),
                )
                .param(
                    iana::OkpKeyParameter::D as i64,
                    Value::Bytes(private_key.to_vec()),
                )
                .algorithm(iana::Algorithm::EdDSA);

            if let Some(pk) = public_key {
                b = b.param(iana::OkpKeyParameter::X as i64, Value::Bytes(pk.to_vec()));
            }

            Ok(b.build())
        }

        Algorithm::P256 | Algorithm::P384 | Algorithm::P521 | Algorithm::Secp256k1 => {
            let profile = ec2_profile(alg)?;
            if private_key.len() != profile.coordinate_len {
                return Err(CoseError::InvalidKeyMaterial);
            }
            let b = if let Some(pk) = public_key {
                ec2_public_key_builder(profile, pk)?
                    .param(
                        iana::Ec2KeyParameter::D as i64,
                        Value::Bytes(private_key.to_vec()),
                    )
                    .algorithm(profile.alg)
            } else {
                CoseKeyBuilder::new_ec2_priv_key(
                    profile.curve,
                    vec![], // x optional
                    vec![], // y optional
                    private_key.to_vec(),
                )
                .algorithm(profile.alg)
            };

            Ok(b.build())
        }

        _ => Err(CoseError::UnsupportedAlgorithm),
    }
}

/// Extract raw private key bytes from a COSE_Key.
///
/// The returned buffer zeroizes on drop because callers often need to hand
/// these bytes to a backend that accepts raw key material.
pub fn cose_key_to_private_bytes(key: &CoseKey) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    validate_cose_key_profile(key)?;
    let d = key
        .params
        .iter()
        .find(|(l, _)| {
            *l == Label::Int(iana::Ec2KeyParameter::D as i64)
                || *l == Label::Int(iana::OkpKeyParameter::D as i64)
        })
        .and_then(|(_, v)| v.as_bytes())
        .ok_or(CoseError::MissingKeyMaterial)?;

    Ok(Zeroizing::new(d.to_vec()))
}

fn ec2_profile(alg: Algorithm) -> Result<Ec2Profile, CoseError> {
    match alg {
        Algorithm::P256 => Ok(Ec2Profile {
            curve: iana::EllipticCurve::P_256,
            alg: iana::Algorithm::ES256,
            coordinate_len: P256_COORDINATE_BYTES,
        }),
        Algorithm::P384 => Ok(Ec2Profile {
            curve: iana::EllipticCurve::P_384,
            alg: iana::Algorithm::ES384,
            coordinate_len: P384_COORDINATE_BYTES,
        }),
        Algorithm::P521 => Ok(Ec2Profile {
            curve: iana::EllipticCurve::P_521,
            alg: iana::Algorithm::ES512,
            coordinate_len: P521_COORDINATE_BYTES,
        }),
        Algorithm::Secp256k1 => Ok(Ec2Profile {
            curve: iana::EllipticCurve::Secp256k1,
            alg: iana::Algorithm::ES256K,
            coordinate_len: P256_COORDINATE_BYTES,
        }),
        _ => Err(CoseError::UnsupportedAlgorithm),
    }
}

fn validate_cose_key_profile(key: &CoseKey) -> Result<KeyProfile, CoseError> {
    match key.kty {
        coset::RegisteredLabel::Assigned(iana::KeyType::OKP) => {
            let crv = get_param_i64(key, iana::OkpKeyParameter::Crv as i64)
                .ok_or(CoseError::InvalidFormat)?;
            let profile = okp_profile(crv)?;
            validate_key_algorithm(key, profile.alg)?;
            validate_optional_param_len(
                key,
                iana::OkpKeyParameter::X as i64,
                profile.coordinate_len,
            )?;
            validate_optional_param_len(
                key,
                iana::OkpKeyParameter::D as i64,
                profile.coordinate_len,
            )?;

            if get_param_bytes(key, iana::OkpKeyParameter::X as i64).is_none()
                && get_param_bytes(key, iana::OkpKeyParameter::D as i64).is_none()
            {
                return Err(CoseError::MissingKeyMaterial);
            }

            Ok(KeyProfile::Okp(profile))
        }
        coset::RegisteredLabel::Assigned(iana::KeyType::EC2) => {
            let crv = get_param_i64(key, iana::Ec2KeyParameter::Crv as i64)
                .ok_or(CoseError::InvalidFormat)?;
            let profile = ec2_profile_from_curve(crv)?;
            validate_key_algorithm(key, Some(profile.alg))?;
            validate_optional_param_len(
                key,
                iana::Ec2KeyParameter::X as i64,
                profile.coordinate_len,
            )?;
            validate_optional_param_len(
                key,
                iana::Ec2KeyParameter::D as i64,
                profile.coordinate_len,
            )?;

            if let Some(y) = get_param_value(key, iana::Ec2KeyParameter::Y as i64) {
                if y.as_bool().is_none() {
                    let y_bytes = y.as_bytes().ok_or(CoseError::InvalidFormat)?;
                    if !y_bytes.is_empty() && y_bytes.len() != profile.coordinate_len {
                        return Err(CoseError::InvalidKeyMaterial);
                    }
                }
            }

            if get_param_bytes(key, iana::Ec2KeyParameter::D as i64).is_none()
                && (get_param_bytes(key, iana::Ec2KeyParameter::X as i64).is_none()
                    || get_param_value(key, iana::Ec2KeyParameter::Y as i64).is_none())
            {
                return Err(CoseError::MissingKeyMaterial);
            }

            Ok(KeyProfile::Ec2(profile))
        }
        _ => Err(CoseError::UnsupportedAlgorithm),
    }
}

fn okp_profile(crv: i64) -> Result<OkpProfile, CoseError> {
    if crv == iana::EllipticCurve::Ed25519 as i64 {
        return Ok(OkpProfile {
            alg: Some(iana::Algorithm::EdDSA),
            coordinate_len: ED25519_PUBLIC_KEY_BYTES,
        });
    }

    if crv == iana::EllipticCurve::X25519 as i64 {
        return Ok(OkpProfile {
            alg: None,
            coordinate_len: X25519_PUBLIC_KEY_BYTES,
        });
    }

    Err(CoseError::UnsupportedAlgorithm)
}

fn ec2_profile_from_curve(crv: i64) -> Result<Ec2Profile, CoseError> {
    if crv == iana::EllipticCurve::P_256 as i64 {
        return ec2_profile(Algorithm::P256);
    }

    if crv == iana::EllipticCurve::P_384 as i64 {
        return ec2_profile(Algorithm::P384);
    }

    if crv == iana::EllipticCurve::P_521 as i64 {
        return ec2_profile(Algorithm::P521);
    }

    if crv == iana::EllipticCurve::Secp256k1 as i64 {
        return ec2_profile(Algorithm::Secp256k1);
    }

    Err(CoseError::UnsupportedAlgorithm)
}

fn validate_key_algorithm(
    key: &CoseKey,
    expected: Option<iana::Algorithm>,
) -> Result<(), CoseError> {
    match (&key.alg, expected) {
        (None, _) => Ok(()),
        (Some(RegisteredLabelWithPrivate::Assigned(actual)), Some(expected_alg))
            if *actual == expected_alg =>
        {
            Ok(())
        }
        _ => Err(CoseError::UnsupportedAlgorithm),
    }
}

fn validate_optional_param_len(
    key: &CoseKey,
    label: i64,
    expected_len: usize,
) -> Result<(), CoseError> {
    if let Some(bytes) = get_param_bytes(key, label) {
        if !bytes.is_empty() && bytes.len() != expected_len {
            return Err(CoseError::InvalidKeyMaterial);
        }
    }

    Ok(())
}

fn get_param_value(key: &CoseKey, label: i64) -> Option<&Value> {
    key.params
        .iter()
        .find(|(candidate, _)| *candidate == Label::Int(label))
        .map(|(_, value)| value)
}

fn get_param_bytes(key: &CoseKey, label: i64) -> Option<&Vec<u8>> {
    get_param_value(key, label).and_then(|value| value.as_bytes())
}

fn get_param_i64(key: &CoseKey, label: i64) -> Option<i64> {
    get_param_value(key, label)
        .and_then(|value| value.as_integer())
        .and_then(|value| value.try_into().ok())
}

fn ec2_public_key_builder(
    profile: Ec2Profile,
    public_key: &[u8],
) -> Result<CoseKeyBuilder, CoseError> {
    let compressed_len = profile
        .coordinate_len
        .checked_add(COMPRESSED_EC_POINT_PREFIX_LEN)
        .ok_or(CoseError::InvalidFormat)?;
    let raw_len = profile
        .coordinate_len
        .checked_mul(2)
        .ok_or(CoseError::InvalidFormat)?;
    let uncompressed_len = raw_len
        .checked_add(COMPRESSED_EC_POINT_PREFIX_LEN)
        .ok_or(CoseError::InvalidFormat)?;

    match public_key.len() {
        len if len == compressed_len
            && (public_key[0] == COMPRESSED_EC_POINT_EVEN_PREFIX
                || public_key[0] == COMPRESSED_EC_POINT_ODD_PREFIX) =>
        {
            let y_sign = public_key[0] == COMPRESSED_EC_POINT_ODD_PREFIX;
            let x = public_key[COMPRESSED_EC_POINT_PREFIX_LEN..compressed_len].to_vec();
            Ok(CoseKeyBuilder::new_ec2_pub_key_y_sign(
                profile.curve,
                x,
                y_sign,
            ))
        }
        len if len == raw_len => {
            let x = public_key[..profile.coordinate_len].to_vec();
            let y = public_key[profile.coordinate_len..raw_len].to_vec();
            Ok(CoseKeyBuilder::new_ec2_pub_key(profile.curve, x, y))
        }
        len if len == uncompressed_len && public_key[0] == UNCOMPRESSED_EC_POINT_PREFIX => {
            let x_start = COMPRESSED_EC_POINT_PREFIX_LEN;
            let y_start = x_start
                .checked_add(profile.coordinate_len)
                .ok_or(CoseError::InvalidFormat)?;
            let x = public_key[x_start..y_start].to_vec();
            let y = public_key[y_start..uncompressed_len].to_vec();
            Ok(CoseKeyBuilder::new_ec2_pub_key(profile.curve, x, y))
        }
        _ => Err(CoseError::InvalidKeyMaterial),
    }
}
