// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Elliptic-curve COSE_Key profile and point conversion helpers.

use coset::{iana, CoseKeyBuilder};
use reallyme_crypto::core::Algorithm;

use crate::CoseError;

use super::profile::{get_param_bytes, get_param_value};
use super::validate_material::validate_public_key;

const COMPRESSED_POINT_PREFIX_BYTES: usize = 1;
const COMPRESSED_POINT_EVEN_PREFIX: u8 = 0x02;
const COMPRESSED_POINT_ODD_PREFIX: u8 = 0x03;
const UNCOMPRESSED_POINT_PREFIX: u8 = 0x04;

pub(crate) const P256_COORDINATE_BYTES: usize = 32;
pub(crate) const P384_COORDINATE_BYTES: usize = 48;
pub(crate) const P521_COORDINATE_BYTES: usize = 66;

#[derive(Clone, Copy)]
pub(crate) struct Ec2Profile {
    pub(crate) curve: iana::EllipticCurve,
    pub(crate) alg: iana::Algorithm,
    pub(crate) coordinate_len: usize,
}

pub(crate) fn ec2_profile(algorithm: Algorithm) -> Result<Ec2Profile, CoseError> {
    match algorithm {
        Algorithm::P256 => Ok(Ec2Profile {
            curve: iana::EllipticCurve::P_256,
            alg: iana::Algorithm::ESP256,
            coordinate_len: P256_COORDINATE_BYTES,
        }),
        Algorithm::P384 => Ok(Ec2Profile {
            curve: iana::EllipticCurve::P_384,
            alg: iana::Algorithm::ESP384,
            coordinate_len: P384_COORDINATE_BYTES,
        }),
        Algorithm::P521 => Ok(Ec2Profile {
            curve: iana::EllipticCurve::P_521,
            alg: iana::Algorithm::ESP512,
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

pub(crate) fn ec2_profile_from_curve(curve: i64) -> Result<Ec2Profile, CoseError> {
    if curve == iana::EllipticCurve::P_256 as i64 {
        return ec2_profile(Algorithm::P256);
    }
    if curve == iana::EllipticCurve::P_384 as i64 {
        return ec2_profile(Algorithm::P384);
    }
    if curve == iana::EllipticCurve::P_521 as i64 {
        return ec2_profile(Algorithm::P521);
    }
    if curve == iana::EllipticCurve::Secp256k1 as i64 {
        return ec2_profile(Algorithm::Secp256k1);
    }
    Err(CoseError::UnsupportedAlgorithm)
}

pub(crate) fn ec2_public_key_builder(
    profile: Ec2Profile,
    public_key: &[u8],
) -> Result<CoseKeyBuilder, CoseError> {
    let compressed_len = compressed_point_len(profile)?;
    let raw_len = raw_point_len(profile)?;
    let uncompressed_len = raw_len
        .checked_add(COMPRESSED_POINT_PREFIX_BYTES)
        .ok_or(CoseError::InvalidFormat)?;

    if public_key.len() == compressed_len {
        let prefix = public_key
            .first()
            .copied()
            .ok_or(CoseError::InvalidKeyMaterial)?;
        if matches!(
            prefix,
            COMPRESSED_POINT_EVEN_PREFIX | COMPRESSED_POINT_ODD_PREFIX
        ) {
            let x = public_key
                .get(COMPRESSED_POINT_PREFIX_BYTES..compressed_len)
                .ok_or(CoseError::InvalidKeyMaterial)?
                .to_vec();
            return Ok(CoseKeyBuilder::new_ec2_pub_key_y_sign(
                profile.curve,
                x,
                prefix == COMPRESSED_POINT_ODD_PREFIX,
            ));
        }
    }

    if public_key.len() == raw_len {
        let x = public_key
            .get(..profile.coordinate_len)
            .ok_or(CoseError::InvalidKeyMaterial)?
            .to_vec();
        let y = public_key
            .get(profile.coordinate_len..raw_len)
            .ok_or(CoseError::InvalidKeyMaterial)?
            .to_vec();
        return Ok(CoseKeyBuilder::new_ec2_pub_key(profile.curve, x, y));
    }

    if public_key.len() == uncompressed_len
        && public_key.first().copied() == Some(UNCOMPRESSED_POINT_PREFIX)
    {
        let x_start = COMPRESSED_POINT_PREFIX_BYTES;
        let y_start = x_start
            .checked_add(profile.coordinate_len)
            .ok_or(CoseError::InvalidFormat)?;
        let x = public_key
            .get(x_start..y_start)
            .ok_or(CoseError::InvalidKeyMaterial)?
            .to_vec();
        let y = public_key
            .get(y_start..uncompressed_len)
            .ok_or(CoseError::InvalidKeyMaterial)?
            .to_vec();
        return Ok(CoseKeyBuilder::new_ec2_pub_key(profile.curve, x, y));
    }

    Err(CoseError::InvalidKeyMaterial)
}

pub(crate) fn canonical_ec_public_key(
    profile: Ec2Profile,
    public_key: &[u8],
) -> Result<Vec<u8>, CoseError> {
    let compressed_len = compressed_point_len(profile)?;
    let raw_len = raw_point_len(profile)?;
    let uncompressed_len = raw_len
        .checked_add(COMPRESSED_POINT_PREFIX_BYTES)
        .ok_or(CoseError::InvalidFormat)?;

    if public_key.len() == compressed_len
        && matches!(
            public_key.first().copied(),
            Some(COMPRESSED_POINT_EVEN_PREFIX | COMPRESSED_POINT_ODD_PREFIX)
        )
    {
        validate_supplied_point(profile, public_key, raw_len, uncompressed_len)?;
        return Ok(public_key.to_vec());
    }

    let (x, y) = if public_key.len() == raw_len {
        (
            public_key
                .get(..profile.coordinate_len)
                .ok_or(CoseError::InvalidKeyMaterial)?,
            public_key
                .get(profile.coordinate_len..raw_len)
                .ok_or(CoseError::InvalidKeyMaterial)?,
        )
    } else if public_key.len() == uncompressed_len
        && public_key.first().copied() == Some(UNCOMPRESSED_POINT_PREFIX)
    {
        let x_start = COMPRESSED_POINT_PREFIX_BYTES;
        let y_start = x_start
            .checked_add(profile.coordinate_len)
            .ok_or(CoseError::InvalidFormat)?;
        (
            public_key
                .get(x_start..y_start)
                .ok_or(CoseError::InvalidKeyMaterial)?,
            public_key
                .get(y_start..uncompressed_len)
                .ok_or(CoseError::InvalidKeyMaterial)?,
        )
    } else {
        return Err(CoseError::InvalidKeyMaterial);
    };

    // Compression must never repair an invalid caller-supplied y-coordinate.
    // Validate the complete SEC1 point first; only then is it safe to retain
    // the y parity and discard the remaining coordinate bytes.
    validate_supplied_point(profile, public_key, raw_len, uncompressed_len)?;

    let y_last = y.last().copied().ok_or(CoseError::InvalidKeyMaterial)?;
    let mut canonical = Vec::with_capacity(compressed_len);
    canonical.push(if y_last & 1 == 1 {
        COMPRESSED_POINT_ODD_PREFIX
    } else {
        COMPRESSED_POINT_EVEN_PREFIX
    });
    canonical.extend_from_slice(x);
    Ok(canonical)
}

fn validate_supplied_point(
    profile: Ec2Profile,
    public_key: &[u8],
    raw_len: usize,
    uncompressed_len: usize,
) -> Result<(), CoseError> {
    let algorithm = algorithm_for_ec2_profile(profile)?;
    if public_key.len() != raw_len {
        return validate_public_key(algorithm, public_key);
    }

    let mut sec1 = Vec::new();
    sec1.try_reserve_exact(uncompressed_len)
        .map_err(|_| CoseError::ResourceLimitExceeded)?;
    sec1.push(UNCOMPRESSED_POINT_PREFIX);
    sec1.extend_from_slice(public_key);
    validate_public_key(algorithm, &sec1)
}

pub(crate) fn ec2_public_bytes_from_key(
    key: &coset::CoseKey,
    profile: Ec2Profile,
) -> Result<Vec<u8>, CoseError> {
    let x = get_param_bytes(key, iana::Ec2KeyParameter::X as i64)
        .ok_or(CoseError::MissingKeyMaterial)?;
    let y = get_param_value(key, iana::Ec2KeyParameter::Y as i64)
        .ok_or(CoseError::MissingKeyMaterial)?;
    let mut public_key = Vec::with_capacity(compressed_point_len(profile)?);
    if let Some(y_sign) = y.as_bool() {
        public_key.push(if y_sign {
            COMPRESSED_POINT_ODD_PREFIX
        } else {
            COMPRESSED_POINT_EVEN_PREFIX
        });
        public_key.extend_from_slice(x);
        return Ok(public_key);
    }

    let y = y.as_bytes().ok_or(CoseError::InvalidFormat)?;
    let y_last = y.last().copied().ok_or(CoseError::InvalidKeyMaterial)?;
    public_key.push(if y_last & 1 == 1 {
        COMPRESSED_POINT_ODD_PREFIX
    } else {
        COMPRESSED_POINT_EVEN_PREFIX
    });
    public_key.extend_from_slice(x);
    Ok(public_key)
}

pub(crate) fn algorithm_for_ec2_profile(profile: Ec2Profile) -> Result<Algorithm, CoseError> {
    match profile.curve {
        iana::EllipticCurve::P_256 => Ok(Algorithm::P256),
        iana::EllipticCurve::P_384 => Ok(Algorithm::P384),
        iana::EllipticCurve::P_521 => Ok(Algorithm::P521),
        iana::EllipticCurve::Secp256k1 => Ok(Algorithm::Secp256k1),
        _ => Err(CoseError::UnsupportedAlgorithm),
    }
}

fn compressed_point_len(profile: Ec2Profile) -> Result<usize, CoseError> {
    profile
        .coordinate_len
        .checked_add(COMPRESSED_POINT_PREFIX_BYTES)
        .ok_or(CoseError::InvalidFormat)
}

fn raw_point_len(profile: Ec2Profile) -> Result<usize, CoseError> {
    profile
        .coordinate_len
        .checked_mul(2)
        .ok_or(CoseError::InvalidFormat)
}
