// SPDX-FileCopyrightText: 2026 ReallyMe LLC

// SPDX-License-Identifier: MIT OR Apache-2.0

//! Elliptic-curve COSE_Key profile and point conversion helpers.

use coset::{iana, CoseKeyBuilder};
use reallyme_crypto::core::Algorithm;

use crate::algorithm::CoseSignatureAlgorithm;
use crate::CoseError;

use super::encoding::CoseEc2PointEncoding;
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
    let signature_algorithm = CoseSignatureAlgorithm::from_crypto_algorithm(algorithm)?;
    ec2_profile_for_signature_algorithm(signature_algorithm)
}

pub(crate) fn ec2_profile_for_signature_algorithm(
    algorithm: CoseSignatureAlgorithm,
) -> Result<Ec2Profile, CoseError> {
    match algorithm {
        CoseSignatureAlgorithm::Es256 | CoseSignatureAlgorithm::Esp256 => Ok(Ec2Profile {
            curve: iana::EllipticCurve::P_256,
            alg: algorithm.to_iana(),
            coordinate_len: P256_COORDINATE_BYTES,
        }),
        CoseSignatureAlgorithm::Esp384 => Ok(Ec2Profile {
            curve: iana::EllipticCurve::P_384,
            alg: algorithm.to_iana(),
            coordinate_len: P384_COORDINATE_BYTES,
        }),
        CoseSignatureAlgorithm::Esp512 => Ok(Ec2Profile {
            curve: iana::EllipticCurve::P_521,
            alg: algorithm.to_iana(),
            coordinate_len: P521_COORDINATE_BYTES,
        }),
        CoseSignatureAlgorithm::Es256K => Ok(Ec2Profile {
            curve: iana::EllipticCurve::Secp256k1,
            alg: algorithm.to_iana(),
            coordinate_len: P256_COORDINATE_BYTES,
        }),
        CoseSignatureAlgorithm::Ed25519
        | CoseSignatureAlgorithm::MlDsa44
        | CoseSignatureAlgorithm::MlDsa65
        | CoseSignatureAlgorithm::MlDsa87 => Err(CoseError::UnsupportedAlgorithm),
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

pub(crate) fn ec_public_key_for_encoding(
    profile: Ec2Profile,
    public_key: &[u8],
    encoding: CoseEc2PointEncoding,
) -> Result<Vec<u8>, CoseError> {
    let canonical = canonical_ec_public_key(profile, public_key)?;
    match encoding {
        CoseEc2PointEncoding::Compressed => Ok(canonical),
        CoseEc2PointEncoding::FullCoordinates => expand_canonical_ec_point(profile, &canonical),
    }
}

#[cfg(feature = "cose-crypto")]
fn expand_canonical_ec_point(profile: Ec2Profile, canonical: &[u8]) -> Result<Vec<u8>, CoseError> {
    use reallyme_crypto::operations::key_encoding::{
        decompress_p256_public_key, decompress_p384_public_key, decompress_p521_public_key,
        decompress_secp256k1_public_key,
    };

    match profile.curve {
        iana::EllipticCurve::P_256 => {
            decompress_p256_public_key(canonical).map_err(|_| CoseError::InvalidKeyMaterial)
        }
        iana::EllipticCurve::P_384 => {
            decompress_p384_public_key(canonical).map_err(|_| CoseError::InvalidKeyMaterial)
        }
        iana::EllipticCurve::P_521 => {
            decompress_p521_public_key(canonical).map_err(|_| CoseError::InvalidKeyMaterial)
        }
        iana::EllipticCurve::Secp256k1 => {
            let (x, y) = decompress_secp256k1_public_key(canonical)
                .map_err(|_| CoseError::InvalidKeyMaterial)?;
            let raw_len = raw_point_len(profile)?;
            let uncompressed_len = raw_len
                .checked_add(COMPRESSED_POINT_PREFIX_BYTES)
                .ok_or(CoseError::ResourceLimitExceeded)?;
            if x.len() != profile.coordinate_len || y.len() != profile.coordinate_len {
                return Err(CoseError::InvalidKeyMaterial);
            }
            let mut expanded = Vec::new();
            expanded
                .try_reserve_exact(uncompressed_len)
                .map_err(|_| CoseError::ResourceLimitExceeded)?;
            expanded.push(UNCOMPRESSED_POINT_PREFIX);
            expanded.extend_from_slice(&x);
            expanded.extend_from_slice(&y);
            Ok(expanded)
        }
        _ => Err(CoseError::UnsupportedAlgorithm),
    }
}

#[cfg(not(feature = "cose-crypto"))]
fn expand_canonical_ec_point(
    _profile: Ec2Profile,
    _canonical: &[u8],
) -> Result<Vec<u8>, CoseError> {
    Err(CoseError::ProviderUnavailable)
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
    // Validate both submitted coordinates before discarding Y. Checking only
    // the compressed point would silently repair an off-curve Y coordinate.
    let uncompressed_len = raw_point_len(profile)?
        .checked_add(COMPRESSED_POINT_PREFIX_BYTES)
        .ok_or(CoseError::ResourceLimitExceeded)?;
    let mut supplied = Vec::new();
    supplied
        .try_reserve_exact(uncompressed_len)
        .map_err(|_| CoseError::ResourceLimitExceeded)?;
    supplied.push(UNCOMPRESSED_POINT_PREFIX);
    supplied.extend_from_slice(x);
    supplied.extend_from_slice(y);
    validate_public_key(algorithm_for_ec2_profile(profile)?, &supplied)?;
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
