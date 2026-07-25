// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Supported COSE_Key profile validation and parameter access.

use ciborium::value::Value;
use coset::{iana, Label, RegisteredLabel, RegisteredLabelWithPrivate};
use reallyme_crypto::core::Algorithm;

use crate::{CoseError, CoseKey};

use super::akp::{akp_profile_from_cose_algorithm, algorithm_for_akp_profile, AkpProfile};
use super::ec::{
    algorithm_for_ec2_profile, ec2_profile_from_curve, ec2_public_bytes_from_key, Ec2Profile,
};
use super::validate_material::{validate_private_public_pair, validate_public_key};

pub(crate) const ED25519_PUBLIC_KEY_BYTES: usize = 32;
pub(crate) const ED25519_SECRET_KEY_BYTES: usize = 32;
pub(crate) const X25519_PUBLIC_KEY_BYTES: usize = 32;

#[derive(Clone, Copy)]
pub(crate) enum KeyProfile {
    Okp(OkpProfile),
    Ec2(Ec2Profile),
    Akp(AkpProfile),
}

#[derive(Clone, Copy)]
pub(crate) struct OkpProfile {
    pub(crate) alg: Option<iana::Algorithm>,
    pub(crate) coordinate_len: usize,
}

pub(crate) fn validate_cose_key_profile(key: &CoseKey) -> Result<KeyProfile, CoseError> {
    let key = key.inner();
    match key.kty {
        RegisteredLabel::Assigned(iana::KeyType::OKP) => validate_okp_profile(key),
        RegisteredLabel::Assigned(iana::KeyType::EC2) => validate_ec2_profile(key),
        RegisteredLabel::Assigned(iana::KeyType::AKP) => validate_akp_profile(key),
        _ => Err(CoseError::UnsupportedAlgorithm),
    }
}

pub(crate) fn validate_parsed_cose_key(key: &CoseKey) -> Result<(), CoseError> {
    validate_cose_key_profile(key).map(|_| ())
}

pub(crate) fn algorithm_for_cose_key(key: &CoseKey) -> Result<Algorithm, CoseError> {
    match validate_cose_key_profile(key)? {
        KeyProfile::Okp(profile) => {
            if profile.alg == Some(iana::Algorithm::Ed25519) {
                Ok(Algorithm::Ed25519)
            } else {
                Ok(Algorithm::X25519)
            }
        }
        KeyProfile::Ec2(profile) => algorithm_for_ec2_profile(profile),
        KeyProfile::Akp(profile) => Ok(algorithm_for_akp_profile(profile)),
    }
}

fn validate_okp_profile(key: &coset::CoseKey) -> Result<KeyProfile, CoseError> {
    let curve =
        get_param_i64(key, iana::OkpKeyParameter::Crv as i64).ok_or(CoseError::InvalidFormat)?;
    let profile = okp_profile(curve)?;
    validate_key_algorithm(key, profile.alg)?;
    validate_optional_param_len(key, iana::OkpKeyParameter::X as i64, profile.coordinate_len)?;
    validate_optional_param_len(key, iana::OkpKeyParameter::D as i64, profile.coordinate_len)?;

    let public_key = get_param_bytes(key, iana::OkpKeyParameter::X as i64);
    let private_key = get_param_bytes(key, iana::OkpKeyParameter::D as i64);
    if public_key.is_none() && private_key.is_none() {
        return Err(CoseError::MissingKeyMaterial);
    }
    if private_key.is_some() && public_key.is_none() {
        // Private keys need an auditable public binding so every accepted key
        // can be validated identically after construction or parsing.
        return Err(CoseError::MissingKeyMaterial);
    }

    let is_signature = profile.alg == Some(iana::Algorithm::Ed25519);
    if private_key.is_some() && !is_signature {
        // X25519 remains public-only until private/public derivation is
        // implemented consistently across every runtime provider.
        return Err(CoseError::UnsupportedAlgorithm);
    }
    validate_key_operations(key, private_key.is_some(), is_signature)?;

    if let Some(public_key) = public_key {
        let algorithm = if is_signature {
            Algorithm::Ed25519
        } else {
            Algorithm::X25519
        };
        validate_public_key(algorithm, public_key)?;
        if let Some(private_key) = private_key {
            validate_private_public_pair(algorithm, private_key, public_key)?;
        }
    }

    Ok(KeyProfile::Okp(profile))
}

fn validate_ec2_profile(key: &coset::CoseKey) -> Result<KeyProfile, CoseError> {
    let curve =
        get_param_i64(key, iana::Ec2KeyParameter::Crv as i64).ok_or(CoseError::InvalidFormat)?;
    let profile = ec2_profile_from_curve(curve)?;
    validate_key_algorithm(key, Some(profile.alg))?;
    validate_optional_param_len(key, iana::Ec2KeyParameter::X as i64, profile.coordinate_len)?;
    validate_optional_param_len(key, iana::Ec2KeyParameter::D as i64, profile.coordinate_len)?;

    if let Some(y) = get_param_value(key, iana::Ec2KeyParameter::Y as i64) {
        if y.as_bool().is_none() {
            let y_bytes = y.as_bytes().ok_or(CoseError::InvalidFormat)?;
            if y_bytes.len() != profile.coordinate_len {
                return Err(CoseError::InvalidKeyMaterial);
            }
        }
    }

    let private_key = get_param_bytes(key, iana::Ec2KeyParameter::D as i64);
    let has_public_point = get_param_bytes(key, iana::Ec2KeyParameter::X as i64).is_some()
        && get_param_value(key, iana::Ec2KeyParameter::Y as i64).is_some();
    if private_key.is_none() && !has_public_point {
        return Err(CoseError::MissingKeyMaterial);
    }
    if private_key.is_some() && !has_public_point {
        // A private scalar without its public point cannot be checked for
        // scalar validity or private/public binding.
        return Err(CoseError::MissingKeyMaterial);
    }

    validate_key_operations(key, private_key.is_some(), true)?;
    if has_public_point {
        let algorithm = algorithm_for_ec2_profile(profile)?;
        let public_key = ec2_public_bytes_from_key(key, profile)?;
        validate_public_key(algorithm, &public_key)?;
        if let Some(private_key) = private_key {
            validate_private_public_pair(algorithm, private_key, &public_key)?;
        }
    }

    Ok(KeyProfile::Ec2(profile))
}

fn validate_akp_profile(key: &coset::CoseKey) -> Result<KeyProfile, CoseError> {
    let algorithm = key.alg.as_ref().ok_or(CoseError::UnsupportedAlgorithm)?;
    let profile = akp_profile_from_cose_algorithm(algorithm)?;
    validate_optional_param_len(
        key,
        iana::AkpKeyParameter::Pub as i64,
        profile.public_key_len,
    )?;
    validate_optional_param_len(
        key,
        iana::AkpKeyParameter::Priv as i64,
        profile.private_key_len,
    )?;
    let public_key = get_param_bytes(key, iana::AkpKeyParameter::Pub as i64)
        .ok_or(CoseError::MissingKeyMaterial)?;
    let private_key = get_param_bytes(key, iana::AkpKeyParameter::Priv as i64);
    validate_key_operations(key, private_key.is_some(), profile.is_signature)?;
    let algorithm = algorithm_for_akp_profile(profile);
    validate_public_key(algorithm, public_key)?;
    if let Some(private_key) = private_key {
        validate_private_public_pair(algorithm, private_key, public_key)?;
    }
    Ok(KeyProfile::Akp(profile))
}

fn okp_profile(curve: i64) -> Result<OkpProfile, CoseError> {
    if curve == iana::EllipticCurve::Ed25519 as i64 {
        return Ok(OkpProfile {
            alg: Some(iana::Algorithm::Ed25519),
            coordinate_len: ED25519_PUBLIC_KEY_BYTES,
        });
    }
    if curve == iana::EllipticCurve::X25519 as i64 {
        return Ok(OkpProfile {
            alg: None,
            coordinate_len: X25519_PUBLIC_KEY_BYTES,
        });
    }
    Err(CoseError::UnsupportedAlgorithm)
}

fn validate_key_algorithm(
    key: &coset::CoseKey,
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
    key: &coset::CoseKey,
    label: i64,
    expected_len: usize,
) -> Result<(), CoseError> {
    if let Some(bytes) = get_param_bytes(key, label) {
        if bytes.len() != expected_len {
            return Err(CoseError::InvalidKeyMaterial);
        }
    }
    Ok(())
}

fn validate_key_operations(
    key: &coset::CoseKey,
    has_private_key: bool,
    is_signature_key: bool,
) -> Result<(), CoseError> {
    for operation in &key.key_ops {
        let allowed = if is_signature_key {
            matches!(
                operation,
                RegisteredLabel::Assigned(iana::KeyOperation::Verify)
                    | RegisteredLabel::Assigned(iana::KeyOperation::Sign) if has_private_key
            ) || matches!(
                operation,
                RegisteredLabel::Assigned(iana::KeyOperation::Verify)
            )
        } else {
            matches!(
                operation,
                RegisteredLabel::Assigned(iana::KeyOperation::DeriveKey)
                    | RegisteredLabel::Assigned(iana::KeyOperation::DeriveBits)
            )
        };
        if !allowed {
            return Err(CoseError::InvalidKeyMaterial);
        }
    }
    Ok(())
}

pub(crate) fn get_param_value(key: &coset::CoseKey, label: i64) -> Option<&Value> {
    key.params
        .iter()
        .find(|(candidate, _)| *candidate == Label::Int(label))
        .map(|(_, value)| value)
}

pub(crate) fn get_param_bytes(key: &coset::CoseKey, label: i64) -> Option<&[u8]> {
    get_param_value(key, label)
        .and_then(Value::as_bytes)
        .map(Vec::as_slice)
}

fn get_param_i64(key: &coset::CoseKey, label: i64) -> Option<i64> {
    get_param_value(key, label)
        .and_then(Value::as_integer)
        .and_then(|value| value.try_into().ok())
}
