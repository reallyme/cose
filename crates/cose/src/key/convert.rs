// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

//! Raw-byte construction, extraction, and canonical encoding for COSE_Key.

use ciborium::value::Value;
use coset::{iana, AsCborValue, CoseKeyBuilder};
use reallyme_crypto::core::Algorithm;
use zeroize::Zeroizing;

use crate::encode_cbor::encode_cbor_value;
use crate::failure::CoseFailure;
use crate::limits::validate_cose_key_bytes;
use crate::{CoseError, CoseKey};

use super::akp::{akp_key, akp_profile, algorithm_for_akp_profile};
use super::ec::{
    algorithm_for_ec2_profile, canonical_ec_public_key, ec2_profile, ec2_public_bytes_from_key,
    ec2_public_key_builder,
};
use super::profile::{
    get_param_bytes, validate_cose_key_profile, KeyProfile, ED25519_PUBLIC_KEY_BYTES,
    ED25519_SECRET_KEY_BYTES, X25519_PUBLIC_KEY_BYTES,
};
use super::validate_material::{validate_private_public_pair, validate_public_key};

pub(crate) struct CoseKeyFromPublicBytesInput<'a> {
    algorithm: Algorithm,
    public_key: &'a [u8],
}

impl<'a> CoseKeyFromPublicBytesInput<'a> {
    pub(crate) const fn new(algorithm: Algorithm, public_key: &'a [u8]) -> Self {
        Self {
            algorithm,
            public_key,
        }
    }
}

pub(crate) struct CoseKeyFromPrivateBytesInput<'a> {
    algorithm: Algorithm,
    private_key: &'a [u8],
    public_key: Option<&'a [u8]>,
}

impl<'a> CoseKeyFromPrivateBytesInput<'a> {
    pub(crate) const fn new(
        algorithm: Algorithm,
        private_key: &'a [u8],
        public_key: Option<&'a [u8]>,
    ) -> Self {
        Self {
            algorithm,
            private_key,
            public_key,
        }
    }
}

#[must_use]
pub(crate) struct CoseKeyOwnerOutput {
    key: CoseKey,
}

impl CoseKeyOwnerOutput {
    pub(crate) fn into_key(self) -> CoseKey {
        self.key
    }
}

pub(crate) struct CoseKeyRefInput<'a> {
    key: &'a CoseKey,
}

impl<'a> CoseKeyRefInput<'a> {
    pub(crate) const fn new(key: &'a CoseKey) -> Self {
        Self { key }
    }

    pub(crate) const fn key(&self) -> &CoseKey {
        self.key
    }
}

#[must_use]
pub(crate) struct CoseKeyBytesOutput {
    bytes: Zeroizing<Vec<u8>>,
}

impl CoseKeyBytesOutput {
    pub(crate) fn into_zeroizing(self) -> Zeroizing<Vec<u8>> {
        self.bytes
    }

    pub(crate) fn into_vec(mut self) -> Vec<u8> {
        // The established native public-key API returns `Vec<u8>`. This is the
        // single deliberate escape from the semantic wipe owner; adapters keep
        // the zeroizing form and never call this compatibility conversion.
        core::mem::take(&mut self.bytes)
    }
}

pub(crate) fn construct_cose_key_from_public(
    input: CoseKeyFromPublicBytesInput<'_>,
) -> Result<CoseKeyOwnerOutput, CoseFailure> {
    construct_cose_key_from_public_impl(input.algorithm, input.public_key)
        .map(|key| CoseKeyOwnerOutput { key })
        .map_err(CoseFailure::from)
}

pub(crate) fn construct_cose_key_from_private(
    input: CoseKeyFromPrivateBytesInput<'_>,
) -> Result<CoseKeyOwnerOutput, CoseFailure> {
    construct_cose_key_from_private_impl(input.algorithm, input.private_key, input.public_key)
        .map(|key| CoseKeyOwnerOutput { key })
        .map_err(CoseFailure::from)
}

pub(crate) fn encode_cose_key(
    input: CoseKeyRefInput<'_>,
) -> Result<CoseKeyBytesOutput, CoseFailure> {
    encode_cose_key_impl(input.key)
        .map(|bytes| CoseKeyBytesOutput { bytes })
        .map_err(CoseFailure::from)
}

pub(crate) fn extract_cose_key_public(
    input: CoseKeyRefInput<'_>,
) -> Result<CoseKeyBytesOutput, CoseFailure> {
    extract_cose_key_public_impl(input.key)
        .map(Zeroizing::new)
        .map(|bytes| CoseKeyBytesOutput { bytes })
        .map_err(CoseFailure::from)
}

pub(crate) fn extract_cose_key_private(
    input: CoseKeyRefInput<'_>,
) -> Result<CoseKeyBytesOutput, CoseFailure> {
    extract_cose_key_private_impl(input.key)
        .map(|bytes| CoseKeyBytesOutput { bytes })
        .map_err(CoseFailure::from)
}

/// Encode a COSE_Key to canonical CBOR bytes.
///
/// The returned buffer zeroizes on drop because a validated [`CoseKey`] may
/// contain private parameters.
///
/// # Errors
///
/// Returns [`CoseError`] when the key profile or material is invalid, or when
/// canonical CBOR serialization or post-serialization validation fails.
pub fn cose_key_to_vec(key: &CoseKey) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    encode_cose_key(CoseKeyRefInput::new(key))
        .map(CoseKeyBytesOutput::into_zeroizing)
        .map_err(CoseFailure::into_native_error)
}

fn encode_cose_key_impl(key: &CoseKey) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    validate_cose_key_profile(key)?;
    encode_cose_key_value(key)
}

#[cfg(feature = "cose-crypto")]
pub(crate) fn canonical_ml_kem_public_key_bytes(
    algorithm: Algorithm,
    public_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    let profile = akp_profile(algorithm)?;
    if profile.is_signature || public_key.len() != profile.public_key_len {
        return Err(CoseError::InvalidKeyMaterial);
    }

    let key = CoseKey::new(akp_key(algorithm, public_key, None)?);
    encode_cose_key_value(&key)
}

fn encode_cose_key_value(key: &CoseKey) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    let value = key
        .inner()
        .clone()
        .to_cbor_value()
        .map_err(|_| CoseError::Cbor)?;
    let encoded = encode_cbor_value(value)?;
    validate_cose_key_bytes(&encoded)?;
    Ok(encoded)
}

/// Build a COSE_Key from raw public key bytes.
///
/// # Errors
///
/// Returns [`CoseError`] when the algorithm lacks a supported COSE_Key mapping
/// or the public key has an invalid length, encoding, point, or backend shape.
pub fn cose_key_from_public_bytes(
    algorithm: Algorithm,
    public_key: &[u8],
) -> Result<CoseKey, CoseError> {
    construct_cose_key_from_public(CoseKeyFromPublicBytesInput::new(algorithm, public_key))
        .map(CoseKeyOwnerOutput::into_key)
        .map_err(CoseFailure::into_native_error)
}

fn construct_cose_key_from_public_impl(
    algorithm: Algorithm,
    public_key: &[u8],
) -> Result<CoseKey, CoseError> {
    match algorithm {
        Algorithm::Ed25519 => {
            if public_key.len() != ED25519_PUBLIC_KEY_BYTES {
                return Err(CoseError::InvalidKeyMaterial);
            }
            validate_public_key(algorithm, public_key)?;
            Ok(CoseKey::new(
                CoseKeyBuilder::new_okp_key()
                    .param(
                        iana::OkpKeyParameter::Crv as i64,
                        Value::Integer((iana::EllipticCurve::Ed25519 as i64).into()),
                    )
                    .param(
                        iana::OkpKeyParameter::X as i64,
                        Value::Bytes(public_key.to_vec()),
                    )
                    .algorithm(iana::Algorithm::Ed25519)
                    .build(),
            ))
        }
        Algorithm::X25519 => {
            if public_key.len() != X25519_PUBLIC_KEY_BYTES {
                return Err(CoseError::InvalidKeyMaterial);
            }
            validate_public_key(algorithm, public_key)?;
            Ok(CoseKey::new(
                CoseKeyBuilder::new_okp_key()
                    .param(
                        iana::OkpKeyParameter::Crv as i64,
                        Value::Integer((iana::EllipticCurve::X25519 as i64).into()),
                    )
                    .param(
                        iana::OkpKeyParameter::X as i64,
                        Value::Bytes(public_key.to_vec()),
                    )
                    .build(),
            ))
        }
        Algorithm::P256 | Algorithm::P384 | Algorithm::P521 | Algorithm::Secp256k1 => {
            let profile = ec2_profile(algorithm)?;
            let canonical = canonical_ec_public_key(profile, public_key)?;
            Ok(CoseKey::new(
                ec2_public_key_builder(profile, &canonical)?
                    .algorithm(profile.alg)
                    .build(),
            ))
        }
        Algorithm::MlDsa44
        | Algorithm::MlDsa65
        | Algorithm::MlDsa87
        | Algorithm::MlKem512
        | Algorithm::MlKem768
        | Algorithm::MlKem1024 => {
            let profile = akp_profile(algorithm)?;
            if public_key.len() != profile.public_key_len {
                return Err(CoseError::InvalidKeyMaterial);
            }
            validate_public_key(algorithm, public_key)?;
            Ok(CoseKey::new(akp_key(algorithm, public_key, None)?))
        }
        _ => Err(CoseError::UnsupportedAlgorithm),
    }
}

/// Extract raw public key bytes from a COSE_Key.
///
/// # Errors
///
/// Returns [`CoseError`] when the key profile, algorithm, parameters, lengths,
/// curve point, or public key material is missing or invalid.
pub fn cose_key_to_public_bytes(key: &CoseKey) -> Result<Vec<u8>, CoseError> {
    extract_cose_key_public(CoseKeyRefInput::new(key))
        .map(CoseKeyBytesOutput::into_vec)
        .map_err(CoseFailure::into_native_error)
}

fn extract_cose_key_public_impl(key: &CoseKey) -> Result<Vec<u8>, CoseError> {
    match validate_cose_key_profile(key)? {
        KeyProfile::Okp(profile) => {
            let public_key = get_param_bytes(key.inner(), iana::OkpKeyParameter::X as i64)
                .ok_or(CoseError::MissingKeyMaterial)?;
            if public_key.len() != profile.coordinate_len {
                return Err(CoseError::InvalidKeyMaterial);
            }
            let algorithm = if profile.alg == Some(iana::Algorithm::Ed25519) {
                Algorithm::Ed25519
            } else {
                Algorithm::X25519
            };
            validate_public_key(algorithm, public_key)?;
            Ok(public_key.to_vec())
        }
        KeyProfile::Ec2(profile) => {
            let public_key = ec2_public_bytes_from_key(key.inner(), profile)?;
            validate_public_key(algorithm_for_ec2_profile(profile)?, &public_key)?;
            Ok(public_key)
        }
        KeyProfile::Akp(profile) => {
            let public_key = get_param_bytes(key.inner(), iana::AkpKeyParameter::Pub as i64)
                .ok_or(CoseError::MissingKeyMaterial)?;
            if public_key.len() != profile.public_key_len {
                return Err(CoseError::InvalidKeyMaterial);
            }
            validate_public_key(algorithm_for_akp_profile(profile), public_key)?;
            Ok(public_key.to_vec())
        }
    }
}

/// Build a COSE_Key from raw private key bytes and its public binding.
///
/// # Errors
///
/// Returns [`CoseError`] when private or public material is missing, malformed,
/// unsupported, or not bound to the supplied private key.
pub fn cose_key_from_private_bytes(
    algorithm: Algorithm,
    private_key: &[u8],
    public_key: Option<&[u8]>,
) -> Result<CoseKey, CoseError> {
    construct_cose_key_from_private(CoseKeyFromPrivateBytesInput::new(
        algorithm,
        private_key,
        public_key,
    ))
    .map(CoseKeyOwnerOutput::into_key)
    .map_err(CoseFailure::into_native_error)
}

fn construct_cose_key_from_private_impl(
    algorithm: Algorithm,
    private_key: &[u8],
    public_key: Option<&[u8]>,
) -> Result<CoseKey, CoseError> {
    if private_key.is_empty() {
        return Err(CoseError::MissingPrivateKey);
    }

    match algorithm {
        Algorithm::Ed25519 => {
            if private_key.len() != ED25519_SECRET_KEY_BYTES {
                return Err(CoseError::InvalidKeyMaterial);
            }
            let public_key = public_key.ok_or(CoseError::MissingKeyMaterial)?;
            if public_key.len() != ED25519_PUBLIC_KEY_BYTES {
                return Err(CoseError::InvalidKeyMaterial);
            }
            validate_private_public_pair(algorithm, private_key, public_key)?;

            // RFC 8949 bytewise key order places -2 (`x`) before -4 (`d`).
            // Building in that order keeps the accepted in-memory key directly
            // serializable by the canonical encoder.
            let key = CoseKeyBuilder::new_okp_key()
                .param(
                    iana::OkpKeyParameter::Crv as i64,
                    Value::Integer((iana::EllipticCurve::Ed25519 as i64).into()),
                )
                .param(
                    iana::OkpKeyParameter::X as i64,
                    Value::Bytes(public_key.to_vec()),
                )
                .param(
                    iana::OkpKeyParameter::D as i64,
                    Value::Bytes(private_key.to_vec()),
                )
                .algorithm(iana::Algorithm::Ed25519)
                .build();
            Ok(CoseKey::new(key))
        }
        Algorithm::P256 | Algorithm::P384 | Algorithm::P521 | Algorithm::Secp256k1 => {
            let profile = ec2_profile(algorithm)?;
            if private_key.len() != profile.coordinate_len {
                return Err(CoseError::InvalidKeyMaterial);
            }
            let public_key = public_key.ok_or(CoseError::MissingKeyMaterial)?;
            let canonical = canonical_ec_public_key(profile, public_key)?;
            validate_private_public_pair(algorithm, private_key, &canonical)?;
            let key = ec2_public_key_builder(profile, &canonical)?
                .param(
                    iana::Ec2KeyParameter::D as i64,
                    Value::Bytes(private_key.to_vec()),
                )
                .algorithm(profile.alg)
                .build();
            Ok(CoseKey::new(key))
        }
        Algorithm::MlDsa44
        | Algorithm::MlDsa65
        | Algorithm::MlDsa87
        | Algorithm::MlKem512
        | Algorithm::MlKem768
        | Algorithm::MlKem1024 => {
            let profile = akp_profile(algorithm)?;
            let public_key = public_key.ok_or(CoseError::MissingKeyMaterial)?;
            if private_key.len() != profile.private_key_len
                || public_key.len() != profile.public_key_len
            {
                return Err(CoseError::InvalidKeyMaterial);
            }
            validate_private_public_pair(algorithm, private_key, public_key)?;
            Ok(CoseKey::new(akp_key(
                algorithm,
                public_key,
                Some(private_key),
            )?))
        }
        _ => Err(CoseError::UnsupportedAlgorithm),
    }
}

/// Extract raw private key bytes from a COSE_Key.
///
/// # Errors
///
/// Returns [`CoseError`] when the profile is invalid or private material is
/// absent.
pub fn cose_key_to_private_bytes(key: &CoseKey) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    extract_cose_key_private(CoseKeyRefInput::new(key))
        .map(CoseKeyBytesOutput::into_zeroizing)
        .map_err(CoseFailure::into_native_error)
}

fn extract_cose_key_private_impl(key: &CoseKey) -> Result<Zeroizing<Vec<u8>>, CoseError> {
    let private_label = match validate_cose_key_profile(key)? {
        KeyProfile::Okp(_) => iana::OkpKeyParameter::D as i64,
        KeyProfile::Ec2(_) => iana::Ec2KeyParameter::D as i64,
        KeyProfile::Akp(_) => iana::AkpKeyParameter::Priv as i64,
    };
    let private_key =
        get_param_bytes(key.inner(), private_label).ok_or(CoseError::MissingKeyMaterial)?;
    Ok(Zeroizing::new(private_key.to_vec()))
}
