// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Public raw-byte facade for typed COSE_Key operations.

use reallyme_crypto::core::Algorithm;
use zeroize::Zeroizing;

use crate::algorithm::CoseSignatureAlgorithm;
use crate::failure::CoseFailure;
use crate::{CoseError, CoseKey};

use super::convert::{
    construct_cose_key_from_private, construct_cose_key_from_public,
    construct_cose_key_from_signature_private, construct_cose_key_from_signature_public,
    encode_cose_key, extract_cose_key_private, extract_cose_key_public, CoseKeyBytesOutput,
    CoseKeyFromPrivateBytesInput, CoseKeyFromPublicBytesInput, CoseKeyOwnerOutput, CoseKeyRefInput,
};

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

/// Build a public COSE_Key with an exact signature-algorithm registration.
///
/// Use this API when the protocol distinguishes registrations that share one
/// cryptographic primitive, such as WebAuthn ES256 (`-7`) and fully specified
/// ESP256 (`-9`).
///
/// # Errors
///
/// Returns [`CoseError`] when the algorithm/key combination, point encoding,
/// length, or public key material is invalid.
pub fn cose_key_from_signature_public_bytes(
    algorithm: CoseSignatureAlgorithm,
    public_key: &[u8],
) -> Result<CoseKey, CoseError> {
    construct_cose_key_from_signature_public(algorithm, public_key)
        .map(CoseKeyOwnerOutput::into_key)
        .map_err(CoseFailure::into_native_error)
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

/// Build a private COSE_Key with an exact signature-algorithm registration.
///
/// # Errors
///
/// Returns [`CoseError`] when private/public material is absent, malformed,
/// unsupported, or not cryptographically bound to the selected algorithm.
pub fn cose_key_from_signature_private_bytes(
    algorithm: CoseSignatureAlgorithm,
    private_key: &[u8],
    public_key: Option<&[u8]>,
) -> Result<CoseKey, CoseError> {
    construct_cose_key_from_signature_private(algorithm, private_key, public_key)
        .map(CoseKeyOwnerOutput::into_key)
        .map_err(CoseFailure::into_native_error)
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
